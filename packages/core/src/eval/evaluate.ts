// The evaluator: place one tool call in a band, from a compiled matrix and binding.
//
// Containment rules it holds to:
// - The matrix grants; nothing here widens. Limits, caps, restrictions and missing verification only
//   ever move a call to a stricter band.
// - A call it can't place (unmapped tool, an argument condition it can't evaluate, missing fact, wrong
//   currency, no open context, conflicting approvers, a wire capability that disagrees with the binding)
//   is unplaceable, never allowed.
// - The strictest placement wins: across every matched binding entry and every batch item.
// - The matrix grants only inside its effective window; with no valid clock, nothing is placed.
// - Authority exists only inside a live execution context covering the call's row (and its task, if bound);
//   a context's band ceiling narrows further.
import { lintBinding } from "../lint/binding.ts";
import { lintScoring, scoringFacts } from "../lint/scoring.ts";
import type { Finding } from "../lint/types.ts";
import { capLevel, score as computeScore, type Level } from "../scoring/score.ts";
import { evalCondition } from "./conditions.ts";
import { addDecimal, cmpDecimal } from "./decimal.ts";
import { extractFact, factOf } from "./facts.ts";
import { resolvePointer } from "./pointer.ts";
import type { Band, Call, CompileResult, Decision, EvalContext, FactValue, Money, Outcome, Placement, PlacementScore, Policy, Reason, Reservation } from "./types.ts";

type Validated = any;

/**
 * Compile a policy. Refuses unless the binding, checked against the matrix, lints clean, and every scoring
 * policy a row cites is given, lints clean against the binding, and reads only facts that row's binding
 * entries extract. (A policy reading a fact the entry never extracts would fail that check on every call:
 * a silent Review Queue Flood rather than a visible configuration error.)
 */
export function compilePolicy(matrix: unknown, binding: unknown, scoring: readonly unknown[] = []): CompileResult {
  const lint = lintBinding(binding, matrix);
  if (!lint.ok) return { ok: false, findings: lint.findings };
  const m = matrix as Validated, b = binding as Validated;
  const rowById = new Map<string, Validated>(), rowByCapability = new Map<string, Validated>();
  for (const row of m.rows) {
    rowById.set(row.id, row);
    for (const cap of row.capabilities) rowByCapability.set(cap, row);
  }

  // Only the policies rows cite are compiled; others given alongside (for another matrix, say) are ignored.
  const findings: Finding[] = [];
  const given = new Map<string, { s: Validated; i: number }>();
  scoring.forEach((s, i) => {
    const key = `${(s as Validated)?.id}@${(s as Validated)?.version}`;
    if (given.has(key)) findings.push({ rule: "scoring.duplicate", severity: "error", path: `/scoring/${i}`, message: `scoring policy ${key} is given more than once` });
    else given.set(key, { s, i });
  });
  const policies = new Map<string, Validated>();
  (m.rows as Validated[]).forEach((row, i) => {
    const sp = row.authority?.confidence?.scoringPolicy;
    if (!sp) return;
    const key = `${sp.id}@${sp.version}`;
    const g = given.get(key);
    if (!g) {
      findings.push({ rule: "scoring.missing", severity: "error", path: `/rows/${i}/authority/confidence/scoringPolicy`, message: `row ${row.id} cites scoring policy ${key}, which wasn't given` });
      return;
    }
    if (!policies.has(key)) {
      const r = lintScoring(g.s, binding);
      findings.push(...r.findings.filter((f) => f.severity === "error").map((f) => ({ ...f, path: `/scoring/${g.i}${f.path}` })));
      if (!r.ok) return;
      policies.set(key, g.s);
    }
    const read = [...new Set(scoringFacts(g.s).map((x) => x.fact))];
    for (const t of b.tools as Validated[]) {
      if (!(row.capabilities as string[]).includes(t.capability)) continue;
      const extracted = new Set([...Object.keys(t.facts ?? {}), ...Object.keys(t.items?.facts ?? {})]);
      const missing = read.filter((f) => !extracted.has(f));
      if (missing.length) findings.push({ rule: "scoring.fact-not-extracted", severity: "error", path: `/rows/${i}`, message: `scoring policy ${key} reads ${missing.join(", ")}, which binding entry ${t.id} doesn't extract` });
    }
  });
  if (findings.length) return { ok: false, findings };
  return { ok: true, policy: { matrix: m, binding: b, rowById, rowByCapability, scoring: policies } };
}

const RANK: Record<Band, number> = { A: 0, B: 1, C: 2, "non-delegable": 3 };
const stricter = (a: Band, b: Band): Band => (RANK[b] > RANK[a] ? b : a);

export function evaluate(policy: Policy, call: Call, ctx: EvalContext): Decision {
  const policyRef: Decision["policy"] = {
    matrix: { id: policy.matrix.id, version: policy.matrix.version },
    binding: { id: policy.binding.id, version: policy.binding.version },
  };
  const unplaceable = (reasons: Reason[]): Decision => ({ outcome: "unplaceable", band: null, placements: [], reasons, reservations: [], policy: policyRef });

  // The matrix grants nothing outside its effective window: before it takes effect, or from its end on.
  if (!Number.isFinite(ctx.now)) return unplaceable([{ code: "clock.unknown", detail: "the evaluation has no valid time, so the matrix's effective window can't be checked" }]);
  const eff = policy.matrix.effective as { from?: string; until?: string } | undefined;
  if (eff?.from !== undefined && !(ctx.now >= Date.parse(eff.from))) return unplaceable([{ code: "matrix.not-in-effect", detail: `matrix ${policy.matrix.id}@${policy.matrix.version} takes effect at ${eff.from}` }]);
  if (eff?.until !== undefined && !(ctx.now < Date.parse(eff.until))) return unplaceable([{ code: "matrix.expired", detail: `matrix ${policy.matrix.id}@${policy.matrix.version} expired at ${eff.until}` }]);

  const matched = (policy.binding.tools as Validated[]).map((t) => ({ t, m: matches(t, call) }));
  const unknown = matched.filter((x) => x.m === null).map((x) => x.t.id);
  if (unknown.length) return unplaceable([{ code: "binding.condition-unevaluable", detail: `entry ${unknown.join(", ")}: an argument the match condition reads is missing` }]);
  const entries = matched.filter((x) => x.m === true).map((x) => x.t);
  if (entries.length === 0) return unplaceable([{ code: "unmapped", detail: `no binding entry matches tool ${call.tool}` }]);
  if (call.declaredCapability !== undefined && !entries.some((t) => t.capability === call.declaredCapability)) {
    return unplaceable([{ code: "capability.mismatch", detail: `the call declares ${call.declaredCapability}; the binding maps it to ${[...new Set(entries.map((t) => t.capability))].join(", ")}` }]);
  }

  // Cap usage accumulates across every placement in this call, so batch items can't each slip under a cap.
  const pending = new Map<string, { total: string | null; count: number }>();
  const placements: Placement[] = [];
  for (const entry of entries) {
    if (entry.items) {
      const items = resolvePointer(call.arguments, entry.items.arg);
      if (!Array.isArray(items) || items.length === 0) return unplaceable([{ code: "batch.empty", detail: `entry ${entry.id}: no items at ${entry.items.arg}` }]);
      if (entry.items.maxItems !== undefined && items.length > entry.items.maxItems) return unplaceable([{ code: "batch.too-large", detail: `entry ${entry.id}: ${items.length} items, at most ${entry.items.maxItems}` }]);
      items.forEach((item, i) => placements.push(place(policy, entry, call, ctx, pending, item, i)));
    } else {
      placements.push(place(policy, entry, call, ctx, pending));
    }
  }

  const reasons = placements.flatMap((p) => p.reasons);
  const reservations = placements.flatMap((p) => (p as Placement & { _res?: Reservation[] })._res ?? []);
  for (const p of placements) delete (p as Placement & { _res?: Reservation[] })._res;
  const scoredBy = new Map(placements.flatMap((p) => (p.score ? [[`${p.score.policy.id}@${p.score.policy.version}`, p.score.policy] as const] : [])));
  if (scoredBy.size) policyRef.scoring = [...scoredBy.values()];

  // A refusal is definite and wins; then anything unplaceable; then the strictest band.
  if (placements.some((p) => p.outcome === "refuse")) return { outcome: "refuse", band: "non-delegable", placements, reasons, reservations: [], policy: policyRef };
  if (placements.some((p) => p.outcome === "unplaceable")) return { outcome: "unplaceable", band: null, placements, reasons, reservations: [], policy: policyRef };

  // Preparatory placements carry no band; a call made only of them is allowed without one, so a
  // record never claims Band A for what was a read in service of a decision.
  const banded = placements.filter((p) => p.band !== null);
  if (banded.length === 0) return { outcome: "allow", band: null, placements, reasons, reservations, policy: policyRef };
  let band: Band = "A";
  for (const p of banded) band = stricter(band, p.band!);
  const atBand = banded.filter((p) => p.band === band);
  const approvers = new Set(atBand.map((p) => p.approverRole).filter((r): r is string => r !== undefined));
  if (approvers.size > 1) {
    return { outcome: "unplaceable", band: null, placements, reasons: [...reasons, { code: "approver.conflict", detail: `rows at band ${band} name different approvers: ${[...approvers].join(", ")}` }], reservations: [], policy: policyRef };
  }
  const outcome: Outcome = band === "A" ? "allow" : band === "B" ? "review" : "escalate";
  const approverRole = [...approvers][0];
  return { outcome, band, ...(approverRole !== undefined ? { approverRole } : {}), placements, reasons, reservations, policy: policyRef };
}

/**
 * Does a binding entry match this call? null when the tool matches but the argument condition can't be
 * evaluated. That's neither a match nor a miss: counting it as a match could grant the entry's capability
 * to a call that's otherwise unmapped, and counting it as a miss could drop an entry that would narrow.
 * The caller makes the call unplaceable.
 */
export function matches(entry: Validated, call: Call): boolean | null {
  const m = entry.match;
  const named = m.tool !== undefined ? m.tool === call.tool : call.tool.startsWith(m.toolPrefix);
  if (!named) return false;
  if (!m.when) return true;
  return evalCondition(m.when, (ptr) => resolvePointer(call.arguments, ptr), "arg");
}

function place(policy: Policy, entry: Validated, call: Call, ctx: EvalContext, pending: Map<string, { total: string | null; count: number }>, item?: unknown, itemIndex?: number): Placement {
  const row = policy.rowByCapability.get(entry.capability);
  const a = row.authority;
  const at = itemIndex === undefined ? "" : ` (item ${itemIndex})`;
  const reasons: Reason[] = [];
  const base = { row: row.id, capability: entry.capability, entry: entry.id };
  const fail = (code: string, detail: string): Placement => ({ ...base, band: null, outcome: "unplaceable", facts, reasons: [...reasons, { code, detail: detail + at, row: row.id }] });

  // Facts: per-call ones from the call's arguments, per-item ones from the item.
  const facts: Record<string, FactValue> = {};
  const factDefs = policy.binding.facts;
  const sources: [Record<string, Validated>, unknown][] = [[entry.facts ?? {}, call.arguments], [entry.items?.facts ?? {}, item]];
  for (const [extractors, args] of sources) {
    for (const [name, ex] of Object.entries(extractors)) {
      const got = extractFact(factDefs[name], ex, args);
      if (got.ok) facts[name] = got.value;
      else reasons.push({ code: "fact.unreadable", detail: `${name}: ${got.why}${at}`, row: row.id });
    }
  }
  const needed = new Set<string>([...(row.requiresFacts ?? [])]);
  for (const r of a.restrictions ?? []) collectFacts(r.when, needed);
  for (const c of [...(a.cumulativeCaps ?? []), ...(a.rateCaps ?? [])]) { if (c.fact) needed.add(c.fact); for (const g of c.groupBy ?? []) needed.add(g); }
  if (a.valueCeiling) needed.add(a.valueCeiling.fact);
  for (const f of needed) if (!Object.hasOwn(facts, f)) return fail("fact.missing", `row ${row.id} needs fact ${f}`);

  if (a.kind === "non-delegable") {
    return { ...base, band: "non-delegable", outcome: "refuse", facts, reasons: [...reasons, { code: "non-delegable", detail: a.reason, row: row.id }] };
  }

  const reservations: Reservation[] = [];
  const restrictionsHit = (allowed: (b: Band) => boolean): Band | "unplaceable" | null => {
    let hit: Band | null = null;
    for (const r of a.restrictions ?? []) {
      const v = evalCondition(r.when, (f) => factOf(facts, f), "fact");
      if (v === null) return "unplaceable";
      if (v && allowed(r.band)) { hit = hit ? stricter(hit, r.band) : r.band; reasons.push({ code: "restriction", detail: r.id, row: row.id }); }
    }
    return hit;
  };

  if (a.kind === "preparatory") {
    // A lease's observation context authorises preparatory capabilities in its scopes, whatever they serve.
    const observing = ctx.contexts.some((c) => c.observation === true && c.scopes?.includes(entry.capability));
    const serving = ctx.contexts.filter((c) => !c.observation && (a.serves as string[]).some((s) => c.rows.includes(s)));
    const authorising = observing ? ctx.contexts.filter((c) => c.observation === true && c.scopes?.includes(entry.capability)) : serving.filter((c) => inScope(c, entry.capability));
    if (observing) { /* authorised by an observation lease */ }
    else if (serving.length === 0) return fail("context.none", `no open execution context for a row ${row.id} serves (${a.serves.join(", ")})`);
    else if (!serving.some((c) => inScope(c, entry.capability))) return fail("context.scope", `no context serving row ${row.id} has ${entry.capability} in its scope`);
    const hit = restrictionsHit(() => true);
    if (hit === "unplaceable") return fail("restriction.unevaluable", "a restriction couldn't be evaluated");
    if (hit) return { ...base, band: "non-delegable", outcome: "refuse", facts, reasons };
    for (const c of a.rateCaps ?? []) {
      const r = capCheck(c, row.id, facts, ctx, pending, reservations, reasons);
      if (r === "breach") return { ...base, band: "non-delegable", outcome: "refuse", facts, reasons };
    }
    return withReservations({ ...base, band: null, outcome: "allow", facts, contexts: authorising.map((c) => c.id), reasons: [...reasons, { code: "preparatory", row: row.id }] }, reservations);
  }

  // Delegable: authority exists only inside a live execution context covering this row. A context bound
  // to a task authorises only calls naming that task; a call that names none isn't in its workflow.
  // Observation contexts never authorise a decision.
  const covering = ctx.contexts.filter((c) => !c.observation && c.rows.includes(row.id));
  if (covering.length === 0) return fail("context.none", `no open execution context covers row ${row.id}`);
  const scoped = covering.filter((c) => inScope(c, entry.capability));
  if (scoped.length === 0) return fail("context.scope", `no context covering row ${row.id} has ${entry.capability} in its scope`);
  const task = factOf(facts, "task");
  const applicable = scoped.filter((c) => c.task === undefined || c.task === task);
  if (applicable.length === 0) return fail("context.task-mismatch", task === undefined ? "the call names no task, and its context is bound to one" : `the call's task isn't the one its context is bound to`);

  // Confidence picks among the bands the matrix authorises; everything after can only narrow.
  // The score comes only from the row's own scoring policy, computed here from the placement's facts.
  let level: Level = "low";
  let scored: PlacementScore | undefined;
  const verified = ctx.verifications?.[entry.capability];
  if (!a.confidence) reasons.push({ code: "confidence.no-policy", row: row.id });
  else {
    const sp = a.confidence.scoringPolicy;
    const sPolicy = policy.scoring.get(`${sp.id}@${sp.version}`);
    if (!sPolicy) reasons.push({ code: "confidence.no-score", detail: `scoring policy ${sp.id}@${sp.version} isn't loaded`, row: row.id });
    else {
      const s = computeScore(sPolicy, { row: row.id, facts, ...(ctx.history ? { history: ctx.history } : {}), ...(call.statedCertainty !== undefined ? { statedCertainty: call.statedCertainty } : {}) });
      reasons.push(...s.reasons);
      const t = a.confidence.thresholds;
      level = capLevel(s.value >= t.high ? "high" : s.value >= t.medium ? "medium" : "low", s.cap);
      scored = { policy: s.policy, value: s.value, level, ...(s.cap ? { cap: s.cap } : {}), ...(verified !== undefined ? { verified } : {}), dimensions: s.dimensions };
    }
  }
  let band: Band = a.routing[level];
  reasons.push({ code: `confidence.${level}`, row: row.id });

  if (band === "A" && a.confidence?.verificationRequired && verified !== true) {
    band = "B";
    reasons.push({ code: "verification.missing", detail: "Band A on this row requires a passing independent verification", row: row.id });
  }

  if (a.valueCeiling) {
    const v = factOf(facts, a.valueCeiling.fact) as Money, lim = a.valueCeiling.limit;
    if (v.currency !== lim.currency) return fail("currency.mismatch", `${a.valueCeiling.fact} is in ${v.currency}; the ceiling is in ${lim.currency}`);
    if (cmpDecimal(v.amount, lim.amount) > 0) { band = stricter(band, a.valueCeiling.onExceed); reasons.push({ code: "ceiling.exceeded", detail: `${v.amount} ${v.currency} > ${lim.amount} ${lim.currency}`, row: row.id }); }
  }

  const hit = restrictionsHit(() => true);
  if (hit === "unplaceable") return fail("restriction.unevaluable", "a restriction couldn't be evaluated");
  if (hit) band = stricter(band, hit);

  for (const c of a.cumulativeCaps ?? []) {
    const r = capCheck(c, row.id, facts, ctx, pending, reservations, reasons);
    if (r === "unplaceable") return fail("cap.currency", `cap ${c.id} is in a different currency from fact ${c.fact}`);
    if (r === "breach") band = stricter(band, c.onBreach);
  }

  // A context's band ceiling (attenuation for sub-agents) narrows further; the strictest applies.
  for (const c of applicable) {
    const ceiling = c.bandCeiling?.[row.id];
    if (ceiling && RANK[ceiling] > RANK[band]) { band = ceiling; reasons.push({ code: "context.ceiling", detail: `context ${c.id} caps this row at ${ceiling}`, row: row.id }); }
  }

  const withScore = scored ? { score: scored } : {};
  const contexts = applicable.map((c) => c.id);
  if (band === "non-delegable") return { ...base, band, outcome: "refuse", facts, ...withScore, contexts, reasons };
  const outcome: Outcome = band === "A" ? "allow" : band === "B" ? "review" : "escalate";
  const approverRole = band === "B" ? a.reviewer : band === "C" ? a.escalation.role : undefined;
  return withReservations({ ...base, band, outcome, ...(approverRole ? { approverRole } : {}), facts, ...withScore, contexts, reasons }, reservations);
}

/** A context without explicit scopes covers everything its rows reach; with scopes, only those. */
function inScope(c: { scopes?: readonly string[] }, capability: string): boolean {
  return c.scopes === undefined || c.scopes.includes(capability);
}

function withReservations(p: Placement, r: Reservation[]): Placement {
  return Object.assign(p, { _res: r });
}

/** Check one cap, counting this placement and earlier ones in the same call. */
function capCheck(c: Validated, rowId: string, facts: Record<string, FactValue>, ctx: EvalContext, pending: Map<string, { total: string | null; count: number }>, reservations: Reservation[], reasons: Reason[]): "ok" | "breach" | "unplaceable" {
  const groupKey = JSON.stringify((c.groupBy ?? []).map((g: string) => factOf(facts, g)));
  const key = `${rowId}\u0000${c.id}\u0000${groupKey}`;
  const usage = ctx.capUsage(rowId, c.id, groupKey);
  let amount: string | undefined;
  if (c.total) {
    const v = factOf(facts, c.fact) as Money;
    if (v.currency !== c.total.currency) return "unplaceable";
    amount = v.amount;
  }
  reservations.push({ capId: c.id, row: rowId, groupKey, ...(amount !== undefined ? { amount } : {}), count: 1 });
  if (usage === null) {
    reasons.push({ code: "cap.history-unreadable", detail: c.id, row: rowId });
    return "breach";
  }
  const prior = pending.get(key) ?? { total: usage.total ?? "0", count: usage.count };
  const next = { total: amount !== undefined ? addDecimal(prior.total ?? "0", amount) : prior.total, count: prior.count + 1 };
  pending.set(key, next);
  const over = (c.total && next.total !== null && cmpDecimal(next.total, c.total.amount) > 0) || (c.count !== undefined && next.count > c.count);
  if (over) reasons.push({ code: "cap.breached", detail: `${c.id}: ${c.total ? `${next.total} > ${c.total.amount} ${c.total.currency}` : `${next.count} > ${c.count}`}`, row: rowId });
  return over ? "breach" : "ok";
}

function collectFacts(c: Validated, out: Set<string>): void {
  if (!c) return;
  if (Array.isArray(c.all)) c.all.forEach((x: Validated) => collectFacts(x, out));
  else if (Array.isArray(c.any)) c.any.forEach((x: Validated) => collectFacts(x, out));
  else if (typeof c.fact === "string") out.add(c.fact);
}
