// The evaluator: place one tool call in a band, from a compiled matrix and binding.
//
// Containment rules it holds to:
// - The matrix grants; nothing here widens. Limits, caps, restrictions and missing verification only
//   ever move a call to a stricter band.
// - A call it can't place (unmapped tool, an argument condition it can't evaluate, missing fact, wrong
//   currency, no open context, conflicting approvers, a wire capability that disagrees with the binding)
//   is unplaceable, never allowed.
// - The strictest placement wins: across every matched binding entry and every batch item.
import { lintBinding } from "../lint/binding.ts";
import { evalCondition } from "./conditions.ts";
import { addDecimal, cmpDecimal } from "./decimal.ts";
import { extractFact } from "./facts.ts";
import { resolvePointer } from "./pointer.ts";
import type { Band, Call, CompileResult, Decision, EvalContext, FactValue, Money, Outcome, Placement, Policy, Reason, Reservation } from "./types.ts";

type Validated = any;

/** Compile a policy. Refuses unless the binding, checked against the matrix, lints clean. */
export function compilePolicy(matrix: unknown, binding: unknown): CompileResult {
  const lint = lintBinding(binding, matrix);
  if (!lint.ok) return { ok: false, findings: lint.findings };
  const m = matrix as Validated;
  const rowById = new Map<string, Validated>(), rowByCapability = new Map<string, Validated>();
  for (const row of m.rows) {
    rowById.set(row.id, row);
    for (const cap of row.capabilities) rowByCapability.set(cap, row);
  }
  return { ok: true, policy: { matrix: m, binding: binding as Validated, rowById, rowByCapability } };
}

const RANK: Record<Band, number> = { A: 0, B: 1, C: 2, "non-delegable": 3 };
const stricter = (a: Band, b: Band): Band => (RANK[b] > RANK[a] ? b : a);

export function evaluate(policy: Policy, call: Call, ctx: EvalContext): Decision {
  const policyRef = {
    matrix: { id: policy.matrix.id, version: policy.matrix.version },
    binding: { id: policy.binding.id, version: policy.binding.version },
  };
  const unplaceable = (reasons: Reason[]): Decision => ({ outcome: "unplaceable", band: null, placements: [], reasons, reservations: [], policy: policyRef });

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
function matches(entry: Validated, call: Call): boolean | null {
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
  for (const f of needed) if (!(f in facts)) return fail("fact.missing", `row ${row.id} needs fact ${f}`);

  if (a.kind === "non-delegable") {
    return { ...base, band: "non-delegable", outcome: "refuse", facts, reasons: [...reasons, { code: "non-delegable", detail: a.reason, row: row.id }] };
  }

  const reservations: Reservation[] = [];
  const restrictionsHit = (allowed: (b: Band) => boolean): Band | "unplaceable" | null => {
    let hit: Band | null = null;
    for (const r of a.restrictions ?? []) {
      const v = evalCondition(r.when, (f) => facts[f], "fact");
      if (v === null) return "unplaceable";
      if (v && allowed(r.band)) { hit = hit ? stricter(hit, r.band) : r.band; reasons.push({ code: "restriction", detail: r.id, row: row.id }); }
    }
    return hit;
  };

  if (a.kind === "preparatory") {
    if (!(a.serves as string[]).some((s) => ctx.openContexts.has(s))) return fail("context.none", `no open execution context for a row ${row.id} serves (${a.serves.join(", ")})`);
    const hit = restrictionsHit(() => true);
    if (hit === "unplaceable") return fail("restriction.unevaluable", "a restriction couldn't be evaluated");
    if (hit) return { ...base, band: "non-delegable", outcome: "refuse", facts, reasons };
    for (const c of a.rateCaps ?? []) {
      const r = capCheck(c, row.id, facts, ctx, pending, reservations, reasons);
      if (r === "breach") return { ...base, band: "non-delegable", outcome: "refuse", facts, reasons };
    }
    return withReservations({ ...base, band: null, outcome: "allow", facts, reasons: [...reasons, { code: "preparatory", row: row.id }] }, reservations);
  }

  // Delegable: confidence picks among the bands the matrix authorises; everything after can only narrow.
  const score = ctx.scores?.[entry.capability];
  const sp = a.confidence?.scoringPolicy;
  let level: "high" | "medium" | "low" = "low";
  if (!a.confidence) reasons.push({ code: "confidence.no-policy", row: row.id });
  else if (!score) reasons.push({ code: "confidence.no-score", row: row.id });
  else if (score.policy.id !== sp.id || score.policy.version !== sp.version) reasons.push({ code: "confidence.wrong-policy", detail: `score from ${score.policy.id}@${score.policy.version}, row uses ${sp.id}@${sp.version}`, row: row.id });
  else if (!Number.isFinite(score.value)) reasons.push({ code: "confidence.invalid", row: row.id });
  else level = score.value >= a.confidence.thresholds.high ? "high" : score.value >= a.confidence.thresholds.medium ? "medium" : "low";
  let band: Band = a.routing[level];
  reasons.push({ code: `confidence.${level}`, row: row.id });

  if (band === "A" && a.confidence?.verificationRequired && score?.verified !== true) {
    band = "B";
    reasons.push({ code: "verification.missing", detail: "Band A on this row requires a passing independent verification", row: row.id });
  }

  if (a.valueCeiling) {
    const v = facts[a.valueCeiling.fact] as Money, lim = a.valueCeiling.limit;
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

  if (band === "non-delegable") return { ...base, band, outcome: "refuse", facts, reasons };
  const outcome: Outcome = band === "A" ? "allow" : band === "B" ? "review" : "escalate";
  const approverRole = band === "B" ? a.reviewer : band === "C" ? a.escalation.role : undefined;
  return withReservations({ ...base, band, outcome, ...(approverRole ? { approverRole } : {}), facts, reasons }, reservations);
}

function withReservations(p: Placement, r: Reservation[]): Placement {
  return Object.assign(p, { _res: r });
}

/** Check one cap, counting this placement and earlier ones in the same call. */
function capCheck(c: Validated, rowId: string, facts: Record<string, FactValue>, ctx: EvalContext, pending: Map<string, { total: string | null; count: number }>, reservations: Reservation[], reasons: Reason[]): "ok" | "breach" | "unplaceable" {
  const groupKey = JSON.stringify((c.groupBy ?? []).map((g: string) => facts[g]));
  const key = `${rowId}\u0000${c.id}\u0000${groupKey}`;
  const usage = ctx.capUsage(c.id, groupKey);
  let amount: string | undefined;
  if (c.total) {
    const v = facts[c.fact] as Money;
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
