// The Delegation Scorecard (VAOM v5 Section 11), computed from decision records. Pure: records and the
// matrix in, a report out. It reads; it never feeds back into a decision.
//
// What it holds to:
// - Every metric is read per decision type (matrix row), as thresholds and targets are set per row.
// - Reviewer privacy: metrics are aggregated per row and its reviewer role. Nothing here reads
//   approver_id, and no reviewer is named, whatever the matrix's reviewerLevelMetrics says. A role held by
//   one person is that person, though: there the review figures describe them, and a deployment should
//   know that before it publishes a scorecard.
// - Honest about its input: records are counted once by id, and records it couldn't date are counted
//   and reported, not silently left out.
// - Honesty about coverage: a metric the records can't support is reported as not measured, with the
//   reason, never as healthy. A metric whose healthy range the matrix doesn't declare reports its value
//   with no verdict. Below a minimum sample there is no verdict either: a signal from eight records is
//   noise wearing a warning light.
// - Healthy ranges the paper gives as illustrative defaults (Section 8) are used only where the matrix
//   is silent, and the report names them as defaults.
import { assessBoundaries, type ProbeResult } from "../boundaries/probes.ts";
import type { DecisionRecord } from "../record/record.ts";

type Validated = any;

export const SCORECARD_FORMAT = "vaom.scorecard/0.1";

export type Status = "healthy" | "breach" | "insufficient-sample" | "no-target" | "not-measured";

export interface Metric {
  status: Status;
  /** The named diagnosis a breach points to (Section 11), present on a breach. */
  diagnosis?: string;
  /** What the status rests on: a target's source, a sample size, or why it isn't measured. */
  note?: string;
  [value: string]: unknown;
}

export interface RowScorecard {
  row: string;
  title: string;
  /** Placements in the period: one per decision, or per batch item. */
  decisions: number;
  metrics: Record<string, Metric>;
}

export interface Scorecard {
  format: typeof SCORECARD_FORMAT;
  matrix: { id: string; version: string };
  period: { from: string; to: string };
  records: number;
  /** What was left out, and why: repeated record ids (counted once), and records, seeds and spawns
   *  whose timestamp couldn't be read. */
  input: { duplicates: number; undated: { records: number; seeds: number; spawns: number }; formats: Record<string, number> };
  rows: RowScorecard[];
  workflow: Record<string, Metric>;
  agents: Record<string, Metric>;
}

export interface ScorecardOptions {
  from: string;
  to: string;
  /** Placements a row needs before any verdict. Default 20. */
  minSample?: number;
  /** Outcomes of seeded cases, from the Guardian's store. Seeds are never decision records. */
  seeds?: readonly SeedOutcome[];
  /** Decided seeds a row needs before a verdict on detection. Default 10. */
  seedMinSample?: number;
  /** Boundary probe results on record. Boundaries are judged as of the end of the period. */
  probes?: readonly ProbeResult[];
  /** Sub-agent spawn decisions on record, allowed and denied. */
  spawns?: readonly SpawnOutcome[];
}

export interface SpawnOutcome {
  ts: string;
  decision: "allow" | "deny";
  /** context_derived; authority_breach (past the matrix's depth, fan-out or count); outside_allowed_patterns; or a request fault. */
  reason: string;
  agent?: string;
}

export interface SeedOutcome {
  row: string;
  ts: string;
  /** detected: the reviewer rejected it. missed: approved (it never executes). expired: nobody decided. */
  result: "detected" | "missed" | "expired";
}

/** Section 8's illustrative starting defaults, used only where the matrix declares nothing. */
export const PAPER_DEFAULTS = {
  maxApprovalShare: 0.9,
  maxExceptionShare: 0.15,
  maxDimensionCorrelation: 0.95,
  maxUtilization: 0.8,
} as const;

const SCOPE_CODES = new Set(["context.none", "context.scope", "context.task-mismatch", "unmapped", "capability.mismatch"]);

export function scorecard(matrix: Validated, records: readonly DecisionRecord[], opts: ScorecardOptions): Scorecard {
  const from = Date.parse(opts.from), to = Date.parse(opts.to);
  if (Number.isNaN(from) || Number.isNaN(to) || to <= from) throw new Error("scorecard: the period must be two timestamps, from before to");
  const minSample = opts.minSample ?? 20;
  const byId = new Map<string, DecisionRecord>();
  let duplicates = 0;
  for (const r of records) { if (byId.has(r.id)) duplicates++; else byId.set(r.id, r); }
  const unique = [...byId.values()];
  const dated = <T>(xs: readonly T[], ts: (x: T) => string) => xs.filter((x) => !Number.isNaN(Date.parse(ts(x))));
  const within = <T>(xs: readonly T[], ts: (x: T) => string) => xs.filter((x) => { const t = Date.parse(ts(x)); return t >= from && t < to; });
  const inPeriod = within(unique, (r) => r.request.ts);
  const weeks = (to - from) / (7 * 86_400_000);
  const formats: Record<string, number> = {};
  for (const r of inPeriod) formats[r.format] = (formats[r.format] ?? 0) + 1;
  const undated = {
    records: unique.length - dated(unique, (r) => r.request.ts).length,
    seeds: (opts.seeds ?? []).length - dated(opts.seeds ?? [], (s) => s.ts).length,
    spawns: (opts.spawns ?? []).length - dated(opts.spawns ?? [], (s) => s.ts).length,
  };

  const seeds = within(opts.seeds ?? [], (s) => s.ts);
  const rows = (matrix.rows as Validated[]).filter((row) => row.authority?.kind === "delegable").map((row) => rowScorecard(row, inPeriod, minSample, seeds.filter((s) => s.row === row.id), opts.seedMinSample ?? 10));
  return {
    format: SCORECARD_FORMAT,
    matrix: { id: matrix.id, version: matrix.version },
    period: { from: opts.from, to: opts.to },
    records: inPeriod.length,
    input: { duplicates, undated, formats },
    rows,
    workflow: {
      oversightLoad: oversightLoad(matrix, inPeriod, weeks),
      chainIntegrity: chainIntegrity(within(opts.spawns ?? [], (s) => s.ts)),
      boundaryVerification: boundaryVerification(matrix, opts.probes ?? [], to),
    },
    agents: scopeDenials(inPeriod, minSample),
  };
}

type Placed = { record: DecisionRecord; placement: DecisionRecord["decision"]["placements"][number] };

function rowScorecard(row: Validated, records: readonly DecisionRecord[], minSample: number, seeds: readonly SeedOutcome[], seedMinSample: number): RowScorecard {
  const placed: Placed[] = records.flatMap((record) => record.decision.placements.filter((p) => p.row === row.id).map((placement) => ({ record, placement })));
  const banded = placed.filter((x) => x.placement.band === "A" || x.placement.band === "B" || x.placement.band === "C");
  const enough = banded.length >= minSample;
  const short: Metric = { status: "insufficient-sample", note: `${banded.length} banded decisions; at least ${minSample} needed for a verdict` };
  const ov = row.oversight ?? {};

  const metrics: Record<string, Metric> = {};

  // 1. Band distribution against the shares the row expected at design.
  const count = { A: 0, B: 0, C: 0 };
  for (const x of banded) count[x.placement.band as "A" | "B" | "C"]++;
  const share = (n: number) => (banded.length ? n / banded.length : 0);
  const observed = { A: share(count.A), B: share(count.B), C: share(count.C) };
  const exp = ov.expectedPerWeek as Record<"A" | "B" | "C", number> | undefined;
  const expTotal = exp ? (exp.A ?? 0) + (exp.B ?? 0) + (exp.C ?? 0) : 0;
  const expected = exp && expTotal > 0 ? { A: (exp.A ?? 0) / expTotal, B: (exp.B ?? 0) / expTotal, C: (exp.C ?? 0) / expTotal } : undefined;
  metrics.bandDistribution = {
    status: banded.length === 0 ? "insufficient-sample" : "no-target",
    counts: count, observed, ...(expected ? { expected } : {}),
    note: "the matrix declares expected volumes but no tolerance, so drift is reported without a verdict",
  };

  // 2. Band A error rate needs post-execution audit outcomes, which aren't in decision records.
  metrics.bandAErrorRate = { status: "not-measured", note: "needs post-execution audit outcomes; decision records don't carry them", ...(row.authority.confidence?.calibration ? { target: row.authority.confidence.calibration.errorTarget } : {}) };

  // 3. Exception-path share: decisions a restriction placed, rather than the composite score.
  const restricted = banded.filter((x) => x.record.decision.reasons.some((r) => r.code === "restriction" && r.row === row.id)).length;
  const exceptionShare = share(restricted);
  metrics.exceptionPathShare = !enough ? { ...short, share: exceptionShare } : {
    status: exceptionShare > PAPER_DEFAULTS.maxExceptionShare ? "breach" : "healthy",
    share: exceptionShare, threshold: PAPER_DEFAULTS.maxExceptionShare, note: "a decision counts as an exception when a restriction placed it; threshold is the paper's default",
    ...(exceptionShare > PAPER_DEFAULTS.maxExceptionShare ? { diagnosis: "Exception Graveyard" } : {}),
  };

  // 4. Dimension correlation with the composite.
  metrics.dimensionCorrelation = dimensionCorrelation(banded, minSample);

  // 5. Verifier effectiveness: disagreement only; the catch rate needs a labelled challenge set.
  const judged = banded.filter((x) => x.placement.score?.verified !== undefined);
  if (judged.length === 0) metrics.verifierEffectiveness = { status: "not-measured", note: "no verifier verdicts recorded" };
  else {
    const disagreement = judged.filter((x) => x.placement.score!.verified === false).length / judged.length;
    metrics.verifierEffectiveness = judged.length < minSample ? { status: "insufficient-sample", disagreement, note: `${judged.length} decisions with a verifier verdict; at least ${minSample} needed for a verdict` } : {
      status: disagreement === 0 ? "breach" : "healthy", disagreement,
      note: "disagreement only; the catch rate needs a labelled challenge set",
      ...(disagreement === 0 ? { diagnosis: "verification theater" } : {}),
    };
  }

  // 6. Stale knowledge: the Guardian doesn't see retrievals.
  metrics.staleKnowledgeShare = { status: "not-measured", note: "retrievals don't pass through the Guardian" };

  // 8. Review engagement, per row and never per reviewer.
  metrics.reviewEngagement = reviewEngagement(row, records, minSample, ov.minPlausibleReviewSeconds);

  // 9. Seeded-error detection.
  metrics.seededDetection = seededDetection(ov.seeding, seeds, seedMinSample);

  // 10. Escalation SLA attainment: the matrix declares no SLA, so report what happened to escalations.
  const escalations = records.filter((r) => r.decision.outcome === "escalate" && r.decision.placements.some((p) => p.row === row.id && p.band === "C"));
  const settled = escalations.filter((r) => r.resolution);
  const expired = settled.filter((r) => r.resolution!.result === "expired").length;
  metrics.escalationSla = { status: escalations.length ? "no-target" : "insufficient-sample", escalations: escalations.length, resolved: settled.length, expired, note: "the matrix declares no escalation SLA; an expired escalation never reached an authorized human in time" };

  return { row: row.id, title: row.title, decisions: placed.length, metrics };
}

/** 9. Seeded-error detection: rejected seeds over decided ones, against the rate set at design. */
function seededDetection(seeding: Validated, seeds: readonly SeedOutcome[], seedMinSample: number): Metric {
  if (seeding?.enabled !== true) return { status: "not-measured", note: "seeding isn't enabled for this row; review engagement is the evidence" };
  const detected = seeds.filter((s) => s.result === "detected").length, missed = seeds.filter((s) => s.result === "missed").length;
  const expired = seeds.filter((s) => s.result === "expired").length, decided = detected + missed;
  const values = { planted: seeds.length, detected, missed, expired, ...(decided ? { detectionRate: detected / decided } : {}), target: seeding.targetDetectionRate };
  if (decided < seedMinSample) return { status: "insufficient-sample", ...values, note: `${decided} decided seeds; at least ${seedMinSample} needed for a verdict` };
  const breach = detected / decided < seeding.targetDetectionRate;
  return {
    status: breach ? "breach" : "healthy", ...values,
    note: "aggregated per row; an expired seed was never decided and counts neither way",
    ...(breach ? { diagnosis: "oversight not effective, whatever the approval rate says" } : {}),
  };
}

function dimensionCorrelation(banded: Placed[], minSample: number): Metric {
  const scored = banded.filter((x) => x.placement.score);
  if (scored.length === 0) return { status: "not-measured", note: "no scored decisions" };
  const need = Math.max(3, minSample);
  if (scored.length < need) return { status: "insufficient-sample", note: `${scored.length} scored decisions; at least ${need} needed for a verdict` };
  const dims = new Set(scored.flatMap((x) => Object.keys(x.placement.score!.dimensions)));
  const correlations: Record<string, number | null> = {};
  const constant: string[] = [];
  let worst = 0;
  for (const d of dims) {
    const pairs = scored.flatMap((x) => { const s = (x.placement.score!.dimensions as Record<string, { score: number } | undefined>)[d]; return s ? [[s.score, x.placement.score!.value] as const] : []; });
    const r = pearson(pairs.map((q) => q[0]), pairs.map((q) => q[1]));
    correlations[d] = r;
    if (r === null) constant.push(d);
    else worst = Math.max(worst, Math.abs(r));
  }
  const breach = worst > PAPER_DEFAULTS.maxDimensionCorrelation;
  return {
    status: breach ? "breach" : "healthy",
    correlations, threshold: PAPER_DEFAULTS.maxDimensionCorrelation,
    ...(constant.length ? { constant } : {}),
    note: "Pearson correlation of each dimension with the composite; a constant dimension has none, and may be a placeholder that always scores the same",
    ...(breach ? { diagnosis: "Dimension Collapse" } : {}),
  };
}

function reviewEngagement(row: Validated, records: readonly DecisionRecord[], minSample: number, minPlausibleSeconds: number | undefined): Metric {
  const reviews = records.filter((r) => r.decision.outcome === "review" && r.decision.placements.some((p) => p.row === row.id && p.band === "B"));
  const decided = reviews.filter((r) => r.resolution && (r.resolution.result === "rejected" || (r.resolution.result === "executed" && r.resolution.approval)));
  const approved = decided.filter((r) => r.resolution!.result === "executed").length;
  const latencies = decided.map((r) => r.resolution!.approval?.latency_ms).filter((x): x is number => typeof x === "number").sort((a, b) => a - b);
  const medianSeconds = latencies.length ? latencies[latencies.length >> 1]! / 1000 : undefined;
  const approvalShare = decided.length ? approved / decided.length : undefined;
  const values = { reviews: reviews.length, decided: decided.length, ...(approvalShare !== undefined ? { approvalShare } : {}), ...(medianSeconds !== undefined ? { medianReviewSeconds: medianSeconds } : {}) };
  if (decided.length < minSample) return { status: "insufficient-sample", ...values, note: `${decided.length} decided reviews; at least ${minSample} needed for a verdict` };
  const flood = approvalShare! > PAPER_DEFAULTS.maxApprovalShare;
  const fast = minPlausibleSeconds !== undefined && medianSeconds !== undefined && medianSeconds < minPlausibleSeconds;
  const diagnosis = flood && fast ? "habituation: rubber-stamping" : flood ? "Review Queue Flood: the agent adds delay, not judgment" : fast ? "reviews faster than the plausible minimum" : undefined;
  return {
    status: diagnosis ? "breach" : "healthy", ...values,
    approvalThreshold: PAPER_DEFAULTS.maxApprovalShare, ...(minPlausibleSeconds !== undefined ? { minPlausibleReviewSeconds: minPlausibleSeconds } : {}),
    note: "aggregated per row and its reviewer role, never per named reviewer (where one person holds the role, these are that person's figures); the approval threshold is the paper's default; modifications aren't recorded, only approvals and rejections",
    ...(diagnosis ? { diagnosis } : {}),
  };
}

/** 12. Chain integrity: no spawn outside the matrix's patterns, depth, fan-out or counts. The Guardian
 *  denies those spawns, so what's measured is the attempt: the delegation trying to leave its envelope. */
function chainIntegrity(spawns: readonly SpawnOutcome[]): Metric {
  const allowed = spawns.filter((s) => s.decision === "allow").length;
  const breaches = spawns.filter((s) => s.decision === "deny" && s.reason === "authority_breach").length;
  const outside = spawns.filter((s) => s.decision === "deny" && s.reason === "outside_allowed_patterns").length;
  const faults = spawns.filter((s) => s.decision === "deny").length - breaches - outside;
  const values = { spawns: spawns.length, allowed, authorityBreaches: breaches, outsidePatterns: outside, requestFaults: faults };
  if (spawns.length === 0) return { status: "insufficient-sample", ...values, note: "no spawn was attempted in the period, so there's nothing to judge" };
  if (breaches + outside === 0) return { status: "healthy", ...values, note: "every spawn stayed inside the matrix's patterns and limits, or was a malformed request" };
  return {
    status: "breach", ...values,
    diagnosis: "dynamic delegation operating outside its designed envelope (every such spawn was denied)",
    note: "an attempt past depth, fan-out or count, or of a type no pattern allows; all were denied, so this is the attempt, not a breach that got through",
  };
}

/** 13. Boundary verification: every boundary held as claimed, within its schedule. */
function boundaryVerification(matrix: Validated, probes: readonly ProbeResult[], at: number): Metric {
  const all = assessBoundaries(matrix, probes, at);
  if (all.length === 0) return { status: "not-measured", note: "the matrix relies on no boundaries" };
  const by = (s: string) => all.filter((a) => a.status === s).map((a) => a.boundary);
  const failed = by("failed"), weak = [...by("degraded"), ...by("overdue"), ...by("unverified")];
  const boundaries = Object.fromEntries(all.map((a) => [a.boundary, { status: a.status, claimed: a.claimed, creditedAs: a.creditedAs, rows: a.rows, ...(a.last ? { last: a.last } : {}), ...(a.dueBy ? { dueBy: a.dueBy } : {}), note: a.note }]));
  const diagnosis = failed.length ? `boundary crossed (${failed.join(", ")}): a circuit-breaker event for every dependent row`
    : weak.length ? `counting below their claimed strength: ${weak.join(", ")}` : undefined;
  return { status: diagnosis ? "breach" : "healthy", boundaries, note: "judged at the end of the period; an unverified or overdue boundary counts at policy strength", ...(diagnosis ? { diagnosis } : {}) };
}

/** 7. Required review hours per week against funded reviewer hours. */
function oversightLoad(matrix: Validated, records: readonly DecisionRecord[], weeks: number): Metric {
  const funded = matrix.oversight?.fundedReviewerHoursPerWeek;
  if (typeof funded !== "number") return { status: "not-measured", note: "the matrix declares no funded reviewer hours" };
  const max = matrix.oversight.maxUtilization ?? PAPER_DEFAULTS.maxUtilization;
  let minutes = 0;
  for (const row of matrix.rows as Validated[]) {
    const ov = row.oversight;
    if (!ov) continue;
    for (const r of records) for (const p of r.decision.placements) {
      if (p.row !== row.id) continue;
      if (p.band === "B") minutes += ov.reviewMinutes ?? 0;
      else if (p.band === "C") minutes += ov.escalationMinutes ?? 0;
      else if (p.band === "A") minutes += (ov.auditSampleRate ?? 0) * (ov.auditMinutes ?? 0);
    }
  }
  // Scaling a short period up to a week turns a busy hour into a crisis; an empty period says nothing.
  const days = weeks * 7;
  if (weeks < 1) return { status: "insufficient-sample", fundedHoursPerWeek: funded, periodDays: days, note: `the period is ${days.toFixed(2)} days; review load is judged over at least a week` };
  if (records.length === 0) return { status: "insufficient-sample", fundedHoursPerWeek: funded, periodDays: days, note: "no decisions in the period" };
  const hoursPerWeek = minutes / 60 / weeks;
  const loadFactor = funded > 0 ? hoursPerWeek / funded : hoursPerWeek > 0 ? Number.POSITIVE_INFINITY : 0;
  const breach = loadFactor > max;
  return {
    status: breach ? "breach" : "healthy", requiredHoursPerWeek: hoursPerWeek, fundedHoursPerWeek: funded, loadFactor, maxUtilization: max,
    periodDays: days,
    note: `required hours from the matrix's per-decision review, escalation and audit minutes, over ${days.toFixed(2)} days`,
    ...(breach ? { diagnosis: "Readiness Condition 6 no longer holds: rubber-stamping is the likely next failure" } : {}),
  };
}

/** 11. Scope-denial rate per agent: calls outside the delegation's scope. Agents are software, not people. */
function scopeDenials(records: readonly DecisionRecord[], minSample: number): Record<string, Metric> {
  const by = new Map<string, { calls: number; denied: number }>();
  for (const r of records) {
    const a = by.get(r.request.agent.id) ?? { calls: 0, denied: 0 };
    a.calls++;
    if (r.decision.outcome === "unplaceable" && r.decision.reasons.some((x) => SCOPE_CODES.has(x.code))) a.denied++;
    by.set(r.request.agent.id, a);
  }
  const out: Record<string, Metric> = {};
  for (const [agent, a] of [...by].sort(([x], [y]) => x.localeCompare(y))) {
    out[agent] = { status: a.calls < minSample ? "insufficient-sample" : "no-target", calls: a.calls, scopeDenials: a.denied, rate: a.denied / a.calls, note: "the matrix declares no healthy rate; spikes are for investigation" };
  }
  return out;
}

function pearson(xs: number[], ys: number[]): number | null {
  if (xs.length < 3) return null;
  const n = xs.length, mx = xs.reduce((a, b) => a + b, 0) / n, my = ys.reduce((a, b) => a + b, 0) / n;
  let sxy = 0, sxx = 0, syy = 0;
  for (let i = 0; i < n; i++) { const dx = xs[i]! - mx, dy = ys[i]! - my; sxy += dx * dy; sxx += dx * dx; syy += dy * dy; }
  if (sxx < 1e-12 || syy < 1e-12) return null;
  return sxy / Math.sqrt(sxx * syy);
}
