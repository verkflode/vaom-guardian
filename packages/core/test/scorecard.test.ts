import { describe, expect, it } from "vitest";
import { CapLedger, compilePolicy, ContextRegistry, decide, resolveRecord, scorecard, type DecisionRecord } from "../src/index.ts";
import { binding, matrix02, quietScoring } from "./helpers.ts";

// The invoice matrix 0.2: rows invoice.approve (expected per week A 1200, B 300, C 20; review 6 min,
// escalation 20 min, audit 5% x 4 min, plausible review 45 s) and invoice.duplicate-anomaly; funded
// reviewer hours 60 a week at 80% utilization.
const FROM = "2026-10-05T00:00:00Z", TO = "2026-10-12T00:00:00Z";
const period = { from: FROM, to: TO };

let n = 0;
type Opts = {
  row?: string; band?: "A" | "B" | "C" | "non-delegable" | null; outcome?: DecisionRecord["decision"]["outcome"]; agent?: string; ts?: string;
  reasons?: { code: string; row?: string }[]; result?: "executed" | "rejected" | "expired" | "not-executed"; latencyMs?: number;
  score?: { value: number; dimensions: Record<string, { score: number }>; verified?: boolean };
};
/** A record with only what the scorecard reads. */
function rec(o: Opts = {}): DecisionRecord {
  const band = o.band === undefined ? "A" : o.band;
  const outcome = o.outcome ?? (band === "A" ? "allow" : band === "B" ? "review" : band === "C" ? "escalate" : band === null ? "unplaceable" : "refuse");
  const row = o.row ?? "invoice.approve";
  const approval = o.result === "executed" && (outcome === "review" || outcome === "escalate")
    ? { approval: { approver_role: "ap-clerk", approver_id: "reviewer-jane", record: `ap-${n}`, ...(o.latencyMs !== undefined ? { latency_ms: o.latencyMs } : {}) } } : {};
  return {
    format: "vaom.decision/0.4", id: `r-${++n}`,
    request: { ts: o.ts ?? "2026-10-06T09:00:00Z", agent: { id: o.agent ?? "ap-agent" }, session: { id: "s" }, action: { tool: "t", params_digest: `sha256:${"0".repeat(64)}` } },
    policy: { matrix: { id: "example.ap.invoice", version: "1.1.0" }, binding: { id: "b", version: "0.3.0" } },
    decision: {
      outcome, band, placements: [{ row, capability: "c", entry: "e", band, outcome, facts: {}, ...(o.score ? { score: { policy: { id: "p", version: "1" }, level: "high", ...o.score } } : {}) }],
      reasons: o.reasons ?? [],
    },
    reservations: [],
    ...(o.result ? { resolution: { ts: "2026-10-06T09:05:00Z", result: o.result, ...approval } } : {}),
  } as DecisionRecord;
}
const many = (k: number, o: Opts | ((i: number) => Opts)) => Array.from({ length: k }, (_, i) => rec(typeof o === "function" ? o(i) : o));
const row = (s: ReturnType<typeof scorecard>, id = "invoice.approve") => s.rows.find((r) => r.row === id)!;

describe("the scorecard's shape", () => {
  it("covers each delegable row, only records inside the period, and names what it can't measure", () => {
    const s = scorecard(matrix02(), [rec(), rec({ ts: "2026-10-12T00:00:00Z" }), rec({ ts: "2026-10-04T23:59:59Z" })], period);
    expect(s.format).toBe("vaom.scorecard/0.1");
    expect(s.records).toBe(1);
    expect(s.rows.map((r) => r.row)).toEqual(["invoice.approve", "invoice.duplicate-anomaly"]);
    const m = row(s).metrics;
    for (const k of ["bandAErrorRate", "staleKnowledgeShare", "seededDetection"]) expect(m[k]!.status).toBe("not-measured");
    // The invoice matrix relies on a boundary nobody has probed: it counts at policy strength, a breach.
    expect(s.workflow.boundaryVerification).toMatchObject({ status: "breach", boundaries: { "no-contract-write": { status: "unverified", creditedAs: "policy" } } });
  });
  it("refuses a period that isn't one", () => {
    expect(() => scorecard(matrix02(), [], { from: TO, to: FROM })).toThrow();
    expect(() => scorecard(matrix02(), [], { from: "soon", to: TO })).toThrow();
  });
  it("gives no verdict below the minimum sample", () => {
    const m = row(scorecard(matrix02(), many(19, { band: "A", reasons: [{ code: "restriction", row: "invoice.approve" }] }), period)).metrics;
    expect(m.exceptionPathShare).toMatchObject({ status: "insufficient-sample", share: 1 });
  });
});

describe("calibration health", () => {
  it("band distribution: observed shares beside the shares expected at design, with no verdict", () => {
    const rs = [...many(15, { band: "A" }), ...many(4, { band: "B" }), rec({ band: "C" }), rec({ band: null })];
    const m = row(scorecard(matrix02(), rs, period)).metrics.bandDistribution!;
    expect(m).toMatchObject({ status: "no-target", counts: { A: 15, B: 4, C: 1 }, observed: { A: 0.75, B: 0.2, C: 0.05 } });
    expect((m.expected as { A: number }).A).toBeCloseTo(1200 / 1520, 12);
  });
  it("exception-path share: decisions a restriction placed, against the paper's 15%", () => {
    const r = (k: number) => [...many(k, { band: "B", reasons: [{ code: "restriction", row: "invoice.approve" }] }), ...many(20 - k, { band: "A" })];
    expect(row(scorecard(matrix02(), r(3), period)).metrics.exceptionPathShare).toMatchObject({ status: "healthy", share: 0.15 });
    expect(row(scorecard(matrix02(), r(4), period)).metrics.exceptionPathShare).toMatchObject({ status: "breach", diagnosis: "Exception Graveyard" });
  });
  it("a restriction on another row doesn't count as this row's exception", () => {
    const rs = many(20, { band: "B", reasons: [{ code: "restriction", row: "invoice.duplicate-anomaly" }] });
    expect(row(scorecard(matrix02(), rs, period)).metrics.exceptionPathShare).toMatchObject({ status: "healthy", share: 0 });
  });
  it("dimension correlation: a composite that tracks one dimension is a Dimension Collapse; a constant dimension is named", () => {
    const collapsed = many(20, (i) => ({ score: { value: 0.5 + i / 50, dimensions: { ruleMatch: { score: 0.5 + i / 50 }, dataCompleteness: { score: 1 } } } }));
    const m = row(scorecard(matrix02(), collapsed, period)).metrics.dimensionCorrelation!;
    expect(m).toMatchObject({ status: "breach", diagnosis: "Dimension Collapse", constant: ["dataCompleteness"] });
    expect((m.correlations as Record<string, number>).ruleMatch).toBeCloseTo(1, 12);
    const mixed = many(20, (i) => { const a = (i % 5) / 4, b = Math.floor(i / 5) / 3; return { score: { value: (a + b) / 2, dimensions: { ruleMatch: { score: a }, anomaly: { score: b } } } }; });
    expect(row(scorecard(matrix02(), mixed, period)).metrics.dimensionCorrelation!.status).toBe("healthy");
  });
  it("verifier effectiveness: not measured without verdicts; never disagreeing is theater", () => {
    const s = (v?: boolean) => ({ value: 1, dimensions: {}, ...(v !== undefined ? { verified: v } : {}) });
    expect(row(scorecard(matrix02(), many(20, { score: s() }), period)).metrics.verifierEffectiveness!.status).toBe("not-measured");
    expect(row(scorecard(matrix02(), many(20, { score: s(true) }), period)).metrics.verifierEffectiveness).toMatchObject({ status: "breach", disagreement: 0, diagnosis: "verification theater" });
    expect(row(scorecard(matrix02(), many(20, (i) => ({ score: s(i !== 0) })), period)).metrics.verifierEffectiveness).toMatchObject({ status: "healthy", disagreement: 0.05 });
  });
});

describe("oversight health", () => {
  const review = (approved: boolean, seconds: number) => rec({ band: "B", result: approved ? "executed" : "rejected", latencyMs: seconds * 1000 });
  it("review engagement: approving nearly everything is a Review Queue Flood", () => {
    const rs = [...Array.from({ length: 19 }, () => review(true, 120)), review(false, 120)];
    expect(row(scorecard(matrix02(), rs, period)).metrics.reviewEngagement).toMatchObject({ status: "breach", approvalShare: 0.95, diagnosis: "Review Queue Flood: the agent adds delay, not judgment" });
  });
  it("review engagement: approving everything, fast, is habituation", () => {
    const rs = Array.from({ length: 20 }, () => review(true, 10));
    expect(row(scorecard(matrix02(), rs, period)).metrics.reviewEngagement).toMatchObject({ status: "breach", medianReviewSeconds: 10, diagnosis: "habituation: rubber-stamping" });
  });
  it("review engagement: rejecting a visible share, at a plausible pace, is healthy; expired reviews aren't decisions", () => {
    const rs = [...Array.from({ length: 16 }, () => review(true, 120)), ...Array.from({ length: 4 }, () => review(false, 90)), ...many(5, { band: "B", result: "expired" })];
    expect(row(scorecard(matrix02(), rs, period)).metrics.reviewEngagement).toMatchObject({ status: "healthy", reviews: 25, decided: 20, approvalShare: 0.8 });
  });
  it("reports nothing about individual reviewers, whatever the records hold", () => {
    const rs = Array.from({ length: 20 }, () => review(true, 120));
    expect(rs[0]!.resolution?.approval?.approver_id).toBe("reviewer-jane");
    expect(JSON.stringify(scorecard(matrix02(), rs, period))).not.toContain("reviewer-jane");
  });
  it("oversight load: required hours a week against funded hours, at the matrix's utilization ceiling", () => {
    // 450 reviews x 6 min = 45 h in one week, against 60 h funded: 0.75, under 0.8.
    expect(scorecard(matrix02(), many(450, { band: "B" }), period).workflow.oversightLoad).toMatchObject({ status: "healthy", requiredHoursPerWeek: 45, loadFactor: 0.75 });
    // 500 reviews: 50 h, 0.83.
    expect(scorecard(matrix02(), many(500, { band: "B" }), period).workflow.oversightLoad).toMatchObject({ status: "breach" });
    // Band A costs its audit sample: 1000 x 5% x 4 min = 200 min.
    expect(scorecard(matrix02(), many(1000, { band: "A" }), period).workflow.oversightLoad!.requiredHoursPerWeek).toBeCloseTo(200 / 60, 12);
  });
  it("escalations: how many expired, with no verdict while the matrix declares no SLA", () => {
    const rs = [rec({ band: "C", result: "executed" }), rec({ band: "C", result: "expired" }), rec({ band: "C" })];
    expect(row(scorecard(matrix02(), rs, period)).metrics.escalationSla).toMatchObject({ status: "no-target", escalations: 3, resolved: 2, expired: 1 });
  });
});

describe("enforcement health", () => {
  it("scope-denial rate per agent counts calls outside the delegation's scope, not other refusals", () => {
    const rs = [
      ...many(18, { agent: "ap-agent" }),
      rec({ agent: "ap-agent", band: null, reasons: [{ code: "context.scope" }] }),
      rec({ agent: "ap-agent", band: null, reasons: [{ code: "fact.missing" }] }),
      rec({ agent: "intruder", band: null, reasons: [{ code: "unmapped" }] }),
    ];
    const a = scorecard(matrix02(), rs, period).agents;
    expect(a["ap-agent"]).toMatchObject({ status: "no-target", calls: 20, scopeDenials: 1, rate: 0.05 });
    expect(a.intruder).toMatchObject({ status: "insufficient-sample", calls: 1, scopeDenials: 1 });
  });
});

describe("chain integrity (metric 12)", () => {
  const sp = (decision: "allow" | "deny", reason: string, ts = "2026-10-06T09:00:00Z") => ({ ts, decision, reason });
  it("no spawn outside the envelope: healthy, even with malformed requests", () => {
    const m = scorecard(matrix02(), [], { ...period, spawns: [sp("allow", "context_derived"), sp("deny", "parent_session_mismatch")] }).workflow.chainIntegrity;
    expect(m).toMatchObject({ status: "healthy", spawns: 2, allowed: 1, authorityBreaches: 0, outsidePatterns: 0, requestFaults: 1 });
  });
  it("a spawn past the limits or outside the patterns, though denied, is a breach: the attempt is the signal", () => {
    expect(scorecard(matrix02(), [], { ...period, spawns: [sp("deny", "authority_breach")] }).workflow.chainIntegrity).toMatchObject({ status: "breach", authorityBreaches: 1 });
    expect(scorecard(matrix02(), [], { ...period, spawns: [sp("deny", "outside_allowed_patterns")] }).workflow.chainIntegrity).toMatchObject({ status: "breach", outsidePatterns: 1 });
  });
  it("only spawns inside the period count", () => {
    expect(scorecard(matrix02(), [], { ...period, spawns: [sp("deny", "authority_breach", "2026-10-01T00:00:00Z")] }).workflow.chainIntegrity!.status).toBe("healthy");
  });
});

describe("from real records", () => {
  it("reads what decide() and resolveRecord() write", () => {
    const r = compilePolicy(matrix02(), binding(), quietScoring());
    if (!r.ok) throw new Error("policy");
    const ledger = new CapLedger(); ledger.load([]);
    const records: DecisionRecord[] = [];
    for (let i = 0; i < 25; i++) {
      const ts = new Date(Date.parse("2026-10-06T08:00:00Z") + i * 600_000).toISOString();
      const contexts = new ContextRegistry(r.policy);
      contexts.open({ id: `c${i}`, session: "s", agent: { id: "ap" }, rows: ["invoice.approve"] }, Date.parse(ts));
      // Without a verifier every high score stops at review; the clerk approves 20 of 25.
      const d = decide(r.policy, { tool: "mcp__erp__approve_invoice", arguments: { invoice_id: `I${i}`, vendor_id: `V${i}`, amount: "100", currency: "EUR", po_number: "PO" } }, ledger, { id: `d${i}`, ts, agent: { id: "ap" }, session: { id: "s" }, contexts, factKey: new Uint8Array(32).fill(1) });
      records.push(resolveRecord(d, i < 20 ? { ts, result: "executed", approval: { approver_role: "ap-clerk", record: `a${i}`, latency_ms: 90_000 } } : { ts, result: "rejected" }));
    }
    const m = row(scorecard(matrix02(), records, period)).metrics;
    expect(m.bandDistribution).toMatchObject({ counts: { A: 0, B: 25, C: 0 } });
    expect(m.reviewEngagement).toMatchObject({ status: "healthy", approvalShare: 0.8, medianReviewSeconds: 90 });
    expect(m.verifierEffectiveness!.status).toBe("not-measured");
  });
});
