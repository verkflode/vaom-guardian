import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildRecord, canonicalize, checkRecord, compilePolicy, evaluate, RecordError, resolveRecord, type Call, type EvalContext, type Policy, type RecordInput } from "../src/index.ts";
import { binding, matrix02 } from "./helpers.ts";

const policy: Policy = (() => {
  const r = compilePolicy(matrix02(), binding());
  if (!r.ok) throw new Error("policy");
  return r.policy;
})();
const key = new Uint8Array(32).fill(7);
const scores = {
  "erp:invoice.approve": { value: 0.94, policy: { id: "invoice-standard", version: "3.2" }, verified: true },
  "erp:invoice.flag": { value: 0.9, policy: { id: "invoice-duplicate", version: "1.0" } },
};
const ctx = (usage: Record<string, { total?: string; count: number }> = {}): EvalContext => ({
  scores,
  openContexts: new Set(),
  capUsage: (_r, c, g) => usage[`${c} ${g}`] ?? { total: "0", count: 0 },
});
const approve = (amount: string, vendor = "V-7"): Call => ({ tool: "mcp__erp__approve_invoice", arguments: { invoice_id: "INV-1", vendor_id: vendor, amount, currency: "EUR" } });

function input(call: Call, c: EvalContext = ctx(), extra: Partial<RecordInput> = {}): RecordInput {
  return {
    id: "dec-1",
    ts: "2026-10-02T10:00:00Z",
    agent: { id: "ap-agent", version: "1.4.0", model: { id: "example-model", version: "2026-09" } },
    session: { id: "sess-1" },
    call,
    decision: evaluate(policy, call, c),
    policy,
    scores,
    factKey: key,
    ...extra,
  };
}
const nodeHmac = (data: string) => `hmac-sha256:${createHmac("sha256", key).update(data, "utf8").digest("hex")}`;

describe("building a record", () => {
  it("records the worked example and validates against the schema", () => {
    const r = buildRecord(input(approve("3200")));
    expect(checkRecord(r)).toEqual([]);
    expect(r.format).toBe("vaom.decision/0.3");
    expect(r.decision).toMatchObject({ outcome: "allow", band: "A" });
    expect(r.policy.matrix).toEqual({ id: "example.ap.invoice", version: "1.1.0" });
  });

  it("stores no arguments, only the SHA-256 of their canonical form", () => {
    const call = approve("3200");
    const r = buildRecord(input(call));
    expect(r.request.action.params_digest).toBe(`sha256:${createHash("sha256").update(canonicalize(call.arguments), "utf8").digest("hex")}`);
    expect(JSON.stringify(r.request)).not.toContain("V-7");
  });

  it("records each fact as the binding says: amount in clear, counterparty as a digest", () => {
    const r = buildRecord(input(approve("3200")));
    const facts = r.decision.placements[0]!.facts;
    expect(facts.amount).toEqual({ value: { amount: "3200", currency: "EUR" } });
    expect(facts.task).toEqual({ value: "INV-1" });
    expect(facts.counterparty).toEqual({ digest: nodeHmac('"V-7"') });
    expect(JSON.stringify(r)).not.toContain("V-7");
  });

  it("stores a cap group as a digest when its facts aren't in clear, but keeps the amount", () => {
    const r = buildRecord(input(approve("3200")));
    expect(r.reservations).toEqual([{ cap: "per-vendor-daily", row: "invoice.approve", group: nodeHmac('["V-7"]'), amount: "3200", count: 1 }]);
  });

  it("gives each batch item its own facts", () => {
    const call: Call = { tool: "mcp__erp__approve_invoices", arguments: { invoices: [{ invoice_id: "A", vendor_id: "V-1", amount: "10" }, { invoice_id: "B", vendor_id: "V-2", amount: "20" }] } };
    const r = buildRecord(input(call));
    expect(r.decision.placements.map((p) => p.facts.task)).toEqual([{ value: "A" }, { value: "B" }]);
    expect(checkRecord(r)).toEqual([]);
  });

  it("records only the scores for capabilities the call touched", () => {
    const r = buildRecord(input(approve("3200")));
    expect(Object.keys(r.request.scores ?? {})).toEqual(["erp:invoice.approve"]);
  });

  it("records the wire, context and model when given", () => {
    const r = buildRecord(input(approve("3200"), ctx(), {
      wire: { protocol: "acs", version: "0.1.0", request_id: "6f1c3c1e-0d2b-4b8e-9a5f-1b2c3d4e5f60", chain_hash: "ab".repeat(32) },
      context: { id: "ctx-9", rows: ["invoice.approve"] },
    }));
    expect(r.request.wire?.protocol).toBe("acs");
    expect(r.request.context?.id).toBe("ctx-9");
    expect(checkRecord(r)).toEqual([]);
  });

  it("is reproducible: the same input gives the same record", () => {
    expect(JSON.stringify(buildRecord(input(approve("3200"))))).toBe(JSON.stringify(buildRecord(input(approve("3200")))));
  });
});

describe("no evidence, no action", () => {
  it("refuses to build when a digest is needed and there's no key", () => {
    expect(() => buildRecord(input(approve("3200"), ctx(), { factKey: undefined as unknown as Uint8Array }))).toThrow(RecordError);
    expect(() => buildRecord(input(approve("3200"), ctx(), { factKey: new Uint8Array(0) }))).toThrow(RecordError);
  });
  it("refuses arguments that aren't JSON", () => {
    expect(() => buildRecord(input({ tool: "mcp__erp__approve_invoice", arguments: { invoice_id: "I", vendor_id: "V", amount: "1", currency: "EUR", n: Number.NaN } }))).toThrow(RecordError);
  });
});

describe("reasons never leak a private fact", () => {
  it("an unreadable counterparty is described by type, not value", () => {
    const call: Call = { tool: "mcp__erp__approve_invoice", arguments: { invoice_id: "I", vendor_id: 4242424, amount: "1", currency: "EUR" } };
    const r = buildRecord(input(call));
    expect(r.decision.outcome).toBe("unplaceable");
    expect(JSON.stringify(r)).not.toContain("4242424");
  });
  it("ceiling and cap reasons lose their amounts when the amount is recorded as a digest", () => {
    const b = binding(); b.facts.amount.record = "digest";
    const c = compilePolicy(matrix02(), b);
    if (!c.ok) throw new Error("policy");
    const call = approve("7777");
    const r = buildRecord({ ...input(call), policy: c.policy, decision: evaluate(c.policy, call, ctx()) });
    expect(r.decision.reasons.find((x) => x.code === "ceiling.exceeded")).toEqual({ code: "ceiling.exceeded", row: "invoice.approve" });
    expect(JSON.stringify(r.decision)).not.toContain("7777");
  });
});

describe("resolving a record", () => {
  const approval = { approver_role: "ap-clerk", record: "approval-17", latency_ms: 4200 };

  it("an allowed call resolves as executed", () => {
    const r = resolveRecord(buildRecord(input(approve("3200"))), { ts: "2026-10-02T10:00:01Z", result: "executed" });
    expect(checkRecord(r)).toEqual([]);
  });
  it("a review executes only on an approval record from the named reviewer", () => {
    const rec = buildRecord(input(approve("6000")));
    expect(rec.decision.outcome).toBe("review");
    expect(() => resolveRecord(rec, { ts: "2026-10-02T10:05:00Z", result: "executed" })).toThrow(/approval record/);
    expect(() => resolveRecord(rec, { ts: "2026-10-02T10:05:00Z", result: "executed", approval: { ...approval, approver_role: "finance-controller" } })).toThrow(/named ap-clerk/);
    expect(checkRecord(resolveRecord(rec, { ts: "2026-10-02T10:05:00Z", result: "executed", approval }))).toEqual([]);
  });
  it("a refused or unplaceable decision can only resolve as not-executed", () => {
    const rec = buildRecord(input({ tool: "mcp__erp__pay_invoice", arguments: {} }));
    expect(rec.decision.outcome).toBe("unplaceable");
    // The explicit check, by its own message; the schema enforces the same rule as a second layer (tested below).
    expect(() => resolveRecord(rec, { ts: "2026-10-02T10:00:01Z", result: "executed" })).toThrow(/can only resolve as not-executed/);
    expect(checkRecord(resolveRecord(rec, { ts: "2026-10-02T10:00:01Z", result: "not-executed" }))).toEqual([]);
  });
  it("an allow can't be rejected, and a record resolves once", () => {
    const rec = buildRecord(input(approve("3200")));
    expect(() => resolveRecord(rec, { ts: "2026-10-02T10:00:01Z", result: "rejected" })).toThrow(RecordError);
    const done = resolveRecord(rec, { ts: "2026-10-02T10:00:01Z", result: "executed" });
    expect(() => resolveRecord(done, { ts: "2026-10-02T10:00:02Z", result: "executed" })).toThrow(/already resolved/);
  });
});

describe("the schema holds the same rules on its own", () => {
  it("rejects an executed review without an approval, and an executed refusal", () => {
    const rec = buildRecord(input(approve("6000")));
    expect(checkRecord({ ...rec, resolution: { ts: "2026-10-02T10:00:01Z", result: "executed" } }).length).toBeGreaterThan(0);
    const un = buildRecord(input({ tool: "mcp__erp__pay_invoice", arguments: {} }));
    expect(checkRecord({ ...un, resolution: { ts: "2026-10-02T10:00:01Z", result: "executed" } }).length).toBeGreaterThan(0);
  });
});
