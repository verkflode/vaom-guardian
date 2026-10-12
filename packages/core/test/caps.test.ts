import { describe, expect, it } from "vitest";
import { CapLedger, compilePolicy, ContextRegistry, decide, evaluate, resolveRecord, type Call, type DecideInput, type DecisionRecord, type Policy } from "../src/index.ts";
import { binding, matrix02, quietScoring } from "./helpers.ts";

// invoice.approve has a per-vendor daily cap of EUR 5,000 (breach: review) and a ceiling of EUR 5,000.
// Scoring without anomaly signals, so a fresh ledger's unfamiliar vendors don't decide the band here.
const policy: Policy = (() => {
  const r = compilePolicy(matrix02(), binding(), quietScoring());
  if (!r.ok) throw new Error("policy");
  return r.policy;
})();
const factKey = new Uint8Array(32).fill(9);
const verifications = { "erp:invoice.approve": true };
const approve = (amount: string, vendor = "V-7", id = "INV"): Call => ({ tool: "mcp__erp__approve_invoice", arguments: { invoice_id: id, vendor_id: vendor, amount, currency: "EUR", po_number: "PO-1" } });

let n = 0;
// Each call runs under a context opened at its own time (contexts live 15 minutes; some tests span a day).
const inputAt = (ts: string, extra: Partial<DecideInput> = {}): DecideInput => {
  const contexts = new ContextRegistry(policy);
  contexts.open({ id: `ctx-${n + 1}`, session: "s1", agent: { id: "ap-agent" }, rows: ["invoice.approve"] }, Date.parse(ts));
  return { id: `dec-${++n}`, ts, agent: { id: "ap-agent" }, session: { id: "s1" }, verifications, factKey, contexts, ...extra };
};
const fresh = () => { const l = new CapLedger(); l.load([]); return l; };
const tick = () => new Promise<void>((r) => setTimeout(r, 0));

describe("the parallel-split attack", () => {
  it("two parallel 3,000 approvals to one vendor: through decide(), the second lands in review", async () => {
    const ledger = fresh();
    // Each request awaits I/O before deciding and after (as a real Guardian does around persistence);
    // decide() itself is synchronous, so nothing interleaves between reading usage and reserving.
    const request = async (id: string) => { await tick(); const rec = decide(policy, approve("3000", "V-7", id), ledger, inputAt("2026-10-02T09:00:00Z")); await tick(); return rec; };
    const [a, b] = await Promise.all([request("I-1"), request("I-2")]);
    expect([a.decision.band, b.decision.band].sort()).toEqual(["A", "B"]);
    expect([a, b].find((r) => r.decision.band === "B")!.decision.reasons.map((r) => r.code)).toContain("cap.breached");
  });

  it("control: a naive evaluate-then-reserve with a pause in between lets both through", async () => {
    // This is the bug the atomic step prevents: both requests read usage 0 before either reserves.
    const ledger = fresh();
    const naive = async (id: string) => {
      const ts = "2026-10-02T09:00:00Z", now = Date.parse(ts);
      const d = evaluate(policy, approve("3000", "V-7", id), { now, verifications, contexts: [{ id: "c", rows: ["invoice.approve"] }], capUsage: (row, cap, g) => ledger.usage(row, cap, g, now, 86_400_000) });
      await tick(); // e.g. awaiting a database write
      ledger.reserve({ id, request: { ts }, decision: { placements: [] }, reservations: d.reservations.map((r) => ({ cap: r.capId, row: r.row, group: r.groupKey, amount: r.amount!, count: 1 })) } as unknown as DecisionRecord);
      return d;
    };
    const [a, b] = await Promise.all([naive("N-1"), naive("N-2")]);
    expect([a.band, b.band]).toEqual(["A", "A"]);
  });
});

describe("decide() judges the matrix's window at the call's own time", () => {
  it("a call stamped before the matrix takes effect is unplaceable, and reserves nothing", () => {
    const ledger = fresh();
    const r = decide(policy, approve("100"), ledger, inputAt("2026-09-30T12:00:00Z"));
    expect(r.decision.outcome).toBe("unplaceable");
    expect(r.decision.reasons.map((x) => x.code)).toEqual(["matrix.not-in-effect"]);
    expect(r.reservations).toEqual([]);
    expect(decide(policy, approve("100"), ledger, inputAt("2026-10-02T12:00:00Z")).decision.outcome).toBe("allow");
  });
});

describe("what counts against a cap", () => {
  it("a pending review counts as used", () => {
    const ledger = fresh();
    const big = decide(policy, { ...approve("4500", "V-7", "I-1"), statedCertainty: 0.8 }, ledger, inputAt("2026-10-02T09:00:00Z"));
    expect(big.decision.outcome).toBe("review");
    expect(decide(policy, approve("1000", "V-7", "I-2"), ledger, inputAt("2026-10-02T09:01:00Z")).decision.band).toBe("B");
  });

  it("a rejected or expired decision releases its use; an executed one keeps it", () => {
    for (const [result, expected] of [["rejected", "A"], ["expired", "A"], ["withdrawn", "A"], ["executed", "B"]] as const) {
      const ledger = fresh();
      const first = decide(policy, approve("4500", "V-7", "I-1"), ledger, inputAt("2026-10-02T09:00:00Z"));
      ledger.settle(first.id, result);
      expect(decide(policy, approve("1000", "V-7", "I-2"), ledger, inputAt("2026-10-02T09:01:00Z")).decision.band, result).toBe(expected);
    }
  });

  it("uses age out of the rolling window", () => {
    const ledger = fresh();
    decide(policy, approve("4500", "V-7", "I-1"), ledger, inputAt("2026-10-02T09:00:00Z"));
    expect(decide(policy, approve("1000", "V-7", "I-2"), ledger, inputAt("2026-10-03T08:59:59Z")).decision.band).toBe("B");
    expect(decide(policy, approve("1000", "V-7", "I-3"), ledger, inputAt("2026-10-03T09:00:01Z")).decision.band).toBe("A");
  });

  it("caps are per group: another vendor has its own room", () => {
    const ledger = fresh();
    decide(policy, approve("4500", "V-7"), ledger, inputAt("2026-10-02T09:00:00Z"));
    expect(decide(policy, approve("4500", "V-8"), ledger, inputAt("2026-10-02T09:01:00Z")).decision.band).toBe("A");
  });

  it("refused and unplaceable decisions reserve nothing", () => {
    const ledger = fresh();
    const un = decide(policy, { tool: "mcp__erp__pay_invoice", arguments: {} }, ledger, inputAt("2026-10-02T09:00:00Z"));
    expect(un.decision.outcome).toBe("unplaceable");
    expect(un.reservations).toEqual([]);
  });
});

describe("fail closed on unknown history", () => {
  it("an unloaded ledger can't say what was used", () => {
    expect(new CapLedger().usage("invoice.approve", "per-vendor-daily", "x", Date.now(), 86_400_000)).toBeNull();
  });
  it("decide() throws until the ledger is loaded, and reserves nothing", () => {
    const ledger = new CapLedger();
    expect(() => decide(policy, approve("100"), ledger, inputAt("2026-10-02T09:00:00Z"))).toThrow(/not loaded/);
    ledger.load([]);
    expect(decide(policy, approve("100"), ledger, inputAt("2026-10-02T09:00:00Z")).decision.band).toBe("A");
  });

  it("a ledger rebuilt from records gives the same usage as the live one", () => {
    const live = fresh();
    const records = [
      decide(policy, approve("2000", "V-7", "I-1"), live, inputAt("2026-10-02T09:00:00Z")),
      decide(policy, approve("2500", "V-7", "I-2"), live, inputAt("2026-10-02T09:05:00Z")),
    ];
    const rejected = resolveRecord(decide(policy, approve("4000", "V-9", "I-3"), live, inputAt("2026-10-02T09:06:00Z")), { ts: "2026-10-02T09:07:00Z", result: "withdrawn" });
    live.settle(rejected.id, "withdrawn");
    // The group key is recorded as a digest (counterparty is private), and the rebuilt ledger keys on it too.
    expect(records[0]!.reservations[0]!.group).toMatch(/^hmac-sha256:/);
    const rebuilt = new CapLedger();
    rebuilt.load([...records, rejected].reverse());
    const next = (l: CapLedger) => decide(policy, approve("600", "V-7", "I-4"), l, inputAt("2026-10-02T09:10:00Z", { id: "next" })).decision.band;
    expect(next(rebuilt)).toBe(next(live));
    expect(next(fresh())).toBe("A");
    const v9 = (l: CapLedger) => decide(policy, approve("4500", "V-9", "I-5"), l, inputAt("2026-10-02T09:11:00Z", { id: "v9" })).decision.band;
    expect(v9(rebuilt)).toBe("A");
  });
});

describe("no evidence, no action", () => {
  it("if the record can't be built, nothing is reserved", () => {
    // Two different failures: no key for the digests, and arguments that aren't JSON (with a valid key,
    // so the failure is in building the record, not in computing the cap group).
    const ledger = fresh();
    expect(() => decide(policy, approve("4500"), ledger, inputAt("2026-10-02T09:00:00Z", { factKey: new Uint8Array(0) }))).toThrow();
    const notJson: Call = { tool: "mcp__erp__approve_invoice", arguments: { invoice_id: "X", vendor_id: "V-7", amount: "4500", currency: "EUR", note: Number.NaN } };
    expect(() => decide(policy, notJson, ledger, inputAt("2026-10-02T09:00:30Z"))).toThrow(/aren't JSON/);
    expect(decide(policy, approve("4500"), ledger, inputAt("2026-10-02T09:01:00Z")).decision.band).toBe("A");
  });
  it("a reservation whose record never went out can be released", () => {
    const ledger = fresh();
    const rec = decide(policy, approve("4500"), ledger, inputAt("2026-10-02T09:00:00Z"));
    ledger.release(rec.id);
    expect(decide(policy, approve("4500"), ledger, inputAt("2026-10-02T09:01:00Z")).decision.band).toBe("A");
  });
  it("a decision id can't reserve twice", () => {
    const ledger = fresh();
    decide(policy, approve("100"), ledger, inputAt("2026-10-02T09:00:00Z", { id: "same" }));
    expect(() => decide(policy, approve("100"), ledger, inputAt("2026-10-02T09:00:01Z", { id: "same" }))).toThrow(/already holds/);
  });
});
