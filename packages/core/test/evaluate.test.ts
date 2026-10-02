import { describe, expect, it } from "vitest";
import { compilePolicy, evaluate, type CapUsage, type Decision, type EvalContext, type Policy } from "../src/index.ts";
import { binding, matrix02, type Doc } from "./helpers.ts";

// The invoice matrix 0.2 and its Claude Code binding. invoice.approve: routing high A / medium B / low C,
// thresholds 0.92 / 0.70, scoring policy invoice-standard@3.2 with verification required, ceiling 5000 EUR
// (over it: B), per-vendor daily cap 5000 EUR (breach: B), reviewer ap-clerk, escalation finance-controller.
function compile(m: Doc = matrix02(), b: Doc = binding()): Policy {
  const r = compilePolicy(m, b);
  if (!r.ok) throw new Error(`policy didn't compile: ${JSON.stringify(r.findings)}`);
  return r.policy;
}

const approveScore = (value: number, verified = true) => ({ "erp:invoice.approve": { value, policy: { id: "invoice-standard", version: "3.2" }, verified } });

function ctx(over: Partial<EvalContext> & { usage?: Record<string, CapUsage | null> } = {}): EvalContext {
  const usage = over.usage ?? {};
  return {
    scores: over.scores ?? approveScore(0.94),
    contexts: over.contexts ?? [{ id: "ctx-1", rows: ["invoice.approve", "invoice.duplicate-anomaly"] }],
    capUsage: (_row, capId, groupKey) => (`${capId} ${groupKey}` in usage ? usage[`${capId} ${groupKey}`]! : { total: "0", count: 0 }),
  };
}

const approve = (amount: unknown, extra: Record<string, unknown> = {}) => ({
  tool: "mcp__erp__approve_invoice",
  arguments: { invoice_id: "INV-1", vendor_id: "V-7", amount, currency: "EUR", ...extra },
});
const codes = (d: Decision) => d.reasons.map((r) => r.code);

describe("compilePolicy", () => {
  it("compiles the invoice matrix and binding", () => {
    expect(compilePolicy(matrix02(), binding()).ok).toBe(true);
  });
  it("refuses a policy that doesn't lint clean", () => {
    const b = binding(); b.matrix.id = "someone.else";
    const r = compilePolicy(matrix02(), b);
    expect(r.ok).toBe(false);
  });
});

describe("the worked example: invoice of EUR 3,200", () => {
  const p = compile();

  it("high confidence, verified, under the ceiling: Band A, allow", () => {
    const d = evaluate(p, approve("3200"), ctx());
    expect(d.outcome).toBe("allow");
    expect(d.band).toBe("A");
    expect(d.placements[0]!.row).toBe("invoice.approve");
    expect(d.policy).toEqual({ matrix: { id: "example.ap.invoice", version: "1.1.0" }, binding: { id: "example.ap.invoice.claude-code", version: "0.2.0" } });
  });

  it("reserves its cap use, for the cap store to hold before allowing", () => {
    const d = evaluate(p, approve("3200"), ctx());
    expect(d.reservations).toEqual([{ capId: "per-vendor-daily", row: "invoice.approve", groupKey: '["V-7"]', amount: "3200", count: 1 }]);
  });

  it("without independent verification, Band A drops to review", () => {
    const d = evaluate(p, approve("3200"), ctx({ scores: approveScore(0.94, false) }));
    expect([d.outcome, d.band, d.approverRole]).toEqual(["review", "B", "ap-clerk"]);
    expect(codes(d)).toContain("verification.missing");
  });

  it("medium confidence: review by the reviewer", () => {
    const d = evaluate(p, approve("3200"), ctx({ scores: approveScore(0.8) }));
    expect([d.outcome, d.band, d.approverRole]).toEqual(["review", "B", "ap-clerk"]);
  });

  it("low confidence: escalation to the escalation role", () => {
    const d = evaluate(p, approve("3200"), ctx({ scores: approveScore(0.5) }));
    expect([d.outcome, d.band, d.approverRole]).toEqual(["escalate", "C", "finance-controller"]);
  });

  it("thresholds are inclusive: exactly 0.92 is high", () => {
    expect(evaluate(p, approve("3200"), ctx({ scores: approveScore(0.92) })).band).toBe("A");
    expect(evaluate(p, approve("3200"), ctx({ scores: approveScore(0.9199) })).band).toBe("B");
  });
});

describe("confidence never comes from the wrong place", () => {
  const p = compile();
  it("no score routes at low", () => {
    const d = evaluate(p, approve("3200"), ctx({ scores: {} }));
    expect(d.band).toBe("C");
    expect(codes(d)).toContain("confidence.no-score");
  });
  it("a score from another scoring policy counts as no score", () => {
    const d = evaluate(p, approve("3200"), ctx({ scores: { "erp:invoice.approve": { value: 0.99, policy: { id: "invoice-standard", version: "3.1" }, verified: true } } }));
    expect(d.band).toBe("C");
    expect(codes(d)).toContain("confidence.wrong-policy");
  });
  it("a non-finite score counts as invalid", () => {
    expect(evaluate(p, approve("3200"), ctx({ scores: approveScore(Number.NaN) })).band).toBe("C");
  });
});

describe("limits only narrow", () => {
  const p = compile();
  it("over the ceiling: review", () => {
    const d = evaluate(p, approve("6000"), ctx());
    expect([d.outcome, d.band]).toEqual(["review", "B"]);
    expect(codes(d)).toContain("ceiling.exceeded");
  });
  it("exactly at the ceiling is within it", () => {
    expect(evaluate(p, approve("5000"), ctx()).band).toBe("A");
    expect(evaluate(p, approve("5000.01"), ctx()).band).toBe("B");
  });
  it("the ceiling holds on its own, with no cap in play", () => {
    // In the example the daily cap equals the ceiling, so over-ceiling amounts also breach the cap.
    // Remove the cap to prove the ceiling alone moves the band.
    const m = matrix02(); delete m.rows[0].authority.cumulativeCaps;
    const pp = compile(m);
    const over = evaluate(pp, approve("6000"), ctx());
    expect(over.band).toBe("B");
    expect(codes(over)).not.toContain("cap.breached");
    expect(evaluate(pp, approve("5000.01"), ctx()).band).toBe("B");
    expect(evaluate(pp, approve("5000"), ctx()).band).toBe("A");
  });
  it("the cap holds on its own, under the ceiling", () => {
    const d = evaluate(p, approve("4000"), ctx({ usage: { 'per-vendor-daily ["V-7"]': { total: "1500", count: 1 } } }));
    expect(d.band).toBe("B");
    expect(codes(d)).not.toContain("ceiling.exceeded");
  });
  it("over the ceiling at low confidence stays at the stricter band", () => {
    expect(evaluate(p, approve("6000"), ctx({ scores: approveScore(0.5) })).band).toBe("C");
  });
  it("a cumulative cap breach moves the call to review", () => {
    const d = evaluate(p, approve("3200"), ctx({ usage: { 'per-vendor-daily ["V-7"]': { total: "3000", count: 1 } } }));
    expect(d.band).toBe("B");
    expect(codes(d)).toContain("cap.breached");
  });
  it("another vendor's usage doesn't count", () => {
    expect(evaluate(p, approve("3200"), ctx({ usage: { 'per-vendor-daily ["V-9"]': { total: "4900", count: 3 } } })).band).toBe("A");
  });
  it("unreadable cap history counts as breached", () => {
    const d = evaluate(p, approve("100"), ctx({ usage: { 'per-vendor-daily ["V-7"]': null } }));
    expect(d.band).toBe("B");
    expect(codes(d)).toContain("cap.history-unreadable");
  });
  it("a restriction pushes a call to its band", () => {
    const m = matrix02(), b = binding();
    m.rows[0].authority.restrictions = [{ id: "pep", when: { fact: "pep", op: "eq", value: true }, band: "C" }];
    b.facts.pep = { type: "boolean" };
    for (const t of b.tools) if (t.capability === "erp:invoice.approve") (t.items ? t.items.facts : t.facts).pep = { arg: "/pep" };
    const pp = compile(m, b);
    expect(evaluate(pp, approve("3200", { pep: true }), ctx()).band).toBe("C");
    expect(evaluate(pp, approve("3200", { pep: false }), ctx()).band).toBe("A");
    expect(evaluate(pp, approve("3200"), ctx()).outcome).toBe("unplaceable");
  });
});

describe("batches can't slip under a ceiling or a cap", () => {
  const p = compile();
  const batch = (items: unknown[]) => ({ tool: "mcp__erp__approve_invoices", arguments: { invoices: items } });
  const inv = (id: string, amount: string, vendor = "V-7") => ({ invoice_id: id, vendor_id: vendor, amount });

  it("three invoices of 2,000 to one vendor: the third breaches the daily cap", () => {
    const d = evaluate(p, batch([inv("A", "2000"), inv("B", "2000"), inv("C", "2000")]), ctx());
    expect(d.band).toBe("B");
    expect(d.placements.map((x) => x.band)).toEqual(["A", "A", "B"]);
    expect(d.reservations).toHaveLength(3);
  });
  it("the same amounts spread over three vendors stay in Band A", () => {
    expect(evaluate(p, batch([inv("A", "2000", "V-1"), inv("B", "2000", "V-2"), inv("C", "2000", "V-3")]), ctx()).band).toBe("A");
  });
  it("one item over the ceiling makes the whole call review", () => {
    expect(evaluate(p, batch([inv("A", "100", "V-1"), inv("B", "7000", "V-2")]), ctx()).band).toBe("B");
  });
  it("an empty or oversized batch is unplaceable", () => {
    expect(evaluate(p, batch([]), ctx()).outcome).toBe("unplaceable");
    expect(evaluate(p, batch(Array.from({ length: 51 }, (_, i) => inv(`I${i}`, "1", `V${i}`))), ctx()).outcome).toBe("unplaceable");
  });
});

describe("what can't be placed is never allowed", () => {
  const p = compile();
  const cases: [string, Parameters<typeof evaluate>[1], EvalContext, string][] = [
    ["unmapped tool", { tool: "mcp__erp__pay_invoice", arguments: {} }, ctx(), "unmapped"],
    ["missing amount", approve(undefined), ctx(), "fact.missing"],
    ["amount as a fractional JSON number", approve(3200.5), ctx(), "fact.missing"],
    ["amount as text that isn't a decimal", approve("3,200"), ctx(), "fact.missing"],
    ["currency the ceiling isn't in", { tool: "mcp__erp__approve_invoice", arguments: { invoice_id: "I", vendor_id: "V", amount: "100", currency: "USD" } }, ctx(), "currency.mismatch"],
    ["declared capability disagrees with the binding", { ...approve("3200"), declaredCapability: "erp:invoice.read" }, ctx(), "capability.mismatch"],
    ["flag tool for a reason the binding doesn't map", { tool: "mcp__erp__flag_invoice", arguments: { invoice_id: "I", reason: "late" } }, ctx(), "unmapped"],
    ["flag tool without the argument its match condition reads", { tool: "mcp__erp__flag_invoice", arguments: { invoice_id: "I" } }, ctx(), "binding.condition-unevaluable"],
  ];
  for (const [name, call, c, code] of cases) {
    it(name, () => {
      const d = evaluate(p, call, c);
      expect(d.outcome).toBe("unplaceable");
      expect(d.reservations).toEqual([]);
      expect(codes(d)).toContain(code);
    });
  }
  it("a whole JSON number is accepted as an exact amount", () => {
    expect(evaluate(p, approve(3200), ctx()).band).toBe("A");
  });
});

describe("preparatory calls need an open context", () => {
  const p = compile();
  const read = { tool: "mcp__erp__get_invoice", arguments: { invoice_id: "INV-1" } };
  it("no open context: unplaceable", () => {
    const d = evaluate(p, read, ctx({ contexts: [] }));
    expect(d.outcome).toBe("unplaceable");
    expect(codes(d)).toContain("context.none");
  });
  it("an open context for a served row: allowed", () => {
    const d = evaluate(p, read, ctx({ contexts: [{ id: "c", rows: ["invoice.approve"] }] }));
    expect(d.outcome).toBe("allow");
    expect(d.band).toBeNull();
  });
  it("a context for an unrelated row doesn't count", () => {
    expect(evaluate(p, read, ctx({ contexts: [{ id: "c", rows: ["contract.modify"] }] })).outcome).toBe("unplaceable");
  });
  it("past the daily read cap: refused", () => {
    const d = evaluate(p, read, ctx({ contexts: [{ id: "c", rows: ["invoice.approve"] }], usage: { "reads-per-day []": { count: 2000 } } }));
    expect(d.outcome).toBe("refuse");
  });
});

describe("refusal and conflict", () => {
  it("a non-delegable capability is refused, whatever the score", () => {
    const m = matrix02(), b = binding();
    m.boundaries["no-contract-write"].intendedMechanism = "policy"; // otherwise the linter forbids mapping a tool to it
    b.tools.push({ id: "amend", match: { tool: "mcp__erp__amend_contract" }, capability: "erp:contract.write" });
    const d = evaluate(compile(m, b), { tool: "mcp__erp__amend_contract", arguments: {} }, ctx({ scores: approveScore(0.99) }));
    expect([d.outcome, d.band]).toEqual(["refuse", "non-delegable"]);
  });
  it("a refusal beats any other placement in the same call", () => {
    const m = matrix02(), b = binding();
    m.boundaries["no-contract-write"].intendedMechanism = "policy";
    b.tools.push({ id: "approve-also-amends", match: { tool: "mcp__erp__approve_invoice" }, capability: "erp:contract.write" });
    expect(evaluate(compile(m, b), approve("3200"), ctx()).outcome).toBe("refuse");
  });
  it("two rows at the same band naming different approvers: unplaceable", () => {
    const m = matrix02(), b = binding();
    // A second entry matches the approve tool and maps it to the flag row, whose high band is B with reviewer ap-clerk.
    // Give that row a different reviewer so both placements sit at B with different approvers.
    m.roles["ap-lead"] = { title: "AP lead" };
    m.rows[1].authority.reviewer = "ap-lead";
    b.tools.push({ id: "approve-also-flags", match: { tool: "mcp__erp__approve_invoice" }, capability: "erp:invoice.flag", facts: { task: { arg: "/invoice_id" } } });
    const d = evaluate(compile(m, b), approve("3200"), ctx({ scores: { ...approveScore(0.8), "erp:invoice.flag": { value: 0.95, policy: { id: "invoice-duplicate", version: "1.0" } } } }));
    expect(d.outcome).toBe("unplaceable");
    expect(codes(d)).toContain("approver.conflict");
  });
});
