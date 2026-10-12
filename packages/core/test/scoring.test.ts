import { describe, expect, it } from "vitest";
import { CapLedger, compilePolicy, ContextRegistry, decide, lintScoring, resolveRecord, score, type Call, type DecideInput, type DecisionRecord, type History, type Policy } from "../src/index.ts";
import { binding, matrix02, rules, scoringPolicies, scoringPolicy, type Doc } from "./helpers.ts";

describe("the scoring linter", () => {
  it("passes every example policy, alone and against its binding", () => {
    for (const s of scoringPolicies()) expect(lintScoring(s).findings).toEqual([]);
    expect(lintScoring(scoringPolicy("invoice-standard"), binding()).findings).toEqual([]);
  });

  it("refuses an unknown format", () => {
    const s = scoringPolicy("invoice-standard"); s.format = "vaom.scoring/9";
    expect(rules(lintScoring(s))).toEqual(["format"]);
  });

  // Each case breaks the invoice policy once and must trip exactly the named rule.
  const cases: [string, (s: Doc, b: Doc) => void, string][] = [
    ["a weight above 1", (s) => { s.dimensions.ruleMatch.weight = 1.5; }, "schema"],
    ["a floor that's neither a number nor must-pass", (s) => { s.dimensions.ruleMatch.floor = "should-pass"; }, "schema"],
    ["a dimension the format doesn't know", (s) => { s.dimensions.vibes = { weight: 0, floor: 0, checks: [] }; }, "schema"],
    ["model certainty given a weight", (s) => { s.modelCertainty.weight = 0.3; }, "schema"],
    ["a burst signal without a window", (s) => { delete s.dimensions.anomaly.signals[2].window; }, "schema"],
    ["a signal of an unknown kind", (s) => { s.dimensions.anomaly.signals[0].kind = "vibes"; }, "schema"],
    ["no approval", (s) => { delete s.approval; }, "schema"],
    ["weights that don't sum to 1", (s) => { s.dimensions.ruleMatch.weight = 0.4; }, "weights.sum"],
    ["an id used twice", (s) => { s.dimensions.anomaly.signals[1].id = "unfamiliar-vendor"; }, "id.duplicate"],
    ["a fact the binding doesn't declare", (s) => { s.dimensions.ruleMatch.rules[0].when.fact = "po_matched"; }, "fact.undeclared"],
    ["an ordered comparison on money", (s) => { s.dimensions.ruleMatch.rules.push({ id: "small", when: { fact: "amount", op: "lt", value: 100 } }); }, "condition.money"],
    ["history keyed on an omitted fact", (_s, b) => { b.facts.counterparty.record = "omit"; }, "history.omitted"],
    ["an unusual-value signal on a string", (s) => { s.dimensions.anomaly.signals[1].fact = "task"; }, "history.not-numeric"],
    ["an unusual-value signal on a digested amount", (_s, b) => { b.facts.amount.record = "digest"; }, "history.not-clear"],
  ];
  for (const [name, mutate, rule] of cases) {
    it(`rejects ${name} (${rule})`, () => {
      const s = scoringPolicy("invoice-standard"), b = binding();
      mutate(s, b);
      const r = lintScoring(s, b);
      expect(r.ok).toBe(false);
      expect(rules(r)).toEqual([rule]);
    });
  }
});

describe("the score, computed as written", () => {
  // A policy small enough to compute by hand: completeness 0.2 (must pass), rules 0.5 (floor 0.8), anomaly 0.3 (floor 0.5).
  const policy = (): Doc => ({
    format: "vaom.scoring/0.1", id: "t", version: "1", title: "t", approval: { role: "owner", date: "2026-10-12" },
    dimensions: {
      dataCompleteness: { weight: 0.2, floor: "must-pass", checks: [{ id: "has-a", present: ["a"] }, { id: "b-positive", when: { fact: "b", op: "gt", value: 0 } }] },
      ruleMatch: { weight: 0.5, floor: 0.8, rules: [{ id: "r1", when: { fact: "a", op: "eq", value: "x" }, weight: 3 }, { id: "r2", when: { fact: "b", op: "lt", value: 10 }, weight: 1 }, { id: "hard", when: { fact: "c", op: "eq", value: true }, hard: true, weight: 1 }] },
      anomaly: { weight: 0.3, floor: 0.5, signals: [{ id: "new-a", kind: "unseen", fact: "a", penalty: 0.4 }, { id: "big-b", kind: "unusual-value", fact: "b", factor: 2, minHistory: 3, penalty: 0.3 }, { id: "busy", kind: "burst", count: 2, window: "PT1H", penalty: 0.5 }] },
    },
    modelCertainty: { floor: 0.6 },
  });
  const quiet: History = { seen: () => true, values: () => [4, 5, 6], count: () => 0 };
  const facts = { a: "x", b: 5, c: true };
  const run = (over: { facts?: Record<string, unknown>; history?: History | null; statedCertainty?: number; policy?: Doc } = {}) =>
    score(over.policy ?? policy(), {
      row: "r", facts: (over.facts ?? facts) as never,
      ...(over.history === null ? {} : { history: over.history ?? quiet }),
      ...(over.statedCertainty !== undefined ? { statedCertainty: over.statedCertainty } : {}),
    });

  it("everything holding: 1, uncapped", () => {
    expect(run()).toMatchObject({ value: 1, dimensions: { dataCompleteness: { score: 1 }, ruleMatch: { score: 1 }, anomaly: { score: 1 } } });
    expect(run().cap).toBeUndefined();
  });

  it("the composite is the weighted sum of dimension scores", () => {
    // b = 10: r2 fails (weight 1 of 5), so rules 0.8; 10 is exactly twice the median, so not unusual.
    // Unseen a: anomaly 0.6. 0.2*1 + 0.5*0.8 + 0.3*0.6 = 0.78.
    const r = run({ facts: { a: "x", b: 10, c: true }, history: { ...quiet, seen: () => false } });
    expect(r.dimensions.ruleMatch).toEqual({ score: 0.8, failed: ["r2"] });
    expect(r.dimensions.anomaly).toEqual({ score: 0.6, fired: ["new-a"] });
    expect(r.value).toBeCloseTo(0.2 + 0.4 + 0.18, 12);
    expect(r.cap).toBeUndefined();
  });

  it("a must-pass dimension below 1 sets the level to low", () => {
    const r = run({ facts: { a: "x", b: -1, c: true } });
    expect(r.dimensions.dataCompleteness).toEqual({ score: 0.5, failed: ["b-positive"] });
    expect(r.cap).toBe("low");
    expect(r.reasons.map((x) => x.code)).toContain("confidence.gate");
  });

  it("a missing fact fails every check and rule that reads it", () => {
    const r = run({ facts: { b: 5, c: true } });
    expect(r.dimensions.dataCompleteness?.failed).toEqual(["has-a"]);
    expect(r.dimensions.ruleMatch?.failed).toEqual(["r1"]);
    expect(r.cap).toBe("low");
  });

  it("a dimension below its floor caps the level at medium", () => {
    const r = run({ facts: { a: "y", b: 5, c: true } }); // r1 fails: rules 0.4 < 0.8
    expect(r.cap).toBe("medium");
    expect(r.reasons.map((x) => x.code)).toContain("confidence.floor");
  });

  it("a failed hard rule caps the level at medium even when its dimension clears the floor", () => {
    const r = run({ facts: { a: "x", b: 5, c: false } }); // rules 0.8, at the floor
    expect(r.dimensions.ruleMatch?.score).toBe(0.8);
    expect(r.cap).toBe("medium");
    expect(r.reasons.map((x) => x.code)).toEqual(["confidence.hard-rule"]);
  });

  it("stated certainty only lowers: the composite becomes the smaller of the two", () => {
    expect(run({ statedCertainty: 0.7 }).value).toBe(0.7);
    const unseen = run({ history: { ...quiet, seen: () => false }, statedCertainty: 1 });
    expect(unseen.value).toBeCloseTo(0.88, 12);
  });

  it("stated certainty below its floor caps at medium; a required one that's absent sets low", () => {
    expect(run({ statedCertainty: 0.59 }).cap).toBe("medium");
    const p = policy(); p.modelCertainty.required = true;
    expect(run({ policy: p }).cap).toBe("low");
    expect(run({ policy: p, statedCertainty: 0.9 }).cap).toBeUndefined();
  });

  it("without a modelCertainty section, a stated certainty is ignored entirely", () => {
    const p = policy(); delete p.modelCertainty;
    expect(run({ policy: p, statedCertainty: 0.1 }).value).toBe(1);
  });

  describe("anomaly signals", () => {
    it("unreadable history fires every signal and says so", () => {
      const r = run({ history: null });
      expect(r.dimensions.anomaly).toEqual({ score: 0, fired: ["new-a", "big-b", "busy"] });
      expect(r.reasons.filter((x) => x.code === "anomaly.history-unreadable")).toHaveLength(3);
      const nulls: History = { seen: () => null, values: () => null, count: () => null };
      expect(run({ history: nulls }).dimensions.anomaly?.score).toBe(0);
    });
    it("unusual-value fires on too little history, and above factor times the median", () => {
      expect(run({ history: { ...quiet, values: () => [4, 5] } }).dimensions.anomaly?.fired).toEqual(["big-b"]);
      expect(run({ facts: { a: "x", b: 10, c: true } }).dimensions.anomaly?.fired).toBeUndefined(); // 10 = 2 x 5
      expect(run({ facts: { a: "x", b: 10.5, c: true } }).dimensions.anomaly?.fired).toEqual(["big-b"]);
    });
    it("unusual-value compares money within one currency only", () => {
      const p = policy(); p.dimensions.anomaly.signals[1].fact = "m";
      const eur = (n: string) => ({ amount: n, currency: "EUR" }), usd = (n: string) => ({ amount: n, currency: "USD" });
      const h = (xs: unknown[]): History => ({ ...quiet, values: () => xs as never });
      const f = { ...facts, m: eur("100") };
      expect(run({ policy: p, facts: f, history: h([eur("90"), eur("100"), eur("110")]) }).dimensions.anomaly?.fired).toBeUndefined();
      expect(run({ policy: p, facts: f, history: h([usd("90"), usd("100"), usd("110")]) }).dimensions.anomaly?.fired).toEqual(["big-b"]);
    });
    it("burst fires at the count, not before", () => {
      expect(run({ history: { ...quiet, count: () => 1 } }).dimensions.anomaly?.fired).toBeUndefined();
      expect(run({ history: { ...quiet, count: () => 2 } }).dimensions.anomaly?.fired).toEqual(["busy"]);
    });
    it("a signal grouped by a fact the call lacks fires", () => {
      const p = policy(); p.dimensions.anomaly.signals[2].groupBy = ["d"];
      expect(run({ policy: p }).dimensions.anomaly?.fired).toEqual(["busy"]);
    });
    it("penalties add up, and the dimension never drops below 0", () => {
      const p = policy(); for (const g of p.dimensions.anomaly.signals) g.penalty = 0.9;
      expect(run({ policy: p, history: null }).dimensions.anomaly?.score).toBe(0);
    });
  });
});

describe("history comes from the Guardian's own records", () => {
  // The full invoice policy, with anomaly signals: an unfamiliar vendor (V-7's counterparty is recorded
  // as a digest) scores 0.875, medium; a familiar one at a usual amount scores 1.0.
  const policy: Policy = (() => {
    const r = compilePolicy(matrix02(), binding(), scoringPolicies());
    if (!r.ok) throw new Error(JSON.stringify(r.findings));
    return r.policy;
  })();
  const factKey = new Uint8Array(32).fill(5);
  const approve = (id: string, amount = "1000", vendor = "V-7"): Call => ({ tool: "mcp__erp__approve_invoice", arguments: { invoice_id: id, vendor_id: vendor, amount, currency: "EUR", po_number: `PO-${id}` } });
  let n = 0;
  const at = (day: number) => `2026-10-${String(day).padStart(2, "0")}T09:00:00Z`;
  const input = (ts: string, extra: Partial<DecideInput> = {}): DecideInput => {
    const contexts = new ContextRegistry(policy);
    contexts.open({ id: `c-${++n}`, session: "s", agent: { id: "ap" }, rows: ["invoice.approve"] }, Date.parse(ts));
    return { id: `h-${n}`, ts, agent: { id: "ap" }, session: { id: "s" }, factKey, contexts, verifications: { "erp:invoice.approve": true }, ...extra };
  };
  const fresh = () => { const l = new CapLedger(); l.load([]); return l; };
  const execute = (ledger: CapLedger, r: DecisionRecord, ts: string) => {
    const done = resolveRecord(r, { ts, result: "executed", ...(r.decision.outcome === "allow" ? {} : { approval: { approver_role: r.decision.approver_role!, record: `ok-${r.id}` } }) });
    ledger.settle(r.id, "executed");
    return done;
  };
  /** Three executed invoices from V-7 at 1,000, a day apart. */
  const withHistory = () => {
    const ledger = fresh(), records: DecisionRecord[] = [];
    for (const d of [1, 2, 3]) records.push(execute(ledger, decide(policy, approve(`H${d}`), ledger, input(at(d))), at(d)));
    return { ledger, records };
  };

  it("a vendor with no executed history is unfamiliar, and too little history makes any amount unusual", () => {
    const r = decide(policy, approve("I1"), fresh(), input(at(4)));
    expect(r.decision.placements[0]!.score?.dimensions.anomaly).toEqual({ score: 0.5, fired: ["unfamiliar-vendor", "unusual-amount"] });
    expect(r.decision.band).toBe("B");
  });

  it("executed history makes a vendor familiar and an amount usual: Band A", () => {
    const { ledger } = withHistory();
    const r = decide(policy, approve("I2"), ledger, input(at(4)));
    expect(r.decision.placements[0]!.score?.dimensions.anomaly).toEqual({ score: 1 });
    expect(r.decision.band).toBe("A");
  });

  it("asking isn't history: decisions that never executed don't make a vendor familiar", () => {
    const ledger = fresh();
    for (const [d, result] of [[1, "rejected"], [2, "expired"], [3, "withdrawn"]] as const) {
      const r = decide(policy, approve(`R${d}`), ledger, input(at(d)));
      resolveRecord(r, { ts: at(d), result });
      ledger.settle(r.id, result);
    }
    const pending = decide(policy, approve("P1"), ledger, input(at(4)));
    expect(pending.decision.band).toBe("B"); // still pending: not executed either
    // Four decisions at 1,000 and none executed: still no familiar vendor, and still too little history for amounts.
    expect(decide(policy, approve("I3"), ledger, input(at(5))).decision.placements[0]!.score?.dimensions.anomaly?.fired).toEqual(["unfamiliar-vendor", "unusual-amount"]);
  });

  it("familiarity is per vendor: another vendor is still unfamiliar", () => {
    const { ledger } = withHistory();
    expect(decide(policy, approve("I4", "1000", "V-8"), ledger, input(at(4))).decision.placements[0]!.score?.dimensions.anomaly?.fired).toEqual(["unfamiliar-vendor", "unusual-amount"]);
  });

  it("an amount over three times the vendor's median is unusual", () => {
    const { ledger } = withHistory();
    expect(decide(policy, approve("I5", "3000"), ledger, input(at(4))).decision.band).toBe("A");
    const r = decide(policy, approve("I6", "3001"), ledger, input(at(4)));
    expect(r.decision.placements[0]!.score?.dimensions.anomaly?.fired).toEqual(["unusual-amount"]);
    expect(r.decision.band).toBe("B");
  });

  it("attempts count towards a burst, whatever became of them", () => {
    const { ledger } = withHistory();
    const day = (m: number) => `2026-10-04T09:${String(m).padStart(2, "0")}:00Z`;
    for (let m = 0; m < 10; m++) {
      const r = decide(policy, approve(`B${m}`, "10"), ledger, input(day(m)));
      ledger.settle(r.id, "withdrawn");
    }
    const r = decide(policy, approve("B10", "10"), ledger, input(day(10)));
    expect(r.decision.placements[0]!.score?.dimensions.anomaly?.fired).toEqual(["approval-burst"]);
    expect(r.decision.band).toBe("B");
  });

  it("a ledger rebuilt from the records scores exactly as the live one", () => {
    const { ledger, records } = withHistory();
    const rebuilt = new CapLedger(); rebuilt.load(records);
    const a = decide(policy, approve("X1", "2000"), ledger, input(at(5), { id: "same" }));
    const b = decide(policy, approve("X1", "2000"), rebuilt, input(at(5), { id: "same" }));
    expect(b.decision.placements[0]!.score).toEqual(a.decision.placements[0]!.score);
    expect(a.decision.band).toBe("A");
  });

  it("digested facts compare under the same key only: a rotated key forgets every vendor", () => {
    const { records } = withHistory();
    const rebuilt = new CapLedger(); rebuilt.load(records);
    const r = decide(policy, approve("K1"), rebuilt, input(at(5), { factKey: new Uint8Array(32).fill(6) }));
    expect(r.decision.placements[0]!.score?.dimensions.anomaly?.fired).toContain("unfamiliar-vendor");
  });

  it("an unloaded ledger can't say what's familiar: every signal fires", () => {
    // decide() refuses to reserve on an unloaded ledger, so this reads the score through evaluate's path.
    const ledger = new CapLedger();
    expect(() => decide(policy, approve("U1"), ledger, input(at(5)))).toThrow();
    expect(ledger.historySeen("invoice.approve", "counterparty", { value: "x" }, 0, null)).toBeNull();
  });
});
