import { describe, expect, it } from "vitest";
import { lintMatrix } from "../src/index.ts";
import { matrix01, matrix02, rules, type Doc } from "./helpers.ts";

// Row indices in the 0.2 example: 0 invoice.approve, 1 invoice.duplicate-anomaly, 2 contract.modify,
// 3 invoice.prepare, 4 contract.prepare.
const committee = (m: Doc) => { m.roles["ap-board"] = { title: "AP board", kind: "committee" }; };

describe("the examples", () => {
  it("0.1 and 0.2 invoice matrices lint clean, with no warnings", () => {
    for (const m of [matrix01(), matrix02()]) {
      const r = lintMatrix(m);
      expect(r.findings).toEqual([]);
      expect(r.ok).toBe(true);
    }
  });
});

describe("fails closed before the semantic rules", () => {
  it("rejects an unknown format", () => {
    const m = matrix02(); m.format = "vaom.matrix/9.9";
    expect(rules(lintMatrix(m))).toEqual(["format"]);
  });
  it("rejects a missing format and non-objects", () => {
    for (const doc of [{}, null, [], "matrix", 42]) expect(rules(lintMatrix(doc))).toEqual(["format"]);
  });
  it("reports schema failures and nothing else", () => {
    const m = matrix02(); delete m.approval;
    const r = lintMatrix(m);
    expect(r.ok).toBe(false);
    expect(rules(r)).toEqual(["schema"]);
  });
});

// Each case changes one thing in a valid matrix and must trip exactly the rule named.
const cases: [string, (m: Doc) => void, string][] = [
  ["duplicate row id", (m) => { m.rows[4].id = "invoice.prepare"; }, "row.duplicate-id"],
  ["capability claimed by two rows", (m) => { m.rows[3].capabilities.push("erp:invoice.approve"); }, "capability.claimed-twice"],
  ["unknown reviewer role", (m) => { m.rows[0].authority.reviewer = "ap-clerc"; }, "ref.role"],
  ["unknown escalation role", (m) => { m.rows[0].authority.escalation.role = "cfo"; }, "ref.role"],
  ["unknown deputy", (m) => { m.rows[0].accountability.deputy = "nobody"; }, "ref.role"],
  ["unknown role in a breaker's notify list", (m) => { m.circuitBreakers[0].notify.push("sec-ops"); }, "ref.role"],
  ["unknown role on the matrix approval", (m) => { m.approval.role = "ceo"; }, "ref.role"],
  ["unknown role confirming funding", (m) => { m.oversight.fundedBy.role = "budget-office"; }, "ref.role"],
  ["unknown boundary on a breaker", (m) => { m.circuitBreakers[1].condition.boundary = "no-contract-writes"; }, "ref.boundary"],
  ["unknown boundary on a row", (m) => { m.rows[3].authority.boundaries = ["erp-read-only"]; }, "ref.boundary"],
  ["preparatory row serves an unknown row", (m) => { m.rows[3].authority.serves.push("invoice.pay"); }, "ref.row"],
  ["effective.until before effective.from", (m) => { m.effective.until = "2026-09-01T00:00:00Z"; }, "effective.order"],
  ["accountable role is its own deputy", (m) => { m.rows[0].accountability.deputy = "ap-owner"; }, "accountability.self-deputy"],
  ["committee is accountable", (m) => { committee(m); m.rows[0].accountability.role = "ap-board"; m.rows[0].accountability.accepted.role = "ap-board"; }, "accountability.committee"],
  ["committee is the deputy", (m) => { committee(m); m.rows[0].accountability.deputy = "ap-board"; }, "accountability.committee"],
  ["preparatory row serves a preparatory row", (m) => { m.rows[4].authority.serves = ["invoice.prepare"]; }, "preparatory.serves-preparatory"],
  ["preparatory row serves a row that forbids preparation", (m) => { m.rows[2].authority.agentMayPrepare = false; }, "preparatory.not-allowed"],
  ["confidence thresholds out of order", (m) => { m.rows[0].authority.confidence.thresholds = { high: 0.6, medium: 0.7 }; }, "confidence.threshold-order"],
  ["cap in another currency", (m) => { m.rows[0].authority.cumulativeCaps[0].total.currency = "USD"; }, "money.currency"],
  ["derivation in another currency", (m) => { m.rows[0].authority.valueCeiling.derivation.frictionCost.currency = "SEK"; }, "money.currency"],
  ["unfunded review load", (m) => { m.oversight.fundedReviewerHoursPerWeek = 40; }, "oversight.unfunded"],
  ["cap window of zero days", (m) => { m.rows[0].authority.cumulativeCaps[0].window = "P0D"; }, "duration.zero"],
  ["rate cap window of zero seconds", (m) => { m.rows[3].authority.rateCaps[0].window = "PT0S"; }, "duration.zero"],
  ["two caps in a row share an id", (m) => { const c = m.rows[0].authority.cumulativeCaps; c.push({ ...c[0], window: "P7D" }); }, "cap.duplicate-id"],
  ["two restrictions in a row share an id", (m) => { const r = { id: "pep", when: { fact: "counterparty", op: "eq", value: "V-1" }, band: "C" }; m.rows[0].authority.restrictions = [r, { ...r, band: "B" }]; }, "restriction.duplicate-id"],
  ["a restriction's in has no array", (m) => { m.rows[0].authority.restrictions = [{ id: "pep", when: { fact: "counterparty", op: "in", value: "V-1" }, band: "C" }]; }, "condition.in-not-array"],
  ["two breakers share an id", (m) => { m.circuitBreakers[1].id = m.circuitBreakers[0].id; }, "breaker.duplicate-id"],
  ["a consent right this version can't enforce", (m) => { m.rows[0].authority.requiredApprovals = [{ role: "ap-owner", within: "PT24H" }]; }, "row.required-approvals-unsupported"],
];

describe("each semantic rule trips on its own", () => {
  for (const [name, mutate, rule] of cases) {
    it(name, () => {
      const m = matrix02(); mutate(m);
      const r = lintMatrix(m);
      expect(r.ok).toBe(false);
      expect(rules(r)).toEqual([rule]);
    });
  }
});

describe("leases", () => {
  const lease = (lifetime: string, maxLifetime: string, observe: string[] = ["erp:invoice.read"]) =>
    ({ observationCapabilities: observe, lifetime, maxLifetime, responseContextLifetime: "PT10M" });

  it("accepts a lease shorter than its maximum lifetime", () => {
    const m = matrix02(); m.rows[0].authority.lease = lease("PT1H", "P30D");
    expect(lintMatrix(m).ok).toBe(true);
  });
  it("rejects a lifetime that isn't shorter than the maximum", () => {
    for (const [l, mx] of [["P30D", "P30D"], ["P2M", "P30D"], ["P1Y", "P11M"]]) {
      const m = matrix02(); m.rows[0].authority.lease = lease(l!, mx!);
      expect(rules(lintMatrix(m)), `${l} vs ${mx}`).toEqual(["lease.lifetime"]);
    }
  });
  it("rejects an observation capability that executes a decision", () => {
    const m = matrix02(); m.rows[0].authority.lease = lease("PT1H", "P30D", ["erp:invoice.flag"]);
    expect(rules(lintMatrix(m))).toEqual(["lease.observation-executes"]);
  });
});

describe("sub-agents receive only delegated authority", () => {
  const chain = (caps: string[]) => ({ maxDepth: 1, maxFanOut: 2, allowedSubagents: [{ type: "reader", capabilities: caps }] });
  it("accepts capabilities governed by delegable or preparatory rows, including other rows", () => {
    const m = matrix02(); m.rows[0].authority.chain = chain(["erp:invoice.read", "erp:invoice.flag"]);
    expect(lintMatrix(m).ok).toBe(true);
  });
  it("rejects a capability no row governs", () => {
    const m = matrix02(); m.rows[0].authority.chain = chain(["erp:ledger.read"]);
    expect(rules(lintMatrix(m))).toEqual(["chain.unknown-capability"]);
  });
  it("rejects a non-delegable capability", () => {
    const m = matrix02(); m.rows[0].authority.chain = chain(["erp:contract.write"]);
    expect(rules(lintMatrix(m))).toEqual(["chain.non-delegable"]);
  });
});

describe("structural boundaries (warnings)", () => {
  it("warns when a non-delegable row's boundary is only scope-denied", () => {
    const m = matrix02(); m.boundaries["no-contract-write"].intendedMechanism = "scope-denied";
    const r = lintMatrix(m);
    expect(r.ok).toBe(true);
    expect(rules(r, "warning")).toEqual(["structural.weak"]);
  });
  it("warns when a non-delegable row names no boundary", () => {
    const m = matrix02(); delete m.rows[2].authority.boundaries; m.circuitBreakers.splice(1, 1);
    const r = lintMatrix(m);
    expect(r.ok).toBe(true);
    expect(rules(r, "warning")).toEqual(["structural.missing"]);
  });
});

describe("findings point at the problem", () => {
  it("uses a JSON Pointer to the offending value", () => {
    const m = matrix02(); m.rows[0].authority.reviewer = "ap-clerc";
    const f = lintMatrix(m).findings[0]!;
    expect(f.path).toBe("/rows/0/authority/reviewer");
    expect(f.message).toContain("ap-clerc");
  });
});
