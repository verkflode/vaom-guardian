import { describe, expect, it } from "vitest";
import { lintBinding } from "../src/index.ts";
import { binding, matrix01, matrix02, rules, type Doc } from "./helpers.ts";

const entry = (b: Doc, id: string) => b.tools.find((t: Doc) => t.id === id);

describe("the example", () => {
  it("lints clean against the 0.2 matrix, with no warnings", () => {
    const r = lintBinding(binding(), matrix02());
    expect(r.findings).toEqual([]);
    expect(r.ok).toBe(true);
  });
  it("fails against the 0.1 matrix: its read entries have no row to govern them there", () => {
    const r = lintBinding(binding(), matrix01());
    expect(rules(r)).toEqual(["capability.ungoverned"]);
    const paths = r.findings.map((f) => f.path).sort();
    expect(paths).toEqual(["/tools/2/capability", "/tools/3/capability", "/tools/4/capability"]);
  });
});

describe("fails closed before the cross-file rules", () => {
  it("rejects an unknown format", () => {
    const b = binding(); b.format = "vaom.binding/0.2";
    expect(rules(lintBinding(b, matrix02()))).toEqual(["format"]);
  });
  it("reports schema failures and nothing else", () => {
    const b = binding(); entry(b, "approve-one").match.toolPrefix = "mcp__erp__";
    expect(rules(lintBinding(b, matrix02()))).toEqual(["schema"]);
  });
  it("refuses to check against a matrix that doesn't lint clean", () => {
    const m = matrix02(); m.rows[0].authority.reviewer = "nobody";
    expect(rules(lintBinding(binding(), m))).toEqual(["matrix.invalid"]);
  });
});

const cases: [string, (b: Doc, m: Doc) => void, string][] = [
  ["binding is for another matrix", (b) => { b.matrix.id = "example.ap.other"; }, "matrix.id"],
  ["matrix version outside the range", (b) => { b.matrix.versions = ">=2.0.0 <3.0.0"; }, "matrix.version"],
  ["exact version that doesn't match", (b) => { b.matrix.versions = "1.0.0"; }, "matrix.version"],
  ["unsupported range syntax", (b) => { b.matrix.versions = "^1.0.0"; }, "matrix.range-syntax"],
  ["capability no row governs", (b) => { entry(b, "flag-duplicate").capability = "erp:invoice.delete"; }, "capability.ungoverned"],
  ["row's required fact not extracted", (b) => { delete entry(b, "approve-one").facts.counterparty; }, "fact.missing"],
  ["batch item missing the amount", (b) => { delete entry(b, "approve-batch").items.facts.amount; }, "fact.missing"],
  ["undeclared fact", (b) => { entry(b, "flag-duplicate").facts.priority = { arg: "/priority" }; }, "fact.undeclared"],
  ["money fact with a plain extractor", (b) => { entry(b, "approve-one").facts.amount = { arg: "/amount" }; }, "fact.extractor-type"],
  ["string fact with a money extractor", (b) => { entry(b, "approve-one").facts.task = { amount: { arg: "/a" }, currency: { const: "EUR" } }; }, "fact.extractor-type"],
  ["host tool for a capability meant to be absent", (b) => { b.tools.push({ id: "amend", match: { tool: "mcp__erp__amend_contract" }, capability: "erp:contract.write" }); }, "boundary.tool-present"],
  ["duplicate entry id", (b) => { entry(b, "flag-duplicate").id = "approve-one"; }, "tool.duplicate-id"],
  ["fact extracted per call and per item", (b) => { entry(b, "approve-batch").facts = { counterparty: { arg: "/default_vendor" } }; }, "fact.per-call-and-item"],
  ["restriction reads a fact nobody extracts", (b, m) => {
    b.facts.pep = { type: "boolean" };
    m.rows[0].authority.restrictions = [{ id: "pep", when: { fact: "pep", op: "eq", value: true }, band: "non-delegable" }];
    entry(b, "approve-one").facts.pep = { arg: "/pep" }; // batch entry still lacks it
  }, "fact.missing"],
  ["a fact named like an Object.prototype property", (b) => { b.facts.constructor = { type: "string", record: "value" }; }, "fact.reserved-name"],
  ["a match condition's in has no array", (b) => { const t = b.tools.find((x: Doc) => x.match.when); t.match.when = { arg: "/reason", op: "in", value: "duplicate" }; }, "condition.in-not-array"],
  ["a fixed currency other than the ceiling's", (b) => { entry(b, "approve-batch").items.facts.amount.currency = { const: "USD" }; }, "fact.currency-mismatch"],
];

describe("each cross-file rule trips on its own", () => {
  for (const [name, mutate, rule] of cases) {
    it(name, () => {
      const b = binding(), m = matrix02(); mutate(b, m);
      const r = lintBinding(b, m);
      expect(r.ok).toBe(false);
      expect(rules(r)).toEqual([rule]);
    });
  }

  it("a summed fact that isn't money is rejected", () => {
    const b = binding(), m = matrix02();
    b.facts.amount.type = "number";
    entry(b, "approve-one").facts.amount = { arg: "/amount" };
    entry(b, "approve-batch").items.facts.amount = { arg: "/amount" };
    expect(rules(lintBinding(b, m))).toEqual(["fact.not-money"]);
  });
});

describe("valid variations stay valid", () => {
  it("an extra, narrower entry for the same capability", () => {
    const b = binding();
    b.tools.push({ id: "flag-any", match: { toolPrefix: "mcp__erp__flag" }, capability: "erp:invoice.flag", facts: { task: { arg: "/invoice_id" } } });
    expect(lintBinding(b, matrix02()).ok).toBe(true);
  });
  it("an exact matching version", () => {
    const b = binding(); b.matrix.versions = "1.1.0";
    expect(lintBinding(b, matrix02()).ok).toBe(true);
  });
});

describe("warnings", () => {
  it("a money fact whose currency is fixed rather than read from the call", () => {
    const b = binding(); entry(b, "approve-batch").items.facts.amount.currency = { const: "EUR" };
    const r = lintBinding(b, matrix02());
    expect(r.ok).toBe(true);
    expect(rules(r, "warning")).toEqual(["fact.currency-fixed"]);
  });
  it("a string fact without an explicit record mode", () => {
    const b = binding(); delete b.facts.task.record;
    const r = lintBinding(b, matrix02());
    expect(r.ok).toBe(true);
    expect(rules(r, "warning")).toEqual(["fact.record-unset"]);
  });
});
