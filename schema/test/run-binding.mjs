// Tests for vaom.binding/0.1: schema cases, plus a prototype of the binding linter's
// cross-file rules (binding against matrix), run against the invoice example.
// Names starting "POS-" must be accepted; every other case must be rejected.
// Needs ajv and ajv-formats resolvable from here; see README.md.
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const load = (p) => JSON.parse(readFileSync(here(p), "utf8"));
const bindingText = readFileSync(here("../examples/invoice.claude-code.binding.json"), "utf8");
const matrixText = readFileSync(here("../examples/invoice.matrix-0.2.json"), "utf8");
const baseBinding = () => JSON.parse(bindingText);
const baseMatrix = () => JSON.parse(matrixText);
const matrix01Text = readFileSync(here("../examples/invoice.matrix-0.1.json"), "utf8");
const entry = (b, id) => b.tools.find((t) => t.id === id);

const ajv = new Ajv({ strict: true, strictRequired: false, strictTypes: false, allErrors: true });
addFormats(ajv);
const validateBinding = ajv.compile(load("../vaom-binding.schema.json"));
const validateMatrix = ajv.compile(load("../vaom-matrix-0.2.schema.json"));

// --- Prototype linter: returns a list of errors; empty means the pair is accepted. ---
function inRange(version, range) {
  // Only the ">=a.b.c <x.y.z" form for now; anything else fails closed.
  const m = /^>=(\d+)\.(\d+)\.(\d+) <(\d+)\.(\d+)\.(\d+)$/.exec(range);
  if (!m) return false;
  const v = version.split(".").map(Number), lo = m.slice(1, 4).map(Number), hi = m.slice(4, 7).map(Number);
  const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
  return cmp(v, lo) >= 0 && cmp(v, hi) < 0;
}
function lintPair(binding, matrix) {
  const errs = [];
  if (binding.matrix.id !== matrix.id) errs.push(`binding is for matrix ${binding.matrix.id}, loaded ${matrix.id}`);
  if (!inRange(matrix.version, binding.matrix.versions)) errs.push(`matrix ${matrix.version} outside ${binding.matrix.versions}`);
  const ids = binding.tools.map((t) => t.id);
  if (new Set(ids).size !== ids.length) errs.push("duplicate tool entry ids");
  for (const t of binding.tools) {
    const rows = matrix.rows.filter((r) => r.capabilities.includes(t.capability));
    if (rows.length !== 1) { errs.push(`${t.id}: capability ${t.capability} governed by ${rows.length} rows`); continue; }
    const row = rows[0];
    for (const f of Object.keys(t.items?.facts ?? {})) if (f in (t.facts ?? {})) errs.push(`${t.id}: fact ${f} extracted both per call and per item (no precedence rule)`);
    const extracted = { ...(t.facts ?? {}), ...(t.items?.facts ?? {}) };
    for (const [f, ex] of Object.entries(extracted)) {
      const def = binding.facts[f];
      if (!def) { errs.push(`${t.id}: fact ${f} not declared`); continue; }
      if ((def.type === "money") !== ("amount" in ex)) errs.push(`${t.id}: fact ${f} extractor doesn't match type ${def.type}`);
    }
    for (const f of row.requiresFacts ?? []) if (!(f in extracted)) errs.push(`${t.id}: row ${row.id} requires fact ${f}`);
    const a = row.authority;
    if (a.kind === "non-delegable") {
      const absent = (a.boundaries ?? []).filter((b) => matrix.boundaries?.[b]?.intendedMechanism === "absent");
      if (absent.length) errs.push(`${t.id}: maps a host tool to ${t.capability}, which boundary ${absent.join(", ")} says is absent`);
    } else {
      const moneyFacts = [a.valueCeiling?.fact, ...(a.cumulativeCaps ?? []).filter((c) => c.total).map((c) => c.fact)].filter(Boolean);
      for (const f of moneyFacts) {
        if (binding.facts[f]?.type !== "money") errs.push(`${t.id}: row ${row.id} sums ${f}, which isn't a money fact`);
        else if (!(f in extracted)) errs.push(`${t.id}: row ${row.id} needs ${f} for its limits`);
      }
      for (const c of a.cumulativeCaps ?? []) for (const g of c.groupBy ?? []) if (!(g in extracted)) errs.push(`${t.id}: cap ${c.id} groups by ${g}, not extracted`);
    }
  }
  return errs;
}

let wrong = 0;
const expect = (name, ok, want, detail) => {
  if (ok !== want) { wrong++; console.log("WRONG", name, "accepted:", ok, "expected:", want, detail ?? ""); }
};

// The example pair itself.
expect("matrix example", validateMatrix(baseMatrix()), true);
expect("binding example (schema)", validateBinding(baseBinding()), true, JSON.stringify(validateBinding.errors));
const exampleLint = lintPair(baseBinding(), baseMatrix());
expect("binding example (lint)", exampleLint.length === 0, true, exampleLint.join("; "));

// Schema cases.
const schemaCases = {
  "tool-and-prefix": (b) => { b.tools[0].match.toolPrefix = "mcp__erp__"; },
  "no-tool-or-prefix": (b) => { b.tools[0].match = {}; },
  "pointer-without-slash": (b) => { b.tools[0].facts.task = { arg: "invoice_id" }; },
  "pointer-bad-escape": (b) => { b.tools[0].facts.task = { arg: "/items/~2" }; },
  "extractor-arg-and-const": (b) => { b.tools[0].facts.task = { arg: "/invoice_id", const: "x" }; },
  "unknown-fact-type": (b) => { b.facts.task.type = "uuid"; },
  "unknown-record-mode": (b) => { b.facts.counterparty.record = "plain"; },
  "regex-op": (b) => { entry(b, "flag-duplicate").match.when = { arg: "/reason", op: "matches", value: ".*" }; },
  "items-maxItems-zero": (b) => { b.tools[1].items.maxItems = 0; },
  "wrong-format": (b) => { b.format = "vaom.binding/0.2"; },
  "POS-prefix-match": (b) => { entry(b, "flag-duplicate").match = { toolPrefix: "mcp__erp__flag", when: { arg: "/reason", op: "eq", value: "duplicate" } }; },
  "POS-record-omit": (b) => { b.facts.task.record = "omit"; },
};
for (const [name, mutate] of Object.entries(schemaCases)) {
  const b = baseBinding(); mutate(b); expect(name, validateBinding(b), name.startsWith("POS-"));
}

// Lint cases: schema-valid bindings (or matrices) that the cross-file rules must reject.
const lintCases = {
  "lint-other-matrix": (b) => { b.matrix.id = "example.ap.other"; },
  "lint-version-out-of-range": (b) => { b.matrix.versions = ">=2.0.0 <3.0.0"; },
  "lint-unsupported-range-syntax": (b) => { b.matrix.versions = "^1.0.0"; },
  "lint-ungoverned-capability": (b) => { entry(b, "flag-duplicate").capability = "erp:invoice.delete"; },
  "lint-missing-required-fact": (b) => { delete b.tools[0].facts.counterparty; },
  "lint-batch-missing-amount": (b) => { delete b.tools[1].items.facts.amount; },
  "lint-undeclared-fact": (b) => { entry(b, "flag-duplicate").facts.priority = { arg: "/priority" }; },
  "lint-money-fact-plain-extractor": (b) => { b.tools[0].facts.amount = { arg: "/amount" }; },
  "lint-string-fact-money-extractor": (b) => { b.tools[0].facts.task = { amount: { arg: "/a" }, currency: { const: "EUR" } }; },
  "lint-ceiling-fact-not-money": (b) => { b.facts.amount.type = "number"; b.tools[0].facts.amount = { arg: "/amount" }; b.tools[1].items.facts.amount = { arg: "/amount" }; },
  "lint-tool-for-absent-boundary": (b) => { b.tools.push({ id: "amend-contract", match: { tool: "mcp__erp__amend_contract" }, capability: "erp:contract.write" }); },
  "lint-duplicate-entry-id": (b) => { entry(b, "flag-duplicate").id = "approve-one"; },
  "lint-batch-fact-collision": (b) => { entry(b, "approve-batch").facts = { counterparty: { arg: "/default_vendor" } }; },
  "POS-extra-narrowing-entry": (b) => { b.tools.push({ id: "flag-any", match: { toolPrefix: "mcp__erp__flag" }, capability: "erp:invoice.flag", facts: { task: { arg: "/invoice_id" } } }); },
};
for (const [name, mutate] of Object.entries(lintCases)) {
  const b = baseBinding(); mutate(b);
  const schemaOk = validateBinding(b);
  if (!schemaOk) { wrong++; console.log("WRONG", name, "should be schema-valid so the lint rule is what rejects it", JSON.stringify(validateBinding.errors)); continue; }
  const errs = lintPair(b, baseMatrix());
  expect(name, errs.length === 0, name.startsWith("POS-"), errs.join("; "));
}

// The 0.2 binding against the 0.1 matrix: the read entries have no row to govern them there.
const errs01 = lintPair(baseBinding(), JSON.parse(matrix01Text));
const readErrs = errs01.filter((e) => /^read-(invoice|vendor|contract): .* governed by 0 rows$/.test(e));
if (readErrs.length !== 3) { wrong++; console.log("WRONG binding vs 0.1 matrix: expected the 3 read entries to be ungoverned, got", errs01); }

const n = 4 + Object.keys(schemaCases).length + Object.keys(lintCases).length;
console.log(`${n} binding cases, ${wrong} wrong`);
process.exit(wrong ? 1 : 0);
