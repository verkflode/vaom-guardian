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
const entry = (b, id) => b.tools.find((t) => t.id === id);

const ajv = new Ajv({ strict: true, strictRequired: false, strictTypes: false, allErrors: true });
addFormats(ajv);
const validateBinding = ajv.compile(load("../vaom-binding.schema.json"));
const validateMatrix = ajv.compile(load("../vaom-matrix-0.2.schema.json"));

let wrong = 0;
const expect = (name, ok, want, detail) => {
  if (ok !== want) { wrong++; console.log("WRONG", name, "accepted:", ok, "expected:", want, detail ?? ""); }
};

// The example pair itself.
expect("matrix example", validateMatrix(baseMatrix()), true);
expect("binding example (schema)", validateBinding(baseBinding()), true, JSON.stringify(validateBinding.errors));

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

const n = 2 + Object.keys(schemaCases).length;
console.log(`${n} binding cases, ${wrong} wrong`);
process.exit(wrong ? 1 : 0);
