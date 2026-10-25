// Compile JSON Schemas into standalone validators: ours for the core, the vendored ACS ones for the adapter.
//
// Ajv normally compiles at runtime with `new Function`, which the core forbids (no eval) and a strict
// browser CSP rejects. Here it compiles once, at build time, into plain JavaScript; esbuild then bundles
// that code with the few Ajv runtime helpers and format checks it needs into one self-contained module.
// The core imports the result and has no runtime dependencies.
//
// Each target also gets types.ts, a TypeScript type per exported schema, derived from the same schemas by
// json-schema-to-typescript, and validators.d.ts, which declares every validator a type guard for its
// schema's type: a document that passes is typed by what the schema says, with no cast.
// Only local files are read: references resolve inside the repository, never over the network.
//
//   node scripts/gen-validators.mjs            write every target (see `targets`)
//   node scripts/gen-validators.mjs --check    fail if any committed output is out of date
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import standaloneCode from "ajv/dist/standalone/index.js";
import { _ } from "ajv";
import { build } from "esbuild";
import { compile } from "json-schema-to-typescript";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// Each target: the schemas to compile, the export names, the output file, and whether the schemas are ours
// (full strict mode) or vendored (strict mode off, since we don't control their keywords; formats still asserted).
const ACS = "packages/acs/vendor/acs-v0.1.4/specification/v0.1.0";
const ACS_ID = "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0";
const targets = [
  {
    out: "packages/core/src/generated/validators.js",
    types: "packages/core/src/generated/types.ts",
    strict: true,
    load: ["schema/vaom-matrix-0.1.schema.json", "schema/vaom-matrix-0.2.schema.json", "schema/vaom-binding.schema.json", "schema/vaom-scoring-0.1.schema.json", "schema/vaom-seeds-0.1.schema.json", "schema/vaom-probes-0.1.schema.json", "schema/vaom-probe-result-0.1.schema.json", "schema/vaom-decision-0.3.schema.json", "schema/vaom-decision-0.4.schema.json"],
    exports: {
      validateMatrix01: "urn:verkflode:vaom:matrix:0.1",
      validateMatrix02: "urn:verkflode:vaom:matrix:0.2",
      validateBinding01: "urn:verkflode:vaom:binding:0.1",
      validateScoring01: "urn:verkflode:vaom:scoring:0.1",
      validateSeeds01: "urn:verkflode:vaom:seeds:0.1",
      validateProbes01: "urn:verkflode:vaom:probes:0.1",
      validateProbeResult01: "urn:verkflode:vaom:probe-result:0.1",
      validateDecision03: "urn:verkflode:vaom:decision:0.3",
      validateDecision04: "urn:verkflode:vaom:decision:0.4",
    },
  },
  {
    out: "packages/acs/src/generated/validators.js",
    types: "packages/acs/src/generated/types.ts",
    strict: false,
    loadDir: ACS,
    exports: {
      validateRequestEnvelope: `${ACS_ID}/request-envelope.json`,
      validateResponseEnvelope: `${ACS_ID}/response-envelope.json`,
      validateClientHello: `${ACS_ID}/handshake.json#/$defs/ClientHello`,
      validateServerHello: `${ACS_ID}/handshake.json#/$defs/ServerHello`,
      validateToolCallRequest: `${ACS_ID}/hooks/tool-call-request.json`,
      validateToolCallResult: `${ACS_ID}/hooks/tool-call-result.json`,
      validateSessionStart: `${ACS_ID}/hooks/session-start.json`,
      validateSubagentStart: `${ACS_ID}/hooks/subagent-start.json`,
      validateSessionEnd: `${ACS_ID}/hooks/session-end.json`,
      validateTurnStart: `${ACS_ID}/hooks/turn-start.json`,
      validateTurnEnd: `${ACS_ID}/hooks/turn-end.json`,
      validateUserMessage: `${ACS_ID}/hooks/user-message.json`,
      validateAgentTrigger: `${ACS_ID}/hooks/agent-trigger.json`,
      validateAgentResponse: `${ACS_ID}/hooks/agent-response.json`,
      validatePreCompact: `${ACS_ID}/hooks/pre-compact.json`,
      validatePostCompact: `${ACS_ID}/hooks/post-compact.json`,
      validateSubagentStop: `${ACS_ID}/hooks/subagent-stop.json`,
    },
  },
];

function jsonFiles(dir) {
  return readdirSync(join(root, dir), { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? jsonFiles(join(dir, e.name)) : e.name.endsWith(".json") ? [join(dir, e.name)] : []);
}

const check = process.argv.includes("--check");
let stale = false;

function emit(path, text, what) {
  const out = join(root, path);
  if (check) {
    let current = "";
    try { current = readFileSync(out, "utf8"); } catch { /* missing counts as stale */ }
    if (current !== text) { console.error(`${path} is out of date: run pnpm gen:validators`); stale = true; }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${path} (${what})`);
  }
}

/**
 * One type per exported schema, named after its validator (validateMatrix02 → Matrix02). The schemas are
 * compiled together, under one wrapper, so a definition they share is declared once.
 */
async function types(t, files) {
  const properties = {};
  for (const [name, id] of Object.entries(t.exports)) {
    const [base, fragment] = id.split("#");
    const file = files.get(base);
    if (!file) throw new Error(`${t.types}: no local file has the $id ${base}`);
    properties[name.replace(/^validate/, "")] = { $ref: `./${file}${fragment ? `#${fragment}` : ""}` };
  }
  const wrapper = { title: "Documents", type: "object", properties, required: Object.keys(properties), additionalProperties: false };
  const decls = await compile(wrapper, "Documents", {
    cwd: root,
    bannerComment: "",
    unreachableDefinitions: false,
    $refOptions: { resolve: { http: false } },
  });
  return [
    "// GENERATED by scripts/gen-validators.mjs from the same schemas as validators.js. Do not edit.",
    "// One type per validated document; the declarations under them are named after the schemas' titles.",
    "/* eslint-disable */",
    "",
    decls.trimEnd(),
    "",
    ...Object.keys(properties).flatMap((n) => {
      // A schema whose title is already the alias's name is declared under it: no alias needed. Any other
      // clash would shadow a different type, so it stops the build.
      if (!new RegExp(`^export (interface|type) ${n}\\b`, "m").test(decls)) return [`export type ${n} = Documents["${n}"];`];
      if (!new RegExp(`^  ${n}: ${n};$`, "m").test(decls)) throw new Error(`${t.types}: ${n} names a different declaration; rename the export`);
      return [];
    }),
    "",
  ].join("\n");
}

for (const t of targets) {
  const ajv = new Ajv2020({
    strict: t.strict,
    // strictRequired/strictTypes misfire on if/then in valid 2020-12 schemas; every other strict check stays on.
    strictRequired: false,
    strictTypes: false,
    allErrors: true,
    code: { source: true, esm: true, formats: _`require("ajv-formats/dist/formats").fullFormats` },
  });
  addFormats(ajv);
  const files = new Map();
  for (const path of t.load ?? jsonFiles(t.loadDir)) {
    const schema = JSON.parse(readFileSync(join(root, path), "utf8"));
    if (schema.$id) { ajv.addSchema(schema); files.set(schema.$id, relative(root, join(root, path))); }
  }
  const source = standaloneCode(ajv, t.exports);
  // Fed through stdin under a fixed name, so no temporary path ends up in the output: the build is
  // reproducible, which is what lets --check compare byte for byte.
  const result = await build({
    stdin: { contents: source, resolveDir: root, sourcefile: "validators.raw.mjs", loader: "js" },
    bundle: true,
    // Paths in the output's comments are relative to this, so the bytes don't depend on where the script runs.
    absWorkingDir: root,
    format: "esm",
    platform: "neutral",
    write: false,
    nodePaths: [join(root, "node_modules")],
    legalComments: "none",
    banner: {
      js: [
        "// GENERATED by scripts/gen-validators.mjs. Do not edit.",
        "// Standalone Ajv validators bundled with their runtime helpers: no eval, no dependencies.",
        "// @ts-nocheck",
      ].join("\n"),
    },
  });
  const code = result.outputFiles[0].text;
  // Real calls only: Ajv's runtime helpers carry codegen metadata as string literals such as
  // 'require("ajv/dist/runtime/equal").default', which is never executed, so a match right after a quote is skipped.
  for (const banned of [/(?<!['"])\bnew Function\b/, /(?<!['"])\beval\s*\(/, /(?<!['"])\brequire\s*\(/]) {
    if (banned.test(code)) throw new Error(`${t.out} would contain ${banned}; refusing to write`);
  }
  emit(t.out, code, `${(code.length / 1024).toFixed(0)} KB`);
  emit(t.out.replace(/\.js$/, ".d.ts"), [
    "// GENERATED by scripts/gen-validators.mjs. Do not edit.",
    "// Each validator is a type guard: data that passes has its schema's type, from types.ts.",
    'import type * as T from "./types.ts";',
    "export interface SchemaError { instancePath: string; schemaPath: string; keyword: string; params: Record<string, unknown>; message?: string }",
    "export interface Validator<D = unknown> { (data: unknown): data is D; errors?: SchemaError[] | null }",
    ...Object.keys(t.exports).map((n) => `export const ${n}: Validator<T.${n.replace(/^validate/, "")}>;`),
    "",
  ].join("\n"), "declarations");
  const typesText = await types(t, files);
  emit(t.types, typesText, `${typesText.split("\n").length} lines`);
}
if (check) {
  if (stale) process.exit(1);
  console.log("generated validators are up to date");
}
