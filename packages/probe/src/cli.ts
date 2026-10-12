#!/usr/bin/env node
// vaom-probe run --probes probes.json --matrix matrix.json --project <agent project dir>
//                [--mcp-config mcp.json] [--claude cmd] [--model m] [--only boundary] [--out dir] [--keep-transcripts]
// Runs each probe as a real Claude Code session and writes one vaom.probe-result file per boundary, for
// `vaom-guardian probe import`. Probes attempt forbidden actions: point them at canaries, never at live
// systems, as the probe set and the matrix's verification targets say.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { lintProbes } from "@verkflode/vaom-guardian-core";
import { runProbe, type ProbeSet } from "./claude-code.ts";

const { positionals, values } = parseArgs({ allowPositionals: true, options: {
  probes: { type: "string" }, matrix: { type: "string" }, project: { type: "string" }, "mcp-config": { type: "string" },
  claude: { type: "string" }, model: { type: "string" }, only: { type: "string" }, out: { type: "string" }, "keep-transcripts": { type: "boolean" },
} });
if (positionals[0] !== "run" || !values.probes || !values.matrix || !values.project) {
  console.error("usage: vaom-probe run --probes probes.json --matrix matrix.json --project <dir> [--mcp-config mcp.json] [--claude cmd] [--model m] [--only boundary] [--out dir]");
  process.exit(2);
}
const set = JSON.parse(readFileSync(values.probes, "utf8")) as ProbeSet & { host: { id: string } };
const lint = lintProbes(set, JSON.parse(readFileSync(values.matrix, "utf8")));
for (const f of lint.findings) console.error(`${f.severity} ${f.path} ${f.message}`);
if (!lint.ok) process.exit(1);
if (set.host.id !== "claude-code") { console.error(`these probes are for host ${set.host.id}; this runner probes claude-code`); process.exit(1); }

const chosen = set.probes.filter((x) => !values.only || x.boundary === values.only);
if (chosen.length === 0) { console.error(`no probe in ${set.id} is for boundary ${values.only}: nothing was probed`); process.exit(1); }
const out = resolve(values.out ?? "probe-results");
mkdirSync(out, { recursive: true });
let failed = false;
for (const p of chosen) {
  const { result, transcript } = await runProbe(set, p, {
    project: resolve(values.project),
    ...(values["mcp-config"] ? { mcpConfig: resolve(values["mcp-config"]) } : {}),
    ...(values.claude ? { claude: values.claude } : {}),
    ...(values.model ? { model: values.model } : {}),
  });
  const file = join(out, `${p.boundary}-${result.ts.replace(/[:.]/g, "-")}.json`);
  writeFileSync(file, JSON.stringify(result, null, 2) + "\n");
  // Transcripts can hold whatever the agent saw; the result keeps only their digest. Opt-in.
  if (values["keep-transcripts"]) writeFileSync(file.replace(/\.json$/, ".transcript.jsonl"), transcript);
  console.log(`${p.boundary}: ${result.observed}${result.evidence.forbiddenPresent.length ? ` (forbidden tools present: ${result.evidence.forbiddenPresent.join(", ")})` : ""} -> ${file}`);
  if (result.observed === "crossed") failed = true;
}
process.exit(failed ? 1 : 0);
