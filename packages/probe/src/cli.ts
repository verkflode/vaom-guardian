#!/usr/bin/env node
// vaom-probe run --probes probes.json --matrix matrix.json --project <agent project dir>
//                [--mcp-config mcp.json] [--claude cmd] [--model m] [--only boundary] [--out dir] [--keep-transcripts]
//                [--setting-sources project|user,project,local] [--no-grant]
// Runs each probe as a real Claude Code session and writes one vaom.probe-result file per boundary, for
// `vaom-guardian probe import`. The probed tools are granted for the session (--allowedTools), so only a
// hook or a deny rule can stop them; --no-grant leaves the project's permissions as they are.
// Probes attempt forbidden actions: point them at canaries, never at live systems, as the probe set and
// the matrix's verification targets say.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { randomUUID } from "node:crypto";
import { lintProbes, PROBE_RESULT_FORMAT, type ProbeResult } from "@verkflode/vaom-guardian-core";
import { RUNNER, runProbe, type ProbeSet } from "./claude-code.ts";

const { positionals, values } = parseArgs({ allowPositionals: true, options: {
  probes: { type: "string" }, matrix: { type: "string" }, project: { type: "string" }, "mcp-config": { type: "string" },
  claude: { type: "string" }, model: { type: "string" }, only: { type: "string" }, out: { type: "string" }, "keep-transcripts": { type: "boolean" }, "setting-sources": { type: "string" }, "no-grant": { type: "boolean" },
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
  // A probe that fails to run is recorded as inconclusive, and the others still run.
  let result: ProbeResult, transcript = "";
  try {
    ({ result, transcript } = await runProbe(set, p, {
      project: resolve(values.project),
      ...(values["mcp-config"] ? { mcpConfig: resolve(values["mcp-config"]) } : {}),
      ...(values.claude ? { claude: values.claude } : {}),
      ...(values.model ? { model: values.model } : {}),
      ...(values["setting-sources"] ? { settingSources: values["setting-sources"] } : {}),
      ...(values["no-grant"] ? { grantProbedTools: false } : {}),
    }));
  } catch (e) {
    result = {
      format: PROBE_RESULT_FORMAT, id: randomUUID(), ts: new Date().toISOString(), boundary: p.boundary, probes: { id: set.id, version: set.version }, runner: RUNNER, host: { id: "claude-code" },
      observed: "inconclusive", evidence: { manifestDigest: `sha256:${"0".repeat(64)}`, forbiddenPresent: [], attempted: [], denied: [], refused: [], canaryHit: false },
      note: `the probe couldn't run: ${(e as Error).message}`,
    };
  }
  const file = join(out, `${p.boundary}-${result.ts.replace(/[:.]/g, "-")}.json`);
  writeFileSync(file, JSON.stringify(result, null, 2) + "\n");
  // Transcripts can hold whatever the agent saw; the result keeps only their digest. Opt-in.
  if (values["keep-transcripts"]) writeFileSync(file.replace(/\.json$/, ".transcript.jsonl"), transcript);
  console.log(`${p.boundary}: ${result.observed}${result.evidence.forbiddenPresent.length ? ` (forbidden tools present: ${result.evidence.forbiddenPresent.join(", ")})` : ""} -> ${file}`);
  if (result.observed === "crossed") failed = true;
}
process.exit(failed ? 1 : 0);
