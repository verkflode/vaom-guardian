#!/usr/bin/env node
// vaom-guardian serve  --config guardian.json [--enroll label:role[,role...]]
// vaom-guardian verify --config guardian.json
// vaom-guardian scorecard --config guardian.json [--from ISO] [--to ISO] [--json]
// vaom-guardian probe import --config guardian.json result.json [result.json...]
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { scorecard, type Metric, type ProbeResult } from "@verkflode/vaom-guardian-core";
import { createGuardian, readConfig } from "./guardian.ts";
import { importProbeResults, verifyEvidence } from "./evidence.ts";
import { createGuardianServer } from "./server.ts";
import { Store } from "./store.ts";

const { positionals, values } = parseArgs({ allowPositionals: true, options: { config: { type: "string" }, enroll: { type: "string" }, from: { type: "string" }, to: { type: "string" }, json: { type: "boolean" } } });
const command = positionals[0];
if (!values.config || (command !== "serve" && command !== "verify" && command !== "scorecard" && !(command === "probe" && positionals[1] === "import"))) {
  console.error("usage: vaom-guardian serve --config guardian.json [--enroll label:role,role]\n       vaom-guardian verify --config guardian.json\n       vaom-guardian scorecard --config guardian.json [--from ISO] [--to ISO] [--json]\n       vaom-guardian probe import --config guardian.json result.json [...]");
  process.exit(2);
}
const config = readConfig(values.config);

if (command === "verify") {
  const r = verifyEvidence(new Store(config.dataDir), `http://localhost:${config.port}`);
  console.log(`${r.records} records, ${r.sessions} sessions, ${r.approvals} approvals, ${r.seeds} planted cases`);
  for (const p of r.problems) console.log(`PROBLEM ${p}`);
  process.exit(r.problems.length ? 1 : 0);
}

if (command === "probe") {
  const files = positionals.slice(2);
  if (files.length === 0) { console.error("probe import: name at least one result file"); process.exit(2); }
  const r = importProbeResults(new Store(config.dataDir), JSON.parse(readFileSync(config.matrix, "utf8")), files.map((f) => ({ name: f, result: JSON.parse(readFileSync(f, "utf8")) })));
  for (const x of r.rejected) console.error(`${x.name}: not imported: ${x.why}`);
  for (const x of r.duplicates) console.log(`${x}: already imported`);
  for (const x of r.imported) console.log(`imported ${x.boundary}: ${x.observed} (${x.ts})`);
  process.exit(r.rejected.length ? 1 : 0);
}

if (command === "scorecard") {
  // Read-only: the evidence files and the matrix, no Guardian started. Default period: the last 7 days.
  const to = values.to ?? new Date().toISOString();
  const from = values.from ?? new Date(Date.parse(to) - 7 * 86_400_000).toISOString();
  const store = new Store(config.dataDir);
  const seeds = store.events().filter((e) => e.type === "seed-outcome").map((e) => ({ row: e.row as string, ts: e.ts, result: e.result as "detected" | "missed" | "expired" }));
  const probes = store.events().filter((e) => e.type === "probe-result").map((e) => e.result as ProbeResult);
  const s = scorecard(JSON.parse(readFileSync(config.matrix, "utf8")), store.records(), { from, to, seeds, probes });
  if (values.json) { console.log(JSON.stringify(s, null, 2)); process.exit(0); }
  const line = (name: string, m: Metric) => console.log(`  ${(m.status === "breach" ? "BREACH" : m.status).padEnd(19)}  ${name}${m.diagnosis ? `: ${m.diagnosis}` : ""}`);
  console.log(`Scorecard for ${s.matrix.id}@${s.matrix.version}, ${s.period.from} to ${s.period.to}: ${s.records} records`);
  for (const r of s.rows) { console.log(`\n${r.row} (${r.decisions} ${r.decisions === 1 ? "decision" : "decisions"})`); for (const [k, m] of Object.entries(r.metrics)) line(k, m); }
  console.log("\nworkflow"); for (const [k, m] of Object.entries(s.workflow)) line(k, m);
  console.log("\nagents"); for (const [k, m] of Object.entries(s.agents)) line(`scope denials, ${k}`, m);
  console.log("\n--json gives every value, target and note.");
  process.exit(0);
}

const g = createGuardian(config);
if (g.recovered) console.log(`recovered: ${g.recovered} pending approval(s) from an unclean stop expired`);
const server = createGuardianServer(g);
server.listen(config.port, "127.0.0.1", () => {
  console.log(`VAOM Guardian: matrix ${g.policy.matrix.id}@${g.policy.matrix.version}, binding ${g.policy.binding.id}@${g.policy.binding.version}, scoring ${[...g.policy.scoring.keys()].join(", ") || "(none)"}`);
  console.log(`ACS endpoint  http://127.0.0.1:${config.port}/acs`);
  console.log(`approvals     ${g.origin}/`);
  if (values.enroll) {
    const [label, roles] = values.enroll.split(":");
    const token = g.approvals.openEnrollment(label ?? "", (roles ?? "").split(",").filter(Boolean), Date.now());
    console.log(`enroll (single use, 10 minutes): ${g.origin}/enroll#token=${token}`);
  } else if (!g.approvals.hasCredentials()) {
    console.log("no approver enrolled: every review and escalation will expire. Restart with --enroll label:role,role");
  }
});
setInterval(() => g.approvals.expire(Date.now()), 5000).unref();
const stop = () => server.close(() => process.exit(0));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
