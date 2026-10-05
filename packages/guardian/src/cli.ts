#!/usr/bin/env node
// vaom-guardian serve  --config guardian.json [--enroll label:role[,role...]]
// vaom-guardian verify --config guardian.json
import { parseArgs } from "node:util";
import { createGuardian, readConfig } from "./guardian.ts";
import { verifyEvidence } from "./evidence.ts";
import { createGuardianServer } from "./server.ts";
import { Store } from "./store.ts";

const { positionals, values } = parseArgs({ allowPositionals: true, options: { config: { type: "string" }, enroll: { type: "string" } } });
const command = positionals[0];
if (!values.config || (command !== "serve" && command !== "verify")) {
  console.error("usage: vaom-guardian serve --config guardian.json [--enroll label:role,role]\n       vaom-guardian verify --config guardian.json");
  process.exit(2);
}
const config = readConfig(values.config);

if (command === "verify") {
  const r = verifyEvidence(new Store(config.dataDir), `http://localhost:${config.port}`);
  console.log(`${r.records} records, ${r.sessions} sessions, ${r.approvals} approvals`);
  for (const p of r.problems) console.log(`PROBLEM ${p}`);
  process.exit(r.problems.length ? 1 : 0);
}

const g = createGuardian(config);
if (g.recovered) console.log(`recovered: ${g.recovered} pending approval(s) from an unclean stop expired`);
const server = createGuardianServer(g);
server.listen(config.port, "127.0.0.1", () => {
  console.log(`VAOM Guardian: matrix ${g.policy.matrix.id}@${g.policy.matrix.version}, binding ${g.policy.binding.id}@${g.policy.binding.version}`);
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
