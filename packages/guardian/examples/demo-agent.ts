// A stand-in agent for trying the approval page: negotiates, starts a session, asks to restart a service
// for incident INC-7 (Band B: the score is high, but the row needs an independent verifier and the Guardian
// has none, so it goes to the SRE lead for review), waits for the human's decision, and
// reports the execution. Run it while the Guardian is serving examples/incident.guardian.json:
//   node packages/guardian/examples/demo-agent.ts
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { sessionKey, sign } from "@verkflode/vaom-guardian-acs";
import { readConfig, shimSignature } from "../src/index.ts";

const config = readConfig(join(import.meta.dirname, "incident.guardian.json"));
const secrets = JSON.parse(readFileSync(join(config.dataDir, "secrets.json"), "utf8"));
const ikm = new Uint8Array(Buffer.from(secrets.ikm, "base64"));
const base = `http://127.0.0.1:${config.port}`;
const session = randomUUID();
let id = 0;

async function acs(method: string, payload: unknown, requestId = randomUUID()) {
  const env = sign({ jsonrpc: "2.0", id: ++id, method, params: { acs_version: "0.1.0", request_id: requestId, timestamp: new Date().toISOString(), metadata: { agent_id: "incident-agent", session_id: session }, payload } }, sessionKey(ikm, session), "demo");
  const r = await fetch(`${base}/acs`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(env) });
  return { requestId, ...(await r.json()) };
}

await acs("handshake/hello", { acs_versions_supported: ["0.1.0"], methods_implemented: ["steps/sessionStart", "steps/toolCallRequest", "steps/toolCallResult"], transports_supported: ["http"], provenance_producer: "none" });
await acs("steps/sessionStart", {});
const ask = await acs("steps/toolCallRequest", { tool: { name: "mcp__deploy__rolling_restart" }, arguments: { incident_id: { value: "INC-7" }, service: { value: "checkout-api" }, stateless: { value: true } } });
console.log(`decision: ${ask.result.decision}${ask.result.ask_details ? `, approver ${ask.result.ask_details.approver.id}` : ""}`);
if (ask.result.decision !== "ask") process.exit(0);
console.log(`open http://localhost:${config.port}/ and decide`);

let status = "pending";
while (status === "pending") {
  const path = `/v1/asks/${session}/${ask.requestId}`, ts = new Date().toISOString();
  const r = await fetch(`${base}${path}?wait=25`, { headers: { "x-vaom-timestamp": ts, "x-vaom-signature": shimSignature(ikm, session, "GET", path, ts) } });
  status = ((await r.json()) as { status: string }).status;
}
console.log(`status: ${status}`);
if (status === "approved") {
  const res = await acs("steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: ask.requestId, exit_status: "success", outputs: [] });
  console.log(`execution recorded: ${res.result.decision}`);
}
