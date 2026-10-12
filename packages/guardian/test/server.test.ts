// The Guardian process end to end over real HTTP on 127.0.0.1: an ACS agent session on the 7D incident
// example, a review routed to the approval page, enrollment and approval with a (software) WebAuthn
// authenticator, the shim's long-poll, execution, and offline verification of the evidence it left.
import { mkdtempSync, readFileSync, statSync, writeFileSync, rmSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { sessionKey, sign } from "@verkflode/vaom-guardian-acs";
import { createGuardian, createGuardianServer, readConfig, shimSignature, Store, verifyEvidence, type Guardian, type SeedOptions } from "../src/index.ts";
import { SoftAuthenticator } from "./authenticator.ts";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
const S1 = "11111111-1111-4111-8111-111111111111";
let n = 0;
const uuid = () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;

const open: { server: Server; dir: string }[] = [];
afterEach(() => {
  for (const o of open.splice(0)) { o.server.close(); rmSync(o.dir, { recursive: true, force: true }); }
});

function configFile(dir: string, port: number, extra: Record<string, unknown> = {}): string {
  const path = join(dir, "guardian.json");
  writeFileSync(path, JSON.stringify({
    format: "vaom-guardian.config/0.1",
    matrix: join(examples, "incident.matrix.json"),
    binding: join(examples, "incident.binding.json"),
    scoring: ["remediation-gate", "incident-detection"].map((s) => join(examples, `${s}.scoring.json`)),
    dataDir: "data",
    port,
    approvalTimeoutSeconds: 60,
    activation: { "incident-agent": { rows: ["remediation.restart"], task: "INC-7" } },
    ...extra,
  }));
  return path;
}

async function start(dir = mkdtempSync(join(tmpdir(), "vaom-guardian-")), extra: Record<string, unknown> = {}, seedOptions?: SeedOptions): Promise<{ g: Guardian; port: number; dir: string; server: Server }> {
  for (let tries = 0; ; tries++) {
    const port = 40000 + Math.floor(Math.random() * 20000);
    const g = createGuardian(readConfig(configFile(dir, port, extra)), Date.now(), seedOptions);
    const server = createGuardianServer(g);
    try {
      await new Promise<void>((res, rej) => { server.once("error", rej); server.listen(port, "127.0.0.1", () => res()); });
      open.push({ server, dir });
      return { g, port, dir, server };
    } catch (e) { if (tries > 5) throw e; }
  }
}

function http(port: number, method: string, path: string, o: { host?: string; origin?: string; type?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = o.body === undefined ? undefined : typeof o.body === "string" ? o.body : JSON.stringify(o.body);
    const req = request({ host: "127.0.0.1", port, method, path, headers: {
      host: o.host ?? `localhost:${port}`,
      ...(o.origin !== undefined ? { origin: o.origin } : {}),
      ...(data !== undefined ? { "content-type": o.type ?? "application/json", "content-length": Buffer.byteLength(data) } : {}),
      ...o.headers,
    } }, (res) => {
      let s = "";
      res.on("data", (c) => (s += c));
      res.on("end", () => { let json: any = null; try { json = JSON.parse(s); } catch { json = s; } resolve({ status: res.statusCode!, json }); });
    });
    req.on("error", reject);
    if (data !== undefined) req.write(data);
    req.end();
  });
}

/** An ACS agent: signs envelopes with the session key derived from the Guardian's shared secret. */
function agent(g: Guardian, port: number, session = S1, agentId = "incident-agent") {
  return async (method: string, payload: unknown, requestId = uuid()) => {
    const env = sign({ jsonrpc: "2.0", id: ++n, method, params: { acs_version: "0.1.0", request_id: requestId, timestamp: new Date().toISOString(), metadata: { agent_id: agentId, session_id: session }, payload } }, sessionKey(g.secrets.ikm, session), "shim");
    const r = await http(port, "POST", "/acs", { host: `127.0.0.1:${port}`, body: env });
    return { ...r.json, requestId };
  };
}
const hello = { acs_versions_supported: ["0.1.0"], methods_implemented: ["steps/sessionStart", "steps/toolCallRequest", "steps/toolCallResult"], transports_supported: ["http"], provenance_producer: "none" };
const restart = (incident: string) => ({ tool: { name: "mcp__deploy__rolling_restart" }, arguments: { incident_id: { value: incident }, service: { value: "web" }, stateless: { value: true } } });

async function session(g: Guardian, port: number) {
  const call = agent(g, port);
  await call("handshake/hello", hello);
  await call("steps/sessionStart", {});
  return call;
}

async function enroll(g: Guardian, port: number, roles: string[], auth = new SoftAuthenticator()) {
  const token = g.approvals.openEnrollment("owner", roles, Date.now());
  const origin = `http://localhost:${port}`;
  const o = await http(port, "POST", "/api/enroll/options", { origin, body: { token } });
  expect(o.status).toBe(200);
  const done = await http(port, "POST", "/api/enroll", { origin, body: { token, registration: auth.create({ challenge: o.json.challenge, origin, rpId: "localhost" }) } });
  expect(done.status, JSON.stringify(done.json)).toBe(200);
  return auth;
}

async function approveWith(port: number, auth: SoftAuthenticator, s: string, r: string) {
  const origin = `http://localhost:${port}`;
  const c = await http(port, "POST", `/api/asks/${s}/${r}/challenge`, { origin, body: {} });
  if (c.status !== 200) return c;
  return http(port, "POST", `/api/asks/${s}/${r}/approve`, { origin, body: auth.get({ challenge: c.json.challenge, origin, rpId: "localhost" }) });
}

function poll(g: Guardian, port: number, s: string, r: string, o: { wait?: number; ts?: string; sig?: string } = {}) {
  const path = `/v1/asks/${s}/${r}`;
  const ts = o.ts ?? new Date().toISOString();
  return http(port, "GET", `${path}${o.wait ? `?wait=${o.wait}` : ""}`, { host: `127.0.0.1:${port}`, headers: { "x-vaom-timestamp": ts, "x-vaom-signature": o.sig ?? shimSignature(g.secrets.ikm, s, "GET", path, ts) } });
}

describe("a review approved with WebAuthn, end to end", () => {
  it("routes to the page, approves with a user-verified assertion, executes, and verifies offline", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    expect(ask.result).toMatchObject({ decision: "ask", ask_details: { approver: { id: "sre-lead" } } });

    const page = await http(port, "GET", "/api/asks");
    expect(page.json.asks).toHaveLength(1);
    expect(page.json.asks[0]).toMatchObject({ tool: "mcp__deploy__rolling_restart", arguments: { incident_id: "INC-7", service: "web", stateless: true }, approver_role: "sre-lead", band: "B" });

    expect((await poll(g, port, S1, ask.requestId)).json.status).toBe("pending");
    const auth = await enroll(g, port, ["sre-lead"]);
    const waiting = poll(g, port, S1, ask.requestId, { wait: 10 });
    const ok = await approveWith(port, auth, S1, ask.requestId);
    expect(ok.status, JSON.stringify(ok.json)).toBe(200);
    expect((await waiting).json.status).toBe("approved");

    const res = await call("steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: ask.requestId, exit_status: "success", outputs: [] });
    expect(res.result.decision).toBe("allow");
    const rec = g.store.records().find((r) => r.request.wire?.request_id === ask.requestId)!;
    expect(rec.resolution).toMatchObject({ result: "executed", approval: { approver_role: "sre-lead" } });

    const report = verifyEvidence(new Store(join(g.config.dataDir)), g.origin);
    expect(report).toMatchObject({ records: 1, approvals: 1, problems: [] });
    expect(report.sessions).toBe(1);
  });
});

describe("spawns are evidence", () => {
  it("stores every sub-agent spawn decision as an event", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const spawn = (type: string, sub: string) => call("steps/subagentStart", { subagent_session_id: sub, parent_session_id: S1, parent_step_id: uuid(), intent_derivation: "inherit_subset", subagent_descriptor: { agent_name: type } });
    expect((await spawn("log-analysis", "22222222-2222-4222-8222-222222222222")).result.decision).toBe("allow");
    expect((await spawn("shell", "33333333-3333-4333-8333-333333333333")).result.decision).toBe("deny");
    expect(g.store.events().filter((e) => e.type === "spawn").map((e) => [e.type, e.decision, e.reason])).toEqual([["spawn", "allow", "context_derived"], ["spawn", "deny", "outside_allowed_patterns"]]);
  });
});

describe("who approved is recorded only when the matrix enables reviewer-level metrics", () => {
  async function approvedOnce(extra: Record<string, unknown> = {}) {
    const { g, port } = await start(undefined, extra);
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    const auth = await enroll(g, port, ["sre-lead"]);
    expect((await approveWith(port, auth, S1, ask.requestId)).status).toBe(200);
    await call("steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: ask.requestId, exit_status: "success", outputs: [] });
    const rec = g.store.records().find((r) => r.request.wire?.request_id === ask.requestId)!;
    const ev = g.store.events().find((e) => e.type === "approval")!;
    return { g, rec, ev };
  }
  it("off (the default): neither the record nor the approval event names the approver, and verify still passes", async () => {
    const { g, rec, ev } = await approvedOnce();
    expect(rec.resolution?.approval).not.toHaveProperty("approver_id");
    expect(ev).not.toHaveProperty("approver_id");
    expect(JSON.stringify(g.store.records())).not.toContain('"owner"');
    expect(verifyEvidence(new Store(g.config.dataDir), g.origin).problems).toEqual([]);
  });
  it("on, with its recorded approval: both name the approver", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaom-guardian-"));
    const m = JSON.parse(readFileSync(join(examples, "incident.matrix.json"), "utf8"));
    m.oversight.reviewerLevelMetrics = { enabled: true, approvalRef: "placeholder: DPIA" };
    writeFileSync(join(dir, "matrix.json"), JSON.stringify(m));
    const { rec, ev } = await approvedOnce({ matrix: join(dir, "matrix.json") });
    expect(rec.resolution?.approval).toMatchObject({ approver_id: "owner" });
    expect(ev.approver_id).toBe("owner");
  });
});

describe("a review approved with WebAuthn, end to end (process)", () => {
  it("keeps its data private: directory 0700, secrets 0600", async () => {
    const { g } = await start();
    expect(statSync(g.config.dataDir).mode & 0o777).toBe(0o700);
    expect(statSync(join(g.config.dataDir, "secrets.json")).mode & 0o777).toBe(0o600);
  });
});

describe("approvals can't be forged or reused", () => {
  it("refuses a credential that doesn't hold the approver role", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    const auth = await enroll(g, port, ["head-of-engineering"]);
    const r = await approveWith(port, auth, S1, ask.requestId);
    expect(r.status).toBe(403);
    expect((await poll(g, port, S1, ask.requestId)).json.status).toBe("pending");
  });
  it("refuses an assertion from an enrolled credential that doesn't hold the role, even with the right challenge", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const origin = `http://localhost:${port}`;
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    await enroll(g, port, ["sre-lead"]);
    const lead = await enroll(g, port, ["head-of-engineering"]);
    const c = await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/challenge`, { origin, body: {} });
    expect(c.json.allowCredentials).not.toContain(lead.credentialId);
    const r = await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/approve`, { origin, body: lead.get({ challenge: c.json.challenge, origin, rpId: "localhost" }) });
    expect(r.status).toBe(403);
    expect(r.json.error).toMatch(/doesn't hold the role/);
  });
  it("a challenge expires after two minutes", async () => {
    const { g, port } = await start(undefined, { approvalTimeoutSeconds: 300 });
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    const auth = await enroll(g, port, ["sre-lead"]);
    const t = Date.now();
    const c = g.approvals.challenge(S1, ask.requestId, t);
    expect(() => g.approvals.approve(S1, ask.requestId, auth.get({ challenge: c.challenge, origin: g.origin, rpId: "localhost" }), t + 121_000)).toThrow(/no live challenge/);
  });
  it("a cross-origin page can't reject an ask (CSRF)", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    expect((await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/reject`, { origin: "http://evil.example", body: {} })).status).toBe(403);
    expect((await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/reject`, { body: {} })).status).toBe(403);
    expect((await poll(g, port, S1, ask.requestId)).json.status).toBe("pending");
  });
  it("refuses an approval without a challenge, a replayed assertion, and an unenrolled authenticator", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const origin = `http://localhost:${port}`;
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    const auth = await enroll(g, port, ["sre-lead"]);
    expect((await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/approve`, { origin, body: auth.get({ challenge: "AAAA", origin, rpId: "localhost" }) })).status).toBe(409);
    const stranger = new SoftAuthenticator();
    const c = await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/challenge`, { origin, body: {} });
    expect((await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/approve`, { origin, body: stranger.get({ challenge: c.json.challenge, origin, rpId: "localhost" }) })).status).toBe(403);
    // A challenge is single use even after a failed attempt.
    expect((await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/approve`, { origin, body: auth.get({ challenge: c.json.challenge, origin, rpId: "localhost" }) })).status).toBe(409);
    // An assertion over one ask's challenge doesn't approve another.
    const ask2 = await call("steps/toolCallRequest", restart("INC-7"));
    const c1 = await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/challenge`, { origin, body: {} });
    await http(port, "POST", `/api/asks/${S1}/${ask2.requestId}/challenge`, { origin, body: {} });
    expect((await http(port, "POST", `/api/asks/${S1}/${ask2.requestId}/approve`, { origin, body: auth.get({ challenge: c1.json.challenge, origin, rpId: "localhost" }) })).status).toBe(403);
  });
  it("an ask that executes without approval is an incident, and verify reports it", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    const res = await call("steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: ask.requestId, exit_status: "success", outputs: [] });
    expect(res.result.reason_codes).toEqual(["execution_without_authority"]);
    expect(verifyEvidence(g.store, g.origin).problems.join("\n")).toMatch(/incident .*execution-without-authority/);
  });
  it("tampering with an approval or the chain on disk is caught by verify", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    const auth = await enroll(g, port, ["sre-lead"]);
    await approveWith(port, auth, S1, ask.requestId);
    await call("steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: ask.requestId, exit_status: "success", outputs: [] });
    expect(verifyEvidence(g.store, g.origin).problems).toEqual([]);

    const ev = join(g.config.dataDir, "events.jsonl");
    const original = readFileSync(ev, "utf8");
    writeFileSync(ev, original.replace(/"approver_role":"sre-lead"/, '"approver_role":"head-of-engineering"'));
    expect(verifyEvidence(g.store, g.origin).problems.join("\n")).toMatch(/approval .*(doesn't hold|different decision)/);
    writeFileSync(ev, original);

    const tampered = (from: RegExp, to: string) => { writeFileSync(ev, original.replace(from, to)); const p = verifyEvidence(g.store, g.origin).problems.join("\n"); writeFileSync(ev, original); return p; };
    // A forged signature.
    const sig = /"signature":"([A-Za-z0-9_-]+)"/.exec(original)![1]!;
    expect(tampered(new RegExp(`"signature":"${sig}"`), `"signature":"${sig.slice(0, -4)}AAAA"`)).toMatch(/signature does not verify/);
    // An enrollment edited to drop the role the approval used.
    expect(tampered(/"roles":\["sre-lead"\]/, '"roles":["head-of-engineering"]')).toMatch(/doesn't hold sre-lead/);
    // A record whose approval reference points nowhere.
    const recs = join(g.config.dataDir, "records.jsonl");
    const recOriginal = readFileSync(recs, "utf8");
    const apId = /"approval":\{[^}]*"record":"([^"]+)"/.exec(recOriginal)![1]!;
    writeFileSync(recs, recOriginal.split(apId).join("00000000-0000-4000-8000-000000000000"));
    expect(verifyEvidence(g.store, g.origin).problems.join("\n")).toMatch(/executed without a verifiable approval/);
    writeFileSync(recs, recOriginal);
    expect(verifyEvidence(g.store, g.origin).problems).toEqual([]);

    const ch = join(g.config.dataDir, "chain.jsonl");
    writeFileSync(ch, readFileSync(ch, "utf8").replace('"step_type":"toolCallRequest"', '"step_type":"turnStart"'));
    expect(verifyEvidence(g.store, g.origin).problems.join("\n")).toMatch(/hash chain does not verify/);
  });
});

describe("reject, expire, recover", () => {
  it("a rejection resolves the record and the shim sees it", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    expect((await http(port, "POST", `/api/asks/${S1}/${ask.requestId}/reject`, { origin: `http://localhost:${port}`, body: {} })).status).toBe(200);
    expect((await poll(g, port, S1, ask.requestId)).json.status).toBe("rejected");
    expect(g.store.records().at(-1)?.resolution?.result).toBe("rejected");
  });
  it("an ask past its timeout expires: deny", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    g.approvals.expire(Date.now() + 61_000);
    expect((await poll(g, port, S1, ask.requestId)).json.status).toBe("expired");
    expect(g.store.records().at(-1)?.resolution?.result).toBe("expired");
  });
  it("after an unclean stop, unapproved asks expire on restart, and the evidence still verifies", async () => {
    const first = await start();
    const call = await session(first.g, first.port);
    await call("steps/toolCallRequest", restart("INC-7"));
    first.server.close();
    open.splice(open.findIndex((o) => o.server === first.server), 1);
    const second = await start(first.dir);
    expect(second.g.recovered).toBe(1);
    expect(second.g.store.records()[0]?.resolution?.result).toBe("expired");
    expect(verifyEvidence(second.g.store, second.g.origin).problems).toEqual([]);
  });
  it("refuses to start on a damaged history, but skips a torn last line", async () => {
    const first = await start();
    const call = await session(first.g, first.port);
    await call("steps/toolCallRequest", restart("INC-8"));
    first.server.close();
    open.splice(open.findIndex((o) => o.server === first.server), 1);
    const recs = join(first.g.config.dataDir, "records.jsonl");
    const good = readFileSync(recs, "utf8");
    writeFileSync(recs, good + '{"id":"torn');
    const ok = await start(first.dir);
    ok.server.close();
    open.splice(open.findIndex((o) => o.server === ok.server), 1);
    writeFileSync(recs, '{"broken\n' + good);
    expect(() => createGuardian(readConfig(join(first.dir, "guardian.json")))).toThrow(/damaged/);
    rmSync(first.dir, { recursive: true, force: true });
  });
});

describe("persistence failure answers with an error, never the decision", () => {
  it("when records can't be written", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    g.store.appendRecords = () => { throw new Error("disk full"); };
    const r = await call("steps/toolCallRequest", restart("INC-7"));
    expect(r.result).toBeUndefined();
    expect(r.error.code).toBe(-32603);
    expect((await http(port, "GET", "/api/asks")).json.asks).toEqual([]);
  });
});

describe("HTTP boundary", () => {
  it("browser routes refuse other hosts (DNS rebinding), cross-origin posts and non-JSON bodies", async () => {
    const { port } = await start();
    expect((await http(port, "GET", "/api/asks", { host: `evil.example:${port}` })).status).toBe(421);
    expect((await http(port, "GET", "/api/asks", { host: `127.0.0.1:${port}` })).status).toBe(421);
    expect((await http(port, "POST", "/api/enroll/options", { origin: "http://evil.example", body: {} })).status).toBe(403);
    expect((await http(port, "POST", "/api/enroll/options", { origin: `http://localhost:${port}`, type: "text/plain", body: "{}" })).status).toBe(415);
  });
  it("the ACS route refuses other hosts and methods", async () => {
    const { port } = await start();
    expect((await http(port, "POST", "/acs", { host: `evil.example:${port}`, body: {} })).status).toBe(421);
    expect((await http(port, "GET", "/acs", { host: `127.0.0.1:${port}` })).status).toBe(405);
  });
  it("the shim's poll needs a fresh, valid signature", async () => {
    const { g, port } = await start();
    const call = await session(g, port);
    const ask = await call("steps/toolCallRequest", restart("INC-7"));
    expect((await poll(g, port, S1, ask.requestId, { sig: "AAAA" })).status).toBe(401);
    expect((await poll(g, port, S1, ask.requestId, { ts: new Date(Date.now() - 60_000).toISOString() })).status).toBe(401);
    const other = "22222222-2222-4222-8222-222222222222";
    const path = `/v1/asks/${S1}/${ask.requestId}`, ts = new Date().toISOString();
    expect((await http(port, "GET", path, { host: `127.0.0.1:${port}`, headers: { "x-vaom-timestamp": ts, "x-vaom-signature": shimSignature(g.secrets.ikm, other, "GET", path, ts) } })).status).toBe(401);
  });
  it("enrollment needs the terminal's token, once", async () => {
    const { g, port } = await start();
    const origin = `http://localhost:${port}`;
    expect((await http(port, "POST", "/api/enroll/options", { origin, body: { token: "guess" } })).status).toBe(403);
    const token = g.approvals.openEnrollment("owner", ["head-of-engineering"], Date.now());
    expect((await http(port, "POST", "/api/enroll/options", { origin, body: { token: token.slice(0, -1) + "x" } })).status).toBe(403);
    const o = await http(port, "POST", "/api/enroll/options", { origin, body: { token } });
    const reg = new SoftAuthenticator().create({ challenge: o.json.challenge, origin, rpId: "localhost" });
    expect((await http(port, "POST", "/api/enroll", { origin, body: { token, registration: reg } })).status).toBe(200);
    expect((await http(port, "POST", "/api/enroll/options", { origin, body: { token } })).status).toBe(403);
    expect((await http(port, "POST", "/api/enroll", { origin, body: { token, registration: reg } })).status).toBe(403);
    expect(() => g.approvals.openEnrollment("x", ["ceo"], Date.now())).toThrow(/not in the matrix/);
  });
  it("pages are served with a strict CSP and no framing", async () => {
    const { port } = await start();
    const r = await new Promise<{ headers: Record<string, unknown> }>((res) => request({ host: "127.0.0.1", port, path: "/", headers: { host: `localhost:${port}` } }, (m) => { m.resume(); res({ headers: m.headers }); }).end());
    expect(String(r.headers["content-security-policy"])).toContain("script-src 'self'");
    expect(r.headers["x-frame-options"]).toBe("DENY");
  });
});

describe("config", () => {
  it("rejects unknown keys, rows not in the matrix, and timeouts over the hook limit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaom-guardian-"));
    try {
      expect(() => readConfig(configFile(dir, 47100, { extra: 1 }))).toThrow(/unknown key/);
      expect(() => readConfig(configFile(dir, 47100, { approvalTimeoutSeconds: 600 }))).toThrow(/under Claude Code/);
      expect(() => createGuardian(readConfig(configFile(dir, 47100, { activation: { a: { rows: ["nope"] } } })))).toThrow(/not in the matrix/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe("seeded cases (VAOM v5 Readiness Condition 6)", () => {
  const seeds = join(examples, "incident.seeds.json");
  const always: SeedOptions = { random: () => 0, delayMs: [0, 0] };
  const origin = (port: number) => `http://localhost:${port}`;
  /** A real restart ask, then the queue as the page sees it, with the planted case due at once. */
  async function queued(seedOptions: SeedOptions = always, extra: Record<string, unknown> = { seeds }) {
    const s = await start(undefined, extra, seedOptions);
    const call = await session(s.g, s.port);
    const real = await call("steps/toolCallRequest", restart("INC-7"));
    const page = await http(s.port, "GET", "/api/asks");
    const seed = page.json.asks.find((a: { request_id: string }) => a.request_id !== real.requestId);
    return { ...s, call, real, page, seed };
  }

  it("plants beside a real review on a seeded row, looking exactly like a real ask, and discloses the rate", async () => {
    const { g, page, real, seed } = await queued();
    expect(page.json.asks).toHaveLength(2);
    const realAsk = page.json.asks.find((a: { request_id: string }) => a.request_id === real.requestId);
    expect(Object.keys(seed).sort()).toEqual(Object.keys(realAsk).sort());
    expect(seed).toMatchObject({ tool: "mcp__deploy__rolling_restart", band: "B", approver_role: "sre-lead", rows: ["remediation.restart"], agent: "incident-agent", arguments: { incident_id: "INC-7" } });
    expect(seed.reasons).toEqual(realAsk.reasons);
    expect(JSON.stringify(page.json.asks)).not.toMatch(/planted|seed|known error/i);
    expect(page.json.seeding).toMatchObject({ rows: [{ row: "remediation.restart", rate: 0.05 }] });
    expect(page.json.seeding.statement).toMatch(/planted/);
    // Marked in the store, never a decision record.
    expect(g.store.events().filter((e) => e.type === "seed-planted")).toHaveLength(1);
    expect(g.store.records().map((r) => r.request.wire?.request_id)).not.toContain(seed.request_id);
  });

  it("a rejected seed is a detection, revealed after the decision; nothing reaches the records", async () => {
    const { g, port, seed } = await queued();
    const before = g.store.records().length;
    const r = await http(port, "POST", `/api/asks/${seed.session}/${seed.request_id}/reject`, { origin: origin(port), body: {} });
    expect(r.json).toMatchObject({ status: "rejected", seeded: { error: expect.stringMatching(/./) } });
    expect(g.store.events().find((e) => e.type === "seed-outcome")).toMatchObject({ result: "detected", row: "remediation.restart" });
    expect(g.store.records()).toHaveLength(before);
  });

  it("an approved seed is a miss: it takes Touch ID like any approval, never executes, and verify checks it", async () => {
    const { g, port, real, seed } = await queued();
    const auth = await enroll(g, port, ["sre-lead"]);
    const r = await approveWith(port, auth, seed.session, seed.request_id);
    expect(r.json).toMatchObject({ status: "approved", seeded: { error: expect.stringMatching(/./) } });
    expect(g.store.events().find((e) => e.type === "seed-outcome")).toMatchObject({ result: "missed" });
    expect(g.store.events().find((e) => e.type === "seed-outcome")).not.toHaveProperty("approver_id");
    expect(g.store.events().filter((e) => e.type === "approval")).toHaveLength(0);
    // The real ask is untouched: still pending, still the only decision.
    expect((await poll(g, port, S1, real.requestId)).json.status).toBe("pending");
    expect(g.store.records().filter((x) => x.resolution?.result === "executed")).toHaveLength(0);
    expect(verifyEvidence(new Store(g.config.dataDir), g.origin)).toMatchObject({ seeds: 1, problems: [] });
  });

  it("verify flags a planted case that turns up as a decision record", async () => {
    const { g, seed } = await queued();
    const planted = g.store.events().find((e) => e.type === "seed-planted")!;
    const fake = { ...g.store.records()[0]!, id: planted.decision as string };
    g.store.appendRecords([fake as never]);
    expect(seed).toBeDefined();
    expect(verifyEvidence(new Store(g.config.dataDir), g.origin).problems.join("\n")).toMatch(/planted case became a decision record/);
  });

  it("verify flags a seed outcome with no planted seed, and a second outcome for one seed", async () => {
    const { g, port, seed } = await queued();
    await http(port, "POST", `/api/asks/${seed.session}/${seed.request_id}/reject`, { origin: origin(port), body: {} });
    const outcome = g.store.events().find((e) => e.type === "seed-outcome")!;
    expect(verifyEvidence(new Store(g.config.dataDir), g.origin).problems).toEqual([]);
    g.store.appendEvents([{ ...outcome, id: "forged-1", decision: "not-a-seed" }, { ...outcome, id: "forged-2" }]);
    const problems = verifyEvidence(new Store(g.config.dataDir), g.origin).problems.join("\n");
    expect(problems).toMatch(/seed outcome forged-1: no planted seed/);
    expect(problems).toMatch(/seed outcome forged-2: seed .* already has an outcome/);
  });

  it("an undecided seed expires, and counts neither way", async () => {
    const { g, seed } = await queued();
    g.approvals.expire(Date.now() + 3_600_000);
    expect(g.store.events().find((e) => e.type === "seed-outcome")).toMatchObject({ result: "expired", request_id: seed.request_id });
  });

  it("a seed left pending by an unclean stop expires on restart", async () => {
    const { g, dir } = await queued();
    const again = await start(dir, { seeds }, always);
    expect(again.g.store.events().find((e) => e.type === "seed-outcome")).toMatchObject({ result: "expired", recovered: true });
    expect(g).toBeDefined();
  });

  it("plants nothing when the draw says no, or when no seed set is configured", async () => {
    expect((await queued({ random: () => 0.99, delayMs: [0, 0] })).page.json.asks).toHaveLength(1);
    const off = await queued(always, {});
    expect(off.page.json.asks).toHaveLength(1);
    expect(off.page.json.seeding).toBeNull();
  });

  it("skips a seed that a real call like it wouldn't send to review, rather than plant something unlike a real ask", async () => {
    // Without copying the incident id, the seed falls outside the session's context: unplaceable, never asked.
    const dir = mkdtempSync(join(tmpdir(), "vaom-guardian-"));
    const s = JSON.parse(readFileSync(seeds, "utf8"));
    for (const x of s.seeds) delete x.copy;
    writeFileSync(join(dir, "seeds.json"), JSON.stringify(s));
    const { g, page } = await queued(always, { seeds: join(dir, "seeds.json") });
    expect(page.json.asks).toHaveLength(1);
    expect(g.store.events().filter((e) => e.type === "seed-skipped")).toHaveLength(1);
    expect(g.store.events().filter((e) => e.type === "seed-planted")).toHaveLength(0);
  });

  it("refuses to start with seeds for a row that doesn't enable seeding", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaom-guardian-"));
    const s = JSON.parse(readFileSync(seeds, "utf8"));
    s.seeds[0].row = "incident.monitor"; s.seeds[0].tool = "mcp__incident__declare";
    writeFileSync(join(dir, "seeds.json"), JSON.stringify(s));
    await expect(start(dir, { seeds: join(dir, "seeds.json") })).rejects.toThrow(/doesn't enable seeding/);
  });
});
