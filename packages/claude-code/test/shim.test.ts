// The shim against a real Guardian over HTTP on 127.0.0.1, on the 7D incident example: hook inputs shaped
// as Claude Code sends them, decisions out, evidence checked with the Guardian's own verify.
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, request, type Server } from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createGuardian, createGuardianServer, readConfig, Store, verifyEvidence, type Guardian } from "@verkflode/vaom-guardian-server";
import { SoftAuthenticator } from "../../guardian/test/authenticator.ts";
import { GuardianClient, runHook, StateDir, type FailureEntry, type ShimOptions } from "../src/index.ts";
import { sessionKey, sign } from "@verkflode/vaom-guardian-acs";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
const CLI = join(import.meta.dirname, "..", "src", "cli.ts");
const CC = "5d1c1b0e-6a0c-4c51-9d0e-2f0f6c1d7a10"; // a Claude Code session id
const AGENT = "incident-agent";

const cleanup: (() => void)[] = [];
afterEach(() => { for (const f of cleanup.splice(0)) f(); });

function listen(server: Server): Promise<number> {
  return (async () => {
    for (let tries = 0; ; tries++) {
      const port = 40000 + Math.floor(Math.random() * 20000);
      try {
        await new Promise<void>((res, rej) => { server.once("error", rej); server.listen(port, "127.0.0.1", () => res()); });
        return port;
      } catch (e) { if (tries > 5) throw e; }
    }
  })();
}

interface Running { g: Guardian; port: number; dir: string; config: string; stop(): Promise<void> }

async function guardian(dir = mkdtempSync(join(tmpdir(), "vaom-shim-")), port?: number): Promise<Running> {
  const config = join(dir, "guardian.json");
  const write = (p: number) => writeFileSync(config, JSON.stringify({
    format: "vaom-guardian.config/0.1",
    matrix: join(examples, "incident.matrix.json"),
    binding: join(examples, "incident.binding.json"),
    scoring: ["remediation-gate", "incident-detection"].map((s) => join(examples, `${s}.scoring.json`)),
    dataDir: "data",
    port: p,
    approvalTimeoutSeconds: 30,
    activation: { [AGENT]: { rows: ["remediation.restart"], task: "INC-7" } },
  }));
  write(port ?? 1024);
  let g = createGuardian(readConfig(config));
  let server = createGuardianServer(g);
  let p: number;
  if (port) { await new Promise<void>((res) => server.listen(port, "127.0.0.1", () => res())); p = port; }
  else {
    // The config names the port, and the Guardian's Host checks use it: pick one, then rebuild with it.
    p = await listen(server);
    server.close();
    write(p);
    g = createGuardian(readConfig(config));
    server = createGuardianServer(g);
    await new Promise<void>((res) => server.listen(p, "127.0.0.1", () => res()));
  }
  let stopped = false;
  const stop = () => new Promise<void>((res) => { if (stopped) return res(); stopped = true; server.closeAllConnections(); server.close(() => res()); });
  cleanup.push(() => { void stop(); rmSync(dir, { recursive: true, force: true }); });
  return { g, port: p, dir, config, stop };
}

function shim(r: Running, o: Partial<ShimOptions> & { state?: StateDir } = {}): ShimOptions {
  const client = new GuardianClient({ port: r.port, ikm: r.g.secrets.ikm, keyId: r.g.secrets.keyId, agentId: AGENT, requestTimeoutMs: 5000 });
  return { client, state: o.state ?? new StateDir(join(r.dir, "shim")), deadline: Date.now() + 60_000, approvalsUrl: `http://localhost:${r.port}/`, ...o };
}

let n = 0;
const toolUse = () => `toolu_${String(++n).padStart(6, "0")}`;
const pre = (tool: string, input: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({ hook_event_name: "PreToolUse", session_id: CC, permission_mode: "default", tool_name: tool, tool_input: input, tool_use_id: toolUse(), ...extra });
const post = (p: { tool_name: string; tool_input: unknown; tool_use_id: string }, event = "PostToolUse") => ({ hook_event_name: event, session_id: CC, permission_mode: "default", tool_name: p.tool_name, tool_input: p.tool_input, tool_use_id: p.tool_use_id, tool_output: "ok" });
const decision = (out: any) => out?.hookSpecificOutput?.permissionDecision;
const restart = (incident = "INC-7") => pre("mcp__deploy__rolling_restart", { incident_id: incident, service: "web", stateless: true });

function http(port: number, method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const origin = `http://localhost:${port}`;
    const req = request({ host: "127.0.0.1", port, method, path, headers: { host: `localhost:${port}`, origin, ...(data ? { "content-type": "application/json", "content-length": Buffer.byteLength(data) } : {}) } }, (res) => {
      let s = ""; res.on("data", (c) => (s += c)); res.on("end", () => resolve({ status: res.statusCode!, json: JSON.parse(s) }));
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

async function enroll(r: Running, roles: string[]): Promise<SoftAuthenticator> {
  const auth = new SoftAuthenticator();
  const token = r.g.approvals.openEnrollment("owner", roles, Date.now());
  const origin = `http://localhost:${r.port}`;
  const o = await http(r.port, "POST", "/api/enroll/options", { token });
  expect((await http(r.port, "POST", "/api/enroll", { token, registration: auth.create({ challenge: o.json.challenge, origin, rpId: "localhost" }) })).status).toBe(200);
  return auth;
}

/** Wait until the approval page shows an ask, then approve or reject it as a human would. */
async function decideOnPage(r: Running, how: "approve" | "reject", auth?: SoftAuthenticator): Promise<void> {
  let ask: any;
  for (let i = 0; i < 200 && !ask; i++) { ask = (await http(r.port, "GET", "/api/asks")).json.asks[0]; if (!ask) await new Promise((res) => setTimeout(res, 20)); }
  expect(ask).toBeTruthy();
  const base = `/api/asks/${ask.session}/${ask.request_id}`;
  if (how === "reject") { expect((await http(r.port, "POST", `${base}/reject`, {})).status).toBe(200); return; }
  const c = await http(r.port, "POST", `${base}/challenge`, {});
  const ok = await http(r.port, "POST", `${base}/approve`, auth!.get({ challenge: c.json.challenge, origin: `http://localhost:${r.port}`, rpId: "localhost" }));
  expect(ok.status, JSON.stringify(ok.json)).toBe(200);
}

describe("PreToolUse decisions", () => {
  it("allows a call the Guardian allows, and reports its execution", async () => {
    const r = await guardian();
    const o = shim(r);
    const call = pre("mcp__telemetry__query", { query: "error rate web" });
    const out = await runHook(call, o);
    expect(decision(out), JSON.stringify(out)).toBe("allow");
    expect(await runHook(post(call), o)).toBeNull();
    const rec = r.g.store.records().filter((x) => x.request.action.tool === "mcp__telemetry__query").at(-1)!;
    expect(rec.resolution?.result).toBe("executed");
    expect(o.state.read(CC)!.calls).toEqual({});
  });

  it("denies a tool the binding doesn't map: unplaceable is defer, and defer times out to deny", async () => {
    const r = await guardian();
    const out = await runHook(pre("Bash", { command: "touch CANARY" }), shim(r));
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/unmapped/);
    const rec = r.g.store.records().at(-1)!;
    expect(rec.request.action.tool).toBe("Bash");
    expect(rec.resolution?.result).toBe("not-executed");
  });

  it("passes ToolSearch through without the Guardian: it loads a schema and acts on nothing", async () => {
    const r = await guardian();
    const o = shim(r);
    const call = pre("ToolSearch", { query: "select:mcp__deploy__rolling_restart", max_results: 1 });
    expect(decision(await runHook(call, o))).toBe("allow");
    expect(await runHook(post(call), o)).toBeNull();
    expect(r.g.store.records()).toHaveLength(0);
    expect(r.g.store.events().filter((e) => e.type === "incident")).toHaveLength(0);
  });

  it("denies under bypassPermissions without asking the Guardian", async () => {
    const r = await guardian();
    const out = await runHook(pre("mcp__telemetry__query", { query: "x" }, { permission_mode: "bypassPermissions" }), shim(r));
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/bypassPermissions/);
    expect(r.g.store.records()).toHaveLength(0);
  });

  it("denies when no Guardian answers (startup posture refuse, not proceed)", async () => {
    const r = await guardian();
    await r.stop();
    const out = await runHook(pre("mcp__telemetry__query", { query: "x" }), shim(r));
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/no decision could be obtained/);
  });

  it("denies when the Guardian negotiates a session but opens no execution context for this agent", async () => {
    const r = await guardian();
    const o = shim(r);
    const stranger = { ...o, client: new GuardianClient({ port: r.port, ikm: r.g.secrets.ikm, keyId: r.g.secrets.keyId, agentId: "someone-else", requestTimeoutMs: 5000 }) };
    expect(decision(await runHook(pre("mcp__telemetry__query", { query: "x" }), stranger))).toBe("deny");
  });

  it("denies an answer that isn't signed by the Guardian, even an allow", async () => {
    const r = await guardian();
    const o = shim(r);
    await runHook({ hook_event_name: "SessionStart", session_id: CC, source: "startup" }, o);
    await r.stop();
    // Something else takes the port and answers every request with an unsigned allow.
    const impostor = createServer((req, res) => {
      let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => {
        const env = JSON.parse(s);
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ jsonrpc: "2.0", id: env.id, result: { type: "final", acs_version: "0.1.0", request_id: env.params.request_id, decision: "allow", chain_hash: "0".repeat(64) } }));
      });
    });
    await new Promise<void>((res) => impostor.listen(r.port, "127.0.0.1", () => res()));
    cleanup.push(() => impostor.close());
    const out = await runHook(pre("mcp__telemetry__query", { query: "x" }), o);
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/signature/);
  });

  it("denies an answer signed with the right secret under another key_id", async () => {
    const r = await guardian();
    const o = shim(r);
    await runHook({ hook_event_name: "SessionStart", session_id: CC, source: "startup" }, o);
    await r.stop();
    // A valid HMAC, but labelled as another secret: the shim holds one label and accepts no other (ACS §10).
    const impostor = createServer((req, res) => {
      let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => {
        const env = JSON.parse(s);
        const answer = { jsonrpc: "2.0", id: env.id, result: { type: "final", acs_version: "0.1.0", request_id: env.params.request_id, decision: "allow", chain_hash: "0".repeat(64) } };
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(sign(answer, sessionKey(r.g.secrets.ikm, env.params.metadata.session_id), "another-label")));
      });
    });
    await new Promise<void>((res) => impostor.listen(r.port, "127.0.0.1", () => res()));
    cleanup.push(() => impostor.close());
    const out = await runHook(pre("mcp__telemetry__query", { query: "x" }), o);
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/key_id/);
  });

  it("records every decision failure in its own audit log, and counts them per class at SessionEnd (§6.4)", async () => {
    const r = await guardian();
    const state = new StateDir(join(r.dir, "shim"));
    const client = new GuardianClient({ port: r.port, ikm: r.g.secrets.ikm, keyId: r.g.secrets.keyId, agentId: AGENT, requestTimeoutMs: 5000, onFailure: (f) => state.recordFailure(CC, f) });
    const sent: { method: string; payload: any }[] = [];
    const call = client.call.bind(client);
    client.call = (session, method, payload, chainHash, o) => { sent.push({ method, payload }); return call(session, method, payload, chainHash, o); };
    const o = shim(r, { client, state });
    await runHook({ hook_event_name: "SessionStart", session_id: CC, source: "startup" }, o);
    expect(state.failureCounts(CC)).toEqual({});
    await r.stop();
    // The Guardian is gone: the call is denied, and the failure is in the shim's own log, which the
    // Guardian never sees.
    expect(decision(await runHook(restart(), o))).toBe("deny");
    const log = readFileSync(state.failureLog, "utf8").trim().split("\n").map((l) => JSON.parse(l) as FailureEntry);
    expect(log).toHaveLength(1);
    expect(log[0]).toMatchObject({ cc_session: CC, method: "steps/toolCallRequest", class: "unreachable" });
    expect(statSync(state.failureLog).mode & 0o777).toBe(0o600);
    await runHook({ hook_event_name: "SessionEnd", session_id: CC, reason: "prompt_input_exit" }, o);
    expect(sent.find((s) => s.method === "steps/sessionEnd")?.payload.summary).toEqual({ decision_failures: { unreachable: 1 } });
  });

  it("classifies an answer signed under another key_id as signature_invalid", async () => {
    const r = await guardian();
    const state = new StateDir(join(r.dir, "shim"));
    const o = shim(r, { state, client: new GuardianClient({ port: r.port, ikm: r.g.secrets.ikm, keyId: r.g.secrets.keyId, agentId: AGENT, requestTimeoutMs: 5000, onFailure: (f) => state.recordFailure(CC, f) }) });
    await runHook({ hook_event_name: "SessionStart", session_id: CC, source: "startup" }, o);
    await r.stop();
    const impostor = createServer((req, res) => {
      let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => {
        const env = JSON.parse(s);
        const answer = { jsonrpc: "2.0", id: env.id, result: { type: "final", acs_version: "0.1.0", request_id: env.params.request_id, decision: "allow", chain_hash: "0".repeat(64) } };
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(sign(answer, sessionKey(r.g.secrets.ikm, env.params.metadata.session_id), "another-label")));
      });
    });
    await new Promise<void>((res) => impostor.listen(r.port, "127.0.0.1", () => res()));
    cleanup.push(() => impostor.close());
    expect(decision(await runHook(restart(), o))).toBe("deny");
    expect(state.failureCounts(CC)).toEqual({ signature_invalid: 1 });
  });

  it("answers allow and deny correctly for parallel calls on one session, with the chain intact", async () => {
    const r = await guardian();
    const o = shim(r);
    const calls = Array.from({ length: 6 }, (_, i) => i % 2 ? pre("Bash", { command: `echo ${i}` }) : pre("mcp__telemetry__query", { query: `q${i}` }));
    const outs = await Promise.all(calls.map((c) => runHook(c, o)));
    expect(outs.map(decision)).toEqual(["allow", "deny", "allow", "deny", "allow", "deny"]);
    expect(outs.some((x) => /chain_mismatch/.test(x.hookSpecificOutput.permissionDecisionReason))).toBe(false);
    expect(verifyEvidence(new Store(r.g.config.dataDir), r.g.origin).problems).toEqual([]);
  });
});

describe("asks: the Guardian is the approver", () => {
  it("waits for a WebAuthn approval, allows, and leaves evidence that verifies", async () => {
    const r = await guardian();
    const auth = await enroll(r, ["sre-lead"]);
    const o = shim(r);
    const call = restart();
    const [out] = await Promise.all([runHook(call, o), decideOnPage(r, "approve", auth)]);
    expect(decision(out), JSON.stringify(out)).toBe("allow");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/approved by sre-lead/);
    expect(await runHook(post(call), o)).toBeNull();
    const rec = r.g.store.records().filter((x) => x.request.action.tool === "mcp__deploy__rolling_restart").at(-1)!;
    expect(rec.resolution).toMatchObject({ result: "executed", approval: { approver_role: "sre-lead" } });
    expect(verifyEvidence(new Store(r.g.config.dataDir), r.g.origin)).toMatchObject({ approvals: 1, problems: [] });
  });

  it("denies when the approver rejects", async () => {
    const r = await guardian();
    const [out] = await Promise.all([runHook(restart(), shim(r)), decideOnPage(r, "reject")]);
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/rejected/);
  });

  it("refuses a --deadline whose hard timer could outlast Claude Code's hook timeout, with an explicit deny", () => {
    const run = (d: string) => spawnSync(process.execPath, [CLI, "hook", "--guardian", "/nonexistent.json", "--agent", "a", "--deadline", d], { input: "", encoding: "utf8" });
    for (const d of ["591", "599"]) {
      const r = run(d);
      expect(r.status).toBe(2);
      expect(JSON.parse(r.stdout).hookSpecificOutput).toMatchObject({ permissionDecision: "deny", permissionDecisionReason: expect.stringMatching(/--deadline must be 10 to 590/) });
    }
  });

  it("denies when its own deadline comes first", async () => {
    const r = await guardian();
    const out = await runHook(restart(), shim(r, { deadline: Date.now() + 7_000 }));
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/before the hook's deadline/);
  });
});

describe("PostToolUse", () => {
  it("reports a call that ran with no decision on record, withholds its output, and the Guardian logs an incident", async () => {
    const r = await guardian();
    const o = shim(r);
    const out = await runHook(post({ tool_name: "Bash", tool_input: { command: "touch CANARY" }, tool_use_id: toolUse() }), o);
    expect(out).toMatchObject({ decision: "block", hookSpecificOutput: { updatedToolOutput: expect.stringMatching(/withheld/) } });
    expect(r.g.store.events().filter((e) => e.type === "incident")).toEqual([expect.objectContaining({ kind: "unlinked-result" })]);
  });

  it("reports a failed execution as executed: the tool was invoked", async () => {
    const r = await guardian();
    const o = shim(r);
    const call = pre("mcp__telemetry__query", { query: "x" });
    expect(decision(await runHook(call, o))).toBe("allow");
    expect(await runHook(post(call, "PostToolUseFailure"), o)).toBeNull();
    expect(r.g.store.records().at(-1)!.resolution?.result).toBe("executed");
  });
});

describe("session lifecycle", () => {
  it("re-negotiates after the Guardian restarts, since its sessions live in memory", async () => {
    const r = await guardian();
    const o = shim(r);
    expect(decision(await runHook(pre("mcp__telemetry__query", { query: "a" }), o))).toBe("allow");
    const before = o.state.read(CC)!.acs_session;
    await r.stop();
    const again = await guardian(r.dir, r.port);
    const o2 = shim(again, { state: o.state });
    expect(decision(await runHook(pre("mcp__telemetry__query", { query: "b" }), o2))).toBe("allow");
    expect(o.state.read(CC)!.acs_session).not.toBe(before);
  });

  it("starts a fresh ACS session after a chain mismatch instead of denying every later call", async () => {
    const r = await guardian();
    const o = shim(r);
    expect(decision(await runHook(pre("mcp__telemetry__query", { query: "a" }), o))).toBe("allow");
    const s = o.state.read(CC)!;
    o.state.write(CC, { ...s, sessions: { ...s.sessions, [s.acs_session]: { chain_hash: "f".repeat(64), negotiated: true } } });
    const out = await runHook(pre("mcp__telemetry__query", { query: "b" }), o);
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/chain_mismatch/);
    expect(decision(await runHook(pre("mcp__telemetry__query", { query: "c" }), o))).toBe("allow");
  });

  it("SessionStart negotiates early, says so when it can't, and SessionEnd closes the session", async () => {
    const r = await guardian();
    const o = shim(r);
    expect(await runHook({ hook_event_name: "SessionStart", session_id: CC, source: "startup" }, o)).toBeNull();
    expect(o.state.read(CC)).not.toBeNull();
    expect(await runHook({ hook_event_name: "SessionEnd", session_id: CC, reason: "prompt_input_exit" }, o)).toBeNull();
    expect(o.state.read(CC)).toBeNull();
    await r.stop();
    const down = await runHook({ hook_event_name: "SessionStart", session_id: CC, source: "startup" }, o);
    expect(down.systemMessage).toMatch(/denied until it answers/);
  });
});

describe("sub-agents: Agent calls become subagentStart, sub-agent calls run on their own session", () => {
  const agentCall = (type?: string, extra: Record<string, unknown> = {}) => pre("Agent", { description: "investigate", prompt: "look at the logs", ...(type ? { subagent_type: type } : {}) }, extra);
  const started = (agentId: string, type: string) => ({ hook_event_name: "SubagentStart", session_id: CC, agent_id: agentId, agent_type: type });
  const stopped = (agentId: string, type: string) => ({ hook_event_name: "SubagentStop", session_id: CC, agent_id: agentId, agent_type: type, stop_hook_active: false });
  const as = (agentId: string, type: string) => ({ agent_id: agentId, agent_type: type });
  const chain = (r: Running) => r.g.store.chain();

  it("derives a context for an allowed type: the sub-agent may read telemetry, not restart", async () => {
    const r = await guardian();
    const o = shim(r);
    const spawn = agentCall("log-analysis");
    expect(decision(await runHook(spawn, o))).toBe("allow");
    expect(await runHook(started("a1", "log-analysis"), o)).toBeNull();
    const read = pre("mcp__telemetry__query", { query: "errors" }, as("a1", "log-analysis"));
    expect(decision(await runHook(read, o))).toBe("allow");
    expect(await runHook(post({ ...read }), o)).toBeNull();
    expect(decision(await runHook(pre("mcp__deploy__rolling_restart", { incident_id: "INC-7", service: "web", stateless: true }, as("a1", "log-analysis")), o))).toBe("deny");

    const s = o.state.read(CC)!;
    const sub = s.agents.a1!.session;
    expect(sub).not.toBe(s.acs_session);
    const rec = r.g.store.records().filter((x) => x.request.action.tool === "mcp__telemetry__query").at(-1)!;
    expect(rec.request.session.id).toBe(sub);
    expect(rec.request.agent.id).toBe(`${AGENT}/log-analysis`);
    expect(rec.resolution?.result).toBe("executed");

    expect(await runHook(stopped("a1", "log-analysis"), o)).toBeNull();
    expect(await runHook(post(spawn), o)).toBeNull();
    expect(o.state.read(CC)!.agents).toEqual({});
    const steps = chain(r).map((c) => `${c.session === sub ? "sub" : "root"}:${c.entry.step_type}`);
    expect(steps).toEqual(["root:sessionStart", "root:subagentStart", "sub:toolCallRequest", "sub:toolCallResult", "sub:toolCallRequest", "sub:sessionEnd", "root:subagentStop"]);
    expect(verifyEvidence(new Store(r.g.config.dataDir), r.g.origin).problems).toEqual([]);
  });

  it("frees the sub-agent's place when it stops: the pattern allows one log-analysis at a time", async () => {
    const r = await guardian();
    const o = shim(r);
    expect(decision(await runHook(agentCall("log-analysis"), o))).toBe("allow");
    await runHook(started("a1", "log-analysis"), o);
    expect(decision(await runHook(agentCall("log-analysis"), o))).toBe("deny");
    await runHook(stopped("a1", "log-analysis"), o);
    expect(decision(await runHook(agentCall("log-analysis"), o))).toBe("allow");
  });

  it("matches SubagentStart to a pending spawn of its own type, not just the oldest", async () => {
    const r = await guardian();
    const o = shim(r);
    expect(decision(await runHook(agentCall("dependency-check"), o))).toBe("allow");
    expect(decision(await runHook(agentCall("log-analysis"), o))).toBe("allow");
    await runHook(started("l1", "log-analysis"), o);
    await runHook(started("d1", "dependency-check"), o);
    // Only the dependency-check pattern reaches upstream status.
    expect(decision(await runHook(pre("mcp__status__upstream", { service: "payments" }, as("l1", "log-analysis")), o))).toBe("deny");
    expect(decision(await runHook(pre("mcp__status__upstream", { service: "payments" }, as("d1", "dependency-check")), o))).toBe("allow");
  });

  it("denies a spawn outside the allowed patterns, including Claude Code's default type", async () => {
    const r = await guardian();
    const o = shim(r);
    const out = await runHook(agentCall(), o);
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/general-purpose is outside the allowed patterns/);
    expect(decision(await runHook(agentCall("shell"), o))).toBe("deny");
  });

  it("denies every call of a sub-agent that started without an allowed spawn, and reports what it ran", async () => {
    const r = await guardian();
    const o = shim(r);
    await runHook(pre("mcp__telemetry__query", { query: "x" }), o); // the root session exists
    const out = await runHook(started("stray", "log-analysis"), o);
    expect(out.hookSpecificOutput.additionalContext).toMatch(/not started through the Guardian/);
    const call = pre("mcp__telemetry__query", { query: "x" }, as("stray", "log-analysis"));
    const d = await runHook(call, o);
    expect(decision(d)).toBe("deny");
    expect(d.hookSpecificOutput.permissionDecisionReason).toMatch(/not started through the Guardian/);
    expect(await runHook(post(call), o)).toMatchObject({ decision: "block" });
    expect(r.g.store.events().filter((e) => e.type === "incident")).toEqual([expect.objectContaining({ kind: "unlinked-result" })]);
  });

  it("ends an allowed spawn that never started when its Agent call returns", async () => {
    const r = await guardian();
    const o = shim(r);
    const spawn = agentCall("log-analysis");
    expect(decision(await runHook(spawn, o))).toBe("allow");
    expect(await runHook(post(spawn, "PostToolUseFailure"), o)).toBeNull();
    expect(o.state.read(CC)!.spawns).toEqual([]);
    expect(chain(r).at(-1)!.entry.step_type).toBe("subagentStop");
    expect(decision(await runHook(agentCall("log-analysis"), o))).toBe("allow");
  });

  it("lets a sub-agent's spawn go only as deep as the matrix allows (depth one here)", async () => {
    const r = await guardian();
    const o = shim(r);
    expect(decision(await runHook(agentCall("dependency-check"), o))).toBe("allow");
    await runHook(started("d1", "dependency-check"), o);
    const out = await runHook(agentCall("log-analysis", as("d1", "dependency-check")), o);
    expect(decision(out)).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toMatch(/authority_breach/);
  });

  it("ends sub-agents with the session", async () => {
    const r = await guardian();
    const o = shim(r);
    expect(decision(await runHook(agentCall("log-analysis"), o))).toBe("allow");
    await runHook(started("a1", "log-analysis"), o);
    await runHook({ hook_event_name: "SessionEnd", session_id: CC, reason: "prompt_input_exit" }, o);
    expect(chain(r).map((c) => c.entry.step_type).slice(-3)).toEqual(["sessionEnd", "subagentStop", "sessionEnd"]);
    expect(o.state.read(CC)).toBeNull();
  });
});

describe("the CLI, as Claude Code runs it", () => {
  function run(args: string[], stdin: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const p = spawn(process.execPath, [CLI, ...args], { stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      p.stdout.on("data", (c) => (stdout += c));
      p.stderr.on("data", (c) => (stderr += c));
      p.on("close", (code) => resolve({ code, stdout, stderr }));
      p.stdin.end(stdin);
    });
  }

  it("allows over a real process boundary", async () => {
    const r = await guardian();
    const res = await run(["hook", "--guardian", r.config, "--agent", AGENT, "--state", join(r.dir, "cli-state")], JSON.stringify(pre("mcp__telemetry__query", { query: "x" })));
    expect(res.code, res.stderr).toBe(0);
    expect(decision(JSON.parse(res.stdout))).toBe("allow");
  });

  it("denies with exit 0 and explicit JSON when the Guardian is down", async () => {
    const r = await guardian();
    await r.stop();
    const res = await run(["hook", "--guardian", r.config, "--agent", AGENT, "--state", join(r.dir, "cli-state")], JSON.stringify(pre("mcp__telemetry__query", { query: "x" })));
    expect(res.code).toBe(0);
    expect(decision(JSON.parse(res.stdout))).toBe("deny");
  });

  it("blocks with exit 2 on input it can't read, and on a configuration it can't load", async () => {
    const r = await guardian();
    expect((await run(["hook", "--guardian", r.config, "--agent", AGENT], "not json")).code).toBe(2);
    const res = await run(["hook", "--guardian", join(r.dir, "missing.json"), "--agent", AGENT], JSON.stringify(pre("Bash", { command: "x" })));
    expect(res.code).toBe(2);
  });

  it("blocks with exit 2 and an explicit deny when the input names no hook event", async () => {
    const r = await guardian();
    for (const input of [{ ...pre("Bash", { command: "x" }), hook_event_name: undefined }, { ...pre("Bash", { command: "x" }), hook_event_name: "" }, { ...pre("Bash", { command: "x" }), hook_event_name: 5 }]) {
      const res = await run(["hook", "--guardian", r.config, "--agent", AGENT, "--state", join(r.dir, "cli-state")], JSON.stringify(input));
      expect(res.code).toBe(2);
      expect(decision(JSON.parse(res.stdout))).toBe("deny");
    }
  });

  it("prints settings that route every tool through the shim and disable bypass mode", async () => {
    const r = await guardian();
    const res = await run(["settings", "--guardian", r.config, "--agent", AGENT], "");
    const s = JSON.parse(res.stdout);
    expect(s.permissions.disableBypassPermissionsMode).toBe("disable");
    expect(s.hooks.PreToolUse[0]).toMatchObject({ matcher: "*", hooks: [{ type: "command", timeout: 600 }] });
    expect(s.hooks.PreToolUse[0].hooks[0].command).toContain(" hook --guardian ");
  });
});

describe("the state lock", () => {
  it("a holder keeps its lock fresh, so a long locked section never looks stale to a waiting hook", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaom-lock-"));
    const timing = { staleMs: 300, waitMs: 2000, heartbeatMs: 50 };
    const a = new StateDir(dir, timing), b = new StateDir(dir, timing);
    const order: string[] = [];
    const slow = a.locked("s", async () => { order.push("a-in"); await new Promise((r) => setTimeout(r, 800)); order.push("a-out"); });
    await new Promise((r) => setTimeout(r, 20));
    await b.locked("s", async () => { order.push("b"); });
    await slow;
    expect(order).toEqual(["a-in", "a-out", "b"]);
    rmSync(dir, { recursive: true, force: true });
  });
});
