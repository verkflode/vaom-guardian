// The request handler end to end, on the 7D incident example: an agent negotiates, opens a session,
// makes calls, and spawns sub-agents, all as signed ACS envelopes. Every response is checked against the
// vendored ACS response schema, and every failure is checked to come out as deny or an error, never allow.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { CapLedger, compilePolicy, ContextRegistry, type Policy } from "@verkflode/vaom-guardian-core";
import { AcsEndpoint, ERR, sessionKey, sign, verify, verifyChain, type ContextEntry, type EndpointConfig } from "../src/index.ts";
import { validateResponseEnvelope } from "../src/generated/validators.js";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
const load = (f: string): any => JSON.parse(readFileSync(join(examples, f), "utf8"));
const scoring = ["remediation-gate", "incident-detection"].map((s) => load(`${s}.scoring.json`));
// The Guardian has no verifier channel, so a restart under the 7D matrix (verification required) never
// reaches Band A. `unverified` drops that requirement, to test the allow path through the wire.
function policy(unverified = false): Policy {
  const m = load("incident.matrix.json");
  if (unverified) for (const row of m.rows) if (row.authority.confidence) delete row.authority.confidence.verificationRequired;
  const r = compilePolicy(m, load("incident.binding.json"), scoring);
  if (!r.ok) throw new Error(JSON.stringify(r.findings));
  return r.policy;
}

const IKM = new Uint8Array(32).fill(7);
const T0 = Date.parse("2026-10-05T10:00:00Z");
const S1 = "11111111-1111-4111-8111-111111111111";
const SUB = "22222222-2222-4222-8222-222222222222";
const AGENT = "incident-agent";

let n = 0;
const uuid = () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;

function setup(over: Partial<EndpointConfig> = {}, unverified = false) {
  const p = policy(unverified);
  const ledger = new CapLedger();
  ledger.load([]);
  const contexts = new ContextRegistry(p);
  let ids = 0;
  const cfg: EndpointConfig = {
    methodsEvaluated: ["steps/sessionStart", "steps/sessionEnd", "steps/toolCallRequest", "steps/toolCallResult", "steps/subagentStart"],
    defaultTimeoutMs: 5000,
    skewWindowMs: 60_000,
    profiles: ["acs-core", "acs-audit"],
    ikm: IKM,
    keyId: "guardian-1",
    factKey: new Uint8Array(32).fill(9),
    approvalTimeoutSeconds: 300,
    deferTimeoutMs: 1000,
    evaluatorVersion: "test",
    activationFor: ({ payload }) => (payload.intent?.raw === "INC-7" ? { rows: ["remediation.restart"], task: "INC-7" } : null),
    ...over,
  };
  const ep = new AcsEndpoint(cfg, { policy: p, ledger, contexts, newId: () => `id-${++ids}` });
  const entries: ContextEntry[] = [];
  return { ep, ledger, contexts, entries, cfg };
}

type Setup = ReturnType<typeof setup>;

function envelope(method: string, payload: unknown, o: { session?: string; agent?: string; at?: number; now?: number; requestId?: string; chainHash?: string; version?: string } = {}) {
  const metadata: any = { agent_id: o.agent ?? AGENT, session_id: o.session ?? S1 };
  if (o.chainHash !== undefined) metadata.session_state = { chain_hash: o.chainHash };
  return { jsonrpc: "2.0", id: ++n, method, params: { acs_version: o.version ?? "0.1.0", request_id: o.requestId ?? uuid(), timestamp: new Date(o.at ?? T0).toISOString(), metadata, payload } };
}
const signed = (env: ReturnType<typeof envelope>, session = S1) => sign(env, sessionKey(IKM, session), "guardian-1");

/** Send a signed request; check the response's schema and signature; collect chain entries. */
function send(s: Setup, method: string, payload: unknown, o: Parameters<typeof envelope>[2] = {}) {
  const env = signed(envelope(method, payload, o), o.session ?? S1);
  const h = s.ep.handle(JSON.stringify(env), o.now ?? o.at ?? T0);
  s.entries.push(...h.entries);
  if (h.response.result && method !== "system/ping") {
    if (method !== "handshake/hello") expect(validateResponseEnvelope(h.response), JSON.stringify(validateResponseEnvelope.errors)).toBe(true);
    if (h.response.result.signature) expect(verify(h.response, sessionKey(IKM, o.session ?? S1))).toEqual({ ok: true });
  }
  return { ...h, env, result: h.response.result, error: h.response.error };
}

const hello = { acs_versions_supported: ["0.1.0"], methods_implemented: ["steps/sessionStart", "steps/toolCallRequest", "steps/toolCallResult", "steps/subagentStart", "steps/sessionEnd"], transports_supported: ["http"], provenance_producer: "none", profiles_supported: ["acs-core", "acs-audit"] };
const tool = (name: string, args: Record<string, unknown>) => ({ tool: { name }, arguments: Object.fromEntries(Object.entries(args).map(([k, v]) => [k, { value: v }])) });
const turn = { turn_id: "t-1", triggered_by: "user_message" };
const restart = (incident: string, stateless = true) => tool("mcp__deploy__rolling_restart", { incident_id: incident, service: "web", stateless });

function started(over: Partial<EndpointConfig> = {}, unverified = false) {
  const s = setup(over, unverified);
  expect(send(s, "handshake/hello", hello).result.negotiated_version).toBe("0.1.0");
  expect(send(s, "steps/sessionStart", { intent: { raw: "INC-7" } }).result.decision).toBe("allow");
  return s;
}

describe("handshake", () => {
  it("negotiates 0.1.0 and declares fail-closed", () => {
    const s = setup();
    const r = send(s, "handshake/hello", hello).result;
    expect(r).toMatchObject({ negotiated_version: "0.1.0", on_decision_failure: "deny", signature_algorithms_supported: ["HMAC-SHA256"], approver_types_supported: ["human"], profiles_accepted: ["acs-core", "acs-audit"] });
    expect(r.methods_evaluated).not.toContain("steps/sessionEnd".replace("End", "Nope"));
  });
  it("refuses a second hello on the same session, and steps before any hello", () => {
    const s = setup();
    expect(send(s, "steps/toolCallRequest", restart("INC-7")).error.code).toBe(ERR.CAPABILITY_NOT_NEGOTIATED);
    send(s, "handshake/hello", hello);
    expect(send(s, "handshake/hello", hello).error.code).toBe(ERR.SESSION_REFUSED);
  });
  it("refuses a hello with no common version or transport", () => {
    expect(send(setup(), "handshake/hello", { ...hello, acs_versions_supported: ["1.0.0"] }).error.code).toBe(ERR.UNSUPPORTED_VERSION);
    expect(send(setup(), "handshake/hello", { ...hello, transports_supported: ["stdio"] }).error.code).toBe(ERR.SESSION_REFUSED);
  });
});

describe("transport checks fail closed", () => {
  it("rejects non-JSON, batches and envelopes that fail the schema", () => {
    const s = setup();
    expect(s.ep.handle("{nope", T0).response.error.code).toBe(ERR.PARSE);
    expect(s.ep.handle("[]", T0).response.error.code).toBe(ERR.INVALID_REQUEST);
    const bad = s.ep.handle({ jsonrpc: "2.0", id: 5, method: "steps/toolCallRequest", params: {} }, T0).response;
    expect(bad).toMatchObject({ id: 5, error: { code: ERR.INVALID_REQUEST } });
  });
  it("rejects unsigned, wrongly keyed and tampered requests", () => {
    const s = started();
    const raw = envelope("steps/toolCallRequest", restart("INC-7"));
    expect(s.ep.handle(raw, T0).response.error.code).toBe(ERR.SIGNATURE_INVALID);
    expect(s.ep.handle(sign(envelope("steps/toolCallRequest", restart("INC-7")), sessionKey(IKM, SUB), "guardian-1"), T0).response.error.code).toBe(ERR.SIGNATURE_INVALID);
    const t = signed(envelope("steps/toolCallRequest", restart("INC-7")));
    (t.params.payload as any).arguments.stateless.value = false;
    expect(s.ep.handle(t, T0).response.error.code).toBe(ERR.SIGNATURE_INVALID);
  });
  it("rejects a key_id it doesn't hold, unsigned, without trying its own secret", () => {
    const s = started();
    const r = s.ep.handle(sign(envelope("steps/toolCallRequest", restart("INC-7")), sessionKey(IKM, S1), "guardian-2"), T0).response;
    expect(r.error.code).toBe(ERR.SIGNATURE_INVALID);
    expect(r.error.message).toMatch(/key_id/);
    expect(r.result).toBeUndefined();
  });
  it("signs its answer under the key_id the request named", () => {
    const s = started();
    expect(s.ep.handle(signed(envelope("steps/toolCallRequest", restart("INC-7"))), T0).response.result.signature.key_id).toBe("guardian-1");
  });
  it("a forged request doesn't burn its request id", () => {
    const s = started();
    const id = uuid();
    s.ep.handle(envelope("steps/toolCallRequest", restart("INC-7"), { requestId: id }), T0);
    expect(send(s, "steps/toolCallRequest", restart("INC-7"), { requestId: id }).result.decision).toBeDefined();
  });
  it("rejects replays and stale timestamps", () => {
    const s = started();
    const env = signed(envelope("steps/toolCallRequest", restart("INC-7")));
    expect(s.ep.handle(env, T0).response.result).toBeDefined();
    expect(s.ep.handle(env, T0).response.error.code).toBe(ERR.REPLAY_DETECTED);
    expect(send(s, "steps/toolCallRequest", restart("INC-7"), { at: T0 - 61_000, now: T0 }).error.code).toBe(ERR.TIMESTAMP_OUT_OF_WINDOW);
    expect(send(s, "steps/toolCallRequest", restart("INC-7"), { at: T0 + 61_000, now: T0 }).error.code).toBe(ERR.TIMESTAMP_OUT_OF_WINDOW);
  });
  it("rejects an unsupported ACS version, and an agent that changes its id mid-session", () => {
    const s = started();
    const env = envelope("steps/toolCallRequest", restart("INC-7"));
    env.params.acs_version = "0.2.0";
    expect(s.ep.handle(signed(env), T0).response.error.code).toBe(ERR.UNSUPPORTED_VERSION);
    expect(send(s, "steps/toolCallRequest", restart("INC-7"), { agent: "someone-else" }).error.code).toBe(ERR.SESSION_REFUSED);
  });
  it("answers methods it doesn't evaluate with an error, not allow: wrapped MCP, memory, skills", () => {
    const s = started();
    for (const m of ["protocols/mcp/tools/call", "steps/memoryStore", "steps/skillLoad", "agbom/snapshot"]) expect(send(s, m, {}).error?.code, m).toBe(ERR.METHOD_NOT_FOUND);
    expect(send(s, "steps/turnStart", turn).result).toMatchObject({ decision: "allow", reason_codes: ["not_evaluated"] });
  });
  it("rejects a payload that fails its step schema", () => {
    expect(send(started(), "steps/toolCallRequest", { tool: { name: "x" } }).error.code).toBe(ERR.INVALID_PARAMS);
  });
  it("answers system/ping without a session", () => {
    const h = setup().ep.handle(envelope("system/ping", {}), T0);
    expect(h.response.result.decision).toBe("allow");
  });
});

describe("tool calls through the matrix (7D)", () => {
  it("routes a restart inside the incident's context: high confidence but no verifier, so Band B, review", () => {
    const s = started();
    const r = send(s, "steps/toolCallRequest", restart("INC-7"));
    expect(r.result).toMatchObject({ decision: "ask", ask_details: { approver: { type: "human", id: "sre-lead" }, timeout_disposition: "deny" } });
    expect(r.records[0]!.decision.placements[0]!.score).toMatchObject({ policy: { id: "remediation-gate", version: "4.1" }, level: "high" });
    expect(r.records[0]!.decision.reasons.map((x) => x.code)).toContain("verification.missing");
    expect(r.records).toHaveLength(1);
    expect(r.records[0]!.request.wire).toMatchObject({ protocol: "acs", request_id: r.env.params.request_id, chain_hash: r.result.chain_hash });
  });
  it("a stateful service fails a hard rule and a restriction: Band C, escalation", () => {
    const r = send(started(), "steps/toolCallRequest", restart("INC-7", false));
    expect(r.result).toMatchObject({ decision: "ask", ask_details: { approver: { type: "human", id: "head-of-engineering" } } });
  });
  it("where the row needs no verification, a high score is Band A: allow", () => {
    expect(send(started({}, true), "steps/toolCallRequest", restart("INC-7")).result.decision).toBe("allow");
  });
  it("defers a restart for another incident (task mismatch) with timeout deny", () => {
    const r = send(started(), "steps/toolCallRequest", restart("INC-8"));
    expect(r.result).toMatchObject({ decision: "defer", defer_details: { timeout_decision: "deny" } });
    expect(r.records[0]!.resolution?.result).toBe("not-executed");
  });
  it("a change-proposal draft outside the session's rows isn't allowed", () => {
    const s = started();
    const r = send(s, "steps/toolCallRequest", tool("mcp__change__draft_proposal", {}));
    expect(r.result.decision).not.toBe("allow");
  });
  it("defers every governed call in a session that opened no context", () => {
    const s = setup();
    send(s, "handshake/hello", hello);
    expect(send(s, "steps/sessionStart", {}).result.reason_codes).toEqual(["no_execution_context"]);
    expect(send(s, "steps/toolCallRequest", restart("INC-7")).result.decision).toBe("defer");
    expect(send(s, "steps/toolCallRequest", tool("mcp__unknown__thing", {})).result.decision).toBe("defer");
  });
  it("never quotes argument values on the wire", () => {
    const r = send(started(), "steps/toolCallRequest", restart("INC-SECRET-42"));
    expect(JSON.stringify(r.response)).not.toContain("INC-SECRET-42");
  });
});

describe("results resolve decisions", () => {
  it("an allowed call that ran resolves as executed and keeps its cap use", () => {
    const s = started({}, true);
    const req = send(s, "steps/toolCallRequest", restart("INC-7"));
    const res = send(s, "steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: req.env.params.request_id, exit_status: "success", outputs: [] });
    expect(res.result.decision).toBe("allow");
    expect(res.records[0]).toMatchObject({ id: req.records[0]!.id, resolution: { result: "executed" } });
  });
  it("an ask that executed without approval is an incident, and its output is withheld", () => {
    const s = started();
    const req = send(s, "steps/toolCallRequest", restart("INC-7"));
    const res = send(s, "steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: req.env.params.request_id, exit_status: "success", outputs: [] });
    expect(res.result).toMatchObject({ decision: "deny", reason_codes: ["execution_without_authority"] });
    expect(res.incidents[0]).toMatchObject({ kind: "execution-without-authority", record: req.records[0]!.id });
  });
  it("an ask that executed after the named approver approved resolves as executed", () => {
    const s = started();
    const req = send(s, "steps/toolCallRequest", restart("INC-7"));
    expect(() => s.ep.approve(S1, req.env.params.request_id, { approver_role: "head-of-engineering", record: "apr-0" })).toThrow(/names sre-lead/);
    s.ep.approve(S1, req.env.params.request_id, { approver_role: "sre-lead", record: "apr-1" });
    const res = send(s, "steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: req.env.params.request_id, exit_status: "success", outputs: [] });
    expect(res.records[0]?.resolution).toMatchObject({ result: "executed", approval: { record: "apr-1" } });
  });
  it("the record names an approver only when the matrix enables reviewer-level metrics", () => {
    const run = (s: Setup) => {
      const req = send(s, "steps/toolCallRequest", restart("INC-7"));
      s.ep.approve(S1, req.env.params.request_id, { approver_role: "sre-lead", approver_id: "jane", record: "apr-1" });
      return send(s, "steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: req.env.params.request_id, exit_status: "success", outputs: [] }).records[0]!.resolution!.approval;
    };
    expect(run(started())).toEqual({ approver_role: "sre-lead", record: "apr-1" });
    const s = started();
    s.ep["deps"].policy.matrix.oversight.reviewerLevelMetrics = { enabled: true, approvalRef: "DPIA-1" };
    expect(run(s)).toEqual({ approver_role: "sre-lead", approver_id: "jane", record: "apr-1" });
  });
  it("a result for no open decision is an incident", () => {
    const s = started();
    const res = send(s, "steps/toolCallResult", { tool: { name: "x" }, request_id_ref: uuid(), exit_status: "success", outputs: [] });
    expect(res.result.decision).toBe("deny");
    expect(res.incidents[0]?.kind).toBe("unlinked-result");
  });
  it("a rejected ask releases its reservation", () => {
    const s = started();
    const req = send(s, "steps/toolCallRequest", restart("INC-7"));
    expect(s.ep.close(S1, req.env.params.request_id, "rejected", "2026-10-05T10:01:00Z").resolution?.result).toBe("rejected");
  });
  it("a response that would fail the ACS schema goes out as an error, and the decision behind it is undone", () => {
    const s = started({ approvalTimeoutSeconds: 1.5 }, true);
    const release = vi.spyOn(s.ledger, "release");
    const req = send(s, "steps/toolCallRequest", restart("INC-7"), {});
    expect(req.result.decision).toBe("allow"); // allow carries no ask_details, so it's valid
    const s2 = started({ approvalTimeoutSeconds: 1.5 });
    const release2 = vi.spyOn(s2.ledger, "release");
    const ask = send(s2, "steps/toolCallRequest", restart("INC-7"));
    expect(ask.error.code).toBe(ERR.INTERNAL);
    expect(ask.records).toEqual([]);
    expect(release2).toHaveBeenCalledTimes(1);
    expect(release).not.toHaveBeenCalled();
    const res = send(s2, "steps/toolCallResult", { tool: { name: "mcp__deploy__rolling_restart" }, request_id_ref: ask.env.params.request_id, exit_status: "success", outputs: [] });
    expect(res.incidents[0]?.kind).toBe("unlinked-result");
  });
  it("persistFailed turns the response into an error and releases the reservation", () => {
    const s = started({}, true);
    const req = send(s, "steps/toolCallRequest", restart("INC-7"));
    const out = s.ep.persistFailed(req, S1);
    expect(out.error.code).toBe(ERR.INTERNAL);
    expect(() => s.ep.close(S1, req.env.params.request_id, "withdrawn", "2026-10-05T10:01:00Z")).toThrow(/no pending/);
  });
});

describe("sub-agents (7D: two read-only sub-agents, depth one)", () => {
  const spawn = (s: Setup, type: string, session = SUB) => send(s, "steps/subagentStart", { subagent_session_id: session, parent_session_id: S1, parent_step_id: uuid(), intent_derivation: "inherit_subset", subagent_descriptor: { agent_name: type } });
  it("derives a log-analysis context; the sub-agent can read telemetry but not restart", () => {
    const s = started();
    expect(spawn(s, "log-analysis").result).toMatchObject({ decision: "allow", reason_codes: ["context_derived"] });
    send(s, "handshake/hello", hello, { session: SUB, agent: `${AGENT}/log-analysis` });
    expect(send(s, "steps/toolCallRequest", tool("mcp__telemetry__query", { q: "errors" }), { session: SUB, agent: `${AGENT}/log-analysis` }).result.decision).toBe("allow");
    expect(send(s, "steps/toolCallRequest", restart("INC-7"), { session: SUB, agent: `${AGENT}/log-analysis` }).result.decision).not.toBe("allow");
  });
  it("closes a derived context when the sub-agent's session ends, freeing its place in the fan-out", () => {
    const s = started();
    const sub = { session: SUB, agent: `${AGENT}/log-analysis` };
    expect(spawn(s, "log-analysis").result.decision).toBe("allow");
    send(s, "handshake/hello", hello, sub);
    send(s, "steps/sessionEnd", { reason: "completed" }, sub);
    expect(spawn(s, "log-analysis", "33333333-3333-4333-8333-333333333333").result.decision).toBe("allow");
  });
  it("denies a type outside the allowed patterns, and a third spawn past the fan-out", () => {
    const s = started();
    expect(spawn(s, "shell").result.decision).toBe("deny");
    expect(spawn(s, "log-analysis", "33333333-3333-4333-8333-333333333333").result.decision).toBe("allow");
    expect(spawn(s, "dependency-check", "44444444-4444-4444-8444-444444444444").result.decision).toBe("allow");
    expect(spawn(s, "log-analysis", "55555555-5555-4555-8555-555555555555").result).toMatchObject({ decision: "deny", reason_codes: ["authority_breach"] });
  });
  it("reports every spawn decision, allowed or denied, as evidence for chain integrity", () => {
    const s = started();
    expect(spawn(s, "log-analysis").spawns).toEqual([{ session: S1, subagent_session: SUB, agent: `${AGENT}/log-analysis`, subagent_type: "log-analysis", decision: "allow", reason: "context_derived", context: expect.any(String), intent_derivation: "inherit_subset" }]);
    expect(spawn(s, "shell", "33333333-3333-4333-8333-333333333333").spawns).toMatchObject([{ subagent_type: "shell", decision: "deny", reason: "outside_allowed_patterns", why: expect.any(String) }]);
    spawn(s, "dependency-check", "44444444-4444-4444-8444-444444444444");
    expect(spawn(s, "log-analysis", "55555555-5555-4555-8555-555555555555").spawns).toMatchObject([{ decision: "deny", reason: "authority_breach" }]);
    expect(send(s, "steps/toolCallRequest", restart("INC-7")).spawns).toEqual([]);
  });
  it("denies a spawn from one session that names another live session as parent", () => {
    const s = started();
    const S3 = "77777777-7777-4777-8777-777777777777";
    send(s, "handshake/hello", hello, { session: S3 });
    send(s, "steps/sessionStart", { intent: { raw: "INC-7" } }, { session: S3 });
    const r = send(s, "steps/subagentStart", { subagent_session_id: SUB, parent_session_id: S1, parent_step_id: uuid(), intent_derivation: "fresh", subagent_descriptor: { agent_name: "log-analysis" } }, { session: S3 });
    expect(r.result).toMatchObject({ decision: "deny", reason_codes: ["parent_session_mismatch"] });
  });
  it("denies a spawn claiming another session as parent", () => {
    const s = started();
    const r = send(s, "steps/subagentStart", { subagent_session_id: SUB, parent_session_id: "66666666-6666-4666-8666-666666666666", parent_step_id: uuid(), intent_derivation: "fresh", subagent_descriptor: { agent_name: "log-analysis" } });
    expect(r.result.decision).toBe("deny");
  });
});

describe("the audit chain", () => {
  it("chains every step, verifies, and carries the head in chain_hash", () => {
    const s = started();
    const r = send(s, "steps/toolCallRequest", restart("INC-7"));
    expect(s.entries.map((e) => e.step_type)).toEqual(["sessionStart", "toolCallRequest"]);
    expect(verifyChain(s.entries)).toBe(true);
    expect(r.result.chain_hash).toBe(s.entries.at(-1)!.entry_hash);
    expect(s.ep.head(S1)).toBe(r.result.chain_hash);
  });
  it("denies with chain_mismatch when the agent's head disagrees, and accepts a matching one", () => {
    const s = started();
    expect(send(s, "steps/toolCallRequest", restart("INC-7"), { chainHash: "00".repeat(32) }).result).toMatchObject({ decision: "deny", reason_codes: ["chain_mismatch"] });
    expect(send(s, "steps/turnStart", turn, { chainHash: s.ep.head(S1)! }).result.decision).toBe("allow");
  });
  it("after sessionEnd, the session takes nothing more", () => {
    const s = started();
    send(s, "steps/sessionEnd", { reason: "completed" });
    expect(send(s, "steps/toolCallRequest", restart("INC-7")).error.code).toBe(ERR.SESSION_REFUSED);
  });
});

describe("fixes from review: state, chaining and fidelity", () => {
  it("a step that fails after it was chained leaves no entry: the agent's last head still matches", () => {
    const s = started({ approvalTimeoutSeconds: 1.5 });
    const head = s.ep.head(S1)!;
    const ask = send(s, "steps/toolCallRequest", restart("INC-7"));
    expect(ask.error.code).toBe(ERR.INTERNAL);
    expect(ask.entries).toEqual([]);
    expect(s.ep.head(S1)).toBe(head);
    expect(send(s, "steps/turnStart", turn, { chainHash: head }).result.decision).toBe("allow");
  });
  it("a refusal whose response fails is undone in full: the ledger matches one rebuilt from the records", () => {
    const s = started({ deferTimeoutMs: 1.5 });
    const r = send(s, "steps/toolCallRequest", restart("INC-9")); // task mismatch: unplaceable, so a defer
    expect(r.error.code).toBe(ERR.INTERNAL);
    expect(s.ledger.historyCount("remediation.restart", {}, T0 + 1, 3_600_000)).toBe(0);
  });
  it("sessionEnd and observed steps are checked against their schemas before they act or are chained", () => {
    const s = started();
    expect(send(s, "steps/turnStart", {}).error.code).toBe(ERR.INVALID_PARAMS);
    expect(send(s, "steps/sessionEnd", {}).error.code).toBe(ERR.INVALID_PARAMS);
    expect(send(s, "steps/toolCallRequest", restart("INC-7")).result.decision).not.toBeUndefined(); // the session is still live
  });
  it("an ended session forgets its request ids and can't negotiate again", () => {
    const s = started();
    send(s, "steps/sessionEnd", { reason: "completed" });
    expect((s.ep as unknown as { replay: { ids: Map<string, unknown> } }).replay.ids.has(S1)).toBe(false);
    expect(send(s, "handshake/hello", hello).error.code).toBe(ERR.SESSION_REFUSED);
  });
  it("answers in the version the session negotiated, on every step", () => {
    const s = setup();
    expect(send(s, "handshake/hello", { ...hello, acs_versions_supported: ["0.1.0", "0.1.1"] }, { version: "0.1.1" }).result.negotiated_version).toBe("0.1.1");
    send(s, "steps/sessionStart", { intent: { raw: "INC-7" } }, { version: "0.1.1" });
    expect(send(s, "steps/toolCallRequest", restart("INC-7"), { version: "0.1.1" }).result.acs_version).toBe("0.1.1");
  });
  it("refuses anything signed before the Guardian started, so a restart can't be used to replay", () => {
    const s = setup({ startedAt: T0 + 1 });
    expect(send(s, "handshake/hello", hello, { at: T0, now: T0 + 5 }).error.code).toBe(ERR.TIMESTAMP_OUT_OF_WINDOW);
    expect(send(s, "handshake/hello", hello, { at: T0 + 2, now: T0 + 5 }).result.negotiated_version).toBe("0.1.0");
  });
  it("a sub-agent is derived from the session's own context, not another live one sharing the session", () => {
    const s = setup();
    send(s, "handshake/hello", hello);
    // A context on the same session opened first, e.g. a lease's response context, with a narrower row set.
    s.contexts.open({ id: "other", session: S1, agent: { id: AGENT }, rows: ["remediation.restart"], scopes: ["telemetry:read"] }, T0);
    send(s, "steps/sessionStart", { intent: { raw: "INC-7" } });
    const r = send(s, "steps/subagentStart", { subagent_session_id: SUB, parent_session_id: S1, parent_step_id: uuid(), intent_derivation: "inherit_subset", subagent_descriptor: { agent_name: "dependency-check" } });
    expect(r.result.decision).toBe("allow");
    expect(s.contexts.live(r.spawns[0]!.context!, T0)?.parent).not.toBe("other");
  });
});

