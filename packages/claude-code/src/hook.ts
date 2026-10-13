// One Claude Code hook call, start to finish: the hook input in, the answer Claude Code should get out.
//
// Claude Code treats any hook failure (crash, timeout, bad output) as "no opinion" and carries on with
// its own permission flow, which runs the call if an allow-rule or bypassPermissions pre-approves it
// (experiments/claude-code-hook-failures). So for PreToolUse this answers explicitly on every path it can
// observe, and every path that isn't a Guardian allow, or a human approval the Guardian reports, is deny:
//
//   bypassPermissions                      deny, before asking anyone (the shim's own rule)
//   no session (handshake fails)           deny: ACS §4.1 startup posture "refuse", not the default "proceed"
//   Guardian error, silence, bad answer    deny: on_decision_failure "deny" (§6.4), whatever the Guardian declared
//   allow                                  allow
//   ask                                    wait for the Guardian's approval page; approved -> allow, else deny
//   deny, defer, modify, anything else     deny (this Guardian's defer always times out to deny)
//
// PostToolUse reports the execution against the decision it ran under (tool_use_id is shared by both
// events). A tool that ran with no decision on record is reported too, as an unlinked result: that's the
// trace a failed PreToolUse hook leaves, and the Guardian logs it as an incident.
//
// Sub-agents (measured on Claude Code 2.1.296): a spawn is a call to the Agent tool, with the type in
// tool_input.subagent_type. SubagentStart follows with an agent_id and agent_type, but nothing linking it
// to that call; the sub-agent's own calls then arrive on the parent's session_id, tagged with agent_id;
// SubagentStop ends it. Parent and sub-agent run concurrently. So:
//
//   PreToolUse(Agent)       steps/subagentStart on the spawner's session, with a fresh ACS session for the
//                           sub-agent. The Guardian derives an attenuated context or denies the spawn; that
//                           answer is the Agent call's allow or deny.
//   SubagentStart           claims the oldest allowed spawn of that type for this agent_id. A sub-agent with
//                           no allowed spawn gets no session, so every call it makes is denied.
//   a sub-agent's calls     decided on its own ACS session (agent "{agent}/{type}"), under the derived context.
//   SubagentStop            sessionEnd on the sub-agent's session (which closes its context), then
//                           steps/subagentStop on the spawner's session with the sub-agent's final chain hash.
//
// Two spawns of the same type in flight at once may be matched to each other's SubagentStart. Both were
// allowed the same pattern under the same parent, so authority is unaffected; only which spawn step the
// evidence links each sub-agent to can swap.
import { randomUUID } from "node:crypto";
import { GuardianClient, GuardianError } from "./client.ts";
import { StateDir, type SessionState } from "./state.ts";

type Json = any;

export interface ShimOptions {
  client: GuardianClient;
  state: StateDir;
  /** Absolute time (ms) by which the shim must have answered: under Claude Code's hook timeout. */
  deadline: number;
  /** Where a human approves asks, for the message shown while denied or waiting. */
  approvalsUrl: string;
  now?: () => number;
}

/** What the CLI writes to stdout (JSON), or nothing. The CLI always exits 0 with it. */
export type HookOutput = Json | null;

export const METHODS_IMPLEMENTED = ["steps/sessionStart", "steps/sessionEnd", "steps/toolCallRequest", "steps/toolCallResult", "steps/subagentStart", "steps/subagentStop"];

const CHAIN_DENIAL = "chain_mismatch";

/**
 * Claude Code tools that act on nothing outside the agent's own context, so they aren't actions in ACS's
 * sense (hooks.md: toolCallRequest covers "every action that escapes the agent's reasoning context").
 * ToolSearch loads a deferred tool's schema; Claude Code calls it before the first use of an MCP tool, and
 * denying it stops the agent before it ever reaches the governed call. Answered allow here, without the
 * Guardian: it confers no authority, since the tool it loads still needs its own decision. Keep this list
 * to tools verified to have no outside effect.
 */
export const HOST_INTERNAL_TOOLS: ReadonlySet<string> = new Set(["ToolSearch"]);

/** Claude Code's sub-agent spawning tool ("Task" in older releases). Decided as subagentStart, not as a tool call. */
export const SPAWN_TOOLS: ReadonlySet<string> = new Set(["Agent", "Task"]);

/** Claude Code's sub-agent type when the Agent call names none. */
const DEFAULT_SUBAGENT_TYPE = "general-purpose";

const deny = (reason: string): HookOutput => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `VAOM Guardian: ${reason}` } });
const allow = (reason: string): HookOutput => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: `VAOM Guardian: ${reason}` } });

/** The hook input can't be classified. The CLI answers it like any failure on a tool call: deny, exit 2. */
export class UnclassifiedHookError extends Error {}

export async function runHook(input: Json, o: ShimOptions): Promise<HookOutput> {
  const event: string = input?.hook_event_name;
  const ccSession: string = input?.session_id;
  // An input that doesn't say which hook it is can't be told apart from a tool call: deny it. (A named
  // event we don't handle isn't a tool call, and returns no opinion.)
  if (typeof event !== "string" || event === "") throw new UnclassifiedHookError("the hook input names no hook event, so it's treated as a tool call and denied");
  if (typeof ccSession !== "string") return event === "PreToolUse" ? deny("the hook input has no session id.") : null;
  switch (event) {
    case "PreToolUse": return preToolUse(input, ccSession, o).catch((e) => deny(`no decision could be obtained, so the call is denied (${(e as Error).message}).`));
    case "PostToolUse": return toolResult(input, ccSession, "success", o);
    case "PostToolUseFailure": return toolResult(input, ccSession, "failure", o);
    case "SessionStart": return sessionStart(ccSession, o);
    case "SessionEnd": return sessionEnd(ccSession, input.reason, o);
    case "SubagentStart": return subagentStart(input, ccSession, o);
    case "SubagentStop": return subagentStop(input, ccSession, o);
    default: return null;
  }
}

// ---- sessions

/** Who a hook call speaks for: the Claude Code session itself, or one of its sub-agents (by agent_id). */
type Speaker = string | undefined;

interface Target { acs: string; agentId: string; sub: boolean }

/** The ACS session for this Claude Code session, negotiating one if there's none yet. Holds the lock. */
async function root(ccSession: string, o: ShimOptions): Promise<SessionState> {
  const s = o.state.read(ccSession);
  if (s) return s;
  const acs = randomUUID();
  await hello(acs, o.client.agentId, o);
  const started = await o.client.call(acs, "steps/sessionStart", { platform_context: { host: "claude-code" } }, null);
  if (started.decision !== "allow") throw new Error(`the Guardian refused the session (${(started.reason_codes ?? []).join(", ") || started.decision})`);
  const fresh: SessionState = { format: "vaom-guardian.shim-state/0.2", acs_session: acs, sessions: { [acs]: { chain_hash: started.chain_hash, negotiated: true } }, calls: {}, spawns: [], agents: {} };
  o.state.write(ccSession, fresh);
  return fresh;
}

function hello(acs: string, agentId: string, o: ShimOptions): Promise<Json> {
  return o.client.call(acs, "handshake/hello", {
    acs_versions_supported: ["0.1.0"],
    methods_implemented: METHODS_IMPLEMENTED,
    transports_supported: ["http"],
    provenance_producer: "none",
    profiles_supported: ["acs-core", "acs-audit"],
  }, null, { agentId });
}

/** The ACS session a speaker uses. A sub-agent with no session was never allowed to start: that throws. */
function target(s: SessionState, who: Speaker, o: ShimOptions): Target {
  if (who === undefined) return { acs: s.acs_session, agentId: o.client.agentId, sub: false };
  const a = s.agents[who];
  if (!a) throw new Error("this sub-agent was not started through the Guardian, so it has no authority");
  return { acs: a.session, agentId: a.agent_id, sub: true };
}

/**
 * One step on a speaker's session, under the lock, with the chain head claimed and updated. A sub-agent's
 * session negotiates on its first step. If the Guardian no longer knows the root session (it restarted;
 * sessions live in its memory), negotiate a new one and send the step once more; a sub-agent's derived
 * context died with the restart, so its steps fail. A chain mismatch is answered with this step's deny,
 * and the session is dropped: the root's so the next call starts fresh, a sub-agent's for good.
 */
async function step(ccSession: string, o: ShimOptions, who: (s: SessionState) => Speaker, method: string, payload: (s: SessionState, t: Target) => Json, after?: (s: SessionState, result: Json, t: Target) => void, requestId?: string): Promise<Json> {
  return o.state.locked(ccSession, async () => {
    for (let attempt = 0; ; attempt++) {
      const s = await root(ccSession, o);
      const t = target(s, who(s), o);
      const acs = (s.sessions[t.acs] ??= { chain_hash: null, negotiated: false });
      let result: Json;
      try {
        if (!acs.negotiated) { await hello(t.acs, t.agentId, o); acs.negotiated = true; }
        result = await o.client.call(t.acs, method, payload(s, t), acs.chain_hash, { agentId: t.agentId, ...(requestId ? { requestId } : {}) });
      } catch (e) {
        if (!t.sub && attempt === 0 && e instanceof GuardianError && (e.code === -32003 || e.code === -32000)) { o.state.remove(ccSession); continue; }
        throw e;
      }
      if ((result.reason_codes ?? []).includes(CHAIN_DENIAL)) {
        if (!t.sub) o.state.remove(ccSession);
        else { dropAgent(s, t.acs); o.state.write(ccSession, s); }
        return result;
      }
      acs.chain_hash = result.chain_hash;
      after?.(s, result, t);
      o.state.write(ccSession, s);
      return result;
    }
  });
}

function dropAgent(s: SessionState, acs: string): void {
  for (const [id, a] of Object.entries(s.agents)) if (a.session === acs) delete s.agents[id];
  delete s.sessions[acs];
}

async function sessionStart(ccSession: string, o: ShimOptions): Promise<HookOutput> {
  try {
    await o.state.locked(ccSession, () => root(ccSession, o));
    return null;
  } catch (e) {
    return { systemMessage: `VAOM Guardian unavailable (${(e as Error).message}). Every tool call it governs will be denied until it answers.` };
  }
}

/** Claude Code's SessionEnd reasons, in ACS's vocabulary (§ sessionEnd: completed, cancelled, error, timeout, abandoned). */
function endReason(reason: unknown): string {
  return reason === "prompt_input_exit" || reason === "logout" || reason === "clear" ? "completed" : "abandoned";
}

async function sessionEnd(ccSession: string, reason: unknown, o: ShimOptions): Promise<HookOutput> {
  try {
    await o.state.locked(ccSession, async () => {
      const s = o.state.read(ccSession);
      if (!s) return;
      for (const a of Object.values(s.agents)) await endSubSession(s, a.session, a.agent_id, "cancelled", o).catch(() => undefined);
      const head = s.sessions[s.acs_session]?.chain_hash ?? null;
      await o.client.call(s.acs_session, "steps/sessionEnd", { reason: endReason(reason), ...(head ? { final_chain_hash: head } : {}) }, head).catch(() => undefined);
      o.state.remove(ccSession);
    });
  } catch { /* nothing to answer: the session is over */ }
  return null;
}

// ---- sub-agents

async function decideSpawn(input: Json, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  const type = typeof input.tool_input?.subagent_type === "string" && input.tool_input.subagent_type ? input.tool_input.subagent_type : DEFAULT_SUBAGENT_TYPE;
  const subSession = randomUUID();
  const result = await step(ccSession, o, () => input.agent_id, "steps/subagentStart", (_s, t) => ({
    subagent_session_id: subSession,
    parent_session_id: t.acs,
    parent_step_id: input.tool_use_id,
    intent_derivation: "inherit_subset",
    subagent_descriptor: { agent_name: type, agent_id: `${t.agentId}/${type}` },
  }), (s, r, t) => {
    if (r.decision !== "allow") return;
    s.spawns.push({ session: subSession, agent_type: type, agent_id: `${t.agentId}/${type}`, parent: t.acs, tool_use_id: input.tool_use_id });
  });
  const codes = (result.reason_codes ?? []).join(", ");
  if (result.decision === "allow") return allow(`sub-agent ${type} may start, with a context derived from this one.`);
  return deny(`${result.reasoning ?? `the sub-agent ${type} may not start.`}${codes ? ` [${codes}]` : ""}`);
}

async function subagentStart(input: Json, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  const none = { hookSpecificOutput: { hookEventName: "SubagentStart", additionalContext: "VAOM Guardian: this sub-agent was not started through the Guardian, so every tool call it makes will be denied." } };
  if (typeof input.agent_id !== "string" || typeof input.agent_type !== "string") return none;
  try {
    return await o.state.locked(ccSession, async () => {
      const s = o.state.read(ccSession);
      const i = s ? s.spawns.findIndex((p) => p.agent_type === input.agent_type) : -1;
      if (!s || i < 0) return none;
      const [p] = s.spawns.splice(i, 1);
      s.agents[input.agent_id] = { session: p!.session, agent_type: p!.agent_type, agent_id: p!.agent_id, parent: p!.parent, tool_use_id: p!.tool_use_id };
      o.state.write(ccSession, s);
      return null;
    });
  } catch {
    return none;
  }
}

/** End a sub-agent's ACS session (closing its derived context), then tell its parent session it stopped. */
async function endSubSession(s: SessionState, sub: string, agentId: string, outcome: "completed" | "failed" | "cancelled", o: ShimOptions): Promise<void> {
  const entry = Object.values(s.agents).find((a) => a.session === sub) ?? s.spawns.find((p) => p.session === sub);
  const st = (s.sessions[sub] ??= { chain_hash: null, negotiated: false });
  try {
    if (!st.negotiated) { await hello(sub, agentId, o); st.negotiated = true; }
    const ended = await o.client.call(sub, "steps/sessionEnd", { reason: outcome === "completed" ? "completed" : outcome === "cancelled" ? "cancelled" : "error", ...(st.chain_hash ? { final_chain_hash: st.chain_hash } : {}) }, st.chain_hash, { agentId });
    const parent = entry?.parent;
    const ps = parent ? s.sessions[parent] : undefined;
    if (parent && ps) {
      const stopped = await o.client.call(parent, "steps/subagentStop", { subagent_session_id: sub, outcome, final_chain_hash: ended.chain_hash }, ps.chain_hash, { agentId: parent === s.acs_session ? o.client.agentId : (Object.values(s.agents).find((a) => a.session === parent)?.agent_id ?? o.client.agentId) });
      ps.chain_hash = stopped.chain_hash;
    }
  } finally {
    dropAgent(s, sub);
    s.spawns = s.spawns.filter((p) => p.session !== sub);
  }
}

async function subagentStop(input: Json, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  if (typeof input.agent_id !== "string") return null;
  try {
    await o.state.locked(ccSession, async () => {
      const s = o.state.read(ccSession);
      const a = s?.agents[input.agent_id];
      if (!s || !a) return;
      await endSubSession(s, a.session, a.agent_id, "completed", o).catch(() => undefined);
      o.state.write(ccSession, s);
    });
  } catch { /* nothing to answer */ }
  return null;
}

// ---- tool calls

function toolCallRequest(input: Json): Json {
  const args: Record<string, { value: unknown }> = {};
  const ti = input.tool_input;
  if (ti && typeof ti === "object" && !Array.isArray(ti)) for (const [k, v] of Object.entries(ti)) args[k] = { value: v };
  return {
    tool: { name: String(input.tool_name) },
    arguments: args,
    ...(input.tool_name === "Bash" && typeof ti?.command === "string" ? { raw_command: ti.command } : {}),
  };
}

async function preToolUse(input: Json, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  if (input.permission_mode === "bypassPermissions") return deny("bypassPermissions mode is refused: every governed call needs the Guardian's decision.");
  if (typeof input.tool_name !== "string" || typeof input.tool_use_id !== "string") return deny("the hook input has no tool name or tool_use_id.");
  if (HOST_INTERNAL_TOOLS.has(input.tool_name)) return allow("host-internal tool, not an action; the tools it loads are decided one by one.");
  if (SPAWN_TOOLS.has(input.tool_name)) return decideSpawn(input, ccSession, o);

  const requestId = randomUUID();
  let acsSession = "";
  const result = await step(ccSession, o, () => input.agent_id, "steps/toolCallRequest", () => toolCallRequest(input), (s, r, t) => {
    acsSession = t.acs;
    if (r.decision === "allow" || r.decision === "ask") s.calls[input.tool_use_id] = { request_id: requestId, tool: input.tool_name, session: t.acs };
  }, requestId);

  const codes = (result.reason_codes ?? []).join(", ");
  switch (result.decision) {
    case "allow":
      return allow(result.reasoning ?? "allowed.");
    case "ask":
      return awaitApproval(acsSession, requestId, result, o);
    case "deny":
      return deny(`${result.reasoning ?? "denied."}${codes ? ` [${codes}]` : ""}`);
    case "defer":
      return deny(`${result.reasoning ?? "deferred."} Deferred calls time out to deny.${codes ? ` [${codes}]` : ""}`);
    default:
      return deny(`the Guardian answered "${result.decision}", which this shim doesn't apply.`);
  }
}

async function awaitApproval(acsSession: string, requestId: string, result: Json, o: ShimOptions): Promise<HookOutput> {
  const now = o.now ?? Date.now;
  const who = result.ask_details?.approver?.id ?? "an approver";
  for (;;) {
    const left = Math.floor((o.deadline - now()) / 1000) - 5;
    if (left < 1) return deny(`no approval from ${who} before the hook's deadline (approvals: ${o.approvalsUrl}).`);
    const status = await o.client.approvalStatus(acsSession, requestId, Math.min(25, left));
    if (status === "approved") return allow(`approved by ${who}.`);
    if (status === "rejected") return deny(`${who} rejected this call.`);
    if (status === "expired") return deny(`the approval request to ${who} expired (approvals: ${o.approvalsUrl}).`);
    if (status !== "pending") return deny(`unknown approval status "${status}".`);
  }
}

async function toolResult(input: Json, ccSession: string, exit: "success" | "failure", o: ShimOptions): Promise<HookOutput> {
  if (typeof input.tool_use_id !== "string" || typeof input.tool_name !== "string" || HOST_INTERNAL_TOOLS.has(input.tool_name)) return null;
  if (SPAWN_TOOLS.has(input.tool_name)) return spawnFinished(input, ccSession, o);
  try {
    let linked = true;
    const result = await step(ccSession, o, (s) => {
      // The session the call was decided on; a call with no decision is reported on the session of whoever
      // made it, or the root if that sub-agent has none.
      const call = s.calls[input.tool_use_id];
      if (call) return Object.entries(s.agents).find(([, a]) => a.session === call.session)?.[0];
      return typeof input.agent_id === "string" && s.agents[input.agent_id] ? input.agent_id : undefined;
    }, "steps/toolCallResult", (s) => {
      const call = s.calls[input.tool_use_id];
      linked = call !== undefined;
      return { tool: { name: input.tool_name }, ...(call ? { request_id_ref: call.request_id } : {}), exit_status: exit, outputs: [] };
    }, (s) => { delete s.calls[input.tool_use_id]; });
    if (result.decision === "allow") return null;
    const why = linked ? (result.reasoning ?? "the Guardian refused this result.") : "this call ran without a Guardian decision on record; it has been reported.";
    // The output is withheld from the model as well as flagged: an ask that ran without its approval
    // mustn't feed the agent's next step.
    return { decision: "block", reason: `VAOM Guardian: ${why}`, hookSpecificOutput: { hookEventName: input.hook_event_name, updatedToolOutput: `[output withheld by VAOM Guardian: ${why}]` } };
  } catch {
    // The call has already run; nothing here can stop it. The decision stays open (its cap use reserved)
    // until the Guardian hears otherwise, which is the conservative side.
    return null;
  }
}

/** The Agent call returned. A spawn it was allowed but that never started is ended, so it stops holding a
 *  place in the parent's fan-out. */
async function spawnFinished(input: Json, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  try {
    await o.state.locked(ccSession, async () => {
      const s = o.state.read(ccSession);
      const p = s?.spawns.find((x) => x.tool_use_id === input.tool_use_id);
      if (!s || !p) return;
      await endSubSession(s, p.session, p.agent_id, "failed", o).catch(() => undefined);
      o.state.write(ccSession, s);
    });
  } catch { /* the call has returned; nothing to answer */ }
  return null;
}
