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
import type { ServerHello, ToolCallRequest, ToolCallResult } from "@verkflode/vaom-guardian-acs";
import { GuardianClient, GuardianError, type StepResult } from "./client.ts";
import { StateDir, type SessionState } from "./state.ts";

/**
 * Claude Code's hook input: the fields this shim reads. Claude Code publishes no schema for it, so runHook
 * checks each field once, on the way in. A field that is missing or null is absent; one that is there with
 * the wrong type makes the input unclassifiable, which is a deny: dropping it could change who a call is
 * decided for (a malformed agent_id would read as the root session).
 */
export interface HookInput {
  hook_event_name: string;
  session_id?: string;
  tool_name?: string;
  tool_use_id?: string;
  tool_input?: Readonly<Record<string, unknown>>;
  agent_id?: string;
  agent_type?: string;
  permission_mode?: string;
  reason?: string;
}

const STRING_FIELDS = ["session_id", "tool_name", "tool_use_id", "agent_id", "agent_type", "permission_mode", "reason"] as const;

/** Check a hook input's fields. Throws UnclassifiedHookError when it names no event or a field has the wrong type. */
export function parseHookInput(raw: unknown): HookInput {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new UnclassifiedHookError("the hook input is not a JSON object, so it's treated as a tool call and denied");
  const o = raw as Record<string, unknown>;
  // An input that doesn't say which hook it is can't be told apart from a tool call: deny it.
  if (typeof o.hook_event_name !== "string" || o.hook_event_name === "") throw new UnclassifiedHookError("the hook input names no hook event, so it's treated as a tool call and denied");
  const input: { -readonly [K in keyof HookInput]: HookInput[K] } = { hook_event_name: o.hook_event_name };
  for (const k of STRING_FIELDS) {
    const v = o[k];
    if (v === undefined || v === null) continue;
    if (typeof v !== "string") throw new UnclassifiedHookError(`the hook input's ${k} is not a string, so it's treated as a tool call and denied`);
    input[k] = v;
  }
  const ti = o.tool_input;
  if (ti !== undefined && ti !== null) {
    if (typeof ti !== "object" || Array.isArray(ti)) throw new UnclassifiedHookError("the hook input's tool_input is not an object, so it's treated as a tool call and denied");
    input.tool_input = ti as Record<string, unknown>;
  }
  return input;
}

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
export type HookOutput =
  | { hookSpecificOutput: { hookEventName: "PreToolUse"; permissionDecision: "allow" | "deny"; permissionDecisionReason: string } }
  | { hookSpecificOutput: { hookEventName: "SubagentStart"; additionalContext: string } }
  | { decision: "block"; reason: string; hookSpecificOutput: { hookEventName: string; updatedToolOutput: string } }
  | { systemMessage: string }
  | null;

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

export async function runHook(raw: unknown, o: ShimOptions): Promise<HookOutput> {
  const input = parseHookInput(raw);
  const event = input.hook_event_name;
  const ccSession = input.session_id;
  // A named event we don't handle isn't a tool call, and returns no opinion.
  if (ccSession === undefined) return event === "PreToolUse" ? deny("the hook input has no session id.") : null;
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

function hello(acs: string, agentId: string, o: ShimOptions): Promise<ServerHello> {
  return o.client.hello(acs, {
    acs_versions_supported: ["0.1.0"],
    methods_implemented: METHODS_IMPLEMENTED,
    transports_supported: ["http"],
    provenance_producer: "none",
    profiles_supported: ["acs-core", "acs-audit"],
  }, { agentId });
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
async function step(ccSession: string, o: ShimOptions, who: (s: SessionState) => Speaker, method: string, payload: (s: SessionState, t: Target) => object, after?: (s: SessionState, result: StepResult, t: Target) => void, requestId?: string): Promise<StepResult> {
  return o.state.locked(ccSession, async () => {
    for (let attempt = 0; ; attempt++) {
      const s = await root(ccSession, o);
      const t = target(s, who(s), o);
      const acs = (s.sessions[t.acs] ??= { chain_hash: null, negotiated: false });
      let result: StepResult;
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
function endReason(reason: string | undefined): string {
  return reason === "prompt_input_exit" || reason === "logout" || reason === "clear" ? "completed" : "abandoned";
}

async function sessionEnd(ccSession: string, reason: string | undefined, o: ShimOptions): Promise<HookOutput> {
  try {
    await o.state.locked(ccSession, async () => {
      const s = o.state.read(ccSession);
      if (!s) return;
      for (const a of Object.values(s.agents)) await endSubSession(s, a.session, a.agent_id, "cancelled", o).catch(() => undefined);
      const head = s.sessions[s.acs_session]?.chain_hash ?? null;
      // How many decision failures this session recorded, per class (§6.4): a session that ends without the
      // count reads as unmeasurable, so it is sent even when it is empty.
      const summary = { decision_failures: o.state.failureCounts(ccSession) };
      await o.client.call(s.acs_session, "steps/sessionEnd", { reason: endReason(reason), summary, ...(head ? { final_chain_hash: head } : {}) }, head).catch(() => undefined);
      o.state.remove(ccSession);
    });
  } catch { /* nothing to answer: the session is over */ }
  return null;
}

// ---- sub-agents

async function decideSpawn(input: HookInput & { tool_use_id: string }, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  const named = input.tool_input?.subagent_type;
  const type = typeof named === "string" && named ? named : DEFAULT_SUBAGENT_TYPE;
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

async function subagentStart(input: HookInput, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  const none: HookOutput = { hookSpecificOutput: { hookEventName: "SubagentStart", additionalContext: "VAOM Guardian: this sub-agent was not started through the Guardian, so every tool call it makes will be denied." } };
  const { agent_id: agentId, agent_type: agentType } = input;
  if (agentId === undefined || agentType === undefined) return none;
  try {
    return await o.state.locked(ccSession, async () => {
      const s = o.state.read(ccSession);
      const i = s ? s.spawns.findIndex((p) => p.agent_type === agentType) : -1;
      if (!s || i < 0) return none;
      const [p] = s.spawns.splice(i, 1);
      s.agents[agentId] = { session: p!.session, agent_type: p!.agent_type, agent_id: p!.agent_id, parent: p!.parent, tool_use_id: p!.tool_use_id };
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

async function subagentStop(input: HookInput, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  const agentId = input.agent_id;
  if (agentId === undefined) return null;
  try {
    await o.state.locked(ccSession, async () => {
      const s = o.state.read(ccSession);
      const a = s?.agents[agentId];
      if (!s || !a) return;
      await endSubSession(s, a.session, a.agent_id, "completed", o).catch(() => undefined);
      o.state.write(ccSession, s);
    });
  } catch { /* nothing to answer */ }
  return null;
}

// ---- tool calls

function toolCallRequest(tool: string, ti: HookInput["tool_input"]): ToolCallRequest {
  const args: Record<string, { value: unknown }> = {};
  for (const [k, v] of Object.entries(ti ?? {})) args[k] = { value: v };
  return {
    tool: { name: tool },
    arguments: args,
    ...(tool === "Bash" && typeof ti?.command === "string" ? { raw_command: ti.command } : {}),
  };
}

async function preToolUse(input: HookInput, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  if (input.permission_mode === "bypassPermissions") return deny("bypassPermissions mode is refused: every governed call needs the Guardian's decision.");
  const { tool_name: tool, tool_use_id: toolUseId } = input;
  if (tool === undefined || toolUseId === undefined) return deny("the hook input has no tool name or tool_use_id.");
  if (HOST_INTERNAL_TOOLS.has(tool)) return allow("host-internal tool, not an action; the tools it loads are decided one by one.");
  if (SPAWN_TOOLS.has(tool)) return decideSpawn({ ...input, tool_use_id: toolUseId }, ccSession, o);

  const requestId = randomUUID();
  let acsSession = "";
  const result = await step(ccSession, o, () => input.agent_id, "steps/toolCallRequest", () => toolCallRequest(tool, input.tool_input), (s, r, t) => {
    acsSession = t.acs;
    if (r.decision === "allow" || r.decision === "ask") s.calls[toolUseId] = { request_id: requestId, tool, session: t.acs };
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

async function awaitApproval(acsSession: string, requestId: string, result: StepResult, o: ShimOptions): Promise<HookOutput> {
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

async function toolResult(input: HookInput, ccSession: string, exit: "success" | "failure", o: ShimOptions): Promise<HookOutput> {
  const { tool_name: tool, tool_use_id: toolUseId, agent_id: agentId } = input;
  if (toolUseId === undefined || tool === undefined || HOST_INTERNAL_TOOLS.has(tool)) return null;
  if (SPAWN_TOOLS.has(tool)) return spawnFinished(toolUseId, ccSession, o);
  try {
    let linked = true;
    const result = await step(ccSession, o, (s) => {
      // The session the call was decided on; a call with no decision is reported on the session of whoever
      // made it, or the root if that sub-agent has none.
      const call = s.calls[toolUseId];
      if (call) return Object.entries(s.agents).find(([, a]) => a.session === call.session)?.[0];
      return agentId !== undefined && s.agents[agentId] ? agentId : undefined;
    }, "steps/toolCallResult", (s): ToolCallResult => {
      const call = s.calls[toolUseId];
      linked = call !== undefined;
      return { tool: { name: tool }, ...(call ? { request_id_ref: call.request_id } : {}), exit_status: exit, outputs: [] };
    }, (s) => { delete s.calls[toolUseId]; });
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
async function spawnFinished(toolUseId: string, ccSession: string, o: ShimOptions): Promise<HookOutput> {
  try {
    await o.state.locked(ccSession, async () => {
      const s = o.state.read(ccSession);
      const p = s?.spawns.find((x) => x.tool_use_id === toolUseId);
      if (!s || !p) return;
      await endSubSession(s, p.session, p.agent_id, "failed", o).catch(() => undefined);
      o.state.write(ccSession, s);
    });
  } catch { /* the call has returned; nothing to answer */ }
  return null;
}
