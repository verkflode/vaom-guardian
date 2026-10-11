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

export const METHODS_IMPLEMENTED = ["steps/sessionStart", "steps/sessionEnd", "steps/toolCallRequest", "steps/toolCallResult"];

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

const deny = (reason: string): HookOutput => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `VAOM Guardian: ${reason}` } });
const allow = (reason: string): HookOutput => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: `VAOM Guardian: ${reason}` } });

export async function runHook(input: Json, o: ShimOptions): Promise<HookOutput> {
  const event: string = input?.hook_event_name;
  const ccSession: string = input?.session_id;
  if (typeof ccSession !== "string") return event === "PreToolUse" ? deny("the hook input has no session id.") : null;
  switch (event) {
    case "PreToolUse": return preToolUse(input, ccSession, o).catch((e) => deny(`no decision could be obtained, so the call is denied (${(e as Error).message}).`));
    case "PostToolUse": return toolResult(input, ccSession, "success", o);
    case "PostToolUseFailure": return toolResult(input, ccSession, "failure", o);
    case "SessionStart": return sessionStart(ccSession, o);
    case "SessionEnd": return sessionEnd(ccSession, input.reason, o);
    default: return null;
  }
}

// ---- session

/** The ACS session for this Claude Code session, negotiating one if there's none yet. Holds the lock. */
async function session(ccSession: string, o: ShimOptions): Promise<SessionState> {
  const s = o.state.read(ccSession);
  if (s) return s;
  const acs = randomUUID();
  await o.client.call(acs, "handshake/hello", {
    acs_versions_supported: ["0.1.0"],
    methods_implemented: METHODS_IMPLEMENTED,
    transports_supported: ["http"],
    provenance_producer: "none",
    profiles_supported: ["acs-core", "acs-audit"],
  }, null);
  const started = await o.client.call(acs, "steps/sessionStart", { platform_context: { host: "claude-code" } }, null);
  if (started.decision !== "allow") throw new Error(`the Guardian refused the session (${(started.reason_codes ?? []).join(", ") || started.decision})`);
  const fresh: SessionState = { format: "vaom-guardian.shim-state/0.1", acs_session: acs, chain_hash: started.chain_hash, calls: {} };
  o.state.write(ccSession, fresh);
  return fresh;
}

/**
 * One step on this session, under its lock, with the chain head claimed and updated. If the Guardian no
 * longer knows the session (it restarted, and sessions live in its memory), negotiate a new one and send
 * the step once more. A chain mismatch is answered with a deny for this step; the session is then dropped,
 * so the next step starts a new one rather than every later call being denied.
 */
async function step(ccSession: string, o: ShimOptions, method: string, payload: (s: SessionState) => Json, after?: (s: SessionState, result: Json) => void, requestId?: string): Promise<Json> {
  return o.state.locked(ccSession, async () => {
    for (let attempt = 0; ; attempt++) {
      const s = await session(ccSession, o);
      let result: Json;
      try {
        result = await o.client.call(s.acs_session, method, payload(s), s.chain_hash, requestId);
      } catch (e) {
        if (attempt === 0 && e instanceof GuardianError && (e.code === -32003 || e.code === -32000)) { o.state.remove(ccSession); continue; }
        throw e;
      }
      if ((result.reason_codes ?? []).includes(CHAIN_DENIAL)) { o.state.remove(ccSession); return result; }
      s.chain_hash = result.chain_hash;
      after?.(s, result);
      o.state.write(ccSession, s);
      return result;
    }
  });
}

async function sessionStart(ccSession: string, o: ShimOptions): Promise<HookOutput> {
  try {
    await o.state.locked(ccSession, () => session(ccSession, o));
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
      await o.client.call(s.acs_session, "steps/sessionEnd", { reason: endReason(reason), ...(s.chain_hash ? { final_chain_hash: s.chain_hash } : {}) }, s.chain_hash).catch(() => undefined);
      o.state.remove(ccSession);
    });
  } catch { /* nothing to answer: the session is over */ }
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

  const requestId = randomUUID();
  const remember = (s: SessionState) => { s.calls[input.tool_use_id] = { request_id: requestId, tool: input.tool_name }; };
  let acsSession = "";
  const result = await step(ccSession, o, "steps/toolCallRequest", () => toolCallRequest(input), (s, r) => {
    acsSession = s.acs_session;
    if (r.decision === "allow" || r.decision === "ask") remember(s);
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
  try {
    let linked = true;
    const result = await step(ccSession, o, "steps/toolCallResult", (s) => {
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
