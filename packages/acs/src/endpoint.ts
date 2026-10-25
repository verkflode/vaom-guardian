// The ACS request handler: one JSON-RPC request in, one response out, plus what the caller must persist
// before sending it. Pure and synchronous: no I/O, no clock (the caller passes `now`), no randomness (the
// caller passes `newId`). The HTTP server, storage and the approval page live in the guardian package.
//
// Order of checks, each failing closed:
//   parse -> no batches -> envelope schema -> ACS version -> signature (session key) -> replay -> session
//   state -> payload schema -> chain cross-check -> the step itself.
// The signature is checked before replay, so a forged request can't burn a request id. An error response
// is a decision failure for the Observed Agent, which this Guardian's handshake declares as deny.
//
// Only these steps are handled: handshake/hello, system/ping, sessionStart, sessionEnd, toolCallRequest,
// toolCallResult, subagentStart, and a short list of purely observational steps, which are answered allow
// with reason not_evaluated and chained. Anything else (wrapped protocols, memory and skill steps, AgBOM)
// is METHOD_NOT_FOUND: a method this Guardian doesn't evaluate must not get an allow by default.
import { decide, resolveRecord, type CapLedger, type ContextRegistry, type ContextSpec, type DecisionRecord, type LiveContext, type Policy, type Resolution } from "@verkflode/vaom-guardian-core";
import { Chain, requestHash, type ContextEntry } from "./chain.ts";
import { AcsError, ERR } from "./errors.ts";
import {
  validateAgentResponse, validateAgentTrigger, validatePostCompact, validatePreCompact, validateRequestEnvelope, validateResponseEnvelope, validateSessionEnd, validateSessionStart,
  validateSubagentStart, validateSubagentStop, validateToolCallRequest, validateToolCallResult, validateTurnEnd, validateTurnStart, validateUserMessage, type Validator,
} from "./generated/validators.js";
import { negotiate, type GuardianConfig } from "./handshake.ts";
import { sessionKey } from "./hkdf.ts";
import { ReplayGuard } from "./replay.ts";
import { sign, verify } from "./sign.ts";
import { toCall, toResult } from "./translate.ts";
import { acceptsVersion } from "./version.ts";

type Json = any;

/** Steps that report what happened and carry no action of their own. Each is checked against its schema
 *  before it's chained: an entry commits to a payload, so the payload must be the step it claims to be. */
export const OBSERVED_STEPS = ["steps/turnStart", "steps/turnEnd", "steps/userMessage", "steps/agentTrigger", "steps/agentResponse", "steps/preCompact", "steps/postCompact", "steps/subagentStop"] as const;
const OBSERVED_VALIDATORS: Record<(typeof OBSERVED_STEPS)[number], Validator> = {
  "steps/turnStart": validateTurnStart, "steps/turnEnd": validateTurnEnd, "steps/userMessage": validateUserMessage, "steps/agentTrigger": validateAgentTrigger,
  "steps/agentResponse": validateAgentResponse, "steps/preCompact": validatePreCompact, "steps/postCompact": validatePostCompact, "steps/subagentStop": validateSubagentStop,
};

export interface EndpointConfig extends GuardianConfig {
  /** Pre-shared secret the per-session HMAC keys are derived from (HKDF, ACS §10.2). */
  ikm: Uint8Array;
  keyId: string;
  /** HMAC key for private facts and cap groups in decision records. */
  factKey?: Uint8Array;
  approvalTimeoutSeconds: number;
  deferTimeoutMs: number;
  evaluatorVersion: string;
  /** The execution context a session opens at sessionStart, or null for none (the session then has no
   *  authority, and every governed call is unplaceable). Human configuration, never computed from the request. */
  activationFor(input: { agentId: string; sessionId: string; payload: Json }): Omit<ContextSpec, "id" | "session" | "agent"> | null;
  /** Further live contexts for a session, e.g. lease observation contexts. */
  extraContexts?(sessionId: string, now: number): readonly LiveContext[];
  /** When this Guardian started (ms). Requests signed before it are refused: the replay guard's memory
   *  doesn't survive a restart. */
  startedAt?: number;
}

export interface EndpointDeps {
  policy: Policy;
  ledger: CapLedger;
  contexts: ContextRegistry;
  newId(): string;
}

export type Incident =
  | { kind: "execution-without-authority"; session: string; request_id: string; record: string; why: string }
  | { kind: "unlinked-result"; session: string; request_id: string; request_id_ref?: string };

export interface Handled {
  /** The JSON-RPC response to send, after everything below is persisted. */
  response: Json;
  /** Records to persist (new, or newly resolved: the same id again). */
  records: DecisionRecord[];
  /** Chain entries to persist, in order. */
  entries: ContextEntry[];
  incidents: Incident[];
  /** Every sub-agent spawn decided, allowed or denied: the evidence for chain integrity (scorecard metric 12). */
  spawns: Spawn[];
}

export interface Spawn {
  session: string;
  subagent_session: string;
  agent: string;
  subagent_type?: string;
  decision: "allow" | "deny";
  /** The ACS reason code: context_derived, authority_breach (depth, fan-out or count), outside_allowed_patterns, or a request fault. */
  reason: string;
  context?: string;
  why?: string;
  /** What the agent declared about the sub-agent's intent. Recorded for the audit; authority comes from
   *  the matrix's patterns, and a derived context only ever narrows. */
  intent_derivation?: string;
}

// An ended session stays as a small tombstone (its chain is a head, its replay ids are dropped), so its id
// can't negotiate again.
interface Session {
  agentId: string;
  version: string;
  chain: Chain;
  context?: string;
  ended: boolean;
}

interface Pending {
  record: DecisionRecord;
  approval?: NonNullable<Resolution["approval"]>;
}

export class AcsEndpoint {
  private readonly cfg: EndpointConfig;
  private readonly deps: EndpointDeps;
  private readonly replay: ReplayGuard;
  private readonly sessions = new Map<string, Session>();
  private readonly pending = new Map<string, Pending>(); // `${session} ${request_id}` -> open decision

  constructor(cfg: EndpointConfig, deps: EndpointDeps) {
    if (cfg.ikm.length < 32) throw new Error("the ACS pre-shared secret must be at least 32 bytes");
    this.cfg = cfg;
    this.deps = deps;
    this.replay = new ReplayGuard(cfg.skewWindowMs, cfg.startedAt);
  }

  handle(raw: string | unknown, now: number): Handled {
    const out: Handled = { response: null, records: [], entries: [], incidents: [], spawns: [] };
    let id: string | number | null = null;
    let requestId: string | undefined;
    try {
      let env: Json;
      if (typeof raw === "string") {
        try { env = JSON.parse(raw); } catch { throw new AcsError(ERR.PARSE, "request is not JSON"); }
      } else env = raw;
      if (Array.isArray(env)) throw new AcsError(ERR.INVALID_REQUEST, "batch requests are not supported");
      if (env && typeof env === "object" && (typeof env.id === "string" || typeof env.id === "number")) id = env.id;
      if (!validateRequestEnvelope(env)) throw new AcsError(ERR.INVALID_REQUEST, "request fails the ACS envelope schema", { errors: brief(validateRequestEnvelope) });

      const p = env.params;
      requestId = p.request_id;
      if (env.method === "system/ping") {
        out.response = { jsonrpc: "2.0", id, result: { type: "final", acs_version: p.acs_version, request_id: p.request_id, decision: "allow" } };
        return out;
      }
      if (!acceptsVersion(p.acs_version)) throw new AcsError(ERR.UNSUPPORTED_VERSION, `ACS ${p.acs_version} is not supported`, { supported_versions: ["0.1.0"] });
      const sid: string = p.metadata.session_id;
      // key_id names the secret (§10): this Guardian holds one, under its configured label, and rejects any
      // other label rather than try another secret. The error is unsigned: no configured secret matches.
      if (p.signature && p.signature.key_id !== this.cfg.keyId) throw new AcsError(ERR.SIGNATURE_INVALID, "unknown key_id");
      const key = sessionKey(this.cfg.ikm, sid);
      const v = verify(env, key);
      if (!v.ok) throw new AcsError(ERR.SIGNATURE_INVALID, v.why);
      this.replay.check(sid, p.request_id, p.timestamp, now, p.nonce);

      if (env.method === "handshake/hello") {
        if (this.sessions.has(sid)) throw new AcsError(ERR.SESSION_REFUSED, "this session has already negotiated");
        const hello = negotiate(p.payload, this.cfg);
        this.sessions.set(sid, { agentId: p.metadata.agent_id, version: hello.negotiated_version, chain: new Chain(), ended: false });
        out.response = { jsonrpc: "2.0", id, result: hello };
        return out;
      }

      const s = this.sessions.get(sid);
      if (!s) throw new AcsError(ERR.CAPABILITY_NOT_NEGOTIATED, "handshake/hello must come first");
      if (s.ended) throw new AcsError(ERR.SESSION_REFUSED, "the session has ended");
      if (p.metadata.agent_id !== s.agentId) throw new AcsError(ERR.SESSION_REFUSED, "agent_id differs from the one that negotiated this session");

      const step = STEPS[env.method as string];
      const observed = (OBSERVED_STEPS as readonly string[]).includes(env.method);
      if (!step && !observed) throw new AcsError(ERR.METHOD_NOT_FOUND, `${env.method} is not evaluated by this Guardian`);
      const validate = step ? step.validate : OBSERVED_VALIDATORS[env.method as (typeof OBSERVED_STEPS)[number]];
      if (validate && !validate(p.payload)) throw new AcsError(ERR.INVALID_PARAMS, `${env.method} payload fails its schema`, { errors: brief(validate) });

      // Chain cross-check (§8.6): the agent's view of the head before this step must match ours. The step's
      // entry is committed only once its response is built: a step that fails leaves no entry, and the
      // agent's last seen head stays right.
      const claimed: string | undefined = p.metadata.session_state?.chain_hash;
      const mismatch = claimed !== undefined && claimed !== (s.chain.head ?? "");
      const entry = s.chain.next({ entry_id: this.deps.newId(), step_id: p.request_id, step_type: (env.method as string).slice("steps/".length), request_hash: requestHash(p), timestamp: p.timestamp });
      const base = { type: "final", acs_version: s.version, request_id: p.request_id, chain_hash: entry.entry_hash };

      let result: Json;
      if (mismatch) result = { ...base, decision: "deny", reason_codes: ["chain_mismatch"], reasoning: "The agent's chain head differs from the Guardian's." };
      else if (observed) result = { ...base, decision: "allow", reason_codes: ["not_evaluated"] };
      else result = { ...base, ...step!.run.call(this, { p, s, sid, now, entry, out }) };

      out.response = sign({ jsonrpc: "2.0", id, result }, key, this.cfg.keyId);
      if (!validateResponseEnvelope(out.response)) throw new AcsError(ERR.INTERNAL, "built response fails the ACS envelope schema", { errors: brief(validateResponseEnvelope) });
      s.chain.commit(entry);
      out.entries.push(entry);
      if (env.method === "steps/sessionEnd") this.replay.forget(sid);
      return out;
    } catch (e) {
      const err = e instanceof AcsError ? e : new AcsError(ERR.INTERNAL, "decision failure");
      // Nothing from a failed request is kept: the response is an error, so no decision went out. A decision
      // made in this request is released whether or not it was resolved here (a refusal is resolved at
      // once); a resolution of an earlier call isn't undone, since that call did run.
      for (const r of out.records) {
        if (r.request.wire?.request_id !== requestId && r.resolution) continue;
        this.deps.ledger.release(r.id);
        if (r.request.wire?.request_id) this.pending.delete(`${r.request.session.id} ${r.request.wire.request_id}`);
      }
      return { response: { jsonrpc: "2.0", id, error: { code: err.code, message: err.message, data: err.data } }, records: [], entries: [], incidents: out.incidents, spawns: out.spawns };
    }
  }

  /** Record a human approval for a pending review or escalation. The approval record itself is issued and
   *  verified by the guardian package; this only binds it to the decision so the execution can resolve. */
  approve(sessionId: string, requestId: string, approval: NonNullable<Resolution["approval"]>): void {
    const p = this.pending.get(`${sessionId} ${requestId}`);
    if (!p) throw new Error("no pending decision with that request id");
    if (p.record.decision.outcome !== "review" && p.record.decision.outcome !== "escalate") throw new Error("only a review or escalation takes an approval");
    if (approval.approver_role !== p.record.decision.approver_role) throw new Error(`the decision names ${p.record.decision.approver_role} as approver`);
    // Who approved is employee monitoring. The record names the approver only when the matrix enables
    // reviewer-level metrics (which needs a recorded approval such as a DPIA); otherwise the role is all
    // the evidence carries, whatever the caller passed.
    const { approver_id: _id, ...anonymous } = approval;
    p.approval = this.deps.policy.matrix.oversight?.reviewerLevelMetrics?.enabled === true ? approval : anonymous;
  }

  /** Resolve a pending decision that will never execute (rejected, expired, withdrawn). Returns the record to persist. */
  close(sessionId: string, requestId: string, result: "rejected" | "expired" | "withdrawn" | "not-executed", ts: string): DecisionRecord {
    const k = `${sessionId} ${requestId}`;
    const p = this.pending.get(k);
    if (!p) throw new Error("no pending decision with that request id");
    const resolved = resolveRecord(p.record, { ts, result });
    this.deps.ledger.settle(resolved.id, result);
    this.pending.delete(k);
    return resolved;
  }

  /** The caller couldn't persist what `handle` returned: release its reservations and answer deny instead. */
  persistFailed(h: Handled, sessionId: string): Json {
    for (const r of h.records) {
      if (!r.resolution) {
        this.deps.ledger.release(r.id);
        if (r.request.wire?.request_id) this.pending.delete(`${sessionId} ${r.request.wire.request_id}`);
      }
    }
    return { jsonrpc: "2.0", id: h.response?.id ?? null, error: { code: ERR.INTERNAL, message: "the decision could not be recorded", data: { reason: "the decision could not be recorded" } } };
  }

  /** The current chain head for a session (for sessionEnd summaries and audits). */
  head(sessionId: string): string | null {
    return this.sessions.get(sessionId)?.chain.head ?? null;
  }
}

interface StepInput { p: Json; s: Session; sid: string; now: number; entry: ContextEntry; out: Handled }
interface Step { validate?: Validator; run(this: AcsEndpoint, i: StepInput): Json }

function brief(v: Validator): Json {
  return (v.errors ?? []).slice(0, 5).map((e) => ({ path: e.instancePath, message: e.message }));
}

// Steps get `this` bound to the endpoint; private state is reached through a cast so the class keeps one surface.
type Inside = { cfg: EndpointConfig; deps: EndpointDeps; pending: Map<string, Pending>; replay: ReplayGuard };
const inside = (e: AcsEndpoint) => e as unknown as Inside;

const STEPS: Record<string, Step> = {
  "steps/sessionStart": {
    validate: validateSessionStart,
    run(i) {
      const { cfg, deps } = inside(this);
      if (i.s.context) return { decision: "deny", reason_codes: ["session_already_started"], reasoning: "The session has already started." };
      const spec = cfg.activationFor({ agentId: i.s.agentId, sessionId: i.sid, payload: i.p.payload });
      if (!spec) return { decision: "allow", reason_codes: ["no_execution_context"], reasoning: "Session started with no execution context: governed calls will be unplaceable." };
      const ctx = deps.contexts.open({ ...spec, id: deps.newId(), session: i.sid, agent: { id: i.s.agentId } }, i.now);
      i.s.context = ctx.id;
      return { decision: "allow", reason_codes: ["context_opened"], policy_data: { context_id: ctx.id, context_expires_at: new Date(ctx.expiresAt).toISOString() } };
    },
  },

  "steps/sessionEnd": {
    validate: validateSessionEnd,
    run(i) {
      const { deps, pending } = inside(this);
      // A session's authority ends with it: its root context, and the context a sub-agent session was
      // derived with at subagentStart, which this session never opened itself.
      for (const c of deps.contexts.liveFor(i.sid, i.now)) deps.contexts.close(c.id);
      if (i.s.context) deps.contexts.close(i.s.context);
      i.s.ended = true;
      // Allowed calls whose result never came stay reserved in the ledger (they may have run); only the
      // memory goes. Reviews and escalations stay until the Guardian resolves them, within their timeout.
      for (const [k, p] of pending) if (k.startsWith(`${i.sid} `) && p.record.decision.outcome === "allow") pending.delete(k);
      return { decision: "allow" };
    },
  },

  "steps/toolCallRequest": {
    validate: validateToolCallRequest,
    run(i) {
      const { cfg, deps, pending } = inside(this);
      const call = toCall(i.p.payload);
      const ts = new Date(i.now).toISOString();
      const record = decide(deps.policy, call, deps.ledger, {
        id: deps.newId(),
        ts,
        agent: { id: i.s.agentId },
        session: { id: i.sid },
        wire: { protocol: "acs", version: i.s.version, request_id: i.p.request_id, chain_hash: i.entry.entry_hash },
        contexts: deps.contexts,
        ...(cfg.extraContexts ? { extraContexts: cfg.extraContexts(i.sid, i.now) } : {}),
        ...(cfg.factKey ? { factKey: cfg.factKey } : {}),
      });
      i.out.records.push(record);
      const o = record.decision.outcome;
      if (o === "allow" || o === "review" || o === "escalate") pending.set(`${i.sid} ${i.p.request_id}`, { record });
      else {
        // Refused and unplaceable calls never execute; resolve now so nothing stays reserved.
        const resolved = resolveRecord(record, { ts, result: "not-executed" });
        deps.ledger.settle(resolved.id, "not-executed");
        i.out.records[i.out.records.length - 1] = resolved;
      }
      return toResult({ outcome: o, band: record.decision.band, ...(record.decision.approver_role ? { approverRole: record.decision.approver_role } : {}), placements: record.decision.placements, reasons: record.decision.reasons, policy: record.policy }, {
        requestId: i.p.request_id, acsVersion: i.s.version, approvalTimeoutSeconds: cfg.approvalTimeoutSeconds, deferTimeoutMs: cfg.deferTimeoutMs, evaluatorVersion: cfg.evaluatorVersion,
      });
    },
  },

  "steps/toolCallResult": {
    validate: validateToolCallResult,
    run(i) {
      const { deps, pending } = inside(this);
      const ref: string | undefined = i.p.payload.request_id_ref;
      const k = `${i.sid} ${ref}`;
      const p = ref === undefined ? undefined : pending.get(k);
      if (!p) {
        i.out.incidents.push({ kind: "unlinked-result", session: i.sid, request_id: i.p.request_id, ...(ref !== undefined ? { request_id_ref: ref } : {}) });
        return { decision: "deny", reason_codes: ["unlinked_result"], reasoning: "No open decision matches this result." };
      }
      const result: Resolution["result"] = i.p.payload.exit_status === "blocked" ? "not-executed" : "executed";
      try {
        const resolved = resolveRecord(p.record, { ts: new Date(i.now).toISOString(), result, ...(p.approval ? { approval: p.approval } : {}) });
        deps.ledger.settle(resolved.id, result);
        pending.delete(k);
        i.out.records.push(resolved);
        return { decision: "allow" };
      } catch (e) {
        // The agent ran something the decision didn't permit (an ask executed without an approval).
        // The call has happened; what's left is to say so, keep the cap use, and withhold the output.
        i.out.incidents.push({ kind: "execution-without-authority", session: i.sid, request_id: ref!, record: p.record.id, why: (e as Error).message });
        pending.delete(k);
        return { decision: "deny", reason_codes: ["execution_without_authority"], reasoning: "This call executed without the approval its decision required." };
      }
    },
  },

  "steps/subagentStart": {
    validate: validateSubagentStart,
    run(i) {
      const { deps } = inside(this);
      const pl = i.p.payload;
      // The session's own context: the one it opened at sessionStart, or, for a sub-agent's session, the one
      // it was derived with. Never another live context that happens to share the session (a lease's).
      const parent = i.s.context ? deps.contexts.live(i.s.context, i.now) : deps.contexts.liveFor(i.sid, i.now).find((c) => c.subagentType !== undefined);
      const type: string | undefined = pl.subagent_descriptor?.agent_name;
      const agentId: string = pl.subagent_descriptor?.agent_id ?? `${i.s.agentId}/${type ?? "unknown"}`;
      const answer = (decision: "allow" | "deny", reason: string, extra: { context?: string; why?: string; policy_data?: Json; reasoning?: string } = {}) => {
        i.out.spawns.push({ session: i.sid, subagent_session: String(pl.subagent_session_id), agent: agentId, ...(type ? { subagent_type: type } : {}), decision, reason, ...(extra.context ? { context: extra.context } : {}), ...(extra.why ? { why: extra.why } : {}), ...(typeof pl.intent_derivation === "string" ? { intent_derivation: pl.intent_derivation } : {}) });
        return { decision, reason_codes: [reason], ...(extra.reasoning ? { reasoning: extra.reasoning } : {}), ...(extra.policy_data ? { policy_data: extra.policy_data } : {}) };
      };
      if (pl.parent_session_id !== i.sid) return answer("deny", "parent_session_mismatch", { reasoning: "A sub-agent can only be started from its own parent session." });
      if (!parent) return answer("deny", "no_parent_context", { reasoning: "The parent session has no live execution context to derive from." });
      if (!type) return answer("deny", "subagent_type_unknown", { reasoning: "A sub-agent must name its type (subagent_descriptor.agent_name)." });
      const r = deps.contexts.derive(parent.id, { id: deps.newId(), session: pl.subagent_session_id, agent: { id: agentId }, rows: [...parent.rows], subagentType: type }, i.now);
      if (r.ok) return answer("allow", "context_derived", { context: r.context.id, policy_data: { context_id: r.context.id, context_expires_at: new Date(r.context.expiresAt).toISOString() } });
      // An escalation needs a human to widen the pattern in the matrix; there's no per-spawn approval path,
      // so it's denied here and reported as such.
      return answer("deny", r.outcome === "refuse" ? "authority_breach" : "outside_allowed_patterns", { why: r.reason, reasoning: r.reason });
    },
  },
};
