// Band B and C approvals: the Guardian is the approver of record. A decision that routes to review or
// escalation waits here until a human approves it on the local page with a WebAuthn user-verified
// assertion (Touch ID), rejects it, or it expires. Only an approval widens what the agent may do, and it
// widens exactly one decision: the challenge the authenticator signs commits to that decision.
//
// An approval event keeps everything needed to check it later without trusting the Guardian: the
// challenge's preimage, the assertion, and (in the enrollment event) the public key.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { canonicalize, type DecisionRecord } from "@verkflode/vaom-guardian-core";
import type { AcsEndpoint } from "@verkflode/vaom-guardian-acs";
import type { Planned, Seeder } from "./seeding.ts";
import type { GuardianEvent, Store } from "./store.ts";
import { b64url, verifyAssertion, verifyRegistration, WebAuthnError, type Assertion, type Jwk, type Registration } from "./webauthn.ts";

export type AskStatus = "pending" | "approved" | "rejected" | "expired";

export interface Ask {
  session: string;
  requestId: string;
  record: DecisionRecord;
  /** Shown to the human on the local page; held in memory only (records keep a digest), and dropped once
   *  the ask is decided. */
  call: { tool: string; arguments: unknown };
  createdAt: number;
  expiresAt: number;
  status: AskStatus;
  /** When it was decided or expired. A decided ask is kept for one approval timeout, for the shim's poll and
   *  the page's reveal, then forgotten: the store has the evidence. */
  settledAt?: number;
  /** Set on a planted case. Never sent to the page; its record is never stored and never executes. */
  seed?: { id: string; row: string; error: string; set: { id: string; version: string } };
}

export interface Credential { id: string; label: string; roles: string[]; jwk: Jwk; signCount: number }

interface Challenge { value: string; preimage: Record<string, string>; expiresAt: number }
interface EnrollToken { token: string; label: string; roles: string[]; expiresAt: number; challenge?: string; userId: string }

const CHALLENGE_TTL_MS = 120_000;
const ENROLL_TTL_MS = 10 * 60_000;

export class ApprovalError extends Error {
  override name = "ApprovalError";
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface ApprovalsOptions {
  store: Store;
  endpoint: AcsEndpoint;
  origin: string;
  rpId: string;
  timeoutMs: number;
  /** Roles the matrix defines; enrollment may only grant these. */
  roles: ReadonlySet<string>;
  /** Name the approver (the credential's label) in approval events and records. Only when the matrix
   *  enables reviewer-level metrics: otherwise that's employee monitoring nobody approved. */
  recordApprovers: boolean;
  /** Plants seeded cases on rows that enable seeding. Absent: no seeding. */
  seeder?: Seeder;
  seedSet?: { id: string; version: string };
}

export class Approvals {
  private readonly o: ApprovalsOptions;
  private readonly asks = new Map<string, Ask>();
  private readonly challenges = new Map<string, Challenge>();
  private readonly credentials = new Map<string, Credential>();
  private readonly waiters = new Map<string, Set<(s: AskStatus) => void>>();
  private scheduled: Planned[] = [];
  private enroll: EnrollToken | undefined;

  constructor(o: ApprovalsOptions) {
    this.o = o;
    // Credentials are rebuilt from the event log: enrollments, then counters from later approvals.
    for (const e of o.store.events()) {
      if (e.type === "enrolled") this.credentials.set(e.credential_id as string, { id: e.credential_id as string, label: e.label as string, roles: e.roles as string[], jwk: e.jwk as Jwk, signCount: e.sign_count as number });
      if (e.type === "approval" || (e.type === "seed-outcome" && e.result === "missed")) { const c = this.credentials.get(e.credential_id as string); if (c) c.signCount = e.sign_count as number; }
      if (e.type === "credential-revoked") this.credentials.delete(e.credential_id as string);
    }
  }

  private key(session: string, requestId: string): string {
    return `${session} ${requestId}`;
  }

  private event(type: string, fields: Record<string, unknown>, now: number): GuardianEvent {
    return { type, id: randomUUID(), ts: new Date(now).toISOString(), ...fields };
  }

  private settle(a: Ask, status: AskStatus, now: number): void {
    a.status = status;
    a.settledAt = now;
    a.call = { tool: a.call.tool, arguments: null };
    const k = this.key(a.session, a.requestId);
    for (const w of this.waiters.get(k) ?? []) w(status);
    this.waiters.delete(k);
    if (status !== "approved") this.challenges.delete(k);
  }

  hasCredentials(): boolean {
    return this.credentials.size > 0;
  }

  // ---- asks

  add(record: DecisionRecord, call: Ask["call"], session: string, requestId: string, now: number): Ask {
    const a: Ask = { session, requestId, record, call, createdAt: now, expiresAt: now + this.o.timeoutMs, status: "pending" };
    this.asks.set(this.key(session, requestId), a);
    const planned = this.o.seeder?.consider({ record, session, call }, now);
    if (planned) this.scheduled.push(planned);
    return a;
  }

  /** Plant seeds that are due. Each is placed by the evaluator as of now, exactly as a real call would be. */
  private plantDue(now: number): void {
    if (!this.o.seeder || this.scheduled.length === 0) return;
    const due = this.scheduled.filter((p) => p.dueAt <= now);
    this.scheduled = this.scheduled.filter((p) => p.dueAt > now);
    for (const p of due) {
      const set = this.o.seedSet ?? { id: "", version: "" };
      // Only into a queue that has a real ask waiting: a lone card in a quiet queue would give the seed away.
      if (![...this.asks.values()].some((a) => !a.seed && a.status === "pending" && a.expiresAt > now)) {
        this.o.store.appendEvents([this.event("seed-skipped", { seed: p.seed.id, set, row: p.seed.row, why: "no real ask was waiting when it was due" }, now)]);
        continue;
      }
      const placed = this.o.seeder.place(p, now);
      if (!placed) {
        this.o.store.appendEvents([this.event("seed-skipped", { seed: p.seed.id, set, row: p.seed.row, why: "a call like it wouldn't be asked now" }, now)]);
        continue;
      }
      this.o.store.appendEvents([this.event("seed-planted", { seed: p.seed.id, set, row: p.seed.row, decision: placed.record.id, session: p.session, request_id: placed.requestId }, now)]);
      this.asks.set(this.key(p.session, placed.requestId), {
        session: p.session, requestId: placed.requestId, record: placed.record, call: placed.call, createdAt: now, expiresAt: now + this.o.timeoutMs, status: "pending",
        seed: { id: p.seed.id, row: p.seed.row, error: p.seed.error, set },
      });
    }
  }

  private seedOutcome(a: Ask, result: "detected" | "missed" | "expired", now: number, extra: Record<string, unknown> = {}): GuardianEvent {
    return this.event("seed-outcome", { seed: a.seed!.id, set: a.seed!.set, row: a.seed!.row, decision: a.record.id, session: a.session, request_id: a.requestId, result, latency_ms: now - a.createdAt, ...extra }, now);
  }

  get(session: string, requestId: string): Ask | undefined {
    return this.asks.get(this.key(session, requestId));
  }

  pending(now: number): Ask[] {
    this.expire(now);
    return [...this.asks.values()].filter((a) => a.status === "pending");
  }

  /** Issue a single-use challenge committing to this decision. */
  challenge(session: string, requestId: string, now: number): { challenge: string; rpId: string; allowCredentials: string[]; approverRole: string } {
    const a = this.live(session, requestId, now);
    const role = a.record.decision.approver_role!;
    const allow = [...this.credentials.values()].filter((c) => c.roles.includes(role)).map((c) => c.id);
    if (allow.length === 0) throw new ApprovalError(403, `no enrolled credential holds the role ${role}`);
    const preimage = { purpose: "vaom-guardian approval", decision: a.record.id, session, request_id: requestId, approver_role: role, params_digest: a.record.request.action.params_digest, nonce: b64url.encode(randomBytes(16)), issued_at: new Date(now).toISOString() };
    const value = b64url.encode(new Uint8Array(createHash("sha256").update(canonicalize(preimage)).digest()));
    this.challenges.set(this.key(session, requestId), { value, preimage, expiresAt: now + CHALLENGE_TTL_MS });
    return { challenge: value, rpId: this.o.rpId, allowCredentials: allow, approverRole: role };
  }

  /** Verify a Touch ID assertion over the issued challenge and approve. Returns the event to persist first. */
  approve(session: string, requestId: string, assertion: Assertion, now: number): GuardianEvent {
    const a = this.live(session, requestId, now);
    const k = this.key(session, requestId);
    const ch = this.challenges.get(k);
    this.challenges.delete(k); // single use, whatever happens next
    if (!ch || ch.expiresAt <= now) throw new ApprovalError(409, "no live challenge for this approval; request a new one");
    // A revocation may have been appended by the CLI while this Guardian runs: read it from the store, so
    // revoking takes effect without a restart. (Each append is one write in append mode, so lines from the
    // two processes don't interleave.)
    for (const e of this.o.store.events()) if (e.type === "credential-revoked") this.credentials.delete(e.credential_id as string);
    const cred = this.credentials.get(assertion?.credentialId);
    if (!cred) throw new ApprovalError(403, "unknown or revoked credential");
    const role = a.record.decision.approver_role!;
    if (!cred.roles.includes(role)) throw new ApprovalError(403, `credential ${cred.label} doesn't hold the role ${role}`);
    let signCount: number;
    try { signCount = verifyAssertion(assertion, cred, { challenge: ch.value, origin: this.o.origin, rpId: this.o.rpId }); } catch (e) {
      if (e instanceof WebAuthnError) throw new ApprovalError(403, `assertion rejected: ${e.message}`);
      throw e;
    }
    if (a.seed) {
      // A planted case: approving it is a miss. Nothing executes; there's no decision to resolve.
      const ev = this.seedOutcome(a, "missed", now, {
        approver_role: role, ...(this.o.recordApprovers ? { approver_id: cred.label } : {}), credential_id: cred.id,
        challenge_preimage: ch.preimage, assertion: { authenticator_data: assertion.authenticatorData, client_data_json: assertion.clientDataJSON, signature: assertion.signature },
        sign_count: signCount,
      });
      this.o.store.appendEvents([ev]);
      cred.signCount = signCount;
      this.settle(a, "approved", now);
      return ev;
    }
    const ev = this.event("approval", {
      decision: a.record.id, session, request_id: requestId, approver_role: role, ...(this.o.recordApprovers ? { approver_id: cred.label } : {}), credential_id: cred.id,
      challenge_preimage: ch.preimage, assertion: { authenticator_data: assertion.authenticatorData, client_data_json: assertion.clientDataJSON, signature: assertion.signature },
      sign_count: signCount, latency_ms: now - a.createdAt,
    }, now);
    this.o.store.appendEvents([ev]);
    cred.signCount = signCount;
    this.o.endpoint.approve(session, requestId, { approver_role: role, ...(this.o.recordApprovers ? { approver_id: cred.label } : {}), record: ev.id, latency_ms: now - a.createdAt });
    this.settle(a, "approved", now);
    return ev;
  }

  /** Reject. Narrowing needs no credential: anyone at the page may say no, and it's logged as such.
   *  Returns the known error when the ask was a planted case, for the page to show after the decision. */
  reject(session: string, requestId: string, now: number): { seededError?: string } {
    const a = this.live(session, requestId, now);
    if (a.seed) {
      this.o.store.appendEvents([this.seedOutcome(a, "detected", now, { authenticated: false })]);
      this.settle(a, "rejected", now);
      return { seededError: a.seed.error };
    }
    const resolved = this.o.endpoint.close(session, requestId, "rejected", new Date(now).toISOString());
    this.o.store.commit({ records: [resolved], events: [this.event("rejection", { decision: a.record.id, session, request_id: requestId, authenticated: false }, now)] });
    this.settle(a, "rejected", now);
    return {};
  }

  /** The known error of a planted case that has been decided, for the page to show afterwards. */
  revealed(session: string, requestId: string): string | undefined {
    const a = this.get(session, requestId);
    return a?.seed && a.status !== "pending" ? a.seed.error : undefined;
  }

  /** The seeding disclosure the page shows on every visit, or null when nothing is seeded. */
  seeding(): ReturnType<Seeder["disclosure"]> | null {
    return this.o.seeder ? this.o.seeder.disclosure() : null;
  }

  /** Expire pending asks past their timeout: the ACS timeout_disposition is deny. */
  expire(now: number): void {
    this.plantDue(now);
    for (const [k, a] of this.asks) if (a.settledAt !== undefined && now - a.settledAt >= this.o.timeoutMs) this.asks.delete(k);
    for (const a of this.asks.values()) {
      if (a.status !== "pending" || a.expiresAt > now) continue;
      if (a.seed) {
        this.o.store.appendEvents([this.seedOutcome(a, "expired", now)]);
        this.settle(a, "expired", now);
        continue;
      }
      const resolved = this.o.endpoint.close(a.session, a.requestId, "expired", new Date(now).toISOString());
      this.o.store.commit({ records: [resolved], events: [this.event("expiry", { decision: a.record.id, session: a.session, request_id: a.requestId }, now)] });
      this.settle(a, "expired", now);
    }
  }

  /** Resolve when the ask leaves pending, or after `ms` with its current status. */
  wait(session: string, requestId: string, ms: number): Promise<AskStatus | undefined> {
    const a = this.get(session, requestId);
    if (!a || a.status !== "pending") return Promise.resolve(a?.status);
    const k = this.key(session, requestId);
    return new Promise((resolve) => {
      const done = (s: AskStatus) => { clearTimeout(t); resolve(s); };
      const t = setTimeout(() => { this.waiters.get(k)?.delete(done); resolve(a.status); }, Math.min(ms, Math.max(0, a.expiresAt - Date.now()) + 50));
      const set = this.waiters.get(k) ?? new Set();
      set.add(done);
      this.waiters.set(k, set);
    });
  }

  private live(session: string, requestId: string, now: number): Ask {
    this.expire(now);
    const a = this.get(session, requestId);
    if (!a) throw new ApprovalError(404, "no such approval request");
    if (a.status !== "pending") throw new ApprovalError(409, `already ${a.status}`);
    return a;
  }

  // ---- enrollment

  /** Open enrollment for one credential. The token is shown only on the Guardian's terminal. */
  openEnrollment(label: string, roles: string[], now: number): string {
    const unknown = roles.filter((r) => !this.o.roles.has(r));
    if (unknown.length) throw new Error(`roles not in the matrix: ${unknown.join(", ")}`);
    if (roles.length === 0) throw new Error("enrollment needs at least one role");
    const token = b64url.encode(randomBytes(24));
    this.enroll = { token, label, roles, expiresAt: now + ENROLL_TTL_MS, userId: b64url.encode(randomBytes(16)) };
    return token;
  }

  enrollmentOptions(token: string, now: number): Record<string, unknown> {
    const e = this.enrollment(token, now);
    e.challenge = b64url.encode(randomBytes(32));
    return {
      challenge: e.challenge, rp: { id: this.o.rpId, name: "VAOM Guardian" }, user: { id: e.userId, name: e.label, displayName: e.label },
      roles: e.roles, excludeCredentials: [...this.credentials.keys()],
    };
  }

  completeEnrollment(token: string, reg: Registration, now: number): GuardianEvent {
    const e = this.enrollment(token, now);
    const challenge = e.challenge;
    this.enroll = undefined; // single use, whatever happens next
    if (!challenge) throw new ApprovalError(409, "enrollment options were not requested");
    let c: ReturnType<typeof verifyRegistration>;
    try { c = verifyRegistration(reg, { challenge, origin: this.o.origin, rpId: this.o.rpId }); } catch (err) {
      if (err instanceof WebAuthnError) throw new ApprovalError(403, `registration rejected: ${err.message}`);
      throw err;
    }
    if (this.credentials.has(c.id)) throw new ApprovalError(409, "credential already enrolled");
    const ev = this.event("enrolled", { credential_id: c.id, label: e.label, roles: e.roles, jwk: c.jwk, sign_count: c.signCount, aaguid: c.aaguid, attestation_format: c.fmt, attestation_verified: false }, now);
    this.o.store.appendEvents([ev]);
    this.credentials.set(c.id, { id: c.id, label: e.label, roles: e.roles, jwk: c.jwk, signCount: c.signCount });
    return ev;
  }

  private enrollment(token: string, now: number): EnrollToken {
    const e = this.enroll;
    if (!e || e.expiresAt <= now || !safeEqual(token, e.token)) throw new ApprovalError(403, "enrollment is not open, or the token is wrong or expired");
    return e;
  }
}

function safeEqual(a: unknown, b: string): boolean {
  if (typeof a !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
