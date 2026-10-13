// Delegation leases, for continuous agents (VAOM Pattern 5, and guardians themselves).
//
// A lease is standing but short observation authority: read and alert only, never execution. It lapses
// unless renewed, and renews only while the agent's health holds. To act, the agent obtains a response
// context for one intervention, derived from an active lease, bound to the alert, expiring in minutes.
//
// - Renewal keeps or narrows the observation scopes; it never widens them.
// - A failed renewal withdraws response authority at once; observation continues until the lease ends.
// - At the maximum lifetime, response authority needs re-attestation by every accountable role (or that
//   role's deputy). Without it the lease degrades to observe-only: response authority is never silently
//   extended, and observation doesn't lapse either (a lapsed lease would blind the monitor). Observe-only
//   renewals continue while health holds.
// - Revoking a lease revokes every response context derived from it.
import type { LiveContext, Policy } from "../eval/types.ts";
import { durationSeconds } from "../lint/duration.ts";
import type { Context, ContextRegistry } from "./contexts.ts";

export interface Health {
  agentVersion: string;
  policyVersion: string;
  breakerOpen: boolean;
  verificationCurrent: boolean;
  heartbeat: boolean;
}

export interface Lease {
  id: string;
  row: string;
  agent: { id: string; version: string };
  policyVersion: string;
  scopes: string[];
  grantedAt: number;
  expiresAt: number;
  /** After this, response authority needs re-attestation; observation continues as observe-only. */
  attestUntil: number;
  /** active: may obtain response contexts. observe-only: may observe, never act. */
  status: "active" | "observe-only" | "revoked";
  responseContexts: string[];
}

export type Result<T> = { ok: true; value: T } | { ok: false; reason: string };

export class LeaseRegistry {
  private byId = new Map<string, Lease>();
  private policy: Policy;
  private contexts: ContextRegistry;
  constructor(policy: Policy, contexts: ContextRegistry) {
    this.policy = policy;
    this.contexts = contexts;
  }

  grant(spec: { id: string; row: string; agent: { id: string; version: string }; scopes?: string[] }, now: number): Lease {
    if (this.byId.has(spec.id)) throw new Error(`lease id ${spec.id} has been used`);
    const lease = this.leaseDef(spec.row);
    const allowed: string[] = lease.observationCapabilities;
    const scopes = spec.scopes ?? allowed;
    const extra = scopes.filter((s) => !allowed.includes(s));
    if (extra.length) throw new Error(`scopes ${extra.join(", ")} are not observation capabilities of row ${spec.row}`);
    const l: Lease = {
      id: spec.id, row: spec.row, agent: spec.agent, policyVersion: this.policy.matrix.version, scopes: [...scopes],
      grantedAt: now, expiresAt: now + this.ms(lease.lifetime), attestUntil: now + this.ms(lease.maxLifetime), status: "active", responseContexts: [],
    };
    this.byId.set(spec.id, l);
    return l;
  }

  /**
   * Renew observation, if the agent's health holds. `narrowTo` may drop scopes, never add them. A failed
   * renewal withdraws response authority; observation continues until the current lease runs out. Past
   * the maximum lifetime without re-attestation, renewal succeeds as observe-only.
   */
  renew(id: string, health: Health, now: number, narrowTo?: string[]): Result<Lease> {
    const l = this.byId.get(id);
    if (!l || l.status === "revoked") return { ok: false, reason: "no such lease, or revoked" };
    if (now >= l.expiresAt) return { ok: false, reason: "lease has run out; grant a new one" };
    const failures = [
      health.agentVersion !== l.agent.version && "agent version changed since the grant",
      health.policyVersion !== l.policyVersion && "policy version changed since the grant",
      health.breakerOpen && "a circuit breaker is open",
      !health.verificationCurrent && "boundary verification is not current",
      !health.heartbeat && "no guardian heartbeat",
    ].filter(Boolean) as string[];
    if (failures.length) { this.withdraw(l, now); return { ok: false, reason: failures.join("; ") }; }
    if (now >= l.attestUntil) this.withdraw(l, now); // degrade, and keep observing
    if (narrowTo) {
      const extra = narrowTo.filter((s) => !l.scopes.includes(s));
      if (extra.length) return { ok: false, reason: `renewal can't widen scopes (${extra.join(", ")})` };
      l.scopes = [...narrowTo];
    }
    l.expiresAt = now + this.ms(this.leaseDef(l.row).lifetime);
    return { ok: true, value: l };
  }

  /**
   * Human re-attestation: every accountable role, or that role's deputy, must sign. Restores response
   * authority and starts a new maximum lifetime. (Re-attestation is itself a reviewed decision; the
   * approval records are referenced here.)
   */
  reattest(id: string, approvals: { role: string; record: string }[], now: number): Result<Lease> {
    const l = this.byId.get(id);
    if (!l || l.status === "revoked") return { ok: false, reason: "no such lease, or revoked" };
    if (now >= l.expiresAt) return { ok: false, reason: "lease has run out; grant a new one" };
    const acc = this.policy.rowById.get(l.row).accountability;
    const required: [string, string | undefined][] = acc.form === "single" ? [[acc.role, acc.deputy]] : acc.owners.map((o: { role: string; deputy?: string }) => [o.role, o.deputy]);
    const signed = new Set(approvals.filter((a) => a.record).map((a) => a.role));
    const missing = required.filter(([role, deputy]) => !signed.has(role) && !(deputy && signed.has(deputy))).map(([role]) => role);
    if (missing.length) return { ok: false, reason: `re-attestation missing from ${missing.join(", ")} (or their deputies)` };
    const def = this.leaseDef(l.row);
    l.status = "active";
    l.attestUntil = now + this.ms(def.maxLifetime);
    l.expiresAt = now + this.ms(def.lifetime);
    return { ok: true, value: l };
  }

  /** A response context for one intervention, bound to the alert, derived from an active lease. */
  respond(id: string, spec: { contextId: string; session: string; alert: string }, now: number): Result<Context> {
    const l = this.byId.get(id);
    if (!l || l.status === "revoked") return { ok: false, reason: "no such lease, or revoked" };
    if (now >= l.expiresAt) return { ok: false, reason: "lease has run out" };
    if (l.status !== "active") return { ok: false, reason: "lease is observe-only: no response authority" };
    if (now >= l.attestUntil) { this.withdraw(l, now); return { ok: false, reason: "maximum lifetime reached without re-attestation; degraded to observe-only" }; }
    const def = this.leaseDef(l.row);
    let ctx: Context;
    try {
      ctx = this.contexts.open({ id: spec.contextId, session: spec.session, agent: l.agent, rows: [l.row], task: spec.alert }, now);
    } catch (e) {
      return { ok: false, reason: (e as Error).message };
    }
    // A response context ends with whichever comes first: its own short lifetime, the lease, or the
    // attestation deadline (response authority never outlives it).
    ctx.expiresAt = Math.min(ctx.expiresAt, now + this.ms(def.responseContextLifetime), l.expiresAt, l.attestUntil);
    l.responseContexts.push(ctx.id);
    return { ok: true, value: ctx };
  }

  /** Revoke the lease and every response context derived from it (a tripped circuit breaker does this). */
  revoke(id: string): void {
    const l = this.byId.get(id);
    if (!l) return;
    l.status = "revoked";
    for (const c of l.responseContexts) this.contexts.revoke(c);
  }

  get(id: string): Lease | undefined {
    return this.byId.get(id);
  }

  /** The lease's observation context for the evaluator, while it may observe: its scopes, preparatory
   *  capabilities only (the evaluator enforces that), never a decision. */
  observation(id: string, now: number): LiveContext | undefined {
    const l = this.byId.get(id);
    if (!l || !this.mayObserve(id, now)) return undefined;
    return { id: `lease:${l.id}`, rows: [l.row], scopes: [...l.scopes], observation: true };
  }

  /** Observation is allowed while the lease is unexpired and not revoked, observe-only included. */
  mayObserve(id: string, now: number): boolean {
    const l = this.byId.get(id);
    return !!l && l.status !== "revoked" && now < l.expiresAt;
  }

  private withdraw(l: Lease, _now: number): void {
    if (l.status === "active") l.status = "observe-only";
    for (const c of l.responseContexts) this.contexts.revoke(c);
  }

  private leaseDef(row: string) {
    const lease = this.policy.rowById.get(row)?.authority?.lease;
    if (!lease) throw new Error(`row ${row} defines no lease`);
    return lease;
  }

  private ms(iso: string): number {
    const s = durationSeconds(iso);
    if (s === null) throw new Error(`invalid duration ${iso}`);
    return s * 1000;
  }
}
