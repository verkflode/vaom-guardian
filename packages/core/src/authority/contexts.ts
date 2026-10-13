// Delegated execution contexts: the unit of enforcement. A context binds an agent and (optionally) a task
// to the matrix rows it may act on, until an expiry. Every call is evaluated against the session's live
// contexts; when a context expires or is revoked, the authority it carried no longer exists.
//
// Containment rules:
// - A context covers only delegable rows, or non-delegable rows that allow preparation. Nothing else.
// - Its lifetime is the shortest maxLifetime among the rows that state one; DEFAULT_CONTEXT_LIFETIME only
//   when none does. (A row that states none, such as a non-delegable row covered for preparation, doesn't
//   shorten a context its delegable rows set.)
// - A derived (child) context can only drop rows, lower band ceilings and end sooner. Depth and fan-out are
//   bounded by the parent row's chain limits; a spawn outside the allowed patterns needs escalation.
// - Revocation cascades to every context derived from the revoked one. Ids are never reusable, so a closed,
//   expired or revoked context can't be replayed.
import { durationSeconds } from "../lint/duration.ts";
import type { Band, Policy } from "../eval/types.ts";

/** Lifetime for a context none of whose rows states executionContext.maxLifetime: short, as VAOM asks. */
export const DEFAULT_CONTEXT_LIFETIME = "PT15M";

export interface ContextSpec {
  id: string;
  session: string;
  agent: { id: string; version?: string };
  /** Matrix rows the context may act on. */
  rows: string[];
  /** Capabilities usable in this context (VAOM's scope set). Absent: every capability its rows reach,
   *  meaning their own and those of preparatory rows serving them. */
  scopes?: string[];
  /** The workflow instance it's bound to (invoice id, incident id). Calls with a different `task` fact are unplaceable. */
  task?: string;
  /** Per-row ceilings, for attenuation: a row capped at B can't reach A in this context. */
  bandCeiling?: Record<string, Band>;
}

export interface Context extends ContextSpec {
  openedAt: number;
  expiresAt: number;
  parent?: string;
  /** Remaining sub-agent depth below this context. */
  depthLeft: number;
  /** Sub-agent type this context was derived as, if any. */
  subagentType?: string;
  state: "open" | "closed" | "revoked";
}

export type DeriveResult =
  | { ok: true; context: Context }
  | { ok: false; outcome: "refuse" | "escalate"; reason: string };

const RANK: Record<Band, number> = { A: 0, B: 1, C: 2, "non-delegable": 3 };

export class ContextRegistry {
  private byId = new Map<string, Context>();
  private policy: Policy;
  constructor(policy: Policy) {
    this.policy = policy;
  }

  /** Open a root context at activation. Throws on an invalid spec: nothing is opened. */
  open(spec: ContextSpec, now: number): Context {
    this.checkSpec(spec);
    // The strictest chain among the rows: a row that allows one level of sub-agents isn't stretched to
    // another row's five by sharing a context with it.
    const chains = this.chains(spec.rows);
    const depth = chains.length ? Math.min(...chains.map((c) => c.maxDepth as number)) : 0;
    const ctx: Context = { ...spec, openedAt: now, expiresAt: now + this.lifetimeMs(spec.rows), depthLeft: depth, state: "open" };
    this.byId.set(spec.id, ctx);
    return ctx;
  }

  /**
   * Derive a sub-agent context from a live parent. Attenuation only: rows must be a subset of the parent's,
   * ceilings at least as strict, expiry no later. The parent's row must allow this sub-agent type with these
   * capabilities, within depth and fan-out.
   */
  derive(parentId: string, child: ContextSpec & { subagentType: string; lifetime?: string }, now: number): DeriveResult {
    const parent = this.live(parentId, now);
    if (!parent) return { ok: false, outcome: "refuse", reason: `parent context ${parentId} is not open` };
    if (child.session === parent.session) return { ok: false, outcome: "refuse", reason: "a sub-agent gets its own session" };
    if (this.byId.has(child.id)) return { ok: false, outcome: "refuse", reason: `context id ${child.id} has been used` };
    const extra = child.rows.filter((r) => !parent.rows.includes(r));
    if (extra.length) return { ok: false, outcome: "refuse", reason: `rows ${extra.join(", ")} are not in the parent context` };
    if (parent.depthLeft < 1) return { ok: false, outcome: "refuse", reason: "chain depth exhausted: an authority breach" };

    // Every chain in the parent context governs the spawn, and the strictest limit of each kind applies:
    // the type must be allowed by every row that defines sub-agent patterns, with the capabilities they
    // all allow.
    const chains = this.chains(parent.rows);
    if (chains.length === 0) return { ok: false, outcome: "escalate", reason: "no row in the parent context defines sub-agent patterns" };
    const maxFanOut = Math.min(...chains.map((c) => c.maxFanOut as number));
    const children = [...this.byId.values()].filter((c) => c.parent === parentId && c.state === "open" && c.expiresAt > now);
    if (children.length >= maxFanOut) return { ok: false, outcome: "refuse", reason: `fan-out ${maxFanOut} reached: an authority breach` };
    const patterns = chains.map((c) => (c.allowedSubagents ?? []).find((p: { type: string }) => p.type === child.subagentType));
    if (patterns.some((p) => !p)) return { ok: false, outcome: "escalate", reason: `sub-agent type ${child.subagentType} is outside the allowed patterns` };
    const counts = patterns.map((p) => p.maxCount).filter((n): n is number => n !== undefined);
    const lifetimes = patterns.map((p) => p.maxLifetime).filter((d): d is string => d !== undefined);
    const pattern = {
      capabilities: (patterns[0].capabilities as string[]).filter((cap) => patterns.every((p) => (p.capabilities as string[]).includes(cap))),
      ...(counts.length ? { maxCount: Math.min(...counts) } : {}),
      ...(lifetimes.length ? { maxLifetime: lifetimes.reduce((a, b) => ((durationSeconds(a) ?? 0) <= (durationSeconds(b) ?? 0) ? a : b)) } : {}),
    } as { capabilities: string[]; maxCount?: number; maxLifetime?: string };
    // The child's scope: what it asks for (default: the whole pattern), within the parent's reach.
    const parentReach = new Set(this.reach(parent));
    const scopes = child.scopes ?? [...pattern.capabilities].filter((c: string) => parentReach.has(c));
    const outsidePattern = scopes.filter((c) => !pattern.capabilities.includes(c));
    if (outsidePattern.length) return { ok: false, outcome: "escalate", reason: `capabilities ${outsidePattern.join(", ")} are outside the ${child.subagentType} pattern` };
    const beyondParent = scopes.filter((c) => !parentReach.has(c));
    if (beyondParent.length) return { ok: false, outcome: "refuse", reason: `capabilities ${beyondParent.join(", ")} are beyond the parent context's reach` };
    if (scopes.length === 0) return { ok: false, outcome: "refuse", reason: "the child context would have no capabilities" };
    if (pattern.maxCount !== undefined && children.filter((c) => c.subagentType === child.subagentType).length >= pattern.maxCount) {
      return { ok: false, outcome: "refuse", reason: `at most ${pattern.maxCount} ${child.subagentType} sub-agents` };
    }

    // Ceilings: the child's are the stricter of its own and the parent's, row by row.
    const bandCeiling: Record<string, Band> = {};
    for (const r of child.rows) {
      const p = parent.bandCeiling?.[r], c = child.bandCeiling?.[r];
      const strict = p && c ? (RANK[c] > RANK[p] ? c : p) : (p ?? c);
      if (strict) bandCeiling[r] = strict;
    }
    // The whole child spec, computed scopes included, must hold on its own: scopes reachable from its rows.
    try { this.checkSpec({ ...child, scopes, bandCeiling }); } catch (e) { return { ok: false, outcome: "refuse", reason: (e as Error).message }; }

    const ownLife = child.lifetime ? durationSeconds(child.lifetime) : null;
    const patternLife = pattern.maxLifetime ? durationSeconds(pattern.maxLifetime) : null;
    const expiresAt = Math.min(parent.expiresAt, now + this.lifetimeMs(child.rows), ...(ownLife !== null ? [now + ownLife * 1000] : []), ...(patternLife !== null ? [now + patternLife * 1000] : []));
    const ctx: Context = { ...child, scopes, bandCeiling, openedAt: now, expiresAt, parent: parentId, depthLeft: parent.depthLeft - 1, subagentType: child.subagentType, state: "open" };
    this.byId.set(child.id, ctx);
    return { ok: true, context: ctx };
  }

  close(id: string): void {
    const c = this.byId.get(id);
    if (c && c.state === "open") c.state = "closed";
  }

  /** Revoke a context and everything derived from it. */
  revoke(id: string): void {
    const c = this.byId.get(id);
    if (!c) return;
    c.state = "revoked";
    for (const child of this.byId.values()) if (child.parent === id && child.state !== "revoked") this.revoke(child.id);
  }

  /** A context, if it's open and unexpired at `now`. */
  live(id: string, now: number): Context | undefined {
    const c = this.byId.get(id);
    return c && c.state === "open" && now < c.expiresAt ? c : undefined;
  }

  /** The session's live contexts at `now`. */
  liveFor(session: string, now: number): Context[] {
    return [...this.byId.values()].filter((c) => c.session === session && c.state === "open" && now < c.expiresAt);
  }

  /** Every capability a context can use: its explicit scopes, or its rows' capabilities plus those of
   *  preparatory rows serving them. */
  reach(c: ContextSpec): string[] {
    if (c.scopes) return [...c.scopes];
    const out = new Set<string>();
    for (const row of this.policy.matrix.rows) {
      const a = row.authority;
      if (c.rows.includes(row.id) || (a.kind === "preparatory" && (a.serves as string[]).some((s) => c.rows.includes(s)))) for (const cap of row.capabilities) out.add(cap);
    }
    return [...out];
  }

  /** The sub-agent chains the given rows define. */
  private chains(rows: readonly string[]): any[] {
    return rows.map((r) => this.policy.rowById.get(r)?.authority?.chain).filter(Boolean);
  }

  private lifetimeMs(rows: string[]): number {
    const fallback = durationSeconds(DEFAULT_CONTEXT_LIFETIME)!;
    const stated = rows
      .map((r) => this.policy.rowById.get(r)?.authority?.executionContext?.maxLifetime as string | undefined)
      .filter((d): d is string => d !== undefined)
      .map((d) => durationSeconds(d) ?? fallback);
    return (stated.length ? Math.min(...stated) : fallback) * 1000;
  }

  private checkSpec(spec: ContextSpec): void {
    if (this.byId.has(spec.id)) throw new Error(`context id ${spec.id} has been used; ids are never reusable`);
    if (spec.rows.length === 0) throw new Error("a context covers at least one row");
    for (const r of spec.rows) {
      const row = this.policy.rowById.get(r);
      if (!row) throw new Error(`row ${r} does not exist`);
      const a = row.authority;
      if (a.kind === "preparatory") throw new Error(`row ${r} is preparatory; open the context for a row it serves`);
      if (a.kind === "non-delegable" && a.agentMayPrepare !== true) throw new Error(`row ${r} is non-delegable and doesn't allow preparation`);
    }
    for (const r of Object.keys(spec.bandCeiling ?? {})) if (!spec.rows.includes(r)) throw new Error(`band ceiling for ${r}, which the context doesn't cover`);
    if (spec.scopes) {
      const { scopes: _ownScopes, ...unscoped } = spec;
      const reach = new Set(this.reach(unscoped));
      const beyond = spec.scopes.filter((c) => !reach.has(c));
      if (beyond.length) throw new Error(`scopes ${beyond.join(", ")} aren't reachable from the context's rows`);
    }
  }
}
