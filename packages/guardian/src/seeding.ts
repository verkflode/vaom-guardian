// Seeded cases (VAOM v5 Readiness Condition 6): known-error asks planted into the review queue of rows
// that enable seeding, to measure whether review catches errors. The rules, held here and in approvals.ts:
// - Only rows that enable seeding, at their rate. The seed set is linted against the policy at startup.
// - A seed is placed by the real evaluator (preview), so the page shows exactly what a real ask would,
//   and preview reserves no cap use and adds nothing to history.
// - A seed never becomes a decision record and never reaches the ACS endpoint, so nothing can execute
//   it whatever the reviewer does. Its outcome is a seed event in the Guardian's store, nothing else.
// - Reviewers are told seeding exists and at what rate (the page says so); never which asks are seeds.
import { randomInt, randomUUID } from "node:crypto";
import { preview, type CapLedger, type ContextRegistry, type DecisionRecord, type Policy } from "@verkflode/vaom-guardian-core";

export interface Seed { id: string; row: string; tool: string; arguments: Record<string, unknown>; copy?: string[]; error: string }
export interface SeedSet { id: string; version: string; disclosure: { statement: string; date: string; ref?: string }; seeds: Seed[] }

export interface Planned { seed: Seed; dueAt: number; session: string; agent: DecisionRecord["request"]["agent"]; args: Record<string, unknown> }

export interface SeederOptions {
  policy: Policy;
  ledger: CapLedger;
  contexts: ContextRegistry;
  factKey?: Uint8Array;
  set: SeedSet;
  /** How often each seed was planted before (from the store), so the least-used goes next. */
  plantedBefore?: ReadonlyMap<string, number>;
  /** Uniform in [0, 1). Injectable for tests; defaults to crypto randomness. */
  random?: () => number;
  /** Delay between the real ask and its seed, uniform in [min, max] ms, so seeds don't arrive in lockstep. */
  delayMs?: [number, number];
}

export class Seeder {
  private readonly o: SeederOptions;
  private readonly used: Map<string, number>;
  private readonly random: () => number;

  constructor(o: SeederOptions) {
    this.o = o;
    this.used = new Map(o.plantedBefore ?? []);
    this.random = o.random ?? (() => randomInt(0, 2 ** 32) / 2 ** 32);
  }

  /** The rate the page discloses for each seeded row. */
  disclosure(): { statement: string; rows: { row: string; title: string; rate: number }[] } {
    const rows = [...new Set(this.o.set.seeds.map((s) => s.row))].map((id) => {
      const row = this.o.policy.rowById.get(id);
      return { row: id, title: row?.title ?? id, rate: row?.oversight?.seeding?.rate ?? 0 };
    });
    return { statement: this.o.set.disclosure.statement, rows };
  }

  /**
   * A real ask was queued: maybe schedule a seed beside it. The row's rate is the share of its queue that
   * is seeded, so each real ask brings a seed with probability rate / (1 - rate).
   */
  consider(real: { record: DecisionRecord; session: string; call: { arguments: unknown } }, now: number): Planned | null {
    const rows = new Set(real.record.decision.placements.map((p) => p.row));
    const candidates = this.o.set.seeds.filter((s) => rows.has(s.row));
    if (candidates.length === 0) return null;
    const rate = this.o.policy.rowById.get(candidates[0]!.row)?.oversight?.seeding;
    if (rate?.enabled !== true || !(rate.rate > 0)) return null;
    if (this.random() >= Math.min(1, rate.rate / (1 - rate.rate))) return null;
    const least = Math.min(...candidates.map((s) => this.used.get(s.id) ?? 0));
    const pool = candidates.filter((s) => (this.used.get(s.id) ?? 0) === least);
    const seed = pool[Math.floor(this.random() * pool.length)]!;
    this.used.set(seed.id, least + 1);
    const [min, max] = this.o.delayMs ?? [5_000, 60_000];
    const args = { ...seed.arguments };
    const from = (real.call.arguments ?? {}) as Record<string, unknown>;
    for (const k of seed.copy ?? []) if (k in from) args[k] = from[k];
    return { seed, dueAt: now + min + Math.floor(this.random() * (max - min + 1)), session: real.session, agent: real.record.request.agent, args };
  }

  /** Place a planned seed as of now. null when a real call like it wouldn't be asked (it would be allowed, refused or unplaceable). */
  place(p: Planned, now: number): { record: DecisionRecord; call: { tool: string; arguments: Record<string, unknown> }; requestId: string } | null {
    const call = { tool: p.seed.tool, arguments: p.args };
    const record = preview(this.o.policy, call, this.o.ledger, {
      id: randomUUID(), ts: new Date(now).toISOString(), agent: p.agent, session: { id: p.session }, contexts: this.o.contexts,
      ...(this.o.factKey ? { factKey: this.o.factKey } : {}),
    });
    if (record.decision.outcome !== "review" && record.decision.outcome !== "escalate") return null;
    return { record, call, requestId: randomUUID() };
  }
}
