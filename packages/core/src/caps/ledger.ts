// The cap ledger: cap uses over rolling windows, in memory, with time passed in (the core reads no clock).
//
// Semantics:
// - A reservation counts from the moment it's made: an approval still pending counts as used.
// - Executed reservations keep counting until they age out of the window. Rejected, expired, withdrawn
//   and not-executed ones are released and stop counting.
// - A ledger whose history hasn't been loaded can't say what was used, so every cap reads as breached.
// - Keys are (row, cap, group) with the group in its recorded form (see recordedGroup), so a ledger
//   rebuilt from decision records matches the live one exactly.
//
// The ledger also keeps the decision history that anomaly signals read (see scoring/score.ts): each
// placement's row and facts as the record holds them, and whether it executed. Only executed placements
// count as familiar or typical, so an agent can't make a vendor familiar by asking; every attempt counts
// towards a burst, so asking repeatedly only ever narrows.
import { canonicalize } from "../canonical/jcs.ts";
import { addDecimal } from "../eval/decimal.ts";
import type { CapUsage, FactValue } from "../eval/types.ts";
import type { DecisionRecord, RecordedFact, Resolution } from "../record/record.ts";

interface Entry {
  decision: string;
  row: string;
  cap: string;
  group: string;
  amount?: string;
  at: number;
  released: boolean;
}

interface Seen {
  decision: string;
  row: string;
  /** Each fact in its recorded form, canonicalised for comparison. */
  facts: Record<string, string>;
  /** Facts recorded in clear, for unusual-value signals. */
  values: Record<string, FactValue>;
  at: number;
  executed: boolean;
}

const RELEASING: ReadonlySet<Resolution["result"]> = new Set(["rejected", "expired", "withdrawn", "not-executed"]);

export class CapLedger {
  private entries: Entry[] = [];
  private seen: Seen[] = [];
  private loaded = false;

  /**
   * Rebuild from decision records (any order). Until this has run, every cap reads as breached.
   * Call it with all records young enough to fall inside the longest cap window.
   */
  load(records: Iterable<DecisionRecord>): void {
    this.entries = [];
    this.seen = [];
    for (const r of records) {
      const at = Date.parse(r.request.ts);
      const released = r.resolution ? RELEASING.has(r.resolution.result) : false;
      for (const res of r.reservations) this.entries.push({ decision: r.id, row: res.row, cap: res.cap, group: res.group, ...(res.amount !== undefined ? { amount: res.amount } : {}), at, released });
      this.remember(r, r.resolution?.result === "executed");
    }
    this.loaded = true;
  }

  /** Usage of one row's cap for one group over the window ending at `now`, or null if history isn't loaded. */
  usage(row: string, cap: string, group: string, now: number, windowMs: number): CapUsage | null {
    if (!this.loaded) return null;
    let total = "0", count = 0;
    for (const e of this.entries) {
      if (e.released || e.row !== row || e.cap !== cap || e.group !== group) continue;
      if (e.at <= now - windowMs || e.at > now) continue;
      count++;
      if (e.amount !== undefined) total = addDecimal(total, e.amount);
    }
    return { total, count };
  }

  /** Hold a decision's cap uses. Refuses while unloaded: nothing may be reserved against unknown history. */
  reserve(record: DecisionRecord): void {
    if (!this.loaded) throw new Error("cap ledger not loaded");
    if (this.entries.some((e) => e.decision === record.id)) throw new Error(`decision ${record.id} already holds reservations`);
    const at = Date.parse(record.request.ts);
    for (const res of record.reservations) this.entries.push({ decision: record.id, row: res.row, cap: res.cap, group: res.group, ...(res.amount !== undefined ? { amount: res.amount } : {}), at, released: false });
    this.remember(record, false);
  }

  /** Apply a resolution: release on rejected, expired, withdrawn or not-executed; keep on executed. */
  settle(decisionId: string, result: Resolution["result"]): void {
    if (result === "executed") for (const s of this.seen) if (s.decision === decisionId) s.executed = true;
    if (!RELEASING.has(result)) return;
    for (const e of this.entries) if (e.decision === decisionId) e.released = true;
  }

  /** Undo a decision that never went out (e.g. its record couldn't be persisted, or its response failed):
   *  its cap uses are released and it leaves history, since no record of it will exist to rebuild from. */
  release(decisionId: string): void {
    this.settle(decisionId, "withdrawn");
    this.seen = this.seen.filter((s) => s.decision !== decisionId);
  }

  /** Drop entries older than `horizonMs` before `now`; pass at least the longest cap or anomaly window.
   *  An anomaly signal without a window reads whatever history is left. */
  prune(now: number, horizonMs: number): void {
    this.entries = this.entries.filter((e) => e.at > now - horizonMs);
    this.seen = this.seen.filter((e) => e.at > now - horizonMs);
  }

  /** Did an executed placement on `row` record `fact` as `recorded`? null if history isn't loaded. */
  historySeen(row: string, fact: string, recorded: RecordedFact, now: number, windowMs: number | null): boolean | null {
    if (!this.loaded) return null;
    const want = canonicalize(recorded);
    return this.inWindow(now, windowMs).some((s) => s.executed && s.row === row && s.facts[fact] === want);
  }

  /** Clear values of `fact` from executed placements on `row` whose group facts match. */
  historyValues(row: string, fact: string, group: Record<string, RecordedFact>, now: number, windowMs: number | null): FactValue[] | null {
    if (!this.loaded) return null;
    return this.inWindow(now, windowMs).filter((s) => s.executed && s.row === row && inGroup(s, group) && Object.hasOwn(s.values, fact)).map((s) => s.values[fact]!);
  }

  /** Placements on `row` whose group facts match, whatever their outcome. */
  historyCount(row: string, group: Record<string, RecordedFact>, now: number, windowMs: number): number | null {
    if (!this.loaded) return null;
    return this.inWindow(now, windowMs).filter((s) => s.row === row && inGroup(s, group)).length;
  }

  private inWindow(now: number, windowMs: number | null): Seen[] {
    return this.seen.filter((s) => s.at <= now && (windowMs === null || s.at > now - windowMs));
  }

  private remember(r: DecisionRecord, executed: boolean): void {
    const at = Date.parse(r.request.ts);
    for (const p of r.decision.placements) {
      const facts: Record<string, string> = {}, values: Record<string, FactValue> = {};
      for (const [k, v] of Object.entries(p.facts)) {
        facts[k] = canonicalize(v);
        if ("value" in v) values[k] = v.value;
      }
      this.seen.push({ decision: r.id, row: p.row, facts, values, at, executed });
    }
  }
}

function inGroup(s: Seen, group: Record<string, RecordedFact>): boolean {
  return Object.entries(group).every(([k, v]) => s.facts[k] === canonicalize(v));
}
