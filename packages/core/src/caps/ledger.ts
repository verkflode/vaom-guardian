// The cap ledger: cap uses over rolling windows, in memory, with time passed in (the core reads no clock).
//
// Semantics:
// - A reservation counts from the moment it's made: an approval still pending counts as used.
// - Executed reservations keep counting until they age out of the window. Rejected, expired, withdrawn
//   and not-executed ones are released and stop counting.
// - A ledger whose history hasn't been loaded can't say what was used, so every cap reads as breached.
// - Keys are (row, cap, group) with the group in its recorded form (see recordedGroup), so a ledger
//   rebuilt from decision records matches the live one exactly.
import { addDecimal } from "../eval/decimal.ts";
import type { CapUsage } from "../eval/types.ts";
import type { DecisionRecord, Resolution } from "../record/record.ts";

interface Entry {
  decision: string;
  row: string;
  cap: string;
  group: string;
  amount?: string;
  at: number;
  released: boolean;
}

const RELEASING: ReadonlySet<Resolution["result"]> = new Set(["rejected", "expired", "withdrawn", "not-executed"]);

export class CapLedger {
  private entries: Entry[] = [];
  private loaded = false;

  /**
   * Rebuild from decision records (any order). Until this has run, every cap reads as breached.
   * Call it with all records young enough to fall inside the longest cap window.
   */
  load(records: Iterable<DecisionRecord>): void {
    this.entries = [];
    for (const r of records) {
      const at = Date.parse(r.request.ts);
      const released = r.resolution ? RELEASING.has(r.resolution.result) : false;
      for (const res of r.reservations) this.entries.push({ decision: r.id, row: res.row, cap: res.cap, group: res.group, ...(res.amount !== undefined ? { amount: res.amount } : {}), at, released });
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
  }

  /** Apply a resolution: release on rejected, expired, withdrawn or not-executed; keep on executed. */
  settle(decisionId: string, result: Resolution["result"]): void {
    if (!RELEASING.has(result)) return;
    for (const e of this.entries) if (e.decision === decisionId) e.released = true;
  }

  /** Undo a reservation whose decision never went out (e.g. its record couldn't be persisted). */
  release(decisionId: string): void {
    this.settle(decisionId, "withdrawn");
  }

  /** Drop entries older than `horizonMs` before `now`; pass at least the longest cap window. */
  prune(now: number, horizonMs: number): void {
    this.entries = this.entries.filter((e) => e.at > now - horizonMs);
  }
}
