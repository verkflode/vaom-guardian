// Append-only evidence storage: journal.jsonl, one commit per line, fsynced before the Guardian answers.
// A commit holds everything one step writes, in up to three lists:
//   records   decision records; a resolution writes the record again (the last version per id wins)
//   chain     ACS context entries, with their session
//   events    enrollments, approvals, rejections, expiries and incidents
// One line per commit makes a decision's record, chain entry and events one write: a line is either whole
// or torn, never half a decision.
// Nothing is rewritten in place. A torn last line (a crash mid-write) is skipped on load; damage anywhere
// else stops the Guardian from starting, because cap usage can't be trusted from a damaged history.
// Before the first commit after a start, the journal's tail is made whole: a complete last line missing its
// newline gets one, and a torn partial line is cut off. A torn line was never answered on (every commit is
// fsynced before the Guardian answers), so nothing acknowledged is lost, and the next commit can't be glued
// onto it.
// A data directory from 0.1.0 holds records.jsonl, chain.jsonl and events.jsonl, one object per line. They
// are read, before the journal, and never written again.
import { closeSync, existsSync, fsyncSync, ftruncateSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, writeSync, chmodSync } from "node:fs";
import { join } from "node:path";
import type { ContextEntry } from "@verkflode/vaom-guardian-acs";
import type { DecisionRecord } from "@verkflode/vaom-guardian-core";

export type GuardianEvent = { type: string; id: string; ts: string } & Record<string, unknown>;

export interface ChainLine { session: string; entry: ContextEntry }

/** What one step writes, all at once. */
export interface Commit { records?: readonly DecisionRecord[]; chain?: readonly ChainLine[]; events?: readonly GuardianEvent[] }

const JOURNAL = "journal.jsonl";

export class Store {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
  }

  private path(name: string): string {
    return join(this.dir, name);
  }

  private repaired = new Set<string>();

  private repairTail(name: string): void {
    if (this.repaired.has(name)) return;
    this.repaired.add(name);
    const p = this.path(name);
    if (!existsSync(p)) return;
    const fd = openSync(p, "r+");
    try {
      const size = fstatSync(fd).size;
      if (size === 0) return;
      const last = Buffer.alloc(1);
      readSync(fd, last, 0, 1, size - 1);
      if (last[0] === 0x0a) return;
      const text = readFileSync(p);
      const start = text.lastIndexOf(0x0a) + 1;
      let whole = true;
      try { JSON.parse(text.subarray(start).toString("utf8")); } catch { whole = false; }
      if (whole) writeSync(fd, "\n", size);
      else ftruncateSync(fd, start);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  /** Write one step's records, chain entries and events as a single fsynced line. */
  commit(c: Commit): void {
    const line: Commit = {
      ...(c.records?.length ? { records: c.records } : {}),
      ...(c.chain?.length ? { chain: c.chain } : {}),
      ...(c.events?.length ? { events: c.events } : {}),
    };
    if (Object.keys(line).length === 0) return;
    this.repairTail(JOURNAL);
    const fd = openSync(this.path(JOURNAL), "a", 0o600);
    try {
      writeSync(fd, JSON.stringify(line) + "\n");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  private read<T>(name: string): T[] {
    const p = this.path(name);
    if (!existsSync(p)) return [];
    const text = readFileSync(p, "utf8");
    const lines = text.split("\n");
    const out: T[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (line === "") continue;
      try {
        out.push(JSON.parse(line));
      } catch {
        const last = i === lines.length - 1; // no trailing newline: the write was torn
        if (last) break;
        throw new Error(`${name} line ${i + 1} is damaged; refusing to start on a damaged history`);
      }
    }
    return out;
  }

  appendRecords(records: readonly DecisionRecord[]): void { this.commit({ records }); }
  appendEvents(events: readonly GuardianEvent[]): void { this.commit({ events }); }

  /** Every list in write order: a 0.1.0 directory's three files first, then the journal. */
  private all<K extends keyof Commit>(key: K, legacy: string): NonNullable<Commit[K]>[number][] {
    const out: NonNullable<Commit[K]>[number][] = [...this.read<NonNullable<Commit[K]>[number]>(legacy)];
    for (const c of this.read<Commit>(JOURNAL)) {
      const list = c?.[key];
      if (list !== undefined && !Array.isArray(list)) throw new Error(`${JOURNAL} holds a commit whose ${key} is not a list; refusing to start on a damaged history`);
      if (list) out.push(...list);
    }
    return out;
  }

  /** The latest version of every record, in first-seen order. */
  records(): DecisionRecord[] {
    const byId = new Map<string, DecisionRecord>();
    for (const r of this.all("records", "records.jsonl")) byId.set(r.id, r);
    return [...byId.values()];
  }
  chain(): ChainLine[] { return this.all("chain", "chain.jsonl"); }
  events(): GuardianEvent[] { return this.all("events", "events.jsonl"); }
}
