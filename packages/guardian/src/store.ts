// Append-only evidence storage: one JSON object per line, fsynced before the Guardian answers.
//   records.jsonl   decision records; a resolution appends the record again (the last line per id wins)
//   chain.jsonl     ACS context entries, with their session
//   events.jsonl    enrollments, approvals, rejections, expiries and incidents
// Nothing is rewritten in place. A torn last line (a crash mid-write) is skipped on load; damage anywhere
// else stops the Guardian from starting, because cap usage can't be trusted from a damaged history.
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync, chmodSync } from "node:fs";
import { join } from "node:path";
import type { ContextEntry } from "@verkflode/vaom-guardian-acs";
import type { DecisionRecord } from "@verkflode/vaom-guardian-core";

export type GuardianEvent = { type: string; id: string; ts: string } & Record<string, unknown>;

export interface ChainLine { session: string; entry: ContextEntry }

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

  private append(name: string, lines: readonly unknown[]): void {
    if (lines.length === 0) return;
    const fd = openSync(this.path(name), "a", 0o600);
    try {
      writeSync(fd, lines.map((l) => JSON.stringify(l) + "\n").join(""));
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

  appendRecords(records: readonly DecisionRecord[]): void { this.append("records.jsonl", records); }
  appendChain(lines: readonly ChainLine[]): void { this.append("chain.jsonl", lines); }
  appendEvents(events: readonly GuardianEvent[]): void { this.append("events.jsonl", events); }

  /** The latest version of every record, in first-seen order. */
  records(): DecisionRecord[] {
    const byId = new Map<string, DecisionRecord>();
    for (const r of this.read<DecisionRecord>("records.jsonl")) byId.set(r.id, r);
    return [...byId.values()];
  }
  chain(): ChainLine[] { return this.read<ChainLine>("chain.jsonl"); }
  events(): GuardianEvent[] { return this.read<GuardianEvent>("events.jsonl"); }
}
