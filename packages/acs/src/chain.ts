// The audit chain (ACS §8.2): entry_hash = lowercase-hex(SHA-256(content_bytes || prev_hash_bytes)), where
// content_bytes is the UTF-8 JCS form of the entry without entry_hash and previous_hash, and prev_hash_bytes
// the raw 32 bytes of previous_hash (empty for the first entry). We always populate request_hash (the
// SHA-256 of the JCS-canonical request params), which the acs-audit profile requires.
import { canonicalize, hex, sha256, utf8 } from "@verkflode/vaom-guardian-core";

export interface ContextEntry {
  entry_id: string;
  step_id: string;
  step_type: string;
  request_hash?: string;
  timestamp?: string;
  previous_hash: string | null;
  entry_hash: string;
}

export type EntryFields = Omit<ContextEntry, "previous_hash" | "entry_hash">;

export function requestHash(params: unknown): string {
  return hex(sha256(utf8(canonicalize(params))));
}

export function entryHash(entry: EntryFields & { previous_hash?: string | null; entry_hash?: string }, previousHash: string | null): string {
  const { entry_hash: _e, previous_hash: _p, ...content } = entry;
  const body = utf8(canonicalize(content));
  const prev = previousHash === null ? new Uint8Array(0) : fromHex(previousHash);
  const input = new Uint8Array(body.length + prev.length);
  input.set(body); input.set(prev, body.length);
  return hex(sha256(input));
}

/** A session's chain, held as its head only: entries go to the caller to persist as they're made. */
export class Chain {
  private current: string | null = null;
  get head(): string | null {
    return this.current;
  }
  /** The entry that would come next, without adding it: a step's entry is committed only once its
   *  response is built, so a failed step leaves the chain where the agent last saw it. */
  next(fields: EntryFields): ContextEntry {
    const previous_hash = this.current;
    return { ...fields, previous_hash, entry_hash: entryHash(fields, previous_hash) };
  }
  /** Add an entry made by `next`. Refuses one made against a head that has since moved. */
  commit(entry: ContextEntry): void {
    if (entry.previous_hash !== this.current) throw new Error("chain entry was made against a different head");
    this.current = entry.entry_hash;
  }
  append(fields: EntryFields): ContextEntry {
    const entry = this.next(fields);
    this.commit(entry);
    return entry;
  }
}

/** Recompute a chain from its entries; true only if every link and hash holds. */
export function verifyChain(entries: readonly ContextEntry[]): boolean {
  let prev: string | null = null;
  for (const e of entries) {
    if (e.previous_hash !== prev) return false;
    if (e.entry_hash !== entryHash(e, prev)) return false;
    prev = e.entry_hash;
  }
  return true;
}

function fromHex(h: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error("previous_hash is not 64 lowercase hex characters");
  return Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
}
