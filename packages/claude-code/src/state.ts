// Per-session shim state. Claude Code starts one shim process per hook call, so whatever must outlive a
// call lives here: which ACS session this Claude Code session speaks as, the shim's view of the chain
// head, and which ACS request each tool_use_id was decided under (PreToolUse and PostToolUse share it).
//
// Parallel tool calls run their hooks at the same time, so every read-modify-write of a session's state
// happens under a lock: a directory created with mkdir, which is atomic. A lock is held for one round
// trip to the Guardian, never while waiting for a human.
import { mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";

export interface CallState { request_id: string; tool: string }

export interface SessionState {
  format: "vaom-guardian.shim-state/0.1";
  /** The ACS session this Claude Code session speaks as. A fresh one after the Guardian restarts. */
  acs_session: string;
  /** The chain head from the Guardian's last signed answer: the shim's claim on the next request (§8.6). */
  chain_hash: string | null;
  /** tool_use_id -> the request it was decided under; removed when PostToolUse reports it. */
  calls: Record<string, CallState>;
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 10_000;

export class StateDir {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
  }

  private file(session: string): string {
    if (!SAFE_ID.test(session)) throw new Error("Claude Code session id has an unexpected shape");
    return join(this.dir, `${session}.json`);
  }

  read(session: string): SessionState | null {
    let raw: string;
    try { raw = readFileSync(this.file(session), "utf8"); } catch { return null; }
    const s = JSON.parse(raw);
    if (s?.format !== "vaom-guardian.shim-state/0.1") throw new Error("shim state file has an unknown format");
    return s as SessionState;
  }

  write(session: string, s: SessionState): void {
    const path = this.file(session);
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(s) + "\n", { mode: 0o600 });
    renameSync(tmp, path);
  }

  remove(session: string): void {
    rmSync(this.file(session), { force: true });
  }

  /** Run `fn` holding this session's lock. A lock older than LOCK_STALE_MS belonged to a process that died. */
  async locked<T>(session: string, fn: () => Promise<T>): Promise<T> {
    const lock = `${this.file(session)}.lock`;
    const until = Date.now() + LOCK_WAIT_MS;
    for (;;) {
      try { mkdirSync(lock, { mode: 0o700 }); break; } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        try { if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) { rmSync(lock, { recursive: true, force: true }); continue; } } catch { continue; }
        if (Date.now() > until) throw new Error("timed out waiting for the shim state lock");
        await new Promise((r) => setTimeout(r, 15));
      }
    }
    try { return await fn(); } finally { rmSync(lock, { recursive: true, force: true }); }
  }
}
