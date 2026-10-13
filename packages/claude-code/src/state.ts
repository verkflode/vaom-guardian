// Per-session shim state. Claude Code starts one shim process per hook call, so whatever must outlive a
// call lives here: which ACS session this Claude Code session speaks as, the shim's view of the chain
// head, which ACS request each tool_use_id was decided under (PreToolUse and PostToolUse share it), and
// which ACS session each of its sub-agents speaks as.
//
// Parallel tool calls run their hooks at the same time, so every read-modify-write of a session's state
// happens under a lock: a directory created with mkdir, which is atomic. A lock is held for one round
// trip to the Guardian, never while waiting for a human.
import { mkdirSync, readFileSync, renameSync, rmSync, statSync, utimesSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";

export interface CallState { request_id: string; tool: string; session: string }

/** An ACS session the shim speaks as: the Claude Code session's own, or one per sub-agent. */
export interface AcsSessionState {
  /** The chain head from the Guardian's last signed answer: the shim's claim on the next request (§8.6). */
  chain_hash: string | null;
  /** Whether handshake/hello has been answered for it. A sub-agent's session negotiates on first use. */
  negotiated: boolean;
}

/** A spawn the Guardian allowed (subagentStart): its ACS session, the agent id it speaks as, the session
 *  that spawned it, and the Agent call that asked for it. */
export interface SpawnState { session: string; agent_type: string; agent_id: string; parent: string; tool_use_id: string }

export interface SessionState {
  format: "vaom-guardian.shim-state/0.2";
  /** The ACS session this Claude Code session speaks as. A fresh one after the Guardian restarts. */
  acs_session: string;
  sessions: Record<string, AcsSessionState>;
  /** tool_use_id -> the request it was decided under; removed when PostToolUse reports it. */
  calls: Record<string, CallState>;
  /** Allowed spawns, oldest first, waiting for Claude Code's SubagentStart. */
  spawns: SpawnState[];
  /** Claude Code agent_id -> the sub-agent's ACS session. */
  agents: Record<string, SpawnState>;
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
/** Lock timing: a lock untouched for staleMs belonged to a process that died; a hook waits at most waitMs
 *  for it; a holder touches it every heartbeatMs. */
export interface LockTiming { staleMs: number; waitMs: number; heartbeatMs: number }
const LOCK: LockTiming = { staleMs: 30_000, waitMs: 10_000, heartbeatMs: 5_000 };

export class StateDir {
  readonly dir: string;
  private readonly lockTiming: LockTiming;
  constructor(dir: string, lockTiming: LockTiming = LOCK) {
    this.dir = dir;
    this.lockTiming = lockTiming;
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
    if (s?.format !== "vaom-guardian.shim-state/0.2") throw new Error("shim state file has an unknown format");
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

  /** Run `fn` holding this session's lock. A lock untouched for longer than staleMs belonged to a process that died. */
  async locked<T>(session: string, fn: () => Promise<T>): Promise<T> {
    const lock = `${this.file(session)}.lock`;
    const { staleMs, waitMs, heartbeatMs } = this.lockTiming;
    const until = Date.now() + waitMs;
    for (;;) {
      try { mkdirSync(lock, { mode: 0o700 }); break; } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        try { if (Date.now() - statSync(lock).mtimeMs > staleMs) { rmSync(lock, { recursive: true, force: true }); continue; } } catch { continue; }
        if (Date.now() > until) throw new Error("timed out waiting for the shim state lock");
        await new Promise((r) => setTimeout(r, 15));
      }
    }
    // Keep the lock fresh while we hold it: one locked section can make several Guardian round trips, and
    // must never look stale to a hook waiting behind it. A holder that dies stops touching it.
    const beat = setInterval(() => { try { const t = new Date(); utimesSync(lock, t, t); } catch { /* gone: nothing to keep */ } }, heartbeatMs);
    try { return await fn(); } finally { clearInterval(beat); rmSync(lock, { recursive: true, force: true }); }
  }
}
