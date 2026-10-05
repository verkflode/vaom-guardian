// Replay protection (ACS §10.3): a timestamp outside the skew window is rejected; a request_id seen before
// in the session is rejected (for the whole session, as the spec says); a nonce seen before within the
// window is rejected. Call this only after the signature verified, so forged requests can't burn ids.
import { AcsError, ERR } from "./errors.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class ReplayGuard {
  private ids = new Map<string, Set<string>>();
  private nonces = new Map<string, Map<string, number>>();
  readonly skewMs: number;
  constructor(skewMs: number) {
    this.skewMs = skewMs;
  }

  check(session: string, requestId: string, timestamp: string, now: number, nonce?: string): void {
    if (!UUID.test(requestId)) throw new AcsError(ERR.INVALID_PARAMS, "request_id is not a UUID");
    const t = Date.parse(timestamp);
    if (Number.isNaN(t) || !/\d{4}-\d{2}-\d{2}T/.test(timestamp)) throw new AcsError(ERR.INVALID_PARAMS, "timestamp is not ISO 8601");
    if (Math.abs(now - t) > this.skewMs) throw new AcsError(ERR.TIMESTAMP_OUT_OF_WINDOW, "timestamp outside the skew window", { skew_window_ms: this.skewMs });
    const ids = this.ids.get(session) ?? new Set<string>();
    if (ids.has(requestId)) throw new AcsError(ERR.REPLAY_DETECTED, "request_id already used in this session");
    if (nonce !== undefined) {
      const seen = this.nonces.get(session) ?? new Map<string, number>();
      for (const [n, at] of seen) if (now - at > this.skewMs) seen.delete(n);
      if (seen.has(nonce)) throw new AcsError(ERR.REPLAY_DETECTED, "nonce already used within the window");
      seen.set(nonce, now);
      this.nonces.set(session, seen);
    }
    ids.add(requestId);
    this.ids.set(session, ids);
  }

  forget(session: string): void {
    this.ids.delete(session);
    this.nonces.delete(session);
  }
}
