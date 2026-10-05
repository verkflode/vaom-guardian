// HKDF-SHA256 (RFC 5869), and the per-session HMAC key ACS-Core asks for (§10). ACS v0.1 doesn't fix the
// HKDF parameters (#118, #11), so ours are provisional and stated here: SHA-256, empty salt,
// info = "acs/0.1.0 session-key " + session_id, 32-byte output. They change when #118 settles.
import { hmacSha256, utf8 } from "@verkflode/vaom-guardian-core";

export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (length > 255 * 32) throw new RangeError("HKDF output too long");
  const prk = hmacSha256(salt.length ? salt : new Uint8Array(32), ikm);
  const out = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  for (let i = 0, o = 0; o < length; i++) {
    const input = new Uint8Array(t.length + info.length + 1);
    input.set(t); input.set(info, t.length); input[input.length - 1] = i + 1;
    t = hmacSha256(prk, input);
    out.set(t.subarray(0, Math.min(32, length - o)), o);
    o += 32;
  }
  return out;
}

export const SESSION_KEY_INFO_PREFIX = "acs/0.1.0 session-key ";

export function sessionKey(ikm: Uint8Array, sessionId: string): Uint8Array {
  return hkdfSha256(ikm, new Uint8Array(0), utf8(SESSION_KEY_INFO_PREFIX + sessionId), 32);
}

