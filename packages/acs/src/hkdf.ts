// HKDF-SHA256 (RFC 5869), and the per-session HMAC key ACS-Core asks for (§10), with the parameters ACS
// settled in #118 (merged in #272, after the v0.1.4 tag): SHA-256, no salt, info = the UTF-8 bytes of
// metadata.session_id exactly as the request carries it, 32-byte output, applied to the secret key_id names.
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

export function sessionKey(ikm: Uint8Array, sessionId: string): Uint8Array {
  return hkdfSha256(ikm, new Uint8Array(0), utf8(sessionId), 32);
}

