// Standard Base64 (RFC 4648, with padding), written out so the adapter needs no host global.
const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!, b = bytes[i + 1], c = bytes[i + 2];
    out += A[a >> 2]! + A[((a & 3) << 4) | ((b ?? 0) >> 4)]!;
    out += b === undefined ? "=" : A[((b & 15) << 2) | ((c ?? 0) >> 6)]!;
    out += c === undefined ? "=" : A[c & 63]!;
  }
  return out;
}

/** Decode strict Base64; returns null for anything malformed (wrong length, bad characters, bad padding). */
export function fromBase64(s: string): Uint8Array | null {
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const pad = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const n = [0, 1, 2, 3].map((k) => (s[i + k] === "=" ? 0 : A.indexOf(s[i + k]!)));
    const v = (n[0]! << 18) | (n[1]! << 12) | (n[2]! << 6) | n[3]!;
    if (o < out.length) out[o++] = (v >> 16) & 255;
    if (o < out.length) out[o++] = (v >> 8) & 255;
    if (o < out.length) out[o++] = v & 255;
  }
  return toBase64(out) === s ? out : null; // rejects non-canonical encodings
}
