// Envelope signatures (ACS §10). The signed input is the RFC 8785 (JCS) form of the whole JSON-RPC
// envelope with its `signature` field removed (params.signature on requests, result.signature on
// responses), as UTF-8. Binding the whole envelope (method, session, request id, timestamp) means a
// captured signature can't be lifted into another envelope.
import { canonicalize, hmacSha256, utf8 } from "@verkflode/vaom-guardian-core";
import { fromBase64, toBase64 } from "./base64.ts";

export const HMAC_SHA256 = "HMAC-SHA256";

export interface Signature { algorithm: string; value: string; key_id: string }

/** Any JSON-RPC envelope: a request carries its signature in params, a response in result. */
type Envelope = { params?: object; result?: object };

function signatureOf(part: object | undefined): Signature | undefined {
  return (part as { signature?: Signature } | undefined)?.signature;
}

function withoutSignature(env: Envelope): unknown {
  const copy: Record<string, unknown> = { ...env };
  for (const part of ["params", "result"] as const) {
    const inner = env[part];
    if (inner && typeof inner === "object") {
      const { signature: _sig, ...rest } = inner as { signature?: Signature };
      copy[part] = rest;
    }
  }
  return copy;
}

export function signingInput(env: Envelope): Uint8Array {
  return utf8(canonicalize(withoutSignature(env)));
}

/** Sign a request (signature in params) or a response (signature in result). Returns a new envelope. */
export function sign<E extends Envelope>(env: E, key: Uint8Array, keyId: string): E {
  const signature: Signature = { algorithm: HMAC_SHA256, value: toBase64(hmacSha256(key, signingInput(env))), key_id: keyId };
  if (env.params) return { ...env, params: { ...env.params, signature } };
  if (env.result) return { ...env, result: { ...env.result, signature } };
  throw new Error("an envelope to sign needs params or result");
}

export type Verified = { ok: true } | { ok: false; why: string };

export function verify(env: Envelope, key: Uint8Array): Verified {
  const sig = signatureOf(env.params) ?? signatureOf(env.result);
  if (!sig) return { ok: false, why: "signature missing" };
  if (sig.algorithm !== HMAC_SHA256) return { ok: false, why: `algorithm ${sig.algorithm} not negotiated` };
  const got = fromBase64(sig.value);
  if (!got) return { ok: false, why: "signature value is not canonical Base64" };
  const want = hmacSha256(key, signingInput(env));
  return equal(got, want) ? { ok: true } : { ok: false, why: "signature does not verify" };
}

/** Constant-time comparison, so timing doesn't reveal how much of a forged signature matched. */
function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
