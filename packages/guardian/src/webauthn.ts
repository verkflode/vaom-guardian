// WebAuthn verification (Level 2), for the approval page: one ES256 credential per approver, user
// verification required on every ceremony. Node built-ins only.
//
// What this proves, and what it doesn't: an assertion shows that someone holding the enrolled
// credential approved this exact challenge, with user verification (Touch ID). Attestation statements are
// not checked (platform passkeys mostly send none), so enrollment itself is trusted to be a human act;
// that's why it takes a one-time token from the Guardian's own terminal, and is logged.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { decodeCbor, decodeCborPrefix, type Cbor } from "./cbor.ts";

/** A P-256 public key as JWK. */
export interface Jwk { kty: "EC"; crv: "P-256"; x: string; y: string }

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_AT = 0x40;
const COSE_ES256 = -7;

export const b64url = {
  encode: (b: Uint8Array) => Buffer.from(b).toString("base64url"),
  decode(s: string): Uint8Array {
    if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new WebAuthnError("not base64url");
    const b = new Uint8Array(Buffer.from(s, "base64url"));
    if (Buffer.from(b).toString("base64url") !== s) throw new WebAuthnError("non-canonical base64url");
    return b;
  },
};

export class WebAuthnError extends Error {
  override name = "WebAuthnError";
}

export interface Expect { challenge: string; origin: string; rpId: string }

export interface StoredCredential { id: string; jwk: Jwk; signCount: number }

const sha256 = (b: Uint8Array | string) => new Uint8Array(createHash("sha256").update(b).digest());

function checkClientData(raw: Uint8Array, type: string, e: Expect): void {
  let cd: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try { cd = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); } catch { throw new WebAuthnError("clientDataJSON is not JSON"); }
  if (cd.type !== type) throw new WebAuthnError(`clientData type is not ${type}`);
  if (cd.challenge !== e.challenge) throw new WebAuthnError("challenge mismatch");
  if (cd.origin !== e.origin) throw new WebAuthnError("origin mismatch");
  if (cd.crossOrigin === true) throw new WebAuthnError("cross-origin ceremony");
}

interface AuthData { rpIdHash: Uint8Array; flags: number; signCount: number; credentialId?: Uint8Array; coseKey?: Cbor; aaguid?: Uint8Array }

function parseAuthData(a: Uint8Array): AuthData {
  if (a.length < 37) throw new WebAuthnError("authenticator data too short");
  const flags = a[32]!;
  const signCount = new DataView(a.buffer, a.byteOffset + 33, 4).getUint32(0);
  const out: AuthData = { rpIdHash: a.subarray(0, 32), flags, signCount };
  if (flags & FLAG_AT) {
    if (a.length < 55) throw new WebAuthnError("attested credential data truncated");
    out.aaguid = a.subarray(37, 53);
    const len = (a[53]! << 8) | a[54]!;
    if (55 + len > a.length) throw new WebAuthnError("credential id truncated");
    out.credentialId = a.subarray(55, 55 + len);
    try { [out.coseKey] = decodeCborPrefix(a, 55 + len); } catch (err) { throw new WebAuthnError(`credential key: ${(err as Error).message}`); }
  }
  return out;
}

function checkAuthData(ad: AuthData, rpId: string): void {
  if (!equal(ad.rpIdHash, sha256(rpId))) throw new WebAuthnError("rpIdHash mismatch");
  if (!(ad.flags & FLAG_UP)) throw new WebAuthnError("user not present");
  if (!(ad.flags & FLAG_UV)) throw new WebAuthnError("user not verified");
}

function coseToJwk(k: Cbor | undefined): Jwk {
  if (!(k instanceof Map)) throw new WebAuthnError("credential key is not a COSE map");
  if (k.get(1) !== 2 || k.get(3) !== COSE_ES256 || k.get(-1) !== 1) throw new WebAuthnError("only ES256 (P-256) credentials are accepted");
  const x = k.get(-2), y = k.get(-3);
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) throw new WebAuthnError("malformed P-256 key");
  const jwk: Jwk = { kty: "EC", crv: "P-256", x: b64url.encode(x), y: b64url.encode(y) };
  try { createPublicKey({ key: jwk, format: "jwk" }); } catch { throw new WebAuthnError("P-256 key is not on the curve"); }
  return jwk;
}

export interface Registration { attestationObject: string; clientDataJSON: string }

export function verifyRegistration(r: Registration, e: Expect): StoredCredential & { aaguid: string; fmt: string } {
  checkClientData(b64url.decode(r.clientDataJSON), "webauthn.create", e);
  let att: Cbor;
  try { att = decodeCbor(b64url.decode(r.attestationObject)); } catch (err) { throw new WebAuthnError(`attestationObject: ${(err as Error).message}`); }
  if (!(att instanceof Map) || !(att.get("authData") instanceof Uint8Array) || typeof att.get("fmt") !== "string") throw new WebAuthnError("malformed attestationObject");
  const ad = parseAuthData(att.get("authData") as Uint8Array);
  checkAuthData(ad, e.rpId);
  if (!ad.credentialId || !ad.coseKey) throw new WebAuthnError("no attested credential data");
  return { id: b64url.encode(ad.credentialId), jwk: coseToJwk(ad.coseKey), signCount: ad.signCount, aaguid: Buffer.from(ad.aaguid!).toString("hex"), fmt: att.get("fmt") as string };
}

export interface Assertion { credentialId: string; authenticatorData: string; clientDataJSON: string; signature: string }

/** Verify an assertion against the stored credential. Returns the new signature counter to store. */
export function verifyAssertion(a: Assertion, cred: StoredCredential, e: Expect): number {
  if (a.credentialId !== cred.id) throw new WebAuthnError("assertion is for another credential");
  const clientData = b64url.decode(a.clientDataJSON);
  checkClientData(clientData, "webauthn.get", e);
  const authData = b64url.decode(a.authenticatorData);
  const ad = parseAuthData(authData);
  checkAuthData(ad, e.rpId);
  const signed = new Uint8Array(authData.length + 32);
  signed.set(authData); signed.set(sha256(clientData), authData.length);
  let ok = false;
  try { ok = cryptoVerify("sha256", signed, { key: cred.jwk, format: "jwk", dsaEncoding: "der" }, b64url.decode(a.signature)); } catch { ok = false; }
  if (!ok) throw new WebAuthnError("signature does not verify");
  // Counters: authenticators that always send 0 (synced passkeys) are allowed; any other must increase.
  if ((ad.signCount !== 0 || cred.signCount !== 0) && ad.signCount <= cred.signCount) throw new WebAuthnError("signature counter did not increase: possible cloned credential");
  return ad.signCount;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
