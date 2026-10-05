import { describe, expect, it } from "vitest";
import { decodeCbor } from "../src/cbor.ts";
import { verifyAssertion, verifyRegistration } from "../src/webauthn.ts";
import { cbor, SoftAuthenticator } from "./authenticator.ts";

const E = { challenge: "Y2hhbGxlbmdl", origin: "http://localhost:47100", rpId: "localhost" };

describe("registration", () => {
  it("accepts an ES256 credential created with user verification", () => {
    const a = new SoftAuthenticator();
    const c = verifyRegistration(a.create(E), E);
    expect(c.id).toBe(a.credentialId);
    expect(c.jwk).toMatchObject({ kty: "EC", crv: "P-256", x: Buffer.from(a.x).toString("base64url") });
    expect(c.fmt).toBe("none");
  });
  it("rejects a wrong challenge, origin, rp id, ceremony type, or a cross-origin ceremony", () => {
    const a = new SoftAuthenticator();
    expect(() => verifyRegistration(a.create({ ...E, challenge: "b3RoZXI" }), E)).toThrow(/challenge/);
    expect(() => verifyRegistration(a.create({ ...E, origin: "http://evil.example" }), E)).toThrow(/origin/);
    expect(() => verifyRegistration(a.create({ ...E, rpId: "evil.example" }), E)).toThrow(/rpIdHash/);
    expect(() => verifyRegistration(a.create({ ...E, type: "webauthn.get" }), E)).toThrow(/type/);
    expect(() => verifyRegistration(a.create({ ...E, crossOrigin: true }), E)).toThrow(/cross-origin/);
  });
  it("requires user verification, not just presence", () => {
    expect(() => verifyRegistration(new SoftAuthenticator().create({ ...E, flags: 0x41 }), E)).toThrow(/not verified/);
  });
  it("accepts only ES256", () => {
    const a = new SoftAuthenticator();
    a.alg = -257;
    expect(() => verifyRegistration(a.create(E), E)).toThrow(/ES256/);
  });
});

describe("assertions", () => {
  const enrolled = () => { const a = new SoftAuthenticator(); const c = verifyRegistration(a.create(E), E); return { a, cred: { id: c.id, jwk: c.jwk, signCount: c.signCount } }; };
  it("verifies, and returns the new counter", () => {
    const { a, cred } = enrolled();
    expect(verifyAssertion(a.get(E), cred, E)).toBe(1);
  });
  it("rejects a different challenge, a tampered authenticator data or signature, and another key", () => {
    const { a, cred } = enrolled();
    expect(() => verifyAssertion(a.get({ ...E, challenge: "b3RoZXI" }), cred, E)).toThrow(/challenge/);
    const g = a.get(E);
    const ad = Buffer.from(g.authenticatorData, "base64url"); ad[36]! ^= 1;
    expect(() => verifyAssertion({ ...g, authenticatorData: ad.toString("base64url") }, cred, E)).toThrow(/signature/);
    const sig = Buffer.from(g.signature, "base64url"); sig[sig.length - 1]! ^= 1;
    expect(() => verifyAssertion({ ...g, signature: sig.toString("base64url") }, cred, E)).toThrow(/signature/);
    const other = new SoftAuthenticator();
    expect(() => verifyAssertion({ ...other.get(E), credentialId: cred.id }, cred, E)).toThrow(/signature/);
  });
  it("requires user presence and user verification on every assertion", () => {
    const { a, cred } = enrolled();
    expect(() => verifyAssertion(a.get({ ...E, flags: 0x01 }), cred, E)).toThrow(/not verified/);
    expect(() => verifyAssertion(a.get({ ...E, flags: 0x04 }), cred, E)).toThrow(/not present/);
  });
  it("rejects a counter that didn't increase, but allows authenticators that always send 0", () => {
    const { a, cred } = enrolled();
    expect(() => verifyAssertion(a.get(E), { ...cred, signCount: 5 }, E)).toThrow(/counter/);
    a.counter = -1;
    expect(verifyAssertion(a.get(E), cred, E)).toBe(0);
  });
  it("rejects an assertion naming another credential", () => {
    const { a, cred } = enrolled();
    expect(() => verifyAssertion({ ...a.get(E), credentialId: "AAAA" }, cred, E)).toThrow(/another credential/);
  });
});

describe("CBOR", () => {
  it("round-trips what the authenticator encodes", () => {
    expect(decodeCbor(cbor(new Map<any, any>([[1, 2], [-7, "x"], ["b", new Uint8Array([1, 2])]])))).toEqual(new Map<any, any>([[1, 2], [-7, "x"], ["b", new Uint8Array([1, 2])]]));
  });
  it("rejects trailing bytes, indefinite lengths, tags, floats and duplicate keys", () => {
    expect(() => decodeCbor(Uint8Array.from([0x01, 0x02]))).toThrow(/trailing/);
    expect(() => decodeCbor(Uint8Array.from([0x5f, 0xff]))).toThrow(/indefinite/);
    expect(() => decodeCbor(Uint8Array.from([0xc1, 0x01]))).toThrow(/tags/);
    expect(() => decodeCbor(Uint8Array.from([0xf9, 0, 0]))).toThrow(/float/);
    expect(() => decodeCbor(Uint8Array.from([0xa2, 0x01, 0x01, 0x01, 0x02]))).toThrow(/duplicate/);
    expect(() => decodeCbor(Uint8Array.from([0x43, 0x01]))).toThrow(/truncated/);
  });
});
