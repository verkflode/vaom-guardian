import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/canonical/jcs.ts";
import { hex, hmacSha256, sha256, utf8 } from "../src/crypto/sha256.ts";

describe("SHA-256", () => {
  it("matches the FIPS 180-4 vectors", () => {
    expect(hex(sha256(utf8("")))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(hex(sha256(utf8("abc")))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(hex(sha256(utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  });
  it("matches node:crypto at every length around the padding boundaries", () => {
    for (let n = 0; n <= 200; n++) {
      const data = Uint8Array.from({ length: n }, (_, i) => (i * 31 + n) & 0xff);
      expect(hex(sha256(data)), `length ${n}`).toBe(createHash("sha256").update(data).digest("hex"));
    }
  });
});

describe("HMAC-SHA256", () => {
  it("matches the RFC 4231 vectors", () => {
    expect(hex(hmacSha256(new Uint8Array(20).fill(0x0b), utf8("Hi There")))).toBe("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    expect(hex(hmacSha256(utf8("Jefe"), utf8("what do ya want for nothing?")))).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    // Test case 6: a key longer than the block size is hashed first.
    expect(hex(hmacSha256(new Uint8Array(131).fill(0xaa), utf8("Test Using Larger Than Block-Size Key - Hash Key First")))).toBe("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
  });
  it("matches node:crypto for assorted keys and messages", () => {
    for (const keyLen of [0, 1, 32, 63, 64, 65, 200]) {
      for (const msgLen of [0, 1, 55, 56, 64, 300]) {
        const key = Uint8Array.from({ length: keyLen }, (_, i) => (i * 7 + 3) & 0xff);
        const msg = Uint8Array.from({ length: msgLen }, (_, i) => (i * 13 + 5) & 0xff);
        expect(hex(hmacSha256(key, msg)), `key ${keyLen}, msg ${msgLen}`).toBe(createHmac("sha256", key).update(msg).digest("hex"));
      }
    }
  });
});

describe("UTF-8", () => {
  it("matches TextEncoder, including astral characters and lone surrogates", () => {
    for (const str of ["", "abc", "é€😀", "\ud800", "x\udc00y", "\ud83d\ude00\ud83d", "\u0000\u007f\u0080\u07ff\u0800\uffff"]) {
      expect(Array.from(utf8(str)), JSON.stringify(str)).toEqual(Array.from(new TextEncoder().encode(str)));
    }
  });
});

describe("JCS (RFC 8785)", () => {
  it("sorts keys and drops insignificant whitespace", () => {
    expect(canonicalize({ b: 2, a: 1, c: { z: true, y: null } })).toBe('{"a":1,"b":2,"c":{"y":null,"z":true}}');
  });
  it("sorts by UTF-16 code units", () => {
    expect(canonicalize({ "\u20ac": 1, "\r": 2, "1": 3, "\u{1f600}": 4, a: 5 })).toBe('{"\\r":2,"1":3,"a":5,"\u20ac":1,"\u{1f600}":4}');
  });
  it("serializes numbers the ES6 way", () => {
    expect(canonicalize([0, -0, 1, -1.5, 1e21, 1e-7, 0.1, 123456789012345680000])).toBe("[0,0,1,-1.5,1e+21,1e-7,0.1,123456789012345680000]");
  });
  it("escapes strings as JSON does", () => {
    expect(canonicalize("é\n\"\u0001")).toBe('"é\\n\\"\\u0001"');
  });
  it("refuses values outside JSON", () => {
    for (const v of [Number.NaN, Number.POSITIVE_INFINITY, undefined, () => 1, BigInt(1), { a: undefined }]) expect(() => canonicalize(v)).toThrow();
  });
});
