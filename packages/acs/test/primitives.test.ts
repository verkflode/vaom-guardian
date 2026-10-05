import { hkdfSync, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalize } from "@verkflode/vaom-guardian-core";
import { type Signature, Chain, entryHash, fromBase64, hkdfSha256, ReplayGuard, requestHash, sessionKey, sign, signingInput, toBase64, verify, verifyChain, AcsError, ERR } from "../src/index.ts";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const bytes = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

describe("HKDF-SHA256 (RFC 5869)", () => {
  it("matches test case 1", () => {
    expect(hex(hkdfSha256(bytes("0b".repeat(22)), bytes("000102030405060708090a0b0c"), bytes("f0f1f2f3f4f5f6f7f8f9"), 42)))
      .toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  });
  it("matches test case 3 (empty salt and info)", () => {
    expect(hex(hkdfSha256(bytes("0b".repeat(22)), new Uint8Array(0), new Uint8Array(0), 42)))
      .toBe("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
  });
  it("matches node:crypto, and the session key uses the stated parameters", () => {
    const ikm = bytes("11".repeat(32)), sid = "6f1c3c1e-0d2b-4b8e-9a5f-1b2c3d4e5f60";
    const node = new Uint8Array(hkdfSync("sha256", ikm, new Uint8Array(0), Buffer.from(`acs/0.1.0 session-key ${sid}`, "utf8"), 32));
    expect(hex(sessionKey(ikm, sid))).toBe(hex(node));
  });
});

describe("Base64", () => {
  it("round-trips every length and matches Buffer", () => {
    for (let n = 0; n < 70; n++) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
      const s = toBase64(b);
      expect(s).toBe(Buffer.from(b).toString("base64"));
      expect(hex(fromBase64(s)!)).toBe(hex(b));
    }
  });
  it("rejects malformed and non-canonical input", () => {
    for (const s of ["abc", "ab=c", "a===", "ab$=", "QQ==QQ==", "QR=="]) expect(fromBase64(s), s).toBeNull();
  });
});

const key = bytes("22".repeat(32));
const request = (): { jsonrpc: string; id: number; method: string; params: { acs_version: string; request_id: string; timestamp: string; metadata: { agent_id: string; session_id: string }; payload: { tool: { name: string }; arguments: Record<string, unknown> }; signature?: Signature } } => ({ jsonrpc: "2.0", id: 7, method: "steps/toolCallRequest", params: { acs_version: "0.1.0", request_id: "6f1c3c1e-0d2b-4b8e-9a5f-1b2c3d4e5f60", timestamp: "2026-10-05T10:00:00Z", metadata: { agent_id: "a", session_id: "6f1c3c1e-0d2b-4b8e-9a5f-1b2c3d4e5f61" }, payload: { tool: { name: "Bash" }, arguments: {} } } });

describe("signatures (§10)", () => {
  it("signs the whole envelope minus the signature, as HMAC-SHA256 in Base64", () => {
    const signed = sign(request(), key, "k1");
    expect(signed.params.signature).toMatchObject({ algorithm: "HMAC-SHA256", key_id: "k1" });
    const expected = createHmac("sha256", key).update(canonicalize(request()), "utf8").digest("base64");
    expect(signed.params.signature!.value).toBe(expected);
    expect(verify(signed, key)).toEqual({ ok: true });
  });
  it("binds method, session, request id and payload: changing any breaks it", () => {
    const signed = sign(request(), key, "k1");
    const tamper = [
      (e: ReturnType<typeof request>) => { e.method = "steps/toolCallResult"; },
      (e: ReturnType<typeof request>) => { e.params.metadata.session_id = "6f1c3c1e-0d2b-4b8e-9a5f-1b2c3d4e5f62"; },
      (e: ReturnType<typeof request>) => { e.params.request_id = "6f1c3c1e-0d2b-4b8e-9a5f-1b2c3d4e5f63"; },
      (e: ReturnType<typeof request>) => { (e.params.payload.tool as { name: string }).name = "Write"; },
      (e: ReturnType<typeof request>) => { e.id = 8; },
    ];
    for (const t of tamper) { const e = structuredClone(signed); t(e); expect(verify(e, key).ok).toBe(false); }
  });
  it("rejects a missing signature, another algorithm, bad Base64, and the wrong key", () => {
    expect(verify(request(), key)).toMatchObject({ ok: false });
    const s = sign(request(), key, "k1");
    expect(verify({ ...s, params: { ...s.params, signature: { ...s.params.signature!, algorithm: "ECDSA-P256" } } }, key).ok).toBe(false);
    expect(verify({ ...s, params: { ...s.params, signature: { ...s.params.signature!, value: "!!" } } }, key).ok).toBe(false);
    expect(verify(s, bytes("33".repeat(32))).ok).toBe(false);
  });
  it("signs responses in result", () => {
    const res = sign({ jsonrpc: "2.0", id: 7, result: { type: "final", acs_version: "0.1.0", request_id: "6f1c3c1e-0d2b-4b8e-9a5f-1b2c3d4e5f60", decision: "allow", chain_hash: "ab".repeat(32) } }, key, "k1");
    expect(verify(res, key).ok).toBe(true);
    expect(verify({ ...res, result: { ...res.result, chain_hash: "cd".repeat(32) } }, key).ok).toBe(false);
    expect(signingInput(res)).toBeInstanceOf(Uint8Array);
  });
});

describe("replay protection (§10.3)", () => {
  const now = Date.parse("2026-10-05T10:00:00Z");
  const uuid = (n: number) => `6f1c3c1e-0d2b-4b8e-9a5f-${String(n).padStart(12, "0")}`;
  const code = (f: () => void) => { try { f(); return "ok"; } catch (e) { return (e as AcsError).code; } };
  it("rejects duplicate request ids within a session, for the whole session", () => {
    const g = new ReplayGuard(60_000);
    expect(code(() => g.check("s", uuid(1), "2026-10-05T10:00:00Z", now))).toBe("ok");
    expect(code(() => g.check("s", uuid(1), "2026-10-05T10:00:30Z", now + 30_000))).toBe(ERR.REPLAY_DETECTED);
    expect(code(() => g.check("s", uuid(1), "2026-10-05T11:00:00Z", now + 3_600_000))).toBe(ERR.REPLAY_DETECTED);
    expect(code(() => g.check("other", uuid(1), "2026-10-05T10:00:00Z", now))).toBe("ok");
  });
  it("rejects timestamps outside the skew window, both ways", () => {
    const g = new ReplayGuard(60_000);
    expect(code(() => g.check("s", uuid(2), "2026-10-05T09:58:59Z", now))).toBe(ERR.TIMESTAMP_OUT_OF_WINDOW);
    expect(code(() => g.check("s", uuid(3), "2026-10-05T10:01:01Z", now))).toBe(ERR.TIMESTAMP_OUT_OF_WINDOW);
    expect(code(() => g.check("s", uuid(4), "2026-10-05T10:01:00Z", now))).toBe("ok");
  });
  it("rejects a repeated nonce, and malformed ids or timestamps", () => {
    const g = new ReplayGuard(60_000);
    expect(code(() => g.check("s", uuid(5), "2026-10-05T10:00:00Z", now, "n-1"))).toBe("ok");
    expect(code(() => g.check("s", uuid(6), "2026-10-05T10:00:00Z", now, "n-1"))).toBe(ERR.REPLAY_DETECTED);
    expect(code(() => g.check("s", "not-a-uuid", "2026-10-05T10:00:00Z", now))).toBe(ERR.INVALID_PARAMS);
    expect(code(() => g.check("s", uuid(7), "yesterday", now))).toBe(ERR.INVALID_PARAMS);
  });
});

describe("the audit chain (§8.2)", () => {
  it("hashes the entry without its hashes, then appends the previous hash's raw bytes", () => {
    const c = new Chain();
    const e1 = c.append({ entry_id: "e1", step_id: "r1", step_type: "sessionStart", request_hash: "aa".repeat(32) });
    expect(e1.previous_hash).toBeNull();
    const manual1 = createHash("sha256").update(canonicalize({ entry_id: "e1", step_id: "r1", step_type: "sessionStart", request_hash: "aa".repeat(32) }), "utf8").digest("hex");
    expect(e1.entry_hash).toBe(manual1);
    const e2 = c.append({ entry_id: "e2", step_id: "r2", step_type: "toolCallRequest" });
    const manual2 = createHash("sha256").update(Buffer.concat([Buffer.from(canonicalize({ entry_id: "e2", step_id: "r2", step_type: "toolCallRequest" }), "utf8"), Buffer.from(e1.entry_hash, "hex")])).digest("hex");
    expect(e2.entry_hash).toBe(manual2);
    expect(c.head).toBe(e2.entry_hash);
    expect(verifyChain(c.all())).toBe(true);
  });
  it("detects a dropped, reordered or edited entry", () => {
    const c = new Chain();
    for (let i = 0; i < 4; i++) c.append({ entry_id: `e${i}`, step_id: `r${i}`, step_type: "toolCallRequest" });
    const all = [...c.all()];
    expect(verifyChain([all[0]!, all[2]!, all[3]!])).toBe(false);
    expect(verifyChain([all[1]!, all[0]!, all[2]!, all[3]!])).toBe(false);
    expect(verifyChain([all[0]!, { ...all[1]!, step_type: "sessionEnd" }, all[2]!, all[3]!])).toBe(false);
    expect(entryHash(all[1]!, all[0]!.entry_hash)).toBe(all[1]!.entry_hash);
  });
  it("request_hash is the SHA-256 of the JCS-canonical params", () => {
    expect(requestHash({ b: 1, a: 2 })).toBe(createHash("sha256").update('{"a":2,"b":1}', "utf8").digest("hex"));
  });
});

import { createHash } from "node:crypto";
