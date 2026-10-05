// A software WebAuthn authenticator for tests: P-256 keys, "none" attestation, settable flags and counter.
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign, type KeyObject } from "node:crypto";

type C = number | string | Uint8Array | Map<C, C> | C[];
export function cbor(v: C): Uint8Array {
  const head = (major: number, n: number): number[] => {
    if (n < 24) return [(major << 5) | n];
    if (n < 256) return [(major << 5) | 24, n];
    if (n < 65536) return [(major << 5) | 25, n >> 8, n & 255];
    return [(major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
  };
  const parts: number[] = [];
  const enc = (x: C) => {
    if (typeof x === "number") parts.push(...(x >= 0 ? head(0, x) : head(1, -1 - x)));
    else if (typeof x === "string") { const b = Buffer.from(x, "utf8"); parts.push(...head(3, b.length), ...b); }
    else if (x instanceof Uint8Array) parts.push(...head(2, x.length), ...x);
    else if (x instanceof Map) { parts.push(...head(5, x.size)); for (const [k, val] of x) { enc(k); enc(val); } }
    else { parts.push(...head(4, x.length)); x.forEach(enc); }
  };
  enc(v);
  return Uint8Array.from(parts);
}

const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const sha = (b: Uint8Array | string) => new Uint8Array(createHash("sha256").update(b).digest());

export class SoftAuthenticator {
  readonly id = new Uint8Array(randomBytes(16));
  private readonly priv: KeyObject;
  readonly x: Uint8Array;
  readonly y: Uint8Array;
  counter = 0;
  alg = -7;
  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.priv = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.x = new Uint8Array(Buffer.from(jwk.x!, "base64url"));
    this.y = new Uint8Array(Buffer.from(jwk.y!, "base64url"));
  }
  get credentialId(): string { return b64u(this.id); }

  private authData(rpId: string, flags: number, attested?: Uint8Array): Uint8Array {
    const head = new Uint8Array(37);
    head.set(sha(rpId));
    head[32] = flags;
    new DataView(head.buffer).setUint32(33, this.counter);
    return attested ? Uint8Array.from([...head, ...attested]) : head;
  }

  create(o: { challenge: string; origin: string; rpId: string; flags?: number; type?: string; crossOrigin?: boolean }) {
    const cose = cbor(new Map<C, C>([[1, 2], [3, this.alg], [-1, 1], [-2, this.x], [-3, this.y]]));
    const attested = Uint8Array.from([...new Uint8Array(16), this.id.length >> 8, this.id.length & 255, ...this.id, ...cose]);
    const authData = this.authData(o.rpId, o.flags ?? 0x45, attested);
    const clientData = JSON.stringify({ type: o.type ?? "webauthn.create", challenge: o.challenge, origin: o.origin, ...(o.crossOrigin ? { crossOrigin: true } : {}) });
    return { attestationObject: b64u(cbor(new Map<C, C>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]))), clientDataJSON: b64u(Buffer.from(clientData)) };
  }

  get(o: { challenge: string; origin: string; rpId: string; flags?: number; type?: string; bump?: number }) {
    this.counter += o.bump ?? 1;
    const authData = this.authData(o.rpId, o.flags ?? 0x05);
    const clientData = Buffer.from(JSON.stringify({ type: o.type ?? "webauthn.get", challenge: o.challenge, origin: o.origin }));
    const sig = cryptoSign("sha256", Buffer.concat([authData, sha(clientData)]), { key: this.priv, dsaEncoding: "der" });
    return { credentialId: this.credentialId, authenticatorData: b64u(authData), clientDataJSON: b64u(clientData), signature: b64u(sig) };
  }
}
