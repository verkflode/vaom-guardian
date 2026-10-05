// A minimal CBOR decoder (RFC 8949): enough for WebAuthn attestation objects and COSE keys. Definite
// lengths only, no tags, no floats: anything else is rejected, never guessed at.
export type Cbor = number | bigint | string | Uint8Array | boolean | null | Cbor[] | Map<Cbor, Cbor>;

export function decodeCbor(bytes: Uint8Array): Cbor {
  const [value, end] = item(bytes, 0, 0);
  if (end !== bytes.length) throw new Error("CBOR: trailing bytes");
  return value;
}

/** Decode one item at `at`; returns it with the offset after it. Exported for authenticator data, where a COSE key is followed by extensions. */
export function decodeCborPrefix(bytes: Uint8Array, at: number): [Cbor, number] {
  return item(bytes, at, 0);
}

function item(b: Uint8Array, at: number, depth: number): [Cbor, number] {
  if (depth > 16) throw new Error("CBOR: nested too deep");
  if (at >= b.length) throw new Error("CBOR: truncated");
  const major = b[at]! >> 5, info = b[at]! & 31;
  let [n, p] = arg(b, at + 1, info);
  switch (major) {
    case 0: return [n, p];
    case 1: return [typeof n === "bigint" ? -1n - n : -1 - n, p];
    case 2: case 3: {
      const len = Number(n);
      if (p + len > b.length) throw new Error("CBOR: truncated string");
      const s = b.subarray(p, p + len);
      return [major === 2 ? new Uint8Array(s) : new TextDecoder("utf-8", { fatal: true }).decode(s), p + len];
    }
    case 4: {
      const out: Cbor[] = [];
      for (let i = 0; i < Number(n); i++) { let v: Cbor; [v, p] = item(b, p, depth + 1); out.push(v); }
      return [out, p];
    }
    case 5: {
      const out = new Map<Cbor, Cbor>();
      for (let i = 0; i < Number(n); i++) {
        let k: Cbor, v: Cbor;
        [k, p] = item(b, p, depth + 1);
        [v, p] = item(b, p, depth + 1);
        if (out.has(k)) throw new Error("CBOR: duplicate map key");
        out.set(k, v);
      }
      return [out, p];
    }
    case 7:
      if (info === 20) return [false, at + 1];
      if (info === 21) return [true, at + 1];
      if (info === 22) return [null, at + 1];
      throw new Error("CBOR: unsupported simple value or float");
    default:
      throw new Error("CBOR: tags are not supported");
  }
}

function arg(b: Uint8Array, at: number, info: number): [number | bigint, number] {
  if (info < 24) return [info, at];
  const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
  if (!size) throw new Error("CBOR: indefinite lengths are not supported");
  if (at + size > b.length) throw new Error("CBOR: truncated argument");
  let v = 0n;
  for (let i = 0; i < size; i++) v = (v << 8n) | BigInt(b[at + i]!);
  return [v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v, at + size];
}
