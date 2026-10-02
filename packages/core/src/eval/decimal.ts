// Exact decimal arithmetic for money. Amounts are decimal strings ("3200", "3200.50"); floating point
// never touches them, so a limit of 5000 is never breached by 5000.0000000001.
const RE = /^(0|[1-9]\d*)(?:\.(\d+))?$/;

export function isDecimal(s: unknown): s is string {
  return typeof s === "string" && RE.test(s);
}

/** Scale two decimals to a common number of fractional digits, as BigInts. */
function scaled(a: string, b: string): [bigint, bigint] {
  const [ai = "0", af = ""] = a.split("."), [bi = "0", bf = ""] = b.split(".");
  const n = Math.max(af.length, bf.length);
  return [BigInt(ai + af.padEnd(n, "0")), BigInt(bi + bf.padEnd(n, "0"))];
}

export function cmpDecimal(a: string, b: string): number {
  const [x, y] = scaled(a, b);
  return x < y ? -1 : x > y ? 1 : 0;
}

export function addDecimal(a: string, b: string): string {
  const af = a.split(".")[1] ?? "", bf = b.split(".")[1] ?? "";
  const n = Math.max(af.length, bf.length);
  const [x, y] = scaled(a, b);
  const s = (x + y).toString().padStart(n + 1, "0");
  return n === 0 ? s : `${s.slice(0, -n)}.${s.slice(-n)}`;
}
