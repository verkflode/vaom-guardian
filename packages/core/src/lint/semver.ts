// The version ranges a binding may use for its matrix. Deliberately small: an exact version
// ("1.2.3") or a half-open range (">=1.0.0 <2.0.0"). Anything else is refused, not guessed at.
type V = [number, number, number];

function parse(v: string): V | null {
  const m = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(v);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function cmp(a: V, b: V): number {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

/** true/false when the range is understood; null when the range syntax isn't supported. */
export function inRange(version: string, range: string): boolean | null {
  const v = parse(version);
  if (!v) return false;
  const exact = parse(range.trim());
  if (exact) return cmp(v, exact) === 0;
  const m = /^>=\s*(\S+)\s+<\s*(\S+)$/.exec(range.trim());
  if (!m) return null;
  const lo = parse(m[1] ?? ""), hi = parse(m[2] ?? "");
  if (!lo || !hi) return null;
  return cmp(v, lo) >= 0 && cmp(v, hi) < 0;
}
