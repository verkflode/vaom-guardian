// ISO 8601 durations as used in the schemas ("PT60M", "P30D", "P1Y2M"). Years and months have no
// fixed length; for comparisons they count as 365 and 30 days, which is stated where it matters.
const RE = /^P(?!$)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/;

export function durationSeconds(iso: string): number | null {
  const m = RE.exec(iso);
  if (!m) return null;
  const n = (i: number) => Number(m[i] ?? 0);
  return ((n(1) * 365 + n(2) * 30 + n(3) * 7 + n(4)) * 24 + n(5)) * 3600 + n(6) * 60 + n(7);
}
