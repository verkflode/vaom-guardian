// Condition evaluation, three-valued: true, false, or null when a value it needs is missing.
// Callers decide what null means; it must never resolve to a wider outcome.
export type Ternary = boolean | null;

type Cond = any;

export function evalCondition(c: Cond, lookup: (name: string) => unknown, key: "fact" | "arg"): Ternary {
  if (Array.isArray(c.all)) {
    let unknown = false;
    for (const x of c.all) { const v = evalCondition(x, lookup, key); if (v === false) return false; if (v === null) unknown = true; }
    return unknown ? null : true;
  }
  if (Array.isArray(c.any)) {
    let unknown = false;
    for (const x of c.any) { const v = evalCondition(x, lookup, key); if (v === true) return true; if (v === null) unknown = true; }
    return unknown ? null : false;
  }
  const v = lookup(c[key]);
  if (v === undefined) return null;
  const w = c.value;
  switch (c.op) {
    case "eq": return deepEqual(v, w);
    case "ne": return !deepEqual(v, w);
    case "in": return Array.isArray(w) ? w.some((x) => deepEqual(v, x)) : null;
    case "gt": return comparable(v, w) ? v > (w as typeof v) : null;
    case "gte": return comparable(v, w) ? v >= (w as typeof v) : null;
    case "lt": return comparable(v, w) ? v < (w as typeof v) : null;
    case "lte": return comparable(v, w) ? v <= (w as typeof v) : null;
    case "prefix": return typeof v === "string" && typeof w === "string" ? v.startsWith(w) : null;
    case "contains": return typeof v === "string" && typeof w === "string" ? v.includes(w) : Array.isArray(v) ? v.some((x) => deepEqual(x, w)) : null;
    default: return null;
  }
}

/** Both numbers or both strings: the only pairs ordered comparisons accept. */
function comparable(a: unknown, b: unknown): a is number | string {
  return (typeof a === "number" && typeof b === "number") || (typeof a === "string" && typeof b === "string");
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a), kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}
