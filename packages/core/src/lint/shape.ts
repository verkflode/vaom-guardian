// Checks shared by the linters, for what the schemas can't express.
import { durationSeconds } from "./duration.ts";
import { tok, type Finding, type Validated } from "./types.ts";

/**
 * Zero-length durations. A window, lifetime or schedule of zero would silently switch its control off
 * (a cap window of P0D counts nothing, so it never breaches), so every duration must be positive.
 * Durations are found by shape: identifiers are lower case, so no other string matches.
 */
export function zeroDurations(doc: unknown): Finding[] {
  const out: Finding[] = [];
  const walk = (node: unknown, path: string) => {
    if (typeof node === "string") {
      if (/^P/.test(node) && durationSeconds(node) === 0) out.push({ rule: "duration.zero", severity: "error", path, message: `duration ${node} is zero; a zero window or lifetime would switch its control off` });
    } else if (Array.isArray(node)) node.forEach((v, i) => walk(v, `${path}/${i}`));
    else if (typeof node === "object" && node !== null) for (const [k, v] of Object.entries(node)) walk(v, `${path}/${tok(k)}`);
  };
  walk(doc, "");
  return out;
}

/** Condition shapes the evaluator can only read as unknown: `in` needs an array. */
export function conditionShape(c: Validated, path: string): Finding[] {
  if (!c || typeof c !== "object") return [];
  if (Array.isArray(c.all)) return c.all.flatMap((x: Validated, i: number) => conditionShape(x, `${path}/all/${i}`));
  if (Array.isArray(c.any)) return c.any.flatMap((x: Validated, i: number) => conditionShape(x, `${path}/any/${i}`));
  if (c.op === "in" && !Array.isArray(c.value)) return [{ rule: "condition.in-not-array", severity: "error", path: `${path}/value`, message: "op in needs an array of values; anything else can never match, so the condition would always be unevaluable" }];
  return [];
}

/** Names that `Object.prototype` already carries: a fact so named would read as present when it's missing. */
export const RESERVED_FACT_NAMES: ReadonlySet<string> = new Set(Object.getOwnPropertyNames(Object.prototype));
