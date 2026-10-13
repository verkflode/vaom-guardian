// Scoring policy linter: JSON Schema validation, then what the schema can't say. With a binding, it also
// checks the policy against the facts the binding declares. A policy that fails is treated as missing, and
// a row whose policy is missing can't be compiled.
import { validateScoring01 } from "../generated/validators.js";
import { schemaFindings } from "./schema-findings.ts";
import { conditionShape, zeroDurations } from "./shape.ts";
import { result, type Finding, type LintResult, type Validated } from "./types.ts";

export const SCORING_FORMAT = "vaom.scoring/0.1";

export const DIMENSIONS = ["dataCompleteness", "ruleMatch", "anomaly"] as const;

const ORDERED = new Set(["gt", "gte", "lt", "lte"]);
const NUMERIC = new Set(["money", "number", "integer"]);

export function lintScoring(scoring: unknown, binding?: unknown): LintResult {
  const s = scoring as Validated;
  const format = typeof s?.format === "string" ? s.format : null;
  if (format !== SCORING_FORMAT) {
    return result(format, [{ rule: "format", severity: "error", path: "/format", message: `unknown or missing scoring policy format ${JSON.stringify(format)}; known: ${SCORING_FORMAT}` }]);
  }
  if (!validateScoring01(scoring)) return result(format, schemaFindings(validateScoring01.errors));

  const out: Finding[] = [];
  const err = (rule: string, path: string, message: string) => out.push({ rule, severity: "error", path, message });
  const d = s.dimensions;

  // Weights are shares of one composite. Summing to 1 keeps the composite on the same 0..1 scale the
  // row's thresholds were calibrated on; a tolerance absorbs binary rounding of decimal weights.
  const sum = DIMENSIONS.reduce((acc, k) => acc + (d[k]?.weight ?? 0), 0);
  if (Math.abs(sum - 1) > 1e-9) err("weights.sum", "/dimensions", `dimension weights sum to ${sum}; they must sum to 1`);

  const ids = new Map<string, string>();
  const unique = (id: string, path: string) => {
    if (ids.has(id)) err("id.duplicate", path, `id ${id} is already used at ${ids.get(id)}`);
    else ids.set(id, path);
  };
  (d.dataCompleteness?.checks ?? []).forEach((c: Validated, i: number) => unique(c.id, `/dimensions/dataCompleteness/checks/${i}/id`));
  (d.ruleMatch?.rules ?? []).forEach((r: Validated, i: number) => unique(r.id, `/dimensions/ruleMatch/rules/${i}/id`));
  (d.anomaly?.signals ?? []).forEach((g: Validated, i: number) => unique(g.id, `/dimensions/anomaly/signals/${i}/id`));

  out.push(...zeroDurations(s));
  (d.dataCompleteness?.checks ?? []).forEach((c: Validated, i: number) => out.push(...conditionShape(c.when, `/dimensions/dataCompleteness/checks/${i}/when`)));
  (d.ruleMatch?.rules ?? []).forEach((r: Validated, i: number) => out.push(...conditionShape(r.when, `/dimensions/ruleMatch/rules/${i}/when`)));

  if (binding !== undefined) out.push(...factFindings(s, binding as Validated));
  return result(format, out);
}

/** Every fact the policy reads, with where it's read. */
export function scoringFacts(s: Validated): { fact: string; path: string; use: "condition" | "present" | "history-value" | "history-key"; op?: string }[] {
  const out: ReturnType<typeof scoringFacts> = [];
  const walk = (c: Validated, path: string) => {
    if (Array.isArray(c.all)) c.all.forEach((x: Validated, i: number) => walk(x, `${path}/all/${i}`));
    else if (Array.isArray(c.any)) c.any.forEach((x: Validated, i: number) => walk(x, `${path}/any/${i}`));
    else out.push({ fact: c.fact, path: `${path}/fact`, use: "condition", op: c.op });
  };
  const d = s.dimensions;
  (d.dataCompleteness?.checks ?? []).forEach((c: Validated, i: number) => {
    const p = `/dimensions/dataCompleteness/checks/${i}`;
    (c.present ?? []).forEach((f: string, j: number) => out.push({ fact: f, path: `${p}/present/${j}`, use: "present" }));
    if (c.when) walk(c.when, `${p}/when`);
  });
  (d.ruleMatch?.rules ?? []).forEach((r: Validated, i: number) => walk(r.when, `/dimensions/ruleMatch/rules/${i}/when`));
  (d.anomaly?.signals ?? []).forEach((g: Validated, i: number) => {
    const p = `/dimensions/anomaly/signals/${i}`;
    if (g.kind === "unseen") out.push({ fact: g.fact, path: `${p}/fact`, use: "history-key" });
    if (g.kind === "unusual-value") out.push({ fact: g.fact, path: `${p}/fact`, use: "history-value" });
    (g.groupBy ?? []).forEach((f: string, j: number) => out.push({ fact: f, path: `${p}/groupBy/${j}`, use: "history-key" }));
  });
  return out;
}

function factFindings(s: Validated, b: Validated): Finding[] {
  const out: Finding[] = [];
  const err = (rule: string, path: string, message: string) => out.push({ rule, severity: "error", path, message });
  const defs: Record<string, Validated> = b?.facts ?? {};
  for (const { fact, path, use, op } of scoringFacts(s)) {
    const def = defs[fact];
    if (!def) { err("fact.undeclared", path, `fact ${fact} is not declared by binding ${b?.id ?? "(unnamed)"}`); continue; }
    const mode = def.record ?? "value";
    if (use === "condition" && op && ORDERED.has(op) && def.type === "money") {
      err("condition.money", path, `fact ${fact} is money; ordered comparisons on money aren't defined in conditions (use the row's value ceiling)`);
    }
    // History is read back from decision records, so a fact must be recorded in a form the signal can use.
    if (use === "history-key" && mode === "omit") {
      err("history.omitted", path, `fact ${fact} is omitted from records, so history can't be matched on it`);
    }
    if (use === "history-value") {
      if (!NUMERIC.has(def.type)) err("history.not-numeric", path, `fact ${fact} has type ${def.type}; an unusual-value signal needs money, number or integer`);
      else if (mode !== "value") err("history.not-clear", path, `fact ${fact} is recorded as ${mode}; an unusual-value signal needs its values in clear`);
    }
  }
  return out;
}
