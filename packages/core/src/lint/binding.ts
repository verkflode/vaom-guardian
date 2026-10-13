// Binding linter: JSON Schema validation, then the binding checked against the matrix it names.
// Fails closed: the matrix must itself lint clean first, and an unsupported version range is refused.
import { validateBinding01 } from "../generated/validators.js";
import { lintMatrix } from "./matrix.ts";
import { inRange } from "./semver.ts";
import { schemaFindings } from "./schema-findings.ts";
import { conditionShape, RESERVED_FACT_NAMES } from "./shape.ts";
import { result, tok, type Finding, type LintResult, type Validated } from "./types.ts";

export const BINDING_FORMAT = "vaom.binding/0.1";

export function lintBinding(binding: unknown, matrix: unknown): LintResult {
  const b = binding as Validated;
  const format = typeof b?.format === "string" ? b.format : null;
  if (format !== BINDING_FORMAT) {
    return result(format, [{ rule: "format", severity: "error", path: "/format", message: `unknown or missing binding format ${JSON.stringify(format)}; known: ${BINDING_FORMAT}` }]);
  }
  if (!validateBinding01(binding)) return result(format, schemaFindings(validateBinding01.errors));

  const m = lintMatrix(matrix);
  if (!m.ok) {
    return result(format, [{ rule: "matrix.invalid", severity: "error", path: "", message: `the matrix does not lint clean (${m.findings.filter((f) => f.severity === "error").length} errors); a binding can't be checked against it` }]);
  }
  return result(format, crossFindings(b, matrix as Validated));
}

function crossFindings(b: Validated, m: Validated): Finding[] {
  const out: Finding[] = [];
  const err = (rule: string, path: string, message: string) => out.push({ rule, severity: "error", path, message });
  const warn = (rule: string, path: string, message: string) => out.push({ rule, severity: "warning", path, message });

  if (b.matrix.id !== m.id) err("matrix.id", "/matrix/id", `binding is for matrix ${b.matrix.id}, but the matrix given is ${m.id}`);
  const r = inRange(m.version, b.matrix.versions);
  if (r === null) err("matrix.range-syntax", "/matrix/versions", `version range ${JSON.stringify(b.matrix.versions)} is not supported; use "X.Y.Z" or ">=X.Y.Z <X.Y.Z"`);
  else if (!r) err("matrix.version", "/matrix/versions", `matrix version ${m.version} is outside ${b.matrix.versions}`);

  const facts: Record<string, Validated> = b.facts;
  for (const [name, def] of Object.entries(facts)) {
    if (RESERVED_FACT_NAMES.has(name)) err("fact.reserved-name", `/facts/${tok(name)}`, `fact name ${name} is reserved: every object already has it, so it could read as present when it's missing`);
    if (def.type === "string" && def.record === undefined) {
      warn("fact.record-unset", `/facts/${tok(name)}`, `string fact ${name} will be recorded in clear by default; set record explicitly ("digest" or "omit" if it identifies a person or counterparty, "value" if clear is intended)`);
    }
  }

  const ids = new Set<string>();
  (b.tools as Validated[]).forEach((t, i) => {
    const p = `/tools/${i}`;
    if (ids.has(t.id)) err("tool.duplicate-id", `${p}/id`, `entry id ${t.id} is used more than once`);
    ids.add(t.id);

    out.push(...conditionShape(t.match?.when, `${p}/match/when`));

    const rows = (m.rows as Validated[]).filter((row) => (row.capabilities as string[]).includes(t.capability));
    if (rows.length !== 1) {
      err("capability.ungoverned", `${p}/capability`, `capability ${t.capability} is governed by ${rows.length} rows; it must be exactly one`);
      return;
    }
    const row = rows[0];
    const a = row.authority;

    const perCall: Record<string, Validated> = t.facts ?? {};
    const perItem: Record<string, Validated> = t.items?.facts ?? {};
    for (const f of Object.keys(perItem)) {
      if (f in perCall) err("fact.per-call-and-item", `${p}/items/facts/${tok(f)}`, `fact ${f} is extracted both per call and per item; there is no precedence rule`);
    }
    const extracted = new Map<string, { ex: Validated; path: string }>();
    for (const [f, ex] of Object.entries(perCall)) extracted.set(f, { ex, path: `${p}/facts/${tok(f)}` });
    for (const [f, ex] of Object.entries(perItem)) if (!extracted.has(f)) extracted.set(f, { ex, path: `${p}/items/facts/${tok(f)}` });

    for (const [f, { ex, path }] of extracted) {
      const def = facts[f];
      if (!def) { err("fact.undeclared", path, `fact ${f} is not declared in facts`); continue; }
      const isMoneyExtractor = typeof ex === "object" && ex !== null && "amount" in ex;
      if ((def.type === "money") !== isMoneyExtractor) err("fact.extractor-type", path, `fact ${f} has type ${def.type} but a ${isMoneyExtractor ? "money" : "plain"} extractor`);
      // A fixed currency asserts what the tool's amounts are in. Legitimate only for a tool that can't take
      // another currency; it must at least agree with the row's limits, or amounts would be compared as if
      // they were in the limit's currency.
      if (isMoneyExtractor && typeof ex.currency === "object" && ex.currency !== null && "const" in ex.currency) {
        const fixed = ex.currency.const;
        warn("fact.currency-fixed", `${path}/currency`, `fact ${f} fixes its currency to ${JSON.stringify(fixed)} instead of reading it from the call; right only if the tool can't take another currency`);
        const limits = [a.valueCeiling?.fact === f ? a.valueCeiling.limit?.currency : undefined, ...((a.cumulativeCaps ?? []) as Validated[]).filter((c) => c.fact === f && c.total).map((c) => c.total.currency)].filter(Boolean);
        for (const cur of new Set(limits)) if (cur !== fixed) err("fact.currency-mismatch", `${path}/currency`, `fact ${f} is fixed to ${JSON.stringify(fixed)}, but row ${row.id} limits it in ${cur}`);
      }
    }

    const need = (f: string, why: string) => {
      if (!extracted.has(f)) err("fact.missing", p, `row ${row.id} needs fact ${f} (${why}), but entry ${t.id} doesn't extract it`);
    };
    for (const f of (row.requiresFacts ?? []) as string[]) need(f, "requiresFacts");
    for (const f of conditionFacts(a.restrictions)) need(f, "a restriction");
    for (const c of [...(a.cumulativeCaps ?? []), ...(a.rateCaps ?? [])] as Validated[]) for (const g of (c.groupBy ?? []) as string[]) need(g, `cap ${c.id} groups by it`);

    if (a.kind === "non-delegable") {
      const absent = ((a.boundaries ?? []) as string[]).filter((bid) => m.boundaries?.[bid]?.intendedMechanism === "absent");
      if (absent.length) err("boundary.tool-present", `${p}/capability`, `entry ${t.id} maps a host tool to ${t.capability}, which boundary ${absent.join(", ")} says is absent from the agent's reach`);
    }
    if (a.kind === "delegable") {
      const summed = [a.valueCeiling?.fact, ...((a.cumulativeCaps ?? []) as Validated[]).filter((c) => c.total).map((c) => c.fact)].filter(Boolean) as string[];
      for (const f of summed) {
        if (facts[f]?.type !== "money") err("fact.not-money", p, `row ${row.id} compares or sums fact ${f}, which isn't declared as money`);
        need(f, "a value limit");
      }
    }
  });
  return out;
}

/** Fact names a set of restrictions reads. A fact the binding never extracts makes the restriction unevaluable. */
function conditionFacts(restrictions: Validated[] | undefined): Set<string> {
  const out = new Set<string>();
  const walk = (c: Validated) => {
    if (!c) return;
    if (Array.isArray(c.all)) c.all.forEach(walk);
    else if (Array.isArray(c.any)) c.any.forEach(walk);
    else if (typeof c.fact === "string") out.add(c.fact);
  };
  for (const r of restrictions ?? []) walk(r.when);
  return out;
}
