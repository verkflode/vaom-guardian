// Seeded-case linter: JSON Schema validation, then each seed checked against the compiled policy. A seed
// may only be planted in the review queue of a row that enables seeding, which the matrix allows only
// where records feed nothing that matters (VAOM v5 Readiness Condition 6), and it must pose as a call the
// binding maps to that row, so it can't land anywhere else.
import { matches } from "../eval/evaluate.ts";
import type { Policy } from "../eval/types.ts";
import { validateSeeds01 } from "../generated/validators.js";
import { schemaFindings } from "./schema-findings.ts";
import { result, type Finding, type LintResult, type Validated } from "./types.ts";

export const SEEDS_FORMAT = "vaom.seeds/0.1";

export function lintSeeds(seeds: unknown, policy: Policy): LintResult {
  const s = seeds as Validated;
  const format = typeof s?.format === "string" ? s.format : null;
  if (format !== SEEDS_FORMAT) {
    return result(format, [{ rule: "format", severity: "error", path: "/format", message: `unknown or missing seeds format ${JSON.stringify(format)}; known: ${SEEDS_FORMAT}` }]);
  }
  if (!validateSeeds01(seeds)) return result(format, schemaFindings(validateSeeds01.errors));

  const out: Finding[] = [];
  const err = (rule: string, path: string, message: string) => out.push({ rule, severity: "error", path, message });
  const ids = new Set<string>();
  (s.seeds as Validated[]).forEach((seed, i) => {
    const p = `/seeds/${i}`;
    if (ids.has(seed.id)) err("id.duplicate", `${p}/id`, `seed id ${seed.id} is used more than once`);
    ids.add(seed.id);
    const row = policy.rowById.get(seed.row);
    if (!row) { err("row.unknown", `${p}/row`, `row ${seed.row} isn't in the matrix`); return; }
    const ov = row.oversight ?? {};
    if (ov.seeding?.enabled !== true) err("row.seeding-off", `${p}/row`, `row ${seed.row} doesn't enable seeding`);
    // At most one seed is planted per real ask, so at most half the queue can be seeds. A higher rate would
    // be disclosed to reviewers but never reached.
    else if (ov.seeding.rate > 0.5) err("row.rate-unreachable", `${p}/row`, `row ${seed.row}'s seeding rate ${ov.seeding.rate} can't be reached: at most half a review queue can be planted`);
    else if ((ov.recordsFeed ?? []).length > 0) err("row.records-feed", `${p}/row`, `row ${seed.row}'s records feed ${ov.recordsFeed.join(", ")}; seeding is never allowed there`);
    // As the evaluator does: an entry whose match condition can't be read makes the call unplaceable, so
    // such a seed would never reach a reviewer.
    const results = (policy.binding.tools as Validated[]).map((t) => ({ t, m: matches(t, { tool: seed.tool, arguments: seed.arguments }) }));
    const unevaluable = results.filter((x) => x.m === null).map((x) => x.t.id as string);
    const matched = results.filter((x) => x.m === true).map((x) => x.t);
    if (unevaluable.length) err("tool.unevaluable", `${p}/arguments`, `entry ${unevaluable.join(", ")} can't evaluate its match condition on these arguments; the seed would be unplaceable`);
    else if (matched.length === 0) err("tool.unmapped", `${p}/tool`, `no binding entry maps ${seed.tool} with these arguments`);
    else if (matched.some((t) => !(row.capabilities as string[]).includes(t.capability))) {
      err("tool.other-row", `${p}/tool`, `${seed.tool} maps to ${[...new Set(matched.map((t) => t.capability))].join(", ")}, not only to row ${seed.row}`);
    }
  });
  return result(format, out);
}
