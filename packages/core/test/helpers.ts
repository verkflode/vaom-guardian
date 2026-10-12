import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { LintResult } from "../src/index.ts";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
const read = (f: string) => readFileSync(join(examples, f), "utf8");

const text = {
  matrix01: read("invoice.matrix-0.1.json"),
  matrix02: read("invoice.matrix-0.2.json"),
  binding: read("invoice.claude-code.binding.json"),
};

// A fresh copy each time, so a case's mutation never leaks into another case.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Doc = any;
export const matrix01 = (): Doc => JSON.parse(text.matrix01);
export const matrix02 = (): Doc => JSON.parse(text.matrix02);
export const binding = (): Doc => JSON.parse(text.binding);

export const errors = (r: LintResult) => r.findings.filter((f) => f.severity === "error");
export const warnings = (r: LintResult) => r.findings.filter((f) => f.severity === "warning");
export const rules = (r: LintResult, severity: "error" | "warning" = "error") =>
  [...new Set(r.findings.filter((f) => f.severity === severity).map((f) => f.rule))].sort();

const scoringFiles = ["invoice-standard", "invoice-duplicate", "aml-dismissal", "remediation-gate", "incident-detection", "reorder-gate", "price-anomaly"];
const scoringText = Object.fromEntries(scoringFiles.map((f) => [f, read(`${f}.scoring.json`)]));
/** Every example scoring policy, fresh. */
export const scoringPolicies = (): Doc[] => scoringFiles.map((f) => JSON.parse(scoringText[f]!));
export const scoringPolicy = (id: string): Doc => JSON.parse(scoringText[id]!);

/**
 * A policy with its anomaly dimension removed and the other weights scaled up to sum to 1 again: for tests
 * about something other than history, so a fresh ledger's unfamiliar vendors don't decide the band.
 */
export function withoutAnomaly(s: Doc): Doc {
  const d = s.dimensions;
  if (!d.anomaly) return s;
  delete d.anomaly;
  const rest = Object.values(d) as { weight: number }[];
  const sum = rest.reduce((a, x) => a + x.weight, 0);
  if (sum === 0) rest[0]!.weight = 1;
  else for (const x of rest) x.weight = x.weight / sum;
  return s;
}
export const quietScoring = (): Doc[] => scoringPolicies().map(withoutAnomaly);
