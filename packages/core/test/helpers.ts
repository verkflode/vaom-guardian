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
