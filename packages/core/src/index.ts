// VAOM Guardian core. Pure: no network, no processes, no environment, no eval, no runtime dependencies.
// It runs unchanged in Node and in the browser (the Delegation Lab).
export { lintMatrix, MATRIX_FORMATS } from "./lint/matrix.ts";
export { lintBinding, BINDING_FORMAT } from "./lint/binding.ts";
export type { Finding, LintResult, Severity } from "./lint/types.ts";
export { compilePolicy, evaluate } from "./eval/evaluate.ts";
export type { Band, Call, CapUsage, CompileResult, Decision, EvalContext, FactValue, Money, Outcome, Placement, Policy, Reason, Reservation, Score } from "./eval/types.ts";
