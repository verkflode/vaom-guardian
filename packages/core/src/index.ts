// VAOM Guardian core. Pure: no network, no processes, no environment, no eval, no runtime dependencies.
// It runs unchanged in Node and in the browser (the Delegation Lab).
export { lintMatrix, MATRIX_FORMATS } from "./lint/matrix.ts";
export { lintBinding, BINDING_FORMAT } from "./lint/binding.ts";
export { lintScoring, SCORING_FORMAT } from "./lint/scoring.ts";
export { lintSeeds, SEEDS_FORMAT } from "./lint/seeds.ts";
export { score, capLevel, type DimensionScore, type History, type Level, type ScoreInput, type ScoreResult } from "./scoring/score.ts";
export type { Finding, LintResult, Severity } from "./lint/types.ts";
// Document types derived from the schemas (scripts/gen-validators.mjs): what a document is once it validates.
export type { Binding01, Decision03, Decision04, Matrix01, Matrix02, ProbeResult01, Probes01, Scoring01, Seeds01 } from "./generated/types.ts";
export { compilePolicy, evaluate } from "./eval/evaluate.ts";
export type { Band, Call, CapUsage, CompileResult, Decision, EvalContext, FactValue, Money, Outcome, Placement, PlacementScore, Policy, Reason, Reservation } from "./eval/types.ts";
export { buildRecord, checkRecord, resolveRecord, RecordError, RECORD_FORMAT } from "./record/record.ts";
export type { DecisionRecord, RecordedFact, RecordInput, Resolution } from "./record/record.ts";
export { canonicalize } from "./canonical/jcs.ts";
export { sha256, hmacSha256, hex, utf8 } from "./crypto/sha256.ts";
export { CapLedger } from "./caps/ledger.ts";
export { decide, preview, type DecideInput } from "./decide.ts";
export { recordedGroup, recordFact } from "./record/record.ts";
export { ContextRegistry, DEFAULT_CONTEXT_LIFETIME, type Context, type ContextSpec, type DeriveResult } from "./authority/contexts.ts";
export { LeaseRegistry, type Health, type Lease } from "./authority/leases.ts";
export type { LiveContext } from "./eval/types.ts";
export { scorecard, SCORECARD_FORMAT, PAPER_DEFAULTS, type Metric, type RowScorecard, type Scorecard, type ScorecardOptions, type SeedOutcome, type SpawnOutcome, type Status } from "./scorecard/scorecard.ts";
export { assessBoundaries, checkProbeResult, classify, contradiction, lintProbes, toolMatches, PROBES_FORMAT, PROBE_RESULT_FORMAT, type BoundaryAssessment, type BoundaryStatus, type Mechanism, type Observed, type ProbeResult } from "./boundaries/probes.ts";
