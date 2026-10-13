import type { Finding } from "../lint/types.ts";
import type { DimensionScore, Dimension, History, Level } from "../scoring/score.ts";

export type Band = "A" | "B" | "C" | "non-delegable";

/**
 * What the evaluator concluded, in VAOM terms. A wire adapter maps it to its protocol
 * (for ACS: allow, ask with the approver, deny, and defer with timeout deny).
 *   allow       Band A: the agent may execute.
 *   review      Band B: execute only after the named reviewer approves.
 *   escalate    Band C: execute only after the named escalation role approves.
 *   refuse      Non-delegable: the agent never executes this, whoever approves.
 *   unplaceable The call can't be placed in a band. Never resolves to allow.
 */
export type Outcome = "allow" | "review" | "escalate" | "refuse" | "unplaceable";

export interface Money { amount: string; currency: string }
export type FactValue = string | number | boolean | Money;

/** A tool call as the evaluator sees it: arguments already unwrapped from any wire format. */
export interface Call {
  tool: string;
  arguments: Record<string, unknown>;
  /** A capability the host or framework declared on the wire. Never grants authority; a mismatch makes the call unplaceable. */
  declaredCapability?: string;
  /** The agent's own stated certainty, if the host passed one. A scoring policy may let it lower a score;
   *  nothing lets it raise one. */
  statedCertainty?: number;
}

/** A placement's confidence score, as its row's scoring policy computed it. */
export interface PlacementScore {
  policy: { id: string; version: string };
  value: number;
  level: Level;
  cap?: "medium" | "low";
  /** The verifier's verdict, when one was supplied. */
  verified?: boolean;
  dimensions: Partial<Record<Dimension, DimensionScore>>;
}

export interface CapUsage {
  /** Sum of the cap's fact over the window, completed and pending; for value caps. */
  total?: string;
  /** Number of actions over the window, completed and pending. */
  count: number;
}

export interface EvalContext {
  /** The time of the call, in ms since the epoch. A matrix grants nothing outside its effective window, so
   *  the evaluator can't decide without the clock; a non-finite value makes every call unplaceable. */
  now: number;
  /** Decision history for anomaly signals. Absent: history can't be read, so every signal fires. */
  history?: History;
  /** An independent verifier's verdict per capability (VAOM v5 Section 8). Rows with verificationRequired
   *  reach Band A only on a pass. The Guardian has no verifier channel yet and supplies none. */
  verifications?: Record<string, boolean>;
  /** Usage of one row's cap for one group key. null means the history can't be read, which counts as breached.
   *  Cap ids are unique only within a row, so the row is part of the key. */
  capUsage(row: string, capId: string, groupKey: string): CapUsage | null;
  /** The session's live execution contexts. Without one covering a call's row there's no authority to act. */
  contexts: readonly LiveContext[];
}

/** What the evaluator needs from a live execution context (see authority/contexts.ts). */
export interface LiveContext {
  id: string;
  rows: readonly string[];
  /** Capabilities usable in this context (VAOM's scope set). Absent: everything its rows reach. */
  scopes?: readonly string[];
  /** An observation context from a live lease: authorises only preparatory capabilities in its scopes
   *  (reading, and messages addressed to humans), never a decision. */
  observation?: boolean;
  task?: string;
  bandCeiling?: Readonly<Record<string, Band>>;
}

export interface Reason {
  code: string;
  detail?: string;
  /** The row the reason applies to, when there is one. */
  row?: string;
}

/** A cap use this decision would make. The cap store reserves these before an allow goes out. */
export interface Reservation {
  capId: string;
  row: string;
  groupKey: string;
  amount?: string;
  count: 1;
}

export interface Placement {
  row: string;
  capability: string;
  entry: string;
  band: Band | null;
  outcome: Outcome;
  approverRole?: string;
  facts: Record<string, FactValue>;
  /** Absent for preparatory and non-delegable placements, and for any placement that stopped before scoring. */
  score?: PlacementScore;
  /** The live contexts that authorised this placement (scope, task and observation all checked). Not
   *  recorded per placement; the record names the first. */
  contexts?: string[];
  reasons: Reason[];
}

export interface Decision {
  outcome: Outcome;
  band: Band | null;
  approverRole?: string;
  /** Every placement that fed the decision: one per matched entry, or per batch item. */
  placements: Placement[];
  reasons: Reason[];
  reservations: Reservation[];
  policy: { matrix: { id: string; version: string }; binding: { id: string; version: string }; scoring?: { id: string; version: string }[] };
}

export type CompileResult = { ok: true; policy: Policy } | { ok: false; findings: Finding[] };

type Validated = any;

export interface Policy {
  matrix: Validated;
  binding: Validated;
  rowByCapability: ReadonlyMap<string, Validated>;
  rowById: ReadonlyMap<string, Validated>;
  /** Scoring policies keyed "id@version", as rows cite them. */
  scoring: ReadonlyMap<string, Validated>;
}
