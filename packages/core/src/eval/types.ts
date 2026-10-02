import type { Finding } from "../lint/types.ts";

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
}

/** A composite confidence score from a deployment's scoring policy. Never the agent's self-report. */
export interface Score {
  value: number;
  policy: { id: string; version: string };
  /** An independent verifier passed. Required for Band A on rows with verificationRequired. */
  verified?: boolean;
}

export interface CapUsage {
  /** Sum of the cap's fact over the window, completed and pending; for value caps. */
  total?: string;
  /** Number of actions over the window, completed and pending. */
  count: number;
}

export interface EvalContext {
  /** Scores per capability the caller has scored. Absent means no score: the call routes at low. */
  scores?: Record<string, Score>;
  /** Usage of a cap for one group key. null means the history can't be read, which counts as breached. */
  capUsage(capId: string, groupKey: string): CapUsage | null;
  /** Rows that currently have an open execution context in this session. */
  openContexts: ReadonlySet<string>;
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
  policy: { matrix: { id: string; version: string }; binding: { id: string; version: string } };
}

export type CompileResult = { ok: true; policy: Policy } | { ok: false; findings: Finding[] };

type Validated = any;

export interface Policy {
  matrix: Validated;
  binding: Validated;
  rowByCapability: ReadonlyMap<string, Validated>;
  rowById: ReadonlyMap<string, Validated>;
}
