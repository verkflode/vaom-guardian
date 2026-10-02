// decide(): evaluate a call against the cap ledger, build its decision record, and reserve its cap uses,
// in one synchronous step. Nothing can run between reading cap usage and reserving it, so parallel calls
// can't each see room under a cap that only one of them fits in. (Splitting an action into parallel calls
// to slip under a cap is a named attack; see the tests.)
//
// If the record can't be built, decide() throws and reserves nothing. The caller must treat that as a
// decision failure, which in this Guardian means deny: no evidence, no action. If persisting the record
// later fails, the caller releases the reservation and denies.
//
// A ledger whose history isn't loaded makes decide() throw (reserve refuses), so a Guardian makes no
// decision at all until it knows what has already been used. That's stricter than reading every cap as
// breached, which would still let a call through to review against unknown usage.
import type { CapLedger } from "./caps/ledger.ts";
import { evaluate } from "./eval/evaluate.ts";
import type { Call, Policy, Score } from "./eval/types.ts";
import { durationSeconds } from "./lint/duration.ts";
import { buildRecord, recordedGroup, type DecisionRecord, type RecordInput } from "./record/record.ts";

export interface DecideInput extends Omit<RecordInput, "call" | "decision" | "policy" | "scores"> {
  scores?: Record<string, Score>;
  /** Rows with an open execution context in this session. */
  openContexts?: ReadonlySet<string>;
}

export function decide(policy: Policy, call: Call, ledger: CapLedger, input: DecideInput): DecisionRecord {
  const now = Date.parse(input.ts);
  if (Number.isNaN(now)) throw new Error(`decide: ts ${JSON.stringify(input.ts)} is not a timestamp`);

  const decision = evaluate(policy, call, {
    ...(input.scores ? { scores: input.scores } : {}),
    openContexts: input.openContexts ?? new Set(),
    capUsage: (row, capId, rawGroup) => {
      const a = policy.rowById.get(row)?.authority;
      const cap = [...(a?.cumulativeCaps ?? []), ...(a?.rateCaps ?? [])].find((c: { id: string }) => c.id === capId);
      const windowS = cap ? durationSeconds(cap.window) : null;
      if (windowS === null) return null; // unknown window: treat as unreadable, which breaches
      return ledger.usage(row, capId, recordedGroup(policy, row, capId, rawGroup, input.factKey), now, windowS * 1000);
    },
  });

  const { openContexts: _contexts, ...recordInput } = input;
  const record = buildRecord({ ...recordInput, call, decision, policy, ...(input.scores ? { scores: input.scores } : {}) });
  ledger.reserve(record);
  return record;
}
