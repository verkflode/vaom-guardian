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
import type { ContextRegistry } from "./authority/contexts.ts";
import type { CapLedger } from "./caps/ledger.ts";
import { evaluate } from "./eval/evaluate.ts";
import type { Call, FactValue, LiveContext, Policy } from "./eval/types.ts";
import { durationSeconds } from "./lint/duration.ts";
import { buildRecord, recordedGroup, recordFact, type DecisionRecord, type RecordedFact, type RecordInput } from "./record/record.ts";
import type { History } from "./scoring/score.ts";

export interface DecideInput extends Omit<RecordInput, "call" | "decision" | "policy"> {
  /** An independent verifier's verdict per capability. See EvalContext.verifications. */
  verifications?: Record<string, boolean>;
  /** The context registry; the session's live contexts at `ts` are the call's authority. None means no authority. */
  contexts?: ContextRegistry;
  /** Further live contexts, e.g. a lease's observation context (LeaseRegistry.observation). */
  extraContexts?: readonly LiveContext[];
}

export function decide(policy: Policy, call: Call, ledger: CapLedger, input: DecideInput): DecisionRecord {
  const record = place(policy, call, ledger, input);
  ledger.reserve(record);
  return record;
}

/**
 * The record decide() would build, with nothing reserved: no cap use, no history. For planting seeded
 * cases (a seed must show a reviewer exactly what a real ask would). Its record is never an answer to an
 * agent and is never stored as a decision.
 */
export function preview(policy: Policy, call: Call, ledger: CapLedger, input: DecideInput): DecisionRecord {
  return place(policy, call, ledger, input);
}

function place(policy: Policy, call: Call, ledger: CapLedger, input: DecideInput): DecisionRecord {
  const now = Date.parse(input.ts);
  if (Number.isNaN(now)) throw new Error(`decide: ts ${JSON.stringify(input.ts)} is not a timestamp`);

  const live: LiveContext[] = [...(input.contexts ? input.contexts.liveFor(input.session.id, now) : []), ...(input.extraContexts ?? [])];
  // History for anomaly signals is the ledger's, compared in the form records hold facts. A fact that
  // can't be put in that form (a digest with no key) makes the history unreadable, so the signal fires.
  const rec = (name: string, v: FactValue): RecordedFact | null => {
    try { return recordFact(policy, name, v, input.factKey); } catch { return null; }
  };
  const recGroup = (g: Record<string, FactValue>): Record<string, RecordedFact> | null => {
    const out: Record<string, RecordedFact> = {};
    for (const [k, v] of Object.entries(g)) { const r = rec(k, v); if (!r) return null; out[k] = r; }
    return out;
  };
  const history: History = {
    seen: (row, fact, v, w) => { const r = rec(fact, v); return r ? ledger.historySeen(row, fact, r, now, w) : null; },
    values: (row, fact, g, w) => { const r = recGroup(g); return r ? ledger.historyValues(row, fact, r, now, w) : null; },
    count: (row, g, w) => { const r = recGroup(g); return r ? ledger.historyCount(row, r, now, w) : null; },
  };

  const decision = evaluate(policy, call, {
    now,
    history,
    ...(input.verifications ? { verifications: input.verifications } : {}),
    contexts: live,
    capUsage: (row, capId, rawGroup) => {
      const a = policy.rowById.get(row)?.authority;
      const cap = [...(a?.cumulativeCaps ?? []), ...(a?.rateCaps ?? [])].find((c: { id: string }) => c.id === capId);
      const windowS = cap ? durationSeconds(cap.window) : null;
      if (!windowS) return null; // unknown or zero window: treat as unreadable, which breaches
      return ledger.usage(row, capId, recordedGroup(policy, row, capId, rawGroup, input.factKey), now, windowS * 1000);
    },
  });

  // Record the context the call ran under: the first one that authorised its first placement.
  const usedId = decision.placements[0]?.contexts?.[0];
  const used = usedId ? live.find((c) => c.id === usedId) : undefined;
  const { contexts: _registry, extraContexts: _extra, verifications: _verifications, ...recordInput } = input;
  const record = buildRecord({
    ...recordInput,
    ...(used && !input.context ? { context: { id: used.id, rows: [...used.rows] } } : {}),
    call, decision, policy,
  });
  return record;
}
