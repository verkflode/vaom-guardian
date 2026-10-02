// Decision records, format vaom.decision/0.3: one decision, replayable.
//
// Privacy by construction:
// - Tool arguments are never stored: only the SHA-256 of their JCS form.
// - Each fact is recorded as the binding says: in clear, as an HMAC-SHA256 digest, or omitted.
// - A cap group whose facts aren't all recorded in clear is stored as a digest too. (A value cap's
//   amount stays in its reservation whatever the fact's mode: summing needs it.)
// - Ceiling and cap reasons, which quote amounts, lose their detail when that amount isn't in clear.
// Failing to build a record throws RecordError. The Guardian treats that as a decision failure
// (deny): no evidence, no action.
import { canonicalize } from "../canonical/jcs.ts";
import { hex, hmacSha256, sha256, utf8 } from "../crypto/sha256.ts";
import type { Call, Decision, FactValue, Policy, Reason, Score } from "../eval/types.ts";
import { validateDecision03 } from "../generated/validators.js";
import { schemaFindings } from "../lint/schema-findings.ts";
import type { Finding } from "../lint/types.ts";

export const RECORD_FORMAT = "vaom.decision/0.3";

export class RecordError extends Error {
  override name = "RecordError";
}

export type RecordedFact = { value: FactValue } | { digest: string } | { omitted: true };

export interface DecisionRecord {
  format: typeof RECORD_FORMAT;
  id: string;
  request: {
    ts: string;
    agent: { id: string; version?: string; model?: { id: string; version?: string } };
    session: { id: string; unattended?: boolean };
    context?: { id: string; rows: string[]; lease?: string };
    action: { tool: string; params_digest: string; declared_capability?: string };
    scores?: Record<string, { value: number; policy: { id: string; version: string }; verified?: boolean }>;
    wire?: { protocol: string; version: string; request_id?: string; chain_hash?: string };
  };
  policy: Decision["policy"];
  decision: {
    outcome: Decision["outcome"];
    band: Decision["band"];
    approver_role?: string;
    placements: { row: string; capability: string; entry: string; band: Decision["band"]; outcome: Decision["outcome"]; approver_role?: string; facts: Record<string, RecordedFact> }[];
    reasons: Reason[];
  };
  reservations: { cap: string; row: string; group: string; amount?: string; count: 1 }[];
  resolution?: Resolution;
}

export interface Resolution {
  ts: string;
  result: "executed" | "rejected" | "expired" | "withdrawn" | "not-executed";
  approval?: { approver_role: string; approver_id?: string; record: string; latency_ms?: number };
}

export interface RecordInput {
  id: string;
  ts: string;
  agent: DecisionRecord["request"]["agent"];
  session: DecisionRecord["request"]["session"];
  context?: DecisionRecord["request"]["context"];
  wire?: DecisionRecord["request"]["wire"];
  call: Call;
  decision: Decision;
  policy: Policy;
  /** The scores the evaluation was given; only those for capabilities the call touched are recorded. */
  scores?: Record<string, Score>;
  /** HMAC key for digest-mode facts and private cap groups. Held outside the agent's reach; never stored. */
  factKey?: Uint8Array;
}

export function buildRecord(input: RecordInput): DecisionRecord {
  const { call, decision, policy } = input;
  const factDefs = policy.binding.facts as Record<string, { record?: "value" | "digest" | "omit" }>;
  const mode = (name: string) => factDefs[name]?.record ?? "value";
  const digest = (data: string): string => {
    if (!input.factKey || input.factKey.length === 0) throw new RecordError("a fact or cap group must be recorded as a digest, but no fact key was given");
    return `hmac-sha256:${hex(hmacSha256(input.factKey, utf8(data)))}`;
  };

  let paramsJcs: string;
  try {
    paramsJcs = canonicalize(call.arguments);
  } catch (e) {
    throw new RecordError(`the call's arguments aren't JSON: ${(e as Error).message}`);
  }

  const placements = decision.placements.map((p) => {
    const facts: Record<string, RecordedFact> = {};
    for (const [name, value] of Object.entries(p.facts)) {
      const m = mode(name);
      facts[name] = m === "value" ? { value } : m === "omit" ? { omitted: true } : { digest: digest(canonicalize(value)) };
    }
    return { row: p.row, capability: p.capability, entry: p.entry, band: p.band, outcome: p.outcome, ...(p.approverRole ? { approver_role: p.approverRole } : {}), facts };
  });

  // Which rows' amounts may be quoted: only where every money fact behind a ceiling or value cap is in clear.
  const amountsPrivate = new Set<string>();
  for (const p of decision.placements) {
    const a = policy.rowById.get(p.row)?.authority;
    const moneyFacts = [a?.valueCeiling?.fact, ...((a?.cumulativeCaps ?? []) as { total?: unknown; fact?: string }[]).filter((c) => c.total).map((c) => c.fact)].filter(Boolean) as string[];
    if (moneyFacts.some((f) => mode(f) !== "value")) amountsPrivate.add(p.row);
  }
  const reasons = decision.reasons.map((r) =>
    (r.code === "ceiling.exceeded" || r.code === "cap.breached") && r.row && amountsPrivate.has(r.row) ? { code: r.code, row: r.row } : r,
  );

  const reservations = decision.reservations.map((res) => ({
    cap: res.capId,
    row: res.row,
    group: recordedGroup(policy, res.row, res.capId, res.groupKey, input.factKey),
    ...(res.amount !== undefined ? { amount: res.amount } : {}),
    count: 1 as const,
  }));

  const touched = new Set(decision.placements.map((p) => p.capability));
  const scores = Object.fromEntries(
    Object.entries(input.scores ?? {})
      .filter(([cap]) => touched.has(cap))
      .map(([cap, s]) => [cap, { value: s.value, policy: s.policy, ...(s.verified !== undefined ? { verified: s.verified } : {}) }]),
  );

  const record: DecisionRecord = {
    format: RECORD_FORMAT,
    id: input.id,
    request: {
      ts: input.ts,
      agent: input.agent,
      session: input.session,
      ...(input.context ? { context: input.context } : {}),
      action: { tool: call.tool, params_digest: `sha256:${hex(sha256(utf8(paramsJcs)))}`, ...(call.declaredCapability ? { declared_capability: call.declaredCapability } : {}) },
      ...(Object.keys(scores).length ? { scores } : {}),
      ...(input.wire ? { wire: input.wire } : {}),
    },
    policy: decision.policy,
    decision: { outcome: decision.outcome, band: decision.band, ...(decision.approverRole ? { approver_role: decision.approverRole } : {}), placements, reasons },
    reservations,
  };
  const problems = checkRecord(record);
  if (problems.length) throw new RecordError(`built record fails its schema: ${problems.map((f) => `${f.path} ${f.message}`).join("; ")}`);
  return record;
}

/**
 * The form a cap group takes in records, and therefore in the cap ledger: the evaluator's raw key when
 * every grouped fact is recorded in clear, otherwise its HMAC digest. One function for both, so a ledger
 * rebuilt from records matches the live one exactly.
 */
export function recordedGroup(policy: Policy, row: string, capId: string, rawKey: string, factKey: Uint8Array | undefined): string {
  const factDefs = policy.binding.facts as Record<string, { record?: string }>;
  const a = policy.rowById.get(row)?.authority;
  const caps = [...(a?.cumulativeCaps ?? []), ...(a?.rateCaps ?? [])] as { id: string; groupBy?: string[] }[];
  const groupBy = caps.find((c) => c.id === capId)?.groupBy ?? [];
  if (groupBy.every((g) => (factDefs[g]?.record ?? "value") === "value")) return rawKey;
  if (!factKey || factKey.length === 0) throw new RecordError("a cap group must be recorded as a digest, but no fact key was given");
  return `hmac-sha256:${hex(hmacSha256(factKey, utf8(rawKey)))}`;
}

/** Add the resolution. Refuses one that contradicts the decision: nothing refused or unplaceable executes,
 *  and a review or escalation executes only on an approval record. */
export function resolveRecord(record: DecisionRecord, resolution: Resolution): DecisionRecord {
  if (record.resolution) throw new RecordError("record is already resolved");
  const o = record.decision.outcome;
  if ((o === "refuse" || o === "unplaceable") && resolution.result !== "not-executed") throw new RecordError(`a ${o} decision can only resolve as not-executed`);
  if ((o === "review" || o === "escalate") && resolution.result === "executed") {
    if (!resolution.approval) throw new RecordError(`a ${o} decision executes only on an approval record`);
    if (resolution.approval.approver_role !== record.decision.approver_role) throw new RecordError(`approval came from ${resolution.approval.approver_role}, but the decision named ${record.decision.approver_role}`);
  }
  if (o === "allow" && resolution.result === "rejected") throw new RecordError("an allow decision has no approver to reject it");
  const resolved: DecisionRecord = { ...record, resolution };
  const problems = checkRecord(resolved);
  if (problems.length) throw new RecordError(`resolved record fails its schema: ${problems.map((f) => `${f.path} ${f.message}`).join("; ")}`);
  return resolved;
}

/** Validate a record against the vaom.decision/0.3 schema. Empty means valid. */
export function checkRecord(record: unknown): Finding[] {
  return validateDecision03(record) ? [] : schemaFindings(validateDecision03.errors);
}
