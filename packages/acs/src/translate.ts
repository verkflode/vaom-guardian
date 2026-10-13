// Translation between ACS and the core. The core never sees an ACS type; this is the only place both meet.
//
// Dispositions (brief §5B, checked against ACS v0.1.0 §6 and §9):
//   allow        -> allow
//   review       -> ask, approver = the row's reviewer, timeout_disposition deny
//   escalate     -> ask, approver = the row's escalation role, timeout_disposition deny
//   refuse       -> deny, reason_codes ["non_delegable"]
//   unplaceable  -> defer, timeout_decision deny
// Reasons go on the wire as codes only: details can quote fact values a binding records privately.
import type { Call, Decision } from "@verkflode/vaom-guardian-core";

type Json = Record<string, unknown>;

/** toolCallRequest payload (already schema-checked) to a core Call. Arguments arrive wrapped as
 *  {value, provenance}; the core gets plain values. The wire capability is passed on for checking only. */
export function toCall(payload: { tool: { name: string }; arguments: Record<string, { value: unknown }>; capability?: string }): Call {
  const args: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload.arguments)) args[k] = v.value;
  return { tool: payload.tool.name, arguments: args, ...(payload.capability !== undefined ? { declaredCapability: payload.capability } : {}) };
}

export interface ResultOptions {
  requestId: string;
  /** The ACS version the session negotiated. */
  acsVersion: string;
  approvalTimeoutSeconds: number;
  deferTimeoutMs: number;
  evaluatorVersion: string;
}

/** What toResult reads from a decision: a core Decision, or the decision part of a record. */
export interface ResultInput {
  outcome: Decision["outcome"];
  band: Decision["band"];
  approverRole?: string;
  placements: readonly { row: string; capability: string }[];
  reasons: readonly { code: string }[];
  policy: Decision["policy"];
}

export function toResult(d: ResultInput, o: ResultOptions): Json {
  const codes = [...new Set(d.reasons.map((r) => r.code))];
  const rows = [...new Set(d.placements.map((p) => p.row))];
  const base: Json = {
    type: "final",
    acs_version: o.acsVersion,
    request_id: o.requestId,
    reason_codes: codes,
    policy_references: [
      ...rows.map((row) => ({ policy_id: d.policy.matrix.id, policy_version: d.policy.matrix.version, rule_id: row })),
      { policy_id: d.policy.binding.id, policy_version: d.policy.binding.version, policy_name: "binding" },
    ],
    metadata: { evaluator: "deterministic", evaluator_version: o.evaluatorVersion },
  };
  switch (d.outcome) {
    case "allow":
      return { ...base, decision: "allow", reasoning: d.band === null ? "Preparatory call inside an open execution context." : `Band ${d.band}: within delegated authority.` };
    case "review":
    case "escalate":
      return {
        ...base,
        decision: "ask",
        reasoning: `Band ${d.band}: needs approval by ${d.approverRole}.`,
        ask_details: {
          approver: { type: "human", id: d.approverRole },
          question: `Approve this ${d.placements[0]?.capability ?? "action"} (matrix row ${rows.join(", ")})?`,
          timeout_seconds: o.approvalTimeoutSeconds,
          timeout_disposition: "deny",
        },
      };
    case "refuse":
      return { ...base, decision: "deny", reasoning: "Non-delegable: the agent never executes this, whoever approves.", reason_codes: [...new Set(["non_delegable", ...codes])] };
    case "unplaceable": {
      const conflict = codes.includes("approver.conflict") || codes.includes("capability.mismatch");
      return {
        ...base,
        decision: "defer",
        reasoning: "The Guardian can't place this call in a band, so it can't be allowed.",
        defer_details: {
          reason: conflict ? "conflicting_policies" : "insufficient_context",
          resolution_method: "timeout",
          resolution_timeout_ms: o.deferTimeoutMs,
          timeout_decision: "deny",
        },
      };
    }
  }
}
