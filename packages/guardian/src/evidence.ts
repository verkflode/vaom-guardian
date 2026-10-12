// Offline verification of a Guardian's evidence, trusting nothing but the files and the matrix:
// every record against its schema, every session's hash chain, every approval's WebAuthn assertion
// (recomputing its challenge from the stored preimage), and every executed review or escalation against
// an approval that names the same decision and role. Seeded cases: every approved seed's assertion is
// checked like an approval, and no seed may ever appear as a decision record or be approved as one.
import { createHash, randomUUID } from "node:crypto";
import { verifyChain, type ContextEntry } from "@verkflode/vaom-guardian-acs";
import { canonicalize, checkProbeResult, checkRecord, type ProbeResult } from "@verkflode/vaom-guardian-core";
import type { Store } from "./store.ts";
import { b64url, verifyAssertion, type Jwk } from "./webauthn.ts";

export interface EvidenceReport {
  records: number;
  sessions: number;
  approvals: number;
  seeds: number;
  problems: string[];
}

export function verifyEvidence(store: Store, origin: string, rpId = "localhost"): EvidenceReport {
  const problems: string[] = [];
  const records = store.records();
  for (const r of records) for (const f of checkRecord(r)) problems.push(`record ${r.id}: ${f.path} ${f.message}`);

  const bySession = new Map<string, ContextEntry[]>();
  for (const { session, entry } of store.chain()) bySession.set(session, [...(bySession.get(session) ?? []), entry]);
  for (const [s, entries] of bySession) if (!verifyChain(entries)) problems.push(`session ${s}: hash chain does not verify`);

  const events = store.events();
  const keys = new Map<string, { jwk: Jwk; roles: string[] }>();
  const approvals = new Map<string, { decision: string; role: string }>();
  const seeds = new Set(events.filter((e) => e.type === "seed-planted").map((e) => e.decision as string));
  for (const e of events) {
    if (e.type === "enrolled") keys.set(e.credential_id as string, { jwk: e.jwk as Jwk, roles: e.roles as string[] });
    const seedApproval = e.type === "seed-outcome" && e.result === "missed";
    if (e.type !== "approval" && !seedApproval) continue;
    if (e.type === "approval" && seeds.has(e.decision as string)) problems.push(`approval ${e.id}: approves a planted case as a real decision`);
    const key = keys.get(e.credential_id as string);
    if (!key) { problems.push(`${e.type} ${e.id}: credential was never enrolled`); continue; }
    if (!key.roles.includes(e.approver_role as string)) problems.push(`${e.type} ${e.id}: credential doesn't hold ${e.approver_role}`);
    const pre = e.challenge_preimage as Record<string, string>;
    if (pre.decision !== e.decision || pre.approver_role !== e.approver_role || pre.request_id !== e.request_id) problems.push(`${e.type} ${e.id}: challenge preimage names a different decision`);
    const challenge = b64url.encode(new Uint8Array(createHash("sha256").update(canonicalize(pre)).digest()));
    const a = e.assertion as { authenticator_data: string; client_data_json: string; signature: string };
    try {
      // Counter monotonicity was enforced live; offline, -1 accepts any counter.
      verifyAssertion({ credentialId: e.credential_id as string, authenticatorData: a.authenticator_data, clientDataJSON: a.client_data_json, signature: a.signature }, { id: e.credential_id as string, jwk: key.jwk, signCount: -1 }, { challenge, origin, rpId });
    } catch (err) { problems.push(`${e.type} ${e.id}: ${(err as Error).message}`); }
    if (seedApproval) continue;
    const rec = records.find((r) => r.id === e.decision);
    if (rec && rec.request.action.params_digest !== pre.params_digest) problems.push(`approval ${e.id}: approved different arguments than the decision recorded`);
    approvals.set(e.id, { decision: e.decision as string, role: e.approver_role as string });
  }
  for (const r of records) if (seeds.has(r.id)) problems.push(`record ${r.id}: a planted case became a decision record`);
  // Every seed outcome belongs to a planted seed, once: an outcome with no planting, or a second outcome for
  // the same seed, would skew the detection rate.
  const decided = new Set<string>();
  for (const e of events) {
    if (e.type !== "seed-outcome") continue;
    const d = e.decision as string;
    if (!seeds.has(d)) problems.push(`seed outcome ${e.id}: no planted seed ${d}`);
    else if (decided.has(d)) problems.push(`seed outcome ${e.id}: seed ${d} already has an outcome`);
    decided.add(d);
  }

  for (const r of records) {
    const o = r.decision.outcome;
    if ((o === "review" || o === "escalate") && r.resolution?.result === "executed") {
      const ap = r.resolution.approval ? approvals.get(r.resolution.approval.record) : undefined;
      if (!ap) problems.push(`record ${r.id}: executed without a verifiable approval`);
      else if (ap.decision !== r.id || ap.role !== r.decision.approver_role) problems.push(`record ${r.id}: its approval belongs to another decision or role`);
    }
    if ((o === "refuse" || o === "unplaceable") && r.resolution && r.resolution.result !== "not-executed") problems.push(`record ${r.id}: a ${o} decision resolved as ${r.resolution.result}`);
  }
  for (const e of events) if (e.type === "probe-result") for (const f of checkProbeResult(e.result)) problems.push(`probe result ${e.id}: ${f.path} ${f.message}`);
  for (const e of events) if (e.type === "incident") problems.push(`incident ${e.id}: ${e.kind}${e.why ? ` (${e.why})` : ""}`);
  return { records: records.length, sessions: bySession.size, approvals: approvals.size, seeds: seeds.size, problems };
}

/**
 * Append boundary probe results to the store, each checked against its schema and the matrix first. All
 * or nothing: if any result is rejected, none is stored. A result is the runner's claim; the store keeps it
 * as evidence, append-only, and the same result id is never stored twice.
 */
export function importProbeResults(store: Store, matrix: { boundaries?: Record<string, unknown>; id?: string }, files: { name: string; result: unknown }[]): { imported: ProbeResult[]; duplicates: string[]; rejected: { name: string; why: string }[] } {
  const known = new Set(store.events().filter((e) => e.type === "probe-result").map((e) => (e.result as ProbeResult).id));
  const imported: ProbeResult[] = [], duplicates: string[] = [], rejected: { name: string; why: string }[] = [];
  for (const f of files) {
    const problems = checkProbeResult(f.result).map((x) => `${x.path} ${x.message}`);
    const r = f.result as ProbeResult;
    if (!problems.length && !(r.boundary in (matrix.boundaries ?? {}))) problems.push(`boundary ${r.boundary} isn't in matrix ${matrix.id ?? ""}`);
    if (problems.length) { rejected.push({ name: f.name, why: problems.join("; ") }); continue; }
    if (known.has(r.id)) { duplicates.push(f.name); continue; }
    known.add(r.id);
    imported.push(r);
  }
  if (rejected.length) return { imported: [], duplicates, rejected };
  const ts = new Date().toISOString();
  store.appendEvents(imported.map((r) => ({ type: "probe-result", id: randomUUID(), ts, result: r })));
  return { imported, duplicates, rejected };
}
