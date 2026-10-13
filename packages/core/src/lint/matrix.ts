// Matrix linter: JSON Schema validation, then the rules JSON Schema can't express.
// Fails closed: an unknown format or a schema failure is never ok, and the semantic rules only
// run on a document that passed its schema.
import { validateMatrix01, validateMatrix02, type Validator } from "../generated/validators.js";
import { durationSeconds } from "./duration.ts";
import { result, tok, type Finding, type LintResult, type Validated } from "./types.ts";
import { schemaFindings } from "./schema-findings.ts";
import { conditionShape, zeroDurations } from "./shape.ts";

export const MATRIX_FORMATS: Record<string, Validator> = {
  "vaom.matrix/0.1": validateMatrix01,
  "vaom.matrix/0.2": validateMatrix02,
};

export function lintMatrix(doc: unknown): LintResult {
  const format = isObject(doc) && typeof doc.format === "string" ? doc.format : null;
  const validate = format ? MATRIX_FORMATS[format] : undefined;
  if (!validate) {
    return result(format, [
      { rule: "format", severity: "error", path: "/format", message: `unknown or missing matrix format ${JSON.stringify(format)}; known: ${Object.keys(MATRIX_FORMATS).join(", ")}` },
    ]);
  }
  if (!validate(doc)) return result(format, schemaFindings(validate.errors));
  return result(format, semanticFindings(doc as Validated));
}

function semanticFindings(m: Validated): Finding[] {
  const out: Finding[] = [];
  const err = (rule: string, path: string, message: string) => out.push({ rule, severity: "error", path, message });
  const warn = (rule: string, path: string, message: string) => out.push({ rule, severity: "warning", path, message });

  const rows: Validated[] = m.rows;
  const roles: Record<string, Validated> = m.roles ?? {};
  const boundaries: Record<string, Validated> = m.boundaries ?? {};

  // Row ids are unique, and each capability belongs to exactly one row.
  const rowById = new Map<string, { row: Validated; i: number }>();
  rows.forEach((row, i) => {
    if (rowById.has(row.id)) err("row.duplicate-id", `/rows/${i}/id`, `row id ${row.id} is used more than once`);
    else rowById.set(row.id, { row, i });
  });
  const capOwner = new Map<string, { row: Validated; i: number }>();
  rows.forEach((row, i) => {
    (row.capabilities as string[]).forEach((cap, j) => {
      const prior = capOwner.get(cap);
      if (prior) err("capability.claimed-twice", `/rows/${i}/capabilities/${j}`, `capability ${cap} is claimed by rows ${prior.row.id} and ${row.id}; authority must attach to one decision type`);
      else capOwner.set(cap, { row, i });
    });
  });

  // Every role, boundary and row reference resolves. An unresolved reference rejects the matrix.
  walkRefs(m, "", (kind, value, path) => {
    if (kind === "role" && !(value in roles)) err("ref.role", path, `role ${value} is not declared in roles`);
    if (kind === "boundary" && !(value in boundaries)) err("ref.boundary", path, `boundary ${value} is not declared in boundaries`);
    if (kind === "row" && !rowById.has(value)) err("ref.row", path, `row ${value} does not exist`);
  });

  out.push(...zeroDurations(m));

  // Breaker ids are unique across the matrix, wherever the breaker is declared.
  const breakers = new Set<string>();
  const breakerIds = (list: Validated[] | undefined, path: string) => (list ?? []).forEach((b, k) => {
    if (breakers.has(b.id)) err("breaker.duplicate-id", `${path}/${k}/id`, `circuit breaker id ${b.id} is used more than once`);
    breakers.add(b.id);
  });
  breakerIds(m.circuitBreakers, "/circuitBreakers");
  rows.forEach((row, i) => breakerIds(row.circuitBreakers, `/rows/${i}/circuitBreakers`));

  if (m.effective?.until && Date.parse(m.effective.until) <= Date.parse(m.effective.from)) {
    err("effective.order", "/effective/until", "effective.until is not after effective.from");
  }

  rows.forEach((row, i) => {
    const p = `/rows/${i}`;
    const a = row.authority;

    // Accountability: nobody deputises for themselves, and a committee can't be accountable.
    const acc = row.accountability;
    const accountable: { role: string; deputy?: string; path: string }[] =
      acc.form === "single"
        ? [{ role: acc.role, deputy: acc.deputy, path: `${p}/accountability` }]
        : (acc.owners as Validated[]).map((o, k) => ({ role: o.role, deputy: o.deputy, path: `${p}/accountability/owners/${k}` }));
    for (const x of accountable) {
      if (x.deputy !== undefined && x.deputy === x.role) err("accountability.self-deputy", `${x.path}/deputy`, `role ${x.role} is its own deputy`);
      if (roles[x.role]?.kind === "committee") err("accountability.committee", `${x.path}/role`, `role ${x.role} is a committee; a committee can hold a consent right, never accountability`);
      if (x.deputy && roles[x.deputy]?.kind === "committee") err("accountability.committee", `${x.path}/deputy`, `deputy ${x.deputy} is a committee`);
    }

    if (a.kind === "preparatory") {
      (a.serves as string[]).forEach((s, k) => {
        const served = rowById.get(s)?.row;
        if (!served) return; // reported as ref.row
        if (served.authority.kind === "preparatory") err("preparatory.serves-preparatory", `${p}/authority/serves/${k}`, `preparatory row ${row.id} serves preparatory row ${s}; it may serve decision rows only`);
        else if (served.authority.kind === "non-delegable" && served.authority.agentMayPrepare !== true) err("preparatory.not-allowed", `${p}/authority/serves/${k}`, `row ${s} does not allow preparation (agentMayPrepare is not true)`);
      });
    }

    if (a.kind === "non-delegable") {
      const bs: string[] = a.boundaries ?? [];
      if (bs.length === 0) warn("structural.missing", `${p}/authority`, `non-delegable row ${row.id} names no boundary keeping it out of reach; make it structural`);
      bs.forEach((b, k) => {
        const mech = boundaries[b]?.intendedMechanism;
        if (mech && mech !== "absent") warn("structural.weak", `${p}/authority/boundaries/${k}`, `boundary ${b} is ${mech}; a non-delegable capability should be absent`);
      });
    }

    // Consent rights must exist as approval records before execution. v0.1 has no way to carry or check
    // them, so a matrix that declares one is refused rather than run with the right silently ignored.
    if ((a.requiredApprovals ?? []).length > 0) err("row.required-approvals-unsupported", `${p}/authority/requiredApprovals`, `row ${row.id} declares consent rights (requiredApprovals), which this version doesn't enforce; it would run without them`);

    // Ids within a row are unique: cap ids key the ledger, restriction ids name what was hit.
    const capIds = new Set<string>();
    for (const [list, key] of [[a.cumulativeCaps, "cumulativeCaps"], [a.rateCaps, "rateCaps"]] as const) {
      ((list ?? []) as Validated[]).forEach((c, k) => {
        if (capIds.has(c.id)) err("cap.duplicate-id", `${p}/authority/${key}/${k}/id`, `cap id ${c.id} is used more than once in row ${row.id}; caps sharing an id would share a ledger count`);
        capIds.add(c.id);
      });
    }
    const restrictionIds = new Set<string>();
    ((a.restrictions ?? []) as Validated[]).forEach((r, k) => {
      if (restrictionIds.has(r.id)) err("restriction.duplicate-id", `${p}/authority/restrictions/${k}/id`, `restriction id ${r.id} is used more than once in row ${row.id}`);
      restrictionIds.add(r.id);
      out.push(...conditionShape(r.when, `${p}/authority/restrictions/${k}/when`));
    });

    if (a.kind !== "delegable") return;

    const t = a.confidence?.thresholds;
    if (t && t.high < t.medium) err("confidence.threshold-order", `${p}/authority/confidence/thresholds`, `high (${t.high}) is below medium (${t.medium})`);

    // All money on a row is in one currency: amounts are never added or compared across currencies.
    const ceiling = a.valueCeiling?.limit?.currency;
    if (ceiling) {
      const d = a.valueCeiling.derivation ?? {};
      for (const k of ["frictionCost", "reviewCost", "riskAppetitePerEvent"]) {
        if (d[k] && d[k].currency !== ceiling) err("money.currency", `${p}/authority/valueCeiling/derivation/${k}/currency`, `${d[k].currency} differs from the ceiling's ${ceiling}`);
      }
      (a.cumulativeCaps ?? []).forEach((c: Validated, k: number) => {
        if (c.total && c.total.currency !== ceiling) err("money.currency", `${p}/authority/cumulativeCaps/${k}/total/currency`, `${c.total.currency} differs from the ceiling's ${ceiling}`);
      });
    }

    if (a.lease) {
      const l = durationSeconds(a.lease.lifetime), mx = durationSeconds(a.lease.maxLifetime);
      if (l !== null && mx !== null && l >= mx) err("lease.lifetime", `${p}/authority/lease/lifetime`, `lifetime ${a.lease.lifetime} is not shorter than maxLifetime ${a.lease.maxLifetime} (years and months counted as 365 and 30 days)`);
      (a.lease.observationCapabilities as string[]).forEach((cap, k) => {
        const owner = capOwner.get(cap)?.row;
        if (owner && owner.authority.kind !== "preparatory") err("lease.observation-executes", `${p}/authority/lease/observationCapabilities/${k}`, `observation capability ${cap} is a decision capability of row ${owner.id}; observation must never execute`);
      });
    }

    // A sub-agent only receives authority the matrix delegates: each capability is governed by a
    // delegable or preparatory row, never a non-delegable one, and never an unknown capability.
    (a.chain?.allowedSubagents ?? []).forEach((s: Validated, k: number) => {
      (s.capabilities as string[]).forEach((cap, c) => {
        const owner = capOwner.get(cap)?.row;
        const path = `${p}/authority/chain/allowedSubagents/${k}/capabilities/${c}`;
        if (!owner) err("chain.unknown-capability", path, `sub-agent capability ${cap} is not governed by any row`);
        else if (owner.authority.kind === "non-delegable") err("chain.non-delegable", path, `sub-agent capability ${cap} belongs to non-delegable row ${owner.id}`);
      });
    });
  });

  // Oversight is funded, not assumed: the review load fits the funded hours at the declared utilization.
  if (m.oversight) {
    let hours = 0;
    for (const row of rows) {
      const o = row.oversight;
      if (!o?.expectedPerWeek) continue;
      const e = o.expectedPerWeek;
      hours += ((e.B ?? 0) * (o.reviewMinutes ?? 0) + (e.C ?? 0) * (o.escalationMinutes ?? 0) + (e.A ?? 0) * (o.auditSampleRate ?? 0) * (o.auditMinutes ?? 0)) / 60;
    }
    const allowed = m.oversight.fundedReviewerHoursPerWeek * (m.oversight.maxUtilization ?? 0.8);
    if (hours > allowed) err("oversight.unfunded", "/oversight/fundedReviewerHoursPerWeek", `review load is ${hours.toFixed(2)} h/week but only ${allowed.toFixed(2)} h/week is funded at the declared utilization`);
  }

  return out;
}

type RefKind = "role" | "boundary" | "row";

/** Visit every reference in the matrix. The registries themselves (top-level roles and boundaries) aren't references. */
function walkRefs(node: unknown, path: string, visit: (kind: RefKind, value: string, path: string) => void, key?: string, parentKey?: string): void {
  if (typeof node === "string") {
    if (key === "role" || key === "deputy" || key === "reviewer") visit("role", node, path);
    else if (key === "boundary") visit("boundary", node, path);
    else if (parentKey === "notify") visit("role", node, path);
    else if (parentKey === "boundaries") visit("boundary", node, path);
    else if (parentKey === "serves") visit("row", node, path);
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((v, i) => walkRefs(v, `${path}/${i}`, visit, undefined, key));
    return;
  }
  if (isObject(node)) {
    for (const [k, v] of Object.entries(node)) {
      if (path === "" && (k === "roles" || k === "boundaries")) continue;
      walkRefs(v, `${path}/${tok(k)}`, visit, k, key);
    }
  }
}

function isObject(x: unknown): x is Record<string, Validated> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}
