// Schema tests for vaom.matrix. The shared cases run against both 0.1 (frozen) and 0.2 (draft), so the
// invariants they check are checked on both versions. Each case mutates the version's invoice example once.
// Names starting "POS-" must validate; every other case must be rejected.
// Plus an exhaustive routing check against an oracle written independently of the schema's pair rules,
// 0.2-only cases for preparatory rows, and a prototype of the matrix linter's preparatory rules.
// Needs ajv and ajv-formats resolvable from here; see README.md.
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const read = (p) => readFileSync(here(p), "utf8");
// strictRequired/strictTypes are ajv lints that misfire on if/then; the schema is valid 2020-12.
const ajv = new Ajv({ strict: true, strictRequired: false, strictTypes: false, allErrors: true });
addFormats(ajv);
const versions = {
  "0.1": { validate: ajv.compile(JSON.parse(read("../vaom-matrix-0.1.schema.json"))), example: read("../examples/invoice.matrix-0.1.json") },
  "0.2": { validate: ajv.compile(JSON.parse(read("../vaom-matrix-0.2.schema.json"))), example: read("../examples/invoice.matrix-0.2.json") },
};

const R = (m, h, md, l) => { m.rows[0].authority.routing = { high: h, medium: md, low: l }; };
const shared = m => { m.rows[0].accountability = { form: "shared", owners: [
  { role: "ap-owner", deputy: "ap-deputy", answersFor: "x", accepted: { role: "ap-owner", date: "2026-09-29" } },
  { role: "finance-controller", deputy: "ap-deputy", answersFor: "y", accepted: { role: "finance-controller", date: "2026-09-29" } } ],
  gapCheckRef: "g", arrangementRef: "a", stopRule: "any-suspends-all-resume" }; };
// Triage row at Band A, modelled on the complaint-classification row (fully reversible, internally
// scoped, 2% misrouting target). A route carries no amount, so it needs no value ceiling.
const triageA = m => {
  const r = m.rows[1];
  r.profile.confidenceMeasurability = "quantifiable";
  r.profile.consequenceScope = "internal-operational";
  r.authority.routing = { high: "A", medium: "B", low: "C" };
  r.authority.confidence.calibration = { errorTarget: 0.02, confidenceLevel: 0.95, sampleSize: 1000, sampleDate: "2026-09-01" };
  r.oversight.auditSampleRate = 0.02; r.oversight.auditMinutes = 3;
};

const cases = {
  "a-without-calibration": m => { delete m.rows[0].authority.confidence.calibration; },
  "seeding-on-regulatory-row": m => { m.rows[0].oversight.seeding = { enabled: true, rate: 0.01, targetDetectionRate: 0.9 }; },
  "seeding-without-recordsFeed": m => { m.rows[1].oversight.seeding = { enabled: true, rate: 0.01, targetDetectionRate: 0.9 }; },
  "restriction-widens-to-a": m => { m.rows[0].authority.restrictions = [{ id: "x", when: { fact: "pep", op: "eq", value: false }, band: "A" }]; },
  "cap-breach-to-a": m => { m.rows[0].authority.cumulativeCaps[0].onBreach = "A"; },
  "judgment-dependent-a": m => { m.rows[0].profile.confidenceMeasurability = "judgment-dependent"; },
  "prohibited-automation-a": m => { m.rows[0].profile.regulatoryExposure = "prohibited-from-full-automation"; },
  "regulated-a-no-justification": m => { m.rows[0].profile.regulatoryExposure = "regulated-decision"; },
  "ambiguous-owner-delegable": m => { m.rows[1].profile.accountabilityClarity = "ambiguous"; },
  "reviewer-metrics-no-dpia": m => { m.oversight.reviewerLevelMetrics.enabled = true; },
  "breaker-resumes": m => { m.circuitBreakers[0].action = "resume"; },
  "lease-lapse-extends": m => { m.rows[0].authority.lease = { observationCapabilities: [], lifetime: "PT1H", maxLifetime: "P30D", responseContextLifetime: "PT10M", reattestation: { onLapse: "extend" } }; },
  "float-amount": m => { m.rows[0].authority.valueCeiling.limit.amount = 5000; },
  "route-B-B-A": m => R(m, "B", "B", "A"),
  "route-B-A-C": m => R(m, "B", "A", "C"),
  "route-C-C-A": m => R(m, "C", "C", "A"),
  "route-C-B-C": m => R(m, "C", "B", "C"),
  "route-A-C-B": m => R(m, "A", "C", "B"),
  "POS-route-A-A-A": m => R(m, "A", "A", "A"),
  "POS-route-A-B-B": m => R(m, "A", "B", "B"),
  "POS-route-B-B-B": m => R(m, "B", "B", "B"),
  "no-workflow-oversight": m => { delete m.oversight; },
  "delegable-row-no-oversight": m => { delete m.rows[1].oversight; },
  "delegable-row-no-review-minutes": m => { delete m.rows[1].oversight.reviewMinutes; },
  "band-a-no-audit-sample": m => { delete m.rows[0].oversight.auditSampleRate; },
  "POS-only-nondelegable-no-oversight": m => { m.rows = [m.rows[2]]; delete m.oversight; },
  "POS-shared-with-deputies": shared,
  "shared-owner-missing-deputy": m => { shared(m); delete m.rows[0].accountability.owners[1].deputy; },
  "shared-top-level-deputy": m => { shared(m); m.rows[0].accountability.deputy = "ap-deputy"; },
  "single-missing-deputy": m => { delete m.rows[0].accountability.deputy; },
  "no-approval": m => { delete m.approval; },
  "decision-row-without-pattern": m => { delete m.rows[0].pattern; },
  "decision-row-without-profile": m => { delete m.rows[2].profile; },
  "POS-triage-band-a-audited": triageA,
  "triage-band-a-no-audit": m => { triageA(m); delete m.rows[1].oversight.auditSampleRate; },
  "triage-band-a-zero-audit": m => { triageA(m); m.rows[1].oversight.auditSampleRate = 0; },
  "band-a-zero-audit": m => { m.rows[0].oversight.auditSampleRate = 0; },
  "POS-band-b-row-zero-audit": m => { m.rows[1].oversight.auditSampleRate = 0; },
  "POS-seeding-where-nothing-sensitive": m => { m.rows[1].oversight.recordsFeed = []; m.rows[1].oversight.seeding = { enabled: true, rate: 0.01, targetDetectionRate: 0.9 }; },
  "seeding-on-investigations": m => { m.rows[1].oversight.recordsFeed = ["investigations"]; m.rows[1].oversight.seeding = { enabled: true, rate: 0.01, targetDetectionRate: 0.9 }; },
  "POS-regulated-a-justified": m => { m.rows[0].profile.regulatoryExposure = "regulated-decision";
    m.rows[0].authority.regulatedJustification = { retainedByHuman: "x", whyNarrower: "y", bounds: "z" }; }
};

let wrong = 0;
const run = (label, validate, doc, want) => {
  const got = validate(doc);
  if (got !== want) { wrong++; console.log("WRONG", label, "valid:", got, "expected:", want); }
};
const rank = { A: 0, B: 1, C: 2 };
const summary = [];

for (const [v, { validate, example }] of Object.entries(versions)) {
  const base = () => JSON.parse(example);
  run(`${v} example`, validate, base(), true);
  for (const [name, mutate] of Object.entries(cases)) { const m = base(); mutate(m); run(`${v} ${name}`, validate, m, name.startsWith("POS-")); }
  let accepted = 0;
  for (const h of "ABC") for (const md of "ABC") for (const l of "ABC") {
    const m = base(); m.rows[0].authority.routing = { high: h, medium: md, low: l };
    const want = rank[h] <= rank[md] && rank[md] <= rank[l];
    if (want) accepted++;
    run(`${v} routing ${h}${md}${l}`, validate, m, want);
  }
  // Review load of the example against funded hours (Condition 6). Arithmetic JSON Schema can't do;
  // the matrix linter will own this check, and until then it guards the example.
  const ex = base();
  const load = ex.rows.reduce((sum, r) => {
    const o = r.oversight; if (!o) return sum; const e = o.expectedPerWeek;
    return sum + ((e.B ?? 0) * o.reviewMinutes + (e.C ?? 0) * o.escalationMinutes + (e.A ?? 0) * (o.auditSampleRate ?? 0) * (o.auditMinutes ?? 0)) / 60;
  }, 0);
  const allowed = ex.oversight.fundedReviewerHoursPerWeek * (ex.oversight.maxUtilization ?? 0.8);
  if (load > allowed) { wrong++; console.log(`WRONG ${v} example review load ${load.toFixed(2)} h/week exceeds ${allowed.toFixed(2)} allowed`); }
  summary.push(`${v}: example + ${Object.keys(cases).length} mutations + 27 routings (${accepted} monotone), load ${load.toFixed(2)}/${allowed.toFixed(2)} h`);
}

// Each version rejects the other's example: the format identifier is a hard gate.
run("0.1 rejects 0.2 example", versions["0.1"].validate, JSON.parse(versions["0.2"].example), false);
run("0.2 rejects 0.1 example", versions["0.2"].validate, JSON.parse(versions["0.1"].example), false);

// 0.2-only: preparatory rows. rows[3] is invoice.prepare, rows[4] is contract.prepare.
const base2 = () => JSON.parse(versions["0.2"].example);
const prep = (m) => m.rows[3];
const prepCases = {
  "prep-with-pattern": m => { prep(m).pattern = "execute-and-audit"; },
  "prep-with-profile": m => { prep(m).profile = structuredClone(m.rows[0].profile); },
  "prep-without-serves": m => { delete prep(m).authority.serves; },
  "prep-serves-empty": m => { prep(m).authority.serves = []; },
  "prep-effect-write": m => { prep(m).authority.effect = "write"; },
  "prep-without-effect": m => { delete prep(m).authority.effect; },
  "prep-with-routing": m => { prep(m).authority.routing = { high: "A", medium: "A", low: "A" }; },
  "prep-with-reviewer": m => { prep(m).authority.reviewer = "ap-clerk"; },
  "prep-rate-cap-by-value": m => { prep(m).authority.rateCaps[0].total = { amount: "1", currency: "EUR" }; prep(m).authority.rateCaps[0].fact = "amount"; },
  "prep-rate-cap-without-count": m => { delete prep(m).authority.rateCaps[0].count; },
  "prep-rate-cap-breach-to-b": m => { prep(m).authority.rateCaps[0].onBreach = "B"; },
  "prep-restriction-to-c": m => { prep(m).authority.restrictions = [{ id: "x", when: { fact: "category", op: "eq", value: "hr" }, band: "C" }]; },
  "POS-prep-restriction-refuses": m => { prep(m).authority.restrictions = [{ id: "x", when: { fact: "category", op: "eq", value: "hr" }, band: "non-delegable" }]; },
  "POS-prep-draft": m => { m.rows[4].authority.effect = "draft"; },
  "POS-prep-with-breaker": m => { prep(m).circuitBreakers = [{ id: "read-burst", condition: { kind: "volume-per-context", threshold: 200, window: "PT1H" }, action: "suspend" }]; },
  "POS-only-prep-and-nondelegable-no-oversight": m => { m.rows = [m.rows[2], m.rows[4]]; delete m.oversight; },
  // Value ceilings: silence must not mean unbounded on financial or external Band A rows (0.2 only).
  "ceiling-financial-a-silent": m => { delete m.rows[0].authority.valueCeiling; },
  "POS-ceiling-financial-a-explicit-none": m => { delete m.rows[0].authority.valueCeiling; m.rows[0].authority.noValueCeiling = { reason: "x", approvedBy: { role: "ap-owner", date: "2026-10-01" } }; },
  "ceiling-none-without-approval": m => { delete m.rows[0].authority.valueCeiling; m.rows[0].authority.noValueCeiling = { reason: "x" }; },
  "ceiling-both-ceiling-and-none": m => { m.rows[0].authority.noValueCeiling = { reason: "x", approvedBy: { role: "ap-owner", date: "2026-10-01" } }; },
  "POS-ceiling-operational-a-silent": m => { m.rows[0].profile.consequenceScope = "internal-operational"; delete m.rows[0].authority.valueCeiling; },
  "ceiling-external-a-silent": m => { m.rows[0].profile.consequenceScope = "external-relational"; delete m.rows[0].authority.valueCeiling; },
};
for (const [name, mutate] of Object.entries(prepCases)) { const m = base2(); mutate(m); run(`0.2 ${name}`, versions["0.2"].validate, m, name.startsWith("POS-")); }
// Known gap, kept visible: frozen 0.1 still accepts a financial Band A row with no ceiling. 0.2 closes it.
{ const m = JSON.parse(versions["0.1"].example); delete m.rows[0].authority.valueCeiling; run("0.1 frozen gap: silent ceiling still validates", versions["0.1"].validate, m, true); }

// Prototype matrix linter, preparatory rules only (plus capability uniqueness and boundary refs, which
// they depend on). Returns errors; empty means accepted.
function lintMatrix(m) {
  const errs = [], byId = new Map();
  for (const r of m.rows) { if (byId.has(r.id)) errs.push(`duplicate row id ${r.id}`); byId.set(r.id, r); }
  const owner = new Map();
  for (const r of m.rows) for (const c of r.capabilities) {
    if (owner.has(c)) errs.push(`capability ${c} claimed by ${owner.get(c)} and ${r.id}`); else owner.set(c, r.id);
  }
  for (const r of m.rows) {
    for (const b of r.authority.boundaries ?? []) if (!m.boundaries?.[b]) errs.push(`${r.id}: unresolved boundary ${b}`);
    if (r.authority.kind !== "preparatory") continue;
    for (const s of r.authority.serves) {
      const t = byId.get(s);
      if (!t) errs.push(`${r.id}: serves unknown row ${s}`);
      else if (t.authority.kind === "preparatory") errs.push(`${r.id}: serves preparatory row ${s}`);
      else if (t.authority.kind === "non-delegable" && t.authority.agentMayPrepare !== true) errs.push(`${r.id}: serves ${s}, which doesn't allow preparation`);
    }
  }
  return errs;
}
const exLint = lintMatrix(base2());
if (exLint.length) { wrong++; console.log("WRONG 0.2 example lint:", exLint.join("; ")); }
const lintCases = {
  "lint-serves-unknown-row": m => { prep(m).authority.serves = ["invoice.approve", "invoice.pay"]; },
  "lint-serves-preparatory-row": m => { m.rows[4].authority.serves = ["invoice.prepare"]; },
  "lint-serves-nondelegable-without-prepare": m => { m.rows[2].authority.agentMayPrepare = false; },
  "lint-prep-claims-decision-capability": m => { prep(m).capabilities.push("erp:invoice.approve"); },
  "lint-unresolved-boundary": m => { prep(m).authority.boundaries = ["erp-read-only"]; },
  "lint-duplicate-row-id": m => { m.rows[4].id = "invoice.prepare"; },
};
for (const [name, mutate] of Object.entries(lintCases)) {
  const m = base2(); mutate(m);
  if (!versions["0.2"].validate(m)) { wrong++; console.log("WRONG", name, "should be schema-valid so the lint rule is what rejects it"); continue; }
  const errs = lintMatrix(m);
  if (errs.length === 0) { wrong++; console.log("WRONG", name, "accepted by lint"); }
}

console.log(summary.join("\n"));
console.log(`0.2 only: ${Object.keys(prepCases).length} schema cases (preparatory rows, value ceilings), ${Object.keys(lintCases).length} lint cases; cross-version: 2; frozen-gap record: 1`);
console.log(`${wrong} wrong`);
process.exit(wrong ? 1 : 0);
