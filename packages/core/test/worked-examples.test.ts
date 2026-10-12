// VAOM v5's worked examples 7B, 7D and 7E, run end to end through the core. Each case quotes the
// whitepaper sentence it checks. Figures the paper doesn't state are illustrative in the example matrices
// and scoring policies (and say so there); these tests assert only outcomes the paper states. Scores are
// computed from each row's scoring policy; the paper's composites (0.83, 0.93, 0.95) are its own policies'
// outputs and aren't reproduced, only the bands they lead to.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CapLedger, compilePolicy, ContextRegistry, decide, LeaseRegistry, lintBinding, lintMatrix, resolveRecord, type Call, type DecideInput, type Policy } from "../src/index.ts";
import { scoringPolicies } from "./helpers.ts";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const load = (f: string): any => JSON.parse(readFileSync(join(examples, f), "utf8"));
function compile(name: string): Policy {
  const r = compilePolicy(load(`${name}.matrix.json`), load(`${name}.binding.json`), scoringPolicies());
  if (!r.ok) throw new Error(`${name} didn't compile: ${JSON.stringify(r.findings)}`);
  return r.policy;
}
const factKey = new Uint8Array(32).fill(3);
const at = (iso: string) => Date.parse(iso);
let seq = 0;
const base = (ts: string, extra: Partial<DecideInput> = {}): DecideInput => ({ id: `d-${++seq}`, ts, agent: { id: "agent" }, session: { id: "s1" }, factKey, ...extra });
const loaded = () => { const l = new CapLedger(); l.load([]); return l; };
/** The independent verifier's verdict (VAOM v5 Section 8). The Guardian has no verifier channel yet; the core takes one. */
const verdict = (capability: string, passed = true): Pick<DecideInput, "verifications"> => ({ verifications: { [capability]: passed } });

describe("all three worked examples lint clean", () => {
  for (const name of ["aml", "incident", "purchasing"]) {
    it(name, () => {
      const m = load(`${name}.matrix.json`);
      expect(lintMatrix(m).findings).toEqual([]);
      expect(lintBinding(load(`${name}.binding.json`), m).findings).toEqual([]);
    });
  }
});

describe("7B: AML transaction triage", () => {
  const p = compile("aml");
  const T = "2026-10-05T08:00:00Z";
  const checked = (passed = true) => verdict("cms:alert.dismiss", passed);
  const open = (task?: string) => { const c = new ContextRegistry(p); c.open({ id: `ctx-${++seq}`, session: "s1", agent: { id: "aml-agent" }, rows: ["alert.dismiss", "sar.determine"], ...(task ? { task } : {}) }, at(T)); return c; };
  const alert = (id: string, amount: string, flags: { pep?: boolean; sanctioned?: boolean; pattern?: string } = {}) =>
    ({ alert_id: id, amount, currency: "EUR", pattern: flags.pattern ?? "salary", pep: flags.pep ?? false, sanctioned_jurisdiction: flags.sanctioned ?? false });
  const dismiss = (a: ReturnType<typeof alert>): Call => ({ tool: "mcp__cms__dismiss_alert", arguments: a });

  it('"Composite confidence: 0.83, routing to Band B (human review)": the structuring alert goes to an investigator', () => {
    const r = decide(p, dismiss(alert("ALR-1", "9500", { pattern: "structuring" })), loaded(), base(T, { contexts: open("ALR-1"), ...checked() }));
    expect([r.decision.outcome, r.decision.band, r.decision.approver_role]).toEqual(["review", "B", "aml-investigator"]);
    // "rule match strength is high (the deposit pattern matches structuring typology)": for a dismissal, a
    // structuring match is the rule that fails, and a failed hard rule caps the level whatever else scores.
    expect(r.decision.placements[0]!.score).toMatchObject({ level: "medium", cap: "medium", dimensions: { ruleMatch: { failed: ["known-false-positive"] } } });
  });

  it('"a batch of 200 alerts ... Band A routing permits auto-dismissal": all 200 dismissed in Band A', () => {
    const alerts = Array.from({ length: 200 }, (_, i) => alert(`ALR-${100 + i}`, String(50 + i)));
    const r = decide(p, { tool: "mcp__cms__dismiss_alerts", arguments: { alerts } }, loaded(), base(T, { contexts: open(), ...checked() }));
    expect(r.decision.outcome).toBe("allow");
    expect(r.decision.placements).toHaveLength(200);
    expect(new Set(r.decision.placements.map((x) => x.band))).toEqual(new Set(["A"]));
  });

  it('"independent verification, where a deterministic checker confirms each dismissal criterion": without it, no Band A', () => {
    const r = decide(p, dismiss(alert("ALR-2", "120")), loaded(), base(T, { contexts: open(), ...checked(false) }));
    expect(r.decision.band).toBe("B");
  });

  for (const [label, a] of [
    ["a politically exposed person (PEP)", alert("ALR-3", "120", { pep: true })],
    ["a sanctioned jurisdiction", alert("ALR-4", "120", { sanctioned: true })],
    ["an amount exceeding the regulatory reporting threshold", alert("ALR-5", "10500")],
  ] as const) {
    it(`"no alert may be auto-dismissed if it involves ${label}": refused, whatever the score`, () => {
      const r = decide(p, dismiss(a), loaded(), base(T, { contexts: open(), ...checked() }));
      expect([r.decision.outcome, r.decision.band]).toEqual(["refuse", "non-delegable"]);
    });
  }

  it("one PEP alert in a batch refuses the whole call: the strictest placement wins", () => {
    const alerts = [alert("ALR-6", "60"), alert("ALR-7", "70", { pep: true }), alert("ALR-8", "80")];
    expect(decide(p, { tool: "mcp__cms__dismiss_alerts", arguments: { alerts } }, loaded(), base(T, { contexts: open(), ...checked() })).decision.outcome).toBe("refuse");
  });

  it('"The regulated determination itself ... stays non-delegable": no SAR tool is mapped, and none may be', () => {
    const r = decide(p, { tool: "mcp__fiu__file_sar", arguments: { alert_id: "ALR-1" } }, loaded(), base(T, { contexts: open(), ...checked() }));
    expect(r.decision.outcome).toBe("unplaceable");
    const b = load("aml.binding.json");
    b.tools.push({ id: "file-sar", match: { tool: "mcp__fiu__file_sar" }, capability: "fiu:sar.file" });
    expect(lintBinding(b, load("aml.matrix.json")).findings.map((f) => f.rule)).toContain("boundary.tool-present");
  });

  it('"it can prioritize it and assemble the investigation package": preparation under the context', () => {
    const r = decide(p, { tool: "mcp__cms__prepare_package", arguments: { alert_id: "ALR-1" } }, loaded(), base(T, { contexts: open("ALR-1") }));
    expect(r.decision.outcome).toBe("allow");
  });

  it('"A regulated decision that reaches Band A on a high composite alone ... is a delegation design error": without the justification the matrix is rejected', () => {
    const m = load("aml.matrix.json");
    delete m.rows[0].authority.regulatedJustification;
    expect(lintMatrix(m).ok).toBe(false);
  });

  it("seeded test cases are forbidden here: the records feed investigations and regulatory reporting", () => {
    const m = load("aml.matrix.json");
    m.rows[0].oversight.seeding = { enabled: true, rate: 0.01, targetDetectionRate: 0.9 };
    expect(lintMatrix(m).ok).toBe(false);
  });
});

describe("7D: autonomous incident remediation", () => {
  const p = compile("incident");
  const T0 = "2026-10-05T02:14:00Z";
  const preflight = (passed = true) => verdict("deploy:service.rolling-restart", passed);
  const restart = (stateless = true): Call => ({ tool: "mcp__deploy__rolling_restart", arguments: { incident_id: "INC-42", service: "orders", stateless } });
  const minutes = (n: number) => new Date(at(T0) + n * 60_000).toISOString();
  const activate = () => {
    const contexts = new ContextRegistry(p);
    // "activated with a delegated execution context ... (accountable role: SRE lead on call; agent identity:
    // remediator-v7; incident ID; scope set; expiry: 60 minutes)"
    const ctx = contexts.open({ id: "remediate-INC-42", session: "rem", agent: { id: "remediator-v7" }, rows: ["remediation.restart", "config.change"], task: "INC-42" }, at(T0));
    return { contexts, ctx };
  };

  it('"the monitoring agent, which holds an observation lease rather than standing authority": it reads and pages, but declaring needs a response context', () => {
    const contexts = new ContextRegistry(p), leases = new LeaseRegistry(p, contexts);
    leases.grant({ id: "monitor", row: "incident.monitor", agent: { id: "monitor-v3", version: "3.0.0" } }, at(T0) - 600_000);
    const obs = leases.observation("monitor", at(T0))!;
    const asMonitor = (call: Call, extra: Partial<DecideInput> = {}) => decide(p, call, loaded(), base(T0, { session: { id: "mon" }, contexts, extraContexts: [obs], ...extra }));
    expect(asMonitor({ tool: "mcp__telemetry__query", arguments: { service: "orders" } }).decision.outcome).toBe("allow");
    expect(asMonitor({ tool: "mcp__alerting__page", arguments: { service: "orders" } }).decision.outcome).toBe("allow");
    // The lease covers only its own scopes: drafting a config change is preparatory, but not in the lease.
    expect(asMonitor({ tool: "mcp__change__draft_proposal", arguments: { change: "x" } }).decision.outcome).toBe("unplaceable");
    const declare: Call = { tool: "mcp__incident__declare", arguments: { alert_id: "ALERT-0214" } };
    expect(asMonitor(declare).decision.outcome).toBe("unplaceable");
    const resp = leases.respond("monitor", { contextId: "resp-0214", session: "mon", alert: "ALERT-0214" }, at(T0));
    expect(resp.ok).toBe(true);
    expect(asMonitor(declare).decision.outcome).toBe("allow");
  });

  it('"Composite: 0.93, Band A. The restart is within delegated authority."', () => {
    const { contexts } = activate();
    const r = decide(p, restart(), loaded(), base(minutes(9), { session: { id: "rem" }, contexts, ...preflight() }));
    expect([r.decision.outcome, r.decision.band]).toEqual(["allow", "A"]);
    expect(r.request.context?.id).toBe("remediate-INC-42");
  });

  it('"independent verification passes: a deterministic pre-flight check": without it, no Band A', () => {
    const { contexts } = activate();
    expect(decide(p, restart(), loaded(), base(minutes(9), { session: { id: "rem" }, contexts, ...preflight(false) })).decision.band).toBe("B");
  });

  it("a restart loop on one incident is an anomaly: the fourth restart within the hour goes to review", () => {
    // Not in the paper's narrative; it's what the example scoring policy's anomaly dimension watches for.
    const { contexts } = activate();
    const ledger = loaded();
    const bands = [5, 6, 7, 8].map((m) => decide(p, restart(), ledger, base(minutes(m), { session: { id: "rem" }, contexts, ...preflight() })).decision.band);
    expect(bands).toEqual(["A", "A", "A", "B"]);
  });

  it('"the service is stateless": a stateful service is off the bounded list and escalates', () => {
    const { contexts } = activate();
    expect(decide(p, restart(false), loaded(), base(minutes(9), { session: { id: "rem" }, contexts, ...preflight() })).decision.outcome).toBe("escalate");
  });

  describe('"It spawns two sub-agents within pre-approved spawn patterns"', () => {
    it('"read-only scopes ... expiring in 20 minutes. Neither can spawn further sub-agents"', () => {
      const { contexts } = activate();
      const logs = contexts.derive("remediate-INC-42", { id: "logs", session: "sub-logs", agent: { id: "log-analysis-1" }, rows: ["remediation.restart"], subagentType: "log-analysis" }, at(minutes(1)));
      const deps = contexts.derive("remediate-INC-42", { id: "deps", session: "sub-deps", agent: { id: "dep-check-1" }, rows: ["remediation.restart"], subagentType: "dependency-check" }, at(minutes(1)));
      expect(logs.ok && deps.ok).toBe(true);
      if (!logs.ok || !deps.ok) return;
      expect(logs.context.scopes).toEqual(["telemetry:read"]);
      expect(deps.context.scopes).toEqual(["telemetry:read", "status:upstream.read"]);
      expect(logs.context.expiresAt).toBe(at(minutes(21)));
      // Neither can spawn further: chain depth is capped at two.
      expect(contexts.derive("logs", { id: "deeper", session: "sub-deeper", agent: { id: "x" }, rows: ["remediation.restart"], subagentType: "log-analysis" }, at(minutes(2)))).toMatchObject({ ok: false, outcome: "refuse" });
    });

    it("a reader can read telemetry but can't restart, even under the restart row's context", () => {
      const { contexts } = activate();
      contexts.derive("remediate-INC-42", { id: "logs", session: "sub-logs", agent: { id: "log-analysis-1" }, rows: ["remediation.restart"], subagentType: "log-analysis" }, at(minutes(1)));
      const asReader = (call: Call) => decide(p, call, loaded(), base(minutes(3), { session: { id: "sub-logs" }, contexts, ...preflight() }));
      expect(asReader({ tool: "mcp__telemetry__query", arguments: { service: "orders" } }).decision.outcome).toBe("allow");
      const r = asReader(restart());
      expect(r.decision.outcome).toBe("unplaceable");
      expect(r.decision.reasons.map((x) => x.code)).toContain("context.scope");
    });

    it('"had the agent ... spawned outside its approved patterns": that needs escalation, and fan-out is bounded', () => {
      const { contexts } = activate();
      expect(contexts.derive("remediate-INC-42", { id: "dep", session: "sub-x", agent: { id: "x" }, rows: ["remediation.restart"], subagentType: "deployer" }, at(minutes(1)))).toMatchObject({ ok: false, outcome: "escalate" });
      contexts.derive("remediate-INC-42", { id: "a", session: "sa", agent: { id: "a" }, rows: ["remediation.restart"], subagentType: "log-analysis" }, at(minutes(1)));
      contexts.derive("remediate-INC-42", { id: "b", session: "sb", agent: { id: "b" }, rows: ["remediation.restart"], subagentType: "dependency-check" }, at(minutes(1)));
      expect(contexts.derive("remediate-INC-42", { id: "c", session: "sc", agent: { id: "c" }, rows: ["remediation.restart"], subagentType: "log-analysis" }, at(minutes(1)))).toMatchObject({ ok: false, outcome: "refuse" });
    });

    it('"The sub-agents\' credentials expired before the incident closed."', () => {
      const { contexts } = activate();
      contexts.derive("remediate-INC-42", { id: "logs", session: "sub-logs", agent: { id: "log-analysis-1" }, rows: ["remediation.restart"], subagentType: "log-analysis" }, at(minutes(1)));
      expect(contexts.live("logs", at(minutes(25)))).toBeUndefined();
      expect(contexts.live("remediate-INC-42", at(minutes(25)))).toBeDefined();
    });
  });

  it('"production configuration changes are non-delegable, and structurally so ... It drafts a change proposal instead"', () => {
    const { contexts } = activate();
    const asRemediator = (call: Call) => decide(p, call, loaded(), base(minutes(10), { session: { id: "rem" }, contexts }));
    expect(asRemediator({ tool: "mcp__config__set", arguments: { key: "pool.size", value: 64 } }).decision.outcome).toBe("unplaceable");
    expect(asRemediator({ tool: "mcp__change__draft_proposal", arguments: { incident_id: "INC-42", change: "pool.size 32 -> 64" } }).decision.outcome).toBe("allow");
  });

  it("the delegated execution context ends at 60 minutes: after that, no authority to restart", () => {
    const { contexts } = activate();
    expect(decide(p, restart(), loaded(), base(minutes(61), { session: { id: "rem" }, contexts, ...preflight() })).decision.outcome).toBe("unplaceable");
  });
});

describe("7E: delegated purchasing", () => {
  const p = compile("purchasing");
  const MONTH = "2026-10-01T07:00:00Z";
  const cartCheck = (passed = true) => verdict("shop:order.place", passed);
  const order = (id: string, total: string, o: { supplier?: string; category?: string; current?: boolean } = {}): Call => ({
    tool: "mcp__shop__place_order",
    arguments: { requisition_id: id, total, currency: "EUR", supplier: o.supplier ?? "supplier-a", category: o.category ?? "consumables", price_list_current: o.current ?? true },
  });
  // "On the first of each month the procurement manager ... signs an open mandate for the agent"
  const mandate = () => { const c = new ContextRegistry(p); c.open({ id: "mandate-2026-10", session: "proc", agent: { id: "buyer-agent" }, rows: ["purchase.reorder", "price.anomaly"] }, at(MONTH)); return c; };
  // Earlier this month the agent spent 13,700, leaving "the remaining mandate balance: €6,300".
  function midMonth() {
    const contexts = mandate(), ledger = loaded();
    const earlier = ["2500", "2500", "2500", "2500", "2500", "1200"];
    earlier.forEach((t, i) => decide(p, order(`REQ-E${i}`, t), ledger, base(`2026-10-0${2 + i}T09:00:00Z`, { session: { id: "proc" }, contexts, ...cartCheck() })));
    return { contexts, ledger, input: (ts: string, v = cartCheck()) => base(ts, { session: { id: "proc" }, contexts, ...v }) };
  }
  const T = "2026-10-12T10:00:00Z";

  it('"Composite: 0.95, against this decision type\'s calibrated threshold of 0.93. Band A. The order totals €1,840."', () => {
    const { ledger, input } = midMonth();
    const r = decide(p, order("REQ-101", "1840"), ledger, input(T));
    expect([r.decision.outcome, r.decision.band]).toEqual(["allow", "A"]);
  });

  it('"a replacement spindle motor at €3,900 ... exceeds the per-order ceiling. Band B"', () => {
    const { ledger, input } = midMonth();
    const r = decide(p, order("REQ-102", "3900", { category: "spare-parts" }), ledger, input(T));
    expect([r.decision.outcome, r.decision.band, r.decision.approver_role]).toEqual(["review", "B", "procurement-manager"]);
  });

  it('"The signature is the Band B approval record": the motor executes on the procurement manager\'s approval', () => {
    const { ledger, input } = midMonth();
    const r = decide(p, order("REQ-102", "3900", { category: "spare-parts" }), ledger, input(T));
    expect(() => resolveRecord(r, { ts: "2026-10-12T10:20:00Z", result: "executed" })).toThrow();
    const done = resolveRecord(r, { ts: "2026-10-12T10:20:00Z", result: "executed", approval: { approver_role: "procurement-manager", record: "signed-cart-REQ-102" } });
    expect(done.resolution?.result).toBe("executed");
  });

  it('"Supplier C\'s price list is past its review-by date, so C\'s offer cannot support a Band A decision"', () => {
    const { ledger, input } = midMonth();
    expect(decide(p, order("REQ-103", "1700", { supplier: "supplier-c", current: false }), ledger, input(T)).decision.band).toBe("B");
  });

  it('"the three framework suppliers only": anyone else needs review', () => {
    const { ledger, input } = midMonth();
    expect(decide(p, order("REQ-104", "300", { supplier: "supplier-z" }), ledger, input(T)).decision.band).toBe("B");
  });

  it('"a cumulative ceiling of €20,000 for the month": an order past the remaining balance needs review', () => {
    const { ledger, input } = midMonth();
    expect(decide(p, order("REQ-105", "1840"), ledger, input(T)).decision.band).toBe("A"); // 15,540 used
    expect(decide(p, order("REQ-106", "2400"), ledger, input("2026-10-12T11:00:00Z")).decision.band).toBe("A"); // 17,940
    expect(decide(p, order("REQ-107", "2400"), ledger, input("2026-10-12T12:00:00Z")).decision.band).toBe("B"); // 20,340
  });

  it('"Supplier onboarding and changes to framework terms are non-delegable": no tool, and none may be mapped', () => {
    const { ledger, input } = midMonth();
    expect(decide(p, { tool: "mcp__erp__onboard_supplier", arguments: { name: "New Co" } }, ledger, input(T)).decision.outcome).toBe("unplaceable");
    const b = load("purchasing.binding.json");
    b.tools.push({ id: "onboard", match: { tool: "mcp__erp__onboard_supplier" }, capability: "erp:supplier.onboard" });
    expect(lintBinding(b, load("purchasing.matrix.json")).findings.map((f) => f.rule)).toContain("boundary.tool-present");
  });

  it('"authority with a hard maximum lifetime, renewed only by a human": once the mandate lapses, nothing can be bought', () => {
    const contexts = mandate();
    const r = decide(p, order("REQ-200", "100"), loaded(), base("2026-11-02T09:00:00Z", { session: { id: "proc" }, contexts, ...cartCheck() }));
    expect(r.decision.outcome).toBe("unplaceable");
  });
});
