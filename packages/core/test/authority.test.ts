import { describe, expect, it } from "vitest";
import { compilePolicy, ContextRegistry, evaluate, LeaseRegistry, type Health, type LiveContext, type Policy } from "../src/index.ts";
import { binding, matrix02, type Doc } from "./helpers.ts";

// The invoice matrix, plus sub-agent limits on invoice.approve and a lease on invoice.duplicate-anomaly
// (a continuous duplicate monitor). The compiled policy is lint-checked like any other.
function policyWith(mutate: (m: Doc) => void = () => {}): Policy {
  const m = matrix02();
  m.rows[0].authority.chain = { maxDepth: 1, maxFanOut: 2, allowedSubagents: [{ type: "reader", capabilities: ["erp:invoice.flag"], maxLifetime: "PT5M", maxCount: 1 }] };
  m.rows[1].authority.lease = { observationCapabilities: ["erp:invoice.read", "erp:vendor.read"], lifetime: "PT1H", maxLifetime: "P30D", responseContextLifetime: "PT10M" };
  mutate(m);
  const r = compilePolicy(m, binding());
  if (!r.ok) throw new Error(`policy: ${JSON.stringify(r.findings)}`);
  return r.policy;
}
const T0 = Date.parse("2026-10-03T09:00:00Z");
const min = (n: number) => n * 60_000;
const agent = { id: "ap-agent", version: "1.4.0" };
const root = (reg: ContextRegistry, extra: object = {}) =>
  reg.open({ id: "root", session: "s1", agent, rows: ["invoice.approve", "invoice.duplicate-anomaly"], ...extra }, T0);

describe("contexts", () => {
  it("live for the shortest stated row lifetime; the named default only when no row states one", () => {
    const reg = new ContextRegistry(policyWith());
    const c = root(reg); // invoice.approve states PT15M; the duplicate row states none and doesn't count
    expect(c.expiresAt - T0).toBe(min(15));
    expect(reg.live("root", T0 + min(15) - 1)).toBeDefined();
    expect(reg.live("root", T0 + min(15))).toBeUndefined();
    expect(reg.liveFor("s1", T0 + min(16))).toEqual([]);
  });

  it("a row stating no lifetime doesn't shorten a context; with none stated, the default applies", () => {
    const longer = policyWith((m) => { m.rows[0].authority.executionContext.maxLifetime = "PT60M"; });
    const reg = new ContextRegistry(longer);
    expect(root(reg).expiresAt - T0).toBe(min(60));
    expect(reg.open({ id: "dup-only", session: "s1", agent, rows: ["invoice.duplicate-anomaly"] }, T0).expiresAt - T0).toBe(min(15));
  });

  it("refuses rows a context can't cover", () => {
    const reg = new ContextRegistry(policyWith());
    expect(() => reg.open({ id: "x", session: "s1", agent, rows: ["invoice.prepare"] }, T0)).toThrow(/preparatory/);
    expect(() => reg.open({ id: "y", session: "s1", agent, rows: ["nope"] }, T0)).toThrow(/does not exist/);
    expect(() => reg.open({ id: "z", session: "s1", agent, rows: [] }, T0)).toThrow(/at least one row/);
  });

  it("ids are never reusable, so a closed context can't be replayed", () => {
    const reg = new ContextRegistry(policyWith());
    root(reg);
    reg.close("root");
    expect(reg.live("root", T0)).toBeUndefined();
    expect(() => root(reg)).toThrow(/never reusable/);
  });
});

describe("deriving sub-agent contexts: attenuation only", () => {
  const child = (extra: object = {}) => ({ id: "kid", session: "s2", agent: { id: "reader-1" }, rows: ["invoice.duplicate-anomaly"], subagentType: "reader", ...extra });

  it("an allowed pattern derives a narrower, shorter context", () => {
    const reg = new ContextRegistry(policyWith());
    root(reg);
    const r = reg.derive("root", child({ bandCeiling: { "invoice.duplicate-anomaly": "C" } }), T0 + min(1));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.context.expiresAt).toBe(T0 + min(6)); // the reader pattern allows 5 minutes
    expect(r.context.depthLeft).toBe(0);
    expect(r.context.bandCeiling).toEqual({ "invoice.duplicate-anomaly": "C" });
  });

  it("a child can't take rows its parent doesn't have", () => {
    const reg = new ContextRegistry(policyWith());
    reg.open({ id: "root", session: "s1", agent, rows: ["invoice.approve"] }, T0);
    expect(reg.derive("root", child(), T0)).toMatchObject({ ok: false, outcome: "refuse" });
  });

  it("a capability outside the pattern, or an unknown type, needs escalation", () => {
    const reg = new ContextRegistry(policyWith());
    root(reg);
    expect(reg.derive("root", child({ rows: ["invoice.approve"], scopes: ["erp:invoice.approve"] }), T0)).toMatchObject({ ok: false, outcome: "escalate" });
    expect(reg.derive("root", child({ subagentType: "writer" }), T0)).toMatchObject({ ok: false, outcome: "escalate" });
  });

  it("depth, fan-out and per-type counts are bounded", () => {
    const reg = new ContextRegistry(policyWith());
    root(reg);
    const first = reg.derive("root", child(), T0);
    expect(first.ok).toBe(true);
    expect(reg.derive("root", child({ id: "kid2", session: "s3" }), T0)).toMatchObject({ ok: false, outcome: "refuse" }); // maxCount 1
    expect(reg.derive("kid", child({ id: "grandkid", session: "s4" }), T0)).toMatchObject({ ok: false, outcome: "refuse" }); // depth exhausted
  });

  it("a child's ceiling is never looser than its parent's", () => {
    const reg = new ContextRegistry(policyWith());
    root(reg, { bandCeiling: { "invoice.duplicate-anomaly": "C" } });
    const r = reg.derive("root", child({ bandCeiling: { "invoice.duplicate-anomaly": "B" } }), T0);
    expect(r.ok && r.context.bandCeiling).toEqual({ "invoice.duplicate-anomaly": "C" });
  });

  it("a sub-agent gets its own session, and revoking the parent revokes the child", () => {
    const reg = new ContextRegistry(policyWith());
    root(reg);
    expect(reg.derive("root", child({ session: "s1" }), T0)).toMatchObject({ ok: false, outcome: "refuse" });
    expect(reg.derive("root", child(), T0).ok).toBe(true);
    reg.revoke("root");
    expect(reg.live("kid", T0)).toBeUndefined();
  });
});

describe("the evaluator needs a context", () => {
  const p = policyWith();
  const scores = { "erp:invoice.approve": { value: 0.95, policy: { id: "invoice-standard", version: "3.2" }, verified: true } };
  const run = (contexts: LiveContext[], invoice = "INV-1") =>
    evaluate(p, { tool: "mcp__erp__approve_invoice", arguments: { invoice_id: invoice, vendor_id: "V-7", amount: "100", currency: "EUR" } }, { scores, contexts, capUsage: () => ({ total: "0", count: 0 }) });

  it("no context covering the row: unplaceable, for that reason", () => {
    // Pinned to the reason: the task check would also reject these, and must not be what's tested here.
    for (const contexts of [[], [{ id: "c", rows: ["invoice.duplicate-anomaly"] }]]) {
      const d = run(contexts);
      expect(d.outcome).toBe("unplaceable");
      expect(d.reasons.map((r) => r.code)).toContain("context.none");
    }
  });
  it("a context bound to another task: unplaceable", () => {
    const d = run([{ id: "c", rows: ["invoice.approve"], task: "INV-2" }]);
    expect(d.outcome).toBe("unplaceable");
    expect(d.reasons.map((r) => r.code)).toContain("context.task-mismatch");
    expect(run([{ id: "c", rows: ["invoice.approve"], task: "INV-1" }]).band).toBe("A");
  });
  it("an observation context never authorises a decision, even one naming it in its scopes", () => {
    // A real lease can't hold a decision capability (grant refuses it); the evaluator's own rule is tested here alone.
    const d = run([{ id: "lease:x", rows: ["invoice.approve"], scopes: ["erp:invoice.approve"], observation: true }]);
    expect(d.outcome).toBe("unplaceable");
    expect(d.reasons.map((r) => r.code)).toContain("context.none");
  });
  it("a context's band ceiling narrows", () => {
    const d = run([{ id: "c", rows: ["invoice.approve"], bandCeiling: { "invoice.approve": "B" } }]);
    expect([d.outcome, d.band]).toEqual(["review", "B"]);
  });
});

describe("leases", () => {
  const healthy: Health = { agentVersion: "1.4.0", policyVersion: "1.1.0", breakerOpen: false, verificationCurrent: true, heartbeat: true };
  const setup = () => { const p = policyWith(); const contexts = new ContextRegistry(p); return { contexts, leases: new LeaseRegistry(p, contexts) }; };
  const grant = (leases: LeaseRegistry) => leases.grant({ id: "L1", row: "invoice.duplicate-anomaly", agent }, T0);

  it("offers an observation context while it may observe, and not after it runs out", () => {
    const { leases } = setup();
    grant(leases);
    expect(leases.observation("L1", T0 + min(30))).toEqual({ id: "lease:L1", rows: ["invoice.duplicate-anomaly"], scopes: ["erp:invoice.read", "erp:vendor.read"], observation: true });
    expect(leases.observation("L1", T0 + min(61))).toBeUndefined();
  });

  it("grants observation scopes only", () => {
    const { leases } = setup();
    expect(grant(leases).scopes).toEqual(["erp:invoice.read", "erp:vendor.read"]);
    expect(() => leases.grant({ id: "L2", row: "invoice.duplicate-anomaly", agent, scopes: ["erp:invoice.flag"] }, T0)).toThrow(/not observation capabilities/);
    expect(() => leases.grant({ id: "L3", row: "invoice.approve", agent }, T0)).toThrow(/defines no lease/);
  });

  it("renews while healthy, never past the attestation deadline, and only narrower", () => {
    const { leases } = setup();
    grant(leases);
    const r = leases.renew("L1", healthy, T0 + min(30), ["erp:invoice.read"]);
    expect(r.ok && r.value.expiresAt).toBe(T0 + min(90));
    expect(r.ok && r.value.scopes).toEqual(["erp:invoice.read"]);
    expect(leases.renew("L1", healthy, T0 + min(40), ["erp:invoice.read", "erp:vendor.read"]).ok).toBe(false);
  });

  it("each health failure withdraws response authority, and observation continues", () => {
    for (const bad of [{ agentVersion: "1.5.0" }, { policyVersion: "1.2.0" }, { breakerOpen: true }, { verificationCurrent: false }, { heartbeat: false }]) {
      const { leases } = setup();
      grant(leases);
      const r = leases.renew("L1", { ...healthy, ...bad }, T0 + min(10));
      expect(r.ok, JSON.stringify(bad)).toBe(false);
      expect(leases.get("L1")!.status).toBe("observe-only");
      expect(leases.mayObserve("L1", T0 + min(59))).toBe(true);
      expect(leases.respond("L1", { contextId: "r", session: "s9", alert: "A-1" }, T0 + min(11)).ok).toBe(false);
    }
  });

  it("a response context is bound to the alert and ends within minutes", () => {
    const { contexts, leases } = setup();
    grant(leases);
    const r = leases.respond("L1", { contextId: "resp-1", session: "s9", alert: "ALERT-7" }, T0 + min(5));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.task).toBe("ALERT-7");
    expect(r.value.rows).toEqual(["invoice.duplicate-anomaly"]);
    expect(r.value.expiresAt).toBe(T0 + min(15));
    expect(contexts.live("resp-1", T0 + min(15))).toBeUndefined();
  });

  it("at the maximum lifetime without re-attestation it degrades to observe-only: observation goes on, action stops", () => {
    const { leases } = setup();
    grant(leases);
    const day = 86_400_000;
    let t = T0;
    while (t < T0 + 30 * day - min(30)) { t += min(30); expect(leases.renew("L1", healthy, t).ok).toBe(true); }
    expect(leases.get("L1")!.status).toBe("active");
    // A response context opened just before the deadline still ends at it.
    const near = leases.respond("L1", { contextId: "near", session: "s9", alert: "A" }, T0 + 30 * day - min(2));
    expect(near.ok && near.value.expiresAt).toBe(T0 + 30 * day);
    // At the deadline: renewal still keeps the monitor watching, but only as observe-only.
    const at = leases.renew("L1", healthy, T0 + 30 * day);
    expect(at.ok).toBe(true);
    expect(leases.get("L1")!.status).toBe("observe-only");
    expect(leases.mayObserve("L1", T0 + 30 * day + min(30))).toBe(true);
    expect(leases.respond("L1", { contextId: "late", session: "s9", alert: "B" }, T0 + 30 * day + min(1)).ok).toBe(false);
  });

  it("re-attestation needs the accountable role or its deputy, and restores response authority", () => {
    const { leases } = setup();
    grant(leases);
    leases.renew("L1", { ...healthy, heartbeat: false }, T0 + min(1));
    expect(leases.reattest("L1", [{ role: "ap-clerk", record: "a-1" }], T0 + min(2)).ok).toBe(false);
    expect(leases.reattest("L1", [{ role: "ap-deputy", record: "a-2" }], T0 + min(2)).ok).toBe(true);
    expect(leases.get("L1")!.status).toBe("active");
  });

  it("in the shared form every co-owner must re-attest", () => {
    const p = policyWith((m) => {
      m.rows[1].accountability = { form: "shared", gapCheckRef: "g", arrangementRef: "a", stopRule: "any-suspends-all-resume", owners: [
        { role: "ap-owner", deputy: "ap-deputy", answersFor: "x", accepted: { role: "ap-owner", date: "2026-10-01" } },
        { role: "finance-controller", deputy: "legal-counsel", answersFor: "y", accepted: { role: "finance-controller", date: "2026-10-01" } }] };
    });
    const contexts = new ContextRegistry(p), leases = new LeaseRegistry(p, contexts);
    grant(leases);
    expect(leases.reattest("L1", [{ role: "ap-owner", record: "a" }], T0).ok).toBe(false);
    expect(leases.reattest("L1", [{ role: "ap-owner", record: "a" }, { role: "legal-counsel", record: "b" }], T0).ok).toBe(true);
  });

  it("revoking a lease revokes its response contexts", () => {
    const { contexts, leases } = setup();
    grant(leases);
    leases.respond("L1", { contextId: "resp-1", session: "s9", alert: "A" }, T0);
    leases.revoke("L1");
    expect(leases.observation("L1", T0)).toBeUndefined();
    expect(contexts.live("resp-1", T0)).toBeUndefined();
    expect(leases.mayObserve("L1", T0)).toBe(false);
  });
});
