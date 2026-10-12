import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CapLedger, compilePolicy, ContextRegistry, decide, lintMatrix, lintSeeds, preview, scorecard, type Policy, type SeedOutcome } from "../src/index.ts";
import { rules, scoringPolicies, type Doc } from "./helpers.ts";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
const load = (f: string): Doc => JSON.parse(readFileSync(join(examples, f), "utf8"));
function policy(m: Doc = load("incident.matrix.json")): Policy {
  const r = compilePolicy(m, load("incident.binding.json"), scoringPolicies());
  if (!r.ok) throw new Error(JSON.stringify(r.findings));
  return r.policy;
}

describe("the seeds linter", () => {
  it("passes the example against the incident matrix, which enables seeding on the restart row", () => {
    expect(lintMatrix(load("incident.matrix.json")).findings).toEqual([]);
    expect(lintSeeds(load("incident.seeds.json"), policy()).findings).toEqual([]);
  });
  const cases: [string, (s: Doc) => void, string, Doc?][] = [
    ["an unknown format", (s) => { s.format = "vaom.seeds/9"; }, "format"],
    ["a seed without its known error", (s) => { delete s.seeds[0].error; }, "schema"],
    ["no disclosure", (s) => { delete s.disclosure; }, "schema"],
    ["a seed id used twice", (s) => { s.seeds[1].id = s.seeds[0].id; }, "id.duplicate"],
    ["a row the matrix doesn't have", (s) => { s.seeds[0].row = "remediation.reboot"; }, "row.unknown"],
    ["a row that doesn't enable seeding", (s) => { s.seeds[0].row = "incident.monitor"; s.seeds[0].tool = "mcp__incident__declare"; }, "row.seeding-off"],
    ["a tool the binding doesn't map", (s) => { s.seeds[0].tool = "mcp__deploy__nuke"; }, "tool.unmapped"],
    ["a tool that maps to another row", (s) => { s.seeds[0].tool = "mcp__telemetry__query"; }, "tool.other-row"],
  ];
  it("rejects a row whose seeding rate can't be reached (row.rate-unreachable)", () => {
    const m = load("incident.matrix.json");
    m.rows.find((r: Doc) => r.id === "remediation.restart").oversight.seeding.rate = 0.6;
    expect(rules(lintSeeds(load("incident.seeds.json"), policy(m)))).toEqual(["row.rate-unreachable"]);
    m.rows.find((r: Doc) => r.id === "remediation.restart").oversight.seeding.rate = 0.5;
    expect(lintSeeds(load("incident.seeds.json"), policy(m)).ok).toBe(true);
  });
  for (const [name, mutate, rule] of cases) {
    it(`rejects ${name} (${rule})`, () => {
      const s = load("incident.seeds.json");
      mutate(s);
      expect(rules(lintSeeds(s, policy()))).toEqual([rule]);
    });
  }
  it("a matrix can't enable seeding on a row whose records feed what matters", () => {
    const m = load("incident.matrix.json");
    m.rows.find((r: Doc) => r.id === "remediation.restart").oversight.recordsFeed = ["investigations"];
    expect(lintMatrix(m).ok).toBe(false);
  });
});

describe("preview: a seed is placed exactly as a real call, and reserves nothing", () => {
  const T = "2026-10-05T10:00:00Z";
  const call = { tool: "mcp__deploy__rolling_restart", arguments: { incident_id: "INC-7", service: "orders-db", stateless: true } };
  it("gives the record decide() would, while the ledger and its history stay untouched", () => {
    const p = policy();
    const contexts = new ContextRegistry(p);
    contexts.open({ id: "c", session: "s", agent: { id: "a" }, rows: ["remediation.restart"], task: "INC-7" }, Date.parse(T));
    const input = { id: "x", ts: T, agent: { id: "a" }, session: { id: "s" }, contexts, factKey: new Uint8Array(32).fill(2) };
    const ledger = new CapLedger(); ledger.load([]);
    const seen = preview(p, call, ledger, input);
    expect(seen.decision).toMatchObject({ outcome: "review", band: "B" });
    expect(ledger.historyCount("remediation.restart", {}, Date.parse(T) + 1, 3_600_000)).toBe(0);
    const real = decide(p, call, ledger, input);
    expect(real).toEqual(seen);
    expect(ledger.historyCount("remediation.restart", {}, Date.parse(T) + 1, 3_600_000)).toBe(1);
  });
});

describe("scorecard metric 9: seeded-error detection", () => {
  const period = { from: "2026-10-05T00:00:00Z", to: "2026-10-12T00:00:00Z" };
  const out = (detected: number, missed: number, expired = 0): SeedOutcome[] => [
    ...Array.from({ length: detected }, () => ({ row: "remediation.restart", ts: "2026-10-06T00:00:00Z", result: "detected" as const })),
    ...Array.from({ length: missed }, () => ({ row: "remediation.restart", ts: "2026-10-06T00:00:00Z", result: "missed" as const })),
    ...Array.from({ length: expired }, () => ({ row: "remediation.restart", ts: "2026-10-06T00:00:00Z", result: "expired" as const })),
  ];
  const m9 = (seeds: SeedOutcome[]) => scorecard(load("incident.matrix.json"), [], { ...period, seeds }).rows.find((r) => r.row === "remediation.restart")!.metrics.seededDetection!;
  it("at or above the target set at design: healthy; expired seeds count neither way", () => {
    expect(m9(out(9, 1, 5))).toMatchObject({ status: "healthy", planted: 15, detectionRate: 0.9, target: 0.9 });
  });
  it("below it: oversight isn't effective, whatever the approval rate says", () => {
    expect(m9(out(8, 2))).toMatchObject({ status: "breach", detectionRate: 0.8, diagnosis: "oversight not effective, whatever the approval rate says" });
  });
  it("too few decided seeds: no verdict", () => {
    expect(m9(out(5, 0, 20)).status).toBe("insufficient-sample");
  });
  it("seeds outside the period, or on another row, don't count; rows without seeding aren't measured", () => {
    const s = [...out(10, 0), { row: "remediation.restart", ts: "2026-10-01T00:00:00Z", result: "missed" as const }, { row: "incident.monitor", ts: "2026-10-06T00:00:00Z", result: "missed" as const }];
    expect(m9(s)).toMatchObject({ planted: 10, missed: 0 });
    const monitor = scorecard(load("incident.matrix.json"), [], { ...period, seeds: s }).rows.find((r) => r.row === "incident.monitor")!.metrics.seededDetection;
    expect(monitor!.status).toBe("not-measured");
  });
});
