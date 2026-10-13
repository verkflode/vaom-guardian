import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CapLedger, compilePolicy, ContextRegistry, type DecisionRecord } from "@verkflode/vaom-guardian-core";
import { Seeder, type SeedSet } from "../src/index.ts";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
const load = (f: string) => JSON.parse(readFileSync(join(examples, f), "utf8"));
const scoring = ["remediation-gate", "incident-detection"].map((s) => load(`${s}.scoring.json`));

function seederOptions(seedingOn = true) {
  const m = load("incident.matrix.json");
  if (!seedingOn) m.rows.find((r: { id: string }) => r.id === "remediation.restart").oversight.seeding = { enabled: false };
  const r = compilePolicy(m, load("incident.binding.json"), scoring);
  if (!r.ok) throw new Error(JSON.stringify(r.findings));
  const ledger = new CapLedger(); ledger.load([]);
  return { policy: r.policy, ledger, contexts: new ContextRegistry(r.policy), set: load("incident.seeds.json") as SeedSet };
}
const seeder = (seedingOn: boolean, random = () => 0) => new Seeder({ ...seederOptions(seedingOn), random, delayMs: { mean: 0, max: 0 } });
const real = { session: "s", call: { arguments: { incident_id: "INC-7" } }, record: { request: { agent: { id: "a" } }, decision: { placements: [{ row: "remediation.restart" }] } } as unknown as DecisionRecord };

describe("the seeder", () => {
  it("plants only on a row whose matrix entry enables seeding, even if handed seeds for another", () => {
    expect(seeder(true).consider(real, 0)).not.toBeNull();
    expect(seeder(false).consider(real, 0)).toBeNull();
  });
  it("draws at rate / (1 - rate) per real ask, so seeds are about `rate` of the queue", () => {
    const q = 0.05 / 0.95;
    expect(seeder(true, () => q - 1e-9).consider(real, 0)).not.toBeNull();
    expect(seeder(true, () => q).consider(real, 0)).toBeNull();
  });
  it("plants the least-used seed next, so a reviewer doesn't meet one case twice before the others", () => {
    const s = seeder(true);
    const ids = [1, 2, 3, 4].map(() => s.consider(real, 0)!.seed.id);
    expect(new Set(ids.slice(0, 2)).size).toBe(2);
    expect(new Set(ids.slice(2)).size).toBe(2);
  });
  it("delays a seed by minutes, exponentially, capped at an hour", () => {
    const at = (u: number) => new Seeder({ ...seederOptions(), random: (() => { let first = true; return () => (first ? ((first = false), 0) : u); })() }).consider(real, 0)!.dueAt;
    expect(at(0)).toBe(0);
    expect(at(1 - Math.exp(-1))).toBe(600_000); // the mean
    expect(at(0.999999)).toBe(3_600_000); // capped
  });
  it("copies only the named arguments from the real call", () => {
    const p = seeder(true).consider({ ...real, call: { arguments: { incident_id: "INC-9", service: "web" } } }, 0)!;
    expect(p.args.incident_id).toBe("INC-9");
    expect(p.args.service).not.toBe("web");
  });
});
