import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ProbeResult } from "@verkflode/vaom-guardian-core";
import { importProbeResults, Store, verifyEvidence } from "../src/index.ts";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
const matrix = JSON.parse(readFileSync(join(examples, "incident.matrix.json"), "utf8"));
let n = 0;
const result = (over: Partial<ProbeResult> = {}): ProbeResult => ({
  format: "vaom.probe-result/0.1", id: `r${++n}`, ts: "2026-10-12T10:00:00Z", boundary: "no-config-write", probes: { id: "example.ops.incident.probes", version: "1.0" },
  runner: { id: "test", version: "0" }, host: { id: "claude-code" }, observed: "absent",
  evidence: { manifestDigest: `sha256:${"0".repeat(64)}`, forbiddenPresent: [], attempted: [], denied: [], refused: [], canaryHit: false }, ...over,
});
const store = () => new Store(mkdtempSync(join(tmpdir(), "vaom-probes-")));

describe("importing probe results", () => {
  it("appends checked results to the store, where verify reads them", () => {
    const s = store();
    const r = importProbeResults(s, matrix, [{ name: "a.json", result: result() }]);
    expect(r.imported).toHaveLength(1);
    expect(s.events().filter((e) => e.type === "probe-result")).toHaveLength(1);
    expect(verifyEvidence(s, "http://localhost:1").problems).toEqual([]);
  });
  it("never stores the same result twice", () => {
    const s = store(), x = result();
    importProbeResults(s, matrix, [{ name: "a.json", result: x }]);
    expect(importProbeResults(s, matrix, [{ name: "again.json", result: x }]).duplicates).toEqual(["again.json"]);
    expect(s.events().filter((e) => e.type === "probe-result")).toHaveLength(1);
  });
  it("is all or nothing: one bad result and none is stored", () => {
    const s = store();
    const r = importProbeResults(s, matrix, [{ name: "good.json", result: result() }, { name: "bad.json", result: { ...result(), observed: "fine" } }, { name: "other.json", result: result({ boundary: "no-sar-filing-tool" }) }]);
    expect(r.rejected.map((x) => x.name)).toEqual(["bad.json", "other.json"]);
    expect(r.rejected[1]!.why).toMatch(/isn't in matrix/);
    expect(s.events().filter((e) => e.type === "probe-result")).toHaveLength(0);
  });
});
