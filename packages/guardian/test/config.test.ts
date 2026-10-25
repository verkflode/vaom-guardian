import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkConfig, readConfig } from "../src/index.ts";

// checkConfig is what `vaom-guardian verify` runs before reading evidence: it must refuse every
// configuration createGuardian refuses, and touch nothing on disk.
const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");

function config(extra: Record<string, unknown> = {}): { path: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "vaom-config-"));
  const path = join(dir, "guardian.json");
  writeFileSync(path, JSON.stringify({
    format: "vaom-guardian.config/0.1",
    matrix: join(examples, "incident.matrix.json"),
    binding: join(examples, "incident.binding.json"),
    scoring: ["remediation-gate", "incident-detection"].map((s) => join(examples, `${s}.scoring.json`)),
    dataDir: "data",
    port: 47123,
    activation: { "incident-agent": { rows: ["remediation.restart"] } },
    ...extra,
  }));
  return { path, dir };
}

describe("checkConfig", () => {
  it("accepts a configuration the Guardian starts with, without creating its data directory", () => {
    const { path, dir } = config();
    const { policy } = checkConfig(readConfig(path));
    expect(policy.rowById.has("remediation.restart")).toBe(true);
    expect(existsSync(join(dir, "data"))).toBe(false);
  });

  it("refuses a matrix that doesn't lint", () => {
    const { path, dir } = config();
    const matrix = JSON.parse(readFileSync(join(examples, "incident.matrix.json"), "utf8"));
    matrix.rows[0].authority = { oops: true };
    writeFileSync(join(dir, "broken.matrix.json"), JSON.stringify(matrix));
    const c = { ...readConfig(path), matrix: join(dir, "broken.matrix.json") };
    expect(() => checkConfig(c)).toThrow(/matrix doesn't lint/);
  });

  it("refuses a policy that doesn't compile (a cited scoring policy missing)", () => {
    const { path } = config({ scoring: [join(examples, "remediation-gate.scoring.json")] });
    expect(() => checkConfig(readConfig(path))).toThrow(/doesn't compile/);
  });

  it("refuses activation naming a row the matrix doesn't have", () => {
    const { path } = config({ activation: { "incident-agent": { rows: ["no.such.row"] } } });
    expect(() => checkConfig(readConfig(path))).toThrow(/rows not in the matrix: no\.such\.row/);
  });
});
