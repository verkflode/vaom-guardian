import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { checkProbeResult } from "@verkflode/vaom-guardian-core";
import { observe, runProbe, type ProbeDef, type ProbeSet } from "../src/index.ts";

const examples = join(import.meta.dirname, "..", "..", "..", "schema", "examples");
const set = JSON.parse(readFileSync(join(examples, "incident.probes.json"), "utf8")) as ProbeSet;
const probe = { ...set.probes[0]!, refusal: "403 Forbidden" };
const fake = join(import.meta.dirname, "fake-claude.mjs");
const run = async (scenario: string, p: ProbeDef = probe) => { process.env.FAKE_SCENARIO = scenario; return (await runProbe(set, p, { project: tmpdir(), claude: fake })).result; };
afterEach(() => { delete process.env.FAKE_SCENARIO; });

describe("probing Claude Code (against a stand-in claude)", () => {
  it("no forbidden tool in the manifest: absent, with the host's version and model", async () => {
    const r = await run("absent");
    expect(r).toMatchObject({ boundary: "no-config-write", observed: "absent", host: { id: "claude-code", version: "9.9.9", model: "claude-haiku-test" }, evidence: { forbiddenPresent: [], canaryHit: false } });
    expect(checkProbeResult(r)).toEqual([]);
  });
  it("the tool is there and the call was denied before it ran: policy", async () => {
    expect(await run("policy")).toMatchObject({ observed: "policy", evidence: { forbiddenPresent: ["mcp__config__set"], attempted: ["mcp__config__set"], denied: ["mcp__config__set"] } });
  });
  it("the call ran and the target refused it, matching the probe's refusal pattern: scope-denied", async () => {
    expect(await run("scope")).toMatchObject({ observed: "scope-denied", evidence: { refused: ["mcp__config__set"] } });
  });
  it("without a refusal pattern, or with an error that isn't a refusal: inconclusive", async () => {
    const { refusal: _r, ...noPattern } = probe;
    expect((await run("scope", noPattern)).observed).toBe("inconclusive");
    expect((await run("errored")).observed).toBe("inconclusive");
  });
  it("the canary was reached: crossed", async () => {
    expect(await run("crossed")).toMatchObject({ observed: "crossed", evidence: { canaryHit: true } });
  });
  it("a host that never starts shows no manifest: inconclusive, never absent", async () => {
    const r = (await runProbe(set, probe, { project: tmpdir(), claude: join(tmpdir(), "no-such-claude") })).result;
    expect(r.note).toMatch(/no tool manifest/);
    expect(r.observed).toBe("inconclusive");
  });
});

describe("reading a transcript", () => {
  it("skips lines that aren't JSON and keeps only what the stream says", () => {
    const o = observe(['not json', JSON.stringify({ type: "system", subtype: "init", tools: ["Read", 7] })].join("\n"));
    expect(o).toEqual({ manifest: ["Read"], attempted: [], denied: [], refused: [], host: {} });
  });
});
