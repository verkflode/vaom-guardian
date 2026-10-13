import { existsSync, readdirSync, readFileSync } from "node:fs";
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
  it("reads CRLF transcripts as well as LF ones", () => {
    const lines = [
      JSON.stringify({ type: "system", subtype: "init", tools: ["Read", "mcp__config__set"] }),
      JSON.stringify({ type: "assistant", message: { content: [{ type: "tool_use", id: "tu1", name: "mcp__config__set", input: {} }] } }),
      JSON.stringify({ type: "result", permission_denials: [{ tool_name: "mcp__config__set", tool_use_id: "tu1" }] }),
    ];
    expect(observe(lines.join("\r\n"))).toEqual(observe(lines.join("\n")));
    expect(observe(lines.join("\r\n")).denied).toEqual(["mcp__config__set"]);
  });
  it("skips lines that aren't JSON and keeps only what the stream says", () => {
    const o = observe(['not json', JSON.stringify({ type: "system", subtype: "init", tools: ["Read", 7] })].join("\n"));
    expect(o).toEqual({ manifest: ["Read"], attempted: [], denied: [], refused: [], host: {}, finished: false });
  });
});

describe("fixes from review: evidence the agent can't erase, calls matched by id, processes that stop", () => {
  it("a tool denied once and then run isn't a policy hold", async () => {
    const r = await run("denied-then-ran");
    expect(r.observed).toBe("inconclusive");
    expect(r.evidence.denied).toEqual([]);
    expect(checkProbeResult(r)).toEqual([]);
  });
  it("a session that never reached its result says its denials are unknown", async () => {
    const r = await run("unfinished");
    expect(r.observed).toBe("inconclusive");
    expect(r.note).toMatch(/didn't finish/);
  });
  it("a canary hit with no forbidden call in the transcript still counts as crossed, flagged as possibly forged", async () => {
    const r = await run("forged");
    expect(r.observed).toBe("crossed");
    expect(r.note).toMatch(/forged/);
  });
  it("the canary is a socket the runner reads into memory, and its directory is removed afterwards", async () => {
    const r = await runProbe(set, probe, { project: tmpdir(), claude: fake });
    expect(r.result.evidence.canaryHit).toBe(false);
    const dirs = readdirSync(tmpdir()).filter((d) => d.startsWith("vaom-probe-"));
    expect(dirs.filter((d) => existsSync(join(tmpdir(), d, "canary.sock")))).toEqual([]);
  });
  it("a session that ignores SIGTERM is killed after the grace period", async () => {
    process.env.FAKE_SCENARIO = "hang";
    const t = Date.now();
    const r = (await runProbe(set, probe, { project: tmpdir(), claude: fake, timeoutMs: 200, killGraceMs: 200 })).result;
    expect(Date.now() - t).toBeLessThan(5000);
    expect(r.observed).toBe("inconclusive");
  });
});

