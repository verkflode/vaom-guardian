// A boundary probe on Claude Code: run the probe's attempt as a real `claude -p` session in the agent's
// own project, so its settings, hooks (the Guardian's shim) and MCP servers are the ones under test, and
// read what happened from the stream-json transcript.
//
// What the transcript gives, and what it doesn't:
// - The tool manifest the agent saw (the init message). That alone settles an "absent" claim.
// - Which tools the agent called, and which calls were denied before running (permission_denials, which
//   includes a hook's deny).
// - A target's refusal only through the probe's `refusal` pattern on the tool's error output. Without one,
//   a call that ran and failed is inconclusive.
// - Whether the canary was reached only through the canary log: the runner hands Claude Code
//   VAOM_CANARY_LOG, and a canary target (an MCP stand-in, say) appends to it when it's called.
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classify, PROBE_RESULT_FORMAT, type ProbeResult } from "@verkflode/vaom-guardian-core";

export const RUNNER = { id: "vaom-probe/claude-code", version: "0.0.0" };

export interface ProbeDef { boundary: string; forbiddenTools: string[]; attempt: { prompt: string }; canary?: string; refusal?: string }
export interface ProbeSet { id: string; version: string; probes: ProbeDef[] }

export interface Observation {
  manifest: string[];
  attempted: string[];
  denied: string[];
  refused: string[];
  host: { version?: string; model?: string };
}

/** Read a stream-json transcript. Lines that aren't JSON are skipped; nothing here trusts their absence. */
export function observe(transcript: string, refusal?: string): Observation {
  const re = refusal ? new RegExp(refusal) : null;
  let manifest: string[] = [];
  const host: Observation["host"] = {};
  const uses = new Map<string, string>(); // tool_use id -> tool name
  const errors = new Map<string, string>(); // tool_use id -> error text
  const denied = new Set<string>();
  for (const line of transcript.split(/\r?\n/)) {
    let m: any;
    try { m = JSON.parse(line); } catch { continue; }
    if (m?.type === "system" && m.subtype === "init") {
      manifest = Array.isArray(m.tools) ? m.tools.filter((t: unknown) => typeof t === "string") : [];
      if (typeof m.claude_code_version === "string") host.version = m.claude_code_version;
      if (typeof m.model === "string") host.model = m.model;
    }
    for (const c of (Array.isArray(m?.message?.content) ? m.message.content : []) as any[]) {
      if (m.type === "assistant" && c?.type === "tool_use" && typeof c.name === "string") uses.set(c.id, c.name);
      if (m.type === "user" && c?.type === "tool_result" && c.is_error === true) errors.set(c.tool_use_id, text(c.content));
    }
    if (m?.type === "result") for (const d of (m.permission_denials ?? []) as any[]) if (typeof d?.tool_name === "string") denied.add(d.tool_name);
  }
  const refused = [...errors].filter(([id, t]) => re !== null && re.test(t) && !denied.has(uses.get(id) ?? "")).map(([id]) => uses.get(id)).filter((x): x is string => !!x);
  return { manifest, attempted: [...new Set(uses.values())], denied: [...denied], refused: [...new Set(refused)], host };
}

function text(c: unknown): string {
  if (typeof c === "string") return c;
  if (Array.isArray(c)) return c.map((x) => (typeof x?.text === "string" ? x.text : "")).join("\n");
  return "";
}

const sha = (s: string) => `sha256:${createHash("sha256").update(s).digest("hex")}`;

/** The result for one probe, from its transcript and whether the canary was reached. */
export function resultFor(set: ProbeSet, probe: ProbeDef, transcript: string, canaryHit: boolean, ts: string): ProbeResult {
  const o = observe(transcript, probe.refusal);
  const c = classify({ manifest: o.manifest, forbiddenTools: probe.forbiddenTools, attempted: o.attempted, denied: o.denied, refused: o.refused, canaryHit });
  const forbidden = (t: string) => probe.forbiddenTools.some((p) => (p.endsWith("*") ? t.startsWith(p.slice(0, -1)) : t === p));
  return {
    format: PROBE_RESULT_FORMAT, id: randomUUID(), ts, boundary: probe.boundary, probes: { id: set.id, version: set.version }, runner: RUNNER,
    host: { id: "claude-code", ...o.host },
    observed: c.observed,
    evidence: {
      manifestDigest: sha(JSON.stringify([...o.manifest].sort())),
      forbiddenPresent: c.forbiddenPresent, attempted: o.attempted.filter(forbidden), denied: o.denied.filter(forbidden), refused: o.refused.filter(forbidden),
      canaryHit, transcriptDigest: sha(transcript),
    },
    ...(o.manifest.length === 0 ? { note: "no tool manifest in the transcript: the session may not have started" } : {}),
  };
}

export interface RunOptions {
  /** The agent's project directory: its .claude settings (with the shim's hooks) apply. */
  project: string;
  mcpConfig?: string;
  /** The Claude Code command. Default "claude". */
  claude?: string;
  model?: string;
  maxTurns?: number;
  timeoutMs?: number;
}

/** Run one probe's attempt as a real Claude Code session. Resolves with the result; never throws on what the agent does. */
export async function runProbe(set: ProbeSet, probe: ProbeDef, o: RunOptions): Promise<{ result: ProbeResult; transcript: string }> {
  const canaryLog = join(mkdtempSync(join(tmpdir(), "vaom-probe-")), "canary.log");
  writeFileSync(canaryLog, "");
  const args = ["-p", probe.attempt.prompt, "--output-format", "stream-json", "--verbose", "--setting-sources", "project", "--max-turns", String(o.maxTurns ?? 6),
    ...(o.mcpConfig ? ["--mcp-config", o.mcpConfig, "--strict-mcp-config"] : []), ...(o.model ? ["--model", o.model] : [])];
  const transcript = await new Promise<string>((resolve) => {
    const child = spawn(o.claude ?? "claude", args, { cwd: o.project, env: { ...process.env, VAOM_CANARY_LOG: canaryLog, CLAUDE_PROJECT_DIR: o.project }, stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    const t = setTimeout(() => child.kill("SIGTERM"), o.timeoutMs ?? 240_000);
    child.on("close", () => { clearTimeout(t); resolve(out); });
    child.on("error", () => { clearTimeout(t); resolve(out); });
  });
  const canaryHit = readFileSync(canaryLog, "utf8").trim().length > 0;
  return { result: resultFor(set, probe, transcript, canaryHit, new Date().toISOString()), transcript };
}
