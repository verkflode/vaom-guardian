#!/usr/bin/env node
// vaom-guardian-claude-code hook     --guardian guardian.json --agent <agent id> [--state dir] [--deadline seconds]
// vaom-guardian-claude-code settings --guardian guardian.json --agent <agent id> [--state dir] [--matcher regex]
//
// `hook` is what Claude Code runs, once per hook call, with the hook input on stdin. Every path ends with
// exit 0 and, for PreToolUse, an explicit decision on stdout. If even that fails (an uncaught error), it
// exits 2, which Claude Code also treats as a block. A hard timer answers deny before Claude Code's own
// hook timeout can turn silence into "no opinion".
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { loadSecrets, readConfig } from "@verkflode/vaom-guardian-server";
import { GuardianClient } from "./client.ts";
import { runHook, UnclassifiedHookError } from "./hook.ts";
import { hookSettings, HOOK_TIMEOUT_SECONDS } from "./settings.ts";
import { StateDir } from "./state.ts";

const DENY = (why: string) => JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `VAOM Guardian: ${why}` } });

let event = "";
const fatal = (why: string) => {
  if (event === "PreToolUse" || event === "") process.stdout.write(DENY(why) + "\n");
  process.stderr.write(`VAOM Guardian shim: ${why}\n`);
  process.exit(event === "PreToolUse" || event === "" ? 2 : 0);
};
process.on("uncaughtException", (e) => fatal(`internal error (${e.message})`));
process.on("unhandledRejection", (e) => fatal(`internal error (${(e as Error)?.message ?? e})`));

const { positionals, values } = parseArgs({ allowPositionals: true, options: {
  guardian: { type: "string" }, agent: { type: "string" }, state: { type: "string" }, deadline: { type: "string" }, matcher: { type: "string" },
} });
const command = positionals[0];
if ((command !== "hook" && command !== "settings") || !values.guardian || !values.agent) {
  process.stderr.write("usage: vaom-guardian-claude-code hook|settings --guardian guardian.json --agent <agent id> [--state dir] [--deadline seconds] [--matcher regex]\n");
  process.exit(2);
}
const guardianPath = resolve(values.guardian);
const stateDir = resolve(values.state ?? join(homedir(), ".vaom-guardian", "claude-code"));

if (command === "settings") {
  process.stdout.write(JSON.stringify(hookSettings({ script: import.meta.filename, guardian: guardianPath, agent: values.agent, state: stateDir, ...(values.matcher ? { matcher: values.matcher } : {}) }), null, 2) + "\n");
  process.exit(0);
}

const started = Date.now();
const deadlineSeconds = Number(values.deadline ?? HOOK_TIMEOUT_SECONDS - 30);
// The hard timer below fires 2 s after the deadline; it must still beat Claude Code's own hook timeout,
// past which silence counts as "no opinion" (fail-open). Keep 8 s more for process startup.
const MAX_DEADLINE = HOOK_TIMEOUT_SECONDS - 10;
if (!(deadlineSeconds >= 10 && deadlineSeconds <= MAX_DEADLINE)) fatal(`--deadline must be 10 to ${MAX_DEADLINE} seconds`);
const deadline = started + deadlineSeconds * 1000;
setTimeout(() => fatal("the shim ran out of time, so the call is denied"), deadline - started + 2000).unref();

const raw = await new Promise<string>((res, rej) => {
  const chunks: Buffer[] = [];
  process.stdin.on("data", (c: Buffer) => chunks.push(c));
  process.stdin.on("end", () => res(Buffer.concat(chunks).toString("utf8")));
  process.stdin.on("error", rej);
});
let input: any;
try { input = JSON.parse(raw); } catch { fatal("the hook input is not JSON"); }
// Anything but a named event is answered as a tool call would be on failure: deny, exit 2.
event = typeof input?.hook_event_name === "string" ? input.hook_event_name : "";

let out;
try {
  const config = readConfig(guardianPath);
  const secrets = loadSecrets(join(config.dataDir, "secrets.json"), false);
  const client = new GuardianClient({ port: config.port, ikm: secrets.ikm, keyId: "claude-code-shim", agentId: values.agent, requestTimeoutMs: 10_000 });
  out = await runHook(input, { client, state: new StateDir(stateDir), deadline, approvalsUrl: `http://localhost:${config.port}/` });
} catch (e) {
  fatal(e instanceof UnclassifiedHookError ? e.message : `can't reach the Guardian's configuration (${(e as Error).message}), so the call is denied`);
}
if (out) process.stdout.write(JSON.stringify(out) + "\n");
process.exit(0);
