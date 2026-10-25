#!/usr/bin/env node
// vaom-guardian-claude-code hook     --guardian guardian.json | --key shim-key.json  --agent <agent id> [--state dir] [--deadline seconds]
// vaom-guardian-claude-code settings --guardian guardian.json | --key shim-key.json  --agent <agent id> [--state dir] [--matcher regex]
//
// --guardian reads the Guardian's configuration and its secrets file: for a shim running as the same OS
// user as the Guardian. --key reads a shim key file (`vaom-guardian shim-key`): for a Guardian running as
// another user, whose data directory the shim (and the agent) can't read.
//
// --for-user <account> makes the hook a no-op (no output, exit 0: no opinion) for every OS account but that
// one. Claude Code's managed settings apply to every account on the machine, so this is how one agent's
// account is governed without changing Claude Code for the others. The account is the process's real one
// (from the system's user database by uid), which nothing in the environment changes.
//
// `hook` is what Claude Code runs, once per hook call, with the hook input on stdin. Every path ends with
// exit 0 and, for PreToolUse, an explicit decision on stdout. If even that fails (an uncaught error), it
// exits 2, which Claude Code also treats as a block. A hard timer answers deny before Claude Code's own
// hook timeout can turn silence into "no opinion".
import { homedir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { loadSecrets, loadShimKey, readConfig, type ShimKey } from "@verkflode/vaom-guardian-server";
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
  guardian: { type: "string" }, key: { type: "string" }, agent: { type: "string" }, state: { type: "string" }, deadline: { type: "string" }, matcher: { type: "string" }, "for-user": { type: "string" },
} });
const command = positionals[0];
if ((command !== "hook" && command !== "settings") || !values.agent || (values.guardian === undefined) === (values.key === undefined)) {
  process.stderr.write("usage: vaom-guardian-claude-code hook|settings (--guardian guardian.json | --key shim-key.json) --agent <agent id> [--state dir] [--deadline seconds] [--matcher regex] [--for-user account]\n");
  process.exit(2);
}
const source = values.key !== undefined ? { key: resolve(values.key) } : { guardian: resolve(values.guardian!) };
const stateDir = resolve(values.state ?? join(homedir(), ".vaom-guardian", "claude-code"));

if (command === "settings") {
  process.stdout.write(JSON.stringify(hookSettings({ node: process.execPath, script: import.meta.filename, ...source, agent: values.agent, state: stateDir, ...(values.matcher ? { matcher: values.matcher } : {}), ...(values["for-user"] ? { forUser: values["for-user"] } : {}) }), null, 2) + "\n");
  process.exit(0);
}

// Another account than the governed one: no opinion, before anything else is read.
if (values["for-user"] !== undefined && userInfo().username !== values["for-user"]) process.exit(0);

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
let input: unknown;
try { input = JSON.parse(raw); } catch { fatal("the hook input is not JSON"); }
// Read only to name the failure; runHook checks the whole input. Anything but a named event is answered as
// a tool call would be on failure: deny, exit 2.
const fields = (typeof input === "object" && input !== null ? input : {}) as { hook_event_name?: unknown; session_id?: unknown };
event = typeof fields.hook_event_name === "string" ? fields.hook_event_name : "";

let out;
try {
  let key: ShimKey;
  if ("key" in source) key = loadShimKey(source.key);
  else {
    const config = readConfig(source.guardian);
    const secrets = loadSecrets(join(config.dataDir, "secrets.json"), false);
    key = { port: config.port, keyId: secrets.keyId, ikm: secrets.ikm };
  }
  const state = new StateDir(stateDir);
  const ccSession = typeof fields.session_id === "string" ? fields.session_id : "unknown";
  const client = new GuardianClient({ port: key.port, ikm: key.ikm, keyId: key.keyId, agentId: values.agent, requestTimeoutMs: 10_000, onFailure: (f) => state.recordFailure(ccSession, f) });
  out = await runHook(input, { client, state, deadline, approvalsUrl: `http://localhost:${key.port}/` });
} catch (e) {
  fatal(e instanceof UnclassifiedHookError ? e.message : `can't reach the Guardian's configuration (${(e as Error).message}), so the call is denied`);
}
if (out) process.stdout.write(JSON.stringify(out) + "\n");
process.exit(0);
