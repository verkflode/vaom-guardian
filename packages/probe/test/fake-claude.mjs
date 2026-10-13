#!/usr/bin/env node
// A stand-in for `claude -p --output-format stream-json`: prints a transcript for the scenario in
// FAKE_SCENARIO, and (for "crossed") reaches the canary the way an instrumented target would.
import { createConnection } from "node:net";
const s = process.env.FAKE_SCENARIO;
const line = (m) => process.stdout.write(JSON.stringify(m) + "\n");
const canary = () => new Promise((res) => { const c = createConnection(process.env.VAOM_CANARY_SOCKET, () => c.end("config.set\n")); c.on("close", res); c.on("error", res); });
if (s === "hang") { process.on("SIGTERM", () => {}); setInterval(() => {}, 1000); }
else {
  const tools = ["Read", "Bash", "mcp__telemetry__query", ...(s === "absent" ? [] : ["mcp__config__set"])];
  // argv isn't in a real init message; the tests read it to see what the runner asked for.
  line({ type: "system", subtype: "init", tools, model: "claude-haiku-test", claude_code_version: "9.9.9", cwd: process.cwd(), argv: process.argv.slice(2) });
  const held = "PreToolUse:mcp__config__set hook error: VAOM Guardian: denied (unmapped)";
  const use = (id = "tu1") => ({ type: "assistant", message: { content: [{ type: "tool_use", id, name: "mcp__config__set", input: { key: "pool.size", value: 64 } }] } });
  const result = (is_error, content, id = "tu1") => ({ type: "user", message: { content: [{ type: "tool_result", tool_use_id: id, is_error, content }] } });
  const denial = (id = "tu1") => ({ tool_name: "mcp__config__set", tool_use_id: id, tool_input: {} });
  let denials = [];
  if (s === "absent") line({ type: "assistant", message: { content: [{ type: "text", text: "I have no tool for writing configuration." }] } });
  if (s === "policy" || s === "unfinished") { line(use()); line(result(true, held)); denials = [denial()]; }
  // Claude Code's own refusal of a tool nobody granted: in permission_denials, but not the Guardian.
  if (s === "ungranted") { line(use()); line(result(true, "Claude requested permissions to use mcp__config__set, but you haven't granted it yet.")); denials = [denial()]; }
  if (s === "scope") { line(use()); line(result(true, [{ type: "text", text: "403 Forbidden: credential lacks config:write" }])); }
  if (s === "errored") { line(use()); line(result(true, "connection reset")); }
  if (s === "crossed") { line(use()); await canary(); line(result(false, "ok")); }
  if (s === "forged") await canary();
  // Denied once, then the same tool called again and run: not a policy hold.
  if (s === "denied-then-ran") { line(use("tu1")); line(result(true, held)); line(use("tu2")); line(result(false, "ok", "tu2")); denials = [denial("tu1")]; }
  if (s !== "unfinished") line({ type: "result", subtype: "success", permission_denials: denials });
}
