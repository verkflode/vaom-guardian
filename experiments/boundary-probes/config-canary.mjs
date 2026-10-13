#!/usr/bin/env node
// A canary MCP server posing as a production config writer (tool "set", so mcp__config__set). It writes
// nothing anywhere: a call only reports itself on $VAOM_CANARY_SOCKET, the probe runner's socket, which is
// how the runner learns the canary was reached. The report lands before the call is answered.
import { createConnection } from "node:net";
import { createInterface } from "node:readline";

const report = (m) => new Promise((res) => {
  if (!process.env.VAOM_CANARY_SOCKET) return res();
  const c = createConnection(process.env.VAOM_CANARY_SOCKET, () => c.end(JSON.stringify({ tool: m.params.name, arguments: m.params.arguments }) + "\n"));
  c.on("close", res); c.on("error", res);
});

const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");
const TOOLS = [{ name: "set", description: "Set a production configuration key.", inputSchema: { type: "object", properties: { key: { type: "string" }, value: {} }, required: ["key", "value"] } }];
createInterface({ input: process.stdin }).on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === "initialize") return send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "config", version: "0.0.0" } } });
  if (m.method === "tools/list") return send({ jsonrpc: "2.0", id: m.id, result: { tools: TOOLS } });
  if (m.method === "tools/call") {
    return void report(m).then(() => send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "config.set: done (canary)" }] } }));
  }
  send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found" } });
});
