#!/usr/bin/env node
// A stand-in MCP server (stdio, newline-delimited JSON-RPC) for the 7D incident tools. It does nothing
// but log each call it receives to $SHIM_MARKER, which is how a run tells "the tool ran" from "it didn't".
//   node mcp-stub.mjs telemetry   -> tool "query"            (mcp__telemetry__query)
//   node mcp-stub.mjs deploy      -> tool "rolling_restart"  (mcp__deploy__rolling_restart)
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const server = process.argv[2];
const TOOLS = {
  telemetry: [{ name: "query", description: "Query incident telemetry.", inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } }],
  deploy: [{ name: "rolling_restart", description: "Rolling restart of a service for an incident.", inputSchema: { type: "object", properties: { incident_id: { type: "string" }, service: { type: "string" }, stateless: { type: "boolean" } }, required: ["incident_id", "service", "stateless"] } }],
}[server];
const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");

createInterface({ input: process.stdin }).on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === "initialize") return send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: server, version: "0.0.0" } } });
  if (m.method === "tools/list") return send({ jsonrpc: "2.0", id: m.id, result: { tools: TOOLS } });
  if (m.method === "tools/call") {
    appendFileSync(process.env.SHIM_MARKER, JSON.stringify({ server, tool: m.params.name, arguments: m.params.arguments }) + "\n");
    return send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: `${server}.${m.params.name}: done` }] } });
  }
  send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found" } });
});
