// Assemble a Guardian from a config file: compile the policy, open the evidence store, rebuild the cap
// ledger from it, and recover from an unclean stop. Refuses to start on anything it can't trust.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { AcsEndpoint, PROFILES } from "@verkflode/vaom-guardian-acs";
import { CapLedger, compilePolicy, ContextRegistry, lintMatrix, resolveRecord, type Policy } from "@verkflode/vaom-guardian-core";
import { Approvals } from "./approvals.ts";
import { loadSecrets, type Secrets } from "./secrets.ts";
import { Store } from "./store.ts";

export const CONFIG_FORMAT = "vaom-guardian.config/0.1";
export const VERSION = "0.0.0";

export interface Activation { rows: string[]; scopes?: string[]; task?: string }

export interface GuardianFileConfig {
  format: typeof CONFIG_FORMAT;
  matrix: string;
  binding: string;
  /** Scoring policy files; every one a matrix row cites must be here, or the Guardian won't start. */
  scoring?: string[];
  dataDir: string;
  port: number;
  approvalTimeoutSeconds?: number;
  skewWindowMs?: number;
  /** Execution context each agent id opens at sessionStart. An agent id not listed opens none. */
  activation?: Record<string, Activation>;
}

const KEYS = new Set(["$schema", "format", "matrix", "binding", "scoring", "dataDir", "port", "approvalTimeoutSeconds", "skewWindowMs", "activation"]);

export function readConfig(path: string): GuardianFileConfig {
  const c = JSON.parse(readFileSync(path, "utf8"));
  const bad = (m: string) => new Error(`${path}: ${m}`);
  if (c?.format !== CONFIG_FORMAT) throw bad(`format must be ${CONFIG_FORMAT}`);
  for (const k of Object.keys(c)) if (!KEYS.has(k)) throw bad(`unknown key ${k}`);
  for (const k of ["matrix", "binding", "dataDir"]) if (typeof c[k] !== "string") throw bad(`${k} must be a path`);
  if (c.scoring !== undefined && !(Array.isArray(c.scoring) && c.scoring.every((s: unknown) => typeof s === "string"))) throw bad("scoring must be a list of paths");
  if (!Number.isInteger(c.port) || c.port < 1024 || c.port > 65535) throw bad("port must be an integer from 1024 to 65535");
  if (c.approvalTimeoutSeconds !== undefined && !(Number.isInteger(c.approvalTimeoutSeconds) && c.approvalTimeoutSeconds >= 10 && c.approvalTimeoutSeconds <= 540)) throw bad("approvalTimeoutSeconds must be 10 to 540 (under Claude Code's 600 s hook limit)");
  if (c.skewWindowMs !== undefined && !(Number.isInteger(c.skewWindowMs) && c.skewWindowMs >= 1000 && c.skewWindowMs <= 300_000)) throw bad("skewWindowMs must be 1000 to 300000");
  for (const [agent, a] of Object.entries((c.activation ?? {}) as Record<string, any>)) {
    if (!Array.isArray(a?.rows) || a.rows.some((r: unknown) => typeof r !== "string")) throw bad(`activation.${agent}.rows must be row ids`);
    for (const k of Object.keys(a)) if (!["rows", "scopes", "task"].includes(k)) throw bad(`activation.${agent}: unknown key ${k}`);
  }
  const base = dirname(resolve(path));
  return { ...c, matrix: resolve(base, c.matrix), binding: resolve(base, c.binding), ...(c.scoring ? { scoring: c.scoring.map((s: string) => resolve(base, s)) } : {}), dataDir: resolve(base, c.dataDir) };
}

export interface Guardian {
  config: GuardianFileConfig;
  policy: Policy;
  store: Store;
  endpoint: AcsEndpoint;
  approvals: Approvals;
  secrets: Secrets;
  origin: string;
  recovered: number;
}

export function createGuardian(config: GuardianFileConfig, now: number = Date.now()): Guardian {
  const matrix = JSON.parse(readFileSync(config.matrix, "utf8"));
  const binding = JSON.parse(readFileSync(config.binding, "utf8"));
  const lint = lintMatrix(matrix);
  if (!lint.ok) throw new Error(`matrix doesn't lint: ${lint.findings.map((f) => `${f.path} ${f.message}`).join("; ")}`);
  const scoring = (config.scoring ?? []).map((f) => JSON.parse(readFileSync(f, "utf8")));
  const compiled = compilePolicy(matrix, binding, scoring);
  if (!compiled.ok) throw new Error(`policy doesn't compile: ${compiled.findings.map((f) => `${f.path} ${f.message}`).join("; ")}`);
  const policy = compiled.policy;
  for (const [agent, a] of Object.entries(config.activation ?? {})) {
    const unknown = a.rows.filter((r) => !policy.rowById.has(r));
    if (unknown.length) throw new Error(`activation.${agent}: rows not in the matrix: ${unknown.join(", ")}`);
  }

  const store = new Store(config.dataDir);
  const secrets = loadSecrets(resolve(config.dataDir, "secrets.json"), true);
  const ts = new Date(now).toISOString();

  // Recovery: asks that were pending at an unclean stop can't be approved any more (the agent's wait is
  // gone), so they expire, unless an approval was recorded, in which case the call may have run and its
  // cap use stays. Allowed calls with no result stay reserved: they may have run.
  const approved = new Set(store.events().filter((e) => e.type === "approval").map((e) => e.decision as string));
  const expired = store.records()
    .filter((r) => !r.resolution && (r.decision.outcome === "review" || r.decision.outcome === "escalate") && !approved.has(r.id))
    .map((r) => resolveRecord(r, { ts, result: "expired" }));
  store.appendRecords(expired);

  const ledger = new CapLedger();
  ledger.load(store.records());
  const contexts = new ContextRegistry(policy);
  const timeoutMs = (config.approvalTimeoutSeconds ?? 300) * 1000;
  const endpoint = new AcsEndpoint({
    methodsEvaluated: ["steps/sessionStart", "steps/sessionEnd", "steps/toolCallRequest", "steps/toolCallResult", "steps/subagentStart"],
    defaultTimeoutMs: timeoutMs + 30_000,
    skewWindowMs: config.skewWindowMs ?? 30_000,
    profiles: PROFILES,
    ikm: secrets.ikm,
    keyId: secrets.keyId,
    factKey: secrets.factKey,
    approvalTimeoutSeconds: timeoutMs / 1000,
    deferTimeoutMs: 1000,
    evaluatorVersion: VERSION,
    activationFor: ({ agentId }) => {
      const a = config.activation?.[agentId];
      return a ? { rows: [...a.rows], ...(a.scopes ? { scopes: [...a.scopes] } : {}), ...(a.task ? { task: a.task } : {}) } : null;
    },
  }, { policy, ledger, contexts, newId: randomUUID });

  const origin = `http://localhost:${config.port}`;
  const approvals = new Approvals({ store, endpoint, origin, rpId: "localhost", timeoutMs, roles: new Set(Object.keys(matrix.roles ?? {})), recordApprovers: matrix.oversight?.reviewerLevelMetrics?.enabled === true });
  return { config, policy, store, endpoint, approvals, secrets, origin, recovered: expired.length };
}
