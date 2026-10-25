// The shim's side of the wire: signed ACS requests to the Guardian on 127.0.0.1, signed answers checked
// before they count, and the long-poll for a pending approval. Anything unexpected throws; the caller
// turns every throw into a deny. Every throw is also a decision failure (ACS §6.4), classified and handed
// to onFailure, so the deployment can record it in its own audit log and count it at sessionEnd.
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { request } from "node:http";
import { ACS_SPEC_VERSION, acceptsVersion, sessionKey, sign, verify } from "@verkflode/vaom-guardian-acs";

type Json = any;

/** The Guardian answered with a JSON-RPC error: a decision failure, which this shim treats as deny. */
export class GuardianError extends Error {
  readonly code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

/** The failure classes of ACS §6.4 (acs.failure.class in the trace mappings, summary.decision_failures). */
export type FailureClass = "timeout" | "unreachable" | "malformed_response" | "guardian_error" | "observed_agent_error" | "signature_invalid" | "handshake_failure" | "other";

/** A request that got no usable decision, with its class. */
export class DecisionFailure extends Error {
  readonly failureClass: FailureClass;
  constructor(failureClass: FailureClass, message: string) {
    super(message);
    this.failureClass = failureClass;
  }
}

export interface FailureReport { method: string; session: string; failureClass: FailureClass; detail: string }

/** The class of any error a request threw. */
export function failureClass(e: unknown, method: string): FailureClass {
  if (e instanceof DecisionFailure) return e.failureClass;
  if (e instanceof GuardianError) return method === "handshake/hello" ? "handshake_failure" : e.code === -32004 ? "signature_invalid" : "guardian_error";
  const code = (e as { code?: unknown })?.code;
  if (typeof code === "string" && /^(ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE|ECONNABORTED)$/.test(code)) return "unreachable";
  return "other";
}

export interface ClientConfig {
  port: number;
  ikm: Uint8Array;
  keyId: string;
  agentId: string;
  /** Per-request timeout for ACS calls, which the Guardian answers without waiting on anyone. */
  requestTimeoutMs: number;
  /** Told of every decision failure, before the throw reaches the caller. */
  onFailure?: (f: FailureReport) => void;
}

function http(port: number, method: "GET" | "POST", path: string, headers: Record<string, string>, body: string | undefined, timeoutMs: number): Promise<{ status: number; json: Json }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, method, path, agent: false, headers: { host: `127.0.0.1:${port}`, ...headers, ...(body !== undefined ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) } : {}) }, timeout: timeoutMs }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => { size += c.length; if (size > 1 << 20) { req.destroy(new DecisionFailure("malformed_response", "answer too large")); return; } chunks.push(c); });
      res.on("end", () => {
        try { resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString("utf8")) }); } catch { reject(new DecisionFailure("malformed_response", "the Guardian's answer is not JSON")); }
      });
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new DecisionFailure("timeout", "the Guardian did not answer in time")));
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export class GuardianClient {
  private readonly cfg: ClientConfig;
  private id = 0;
  constructor(cfg: ClientConfig) {
    this.cfg = cfg;
  }

  /**
   * One ACS request. Returns the result, after checking that it answers this request and, for every step
   * but the handshake, that it carries the Guardian's signature under this session's key. The ACS v0.1
   * handshake answer is unsigned (§4), so nothing in it widens what the shim does: the shim applies deny
   * on failure whatever the Guardian declares.
   */
  /** The agent id this shim speaks as. A sub-agent speaks as "{agentId}/{sub-agent type}". */
  get agentId(): string {
    return this.cfg.agentId;
  }

  async call(session: string, method: string, payload: Json, chainHash: string | null, o: { requestId?: string; agentId?: string } = {}): Promise<Json> {
    return this.reporting(method, session, () => this.request(session, method, payload, chainHash, o));
  }

  /** Run a request, telling onFailure of any throw before passing it on. */
  private async reporting<T>(method: string, session: string, f: () => Promise<T>): Promise<T> {
    try {
      return await f();
    } catch (e) {
      try { this.cfg.onFailure?.({ method, session, failureClass: failureClass(e, method), detail: (e as Error).message }); } catch { /* recording must not change the answer */ }
      throw e;
    }
  }

  private async request(session: string, method: string, payload: Json, chainHash: string | null, o: { requestId?: string; agentId?: string }): Promise<Json> {
    const requestId = o.requestId ?? randomUUID();
    const key = sessionKey(this.cfg.ikm, session);
    const env = sign({
      jsonrpc: "2.0", id: ++this.id, method,
      params: {
        acs_version: ACS_SPEC_VERSION, request_id: requestId, timestamp: new Date().toISOString(), nonce: randomBytes(16).toString("hex"),
        metadata: { agent_id: o.agentId ?? this.cfg.agentId, session_id: session, ...(chainHash !== null ? { session_state: { chain_hash: chainHash } } : {}) },
        payload,
      },
    }, key, this.cfg.keyId);
    const r = await http(this.cfg.port, "POST", "/acs", {}, JSON.stringify(env), this.cfg.requestTimeoutMs);
    const res = r.json;
    if (res?.error) throw new GuardianError(Number(res.error.code), String(res.error.message ?? "error"));
    if (r.status !== 200 || res?.jsonrpc !== "2.0" || res.id !== env.id || !res.result) throw new DecisionFailure("malformed_response", `unexpected answer from the Guardian (HTTP ${r.status})`);
    const result = res.result;
    if (method === "handshake/hello") {
      if (typeof result.negotiated_version !== "string" || !acceptsVersion(result.negotiated_version)) throw new DecisionFailure("handshake_failure", "the Guardian negotiated a version this shim doesn't speak");
      return result;
    }
    if (result.signature && result.signature.key_id !== this.cfg.keyId) throw new DecisionFailure("signature_invalid", "the Guardian's answer is signed under a different key_id");
    const v = verify(res, key);
    if (!v.ok) throw new DecisionFailure("signature_invalid", `the Guardian's answer fails its signature check: ${v.why}`);
    if (result.request_id !== requestId) throw new DecisionFailure("malformed_response", "the Guardian's answer is for a different request");
    if (typeof result.chain_hash !== "string") throw new DecisionFailure("malformed_response", "the Guardian's answer carries no chain hash");
    return result;
  }

  /** Long-poll the approval for a pending ask, at most `waitSeconds`. Returns pending, approved, rejected or expired. */
  async approvalStatus(session: string, requestId: string, waitSeconds: number): Promise<string> {
    return this.reporting("approval-status", session, () => this.status(session, requestId, waitSeconds));
  }

  private async status(session: string, requestId: string, waitSeconds: number): Promise<string> {
    const path = `/v1/asks/${session}/${requestId}`;
    const ts = new Date().toISOString();
    const key = sessionKey(this.cfg.ikm, session);
    const mac = (s: string) => createHmac("sha256", key).update(s).digest();
    const r = await http(this.cfg.port, "GET", `${path}?wait=${waitSeconds}`, { "x-vaom-timestamp": ts, "x-vaom-signature": mac(`GET ${path} ${ts}`).toString("base64") }, undefined, (waitSeconds + 10) * 1000);
    const status = r.json?.status;
    if (r.status !== 200 || typeof status !== "string") throw new DecisionFailure("malformed_response", `approval status unavailable (HTTP ${r.status})`);
    const got = Buffer.from(String(r.json.signature ?? ""), "base64"), want = mac(`STATUS ${path} ${status} ${ts}`);
    if (got.length !== want.length || !timingSafeEqual(got, want)) throw new DecisionFailure("signature_invalid", "the approval status fails its signature check");
    return status;
  }
}
