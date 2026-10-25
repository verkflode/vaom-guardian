// The Guardian's HTTP surface, bound to 127.0.0.1 only.
//
//   POST /acs                          ACS JSON-RPC (signed envelopes; see packages/acs)
//   GET  /v1/asks/{session}/{request}  approval status for the shim, long-polled (?wait=seconds), HMAC-authenticated both ways
//   GET  /                             the approval page; /app.js its script
//   GET  /enroll                       credential enrollment page (needs the token from the terminal)
//   /api/...                           JSON for those pages; /api/asks* needs this run's page token
//                                      (X-VAOM-Page-Token), printed in the page link on the terminal
//
// Every answer is decided and persisted before it's sent; if persisting fails, the answer is an error,
// which the agent treats as deny. Browser routes check Host and Origin (against DNS rebinding and
// cross-site requests) and require a JSON content type, so a cross-origin form can't reach them without a
// preflight this server never answers.
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { sessionKey } from "@verkflode/vaom-guardian-acs";
import { ApprovalError } from "./approvals.ts";
import type { Guardian } from "./guardian.ts";
import { APP_JS, ENROLL_HTML, INDEX_HTML } from "./page.ts";

const MAX_BODY = 1 << 20;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHIM_SKEW_MS = 30_000;

/** The shim's request authentication: HMAC-SHA256 under the session key over "GET {path} {timestamp}". The
 *  answer is signed the same way over "STATUS {path} {status} {timestamp}", with the request's timestamp. */
export function shimSignature(ikm: Uint8Array, session: string, method: string, path: string, ts: string): string {
  return createHmac("sha256", sessionKey(ikm, session)).update(`${method} ${path} ${ts}`).digest("base64");
}

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function body(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new HttpError(413, "request body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

/** A request body's named fields, each checked to be a string, or a 400: nothing reads an unchecked body. */
function strings<K extends string>(input: unknown, keys: readonly K[]): Record<K, string> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new HttpError(400, "the body must be a JSON object");
  const o = input as Record<string, unknown>;
  for (const k of keys) if (typeof o[k] !== "string") throw new HttpError(400, `${k} must be a string`);
  return o as Record<K, string>;
}

function send(res: ServerResponse, status: number, type: string, payload: string): void {
  res.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": type, "Content-Length": Buffer.byteLength(payload) });
  res.end(payload);
}
const json = (res: ServerResponse, status: number, v: unknown) => send(res, status, "application/json; charset=utf-8", JSON.stringify(v));

export function createGuardianServer(g: Guardian, now: () => number = Date.now): Server {
  const port = g.config.port;
  const browserHost = `localhost:${port}`;
  const agentHosts = new Set([`127.0.0.1:${port}`, browserHost]);

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const host = req.headers.host ?? "";
    const p = url.pathname;

    // ---- agent-facing
    if (p === "/acs") {
      if (!agentHosts.has(host)) throw new HttpError(421, "wrong host");
      if (req.method !== "POST") throw new HttpError(405, "POST only");
      const raw = await body(req);
      return json(res, 200, acs(raw));
    }
    const m = /^\/v1\/asks\/([^/]+)\/([^/]+)$/.exec(p);
    if (m) {
      if (!agentHosts.has(host)) throw new HttpError(421, "wrong host");
      if (req.method !== "GET") throw new HttpError(405, "GET only");
      const [, session, requestId] = m as unknown as [string, string, string];
      if (!UUID.test(session) || !UUID.test(requestId)) throw new HttpError(400, "bad ids");
      const ts = String(req.headers["x-vaom-timestamp"] ?? "");
      const sig = String(req.headers["x-vaom-signature"] ?? "");
      const t = Date.parse(ts);
      if (Number.isNaN(t) || Math.abs(now() - t) > SHIM_SKEW_MS) throw new HttpError(401, "timestamp missing or outside the window");
      const want = Buffer.from(shimSignature(g.secrets.ikm, session, "GET", p, ts), "base64");
      const got = Buffer.from(sig, "base64");
      if (got.length !== want.length || !timingSafeEqual(got, want)) throw new HttpError(401, "bad signature");
      const wait = Math.min(Math.max(Number(url.searchParams.get("wait") ?? 0) || 0, 0), 25);
      g.approvals.expire(now());
      const status = wait > 0 ? await g.approvals.wait(session, requestId, wait * 1000) : g.approvals.get(session, requestId)?.status;
      if (!status) throw new HttpError(404, "no such approval request");
      // Signed back over the request's own timestamp, so the shim acts only on a status this Guardian gave
      // for this request, never on whatever else might be listening on the port.
      return json(res, 200, { status, signature: shimSignature(g.secrets.ikm, session, "STATUS", `${p} ${status}`, ts) });
    }

    // ---- browser-facing
    if (host !== browserHost) throw new HttpError(421, `open the page at http://${browserHost}/`);
    // The asks and their arguments, and rejecting one, are for whoever holds this run's page token: the
    // terminal that started the Guardian. Any other local process gets nothing (approving also needs Touch ID).
    if (p === "/api/asks" || p.startsWith("/api/asks/")) {
      const got = Buffer.from(String(req.headers["x-vaom-page-token"] ?? ""));
      const want = Buffer.from(g.pageToken);
      if (got.length !== want.length || !timingSafeEqual(got, want)) throw new HttpError(401, "open the approval link printed on the Guardian's terminal: it carries this run's page token");
    }
    if (req.method === "GET") {
      if (p === "/") return send(res, 200, "text/html; charset=utf-8", INDEX_HTML);
      if (p === "/enroll") return send(res, 200, "text/html; charset=utf-8", ENROLL_HTML);
      if (p === "/app.js") return send(res, 200, "text/javascript; charset=utf-8", APP_JS);
      if (p === "/api/asks") {
        return json(res, 200, {
          enrolled: g.approvals.hasCredentials(),
          seeding: g.approvals.seeding(),
          asks: g.approvals.pending(now()).map((a) => ({
            session: a.session, request_id: a.requestId, tool: a.call.tool, arguments: a.call.arguments,
            rows: [...new Set(a.record.decision.placements.map((x) => x.row))], capabilities: [...new Set(a.record.decision.placements.map((x) => x.capability))],
            band: a.record.decision.band, outcome: a.record.decision.outcome, approver_role: a.record.decision.approver_role,
            reasons: [...new Set(a.record.decision.reasons.map((r) => r.code))], agent: a.record.request.agent.id,
            created_at: new Date(a.createdAt).toISOString(), expires_at: new Date(a.expiresAt).toISOString(),
          })),
        });
      }
      throw new HttpError(404, "not found");
    }
    if (req.method !== "POST") throw new HttpError(405, "method not allowed");
    if (req.headers.origin !== g.origin) throw new HttpError(403, "cross-origin request refused");
    if (!String(req.headers["content-type"] ?? "").startsWith("application/json")) throw new HttpError(415, "JSON only");
    let input: unknown;
    try { input = JSON.parse(await body(req)); } catch (e) { if (e instanceof HttpError) throw e; throw new HttpError(400, "body is not JSON"); }

    const a = /^\/api\/asks\/([^/]+)\/([^/]+)\/(challenge|approve|reject)$/.exec(p);
    if (a) {
      const [, session, requestId, action] = a as unknown as [string, string, string, string];
      if (action === "challenge") return json(res, 200, g.approvals.challenge(session, requestId, now()));
      // A planted case is revealed only once decided, so the reviewer learns from it.
      if (action === "approve") {
        const ev = g.approvals.approve(session, requestId, strings(input, ["credentialId", "authenticatorData", "clientDataJSON", "signature"]), now());
        const seededError = g.approvals.revealed(session, requestId);
        return json(res, 200, { status: "approved", approval: ev.id, ...(seededError ? { seeded: { error: seededError } } : {}) });
      }
      const r = g.approvals.reject(session, requestId, now());
      return json(res, 200, { status: "rejected", ...(r.seededError ? { seeded: { error: r.seededError } } : {}) });
    }
    if (p === "/api/enroll/options") return json(res, 200, g.approvals.enrollmentOptions(strings(input, ["token"]).token, now()));
    if (p === "/api/enroll") {
      const { token } = strings(input, ["token"]);
      const registration = strings((input as { registration?: unknown }).registration, ["attestationObject", "clientDataJSON"]);
      const ev = g.approvals.completeEnrollment(token, registration, now());
      return json(res, 200, { enrolled: ev.credential_id, roles: ev.roles });
    }
    throw new HttpError(404, "not found");
  }

  /** One ACS request: decide, persist, then answer; and register an ask for the approval page. */
  function acs(raw: string): unknown {
    const t = now();
    const h = g.endpoint.handle(raw, t);
    const session = h.request?.params.metadata.session_id ?? "";
    try {
      const ts = new Date(t).toISOString();
      g.store.commit({
        records: h.records,
        chain: h.entries.map((entry) => ({ session, entry })),
        events: [
          ...h.incidents.map((i) => ({ type: "incident", id: crypto.randomUUID(), ts, ...i })),
          ...h.spawns.map((s) => ({ type: "spawn", id: crypto.randomUUID(), ts, ...s })),
        ],
      });
    } catch {
      return g.endpoint.persistFailed(h, session);
    }
    const r = h.records[0];
    const asked = h.response?.result !== undefined && "decision" in h.response.result && h.response.result.decision === "ask";
    if (h.call && h.request && r && !r.resolution && (r.decision.outcome === "review" || r.decision.outcome === "escalate") && asked) {
      g.approvals.add(r, { tool: h.call.tool, arguments: h.call.arguments }, session, h.request.params.request_id, t);
    }
    return h.response;
  }

  return createServer((req, res) => {
    route(req, res).catch((e) => {
      const status = e instanceof HttpError || e instanceof ApprovalError ? e.status : 500;
      if (!res.headersSent) json(res, status, { error: status === 500 ? "internal error" : (e as Error).message });
    });
  });
}
