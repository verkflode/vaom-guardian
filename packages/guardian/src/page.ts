// The local approval and enrollment pages. Static: the script is served from /app.js under a CSP that
// allows only same-origin scripts. Everything the agent supplied (tool names, arguments) is put on the
// page with textContent, never as HTML.
const STYLE = `
:root { --bg: #f6f5f2; --fg: #1d1d1b; --muted: #6b6a66; --card: #ffffff; --line: #dedcd6; --accent: #1f5f4a; --danger: #9b2c2c; --code: #f0eee9; color-scheme: light dark; }
@media (prefers-color-scheme: dark) { :root { --bg: #161615; --fg: #ecebe7; --muted: #a09e98; --card: #1f1f1d; --line: #34332f; --accent: #6cc4a1; --danger: #f08a8a; --code: #2a2a27; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
main { max-width: 760px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 20px; margin: 0 0 4px; }
.sub { color: var(--muted); margin: 0 0 24px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; margin-bottom: 16px; }
.row { display: flex; flex-wrap: wrap; gap: 6px 16px; color: var(--muted); font-size: 13px; margin: 6px 0 10px; }
.tool { font-weight: 600; font-size: 16px; word-break: break-all; }
pre { background: var(--code); padding: 10px; border-radius: 6px; white-space: pre-wrap; word-break: break-word; max-height: 360px; overflow: auto; font-size: 13px; margin: 0 0 12px; }
button { font: inherit; border-radius: 8px; padding: 8px 14px; border: 1px solid var(--line); background: var(--card); color: var(--fg); cursor: pointer; }
button.approve { background: var(--accent); border-color: var(--accent); color: var(--bg); font-weight: 600; }
button.reject { color: var(--danger); }
button:disabled { opacity: .5; cursor: default; }
.actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.msg { font-size: 13px; color: var(--muted); }
.err { color: var(--danger); }
.empty { color: var(--muted); text-align: center; padding: 40px 0; }
.note { font-size: 13px; color: var(--muted); }
`;

const shell = (title: string, inner: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title><style>${STYLE}</style></head>
<body><main>${inner}</main><script src="/app.js"></script></body></html>`;

export const INDEX_HTML = shell("Guardian approvals", `
<h1>Guardian approvals</h1>
<p class="sub">Calls waiting for a human decision. Approving takes Touch ID, and approves that one call only.</p>
<p id="seeding" class="note" hidden></p>
<div id="asks"><p class="empty">Loading…</p></div>
<p class="note">A Guardian decision is policy strength: it holds while the Guardian and its shim run.</p>`);

export const ENROLL_HTML = shell("Guardian enrollment", `
<h1>Enroll an approver</h1>
<p class="sub">Registers this device's Touch ID as an approver credential for the roles shown on the Guardian's terminal.</p>
<div class="card"><p id="roles" class="msg">Checking the enrollment link…</p>
<div class="actions"><button id="enroll" class="approve" disabled>Enroll with Touch ID</button><span id="enroll-msg" class="msg"></span></div></div>`);

export const APP_JS = `"use strict";
const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const b64d = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  for (const k of kids) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}

const busy = new Set();
async function approve(a, msg, buttons) {
  buttons.forEach((b) => b.disabled = true); busy.add(a.request_id); msg.className = "msg"; msg.textContent = "Waiting for Touch ID…";
  try {
    const c = await post("/api/asks/" + a.session + "/" + a.request_id + "/challenge", {});
    const cred = await navigator.credentials.get({ publicKey: { challenge: b64d(c.challenge), rpId: c.rpId, allowCredentials: c.allowCredentials.map((id) => ({ type: "public-key", id: b64d(id) })), userVerification: "required", timeout: 60000 } });
    const r = await post("/api/asks/" + a.session + "/" + a.request_id + "/approve", { credentialId: b64e(cred.rawId), authenticatorData: b64e(cred.response.authenticatorData), clientDataJSON: b64e(cred.response.clientDataJSON), signature: b64e(cred.response.signature) });
    decided.add(a.request_id);
    msg.textContent = r.seeded ? "This was a planted case, and it was not executed. The known error: " + r.seeded.error : "Approved.";
  } catch (e) { msg.className = "msg err"; msg.textContent = e.message; buttons.forEach((b) => b.disabled = false); }
  finally { busy.delete(a.request_id); refresh(); }
}
async function reject(a, msg, buttons) {
  buttons.forEach((b) => b.disabled = true); busy.add(a.request_id);
  try {
    const r = await post("/api/asks/" + a.session + "/" + a.request_id + "/reject", {});
    decided.add(a.request_id);
    msg.textContent = r.seeded ? "Rejected. This was a planted case, and you caught it. The known error: " + r.seeded.error : "Rejected.";
  }
  catch (e) { msg.className = "msg err"; msg.textContent = e.message; buttons.forEach((b) => b.disabled = false); }
  finally { busy.delete(a.request_id); refresh(); }
}

const shown = new Map();
// Decided cards stay until the page is reloaded, so the outcome (and a planted case's known error) can be read.
const decided = new Set();
async function refresh() {
  const root = document.getElementById("asks");
  let data;
  try { const r = await fetch("/api/asks"); data = await r.json(); } catch { return; }
  const s = document.getElementById("seeding");
  if (data.seeding) {
    s.hidden = false;
    s.textContent = "Planted cases: " + data.seeding.statement + " Rates: " + data.seeding.rows.map((r) => r.title + " about " + Math.round(r.rate * 100) + "% of reviews").join("; ") + ". You're never told which cases are planted until you've decided.";
  } else s.hidden = true;
  if (!data.enrolled) { root.replaceChildren(el("p", { class: "empty" }, "No approver is enrolled yet. Start the Guardian with --enroll to get an enrollment link.")); return; }
  const live = new Set(data.asks.map((a) => a.request_id));
  for (const [id, node] of shown) if (!live.has(id) && !busy.has(id) && !decided.has(id)) { node.remove(); shown.delete(id); }
  for (const a of data.asks) {
    if (shown.has(a.request_id)) continue;
    const msg = el("span", { class: "msg" });
    const ok = el("button", { class: "approve" }, "Approve with Touch ID");
    const no = el("button", { class: "reject" }, "Reject");
    ok.onclick = () => approve(a, msg, [ok, no]);
    no.onclick = () => reject(a, msg, [ok, no]);
    const card = el("div", { class: "card" },
      el("div", { class: "tool" }, a.tool),
      el("div", { class: "row" },
        el("span", {}, "Band " + a.band + " · " + a.outcome),
        el("span", {}, "approver: " + a.approver_role),
        el("span", {}, "row: " + a.rows.join(", ")),
        el("span", {}, "agent: " + a.agent),
        el("span", {}, "expires " + new Date(a.expires_at).toLocaleTimeString())),
      el("pre", {}, JSON.stringify(a.arguments, null, 2)),
      el("div", { class: "row" }, "reasons: " + a.reasons.join(", ")),
      el("div", { class: "actions" }, ok, no, msg));
    shown.set(a.request_id, card);
    root.append(card);
  }
  const empty = root.querySelector(".empty");
  if (shown.size === 0 && !empty) root.replaceChildren(el("p", { class: "empty" }, "Nothing is waiting."));
  if (shown.size > 0 && empty) empty.remove();
}

async function enrollPage() {
  const token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
  const btn = document.getElementById("enroll"), msg = document.getElementById("enroll-msg"), roles = document.getElementById("roles");
  let o;
  try { o = await post("/api/enroll/options", { token }); } catch (e) { roles.className = "msg err"; roles.textContent = e.message; return; }
  roles.textContent = "Credential '" + o.user.name + "' for roles: " + o.roles.join(", ");
  btn.disabled = false;
  btn.onclick = async () => {
    btn.disabled = true; msg.className = "msg"; msg.textContent = "Waiting for Touch ID…";
    try {
      const cred = await navigator.credentials.create({ publicKey: {
        challenge: b64d(o.challenge), rp: o.rp, user: { id: b64d(o.user.id), name: o.user.name, displayName: o.user.displayName },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], timeout: 120000, attestation: "none",
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
        excludeCredentials: o.excludeCredentials.map((id) => ({ type: "public-key", id: b64d(id) })) } });
      const r = await post("/api/enroll", { token, registration: { attestationObject: b64e(cred.response.attestationObject), clientDataJSON: b64e(cred.response.clientDataJSON) } });
      msg.textContent = "Enrolled for " + r.roles.join(", ") + ". You can close this page.";
    } catch (e) { msg.className = "msg err"; msg.textContent = e.message + " (the link is single-use: restart enrollment from the terminal)"; }
  };
}

if (location.pathname === "/enroll") enrollPage(); else { refresh(); setInterval(refresh, 2000); }
`;
