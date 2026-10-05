// The Guardian's secrets: the ACS pre-shared key (shared with the shim) and the fact key for private
// facts in records. Generated on first start into a 0600 file. A process running as the same OS user can
// read it; see the README on what that means for the strength of the boundary.
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";

export interface Secrets { ikm: Uint8Array; factKey: Uint8Array; keyId: string }

export function loadSecrets(path: string, create: boolean): Secrets {
  if (!existsSync(path)) {
    if (!create) throw new Error(`no secrets file at ${path}`);
    const s = { format: "vaom-guardian.secrets/0.1", key_id: `guardian-${randomBytes(4).toString("hex")}`, ikm: randomBytes(32).toString("base64"), fact_key: randomBytes(32).toString("base64") };
    writeFileSync(path, JSON.stringify(s, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  }
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) throw new Error(`${path} is readable by other users (mode ${mode.toString(8)}); chmod 600 it`);
  const j = JSON.parse(readFileSync(path, "utf8"));
  const ikm = new Uint8Array(Buffer.from(j.ikm, "base64")), factKey = new Uint8Array(Buffer.from(j.fact_key, "base64"));
  if (ikm.length < 32 || factKey.length < 32 || typeof j.key_id !== "string") throw new Error(`${path} is malformed`);
  return { ikm, factKey, keyId: j.key_id };
}
