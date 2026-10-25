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

export const SHIM_KEY_FORMAT = "vaom-guardian.shim-key/0.1";

/** What a shim needs and nothing more: where the Guardian listens and the ACS key, without the fact key. */
export interface ShimKey { port: number; keyId: string; ikm: Uint8Array }

/**
 * The shim's key file, for a shim that runs as another OS user than the Guardian and so can't read the
 * Guardian's data directory. It holds the ACS pre-shared key, which the agent's account then holds too:
 * whoever has it can sign as the shim, or answer as a Guardian when none is listening on the port.
 */
export function shimKeyFile(secrets: Secrets, port: number): string {
  return JSON.stringify({ format: SHIM_KEY_FORMAT, port, key_id: secrets.keyId, ikm: Buffer.from(secrets.ikm).toString("base64") }, null, 2) + "\n";
}

/** Read a shim key file. Like secrets.json, it must be readable by its owner only. */
export function loadShimKey(path: string): ShimKey {
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) throw new Error(`${path} is readable by other users (mode ${mode.toString(8)}); chmod 600 it`);
  const j = JSON.parse(readFileSync(path, "utf8"));
  const ikm = new Uint8Array(Buffer.from(String(j?.ikm ?? ""), "base64"));
  if (j?.format !== SHIM_KEY_FORMAT || !Number.isInteger(j.port) || j.port < 1024 || j.port > 65535 || typeof j.key_id !== "string" || ikm.length < 32) throw new Error(`${path} is not a ${SHIM_KEY_FORMAT} file`);
  return { port: j.port, keyId: j.key_id, ikm };
}
