// Approver credentials as the store records them: enrolled through the page (a terminal token gates it),
// revoked from the CLI. Revocation is an event like any other; a running Guardian reads it before
// accepting an approval, and `verify` flags anything a credential signed after it.
import { randomUUID } from "node:crypto";
import type { Store } from "./store.ts";

export interface CredentialInfo { id: string; label: string; roles: string[]; enrolled: string; revoked?: string }

export function listCredentials(store: Store): CredentialInfo[] {
  const out = new Map<string, CredentialInfo>();
  for (const e of store.events()) {
    if (e.type === "enrolled") out.set(e.credential_id as string, { id: e.credential_id as string, label: e.label as string, roles: e.roles as string[], enrolled: e.ts });
    if (e.type === "credential-revoked") { const c = out.get(e.credential_id as string); if (c) c.revoked = e.ts; }
  }
  return [...out.values()];
}

/** Revoke an enrolled credential. Throws if there's no such credential, or it's already revoked. */
export function revokeCredential(store: Store, id: string, now: number): CredentialInfo {
  const c = listCredentials(store).find((x) => x.id === id);
  if (!c) throw new Error(`no enrolled credential ${id}`);
  if (c.revoked) throw new Error(`credential ${id} was already revoked at ${c.revoked}`);
  const ts = new Date(now).toISOString();
  store.appendEvents([{ type: "credential-revoked", id: randomUUID(), ts, credential_id: id }]);
  return { ...c, revoked: ts };
}
