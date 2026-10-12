// The VAOM Guardian process: ACS over local HTTP, append-only evidence, WebAuthn approvals.
export { createGuardian, readConfig, CONFIG_FORMAT, VERSION, type Guardian, type GuardianFileConfig, type Activation, type SeedOptions } from "./guardian.ts";
export { createGuardianServer, shimSignature } from "./server.ts";
export { Approvals, ApprovalError, type Ask, type AskStatus, type Credential } from "./approvals.ts";
export { Store, type GuardianEvent, type ChainLine } from "./store.ts";
export { loadSecrets, type Secrets } from "./secrets.ts";
export { importProbeResults, verifyEvidence, type EvidenceReport } from "./evidence.ts";
export { verifyAssertion, verifyRegistration, WebAuthnError, b64url } from "./webauthn.ts";
export { Seeder, type Seed, type SeedSet } from "./seeding.ts";
