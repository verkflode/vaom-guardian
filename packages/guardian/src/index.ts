// The VAOM Guardian process: ACS over local HTTP, append-only evidence, WebAuthn approvals.
export { checkConfig, createGuardian, readConfig, CONFIG_FORMAT, VERSION, type Guardian, type GuardianFileConfig, type Activation, type SeedOptions } from "./guardian.ts";
export { createGuardianServer, shimSignature } from "./server.ts";
export { Approvals, ApprovalError, type Ask, type AskStatus, type Credential } from "./approvals.ts";
export { Store, type GuardianEvent, type ChainLine } from "./store.ts";
export { loadSecrets, loadShimKey, shimKeyFile, SHIM_KEY_FORMAT, type Secrets, type ShimKey } from "./secrets.ts";
export { importProbeResults, verifyEvidence, type EvidenceReport } from "./evidence.ts";
export { listCredentials, revokeCredential, type CredentialInfo } from "./credentials.ts";
export { verifyAssertion, verifyRegistration, WebAuthnError, b64url } from "./webauthn.ts";
export { Seeder, type Seed, type SeedSet } from "./seeding.ts";
