// The VAOM Guardian process: ACS over local HTTP, append-only evidence, WebAuthn approvals.
export { createGuardian, readConfig, CONFIG_FORMAT, VERSION, type Guardian, type GuardianFileConfig, type Activation } from "./guardian.ts";
export { createGuardianServer, shimSignature } from "./server.ts";
export { Approvals, ApprovalError, type Ask, type AskStatus, type Credential } from "./approvals.ts";
export { Store, type GuardianEvent, type ChainLine } from "./store.ts";
export { loadSecrets, type Secrets } from "./secrets.ts";
export { verifyEvidence, type EvidenceReport } from "./evidence.ts";
export { verifyAssertion, verifyRegistration, WebAuthnError, b64url } from "./webauthn.ts";
