// VAOM Guardian's ACS wire adapter, pinned to ACS v0.1.4 (spec text 0.1.0). Pure: no I/O.
export { ACS_PIN, ACS_SPEC_VERSION, acceptsVersion } from "./version.ts";
export { AcsError, ERR } from "./errors.ts";
export { fromBase64, toBase64 } from "./base64.ts";
export { hkdfSha256, sessionKey } from "./hkdf.ts";
export { HMAC_SHA256, sign, signingInput, verify, type Signature, type Verified } from "./sign.ts";
export { ReplayGuard } from "./replay.ts";
export { Chain, entryHash, requestHash, verifyChain, type ContextEntry, type EntryFields } from "./chain.ts";
export { negotiate, PROFILES, type GuardianConfig } from "./handshake.ts";
export { toCall, toResult, type ResultInput, type ResultOptions } from "./translate.ts";
export { AcsEndpoint, OBSERVED_STEPS, type EndpointConfig, type EndpointDeps, type Handled, type Incident, type Spawn } from "./endpoint.ts";
