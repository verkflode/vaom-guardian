// handshake/hello (ACS §4). This Guardian always declares on_decision_failure: deny, departing from the
// ACS default of proceed, and offers HMAC-SHA256 only.
import type { ServerHello } from "./generated/types.ts";
import { validateClientHello, validateServerHello } from "./generated/validators.js";
import { AcsError, ERR } from "./errors.ts";
import { HMAC_SHA256 } from "./sign.ts";
import { acceptsVersion, ACS_SPEC_VERSION } from "./version.ts";

export interface GuardianConfig {
  methodsEvaluated: readonly string[];
  defaultTimeoutMs: number;
  perMethodTimeoutMs?: Readonly<Record<string, number>>;
  skewWindowMs: number;
  profiles: readonly string[];
}

export const PROFILES = ["acs-core", "acs-audit"] as const;

export function negotiate(hello: unknown, cfg: GuardianConfig): ServerHello {
  if (!validateClientHello(hello)) throw new AcsError(ERR.INVALID_PARAMS, "ClientHello fails its schema", { errors: validateClientHello.errors });
  const h = hello;
  const versions = h.acs_versions_supported.filter(acceptsVersion).sort(cmp);
  const negotiated = versions.at(-1);
  if (!negotiated) throw new AcsError(ERR.UNSUPPORTED_VERSION, "no common ACS version", { supported_versions: [ACS_SPEC_VERSION] });
  if (!h.transports_supported.includes("http")) throw new AcsError(ERR.SESSION_REFUSED, "this Guardian speaks HTTP only");
  const implemented = new Set<string>(h.methods_implemented);
  const serverHello = {
    negotiated_version: negotiated,
    methods_evaluated: cfg.methodsEvaluated.filter((m) => implemented.has(m)),
    selected_transport: "http",
    signature_algorithms_supported: [HMAC_SHA256],
    timeout_config: { default_ms: cfg.defaultTimeoutMs, ...(cfg.perMethodTimeoutMs ? { per_method_ms: cfg.perMethodTimeoutMs } : {}) },
    skew_window_ms: cfg.skewWindowMs,
    on_decision_failure: "deny",
    approver_types_supported: ["human"],
    policy_requires_provenance: false,
    profiles_accepted: cfg.profiles.filter((p) => new Set<string>(h.profiles_supported ?? []).has(p)),
  };
  if (!validateServerHello(serverHello)) throw new AcsError(ERR.INTERNAL, "built ServerHello fails its schema", { errors: validateServerHello.errors });
  return serverHello;
}

function cmp(a: string, b: string): number {
  const x = a.split(".").map(Number), y = b.split(".").map(Number);
  return x[0]! - y[0]! || x[1]! - y[1]! || x[2]! - y[2]!;
}
