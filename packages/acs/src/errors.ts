// JSON-RPC and ACS error codes (ACS §17). An error response is a decision failure for the Observed Agent,
// which under this Guardian's handshake (on_decision_failure: deny) means deny.
export const ERR = {
  PARSE: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
  SESSION_REFUSED: -32000,
  UNSUPPORTED_VERSION: -32001,
  PROVENANCE_REQUIRED: -32002,
  CAPABILITY_NOT_NEGOTIATED: -32003,
  SIGNATURE_INVALID: -32004,
  REPLAY_DETECTED: -32005,
  TIMESTAMP_OUT_OF_WINDOW: -32006,
  CHAIN_MISMATCH: -32007,
} as const;

export class AcsError extends Error {
  override name = "AcsError";
  readonly code: number;
  readonly data: Record<string, unknown>;
  constructor(code: number, message: string, data: Record<string, unknown> = {}) {
    super(message);
    this.code = code;
    this.data = { reason: message, ...data };
  }
}
