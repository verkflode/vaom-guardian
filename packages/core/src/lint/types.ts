export type Severity = "error" | "warning";

export interface Finding {
  /** Stable rule name, e.g. "ref.role" or "schema". */
  rule: string;
  severity: Severity;
  /** JSON Pointer (RFC 6901) into the document the finding is about. */
  path: string;
  message: string;
}

export interface LintResult {
  /** True only when there are no errors. Warnings don't block acceptance. */
  ok: boolean;
  /** The document's declared format, if it was readable. */
  format: string | null;
  findings: Finding[];
}

/** Documents are walked after schema validation, so their shape is known; this alias marks those reads. */
export type Validated = any;

export function result(format: string | null, findings: Finding[]): LintResult {
  return { ok: !findings.some((f) => f.severity === "error"), format, findings };
}

/** Escape one JSON Pointer token. */
export function tok(key: string | number): string {
  return String(key).replace(/~/g, "~0").replace(/\//g, "~1");
}
