import type { SchemaError } from "../generated/validators.js";
import type { Finding } from "./types.ts";

/** Turn validator errors into findings. Every one is an error: a document that fails its schema is rejected. */
export function schemaFindings(errors: SchemaError[] | null | undefined): Finding[] {
  if (!errors || errors.length === 0) {
    return [{ rule: "schema", severity: "error", path: "", message: "schema validation failed without details" }];
  }
  return errors.map((e) => ({
    rule: "schema",
    severity: "error" as const,
    path: e.instancePath,
    message: `${e.message ?? e.keyword}${Object.keys(e.params).length ? ` ${JSON.stringify(e.params)}` : ""}`,
  }));
}
