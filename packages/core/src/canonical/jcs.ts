// JSON Canonicalization Scheme (RFC 8785): the canonical form ACS signs and chain-hashes, and the
// form record digests use. Strict: values outside the JSON data model (undefined, functions, bigint,
// non-finite numbers) throw instead of being silently dropped or changed.
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError(`JCS: non-finite number ${value}`);
      return Object.is(value, -0) ? "0" : JSON.stringify(value); // ES6 Number serialization
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
      const keys = Object.keys(value).sort(compareUtf16);
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize((value as Record<string, unknown>)[k])}`).join(",")}}`;
    }
    default:
      throw new TypeError(`JCS: ${typeof value} is not JSON`);
  }
}

/** RFC 8785 sorts property names by their UTF-16 code units, which is plain string comparison in JS. */
function compareUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
