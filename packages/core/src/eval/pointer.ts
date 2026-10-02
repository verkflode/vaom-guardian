// RFC 6901 JSON Pointer resolution over plain values. Returns undefined when the path doesn't exist.
export function resolvePointer(doc: unknown, pointer: string): unknown {
  if (pointer === "") return doc;
  let cur: unknown = doc;
  for (const raw of pointer.slice(1).split("/")) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(cur)) {
      if (!/^(0|[1-9]\d*)$/.test(key)) return undefined;
      cur = cur[Number(key)];
    } else if (typeof cur === "object" && cur !== null && Object.hasOwn(cur, key)) {
      cur = (cur as Record<string, unknown>)[key];
    } else {
      return undefined;
    }
  }
  return cur;
}
