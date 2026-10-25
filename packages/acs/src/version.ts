// The ACS version this adapter implements. Pinned: the spec moves, and a version bump means rewriting
// this adapter, never the core.
export const ACS_SPEC_VERSION = "0.1.0";
export const ACS_PIN = { tag: "v0.1.4", commit: "834f3f0d51e7bbbd9a68ff682bec89f97ddd72d8" } as const;

/** 0.1.x only: while the major version is 0, a different minor version may change meaning (ACS #196). */
export function acceptsVersion(v: string): boolean {
  return /^0\.1\.(0|[1-9]\d*)$/.test(v);
}
