// The ACS version this adapter implements. Pinned: the spec moves, and a version bump means rewriting
// this adapter, never the core.
export const ACS_SPEC_VERSION = "0.1.0";
export const ACS_PIN = { tag: "v0.1.2", commit: "7743826b2ec02e3daf47a08c82170fc7a43b0838" } as const;

/** 0.1.x only: while the major version is 0, a different minor version may change meaning (ACS #196). */
export function acceptsVersion(v: string): boolean {
  return /^0\.1\.(0|[1-9]\d*)$/.test(v);
}
