# Schema tests

These test the JSON Schemas alone. The rules JSON Schema can't express (reference integrity, uniqueness, review-load arithmetic, binding against matrix) are the linter's, tested in `packages/core/test/`.

Run from the repo root: `pnpm test:schema` (or `pnpm test` for everything). Both runners print their own counts, which are the authoritative numbers. As of 2026-10-02:

- `run.mjs` (matrix): for each version, 0.1 (frozen) and 0.2 (draft), the example plus 41 single-mutation cases and all 27 confidence routings against an independent monotonicity oracle. The shared cases check the same invariants on both versions; this is strong evidence that 0.2 keeps 0.1's invariants, not a proof. 0.2 alone adds 22 schema cases (preparatory rows, value ceilings). Two cross-version checks confirm each version rejects the other's example, and one test records a known gap in frozen 0.1: a financial Band A row with no value ceiling still validates there, while 0.2 rejects it. `POS-` cases must pass; the rest must fail.
- `run-binding.mjs`: the example binding and 12 single-mutation schema cases.
