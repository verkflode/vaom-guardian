# Schema tests

Both runners print their own counts, which are the authoritative numbers. As of 2026-10-01:

- `node run.mjs` (matrix): for each version, 0.1 (frozen) and 0.2 (draft), the example plus 41 single-mutation cases and all 27 confidence routings against an independent monotonicity oracle. The shared cases check the same invariants on both versions; this is strong evidence that 0.2 keeps 0.1's invariants, not a proof. 0.2 alone adds 22 schema cases (preparatory rows, value ceilings) and 6 cases for a prototype of the matrix linter's preparatory rules. Two cross-version checks confirm each version rejects the other's example. One test records a known gap in frozen 0.1: a financial Band A row with no value ceiling still validates there, while 0.2 rejects it. `POS-` cases must pass; the rest must fail.
- `node run-binding.mjs`: the example binding against the 0.2 matrix (schema and lint), 12 schema cases, 14 cross-file cases for a prototype of the binding linter, and a check that the binding's read entries are ungoverned under the 0.1 matrix.

The linter itself isn't built yet. These prototypes cover only part of the rules listed in the design notes.

There's no package.json yet, so `ajv` and `ajv-formats` have to be resolvable from this directory. For now, symlink a `node_modules` that contains them.
