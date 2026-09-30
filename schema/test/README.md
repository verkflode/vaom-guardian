# Schema tests

`node run.mjs` (matrix) runs 42 single-mutation cases and all 27 routings against both matrix versions (0.1 frozen, 0.2 draft), so 0.2 provably keeps every 0.1 invariant. It also runs 16 preparatory-row cases and 6 cases for a prototype of the matrix linter's preparatory rules. `POS-` cases must pass; the rest must fail.

There's no package.json yet (the repo and language are undecided), so `ajv` and `ajv-formats` have to be resolvable from this directory. For now, symlink a `node_modules` that contains them. When the repo exists, this becomes a normal test.

`node run-binding.mjs` validates the example binding against the 0.2 matrix: 10 schema cases, 13 cross-file cases, and a check that its read entries are ungoverned under the 0.1 matrix. The cross-file cases run against a prototype of the binding linter's rules (binding checked against the matrix).
