# VAOM Guardian

A reference implementation of the Verkflöde Agent Operating Model (VAOM) as an [OWASP Agent Control Standard](https://github.com/genai-security-project/agent-control-standard) Guardian: it fails closed, enforces a VAOM Delegation Authority Matrix, and produces evidence that the boundaries hold.

**What it is:** a reference implementation, an evidence generator, and a contributor to ACS conformance work.

**What it isn't:** a production security product, an enterprise platform, or an approval app. A Guardian `deny` is a policy-strength control; the project's reports say so, and push towards boundaries that don't depend on it.

## ACS version and failure posture

- **Pinned spec:** ACS repository tag [`v0.1.2`](https://github.com/GenAI-Security-Project/agent-control-standard/tree/v0.1.2) (commit `7743826b2ec0`), whose specification text is version 0.1.0. The Guardian sends `acs_version: "0.1.0"` and accepts 0.1.x only (any patch release; a different minor version is refused, see ACS issue #196).
- **Fails closed, unlike the ACS default.** ACS defaults `on_decision_failure` to `proceed` (fail-open, §6.4). This Guardian declares `on_decision_failure: "deny"` in its handshake, and its Claude Code shim refuses to start a session unguarded when the handshake gets no answer (§4.1, whose default is also `proceed`). The Guardian alone can't guarantee this: the shim and the host's hook behaviour have to fail closed as well, and the project will test that rather than assume it.

## Status

Early. Available so far:

- `schema/`: JSON Schemas for the Delegation Authority Matrix (`vaom.matrix/0.1`, frozen; `0.2`, draft) and for binding an agent host's tools to matrix capabilities (`vaom.binding/0.1`, draft), with examples and tests. (The frozen 0.1 schema's own description still reads "Draft 0.1, a sketch": that text was frozen with it.)

- `packages/core`: the pure core (no I/O, no eval, zero runtime dependencies, runs in Node and the browser). So far it holds the **linter**, `lintMatrix` and `lintBinding`: JSON Schema validation through validators compiled ahead of time, plus the rules JSON Schema can't express, such as reference integrity, uniqueness, currency consistency, lease lifetimes, sub-agent authority, funded review load, and the binding checked against its matrix. It fails closed: an unknown format or a schema failure is never accepted.

It also holds the **evaluator**, `compilePolicy` and `evaluate`: it places one tool call in a band from a lint-clean matrix and binding. The confidence score must come from the row's scoring policy, never the agent; ceilings, caps, restrictions and missing verification only ever narrow; batch items count toward caps together; and anything it can't place is `unplaceable`, never allowed. It returns the cap uses to reserve, for the cap store that comes next.

And it holds **decision records** (`vaom.decision/0.3`, schema in `schema/vaom-decision-0.3.schema.json`): each decision as replayable evidence (matrix and binding versions, outcome, band, approver, reasons, cap reservations, and later its resolution). Arguments are stored only as a digest; facts are recorded in clear, as a keyed digest, or not at all, as the binding says. A record that can't be built means no action.

The **cap ledger** and **`decide`** complete the decision path: `decide` evaluates a call against the ledger, builds its record and reserves its cap uses in one synchronous step, so parallel calls can't each see room under a cap only one of them fits in. Pending approvals count as used until resolved; rejected, expired and withdrawn ones are released. Until its history is loaded the ledger refuses to reserve, so no decision is made against unknown usage. A ledger rebuilt from decision records matches the live one exactly.

**Execution contexts and leases** bound authority in time. A call has authority only inside a live context covering its row (bound to its task, if given); contexts expire, can't be reused, and revocation cascades. Sub-agent contexts can only narrow: fewer rows, stricter band ceilings, earlier expiry, within the matrix's depth and fan-out, and a spawn outside the allowed patterns needs escalation. Leases give continuous agents short, renewable observation authority; acting needs a per-alert response context; a failed health check withdraws response authority at once; and at the maximum lifetime without human re-attestation the lease degrades to observe-only, never extends.

The Guardian itself (the ACS wire and the host shims) is not built yet.

## Development

Requires Node 22+ and pnpm. `pnpm install`, then `pnpm test` (core tests and schema tests) and `pnpm typecheck`. After changing a schema, run `pnpm gen:validators`; a test fails if the committed validators are stale.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
