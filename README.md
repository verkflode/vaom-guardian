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

The Guardian itself is not built yet.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
