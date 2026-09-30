# VAOM Guardian

A reference implementation of the Verkflöde Agent Operating Model (VAOM) as an [OWASP Agent Control Standard](https://github.com/genai-security-project/agent-control-standard) Guardian: it fails closed, enforces a VAOM Delegation Authority Matrix, and produces evidence that the boundaries hold.

**What it is:** a reference implementation, an evidence generator, and a contributor to ACS conformance work.

**What it isn't:** a production security product, an enterprise platform, or an approval app. A Guardian `deny` is a policy-strength control; the project's reports say so, and push towards boundaries that don't depend on it.

## Status

Early. Available so far:

- `schema/`: JSON Schemas for the Delegation Authority Matrix (`vaom.matrix/0.1`, frozen; `0.2`, draft) and for binding an agent host's tools to matrix capabilities (`vaom.binding/0.1`, draft), with examples and tests.

The Guardian itself is not built yet.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
