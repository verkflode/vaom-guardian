# Changelog

## 0.1.0 (2026-10-25)

The first tagged release of the VAOM Guardian: a reference implementation of the
[Verkflöde Agent Operating Model (VAOM) v5.0](https://vaom.ai/) as an
[OWASP Agent Control Standard (ACS)](https://github.com/genai-security-project/agent-control-standard)
Guardian. It fails closed, enforces a VAOM Delegation Authority Matrix, and produces evidence that the
boundaries hold.

It is a reference implementation and an evidence generator, not a production security product. A Guardian
`deny` is policy strength, and the [Limits](README.md#limits) say where each guarantee ends. Read them
before running it near anything real.

The packages are not published to npm. Use it from a clone: Node 22.18 or later and pnpm.

### What's in it

- **Formats** (`schema/`): JSON Schemas for the Delegation Authority Matrix (`vaom.matrix/0.1`, frozen;
  `vaom.matrix/0.2`, draft), the binding of an agent host's tools to matrix capabilities
  (`vaom.binding/0.1`), scoring policies (`vaom.scoring/0.1`), seeded review cases (`vaom.seeds/0.1`),
  boundary probes and their results (`vaom.probes/0.1`, `vaom.probe-result/0.1`) and decision records
  (`vaom.decision/0.4`; `0.3` still validates). Every format but matrix 0.1 is a draft and can change
  before it is frozen.
- **The pure core** (`packages/core`): the linter, which decides whether a matrix, binding and scoring
  policies may run; the evaluator and `decide`, which place a tool call in a band and reserve its cap
  uses in one step; confidence scores computed from facts and history, never supplied by the agent;
  execution contexts, leases and sub-agent attenuation; the Delegation Scorecard (VAOM v5 §11) from
  decision records; boundary verification from probe results. No I/O and no runtime dependencies: it
  runs in Node and the browser. VAOM v5's worked examples 7B, 7D and 7E run end to end as tests.
- **The ACS wire adapter** (`packages/acs`): handshake, HMAC-SHA256 signatures with per-session keys
  derived as ACS §10 settles them and `key_id` checked, replay protection and a hash-chained audit trail;
  `on_decision_failure: "deny"`; review and escalation as `ask`, non-delegable as `deny`, unplaceable as
  `defer`, each with a deny on timeout.
- **The Guardian process** (`packages/guardian`): the ACS endpoint on 127.0.0.1, append-only evidence
  synced to disk before it answers, approvals by WebAuthn with user verification (Touch ID), seeded
  cases, spawn and probe evidence, and the `verify` and `scorecard` commands. `verify` checks a
  configuration the way the Guardian does before it starts, then re-checks the stored evidence.
- **The Claude Code shim** (`packages/claude-code`): hooks that put every tool call and sub-agent spawn
  behind the Guardian. Anything other than a verified `allow` or a signed approval is a deny, and every
  decision failure is recorded in the shim's own audit log and counted at session end. Measured on Claude
  Code 2.1.296.
- **Boundary probes** (`packages/probe`): real Claude Code sessions that attempt each forbidden action
  against a canary and report the mechanism that held.

### Compatibility

- **ACS:** pinned to the specification at repository tag `v0.1.4` (commit `834f3f0d51e7`, specification
  text 0.1.0), with two rules settled after that tag implemented ahead of the next one: the HMAC key
  derivation and `key_id` (§10) and recording every decision failure (§6.4). The Guardian sends
  `acs_version` 0.1.0 and accepts any 0.1 patch release. It declares the `acs-core` profile; the
  README's [failure posture](README.md#acs-version-and-failure-posture) lists the one Core item it
  doesn't meet (wrapped MCP) and what else is out of v0.1 scope.
- **Formats:** a configuration that `verify` accepts under 0.1.0 names its format versions; later
  releases will say which of them change.

### Also using it

The [Delegation Lab](https://lab.vaom.ai) runs this core in the browser for every decision in the game,
across four scenarios built on the worked examples, and exports files that `verify` checks.
