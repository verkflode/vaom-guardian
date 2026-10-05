# What Claude Code does when a PreToolUse hook fails

An experiment, run on 2026-10-05 against **Claude Code 2.1.285**, to find out whether a guardian behind a Claude Code `PreToolUse` hook can fail closed. The documentation says a failed hook is a "non-blocking error"; this measures what that means in practice.

## Method

Each run creates a throwaway project whose `PreToolUse` hook (matcher `Bash`, timeout 5 s) behaves in one specific way, then asks the model, non-interactively (`claude -p`, Haiku, at most 3 turns), to run `touch CANARY`. **If the file `CANARY` appears, the tool ran.** Each hook logs that it was invoked, which separates "the hook was skipped" from "the model never tried". Settings come only from the test project (`--setting-sources project`), plus `--settings` where noted.

Hook behaviours: explicit `deny` and explicit `allow` (controls); exit 2; exit 1 with no output; exit 1 with non-JSON output; exit 0 with malformed JSON; a crash (SIGSEGV); a timeout; a missing hook command; a hook that exits 0 with no output (no opinion); and no hook at all.

Rerun: `./run.sh <scenario> <mode>` prints one result row. Scenarios are the scripts in `hooks/` plus `missing` and `nohook`.

## Results

| Hook behaviour | Default mode, call pre-approved by an allow-rule | Default/manual mode, not pre-approved | `bypassPermissions` |
|---|---|---|---|
| explicit `deny` | **blocked** | **blocked** | **blocked** |
| exit 2 | **blocked** | **blocked** | **blocked** |
| explicit `allow` | ran | ran | ran |
| no opinion (exit 0, no output) | ran | prompt (denied: `-p` can't prompt) | ran |
| exit 1, no output | ran | prompt | ran |
| exit 1, non-JSON output | ran | prompt | ran |
| exit 0, malformed JSON | ran | prompt | ran |
| crash | ran | prompt | ran |
| timeout | ran | prompt | ran |
| missing command | ran | prompt | ran |
| no hook at all | ran | prompt | ran |

Raw rows: `results-allowrule.tsv`, `results-modes.tsv`, `results-controls.tsv`.

## Findings

1. **An explicit `deny` (or exit 2) blocks in every mode, `bypassPermissions` included.** A guardian that answers is obeyed.
2. **Every hook failure is treated exactly as a hook with no opinion.** The call falls through to Claude Code's normal permission flow. So it **fails open whenever the call would otherwise be allowed**: when an allow-rule pre-approves it, or in `bypassPermissions`. It degrades to a human prompt only when Claude Code would have prompted anyway.
3. **The hook input carries `tool_use_id`, identical in `PreToolUse` and `PostToolUse`, and `permission_mode`.** (The hook documentation reviewed beforehand didn't list `tool_use_id`.) A guardian can therefore tie a decision to the execution that followed, and see the permission mode it's operating under.
4. Side findings, not needed for the conclusions: `permissions.allow` in the untrusted test project was ignored while its hooks ran (the same rule via `--settings` applied); and in `-p` runs, `auto` and `manual` modes didn't approve `touch`, so those two columns of `results-modes.tsv` say nothing about hooks. The table above uses the default-mode runs with a working rule.

## What this means for a guardian

A guardian can't make Claude Code fail closed on its own. What it can do:

- **Answer explicitly, always.** The shim turns every failure it can observe into an explicit `deny`, under its own deadline shorter than the hook timeout.
- **Be the only source of pre-approval.** With no allow-rules for governed tools, the guardian's own `allow` is what skips the prompt, so a guardian that can't run at all degrades to Claude Code's prompt instead of silent execution.
- **Refuse bypass.** The shim sees `permission_mode` and can deny every call under `bypassPermissions`. That holds while the shim runs; if it can't run and bypass is on, calls execute unguarded, and nothing on the hook side can prevent it.
