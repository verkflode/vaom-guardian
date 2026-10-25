// The Claude Code shim for VAOM Guardian.
export { runHook, UnclassifiedHookError, METHODS_IMPLEMENTED, HOST_INTERNAL_TOOLS, SPAWN_TOOLS, type HookOutput, type ShimOptions } from "./hook.ts";
export { DecisionFailure, failureClass, GuardianClient, GuardianError, type ClientConfig, type FailureClass, type FailureReport } from "./client.ts";
export { StateDir, type SessionState, type CallState, type SpawnState, type AcsSessionState, type FailureEntry } from "./state.ts";
export { hookSettings, HOOK_TIMEOUT_SECONDS, type SettingsInput } from "./settings.ts";
