// The Claude Code settings that wire the shim in. Two things in them matter as much as the hooks:
//
// - No allow-rules for the tools the Guardian governs. Claude Code treats a hook that can't run as "no
//   opinion", so with an allow-rule a dead shim means silent execution; without one it means Claude Code's
//   own prompt. The Guardian's allow should be the only pre-approval.
// - bypassPermissions disabled. The shim denies every call under it while the shim runs; disabling the
//   mode also covers the case where the shim can't run at all. Put this in managed or user settings, where
//   the agent's project can't override it.
export const HOOK_TIMEOUT_SECONDS = 600;

/** Where the shim finds the Guardian: its configuration (same OS user) or a shim key file (another user).
 *  `node` is the interpreter's absolute path, so the hook doesn't run whichever `node` comes first on the
 *  agent's PATH. */
export type SettingsInput = { node: string; script: string; agent: string; state: string; matcher?: string; forUser?: string } & ({ guardian: string } | { key: string });

const quote = (s: string) => `'${s.replaceAll("'", `'\\''`)}'`;

export function hookSettings(i: SettingsInput): unknown {
  const source = "key" in i ? ["--key", quote(i.key)] : ["--guardian", quote(i.guardian)];
  const command = [quote(i.node), quote(i.script), "hook", ...source, "--agent", quote(i.agent), "--state", quote(i.state), ...(i.forUser ? ["--for-user", quote(i.forUser)] : [])].join(" ");
  const tool = (timeout: number) => [{ matcher: i.matcher ?? "*", hooks: [{ type: "command", command, timeout }] }];
  const session = (timeout: number) => [{ hooks: [{ type: "command", command, timeout }] }];
  return {
    permissions: { disableBypassPermissionsMode: "disable" },
    hooks: {
      SessionStart: session(30),
      PreToolUse: tool(HOOK_TIMEOUT_SECONDS),
      PostToolUse: tool(30),
      PostToolUseFailure: tool(30),
      SubagentStart: session(30),
      SubagentStop: session(30),
      SessionEnd: session(10),
    },
  };
}
