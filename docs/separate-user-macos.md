# The Guardian as a separate macOS user

**Status: draft, written 2026-10-25. It becomes a tested recipe once the checklist at the end has been run
on a real Mac and the results are recorded there.**

By default the Guardian runs as the same OS user as the agent. The agent can then read the Guardian's data
directory, including its secrets, edit its policy files, and stop it ([limits](../README.md#limits)). This
recipe runs the Guardian under its own account, so that the operating system, not policy, keeps the agent
away from it.

## What it changes, and what it doesn't

With this setup, the agent's account **can't**:

- read or change the Guardian's evidence, its secrets file (including the fact key) or its credentials;
- change the matrix, binding, scoring policies or configuration the Guardian enforces;
- change the Guardian's code or the Node.js it runs on;
- stop the Guardian, or read its memory (where the page token lives);
- remove or switch off the shim's hooks, re-enable bypass mode or add its own allow-rules (managed settings).

What stays as it was:

- **A `deny` is still policy strength.** Claude Code, running as the agent, enforces the Guardian's
  answers. The separate account protects the Guardian; it doesn't make the agent host obey.
- **The agent's account holds the ACS key.** The shim runs as the agent, so its key file is readable by
  the agent. Whatever holds the key can sign requests as the shim (the Guardian still decides every one)
  and, while no Guardian is listening on the port, answer as one. Doing either needs code execution in the
  agent's account, which takes tool calls the Guardian allowed.
- **The shim's state is the agent's.** Tampering with it breaks chain heads (denies) or the links between
  calls and their results (which `verify` reports); it grants nothing.
- **Administrators are outside the boundary.** Anyone who can `sudo` can do everything below in reverse.

## Accounts and paths

| What | Owner | Path |
|---|---|---|
| Node.js | root | `/usr/local/bin/node` (the nodejs.org installer) |
| Guardian and shim code | root | `/usr/local/vaom-guardian` |
| Claude Code | root | `/usr/local/bin/claude` (global npm install) |
| Managed settings | root | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Guardian account | `vaomguardian` (standard, hidden) | home `/Users/vaomguardian`, mode 700 |
| Guardian config and data | `vaomguardian` | `/Users/vaomguardian/guardian/` |
| Agent account | `vaomagent` (standard, **not** admin) | home `/Users/vaomagent` |
| Shim key and state | `vaomagent` | `/Users/vaomagent/.vaom-guardian/` |

Why these owners:

- **Nothing the Guardian runs may be writable by the agent.** Homebrew's `/opt/homebrew` belongs to the
  user who installed it, so a Homebrew `node` is replaceable by that user. Use the nodejs.org installer.
- **The agent must not be an administrator.** An administrator can make system-wide changes with its
  password (`sudo`, installers, System Settings), including to the managed settings; the agent needs none
  of that.
- **Claude Code is root-owned** so the agent can't swap its own host for one that skips hooks. Updates
  then need an administrator, so automatic updates are switched off in the managed settings.

Run every step below as an administrator, in Terminal or over SSH. Commands that start with `sudo` ask for
your password.

## 1. Node.js, pnpm and Claude Code

Install the current LTS of Node.js (22.18 or later) with the macOS installer from nodejs.org, then:

```sh
ls -l /usr/local/bin/node                      # owner root
sudo npm install -g pnpm@11.9.0 @anthropic-ai/claude-code@<version>
ls -l /usr/local/bin/pnpm /usr/local/bin/claude
```

## 2. The two accounts

```sh
for u in vaomguardian vaomagent; do
  sudo sysadminctl -addUser "$u" -fullName "$u" -password "$(openssl rand -base64 30)"
done
sudo dscl . create /Users/vaomguardian IsHidden 1
sudo chmod 700 /Users/vaomguardian /Users/vaomagent
dseditgroup -o checkmember -m vaomagent admin  # must say: no vaomagent is NOT a member of admin
```

The Guardian account's password is random and thrown away: nobody logs in as it; it is only ever run with
`sudo -u`. The agent account gets a password you keep if you want to log in as it; otherwise reset it later
with `sudo sysadminctl -resetPasswordFor vaomagent`.

## 3. The code

Use a commit that has `vaom-guardian shim-key` (it isn't in 0.1.0).

```sh
sudo git clone https://github.com/verkflode/vaom-guardian.git /usr/local/vaom-guardian
sudo git -C /usr/local/vaom-guardian checkout <commit or tag>
cd /usr/local/vaom-guardian && sudo pnpm install --prod --frozen-lockfile --ignore-scripts
```

`--prod` installs no third-party code: the packages depend only on each other and on Node.js.

## 4. The Guardian's configuration

As the Guardian's account, write its config. This example runs the incident example (VAOM worked example
7D); for your own matrix, point `matrix`, `binding` and `scoring` at files the agent can't write.

```sh
sudo -u vaomguardian mkdir -m 700 /Users/vaomguardian/guardian
sudo -u vaomguardian tee /Users/vaomguardian/guardian/guardian.json > /dev/null <<'JSON'
{
  "format": "vaom-guardian.config/0.1",
  "matrix": "/usr/local/vaom-guardian/schema/examples/incident.matrix.json",
  "binding": "/usr/local/vaom-guardian/schema/examples/incident.binding.json",
  "scoring": [
    "/usr/local/vaom-guardian/schema/examples/remediation-gate.scoring.json",
    "/usr/local/vaom-guardian/schema/examples/incident-detection.scoring.json"
  ],
  "dataDir": "/Users/vaomguardian/guardian/data",
  "port": 47100,
  "approvalTimeoutSeconds": 300,
  "activation": { "incident-agent": { "rows": ["remediation.restart"], "task": "INC-7" } }
}
JSON
# A function, not a variable: zsh (the macOS default) doesn't split a variable into words.
G() { sudo -u vaomguardian -H /usr/local/bin/node /usr/local/vaom-guardian/packages/guardian/src/cli.ts "$@"; }
G verify --config /Users/vaomguardian/guardian/guardian.json
```

## 5. The shim's key

`shim-key` writes only what the shim needs: the port, the key id and the ACS key, without the fact key. It
refuses to print to a terminal, so pipe it straight into the agent's file:

```sh
sudo -v   # so the two sudo commands in the pipe don't both ask for your password
sudo -u vaomagent mkdir -m 700 /Users/vaomagent/.vaom-guardian
G shim-key --config /Users/vaomguardian/guardian/guardian.json \
  | sudo -u vaomagent sh -c 'umask 077; cat > /Users/vaomagent/.vaom-guardian/shim-key.json'
```

A new key (after deleting the Guardian's `secrets.json`) means running this again.

## 6. Managed settings

Print the hooks for the agent, then add the managed-only settings to them:

```sh
sudo -u vaomagent -H /usr/local/bin/node /usr/local/vaom-guardian/packages/claude-code/src/cli.ts settings \
  --key /Users/vaomagent/.vaom-guardian/shim-key.json --agent incident-agent \
  --state /Users/vaomagent/.vaom-guardian/claude-code --for-user vaomagent > /tmp/vaom-hooks.json
```

Add the managed-only keys, and install the result:

```sh
/usr/local/bin/node -e '
  const fs = require("fs"), f = "/tmp/vaom-hooks.json", s = JSON.parse(fs.readFileSync(f, "utf8"));
  Object.assign(s, { allowManagedHooksOnly: true, allowManagedPermissionRulesOnly: true, env: { DISABLE_AUTOUPDATER: "1" } });
  fs.writeFileSync(f, JSON.stringify(s, null, 2) + "\n");'
sudo mkdir -p "/Library/Application Support/ClaudeCode"
sudo install -m 644 -o root -g wheel /tmp/vaom-hooks.json "/Library/Application Support/ClaudeCode/managed-settings.json"
rm /tmp/vaom-hooks.json
```

Managed settings apply to every account on the Mac: Claude Code has no per-user managed settings. The
hooks carry `--for-user vaomagent`, so for any other account the shim answers nothing (no opinion) and
Claude Code works as it would without them. The managed-only settings below aren't per-user, though:
under other accounts too, Claude Code ignores hooks and allow-rules from user and project settings.

What each part does:

- **The hooks** run the shim with the absolute path of the root-owned `node`, for `vaomagent` only. The
  shim checks its real account, from the system's user database, so the agent can't pass for another.
- **`permissions.disableBypassPermissionsMode`** keeps bypass mode off.
- **`allowManagedHooksOnly`** blocks hooks from user, project, local and plugin settings, so nothing runs
  beside the shim.
- **`allowManagedPermissionRulesOnly`** ignores allow-rules anywhere else, so the Guardian's `allow` is
  the only pre-approval.

Managed hooks can't be switched off from user or project settings (`disableAllHooks` there doesn't reach
them).

## 7. Run the Guardian

In a terminal you keep open:

```sh
G serve --config /Users/vaomguardian/guardian/guardian.json --enroll owner:sre-lead
```

It prints the approvals link (with this run's page token) and a one-time enrolment link. Both use
`http://localhost:47100`. The page refuses any other host, so open them either:

- **on the Mac itself**, or
- **from another Mac, through an SSH tunnel** with the same port on both ends:
  `ssh -L 47100:127.0.0.1:47100 <this Mac>`. Touch ID is then the other Mac's, and the passkey you enrol
  lives there. While the tunnel is open, processes on that Mac can reach the port too; they still need the
  page token to see or reject asks, and a Touch ID assertion to approve.

To keep it running across restarts, a LaunchDaemon with `UserName` `vaomguardian` does the same job; its
output (with the links) then goes to a log only that account and administrators can read.

## 8. The agent

Log in to Claude Code as the agent (`sudo -iu vaomagent`, then `claude`), and work in a project under
`/Users/vaomagent`.

## Checklist

Run as the agent (`sudo -iu vaomagent`) unless it says otherwise. Each line says what should happen.

| # | Check | Expected |
|---|---|---|
| 1 | `ls /Users/vaomguardian` | Permission denied |
| 2 | `cat /Users/vaomguardian/guardian/data/secrets.json` | Permission denied |
| 3 | `touch /usr/local/vaom-guardian/x` | Permission denied |
| 4 | `touch "/Library/Application Support/ClaudeCode/x"`, and `mv` of that folder | Permission denied |
| 5 | `pkill -u vaomguardian node` | Operation not permitted |
| 6 | `curl -s -H 'host: localhost:47100' localhost:47100/api/asks` | 401 |
| 7 | `claude -p` asking for a governed read (`mcp__telemetry__query`) | allowed by the Guardian |
| 8 | `claude -p` asking for `Bash` | denied by the Guardian |
| 9 | `claude -p` asking for a restart; approve it with Touch ID | runs after the approval |
| 10 | `claude --dangerously-skip-permissions` | bypass mode refused |
| 11 | `disableAllHooks: true` in `~/.claude/settings.json`, then 8 again | still denied |
| 12 | Guardian stopped, then 7 again | denied |
| 13 | As an administrator: `G verify --config …` | no problems |
| 14 | Boundary probes (`vaom-probe run`) as the agent, imported with `G probe import` | results imported |

Checks 7 to 9 need the agent project from [`experiments/claude-code-shim/`](../experiments/claude-code-shim/)
(its MCP stubs) or your own tools bound in the binding.

## Test record

Not run yet.
