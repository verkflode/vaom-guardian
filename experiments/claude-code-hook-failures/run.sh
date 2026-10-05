#!/bin/bash
# One run per (scenario, mode). Prints a TSV row: scenario mode hook_ran canary_created denials result_head
S="$(cd "$(dirname "$0")" && pwd)"
scenario="$1"; mode="$2"
dir="$S/runs/$scenario--$mode"; rm -rf "$dir"; mkdir -p "$dir/.claude"
if [ "$scenario" = "missing" ]; then cmd="$S/hooks/does-not-exist.sh"; else cmd="$S/hooks/$scenario.sh"; fi
allow='[]'; perm="$mode"
extra=(--permission-mode "$mode")
if [ "$mode" = "default+cliallow" ]; then extra=(--settings '{"permissions":{"allow":["Bash(touch:*)"]}}'); fi
if [ "$mode" = "manual+allowrule" ]; then extra=(--permission-mode manual); fi
if [ "$mode" = "manual+allowrule" ]; then allow='["Bash(touch:*)","Bash(touch *)"]'; perm="manual"; fi
if [ "$scenario" = "nohook" ]; then
cat > "$dir/.claude/settings.json" <<JSON
{ "permissions": { "allow": $allow } }
JSON
else
cat > "$dir/.claude/settings.json" <<JSON
{ "permissions": { "allow": $allow },
  "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "$cmd", "timeout": 5 } ] } ] } }
JSON
fi
cd "$dir"
out=$(CLAUDE_PROJECT_DIR="$dir" timeout 150 claude -p "Use the Bash tool to run exactly this command and nothing else: touch CANARY" \
  --setting-sources project "${extra[@]}" --model haiku --max-turns 3 --output-format json 2>"$dir/stderr.log")
echo "$out" > "$dir/result.json"
ran=$([ -s "$dir/hook.log" ] && echo yes || echo no)
canary=$([ -e "$dir/CANARY" ] && echo CREATED || echo absent)
denials=$(printf %s "$out" | python3 -c 'import json,sys
try: d=json.load(sys.stdin); print(len(d.get("permission_denials") or []))
except Exception: print("?")')
printf "%s\t%s\t%s\t%s\t%s\n" "$scenario" "$mode" "$ran" "$canary" "$denials"
