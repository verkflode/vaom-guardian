#!/bin/bash
# Log that the hook ran (into the project dir it runs in), then misbehave as named.
echo "ran $(date +%s)" >> "$CLAUDE_PROJECT_DIR/hook.log" 2>/dev/null || echo "ran" >> ./hook.log
