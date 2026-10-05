#!/bin/bash
source "$(dirname "$0")/common.sh"
printf %s '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"guardian says no"}}'; exit 0
