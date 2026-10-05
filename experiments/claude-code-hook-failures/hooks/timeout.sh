#!/bin/bash
source "$(dirname "$0")/common.sh"
sleep 25; printf %s '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"too late"}}'; exit 0
