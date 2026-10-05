#!/bin/bash
source "$(dirname "$0")/common.sh"
echo "blocked by exit 2" >&2; exit 2
