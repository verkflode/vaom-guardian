#!/bin/bash
source "$(dirname "$0")/common.sh"
cat /does/not/exist/file >/dev/null && echo unreachable; kill -SEGV $$
