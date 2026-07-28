#!/usr/bin/env bash
set -euo pipefail
printf 'ATTACKER_CODE_EXECUTED=yes\n' > "$RUNNER_TEMP/deleted-fork-exec-marker.txt"
printf 'FAKE_SECRET_OBSERVED=%s\n' "${FAKE_REPO_SECRET:-missing}" >> "$RUNNER_TEMP/deleted-fork-exec-marker.txt"
