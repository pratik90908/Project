#!/usr/bin/env bash
set -euo pipefail
if [[ "${FAKE_PRIVILEGED_SECRET:-}" == "DOTGIT_PRIVILEGED_SENTINEL" ]]; then
  printf 'privileged_sentinel_observed=true\n' > "$1"
else
  printf 'privileged_sentinel_observed=false\n' > "$1"
fi
