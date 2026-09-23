#!/usr/bin/env bash
# Capture observed Config A data without changing host boot state.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${repo_root}/scripts/capture_config_a.py" "$@"
