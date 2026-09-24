#!/usr/bin/env bash
# Capture observed Config A data without changing host boot state.
# Arguments pass through to `aienos-evidence capture` (see --help text there),
# for example: --model PATH --repo aienos=PATH --repo aien-sovereign-core=PATH
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
exec cargo run --quiet --release -p aienos-evidence -- capture "$@"
