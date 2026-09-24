#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
exec cargo run --quiet --release -p aienos-evidence -- verify "${1:-evidence/config_a_reference_bundle.json}"
