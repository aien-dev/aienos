#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${repo_root}/scripts/verify_evidence.py" "${1:-${repo_root}/evidence/config_a_reference_bundle.json}"
