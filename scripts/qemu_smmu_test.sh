#!/usr/bin/env bash
# Exercise IORT discovery, SMMUv3 translation and real xHCI keyboard DMA.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
AIENOS_QEMU_SMMU=1 exec bash scripts/qemu_keyboard_test.sh
