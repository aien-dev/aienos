#!/usr/bin/env bash
# Exercise IORT discovery, SMMUv3 translation and real xHCI keyboard DMA.
# Always the confined path: the unsafe DMA bypass is forced off here.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
unset AIENOS_BUILD_FEATURES
AIENOS_UNSAFE_DMA_BYPASS=0 AIENOS_QEMU_SMMU=1 exec bash scripts/qemu_keyboard_test.sh
