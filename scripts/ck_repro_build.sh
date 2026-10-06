#!/usr/bin/env bash
# ck_repro_build.sh -- build the AIENOS C kernel UEFI image twice from the same
# clean commit, in two fresh output folders, and compare the sha256 digests
# (docs/native/PREFLIGHT-AND-RECOVERY.md section 1). Host only: builds files
# under a temp folder, never touches the ESP, NVRAM, firmware, keys or any disk.
#
# Usage: bash scripts/ck_repro_build.sh [full|core] [--keep DIR]
#   full (default)  make full: the image with the boot stages
#   core            make: the core-only image (the M1 / M0_ROLLBACK candidate)
#   --keep DIR      copy build A's BOOTAA64.EFI to DIR (for staging later)
# The hardware staging image (CK_HARDWARE_STAGING=1) needs the owner's files
# and is built by the stage scripts; this script does not build it.
#
# Prints both digests and, last, one line:
#   CK_REPRO_BUILD: PASS <kind> commit=<commit> sha256=<digest>
#   CK_REPRO_BUILD: FAIL <kind> (digests differ: <a> <b>)
# Exit 0 PASS, 1 FAIL, 2 usage error, dirty tree or build failure.
# The digest changes with every commit (the commit hash is built into the
# image), so it is recorded per commit, never written down in advance.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

kind=full keep=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        full|core) kind="$1"; shift ;;
        --keep) [[ $# -ge 2 ]] || { echo "--keep needs a folder"; exit 2; }; keep="$2"; shift 2 ;;
        *) echo "usage: $0 [full|core] [--keep DIR]"; exit 2 ;;
    esac
done

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "refused: the working tree is not clean (a digest must map to one commit)"
    git status --short | head -20
    exit 2
fi
commit="$(git rev-parse HEAD)"
cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
target=""; [[ "${kind}" == full ]] && target=full

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
declare -A digest=()
for b in a b; do
    out="${work}/ck-${b}"
    if ! make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" ${target} >"${work}/build-${b}.log" 2>&1; then
        tail -20 "${work}/build-${b}.log"
        echo "CK_REPRO_BUILD: FAIL ${kind} (build ${b} failed)"
        exit 2
    fi
    img="${out}/BOOTAA64.EFI"
    [[ "${kind}" == full ]] && img="${out}/full/BOOTAA64.EFI"
    [[ -f "${img}" ]] || { echo "CK_REPRO_BUILD: FAIL ${kind} (build ${b} produced no ${img#"${work}"/})"; exit 2; }
    digest[${b}]="$(sha256sum "${img}" | cut -c1-64)"
    echo "build ${b}: ${digest[${b}]}  $(stat -c %s "${img}") bytes  (OUT=${out})"
    [[ "${b}" == a ]] && img_a="${img}"
done
echo "commit: ${commit}"
echo "toolchain: $(${cross}gcc --version | head -1); $(${cross}ld --version | head -1)"
if [[ -n "${keep}" ]]; then
    mkdir -p "${keep}"
    cp "${img_a}" "${keep}/BOOTAA64.EFI"
    echo "kept: ${keep}/BOOTAA64.EFI"
fi
if [[ "${digest[a]}" == "${digest[b]}" ]]; then
    echo "CK_REPRO_BUILD: PASS ${kind} commit=${commit} sha256=${digest[a]}"
    exit 0
fi
echo "CK_REPRO_BUILD: FAIL ${kind} (digests differ: ${digest[a]} ${digest[b]})"
exit 1
