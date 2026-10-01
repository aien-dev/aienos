#!/usr/bin/env bash
# verify_recovery_tools.sh: Verify that the standalone recovery initrd ships
# the tooling issue #17 requires: mount the NVMe root, repair /boot/efi, and
# restore boot entries. Host-side, static check only: extracts the built
# initrd and greps for files and init hooks. No real devices, no root, no
# QEMU boot (qemu_verify_recovery_media.sh already covers the boot itself).
# Zero Disk Secrets and Unslop compliant.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

# With an argument: inspect exactly that image, and fail if it is missing
# (never substitute a freshly built one). Without: build a private copy in
# WORK_DIR, so parallel runs never share a fixed /tmp path and no stale
# user-owned file is left where a root build would later collide with it.
if [[ $# -ge 1 ]]; then
    INITRD_IMG="$1"
    if [[ ! -f "${INITRD_IMG}" ]]; then
        echo "FAIL  initrd image not found: ${INITRD_IMG}" >&2
        exit 1
    fi
else
    INITRD_IMG="${WORK_DIR}/aienos-recovery-standalone-initrd.img"
# Repo checks run on hosts without gocryptfs (CI, laptops). Only there, and
# visibly, allow a test image without it. The real stick build
# (build_recovery_media.sh) never sets this.
if ! command -v gocryptfs >/dev/null 2>&1 && [[ ! -f /home/atlas/atlas-forgejo-setup-20260904/runtime/usr/bin/gocryptfs && -z "${AIENOS_GOCRYPTFS:-}" ]]; then
    echo "SKIP  gocryptfs not on this host; building a TEST-ONLY image without it"
    export AIENOS_RECOVERY_ALLOW_NO_GOCRYPTFS=1
fi

    echo "Building standalone recovery initrd..."
    bash "${REPO_ROOT}/scripts/build_standalone_recovery_initrd.sh" "${INITRD_IMG}"
fi

ROOT_DIR="${WORK_DIR}/root"
mkdir -p "${ROOT_DIR}"

echo "Extracting ${INITRD_IMG}..."
gzip -dc "${INITRD_IMG}" | (cd "${ROOT_DIR}" && cpio -idm --quiet)

FAILED=0
check() {
    if [[ "$2" == 1 ]]; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        FAILED=1
    fi
}

have_file() { [[ -f "${ROOT_DIR}/$1" || -x "${ROOT_DIR}/$1" || -L "${ROOT_DIR}/$1" ]] && echo 1 || echo 0; }
init_has() { grep -q -- "$1" "${ROOT_DIR}/init" 2>/dev/null && echo 1 || echo 0; }
module_packaged() { grep -qxF "$1.ko" "${ROOT_DIR}/etc/aienos-modules.order" 2>/dev/null && echo 1 || echo 0; }

echo ""
echo "-- required tools for NVMe root mount --"
check "busybox present" "$(have_file bin/busybox)"
check "mount present" "$(have_file bin/mount)"
check "lsblk present" "$(have_file bin/lsblk)"
check "blkid present" "$(have_file bin/blkid)"
check "cryptsetup present" "$(have_file bin/cryptsetup)"
check "nvme kernel module packaged" "$(module_packaged nvme)"
check "dm-crypt kernel module packaged" "$(module_packaged dm-crypt)"

echo ""
echo "-- required tools for /boot/efi repair --"
check "fsck.vfat present" "$(have_file bin/fsck.vfat)"
check "mkfs.vfat present" "$(have_file bin/mkfs.vfat)"
check "fsck.ext4 present" "$(have_file bin/fsck.ext4)"
check "efibootmgr present" "$(have_file bin/efibootmgr)"

echo ""
echo "-- required tools for boot-entry restore --"
check "efibootmgr present (boot entries)" "$(have_file bin/efibootmgr)"
check "chroot present" "$(have_file bin/chroot)"
check "findmnt present for attended evidence collector" "$(have_file bin/findmnt)"
check "attended evidence collector packaged on media" "$(have_file usr/local/sbin/collect_recovery_boot_evidence)"

echo ""
echo "-- TRUST-1 Gate 1 items 8, 10, 11-12: TPM, signatures, recovery unlock --"
check "tpm2_pcrread present" "$(have_file bin/tpm2_pcrread)"
check "tpm2 device transport library packaged (dlopen, not seen by ldd)" \
    "$(compgen -G "${ROOT_DIR}/lib/*-linux-gnu/libtss2-tcti-device.so.0*" >/dev/null && echo 1 || echo 0)"
check "sbverify present" "$(have_file bin/sbverify)"
check "age present" "$(have_file bin/age)"
if [[ "${AIENOS_RECOVERY_ALLOW_NO_GOCRYPTFS:-0}" == 1 ]]; then
    echo "SKIP  gocryptfs present (TEST-ONLY image built on a host without gocryptfs)"
else
    check "gocryptfs present" "$(have_file bin/gocryptfs)"
fi
check "fusermount3 present" "$(have_file bin/fusermount3)"

# Every shared library each recovery tool needs (and what those need in
# turn) must be inside the image itself, or the tool fails only later, in the
# rescue shell. Static check with readelf: no root, no execution.
lib_in_image() {
    local d
    for d in lib lib64 usr/lib lib/aarch64-linux-gnu usr/lib/aarch64-linux-gnu lib/x86_64-linux-gnu usr/lib/x86_64-linux-gnu; do
        [[ -e "${ROOT_DIR}/${d}/$1" ]] && { echo "${ROOT_DIR}/${d}/$1"; return 0; }
    done
    return 1
}
closure_ok() { # binary path inside image
    local queue=("$1") seen=" " f lib p
    while [[ ${#queue[@]} -gt 0 ]]; do
        f="${queue[0]}"; queue=("${queue[@]:1}")
        while read -r lib; do
            [[ "${seen}" == *" ${lib} "* ]] && continue
            seen+="${lib} "
            p="$(lib_in_image "${lib}")" || { echo "missing ${lib} (needed by ${f##*/})" >&2; echo 0; return; }
            queue+=("$(readlink -f "${p}")")
        done < <(readelf -d "${f}" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
    done
    echo 1
}
if command -v readelf >/dev/null; then
    for t in gocryptfs age sbverify tpm2_pcrread cryptsetup fusermount3 efibootmgr; do
        [[ -e "${ROOT_DIR}/bin/${t}" ]] || continue
        check "${t}: every shared library it needs is inside the image" "$(closure_ok "${ROOT_DIR}/bin/${t}")"
    done
    tcti="$(compgen -G "${ROOT_DIR}/lib/*-linux-gnu/libtss2-tcti-device.so.0" | head -n 1 || true)"
    [[ -z "${tcti}" ]] || check "tpm2 device transport: its libraries are inside the image" "$(closure_ok "$(readlink -f "${tcti}")")"
else
    echo "SKIP  library closure checks (readelf not installed)"
fi

echo ""
echo "-- init hooks --"
check "init is executable" "$([[ -x "${ROOT_DIR}/init" ]] && echo 1 || echo 0)"
check "init keeps zero-disk test mode (aienos.test=1)" "$(init_has 'aienos.test=1')"
check "init reports EFI boot entries (efibootmgr)" "$(init_has 'efibootmgr')"
check "init drops into an interactive maintenance shell" "$(init_has 'exec /bin/sh')"

echo ""
if [[ "${FAILED}" != 0 ]]; then
    echo "RECOVERY_TOOLS: FAIL"
    exit 1
fi
echo "RECOVERY_TOOLS: PASS (initrd ships mount, EFI repair, and boot-entry restore capability)"
