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

INITRD_IMG="${1:-/tmp/aienos-recovery-standalone-initrd.img}"

if [[ ! -f "${INITRD_IMG}" ]]; then
    echo "Building standalone recovery initrd..."
    bash "${REPO_ROOT}/scripts/build_standalone_recovery_initrd.sh" "${INITRD_IMG}"
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "Extracting ${INITRD_IMG}..."
gzip -dc "${INITRD_IMG}" | (cd "${WORK_DIR}" && cpio -idm --quiet)

FAILED=0
check() {
    if [[ "$2" == 1 ]]; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        FAILED=1
    fi
}

have_file() { [[ -f "${WORK_DIR}/$1" || -x "${WORK_DIR}/$1" || -L "${WORK_DIR}/$1" ]] && echo 1 || echo 0; }
init_has() { grep -q -- "$1" "${WORK_DIR}/init" 2>/dev/null && echo 1 || echo 0; }
module_packaged() { grep -qxF "$1.ko" "${WORK_DIR}/etc/aienos-modules.order" 2>/dev/null && echo 1 || echo 0; }

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

echo ""
echo "-- init hooks --"
check "init is executable" "$([[ -x "${WORK_DIR}/init" ]] && echo 1 || echo 0)"
check "init keeps zero-disk test mode (aienos.test=1)" "$(init_has 'aienos.test=1')"
check "init reports EFI boot entries (efibootmgr)" "$(init_has 'efibootmgr')"
check "init drops into an interactive maintenance shell" "$(init_has 'exec /bin/sh')"

echo ""
if [[ "${FAILED}" != 0 ]]; then
    echo "RECOVERY_TOOLS: FAIL"
    exit 1
fi
echo "RECOVERY_TOOLS: PASS (initrd ships mount, EFI repair, and boot-entry restore capability)"
