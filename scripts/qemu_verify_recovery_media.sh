#!/usr/bin/env bash
# qemu_verify_recovery_media.sh: Verify standalone recovery environment in QEMU AArch64
# Invariant: BOOTS WITH ZERO HARD DISKS ATTACHED. Internal NVMe must not be present.
# Proves 100% RAM disk self-containment under rdinit=/init.
# Zero Disk Secrets and Unslop compliant.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT
LOG="${WORK_DIR}/recovery_qemu.log"

PROD_VMLINUZ=$(sudo -n ls -1t /boot/vmlinuz-* 2>/dev/null | head -n 1 || ls -1t /boot/vmlinuz-* 2>/dev/null | head -n 1 || true)
if [[ -z "${PROD_VMLINUZ}" ]]; then
    echo "Error: Signed production kernel not found in /boot" >&2
    exit 1
fi

KERNEL_IMAGE="${WORK_DIR}/vmlinuz"
if [[ -r "${PROD_VMLINUZ}" ]]; then
    cp "${PROD_VMLINUZ}" "${KERNEL_IMAGE}"
else
    sudo -n cp "${PROD_VMLINUZ}" "${KERNEL_IMAGE}"
    sudo -n chown "$(id -u):$(id -g)" "${KERNEL_IMAGE}"
fi

INITRD_TMP="${WORK_DIR}/aienos-recovery-standalone-initrd.img"
echo "Building standalone recovery initrd..."
bash "${REPO_ROOT}/scripts/build_standalone_recovery_initrd.sh" "${INITRD_TMP}"

echo "Booting standalone recovery kernel in QEMU with ZERO hard disks attached..."
started=$(date +%s)
set +e
timeout 30 qemu-system-aarch64 \
    -M virt -cpu max -smp 2 -m 1024 \
    -kernel "${KERNEL_IMAGE}" \
    -initrd "${INITRD_TMP}" \
    -append "rdinit=/init aienos.test=1 console=ttyAMA0 panic=1 quiet" \
    -display none -nic none \
    -serial file:"${LOG}" -no-reboot
QEMU_STATUS=$?
set -e
elapsed=$(( $(date +%s) - started ))

tr -d '\r' <"${LOG}" >"${WORK_DIR}/recovery_qemu.txt"

failed=0
check() {
    if grep -q -- "$2" "${WORK_DIR}/recovery_qemu.txt"; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        failed=1
    fi
}

echo "qemu exit ${QEMU_STATUS} after ${elapsed} s"
check "Recovery banner displayed" "AIENOS Standalone Hardware Recovery Core"
check "100% RAM disk verified" "Root filesystem: 100% RAM disk"
check "Internal NVMe confirmed unmounted" "Internal NVMe status: UNMOUNTED"
check "Automated recovery test passed" "TEST MODE DETECTED: automated recovery verification complete"

if [[ "${failed}" != 0 ]]; then
    echo "---- recovery console log ----"
    cat "${WORK_DIR}/recovery_qemu.txt"
    echo "RECOVERY_ZERO_DISK: FAIL"
    exit 1
fi

echo "RECOVERY_ZERO_DISK: PASS (verified standalone RAM recovery with zero attached storage)"
