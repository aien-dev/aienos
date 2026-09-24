#!/usr/bin/env bash
# qemu_verify_recovery_media.sh: Verify standalone recovery environment in QEMU AArch64
# Invariant: BOOTS WITH ZERO HARD DISKS ATTACHED. Internal NVMe must not be present.
# Proves 100% RAM disk self-containment under rdinit=/init.
# Zero Disk Secrets and Unslop compliant.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }

if [[ "$(uname -m)" != "aarch64" ]]; then
    echo "SKIPPED: Host architecture is $(uname -m). AArch64 kernel recovery boot requires an AArch64 host or cross-built AArch64 kernel."
    exit 0
fi

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

# Second boot: the packaged drivers must find a USB stick, an NVMe drive and a
# USB keyboard. The disks are blank scratch images, never host storage.
DEV_LOG="${WORK_DIR}/recovery_devices.log"
truncate -s 64M "${WORK_DIR}/usb.img" "${WORK_DIR}/nvme.img"
ACCEL=(-cpu max)
DEV_TIMEOUT=120
if [[ -w /dev/kvm ]]; then
    ACCEL=(-accel kvm -cpu host)
    DEV_TIMEOUT=60
fi

echo "Booting recovery kernel with a scratch USB stick, NVMe drive and USB keyboard..."
set +e
timeout "${DEV_TIMEOUT}" qemu-system-aarch64 \
    -M virt "${ACCEL[@]}" -smp 2 -m 1024 \
    -kernel "${KERNEL_IMAGE}" \
    -initrd "${INITRD_TMP}" \
    -append "rdinit=/init aienos.test=1 console=ttyAMA0 panic=1" \
    -device qemu-xhci -device usb-kbd \
    -drive if=none,id=usbstick,format=raw,file="${WORK_DIR}/usb.img" -device usb-storage,drive=usbstick \
    -drive if=none,id=nvme0,format=raw,file="${WORK_DIR}/nvme.img" -device nvme,drive=nvme0,serial=aienos-test \
    -display none -nic none \
    -serial file:"${DEV_LOG}" -no-reboot
DEV_STATUS=$?
set -e

tr -d '\r' <"${DEV_LOG}" >"${WORK_DIR}/recovery_devices.txt"
echo "qemu exit ${DEV_STATUS}"

failed=0
check_devices() {
    if grep -qE -- "$2" "${WORK_DIR}/recovery_devices.txt"; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        failed=1
    fi
}
modules_line=$(grep -m1 'Kernel modules loaded:' "${WORK_DIR}/recovery_devices.txt" || true)
if [[ "${modules_line}" =~ loaded:\ ([0-9]+)/([0-9]+) ]] && [[ "${BASH_REMATCH[1]}" == "${BASH_REMATCH[2]}" ]] && [[ "${BASH_REMATCH[2]}" -gt 0 ]]; then
    echo "PASS  All packaged kernel modules loaded (${BASH_REMATCH[1]}/${BASH_REMATCH[2]})"
else
    echo "FAIL  All packaged kernel modules loaded (${modules_line:-no report})"
    failed=1
fi
check_devices "USB keyboard detected" "Input devices: [1-9]"
check_devices "USB stick visible" "^sda"
check_devices "NVMe drive visible" "^nvme0n1"

if [[ "${failed}" != 0 ]]; then
    echo "---- recovery device console log ----"
    cat "${WORK_DIR}/recovery_devices.txt"
    echo "RECOVERY_DEVICES: FAIL"
    exit 1
fi

echo "RECOVERY_DEVICES: PASS (packaged drivers found USB keyboard, USB stick and NVMe)"
