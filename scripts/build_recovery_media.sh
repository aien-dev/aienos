#!/usr/bin/env bash
# build_recovery_media.sh: Build standalone UEFI recovery system on target USB drive
# Certified for Secure Boot execution using signed Shim + GRUB / standalone RAM recovery payload.
# Invariant: 100% self-contained RAM disk under rdinit=/init. Internal NVMe must not be mounted.
# Guard: Multi-factor validation rejects ATLAS_RECOV (label, UUID, PARTUUID) and host internal NVMe.
# Invariant: NO PLAINTEXT SECRETS IN REPOSITORY OR BUILD ARTIFACTS. Unslop compliant.

set -euo pipefail

TARGET_DEV="${1:-}"

if [[ -z "${TARGET_DEV}" ]]; then
    echo "Usage: $0 <target-partition> (e.g. /dev/sdb1)" >&2
    echo "Error: Target block device must be explicitly specified." >&2
    exit 1
fi

if [[ ! -b "${TARGET_DEV}" ]]; then
    echo "Error: Target ${TARGET_DEV} is not a valid block device." >&2
    exit 1
fi

# Multi-factor identity inspection
TARGET_LABEL=$(lsblk -no LABEL "${TARGET_DEV}" 2>/dev/null || blkid -s LABEL -o value "${TARGET_DEV}" 2>/dev/null || true)
TARGET_UUID=$(lsblk -no UUID "${TARGET_DEV}" 2>/dev/null || blkid -s UUID -o value "${TARGET_DEV}" 2>/dev/null || true)
TARGET_PARTUUID=$(lsblk -no PARTUUID "${TARGET_DEV}" 2>/dev/null || blkid -s PARTUUID -o value "${TARGET_DEV}" 2>/dev/null || true)
TARGET_MOUNTS=$(lsblk -no MOUNTPOINTS "${TARGET_DEV}" 2>/dev/null || true)

# 1. Reject ATLAS_RECOV by label, filesystem UUID, and partition UUID
KNOWN_ATLAS_RECOV_UUID="669D-4D0E"
KNOWN_ATLAS_RECOV_PARTUUID="335d7260-01"

if [[ "${TARGET_LABEL}" == "ATLAS_RECOV" || "${TARGET_UUID}" == "${KNOWN_ATLAS_RECOV_UUID}" || "${TARGET_PARTUUID}" == "${KNOWN_ATLAS_RECOV_PARTUUID}" ]]; then
    echo "FATAL: Target matches ATLAS_RECOV identity (Label: ${TARGET_LABEL}, UUID: ${TARGET_UUID}, PARTUUID: ${TARGET_PARTUUID})." >&2
    echo "ATLAS_RECOV contains encrypted offline recovery keys and must NEVER be overwritten." >&2
    exit 1
fi

# 2. Reject internal NVMe storage and system partitions
KNOWN_HOST_ROOT_UUID="d27bfd26-ff30-400e-9eca-9cdf73de9406"
KNOWN_HOST_EFI_UUID="9DA2-3597"

if [[ "${TARGET_DEV}" == *"nvme"* || "${TARGET_UUID}" == "${KNOWN_HOST_ROOT_UUID}" || "${TARGET_UUID}" == "${KNOWN_HOST_EFI_UUID}" ]]; then
    echo "FATAL: Target ${TARGET_DEV} is an internal host system disk or EFI system partition." >&2
    exit 1
fi

# 3. Reject active host mounts
if [[ -n "${TARGET_MOUNTS}" ]]; then
    echo "FATAL: Target ${TARGET_DEV} has active mountpoints: ${TARGET_MOUNTS}. Unmount before provisioning." >&2
    exit 1
fi

# 4. If target is a disk containing partitions, ensure none of its child partitions match ATLAS_RECOV
CHILD_IDS=$(lsblk -no LABEL,UUID,PARTUUID "${TARGET_DEV}" 2>/dev/null || true)
if echo "${CHILD_IDS}" | grep -qE "ATLAS_RECOV|${KNOWN_ATLAS_RECOV_UUID}|${KNOWN_ATLAS_RECOV_PARTUUID}"; then
    echo "FATAL: Device ${TARGET_DEV} contains partition matching ATLAS_RECOV identity." >&2
    exit 1
fi

MOUNT_POINT="/mnt/aienos-recovery"
echo "Building AIENOS standalone recovery media on ${TARGET_DEV}..."

sudo mkdir -p "${MOUNT_POINT}"
sudo mount "${TARGET_DEV}" "${MOUNT_POINT}"

cleanup() {
    sudo umount "${MOUNT_POINT}" 2>/dev/null || true
    sudo rmdir "${MOUNT_POINT}" 2>/dev/null || true
}
trap cleanup EXIT

echo "Populating EFI boot structure..."
sudo mkdir -p "${MOUNT_POINT}/EFI/BOOT"
sudo mkdir -p "${MOUNT_POINT}/aienos-recovery"

# Copy signed Microsoft-compatible Shim as default UEFI fallback bootloader
sudo cp /boot/efi/EFI/boot/BOOTAA64.EFI "${MOUNT_POINT}/EFI/BOOT/BOOTAA64.EFI"
sudo cp /boot/efi/EFI/ubuntu/grubaa64.efi "${MOUNT_POINT}/EFI/BOOT/grubaa64.efi"
sudo cp /boot/efi/EFI/ubuntu/mmaa64.efi "${MOUNT_POINT}/EFI/BOOT/mmaa64.efi" 2>/dev/null || true

# Copy current signed production kernel
PROD_VMLINUZ=$(ls -1t /boot/vmlinuz-* | head -n 1)
echo "Copying signed production kernel: ${PROD_VMLINUZ}"
sudo cp "${PROD_VMLINUZ}" "${MOUNT_POINT}/aienos-recovery/vmlinuz"

# Build and copy standalone RAM-only recovery initrd (zero NVMe root dependencies)
INITRD_TMP="/tmp/aienos-recovery-standalone-initrd.img"
echo "Building standalone RAM recovery initrd..."
bash "$(dirname "$0")/build_standalone_recovery_initrd.sh" "${INITRD_TMP}"

echo "Copying standalone recovery initrd to media..."
sudo cp "${INITRD_TMP}" "${MOUNT_POINT}/aienos-recovery/initrd.img"
rm -f "${INITRD_TMP}"

# Create standalone recovery GRUB config that boots directly to RAM maintenance shell
cat << "GRUB_EOF" | sudo tee "${MOUNT_POINT}/EFI/BOOT/grub.cfg" > /dev/null
set timeout=5
set default=0

menuentry "AIENOS Standalone Recovery System (RAM Maintenance Core)" {
    search --no-floppy --file --set=root /aienos-recovery/vmlinuz
    linux /aienos-recovery/vmlinuz rdinit=/init console=tty0 console=ttyAMA0,115200n8 quiet
    initrd /aienos-recovery/initrd.img
}

menuentry "AIENOS Standalone Recovery System (Automated EFI Repair)" {
    search --no-floppy --file --set=root /aienos-recovery/vmlinuz
    linux /aienos-recovery/vmlinuz rdinit=/init aienos.repair=1 console=tty0 console=ttyAMA0,115200n8
    initrd /aienos-recovery/initrd.img
}

menuentry "Reboot to Incumbent Linux" {
    exit
}
GRUB_EOF

sync
echo "AIENOS standalone recovery media build complete on ${TARGET_DEV}."
