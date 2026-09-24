#!/usr/bin/env bash
# build_recovery_media.sh: Build standalone UEFI recovery system on target USB drive
# Certified for Secure Boot execution using signed Shim + GRUB / standalone recovery payload.
# Operator-authorized variance recorded for /dev/sda (ATLAS_RECOV repurposing).

set -euo pipefail

TARGET_DEV="${1:-/dev/sda1}"
MOUNT_POINT="/mnt/aienos-recovery"

echo "Building AIENOS recovery media on $TARGET_DEV..."

if [ ! -b "$TARGET_DEV" ]; then
    echo "Error: Target $TARGET_DEV is not a block device" >&2
    exit 1
fi

sudo mkdir -p "$MOUNT_POINT"
sudo mount "$TARGET_DEV" "$MOUNT_POINT"

cleanup() {
    sudo umount "$MOUNT_POINT" 2>/dev/null || true
    sudo rmdir "$MOUNT_POINT" 2>/dev/null || true
}
trap cleanup EXIT

echo "Populating EFI boot structure..."
sudo mkdir -p "$MOUNT_POINT/EFI/BOOT"
sudo mkdir -p "$MOUNT_POINT/aienos-recovery"

# Copy signed Microsoft-compatible Shim as default UEFI fallback bootloader
sudo cp /boot/efi/EFI/boot/BOOTAA64.EFI "$MOUNT_POINT/EFI/BOOT/BOOTAA64.EFI"
sudo cp /boot/efi/EFI/ubuntu/grubaa64.efi "$MOUNT_POINT/EFI/BOOT/grubaa64.efi"
sudo cp /boot/efi/EFI/ubuntu/mmaa64.efi "$MOUNT_POINT/EFI/BOOT/mmaa64.efi" 2>/dev/null || true

# Copy current signed production kernel and initrd into recovery tree
PROD_VMLINUZ=$(ls -1t /boot/vmlinuz-* | head -n 1)
PROD_INITRD=$(ls -1t /boot/initrd.img-* | head -n 1)

echo "Copying signed production kernel: $PROD_VMLINUZ"
sudo cp "$PROD_VMLINUZ" "$MOUNT_POINT/aienos-recovery/vmlinuz"
echo "Copying initrd: $PROD_INITRD"
sudo cp "$PROD_INITRD" "$MOUNT_POINT/aienos-recovery/initrd.img"

# Create standalone recovery GRUB config that boots directly to maintenance shell
cat << "GRUB_EOF" | sudo tee "$MOUNT_POINT/EFI/BOOT/grub.cfg" > /dev/null
set timeout=5
set default=0

menuentry "AIENOS Standalone Recovery System (Emergency Maintenance)" {
    search --no-floppy --file --set=root /aienos-recovery/vmlinuz
    linux /aienos-recovery/vmlinuz root=LABEL=root ro single recovery systemd.unit=emergency.target console=tty0 console=ttyAMA0,115200n8
    initrd /aienos-recovery/initrd.img
}

menuentry "Reboot to Incumbent Linux" {
    exit
}
GRUB_EOF

sync
echo "AIENOS recovery media build complete on $TARGET_DEV."
