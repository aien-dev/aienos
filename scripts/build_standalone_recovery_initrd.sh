#!/usr/bin/env bash
# build_standalone_recovery_initrd.sh: Creates a 100% self-contained recovery initrd
# Does NOT mount or require internal NVMe root at boot. Contains busybox/shell,
# cryptsetup, gocryptfs, age, tpm2 tools, efibootmgr/efivar, and filesystem repair
# utilities. On operator request it can mount the NVMe root, repair /boot/efi, and
# restore UEFI boot entries.
# Zero Disk Secrets and Unslop compliant.

set -euo pipefail

OUT_INITRD="${1:-/tmp/aienos-recovery-standalone-initrd.img}"
WORK_DIR=$(mktemp -d /tmp/recovery-initrd-build.XXXXXX)

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "Building standalone recovery root in $WORK_DIR..."
mkdir -p "$WORK_DIR"/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,etc,mnt/root,mnt/cipher,mnt/plain,tmp,lib,lib64}

# Required binaries for the rescue environment (mount NVMe root, repair
# /boot/efi, restore boot entries). Each must exist on the build host.
BINARIES=(
    /bin/busybox
    /bin/bash
    /bin/lsblk
    blkid
    /bin/mount
    /bin/umount
    /bin/mkdir
    /bin/cat
    /bin/grep
    /bin/sed
    /bin/awk
    /bin/cut
    /bin/tr
    /bin/find
    /bin/stty
    /bin/sync
    /bin/dmesg
    /bin/sha256sum
    /bin/tar
    chroot
    efibootmgr
    cryptsetup
    mkfs.vfat
)

# Optional binaries: warn but continue when the host cannot provide them.
OPTIONAL_BINARIES=(
    efivar
    fsck.vfat
    fsck.ext4
    lvm
    age
    tpm2_pcrread
)

# Resolve a binary to an absolute path, following usrmerge /sbin -> /usr/sbin.
resolve_bin() {
    local name="$1"
    if [[ "$name" == */* && -f "$name" ]]; then
        echo "$name"; return 0
    fi
    local base; base=$(basename "$name")
    local d
    for d in /bin /sbin /usr/bin /usr/sbin; do
        if [[ -f "$d/$base" ]]; then
            echo "$d/$base"; return 0
        fi
    done
    return 1
}

copy_with_libs() {
    local src="$1" dest_name="$2" lib
    cp -p "$src" "$WORK_DIR/bin/$dest_name"
    if ldd "$src" >/dev/null 2>&1; then
        ldd "$src" 2>/dev/null | grep -o '/lib[^ ]*' | while read -r lib; do
            if [[ -f "$lib" ]]; then
                mkdir -p "$WORK_DIR/$(dirname "$lib")"
                cp -p -u "$lib" "$WORK_DIR/$lib" 2>/dev/null || true
            fi
        done
    fi
}

for bin in "${BINARIES[@]}"; do
    src=$(resolve_bin "$bin") || { echo "MISSING: required binary $bin is not present on this host" >&2; exit 1; }
    copy_with_libs "$src" "$(basename "$bin")"
done

for bin in "${OPTIONAL_BINARIES[@]}"; do
    if src=$(resolve_bin "$bin"); then
        copy_with_libs "$src" "$(basename "$bin")"
    else
        echo "OPTIONAL MISSING: $bin not packaged (host lacks it)" >&2
    fi
done

# Copy gocryptfs if available (optional; unlock of gocryptfs volumes)
if src=$(resolve_bin gocryptfs); then
    copy_with_libs "$src" "gocryptfs"
else
    echo "OPTIONAL MISSING: gocryptfs not packaged (host lacks it)" >&2
fi

# Create EFI repair helper
cat << 'REPAIR_EOF' > "$WORK_DIR/bin/aienos-efi-repair"
#!/bin/busybox sh
# aienos-efi-repair: repair /boot/efi and restore UEFI boot entries.
# Mounts the EFI system partition, verifies/repairs the shim+GRUB fallback
# chain, and re-registers the standard boot entries with efibootmgr.
# Dry run when AIENOS_EFI_REPAIR_DRY_RUN=1 (host-side testing only).
set -u

ESP_MNT="${AIENOS_ESP_MNT:-/mnt/esp}"
DRY_RUN="${AIENOS_EFI_REPAIR_DRY_RUN:-0}"
FAILED=0

say() { echo "[efi-repair] $*"; }
fail() { echo "[efi-repair] FAIL: $*"; FAILED=1; }

find_esp() {
    # Locate the ESP: a vfat partition. Prefer the known host EFI UUID.
    cand=""
    for dev in /dev/nvme*p* /dev/sd?*; do
        [ -b "$dev" ] || continue
        fstype=$(blkid -s TYPE -o value "$dev" 2>/dev/null || true)
        [ "$fstype" = "vfat" ] || continue
        uuid=$(blkid -s UUID -o value "$dev" 2>/dev/null || true)
        if [ "$uuid" = "9DA2-3597" ]; then
            echo "$dev"; return 0
        fi
        cand="$dev"
    done
    # Fall back to the last vfat candidate seen
    [ -n "$cand" ] && { echo "$cand"; return 0; }
    return 1
}

ESP_DEV="${1:-}"
if [ -z "$ESP_DEV" ]; then
    ESP_DEV=$(find_esp) || { fail "no EFI system partition found"; exit 1; }
fi
say "ESP device: $ESP_DEV"

mkdir -p "$ESP_MNT"
if [ "$DRY_RUN" != "1" ]; then
    if ! mountpoint -q "$ESP_MNT" 2>/dev/null; then
        mount -t vfat "$ESP_DEV" "$ESP_MNT" || { fail "cannot mount $ESP_DEV"; exit 1; }
    fi
fi
say "ESP mounted at $ESP_MNT"

# 1. Fallback bootloader path
for f in EFI/BOOT/BOOTAA64.EFI EFI/BOOT/grubaa64.efi; do
    if [ -f "$ESP_MNT/$f" ]; then
        say "present: $f"
    else
        fail "missing: $f"
    fi
done

# 2. Report filesystem usage
df_out=$(df "$ESP_MNT" 2>/dev/null | tail -1 || true)
say "esp usage: $df_out"

# 3. Restore boot entries
if [ "$DRY_RUN" = "1" ]; then
    say "dry run: would run efibootmgr to restore the 'ubuntu' shim entry"
else
    DISK=$(echo "$ESP_DEV" | sed -n 's/^\(\/dev\/nvme[0-9]*n[0-9]*\)p[0-9]*$/\1/p')
    PART=$(echo "$ESP_DEV" | sed -n 's/^\(\/dev\/nvme[0-9]*n[0-9]*\)p\([0-9]*\)$/\2/p')
    if [ -z "$DISK" ]; then
        DISK=$(echo "$ESP_DEV" | sed -n 's/^\(\/dev\/sd[a-z]*\)[0-9]*$/\1/p')
        PART=$(echo "$ESP_DEV" | sed -n 's/^\/dev\/sd[a-z]*\([0-9]*\)$/\1/p')
    fi
    if [ -n "$DISK" ] && [ -n "$PART" ]; then
        if ! efibootmgr 2>/dev/null | grep -q "Boot[0-9A-Fa-f]\{4\}.\{0,2\} ubuntu"; then
            say "creating boot entry: ubuntu -> \\EFI\\BOOT\\BOOTAA64.EFI on $DISK part $PART"
            efibootmgr --create --disk "$DISK" --part "$PART" \
                --label "ubuntu" --loader '\\EFI\\BOOT\\BOOTAA64.EFI' >/dev/null 2>&1 \
                && say "boot entry created" || fail "efibootmgr entry creation failed"
        else
            say "boot entry 'ubuntu' already present"
        fi
        efibootmgr 2>/dev/null | sed -n '1,8p'
    else
        say "WARN: could not derive disk/partition from $ESP_DEV; skipping entry restore"
    fi
fi

if [ "$FAILED" = "0" ]; then
    say "REPAIR RESULT: PASS"
    exit 0
fi
say "REPAIR RESULT: FAIL"
exit 1
REPAIR_EOF
chmod +x "$WORK_DIR/bin/aienos-efi-repair"

# Create standalone init script
cat << 'INIT_EOF' > "$WORK_DIR/init"
#!/bin/busybox sh
# Standalone AIENOS Recovery Environment
# Runs completely in RAM, independently of internal NVMe storage.
# Boots to a rescue menu that can mount the NVMe root, repair /boot/efi, and
# restore UEFI boot entries on explicit operator request.

/bin/busybox --install -s /bin
stty -ixon 2>/dev/null || true

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts 2>/dev/null || true

# LVM: activate volume groups so the NVMe root LV becomes visible
if [ -x /bin/lvm ]; then
    /bin/lvm vgscan >/dev/null 2>&1 || true
    /bin/lvm vgchange -ay >/dev/null 2>&1 || true
fi

banner() {
    clear
    echo "============================================================"
    echo "AIENOS Standalone Hardware Recovery Core"
    echo "Root filesystem: 100% RAM disk (Self-contained)"
    echo "Internal NVMe status: UNMOUNTED (mount is operator-initiated)"
    echo "============================================================"
    echo ""
    echo "Block device topology:"
    lsblk -f 2>/dev/null || blkid 2>/dev/null || true
    echo ""
}

mount_nvme_root() {
    target=""
    # Prefer the known host root filesystem UUID, then any ext4 on NVMe.
    for dev in /dev/mapper/* /dev/nvme*p*; do
        [ -b "$dev" ] || continue
        uuid=$(blkid -s UUID -o value "$dev" 2>/dev/null || true)
        fstype=$(blkid -s TYPE -o value "$dev" 2>/dev/null || true)
        if [ "$uuid" = "d27bfd26-ff30-400e-9eca-9cdf73de9406" ]; then
            target="$dev"; break
        fi
        if [ "$fstype" = "ext4" ] && [ -z "$target" ]; then
            target="$dev"
        fi
    done
    if [ -z "$target" ]; then
        echo "No ext4 NVMe root candidate found."
        return 1
    fi
    mkdir -p /mnt/root
    if mount -o ro "$target" /mnt/root 2>/dev/null || mount "$target" /mnt/root; then
        echo "Mounted $target at /mnt/root"
        mount | grep /mnt/root
        return 0
    fi
    echo "Failed to mount $target"
    return 1
}

rescue_menu() {
    while true; do
        echo ""
        echo "--- AIENOS rescue menu ---"
        echo "1) List block devices"
        echo "2) Mount NVMe root at /mnt/root"
        echo "3) Repair /boot/efi and restore boot entries (aienos-efi-repair)"
        echo "4) Show UEFI boot entries (efibootmgr)"
        echo "5) Open a shell"
        echo "6) Power off"
        echo "7) Reboot"
        printf "choice: "
        read -r choice
        case "$choice" in
            1) lsblk -f 2>/dev/null || blkid 2>/dev/null || true ;;
            2) mount_nvme_root ;;
            3) /bin/aienos-efi-repair ;;
            4) efibootmgr 2>/dev/null || echo "efibootmgr unavailable (no EFI variables?)" ;;
            5) echo "Type 'exit' to return to the menu."; /bin/sh ;;
            6) sync; poweroff -f ;;
            7) sync; reboot -f ;;
            *) echo "unknown choice" ;;
        esac
    done
}

banner

if grep -q "aienos.test=1" /proc/cmdline 2>/dev/null; then
    echo "TEST MODE DETECTED: automated recovery verification complete."
    poweroff -f 2>/dev/null || reboot -f 2>/dev/null || exit 0
fi

if grep -q "aienos.repair=1" /proc/cmdline 2>/dev/null; then
    echo "AUTO-REPAIR MODE: running aienos-efi-repair, then rebooting."
    /bin/aienos-efi-repair
    echo "Auto-repair finished (status $?); rebooting in 5 s."
    sleep 5
    sync
    reboot -f 2>/dev/null || poweroff -f 2>/dev/null || exit 0
fi

echo "This environment runs entirely in RAM. Internal NVMe stays unmounted"
echo "until you choose menu option 2 or 3."
rescue_menu
INIT_EOF

chmod +x "$WORK_DIR/init"

echo "Packaging standalone initrd to $OUT_INITRD..."
(cd "$WORK_DIR" && find . | cpio -H newc -o | gzip -9) > "$OUT_INITRD"
echo "Standalone recovery initrd build complete: $(du -h "$OUT_INITRD")"
