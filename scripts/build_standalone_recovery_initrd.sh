#!/usr/bin/env bash
# build_standalone_recovery_initrd.sh: Creates a 100% self-contained recovery initrd
# Does NOT mount or require internal NVMe root. Contains busybox/shell, cryptsetup,
# gocryptfs, age, tpm2 tools, and diagnostic recovery utilities.
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

# Ensure base binaries are present
BINARIES=(
    /bin/busybox
    /bin/sh
    /bin/bash
    /bin/lsblk
    /sbin/blkid
    /bin/mount
    /bin/umount
    /bin/mkdir
    /bin/cat
    /bin/grep
    /bin/sed
    /bin/sha256sum
    /usr/bin/age
    /usr/bin/tpm2_pcrread
    /usr/bin/efibootmgr
    /usr/bin/findmnt
    /sbin/cryptsetup
    # Repair tools for issue #17: repair /boot/efi (fsck.vfat, mkfs.vfat),
    # check the NVMe root filesystem (fsck.ext4), and chroot into it to
    # restore boot entries from the installed bootloader.
    /usr/sbin/fsck.vfat
    /usr/sbin/mkfs.vfat
    /usr/sbin/fsck.ext4
    /usr/sbin/chroot
)

for bin in "${BINARIES[@]}"; do
    if [[ -f "$bin" ]]; then
        cp -p "$bin" "$WORK_DIR/bin/"
        # Copy dynamically linked libraries if binary is dynamic
        if ldd "$bin" >/dev/null 2>&1; then
            ldd "$bin" 2>/dev/null | grep -o '/lib[^ ]*' | while read -r lib; do
                if [[ -f "$lib" ]]; then
                    mkdir -p "$WORK_DIR/$(dirname "$lib")"
                    cp -p -u "$lib" "$WORK_DIR/$lib" 2>/dev/null || true
                fi
            done
        fi
    else
        echo "Error: required recovery binary $bin not found on the build host" >&2
        exit 1
    fi
done

# The attended collector must travel on the recovery media itself; it cannot
# depend on a repository checkout being present in the RAM rescue shell.
mkdir -p "$WORK_DIR/usr/local/sbin"
install -m 0755 "$(dirname "$0")/collect_recovery_boot_evidence.sh" \
    "$WORK_DIR/usr/local/sbin/collect_recovery_boot_evidence"

# Copy gocryptfs if available
GOCRYPTFS_BIN=$(which gocryptfs 2>/dev/null || echo "/home/atlas/atlas-forgejo-setup-20260904/runtime/usr/bin/gocryptfs")
if [[ -f "$GOCRYPTFS_BIN" ]]; then
    cp -p "$GOCRYPTFS_BIN" "$WORK_DIR/bin/gocryptfs"
    if ldd "$GOCRYPTFS_BIN" >/dev/null 2>&1; then
        ldd "$GOCRYPTFS_BIN" 2>/dev/null | grep -o '/lib[^ ]*' | while read -r lib; do
            if [[ -f "$lib" ]]; then
                mkdir -p "$WORK_DIR/$(dirname "$lib")"
                cp -p -u "$lib" "$WORK_DIR/$lib" 2>/dev/null || true
            fi
        done
    fi
fi

# Kernel drivers the recovery shell needs on Machine 1 that the Ubuntu kernel
# builds as modules: the ACPI xHCI controllers (NVDA8000), USB and Logitech
# keyboards, USB sticks, the internal NVMe, dm-crypt and FAT text encodings.
# Modules must match the kernel the callers copy: the newest /boot/vmlinuz-*.
KVER="${AIENOS_RECOVERY_KVER:-$(basename "$(ls -1t /boot/vmlinuz-* | head -n 1)" | sed 's/^vmlinuz-//')}"
RECOVERY_MODULES=(
    xhci-plat-hcd
    usbhid hid-generic hid-logitech-dj hid-logitech-hidpp
    usb-storage uas
    nvme
    dm-crypt
    nls_iso8859-1 nls_utf8
)

mkdir -p "$WORK_DIR/lib/modules/aienos" "$WORK_DIR/etc"
: > "$WORK_DIR/etc/aienos-modules.order"
for mod in "${RECOVERY_MODULES[@]}"; do
    deps=$(modprobe -S "$KVER" --show-depends "$mod") || {
        echo "Error: module $mod not found for kernel $KVER" >&2
        exit 1
    }
    # Dependencies come first; builtin lines need nothing copied.
    while read -r kind path _; do
        [[ "$kind" == "insmod" ]] || continue
        name=$(basename "$path")
        name="${name%.zst}"
        name="${name%.xz}"
        grep -qxF "$name" "$WORK_DIR/etc/aienos-modules.order" && continue
        # Decompress so busybox insmod can load it; the signature appended
        # before compression is kept, so Secure Boot lockdown still accepts it.
        case "$path" in
            *.zst) zstd -q -d -c "$path" > "$WORK_DIR/lib/modules/aienos/$name" ;;
            *.xz) xz -d -c "$path" > "$WORK_DIR/lib/modules/aienos/$name" ;;
            *) cp -p "$path" "$WORK_DIR/lib/modules/aienos/$name" ;;
        esac
        echo "$name" >> "$WORK_DIR/etc/aienos-modules.order"
    done <<< "$deps"
done
echo "Packaged $(wc -l < "$WORK_DIR/etc/aienos-modules.order") kernel modules for $KVER"

# Create standalone init script
cat << 'INIT_EOF' > "$WORK_DIR/init"
#!/bin/busybox sh
# Standalone AIENOS Recovery Environment
# Runs completely in RAM, independently of internal NVMe storage

/bin/busybox --install -s /bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null
# Read-only: recovery must opt in explicitly before changing firmware variables.
mount -t efivarfs -o ro efivarfs /sys/firmware/efi/efivars 2>/dev/null

secure_boot="unknown (no EFI variables)"
sb_var=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
if [ -r "$sb_var" ]; then
    # 4 attribute bytes, then 1 data byte. busybox od ignores -j with -N,
    # so read the last byte with tail.
    case "$(tail -c1 "$sb_var" | od -An -tu1 | tr -d ' ')" in
        1) secure_boot="enabled" ;;
        0) secure_boot="disabled" ;;
        *) secure_boot="unreadable" ;;
    esac
fi
lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unavailable")

loaded=0
failed=""
while read -r mod; do
    if insmod "/lib/modules/aienos/$mod" 2>/dev/null; then
        loaded=$((loaded + 1))
    else
        failed="$failed $mod"
    fi
done < /etc/aienos-modules.order
total=$(wc -l < /etc/aienos-modules.order)
# Give USB and NVMe time to enumerate before listing disks.
sleep 3

{
    echo "============================================================"
    echo "AIENOS Standalone Hardware Recovery Core"
    echo "Root filesystem: 100% RAM disk (Self-contained)"
    echo "Internal NVMe status: UNMOUNTED"
    echo "============================================================"
    echo ""
    echo "Secure Boot: $secure_boot"
    echo "Kernel lockdown: $lockdown"
    echo "Kernel modules loaded: $loaded/$total"
    [ -n "$failed" ] && echo "Kernel modules failed:$failed"
    echo "Input devices: $(ls /sys/class/input 2>/dev/null | grep -c '^input')"
    cat /sys/class/input/input*/name 2>/dev/null | sed 's/^/  /'
    echo "Kernel: $(uname -r)  Clock (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    for pcr in 0 7; do
        echo "TPM PCR $pcr (sha256): $(cat /sys/class/tpm/tpm0/pcr-sha256/$pcr 2>/dev/null || echo unavailable)"
    done
    echo ""
    echo "Block device topology:"
    lsblk 2>/dev/null || true
    for part in /dev/sd*[0-9] /dev/nvme*n*p*; do
        [ -b "$part" ] && echo "  $part: $(blkid -p -o export -s LABEL -s TYPE -s UUID "$part" 2>/dev/null | tr "\n" " ")"
    done
    echo ""
    echo "Firmware boot entries:"
    efibootmgr 2>/dev/null | sed 's/^/  /' || echo "  unavailable"
    echo ""
} > /tmp/recovery-report 2>&1

# One-shot unattended self-test: Linux leaves aienos-selftest-once on the
# stick. Only then is the stick mounted read-write, the flag removed and the
# report saved; an ordinary recovery boot never writes anywhere.
selftest=0
# Probe partitions directly: without udev, blkid -L and lsblk see no labels.
stick=""
for part in /dev/sd*[0-9] /dev/nvme*n*p*; do
    [ -b "$part" ] || continue
    if [ "$(blkid -p -o value -s LABEL "$part" 2>/dev/null)" = AIENOSRECOV ]; then
        stick="$part"
        break
    fi
done
if [ -n "$stick" ]; then
    mkdir -p /mnt/stick
    if mount -t vfat -o ro "$stick" /mnt/stick 2>/dev/null; then
        if [ -f /mnt/stick/aienos-selftest-once ] && mount -o remount,rw /mnt/stick 2>/dev/null; then
            selftest=1
            rm -f /mnt/stick/aienos-selftest-once
            mkdir -p /mnt/stick/aienos-evidence
            cp /tmp/recovery-report "/mnt/stick/aienos-evidence/selftest-$(date -u +%Y%m%dT%H%M%SZ).txt"
            sync
        fi
        umount /mnt/stick
    fi
fi

clear
cat /tmp/recovery-report
# The shell lives on /dev/console (the screen on Machine 1). Mirror the report
# to the serial port too, so emulator tests can read it; bounded so a serial
# port with no carrier can never delay the shell.
if [ -c /dev/ttyAMA0 ]; then
    timeout 2 sh -c 'cat /tmp/recovery-report > /dev/ttyAMA0' 2>/dev/null &
fi

if grep -q "aienos.test=1" /proc/cmdline 2>/dev/null; then
    echo "TEST MODE DETECTED: automated recovery verification complete."
    poweroff -f 2>/dev/null || reboot -f 2>/dev/null || exit 0
fi

if [ "$selftest" = 1 ]; then
    echo "SELF-TEST: report saved to the recovery stick (aienos-evidence/)."
    echo "Press Enter within 60 s to stay in the recovery shell; otherwise the machine restarts."
    if ! read -t 60 _; then
        echo "SELF-TEST: restarting."
        sync
        reboot -f
    fi
fi

echo "Dropping into standalone maintenance shell."
echo "Type 'reboot' or 'poweroff' when recovery verification completes."
echo ""

exec /bin/sh
INIT_EOF

chmod +x "$WORK_DIR/init"

echo "Packaging standalone initrd to $OUT_INITRD..."
(cd "$WORK_DIR" && find . | cpio -H newc -o | gzip -9) > "$OUT_INITRD"
echo "Standalone recovery initrd build complete: $(du -h "$OUT_INITRD")"
