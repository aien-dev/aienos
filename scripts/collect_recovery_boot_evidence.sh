#!/usr/bin/env bash
# collect_recovery_boot_evidence.sh: Record evidence that the AIENOS recovery
# USB actually booted Machine 1 into a rescue environment that can mount the
# NVMe root, repair /boot/efi, and restore boot entries (issue #17).
#
# Run this on Machine 1 (spark-b87b), booted from the recovery USB, under:
#   aien-proof hold --resource machine-1 --job recovery-boot-evidence -- \
#       bash scripts/collect_recovery_boot_evidence.sh /mnt/root
#
# Optional first argument: where the NVMe root is already mounted (default
# /mnt/root). This script is READ-ONLY: it never formats, never deletes,
# never writes to the ESP or the NVMe root, and never changes BootOrder. It
# only inspects mount state, filesystem presence, and firmware variables
# that are already exposed read-only by the kernel.
set -uo pipefail

ROOT_MNT="${1:-/mnt/root}"
ESP_MNT="${AIENOS_ESP_MNT:-${ROOT_MNT}/boot/efi}"
FAILED=0

check() { # name, pass(0/1), detail
    if [[ "$2" == 1 ]]; then
        echo "PASS  $1: $3"
    else
        echo "FAIL  $1: $3"
        FAILED=1
    fi
}

echo "== recovery environment identity"
echo "captured_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
echo "kernel: $(uname -r 2>/dev/null || echo unknown)"
echo "cmdline: $(cat /proc/cmdline 2>/dev/null || echo unknown)"
echo "hostname: $(cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)"

echo "== media identity (this boot's root)"
root_src="$(findmnt -no SOURCE / 2>/dev/null || echo unknown)"
echo "root_source: ${root_src}"
check "booted_from_removable_media" \
    "$(findmnt -no SOURCE / 2>/dev/null | grep -qE 'sd|usb|mapper|/dev/ram|rootfs|tmpfs' && echo 1 || echo 0)" \
    "root is ${root_src} (not the internal NVMe)"

echo "== secure boot state"
sb="unknown"
sb_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
if [[ -r "${sb_var}" ]]; then
    sb="$(od -An -t u1 -j 4 -N 1 "${sb_var}" 2>/dev/null | tr -d ' ')"
fi
echo "secure_boot_byte: ${sb}"
check "secure_boot_state_recorded" "$([[ "${sb}" == "0" || "${sb}" == "1" ]] && echo 1 || echo 0)" \
    "byte=${sb} (1=enabled)"

echo "== NVMe root mount"
check "nvme_root_mounted" "$(findmnt "${ROOT_MNT}" >/dev/null 2>&1 && echo 1 || echo 0)" \
    "findmnt ${ROOT_MNT}"
root_dev="$(findmnt -no SOURCE "${ROOT_MNT}" 2>/dev/null || echo unknown)"
echo "nvme_root_device: ${root_dev}"
check "nvme_root_is_internal" \
    "$(echo "${root_dev}" | grep -qE 'nvme|mapper' && echo 1 || echo 0)" \
    "source ${root_dev}"

echo "== /boot/efi access (read-only inspection; nothing is written here)"
esp_ok=0
if findmnt "${ESP_MNT}" >/dev/null 2>&1 || mountpoint -q "${ESP_MNT}" 2>/dev/null; then
    esp_ok=1
fi
check "esp_mounted" "${esp_ok}" "findmnt ${ESP_MNT}"

esp_fallback_present=0
if [[ "${esp_ok}" == 1 && -f "${ESP_MNT}/EFI/BOOT/BOOTAA64.EFI" ]]; then
    esp_fallback_present=1
fi
check "esp_fallback_bootloader_present" "${esp_fallback_present}" \
    "${ESP_MNT}/EFI/BOOT/BOOTAA64.EFI"

esp_writable=0
if [[ "${esp_ok}" == 1 ]]; then
    esp_opts="$(findmnt -no OPTIONS "${ESP_MNT}" 2>/dev/null || echo "")"
    [[ "${esp_opts}" == *"rw"* ]] && esp_writable=1
fi
check "esp_mounted_rw_capable" "${esp_writable}" \
    "mount options: $(findmnt -no OPTIONS "${ESP_MNT}" 2>/dev/null || echo unknown) (repair capability observed, not exercised)"

echo "== boot entry restore capability"
efi_vars=0
[[ -d /sys/firmware/efi/efivars ]] && efi_vars=1
check "efi_variables_present" "${efi_vars}" "/sys/firmware/efi/efivars"
entries="$(efibootmgr 2>/dev/null || true)"
echo "${entries}" | sed -n '1,6p'
check "efibootmgr_readable" "$(grep -q '^Boot' <<<"${entries}" && echo 1 || echo 0)" \
    "efibootmgr lists boot entries"

echo "== verdict"
if [[ "${FAILED}" == 0 ]]; then
    echo "RECOVERY_BOOT_GATE: PASS"
else
    echo "RECOVERY_BOOT_GATE: FAIL"
    exit 1
fi
