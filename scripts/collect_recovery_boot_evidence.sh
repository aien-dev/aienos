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
# /mnt/root). The script performs read-only verification plus a harmless
# marker-file round-trip on the ESP to prove repair access. It never formats,
# never deletes, and never changes BootOrder.
set -uo pipefail

ROOT_MNT="${1:-/mnt/root}"
ESP_MNT="${AIENOS_ESP_MNT:-${ROOT_MNT}/boot/efi}"
MARKER_REL="EFI/AIENOS/RECOVERY-MARKER.TXT"
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
for var in /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c; do
    if [[ -r "${var}" ]]; then
        sb="$(od -An -t u1 -j 4 -N 1 "${var}" 2>/dev/null | tr -d ' ')"
    fi
done
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

echo "== /boot/efi access and repair proof"
esp_ok=0
if findmnt "${ESP_MNT}" >/dev/null 2>&1 || mountpoint -q "${ESP_MNT}" 2>/dev/null; then
    esp_ok=1
fi
check "esp_mounted" "${esp_ok}" "findmnt ${ESP_MNT}"

marker_path="${ESP_MNT}/${MARKER_REL}"
marker_ok=0
if [[ "${esp_ok}" == 1 ]]; then
    mkdir -p "$(dirname "${marker_path}")" 2>/dev/null || true
    if echo "aienos recovery boot $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" >"${marker_path}" 2>/dev/null \
        && grep -q "aienos recovery boot" "${marker_path}" 2>/dev/null; then
        marker_ok=1
        rm -f "${marker_path}" 2>/dev/null || true
    fi
fi
check "esp_write_roundtrip" "${marker_ok}" "created+verified+removed ${MARKER_REL}"

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
