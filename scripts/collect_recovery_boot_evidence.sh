#!/bin/bash
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
# Gate 1 items 11-12 (recovery unlock) run only when the operator sets
# AIENOS_UNLOCK_CIPHER, AIENOS_UNLOCK_SPARE and AIENOS_UNLOCK_IDENTITY for
# that run; the store is then opened read-only and the passfile lives only
# in RAM (/tmp) and is deleted straight after the mount.
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
root_opts="$(findmnt -no OPTIONS "${ROOT_MNT}" 2>/dev/null || echo unknown)"
echo "nvme_root_mount_options: ${root_opts}"
check "nvme_root_mounted_readonly" \
    "$(case ",${root_opts}," in *,ro,*) echo 1 ;; *) echo 0 ;; esac)" \
    "mount options: ${root_opts}"

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

esp_opts="$(findmnt -no OPTIONS "${ESP_MNT}" 2>/dev/null || echo unknown)"
echo "esp_mount_options: ${esp_opts}"
check "esp_mounted_readonly" \
    "$(case ",${esp_opts}," in *,ro,*) echo 1 ;; *) echo 0 ;; esac)" \
    "mount options: ${esp_opts}"

echo "== boot entry restore capability"
efi_vars=0
[[ -d /sys/firmware/efi/efivars ]] && efi_vars=1
check "efi_variables_present" "${efi_vars}" "/sys/firmware/efi/efivars"
entries="$(efibootmgr 2>/dev/null || true)"
echo "${entries}" | sed -n '1,6p'
check "efibootmgr_readable" "$(grep -q '^Boot' <<<"${entries}" && echo 1 || echo 0)" \
    "efibootmgr lists boot entries"

echo "== TRUST-1 Gate 1 item 6: disks and encrypted stores (read-only)"
lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL 2>/dev/null || echo "lsblk unavailable"
# The Spark's encrypted stores are gocryptfs folders on the NVMe root.
CIPHER_DIRS="${AIENOS_CIPHER_DIRS:-/home/atlas/atlas-runtime-setup-20260905/private-cipher /home/drakestapleton/workspace/atlas-forgejo/cipher}"
stores_seen=0
for c in ${CIPHER_DIRS}; do
    conf="${ROOT_MNT}${c}/gocryptfs.conf"
    if [[ -f "${conf}" ]]; then
        echo "gocryptfs_store: ${c} conf_sha256=$(sha256sum "${conf}" | cut -d' ' -f1)"
        stores_seen=$((stores_seen + 1))
    else
        echo "gocryptfs_store: ${c} NOT FOUND under ${ROOT_MNT}"
    fi
done
check "encrypted_stores_identified" "$([[ ${stores_seen} -gt 0 ]] && echo 1 || echo 0)" \
    "${stores_seen} gocryptfs store(s) found on the NVMe root"

echo "== TRUST-1 Gate 1 item 8: PCRs and event log (read-only)"
export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
pcrs="$(tpm2_pcrread sha256 2>/dev/null || true)"
echo "${pcrs}" | sed -n '1,26p'
check "pcrs_read" "$(grep -qE '^ +7 *:' <<<"${pcrs}" && echo 1 || echo 0)" "tpm2_pcrread sha256"
evlog=/sys/kernel/security/tpm0/binary_bios_measurements
if [[ -r "${evlog}" ]]; then
    echo "event_log_sha256: $(sha256sum "${evlog}" | cut -d' ' -f1)"
    echo "event_log_bytes: $(wc -c <"${evlog}")"
fi
check "event_log_recorded" "$([[ -r "${evlog}" ]] && echo 1 || echo 0)" "${evlog}"

echo "== TRUST-1 Gate 1 items 9-10: AIENOS slots, loader hashes and signatures (read-only)"
if [[ "${esp_ok}" == 1 ]]; then
    ls -la "${ESP_MNT}/EFI" 2>/dev/null
    ls -laR "${ESP_MNT}"/EFI/AIENOS* 2>/dev/null || echo "aienos_slots: none on this ESP yet (expected before Gate 6)"
    loaders=0
    while IFS= read -r -d '' efi; do
        echo "efi_image: ${efi#"${ESP_MNT}"} sha256=$(sha256sum "${efi}" | cut -d' ' -f1)"
        sbverify --list "${efi}" 2>/dev/null | sed -n 's/^ *\(subject\|issuer\):/  \1:/p' | head -n 4
        loaders=$((loaders + 1))
    done < <(find "${ESP_MNT}" -type f -iname '*.efi' -print0 2>/dev/null)
    check "esp_loaders_hashed" "$([[ ${loaders} -gt 0 ]] && echo 1 || echo 0)" "${loaders} EFI image(s) hashed"
else
    check "esp_loaders_hashed" 0 "ESP not mounted"
fi

echo "== TRUST-1 Gate 1 items 11-12: recovery unlock (only when explicitly authorized)"
# Runs ONLY when the operator sets all three variables for this run. Opens
# ONE store read-only with the offline spare: the passfile is decrypted into
# RAM (/tmp), used once and deleted; nothing is written to the NVMe.
if [[ -n "${AIENOS_UNLOCK_CIPHER:-}" && -n "${AIENOS_UNLOCK_SPARE:-}" && -n "${AIENOS_UNLOCK_IDENTITY:-}" ]]; then
    plain="${AIENOS_UNLOCK_MNT:-/mnt/plain}"
    mkdir -p "${plain}"
    unlock_ok=0
    if age -d -i "${AIENOS_UNLOCK_IDENTITY}" -o /tmp/aienos-unlock-pass "${AIENOS_UNLOCK_SPARE}" \
        && gocryptfs -q -nosyslog -ro -passfile /tmp/aienos-unlock-pass "${AIENOS_UNLOCK_CIPHER}" "${plain}"; then
        unlock_ok=1
    fi
    rm -f /tmp/aienos-unlock-pass
    check "recovery_unlock_readonly" "${unlock_ok}" "store ${AIENOS_UNLOCK_CIPHER} opened read-only with the offline spare"
    if [[ "${unlock_ok}" == 1 && -n "${AIENOS_UNLOCK_EXPECT:-}" ]]; then
        # AIENOS_UNLOCK_EXPECT="relative/path sha256" of the harmless test file.
        exp_path="${AIENOS_UNLOCK_EXPECT% *}"
        exp_sha="${AIENOS_UNLOCK_EXPECT##* }"
        got_sha="$(sha256sum "${plain}/${exp_path}" 2>/dev/null | cut -d' ' -f1)"
        echo "test_artifact: ${exp_path} sha256=${got_sha:-unreadable}"
        check "test_artifact_round_trip" "$([[ "${got_sha}" == "${exp_sha}" ]] && echo 1 || echo 0)" \
            "expected ${exp_sha}"
    fi
    [[ "${unlock_ok}" == 1 ]] && { umount "${plain}" 2>/dev/null || fusermount3 -u "${plain}"; }
else
    echo "recovery_unlock: not authorized for this run (set AIENOS_UNLOCK_CIPHER, AIENOS_UNLOCK_SPARE, AIENOS_UNLOCK_IDENTITY)"
fi

echo "== verdict"
if [[ "${FAILED}" == 0 ]]; then
    echo "RECOVERY_BOOT_GATE: PASS"
else
    echo "RECOVERY_BOOT_GATE: FAIL"
    exit 1
fi
