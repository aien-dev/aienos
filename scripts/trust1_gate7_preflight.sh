#!/usr/bin/env bash
# trust1_gate7_preflight.sh: TRUST-1 Gate 7 pre-flight check (read-only).
#
# Checks, before the attended Gate 7 steps, everything that can be checked
# without the operator's reboot measurements: the tools the stick and the
# snapshot/compare steps need, the offline spare and the encrypted storage
# folder, the TPM, Secure Boot, and (if the stick is plugged in and open, or
# an image path is given) the tools inside the recovery image.
#
# Safety rules (after the 2026-09-30 /dev deletion incident):
#   - changes nothing on the machine: no sudo, no mount, no chroot, no efivar
#     or boot-entry writes, no TPM writes;
#   - never creates, removes or binds anything under /dev (it only looks at
#     /dev entries with `test`, and reads PCRs through the TPM like
#     tpm_measurement_campaign.sh does);
#   - writes only inside one private temp folder, which it removes with
#     `rm --one-file-system` and only if nothing is mounted under it.
#
# Usage: bash scripts/trust1_gate7_preflight.sh [INITRD_IMAGE]
#   INITRD_IMAGE  optional: a recovery initrd to inspect. Without it, the
#                 image on a mounted AIENOSRECOV stick is used; if the stick
#                 is not open, a private copy is built in a temp folder.
# Exit: 0 = no FAIL, 1 = at least one FAIL.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPARE_DIR="${AIENOS_SPARE_DIR:-${HOME}/.config/atlas/offline-spares}"
SPARE="${SPARE_DIR}/atlas-private-storage.passfile.age"
CIPHER_DIR="${AIENOS_CIPHER_DIR:-/home/atlas/atlas-runtime-setup-20260905/private-cipher}"
EVENTLOG="${AIENOS_EVENTLOG:-/sys/kernel/security/tpm0/binary_bios_measurements}"
EFIVARS="${AIENOS_EFIVARS_DIR:-/sys/firmware/efi/efivars}"
SB_VAR="${EFIVARS}/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

TMP="$(mktemp -d /tmp/trust1-gate7-preflight.XXXXXX)" || { echo "FAIL  could not create a temp folder"; exit 1; }
cleanup() {
    # Refuse to delete if anything is mounted inside the temp folder.
    if findmnt -rn -o TARGET 2>/dev/null | grep -q "^${TMP}\(/\|$\)"; then
        echo "WARNING: something is mounted under ${TMP}; leaving it in place" >&2
        return
    fi
    rm -rf --one-file-system -- "${TMP}"
}
trap cleanup EXIT

PASSES=0; FAILS=0; SKIPS=0
pass() { echo "PASS  $1"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL  $1"; FAILS=$((FAILS + 1)); }
skip() { echo "SKIP  $1"; SKIPS=$((SKIPS + 1)); }
check() { if [[ "$2" == 1 ]]; then pass "$1"; else fail "$1"; fi; }
yes_if() { if "$@" >/dev/null 2>&1; then echo 1; else echo 0; fi; }

echo "TRUST-1 Gate 7 pre-flight (read-only; changes nothing)"
echo ""

echo "-- 1. The Spark's device list looks healthy (after the 2026-09-30 incident) --"
check "/dev/null is a real device (not a plain file)" "$(yes_if test -c /dev/null)"
check "the TPM device /dev/tpmrm0 exists" "$(yes_if test -c /dev/tpmrm0)"

echo ""
echo "-- 2. The TPM can be read --"
check "you are in the tss group (allowed to read the TPM)" \
    "$(id -nG | tr ' ' '\n' | grep -qx tss && echo 1 || echo 0)"
check "the TPM device is readable by you" "$(yes_if test -r /dev/tpmrm0)"
if command -v tpm2_pcrread >/dev/null 2>&1; then
    check "the TPM answers a read of startup measurement 7 (Secure Boot state)" \
        "$(yes_if tpm2_pcrread sha256:7)"
else
    fail "tpm2_pcrread is installed (needed to read the TPM)"
fi
check "the firmware's startup measurement log is readable" "$(yes_if test -r "${EVENTLOG}")"

echo ""
echo "-- 3. Secure Boot state can be read --"
if command -v mokutil >/dev/null 2>&1; then
    sb="$(mokutil --sb-state 2>/dev/null || true)"
    check "Secure Boot reports ON (mokutil says: ${sb:-nothing})" \
        "$([[ "${sb}" == *"SecureBoot enabled"* ]] && echo 1 || echo 0)"
else
    fail "mokutil is installed (reads the Secure Boot state)"
fi
if [[ -r "${SB_VAR}" ]]; then
    # efivarfs: 4 attribute bytes, then the 1-byte value.
    sb_byte="$(od -An -tu1 -j4 -N1 "${SB_VAR}" 2>/dev/null | tr -d ' ')"
    check "the firmware's own Secure Boot setting reads 1 (ON), got '${sb_byte}'" \
        "$([[ "${sb_byte}" == 1 ]] && echo 1 || echo 0)"
else
    fail "the firmware's Secure Boot setting is readable"
fi

echo ""
echo "-- 4. Tools the stick build copies from Ubuntu are all present --"
mapfile -t stick_bins < <(sed -n '/^BINARIES=(/,/^)/p' "${REPO_ROOT}/scripts/build_standalone_recovery_initrd.sh" \
    | sed -n 's/^[[:space:]]*\(\/[^[:space:]]*\).*/\1/p')
if [[ ${#stick_bins[@]} -eq 0 ]]; then
    fail "read the list of stick tools from build_standalone_recovery_initrd.sh"
else
    missing=()
    for b in "${stick_bins[@]}"; do [[ -e "${b}" ]] || missing+=("${b}"); done
    check "all ${#stick_bins[@]} programs the stick build copies exist on Ubuntu${missing[*]:+ (missing: ${missing[*]})}" \
        "$([[ ${#missing[@]} -eq 0 ]] && echo 1 || echo 0)"
fi
gocryptfs_bin="${AIENOS_GOCRYPTFS:-$(command -v gocryptfs 2>/dev/null || echo /home/atlas/atlas-forgejo-setup-20260904/runtime/usr/bin/gocryptfs)}"
check "gocryptfs (opens the private storage) is where the stick build looks: ${gocryptfs_bin}" \
    "$(yes_if test -f "${gocryptfs_bin}")"

echo ""
echo "-- 5. Snapshot, compare and stick scripts are present --"
for s in tpm_measurement_campaign.sh build_recovery_media.sh build_standalone_recovery_initrd.sh \
         verify_recovery_tools.sh collect_recovery_boot_evidence.sh; do
    check "scripts/${s} is present" "$(yes_if test -f "${REPO_ROOT}/scripts/${s}")"
done
for t in tpm2_pcrread tpm2_eventlog mokutil efibootmgr sha256sum aien-proof; do
    check "${t} is installed on Ubuntu" "$(yes_if command -v "${t}")"
done

echo ""
echo "-- 6. Key ciphertext is where the docs say, and no secret key sits beside it --"
if [[ -s "${SPARE}" ]]; then
    hdr="$(head -n 1 "${SPARE}" 2>/dev/null)"
    check "the offline spare is present and locked (age format): ${SPARE}" \
        "$([[ "${hdr}" == "age-encryption.org/v1" ]] && echo 1 || echo 0)"
else
    fail "the offline spare is present and not empty: ${SPARE}"
fi
if [[ -d "${SPARE_DIR}" ]]; then
    if grep -rlq 'AGE-SECRET-KEY-' "${SPARE_DIR}" 2>/dev/null; then
        fail "no unlocking identity (secret key) is stored next to the spares on the Spark"
    else
        pass "no unlocking identity (secret key) is stored next to the spares on the Spark"
    fi
fi
if [[ -d "${CIPHER_DIR}" ]]; then
    if [[ -r "${CIPHER_DIR}/gocryptfs.conf" ]]; then
        pass "the encrypted private storage folder and its gocryptfs.conf are present: ${CIPHER_DIR}"
    elif [[ -e "${CIPHER_DIR}/gocryptfs.conf" ]]; then
        skip "the encrypted storage's gocryptfs.conf exists but you may not read it (not a fault)"
    else
        fail "the encrypted private storage has its gocryptfs.conf: ${CIPHER_DIR}"
    fi
elif [[ -e "${CIPHER_DIR}" ]]; then
    skip "the encrypted private storage folder exists but you may not look inside (not a fault)"
else
    fail "the encrypted private storage folder exists: ${CIPHER_DIR}"
fi

echo ""
echo "-- 7. Tools inside the recovery image --"
image=""; image_note=""
if [[ $# -ge 1 ]]; then
    image="$1"; image_note="the image you named"
else
    stick_mnt="$(findmnt -rn -o TARGET -S LABEL=AIENOSRECOV 2>/dev/null | head -n 1)"
    if [[ -n "${stick_mnt}" ]]; then
        image="${stick_mnt}/aienos-recovery/initrd.img"; image_note="the image on the plugged-in stick"
    fi
fi
log="${TMP}/verify_recovery_tools.log"
if [[ -n "${image}" ]]; then
    if [[ -f "${image}" ]]; then
        TMPDIR="${TMP}" bash "${REPO_ROOT}/scripts/verify_recovery_tools.sh" "${image}" >"${log}" 2>&1
        rc=$?
    else
        echo "image not found: ${image}" >"${log}"; rc=1
    fi
else
    image_note="a fresh private copy built now (stick not open; this is what Step 4 would write)"
    TMPDIR="${TMP}" bash "${REPO_ROOT}/scripts/verify_recovery_tools.sh" >"${log}" 2>&1
    rc=$?
fi
grep -E '^(FAIL|SKIP)|^image not found' "${log}" | sed 's/^/      /'
check "every recovery tool is inside ${image_note}" "$([[ ${rc} -eq 0 ]] && echo 1 || echo 0)"

echo ""
echo "-- Not checked here (need Drake's reboots or later gates) --"
echo "NOT CHECKED  startup measurements match across normal boots (Gate 2 reboot snapshots)"
echo "NOT CHECKED  owner key fingerprints and backups (Gate 3 key ceremony not run yet)"
echo "NOT CHECKED  owner-signed loader and its fingerprint (Gate 4)"
echo "NOT CHECKED  Secure Boot variables archived, Gates 0-6 PASS, operator approval"
echo "NOT CHECKED  the stick actually boots and unlocks with Secure Boot ON (Gate 1, Step 6)"
echo "NOT CHECKED  every Gate 7 checkpoint A-E (attended hardware boot)"

echo ""
echo "Summary: ${PASSES} passed, ${FAILS} failed, ${SKIPS} skipped"
if [[ ${FAILS} -ne 0 ]]; then
    echo "GATE7_PREFLIGHT: FAIL"
    exit 1
fi
echo "GATE7_PREFLIGHT: PASS (only covers what can be checked before the reboots)"
