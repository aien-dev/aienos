#!/usr/bin/env bash
# ck_owner_keys_check.sh -- build-side proof that the C kernel hardware
# staging image never embeds the TEST Store keys, the TEST store uuid or the
# TEST machine id (native/kernel/README.md, "Owner provisioning").
#
#   bash scripts/ck_owner_keys_check.sh
#
# Checks, each PASS or FAIL:
#   1. make full CK_HARDWARE_STAGING=1 with no owner files is refused with the
#      expected message (also with only one of the two files); owner files
#      without CK_HARDWARE_STAGING are refused.
#   2. tools/ck_owner_gen.c refuses every known TEST value and every malformed
#      input (wrong length, not hex, duplicate, unknown name, missing name,
#      all-equal bytes) and writes no header.
#   3. With the labelled TEST-fixture owner files
#      (native/kernel/tests/fixtures/owner/, public bytes only, distinct from
#      every old TEST constant) the hardware staging image builds; its ELF and
#      EFI carry no TEST Store label, TEST uuid, TEST Store print line, fixture
#      label, or TEST key symbol; they do carry the fixture machine id bytes
#      and the BLOCKED_OPERATOR Store refusal line.
#   4. Control: the default full image still carries the labelled TEST Store
#      label (the grep is not vacuous).
# Build-only: nothing is booted. Takes the Spark quiet flag like the qemu_ck_*
# scripts (NOT_RUN, exit 3, if another run holds it). No Python.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kdir="${repo_root}/native/kernel"
fix="${kdir}/tests/fixtures/owner"
out="${CK_OWNER_CHECK_OUT:-${repo_root}/target/ck-owner-keys-check}"
cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-ck_owner_keys_check $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "CK_OWNER_KEYS_CHECK: NOT_RUN"
    exit 3
fi
tmp="$(mktemp -d)"
cleanup() {
    rm -rf "${tmp}"
    if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
}
trap cleanup EXIT

fails=0
ok() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; fails=$((fails + 1)); }
mk() { make -s -C "${kdir}" CROSS="${cross}" OUT="${out}" "$@"; }

own="${fix}/TEST-FIXTURE-owner-pubkeys.txt"
mach="${fix}/TEST-FIXTURE-machine-id.txt"
refusal="CK_HARDWARE_STAGING refuses the TEST Store keys and TEST machine id"

# ---- 1. build-time refusals ----------------------------------------------
expect_make_refused() { # label, expected text, make args...
    local label="$1" want="$2"; shift 2
    local log="${tmp}/make.log"
    if mk "$@" >"${log}" 2>&1; then
        bad "${label}: build was not refused"
    elif grep -qF -- "${want}" "${log}"; then
        ok "${label}: refused ($(grep -oF -- "${want}" "${log}" | head -1))"
    else
        bad "${label}: refused without the expected message: $(tail -c 300 "${log}")"
    fi
}
expect_make_refused "hardware staging, no owner files" "${refusal}" full CK_HARDWARE_STAGING=1
expect_make_refused "hardware staging, owner keys only" "${refusal}" full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own}"
expect_make_refused "hardware staging, machine id only" "${refusal}" full CK_HARDWARE_STAGING=1 CK_MACHINE_ID="${mach}"
expect_make_refused "owner files without hardware staging" "only used with CK_HARDWARE_STAGING=1" \
    full CK_OWNER_PUBKEYS="${own}" CK_MACHINE_ID="${mach}"
expect_make_refused "hardware staging + TEST artifact anchor" "cannot be combined with CK_HARDWARE_STAGING" \
    full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own}" CK_MACHINE_ID="${mach}" CK_SEED0B_TEST_ANCHOR=1

# ---- 2. generator refusals -----------------------------------------------
mk owner-gen
gen="${out}/host/ck_owner_gen"
good_pk="owner_root_ed25519 $(awk '$1=="owner_root_ed25519"{print $2}' "${own}")"
good_mid="machine_id $(awk '$1=="machine_id"{print $2}' "${mach}")"
good_uu="store_uuid $(awk '$1=="store_uuid"{print $2}' "${mach}")"
expect_gen_refused() { # label, expected text, owner file text, machine file text
    local label="$1" want="$2"
    printf '%s\n' "$3" >"${tmp}/o.txt"
    printf '%s\n' "$4" >"${tmp}/m.txt"
    rm -f "${tmp}/h.h"
    local res rc=0
    res="$("${gen}" "${tmp}/o.txt" "${tmp}/m.txt" "${tmp}/h.h" 2>&1)" || rc=$?
    if [[ "${rc}" == 1 && "${res}" == *"CK_OWNER_GEN: REFUSED"* && "${res}" == *"${want}"* && ! -e "${tmp}/h.h" ]]; then
        ok "generator refuses ${label} (${res#CK_OWNER_GEN: REFUSED })"
    else
        bad "generator ${label}: rc=${rc} out=${res}"
    fi
}
z64="$(printf '0%.0s' {1..64})"
expect_gen_refused "RFC 8032 TEST 1 owner key" "RFC 8032 TEST public key" \
    "owner_root_ed25519 d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" "${good_mid}"$'\n'"${good_uu}"
expect_gen_refused "RFC 8032 TEST 2 owner key" "RFC 8032 TEST public key" \
    "owner_root_ed25519 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c" "${good_mid}"$'\n'"${good_uu}"
expect_gen_refused "RFC 8032 TEST 3 owner key" "RFC 8032 TEST public key" \
    "owner_root_ed25519 fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025" "${good_mid}"$'\n'"${good_uu}"
expect_gen_refused "TEST machine id 0xA1" "TEST machine id" \
    "${good_pk}" "machine_id a1${z64:2}"$'\n'"${good_uu}"
expect_gen_refused "TEST store uuid" "TEST store uuid" \
    "${good_pk}" "${good_mid}"$'\n'"store_uuid 4149454e2d544553542d424f4f543031"
expect_gen_refused "all-zero owner key" "all bytes equal" "owner_root_ed25519 ${z64}" "${good_mid}"$'\n'"${good_uu}"
expect_gen_refused "all-zero machine id" "all bytes equal" "${good_pk}" "machine_id ${z64}"$'\n'"${good_uu}"
expect_gen_refused "short owner key" "need exactly 64 hex digits" "owner_root_ed25519 abcd" "${good_mid}"$'\n'"${good_uu}"
expect_gen_refused "long store uuid" "need exactly 32 hex digits" \
    "${good_pk}" "${good_mid}"$'\n'"store_uuid ${z64:0:30}0102"
expect_gen_refused "non-hex owner key" "not hex" "owner_root_ed25519 zz${z64:2}" "${good_mid}"$'\n'"${good_uu}"
expect_gen_refused "duplicate machine id" "given twice" "${good_pk}" "${good_mid}"$'\n'"${good_mid}"$'\n'"${good_uu}"
expect_gen_refused "unknown name" "unknown name" "${good_pk}"$'\n'"k_vol ${z64}" "${good_mid}"$'\n'"${good_uu}"
expect_gen_refused "missing store uuid" "missing" "${good_pk}" "${good_mid}"
expect_gen_refused "machine id equal to owner key" "equals the owner root public key" \
    "${good_pk}" "machine_id ${good_pk#owner_root_ed25519 }"$'\n'"${good_uu}"

# ---- 3. hardware staging image with the TEST-fixture owner files ---------
hw="${out}/full-hardware-staging"
if mk full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own}" CK_MACHINE_ID="${mach}" >"${tmp}/hw.log" 2>&1 \
    && [[ -s "${hw}/BOOTAA64.EFI" && -s "${hw}/aienos-ck.elf" ]]; then
    ok "hardware staging image built with the TEST-fixture owner files ($(grep -c . "${tmp}/hw.log") build lines)"
    grep -qF "no TEST Store label, uuid or key code" "${tmp}/hw.log" \
        && ok "Makefile owner_check ran on the hardware staging ELF" || bad "Makefile owner_check line missing"
else
    bad "hardware staging image with fixture owner files did not build: $(tail -c 400 "${tmp}/hw.log")"
fi
banned='AIENOS-LANE18-TEST-KVOL-NOT-SECRET|AIEN-TEST-BOOT01|TEST identity, TEST keys|formatted TEST store|TEST-FIXTURE|TEST FIXTURE'
for f in "${hw}/aienos-ck.elf" "${hw}/BOOTAA64.EFI"; do
    [[ -s "${f}" ]] || { bad "missing ${f}"; continue; }
    s="$(grep -aoE "${banned}" "${f}" | sort -u | tr '\n' ' ' || true)"
    [[ -z "${s}" ]] && ok "no TEST Store label/uuid/print line or fixture label in $(basename "${f}")" \
        || bad "$(basename "${f}") carries: ${s}"
    hex="$(od -An -tx1 -v "${f}" | tr -d ' \n')"
    mid_hex="$(awk '$1=="machine_id"{print $2}' "${mach}")"
    [[ "${hex}" == *"${mid_hex}"* ]] && ok "$(basename "${f}") carries the provisioned machine id bytes" \
        || bad "$(basename "${f}") lacks the provisioned machine id bytes"
    [[ "${hex}" == *"4149454e2d544553542d424f4f543031"* ]] && bad "$(basename "${f}") carries the TEST uuid bytes" \
        || ok "no TEST uuid bytes in $(basename "${f}")"
    grep -aqF 'production Store key source' "${f}" && ok "$(basename "${f}") carries the BLOCKED_OPERATOR Store refusal" \
        || bad "$(basename "${f}") lacks the BLOCKED_OPERATOR Store refusal"
done
if [[ -s "${hw}/aienos-ck.elf" ]]; then
    nmtool="${cross}nm"
    y="$("${nmtool}" "${hw}/aienos-ck.elf" | grep -E ' (ck_store_test_keys|ck_store_test_uuid)$' || true)"
    [[ -z "${y}" ]] && ok "no TEST Store key symbols in the hardware staging ELF" || bad "TEST symbols: ${y}"
    "${nmtool}" "${hw}/aienos-ck.elf" | grep -qE ' ck_store_production_keys$' \
        && ok "ck_store_production_keys (BLOCKED_OPERATOR seam) is linked" || bad "ck_store_production_keys not linked"
fi

# ---- 4. control: the default image keeps the labelled TEST keys -----------
if mk full >"${tmp}/def.log" 2>&1 && grep -aqF 'AIENOS-LANE18-TEST-KVOL-NOT-SECRET' "${out}/full/aienos-ck.elf"; then
    ok "control: default full image still carries the labelled TEST Store label"
else
    bad "control: default full image lacks the TEST Store label or did not build"
fi

if [[ "${fails}" == 0 ]]; then
    echo "CK_OWNER_KEYS_CHECK: PASS"
else
    echo "CK_OWNER_KEYS_CHECK: FAIL failures=${fails}"
    exit 1
fi
