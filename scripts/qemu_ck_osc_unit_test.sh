#!/usr/bin/env bash
# AIENOS_CK_OSC_UNIT gate: OSC unit admission (OSC_UNIT_ARTIFACT v1, aien-protocols
# PR #17) in the C kernel, booted in QEMU AArch64 + UEFI (AAVMF).
#
# Label: QEMU (aarch64 virt), TEST signer, not physical. Nothing here ran on a
# Spark or any real machine. The only key is the spec's THROWAWAY TEST key; no
# OWNER anchor exists (TRUST-1 has not provisioned one). Admission only: no
# unit is mapped, launched or scheduled.
#
# Four conformance vectors (tests/fixtures/osc_unit/vectors) are written into
# the sealed C Store of a GPT boot disk image at build time and read back by the
# kernel's store stage, the same path as the P2 artifacts (svc/artifact_store.h):
#   a01_valid_min.unit      TEST-signed, valid
#   a04_valid_owner_class.unit  OWNER class, valid signature, no OWNER anchor
#   r14_bad_signature.unit  TEST-signed, signature byte flipped
#   r37_code_svc.unit       code contains an SVC word
# Two boots of the full image, each with QEMU iommu=smmuv3 and the NVMe image:
#   1. qualification build (CK_SEED0B_TEST_ANCHOR=1, TEST ONLY): a01 ACCEPT with
#      the UnitDigest and program id of the frozen expected.txt; a04
#      UNTRUSTED_SIGNER; r14 BAD_SIGNATURE; r37 CODE_INSTRUCTION.
#   2. ordinary (release) build, no anchors: a01 TEST_SIGNER_IN_RELEASE; a04
#      UNTRUSTED_SIGNER; r14 TEST_SIGNER_IN_RELEASE (the class check precedes the
#      signature); r37 CODE_INSTRUCTION; nothing accepted.
# Static: the release image carries the TEST public key nowhere.
# Last line: AIENOS_CK_OSC_UNIT: PASS|FAIL|NOT_RUN.
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict=AIENOS_CK_OSC_UNIT

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict}: NOT_RUN"; exit 2; }

# Machine quiet flag (read only) and the QEMU gate lock (one gate at a time):
# scripts/lib_gate_hold.sh (aienos#278).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take "qemu_ck_osc_unit_test" "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "${verdict}: NOT_RUN"
    exit 3
fi
# Release only this run's own gate lock record, at most once.
release_flag() { gh_lock_release; }
work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; release_flag; }
trap cleanup EXIT
failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out_prod="${AIENOS_CK_OUT_PROD:-${repo_root}/target/native-kernel}"
out_qual="${AIENOS_CK_OUT_QUAL:-${repo_root}/target/native-kernel-seed0b-test}"
mk() { make -s -C native/kernel CROSS="${cross}" AIENOS_COMMIT="${commit}" "$@" >/dev/null; }
mk OUT="${out_prod}" full
mk OUT="${out_qual}" CK_SEED0B_TEST_ANCHOR=1 full
make -s -C native/kernel OUT="${out_prod}" store-image gpt-image >/dev/null
simg="${out_prod}/host/ck_store_image"

fix="native/kernel/tests/fixtures/osc_unit"
units=(a01_valid_min.unit a04_valid_owner_class.unit r14_bad_signature.unit r37_code_svc.unit)
files=()
for u in "${units[@]}"; do files+=("${fix}/vectors/${u}"); done
a01_line=$(grep -E '^a01_valid_min\.unit ' "${fix}/vectors/expected.txt")
a01_digest=$(sed -E 's/.* unit_digest=([0-9a-f]{64}) .*/\1/' <<<"${a01_line}")
a01_prog=$(sed -E 's/.* program_id=([0-9a-f]{64})$/\1/' <<<"${a01_line}")
[[ ${#a01_digest} == 64 && ${#a01_prog} == 64 ]] || { fail "expected UnitDigest read from the frozen expected.txt"; }

# ---- static: the release image does not carry the TEST public key ----------
key_hex=$(tr -d '\n' <"${fix}/keys/test1.pub")
key_bytes=$(printf "$(sed 's/../\\x&/g' <<<"${key_hex}")")
for d in "${out_prod}/full"; do
    if LC_ALL=C grep -aqF -- "${key_bytes}" "${d}/BOOTAA64.EFI"; then fail "release image ${d#"${repo_root}"/} carries the OSC TEST public key"
    else pass "release image ${d#"${repo_root}"/} does not carry the OSC TEST public key"; fi
done
if LC_ALL=C grep -aqF -- "${key_bytes}" "${out_qual}/full/BOOTAA64.EFI"; then
    pass "the check sees the TEST key in the TEST-anchor qualification image (never counted as release)"
else
    fail "the TEST key is not found in the qualification image, so the release check proves nothing"
fi

# ---- boot disk: the vectors in the sealed Store ------------------------------
disk="${work}/nvme.img"
"${out_prod}/host/ck_gpt_image" create "${disk}" 512 64 aienos-middle >/dev/null || fail "GPT boot disk image created"
if "${simg}" build "${disk}" 512 "${files[@]}" >"${work}/build.txt" 2>&1; then pass "boot disk built: $(head -1 "${work}/build.txt")"
else fail "boot disk build: $(head -3 "${work}/build.txt" | tr '\n' ' ')"; fi
"${simg}" list "${disk}" 512 >"${work}/list.txt" 2>&1 || fail "host read-back of the boot disk Store"
for f in "${files[@]}"; do
    grep -qxF "$(basename "${f}") bytes=$(stat -c %s "${f}") sha256=$(sha256sum "${f}" | cut -d' ' -f1)" "${work}/list.txt" \
        || fail "host read-back of $(basename "${f}")"
done

boot() { # image, serial text output, disk image
    local esp="${work}/esp" log="${work}/serial.log" started status
    rm -rf "${esp}"
    mkdir -p "${esp}/EFI/BOOT" "${esp}/EFI/AIENOS"
    touch "${esp}/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$1" "${esp}/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    started=$(date +%s)
    set +e
    nice -n 10 timeout "${AIENOS_QEMU_TIMEOUT:-300}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${esp}" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="$3" \
        -device nvme,drive=nvme0,serial=aienos-nvme-test \
        -device ramfb -display none -nic none \
        -serial file:"${log}" -no-reboot
    status=$?
    set -e
    tr -d '\r' <"${log}" >"$2"
    echo "qemu exit ${status} after $(( $(date +%s) - started )) s (commit ${commit:0:12})"
    [[ "${status}" == 0 ]] || fail "QEMU exit status ${status} (124 = timeout)"
}
has() { grep -qE -- "$2" "$1"; }
check() { if has "$1" "$3"; then pass "$2"; else fail "$2"; fi; }
common_checks() {
    check "$1" "left firmware and entered the kernel" "kernel: alive"
    check "$1" "kernel read all ${#units[@]} candidates from the boot disk Store" "^artifact_candidates: ${#units[@]}$"
    check "$1" "artifact_source=nvme_store" "^artifact_source: nvme_store generation=[0-9]+ candidates=${#units[@]} "
    if has "$1" "^report-truncated:"; then fail "kernel report lines were truncated"; else pass "no kernel report line was truncated"; fi
    check "$1" "final report reached the console" "report_kind: final"
    if has "$1" "report_kind: (panic|fault)"; then fail "panic or fault reported"; fi
    if has "$1" "^artifact_bundle: malformed"; then fail "candidate list malformed"; fi
    if has "$1" "TEST-ONLY QEMU fw_cfg|^artifact_source: fw_cfg"; then fail "fw_cfg source in a counted boot"; fi
    if has "$1" "^artifact: "; then fail "an OSC unit was handed to the Binary Artifact v0 path"; else pass "no OSC unit went through the Binary Artifact v0 path"; fi
    check "$1" "one osc_unit line per candidate" "^osc_units: seen=${#units[@]} "
    check "$1" "the summary says admission only, nothing launched" "^osc_units: .*\(admission only, nothing launched\)$"
}
unit_line() { # serial name expected-regex-tail
    if has "$1" "^osc_unit: ${2//./\\.} $3\$"; then pass "$2 -> $4"; else fail "$2 expected: $4 (got: $(grep -E "^osc_unit: ${2//./\\.} " "$1" | head -1 || echo none))"; fi
}

# ---- boot 1: qualification build (TEST ONLY anchor) -------------------------
qual="${work}/qualification.txt"
cp "${disk}" "${work}/disk-qual.img"
boot "${out_qual}/full/BOOTAA64.EFI" "${qual}" "${work}/disk-qual.img"
common_checks "${qual}"
check "${qual}" "policy line: qualification mode, one TEST anchor, no OWNER anchor, TEST ONLY, QEMU not physical" \
    "^osc_policy: mode=qualification test_anchors=1 \(throwaway TEST key, TEST ONLY\) owner_anchors=0 domains=1 gen_width=32; QEMU, not physical$"
unit_line "${qual}" a01_valid_min.unit \
    "ACCEPT unit_digest=${a01_digest} program_id=${a01_prog} funcs=2 caps=0 signer=TEST" \
    "ACCEPT, UnitDigest and program id equal the frozen expected.txt"
unit_line "${qual}" a04_valid_owner_class.unit "REFUSED code=25 name=UNTRUSTED_SIGNER" "REFUSED UNTRUSTED_SIGNER (OWNER, no OWNER anchor)"
unit_line "${qual}" r14_bad_signature.unit "REFUSED code=26 name=BAD_SIGNATURE" "REFUSED BAD_SIGNATURE"
unit_line "${qual}" r37_code_svc.unit "REFUSED code=34 name=CODE_INSTRUCTION" "REFUSED CODE_INSTRUCTION (SVC word)"
check "${qual}" "qualification totals: 1 accepted, 3 refused" "^osc_units: seen=4 accepted=1 refused=3 "

# ---- boot 2: ordinary (release) build, no anchors ----------------------------
prod="${work}/release.txt"
cp "${disk}" "${work}/disk-prod.img"
boot "${out_prod}/full/BOOTAA64.EFI" "${prod}" "${work}/disk-prod.img"
release_flag
common_checks "${prod}"
check "${prod}" "policy line: release mode, no anchors at all" \
    "^osc_policy: mode=release test_anchors=0 owner_anchors=0 \(none provisioned\) domains=1 gen_width=32; QEMU, not physical$"
if has "${prod}" "seed0b-test qualification build"; then fail "release build carries the qualification label"; fi
unit_line "${prod}" a01_valid_min.unit "REFUSED code=24 name=TEST_SIGNER_IN_RELEASE" "REFUSED TEST_SIGNER_IN_RELEASE (a valid TEST-signed unit)"
unit_line "${prod}" a04_valid_owner_class.unit "REFUSED code=25 name=UNTRUSTED_SIGNER" "REFUSED UNTRUSTED_SIGNER (OWNER, no anchor)"
unit_line "${prod}" r14_bad_signature.unit "REFUSED code=24 name=TEST_SIGNER_IN_RELEASE" "REFUSED TEST_SIGNER_IN_RELEASE (class is checked before the signature)"
unit_line "${prod}" r37_code_svc.unit "REFUSED code=34 name=CODE_INSTRUCTION" "REFUSED CODE_INSTRUCTION"
check "${prod}" "release totals: nothing accepted" "^osc_units: seen=4 accepted=0 refused=4 "

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then
    cp "${qual}" "${AIENOS_LOG_DIR}/qemu_ck_osc_unit_qualification_serial.log"
    cp "${prod}" "${AIENOS_LOG_DIR}/qemu_ck_osc_unit_release_serial.log"
fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- qualification serial (osc lines) ----"; grep -E "^(osc_|artifact|kernel|report_kind|panic|fault)" "${qual}" | head -60 || true
    echo "---- release serial (osc lines) ----"; grep -E "^(osc_|artifact|kernel|report_kind|panic|fault)" "${prod}" | head -60 || true
fi
echo "label: QEMU (aarch64 virt), TEST signer, not physical"
if [[ "${failed}" == 0 ]]; then echo "${verdict}: PASS"; else echo "${verdict}: FAIL"; exit 1; fi
