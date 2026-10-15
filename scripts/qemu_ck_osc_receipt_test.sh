#!/usr/bin/env bash
# AIENOS_CK_OSC_RECEIPT gate (aienos#383): the C kernel refuses to launch an OSC unit unless a valid signed Omega
# realization receipt (omega spec/one-layer-receipts.md, receipt v1) comes with it. Booted in QEMU AArch64 + UEFI
# (AAVMF).
#
# Label: QEMU (aarch64 virt), TEST signer, not physical. Nothing here ran on a Spark or any real machine. The
# receipts are minted by omega checker2 with its TEST key (tests/fixtures/osc_receipt/PROVENANCE.txt), except
# a01.owner.rcpt, signed with the owner key on the owner YubiKey (tests/fixtures/osc_receipt_owner/PROVENANCE.txt,
# aienos#387); the units are signed with the container spec's THROWAWAY TEST key.
#
# One unit (a01_valid_min.unit) and fourteen receipts are written into the sealed C Store of a GPT boot disk
# image. One boot of the qualification image built with CK_SEED0B_TEST_ANCHOR=1 CK_OSC_LAUNCH_TEST=1
# CK_OSC_RECEIPT_TEST=1 launches a01 add(a, b) eighteen times, each time with one receipt or none, and prints one
# "osc_rcpt_launch:" line each. This gate checks:
#   with the valid receipt the unit RETURNS the exact value (first and last launch), and with the owner receipt in
#   release mode (aienos#387);
#   no receipt, an altered, stale, revoked, expired, not-yet-valid, wrong-target, wrong-firmware, wrong-program,
#   wrong-executable, wrong-length, wrong-dependencies or untrusted-checker receipt, the TEST key revoked, and a
#   TEST receipt under the release policy are each REFUSED with its own named reason, and nothing is mapped;
#   the receipt id printed is the SHA-256 of the receipt file.
# Last line: AIENOS_CK_OSC_RECEIPT: PASS|FAIL|NOT_RUN.
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict=AIENOS_CK_OSC_RECEIPT
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict}: NOT_RUN"; exit 2; }

# Machine quiet flag (read only) and the QEMU gate lock (one gate at a time):
# scripts/lib_gate_hold.sh (aienos#278).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take "qemu_ck_osc_receipt_test" "${AIENOS_GATE_MINUTES:-60}"; then
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
out_rcpt="${AIENOS_CK_OUT_RECEIPT:-${repo_root}/target/native-kernel-osc-receipt-test}"
mk() { make -s -C native/kernel CROSS="${cross}" AIENOS_COMMIT="${commit}" "$@" >/dev/null; }
mk OUT="${out_rcpt}" CK_SEED0B_TEST_ANCHOR=1 CK_OSC_LAUNCH_TEST=1 CK_OSC_RECEIPT_TEST=1 full
make -s -C native/kernel OUT="${out_prod}" store-image gpt-image >/dev/null
simg="${out_prod}/host/ck_store_image"

fix="native/kernel/tests/fixtures/osc_unit"
rfix="native/kernel/tests/fixtures/osc_receipt"
ofix="native/kernel/tests/fixtures/osc_receipt_owner"
rcpts=(a01 l01 n_altered n_stale n_revoked_id n_expired n_future n_target n_program n_length n_firmware n_deps n_checker)
files=("${fix}/vectors/a01_valid_min.unit")
for r in "${rcpts[@]}"; do files+=("${rfix}/${r}.rcpt"); done
files+=("${ofix}/a01.owner.rcpt")
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

serial="${work}/serial.txt"
cp "${disk}" "${work}/disk-run.img"
boot "${out_rcpt}/full/BOOTAA64.EFI" "${serial}" "${work}/disk-run.img"
release_flag

check "${serial}" "left firmware and entered the kernel" "kernel: alive"
check "${serial}" "kernel read all fifteen candidates (one unit, fourteen receipts) from the boot disk Store" "^artifact_candidates: 15$"
if has "${serial}" "^report-truncated:"; then fail "kernel report lines were truncated"; else pass "no kernel report line was truncated"; fi
check "${serial}" "final report reached the console" "report_kind: final"
if has "${serial}" "report_kind: (panic|fault)"; then fail "panic or fault reported"; else pass "no kernel panic or fault report"; fi
check "${serial}" "a01 admitted (the container check is unchanged)" "^osc_unit: a01_valid_min\\.unit ACCEPT "
check "${serial}" "receipt policy line: qualification, TEST receipt anchor, the owner root as owner receipt anchor, launch requires a receipt" \
    "^osc_receipt_policy: mode=qualification receipt_test_anchors=1 receipt_owner_anchors=1 \\(the owner root\\) checkers=1 target=aienos-ck-aarch64-el0 epoch_floor=10 epoch_now=20 revoked_ids=1 revoked_keys=0 firmware=none dependencies=none producer=none; launch requires a valid receipt; QEMU, not physical$"
for rf in "${files[@]:1}"; do
    r=$(basename "${rf}" .rcpt); b=$(stat -c %s "${rf}"); id=-
    [[ "${b}" == 416 ]] && id=$(sha256sum "${rf}" | cut -c1-64)
    check "${serial}" "${r}.rcpt stored from the Store (bytes=${b})" "^osc_receipt: ${r//./\\.}\\.rcpt STORED bytes=${b} id=${id} "
done
check "${serial}" "receipt totals: 14 seen, 14 stored" "^osc_receipts: seen=14 stored=14 dropped=0 "
check "${serial}" "self-test announces 18 launches" "^osc_rcpt_selftest: launches=18 unit=a01_valid_min\\.unit; "

label='QEMU \(aarch64 virt\), TEST signer, not physical'
a=a01_valid_min.unit
# rline TEXT ARGS RECEIPT POLICY RESULT REVOKED [run]: one launch line. A refusal ran nothing: no tick, no page.
rline() {
    local file="${rfix}/$3" id='-' t
    [[ -e "${ofix}/$3" ]] && file="${ofix}/$3"
    [[ "$3" != none && $(stat -c %s "${file}") == 416 ]] && id=$(sha256sum "${file}" | cut -c1-16)
    t="ticks=0 pages_mapped=0 page_tables_zeroed=1 slot_free=1"
    [[ "${7:-}" == run ]] && t="ticks=[0-9]+ pages_mapped=[1-9][0-9]* page_tables_zeroed=1 slot_free=1"
    check "${serial}" "$1" "^osc_rcpt_launch: ${a} add\\($2\\) receipt=${3//./\\.} policy=$4 -> $5 receipt_id=${id} revoked=$6 ${t}; ${label}\$"
}
ref() { echo "REFUSED_AT_ADMISSION code=$1 name=RECEIPT_$2"; }
rline "valid receipt: the unit runs, add(1,2) RETURNED 3" '1,2' a01.rcpt qualification 'RETURNED value=3' - run
rline "no receipt: refused RECEIPT_MISSING (64)" '2,3' none qualification "$(ref 64 MISSING)" -
rline "altered receipt (one byte of the executable digest flipped): RECEIPT_BAD_SIGNATURE (75)" '3,4' n_altered.rcpt qualification "$(ref 75 BAD_SIGNATURE)" -
rline "replayed receipt below the epoch floor: RECEIPT_STALE_EPOCH (77)" '4,5' n_stale.rcpt qualification "$(ref 77 STALE_EPOCH)" -
rline "revoked receipt id: RECEIPT_REVOKED (76), revoked=receipt_id" '5,6' n_revoked_id.rcpt qualification "$(ref 76 REVOKED)" receipt_id
rline "revoked signer key (the TEST key fingerprint revoked): RECEIPT_REVOKED (76), revoked=signer_key" '6,7' a01.rcpt revoked_test_key "$(ref 76 REVOKED)" signer_key
rline "expired receipt: RECEIPT_EXPIRED (78)" '7,8' n_expired.rcpt qualification "$(ref 78 EXPIRED)" -
rline "receipt not yet valid: RECEIPT_NOT_YET_VALID (79)" '8,9' n_future.rcpt qualification "$(ref 79 NOT_YET_VALID)" -
rline "receipt for another target: RECEIPT_WRONG_TARGET (80)" '9,10' n_target.rcpt qualification "$(ref 80 WRONG_TARGET)" -
rline "receipt for another executable (l01's): RECEIPT_EXECUTABLE_MISMATCH (83)" '10,11' l01.rcpt qualification "$(ref 83 EXECUTABLE_MISMATCH)" -
rline "receipt for another program: RECEIPT_PROGRAM_MISMATCH (82)" '11,12' n_program.rcpt qualification "$(ref 82 PROGRAM_MISMATCH)" -
rline "receipt of the wrong length (417 bytes): RECEIPT_SIZE (65)" '12,13' n_length.rcpt qualification "$(ref 65 SIZE)" -
rline "TEST receipt under the release policy: RECEIPT_TEST_SIGNER_IN_PRODUCTION (73)" '13,14' a01.rcpt release "$(ref 73 TEST_SIGNER_IN_PRODUCTION)" -
rline "receipt naming firmware: RECEIPT_WRONG_FIRMWARE (81)" '14,15' n_firmware.rcpt qualification "$(ref 81 WRONG_FIRMWARE)" -
rline "receipt with a dependency: RECEIPT_DEPENDENCIES_MISMATCH (88)" '15,16' n_deps.rcpt qualification "$(ref 88 DEPENDENCIES_MISMATCH)" -
rline "receipt from an unlisted checker: RECEIPT_UNTRUSTED_CHECKER (86)" '16,17' n_checker.rcpt qualification "$(ref 86 UNTRUSTED_CHECKER)" -
rline "owner receipt (signed on the owner YubiKey) in release mode: the unit runs, add(17,18) RETURNED 35" '17,18' a01.owner.rcpt release 'RETURNED value=35' - run
rline "after every refusal, the valid receipt still runs the unit: add(20,22) RETURNED 42" '20,22' a01.rcpt qualification 'RETURNED value=42' - run
check "${serial}" "summary: 3 returned, 15 refused" "^osc_rcpt_launches: returned=3 trapped=0 refused=15 unknown=0; ${label}\$"
nl=$(grep -c '^osc_rcpt_launch: ' "${serial}" || true)
names=$(grep -oE '^osc_rcpt_launch: .* name=RECEIPT_[A-Z_]+' "${serial}" | sed -E 's/.*name=//' | sort | uniq -d | tr '\n' ' ')
[[ "${nl}" == 18 ]] && pass "exactly 18 receipt launch lines" || fail "receipt launch lines (${nl} of 18)"
# REVOKED appears twice on purpose (receipt id, signer key), told apart by the revoked= column
[[ "${names}" == "RECEIPT_REVOKED " ]] && pass "every other refusal names a reason of its own" || fail "refusal reasons repeated: ${names}"
if grep -E '^osc_launch: ' "${serial}" | grep -q .; then fail "a C3-3a launch line appeared in the receipt self-test"; else pass "only the receipt self-test ran"; fi

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then cp "${serial}" "${AIENOS_LOG_DIR}/qemu_ck_osc_receipt_serial.log"; fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial (osc lines) ----"; grep -E "^(osc_|artifact|kernel|report_kind|panic|fault)" "${serial}" | head -80 || true
fi
echo "label: QEMU (aarch64 virt), TEST signer, not physical"
if [[ "${failed}" == 0 ]]; then echo "${verdict}: PASS"; else echo "${verdict}: FAIL"; exit 1; fi
