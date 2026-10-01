#!/usr/bin/env bash
# Boot the AIENOS C kernel core with the P2 sealed-artifact loader
# (native/kernel/core/artifact_loader.c) in QEMU AArch64 + UEFI (AAVMF) and
# check the serial console against the same expectations as the Rust gate
# scripts/qemu_artifact_test.sh (SEED-0B / P2-5). QEMU is not hardware: a
# PASS here qualifies nothing physical.
#
# Two boots, as in the Rust gate:
#   1. qualification build (make CK_SEED0B_TEST_ANCHOR=1): trusts the RFC 8032
#      TEST 1 public key only (TEST ONLY); P26SEED, P25EXEC/WX/SPIN/TAMP and
#      the hostile set H01..H29 with their expected stage and reason;
#   2. ordinary build: empty production trust, every candidate refused.
# Every candidate's receipt is decoded, bound to the supplied artifact,
# digest-recomputed, TEST-signed and verified by the in-tree C tool.
#
# Differences from qemu_artifact_test.sh, all deliberate (native/kernel/GATES.md):
#  - builds with make (gcc), the artifacts with the in-tree C tool
#    (native/kernel/tools/ck_artifact_tool.c), not cargo / the Rust tool; the
#    probe programs are the committed fixtures, packed by the same pack.sh;
#  - candidates reach the kernel as one QEMU fw_cfg file
#    (opt/aienos/artifacts, a bundle) instead of ESP files read by a UEFI
#    loader: the C boot stub reads no files;
#  - no Machine 1 captured-log mode (SEED-0B Machine 1 stays with the Rust gate);
#  - takes the machine quiet flag itself (noclobber) and prints NOT_RUN while
#    another run holds it; AIENOS_QUIET_FLAG / AIENOS_QUIET_TAG as in
#    qemu_ck_boot_test.sh;
#  - stricter: any QEMU exit status other than 0 fails.
# Last line: AIENOS_CK_P2_ARTIFACT: PASS|FAIL|NOT_RUN.
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict=AIENOS_CK_P2_ARTIFACT

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict}: NOT_RUN"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out_prod="${repo_root}/target/native-kernel"
out_qual="${repo_root}/target/native-kernel-seed0b-test"
make -s -C native/kernel CROSS="${cross}" OUT="${out_prod}" AIENOS_COMMIT="${commit}" >/dev/null
make -s -C native/kernel CROSS="${cross}" OUT="${out_qual}" AIENOS_COMMIT="${commit}" \
    CK_SEED0B_TEST_ANCHOR=1 >/dev/null
make -s -C native/kernel OUT="${out_prod}" tool >/dev/null
tool="${out_prod}/host/ck_artifact_tool"

# Machine quiet flag: one heavy run at a time on the Spark.
quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_artifact_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${verdict}: NOT_RUN"
    exit 3
fi
own_flag=1
release_flag() {
    if [[ "${own_flag}" == 1 ]]; then
        own_flag=0
        if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
    fi
}
work="$(mktemp -d)"
cleanup() {
    rm -rf "${work}"
    release_flag
}
trap cleanup EXIT
failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

# ---- inputs -----------------------------------------------------------------
fixtures="crates/aienos-artifact-tool/fixtures/p2_5"
seed_fixtures="crates/aienos-artifact-tool/fixtures/p2_6"
art="${work}/artifacts"
mkdir -p "${art}"
"${fixtures}/pack.sh" "${tool}" "${art}" >/dev/null
"${seed_fixtures}/pack.sh" "${tool}" "${art}" >/dev/null
mv "${art}/ids.txt" "${work}/ids.txt"
"${tool}" negative-corpus "${art}" >/dev/null
mv "${art}/expected.txt" "${work}/expected.txt"
for f in "${art}"/H*.AIEN; do
    n=$(basename "${f}")
    awk -v n="${n}" '$1 == n { found = 1 } END { exit !found }' "${work}/ids.txt" \
        || echo "${n} $("${tool}" id "${f}" 2>/dev/null || echo none)" >>"${work}/ids.txt"
done
mapfile -t files < <(find "${art}" -maxdepth 1 -name '*.AIEN' | LC_ALL=C sort)
candidate_count=${#files[@]}
"${tool}" bundle "${work}/bundle.bin" "${files[@]}" >/dev/null
id_prefix() { awk -v n="$1" '$1 == n { print substr($2, 1, 16) }' "${work}/ids.txt"; }

boot() { # image, serial text output
    local esp="${work}/esp" log="${work}/serial.log" started status
    rm -rf "${esp}"
    mkdir -p "${esp}/EFI/BOOT" "${esp}/EFI/AIENOS"
    touch "${esp}/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$1" "${esp}/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    started=$(date +%s)
    set +e
    # Issue #61: single-threaded TCG; MTTCG hung in 1/40 soak boots.
    nice -n 10 timeout "${AIENOS_QEMU_TIMEOUT:-300}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${esp}" \
        -device virtio-blk-pci,drive=esp \
        -fw_cfg name=opt/aienos/artifacts,file="${work}/bundle.bin" \
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
common_checks() { # serial
    check "$1" "left firmware and entered the kernel" "kernel: alive"
    check "$1" "M3 cooperative threads unchanged" "threads: ok"
    check "$1" "M3 EL0 isolation proof unchanged" "el0: ok write=granted forged=denied fault=contained exit=0"
    check "$1" "M3 typed IPC proof unchanged" "ipc: ok message=delivered cap=delegated rights=attenuated forged=denied revoked=denied"
    check "$1" "kernel read all ${candidate_count} artifact candidates" "^artifact_candidates: ${candidate_count}$"
    if grep -q "^report-truncated:" "$1"; then fail "kernel report lines were truncated"; else pass "no kernel report line was truncated"; fi
    check "$1" "final report reached the console" "report_kind: final"
    if has "$1" "report_kind: (panic|fault)"; then fail "panic or fault reported"; fi
    if has "$1" "^receipt: [^ ]+ seq=[0-9]+ invalid$"; then fail "a candidate produced no valid receipt"; fi
    if has "$1" "^artifact_bundle: malformed"; then fail "kernel found the bundle malformed"; fi
    local before after
    before=$(grep -oE "artifact_frames_free_before: [0-9]+" "$1" | awk '{print $2}' | tail -1)
    after=$(grep -oE "artifact_frames_free_after: [0-9]+" "$1" | awk '{print $2}' | tail -1)
    if [[ -n "${before}" && "${before}" == "${after}" ]]; then
        pass "every frame returned after all candidates (${before} free before and after)"
    else
        fail "frame accounting across candidates (before=${before:-?} after=${after:-?})"
    fi
}

rtag=""
receipt_check() { # serial name pattern
    local serial="$1" name="$2" want="$3" line record kdigest out
    line=$(grep -E "^receipt: ${name//./\\.} seq=[0-9]+ digest=[0-9a-f]{64} record=[0-9a-f]{1024}$" "${serial}" | tail -1 || true)
    if [[ -z "${line}" ]]; then fail "${name} receipt emitted"; return; fi
    record=${line##*record=}
    kdigest=$(sed -E 's/.* digest=([0-9a-f]{64}) .*/\1/' <<<"${line}")
    local file="${work}/${rtag}-${name}.receipt"
    "${tool}" receipt from-hex "${record}" "${file}" >/dev/null
    if ! out=$("${tool}" receipt check "${file}" "${art}/${name}" 2>&1); then
        fail "${name} receipt binds the supplied artifact (${out})"; return
    fi
    if [[ "${out}" != *"digest=${kdigest} "* ]]; then fail "${name} receipt digest recomputed by the host"; return; fi
    if ! grep -qE -- "${want}" <<<"${out}"; then fail "${name} receipt records the observed outcome (${out})"; return; fi
    "${tool}" receipt sign-test "${file}" "${file}.signed" >/dev/null
    if "${tool}" receipt verify "${file}.signed" | grep -q "RECEIPT_VERIFY: PASS digest=${kdigest} "; then
        pass "${name} receipt: bound, host digest match, observed outcome, TEST ONLY signature verifies"
    else
        fail "${name} signed receipt verifies"
    fi
}
stage_code() { case "$1" in received) echo 1;; staged) echo 2;; verified) echo 3;; authorized) echo 4;;
    reserved) echo 5;; mapped) echo 6;; hashed) echo 7;; sealed) echo 8;; caps) echo 9;; *) echo x;; esac; }
status_of() { case "$1" in exited:*) echo Exited;; timeout) echo Timeout;; fault:*) echo Fault;;
    bad-syscall:*) echo BadSyscall;; resource-overrun) echo ResourceOverrun;; *) echo NotRun;; esac; }
admitted_line() { # name, exec regex, caps
    echo "^artifact: ${1//./\\.} admitted id=$(id_prefix "$1") tier=seed0b-test exec=$2 bytes=identified=verified=admitted=mapped=executed wx=enforced caps=$3 revoked=yes reclaimed=yes frames=[0-9]+ "
}

# ---- boot 1: qualification build -------------------------------------------
qual="${work}/qualification.txt"
rtag=qual
boot "${out_qual}/BOOTAA64.EFI" "${qual}"
common_checks "${qual}"
check "${qual}" "qualification build is labelled TEST ONLY" \
    "artifact_trust: seed0b-test qualification build — TEST ONLY"
check "${qual}" "receipts carry the SEED-0B-QEMU tier" "^artifact_receipt_tier: SEED-0B-QEMU$"
check "${qual}" "P26SEED read through its grant, WRITE and forged authority denied, exit 0, reclaimed" \
    "$(admitted_line P26SEED.AIEN exited:0x0 1)syscalls=9 reads=3 denials=5$"
check "${qual}" "P26SEED granted exactly its READ request" \
    "^grant: P26SEED\.AIEN\[0\] kind=object id=1 rights=0x1 bounds=0\+32 max_ops=4 max_bytes=32$"
if [[ $(grep -c "^grant: P26SEED\.AIEN\[" "${qual}") == 1 ]]; then pass "P26SEED holds exactly one capability"; else fail "P26SEED holds exactly one capability"; fi
receipt_check "${qual}" P26SEED.AIEN "decision=Admitted tier=SEED-0B-QEMU stage=0 reason=0x0 status=Exited exit=0 syscalls=9 reads_ok=3 denials=5 flags=0xff$"
check "${qual}" "P25EXEC executed its exact authenticated bytes, exit 0, caps revoked, reclaimed" \
    "$(admitted_line P25EXEC.AIEN exited:0x0 1)syscalls=3 reads=1 denials=1$"
check "${qual}" "P25WX killed by a W^X fault on its code page, reclaimed" \
    "$(admitted_line P25WX.AIEN fault:code-write 0)syscalls=0 reads=0 denials=0$"
check "${qual}" "P25SPIN killed at its time budget, reclaimed" \
    "$(admitted_line P25SPIN.AIEN timeout 0)syscalls=0 reads=0 denials=0$"
check "${qual}" "P25TAMP (payload byte flipped after signing) rejected BadSignature, reclaimed" \
    "^artifact: P25TAMP\.AIEN rejected stage=verified reason=BadSignature reclaimed=yes$"
receipt_check "${qual}" P25EXEC.AIEN "decision=Admitted .* status=Exited exit=0 syscalls=3 reads_ok=1 denials=1 flags=0xfd$"
receipt_check "${qual}" P25WX.AIEN "decision=Admitted .* status=Fault exit=0 syscalls=0 reads_ok=0 denials=0 flags=0xe4$"
receipt_check "${qual}" P25SPIN.AIEN "decision=Admitted .* status=Timeout exit=0 syscalls=0 reads_ok=0 denials=0 flags=0xe4$"
receipt_check "${qual}" P25TAMP.AIEN "decision=Rejected .* stage=3 reason=0x12 status=NotRun exit=0 syscalls=0 reads_ok=0 denials=0 flags=0x04$"

matrix_total=0 matrix_admitted=0
while read -r name decision a b c _; do
    [[ -n "${name}" ]] || continue
    matrix_total=$((matrix_total + 1))
    if [[ "${decision}" == rejected ]]; then
        check "${qual}" "${name} refused at ${a} (${b}), never ran, reclaimed" \
            "^artifact: ${name//./\\.} rejected stage=${a} reason=${b} reclaimed=yes$"
        receipt_check "${qual}" "${name}" "decision=Rejected .* stage=$(stage_code "${a}") reason=${c} status=NotRun exit=0 syscalls=0 reads_ok=0 denials=0 flags=0x04$"
    else
        matrix_admitted=$((matrix_admitted + 1))
        check "${qual}" "${name} admitted and contained (${a}), reclaimed" "$(admitted_line "${name}" "${a}" "${b}")"
        receipt_check "${qual}" "${name}" "decision=Admitted .* status=$(status_of "${a}") "
    fi
done < <(sed 's/ #.*//' "${work}/expected.txt")
[[ "${matrix_total}" -ge 29 ]] && pass "hostile matrix has ${matrix_total} cases" || fail "hostile matrix has only ${matrix_total} cases"
check "${qual}" "H29 requested READ|WRITE and was granted READ only" \
    "^grant: H29-READ-WRITE-REQUEST\.AIEN\[0\] kind=object id=1 rights=0x1 "
if has "${qual}" "^grant: H28-"; then fail "H28 (WRITE-only request) received a capability"; else pass "H28 requested only WRITE and received no capability"; fi
check "${qual}" "final report summarises every admission decision" \
    "^artifacts: candidates=${candidate_count} admitted=$((4 + matrix_admitted)) rejected=$((1 + matrix_total - matrix_admitted))$"

# ---- boot 2: ordinary build, empty production trust -------------------------
prod="${work}/production.txt"
rtag=prod
boot "${out_prod}/BOOTAA64.EFI" "${prod}"
release_flag
common_checks "${prod}"
if has "${prod}" "seed0b-test qualification build"; then fail "ordinary build must not carry the qualification label"; fi
if has "${prod}" "^artifact: [^ ]+ admitted"; then fail "ordinary build admitted an artifact"; else pass "ordinary build admitted nothing"; fi
prod_expect() { # name -> "stage reason code" in the ordinary build
    local line
    line=$(sed 's/ #.*//' "${work}/expected.txt" | awk -v n="$1" '$1 == n')
    if [[ -n "${line}" ]] && read -r _ d s r c <<<"${line}" && [[ "${d}" == rejected && "${s}" == verified \
        && "${r}" != BadSignature && "${r}" != UntrustedSigner ]]; then
        echo "${s} ${r} ${c}"
    else
        echo "verified UntrustedSigner 0x11"
    fi
}
for f in "${files[@]}"; do
    name=$(basename "${f}")
    read -r s r c <<<"$(prod_expect "${name}")"
    check "${prod}" "ordinary build refuses ${name} (${r}), reclaimed" \
        "^artifact: ${name//./\\.} rejected stage=${s} reason=${r} reclaimed=yes$"
    receipt_check "${prod}" "${name}" "decision=Rejected .* stage=$(stage_code "${s}") reason=${c} status=NotRun .* flags=0x04$"
done
check "${prod}" "final report summarises zero admitted" \
    "^artifacts: candidates=${candidate_count} admitted=0 rejected=${candidate_count}$"

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then
    cp "${qual}" "${AIENOS_LOG_DIR}/qemu_ck_artifact_qualification_serial.log"
    cp "${prod}" "${AIENOS_LOG_DIR}/qemu_ck_artifact_production_serial.log"
fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- qualification serial (artifact lines) ----"
    grep -E "^(artifact|grant|kernel|report_kind|panic|fault|exception|esr|far)" "${qual}" | head -120 || true
fi
if [[ "${failed}" == 0 ]]; then echo "${verdict}: PASS"; else echo "${verdict}: FAIL"; exit 1; fi
