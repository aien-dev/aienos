#!/usr/bin/env bash
# SEED-0B QEMU qualification (P2-5 loader, P2-6 SEED-0B artifact and
# Admission Receipt v0, P2-7 negative matrix) in QEMU AArch64 (UEFI, EL2).
#
# Firmware reads signed .AIEN files from \EFI\AIENOS\ARTIFACTS on the ESP and
# hands their bytes to the kernel, which stages, verifies, admits, loads and
# runs each one as an isolated EL0 task, then reclaims it. Two boots:
#
#   1. seed0b-qualification build (TEST ONLY qualification trust anchor):
#      P26SEED  first SEED-0B capability artifact: READ granted and used,
#               WRITE through the READ handle denied, forged/never-issued/
#               zero handles denied, read past the grant denied, exits 0
#      P25EXEC  admitted, runs from the exact authenticated bytes, exits 0
#      P25WX    admitted, killed by a W^X permission fault on its code page
#      P25SPIN  admitted, killed when its admitted time budget runs out
#      P25TAMP  one payload byte flipped after signing: rejected BadSignature
#      H01..H29 negative matrix (aienos-artifact-tool negative-corpus): each
#               refused at its expected stage with its stable reason, or
#               admitted and contained with its expected outcome
#   2. ordinary build (empty production trust set): every candidate refused;
#      production trust fails closed.
#
# Every candidate must be reclaimed (all frames returned, no live
# capabilities) and emits an unsigned Admission Receipt v0; the host checks
# each binds the artifact it supplied and its observed outcome, matches the
# kernel digest, signs it with the TEST ONLY SEED-0B receipt key and
# verifies it. Canonical markers (ARTIFACT_*, SEED0B_*, ADMISSION_RECEIPT,
# HOSTILE_MATRIX, SEED_0B_QEMU) summarise the claims; each passes only if
# every check tagged with it passed. AIENOS_SEED0B_EVIDENCE=<file> writes
# the evidence record. No physical hardware is touched.
#
# Captured-log mode (P2-9, Machine 1): AIENOS_SEED0B_SERIAL=<console log>
# with AIENOS_SEED0B_INPUTS=<dir from scripts/seed0b_machine1_prepare.sh>
# skips both QEMU boots, proves the staged inputs are byte-identical to a
# fresh deterministic pack and to their MANIFEST.sha256, that the inputs, the
# log and this clean checkout share one commit, that the log shows Machine 1's
# CPU identity, and applies the qualification-boot checks to the captured log
# with the SEED-0B-MACHINE1 tier (marker SEED_0B_MACHINE1).
#
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
captured="${AIENOS_SEED0B_SERIAL:-}"
if [[ -n "${captured}" ]]; then
    [[ -r "${captured}" ]] || { echo "captured console log not readable: ${captured}"; exit 2; }
    [[ -d "${AIENOS_SEED0B_INPUTS:-}" ]] || { echo "AIENOS_SEED0B_INPUTS must name the prepared inputs directory"; exit 2; }
    tier_label=SEED-0B-MACHINE1
    final_marker=SEED_0B_MACHINE1
else
    command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
    [[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }
    tier_label=SEED-0B-QEMU
    final_marker=SEED_0B_QEMU
fi

fixtures="crates/aienos-artifact-tool/fixtures/p2_5"
seed_fixtures="crates/aienos-artifact-tool/fixtures/p2_6"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
failed=0

# ---- claim categories -------------------------------------------------------
CATEGORIES=(ARTIFACT_PARSE ARTIFACT_IDENTITY ARTIFACT_SIGNATURE ARTIFACT_ADMISSION
    ARTIFACT_LOADED_BYTES ARTIFACT_WX SEED0B_AUTHORIZED_READ SEED0B_WRITE_DENIED
    SEED0B_FORGED_DENIED SEED0B_RESOURCE_BOUND SEED0B_CLEANUP ADMISSION_RECEIPT HOSTILE_MATRIX)
declare -A seen=() bad=()
cats=""   # categories the next checks count toward
rtag=""   # which boot the next receipt files belong to
pass() {
    echo "PASS  $1"
    local c
    for c in ${cats}; do seen[$c]=1; done
}
fail() {
    echo "FAIL  $1"
    failed=1
    local c
    for c in ${cats}; do bad[$c]=1; done
}

# ---- inputs -----------------------------------------------------------------
# The committed probe bytes are the qualification inputs. When an assembler
# is available, prove they are exactly what probe.S assembles to.
as_bin=as
[[ "$(uname -m)" == "aarch64" ]] || as_bin=aarch64-linux-gnu-as
if command -v "${as_bin}" >/dev/null; then
    "${fixtures}/assemble.sh" "${work}/asm"
    "${seed_fixtures}/assemble.sh" "${work}/asm"
    for pair in "${fixtures}:p25exec" "${fixtures}:p25wx" "${fixtures}:p25spin" "${seed_fixtures}:p26seed"; do
        dir=${pair%%:*} probe=${pair##*:}
        if cmp -s "${work}/asm/${probe}/code.bin" "${dir}/${probe}/code.bin"; then
            pass "${probe} code.bin is exactly what probe.S assembles to"
        else
            fail "${probe} code.bin differs from probe.S"
        fi
    done
else
    echo "NOTE  no AArch64 assembler; using committed probe bytes unchecked"
fi

# Test-only signing: debug build by design (release refuses the feature).
cargo build --quiet -p aienos-artifact-tool --features seed0b-test-signing
tool="target/debug/aienos-artifact-tool"
esp_art="${work}/esp/EFI/AIENOS/ARTIFACTS"
mkdir -p "${work}/esp/EFI/BOOT" "${esp_art}"
"${fixtures}/pack.sh" "${tool}" "${esp_art}"
"${seed_fixtures}/pack.sh" "${tool}" "${esp_art}"
"${tool}" negative-corpus "${esp_art}" >/dev/null
mv "${esp_art}/ids.txt" "${work}/ids.txt"
mv "${esp_art}/expected.txt" "${work}/expected.txt"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
for f in "${esp_art}"/H*.AIEN; do
    n=$(basename "${f}")
    awk -v n="${n}" '$1 == n { found = 1 } END { exit !found }' "${work}/ids.txt" || echo "${n} $("${tool}" id "${f}" 2>/dev/null || echo none)" >>"${work}/ids.txt"
done
candidate_count=$(find "${esp_art}" -maxdepth 1 -name '*.AIEN' | wc -l)
if [[ -n "${captured}" ]]; then
    cats="ARTIFACT_IDENTITY"
    staged="${AIENOS_SEED0B_INPUTS}/ARTIFACTS"
    if [[ ! -d "${staged}" ]]; then
        echo "FAIL  ${staged} is not a directory (AIENOS_SEED0B_INPUTS must be the prepared inputs root)"
        echo "SEED_0B_MACHINE1: FAIL"
        exit 1
    fi
    staged_count=$(find "${staged}" -maxdepth 1 -name '*.AIEN' | wc -l)
    [[ "${staged_count}" == "${candidate_count}" ]] || fail "staged ${staged_count} candidates, expected ${candidate_count}"
    for f in "${esp_art}"/*.AIEN; do
        n=$(basename "${f}")
        if cmp -s "${f}" "${staged}/${n}"; then
            pass "staged ${n} is byte-identical to the deterministic pack"
        else
            fail "staged ${n} differs from the deterministic pack"
        fi
    done

    # Bind log -> inputs -> this checkout, and log -> Machine 1. A captured log
    # is operator-attested (TRUST-1 adds measured boot); these checks stop the
    # honest mix-ups: a log from another commit, other inputs, or QEMU.
    manifest="${AIENOS_SEED0B_INPUTS}/MANIFEST.sha256"
    inputs_commit=""
    if [[ ! -r "${manifest}" ]]; then
        fail "prepared inputs carry MANIFEST.sha256"
    else
        if (cd "${AIENOS_SEED0B_INPUTS}" && grep -v '^#' MANIFEST.sha256 | sha256sum --check --strict --quiet); then
            pass "staged inputs match MANIFEST.sha256"
        else
            fail "staged inputs do not match MANIFEST.sha256"
        fi
        listed=$(grep -vc '^#' "${manifest}" || true)
        present=$(cd "${AIENOS_SEED0B_INPUTS}" && find . -type f ! -name MANIFEST.sha256 | wc -l)
        if [[ "${listed}" == "${present}" ]]; then
            pass "MANIFEST.sha256 lists every staged file (${present})"
        else
            fail "MANIFEST.sha256 lists ${listed} files but ${present} are staged"
        fi
        inputs_commit=$(sed -n 's/^# commit \([0-9a-f]\{40\}\)$/\1/p' "${manifest}")
    fi
    head_commit=$(git rev-parse HEAD)
    if [[ -n "${inputs_commit}" && "${inputs_commit}" == "${head_commit}" ]]; then
        pass "inputs were prepared from this checkout's commit ${head_commit}"
    else
        fail "inputs commit '${inputs_commit}' is not this checkout's HEAD ${head_commit}"
    fi
    if [[ -z "$(git status --porcelain)" ]]; then
        pass "checkout is clean"
    else
        fail "checkout has uncommitted changes"
    fi
    log_commit=$(tr -d '\r' <"${captured}" | sed -n 's/^aienos_commit: //p' | sort -u)
    if [[ -n "${inputs_commit}" && "${log_commit}" == "${inputs_commit}" ]]; then
        pass "captured log was produced by the prepared image's commit"
    else
        fail "captured log commit '${log_commit}' is not the inputs commit '${inputs_commit}'"
    fi
    # Machine 1 CPU identity (evidence/m2_first_boot_2026-09-24.md): 20 cores,
    # boot core Cortex-A725 (part 0xd87) or Cortex-X925 (0xd85).
    if tr -d '\r' <"${captured}" | grep -q '^cpu_cores: 20$' && \
       tr -d '\r' <"${captured}" | grep -qE '^boot_cpu_midr: 0x[0-9a-f]+ \(part 0xd8[57]\)$'; then
        pass "captured log shows Machine 1 CPU identity (20 cores, A725/X925 boot core)"
    else
        fail "captured log does not show Machine 1 CPU identity; a QEMU log cannot qualify Machine 1"
    fi
    cats=""
fi
id_prefix() { # name -> first 16 hex digits of its ArtifactId
    awk -v n="$1" '$1 == n { print substr($2, 1, 16) }' "${work}/ids.txt"
}

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
build_image() { # features, output
    AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
        -p aienos-boot --target aarch64-unknown-uefi --features "$1" --bin aienos-handoff
    cp target/aarch64-unknown-uefi/release/aienos-handoff.efi "$2"
}
if [[ -z "${captured}" ]]; then
    build_image seed0b-qualification "${work}/qualification.efi"
    build_image handoff "${work}/production.efi"
fi

boot() { # image, serial text output
    cp "$1" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    local log="${work}/serial.log" started status
    started=$(date +%s)
    set +e
    # Issue #61: single-threaded TCG; MTTCG hung in 1/40 soak boots.
    timeout "${AIENOS_QEMU_TIMEOUT:-300}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -device ramfb -display none -nic none \
        -serial file:"${log}" -no-reboot
    status=$?
    set -e
    tr -d '\r' <"${log}" >"$2"
    echo "qemu exit ${status} after $(( $(date +%s) - started )) s (commit ${commit:0:12})"
    [[ "${status}" != 124 ]] || { cats=""; fail "QEMU timed out (no reset)"; }
}

has() { grep -qE -- "$2" "$1"; }
check() { # serial, description, extended regex
    if has "$1" "$3"; then pass "$2"; else fail "$2"; fi
}
common_checks() { # serial
    cats=""
    check "$1" "left firmware and entered the kernel" "kernel: alive"
    check "$1" "M3 cooperative threads unchanged" "threads: ok"
    check "$1" "M3 EL0 isolation proof unchanged" "el0: ok write=granted forged=denied fault=contained exit=0"
    check "$1" "M3 typed IPC proof unchanged" "ipc: ok message=delivered cap=delegated rights=attenuated forged=denied revoked=denied"
    check "$1" "firmware read all ${candidate_count} artifact candidates" "^artifact_candidates: ${candidate_count}$"
    if grep -q "^report-truncated:" "$1"; then
        fail "kernel report lines were truncated: $(grep "^report-truncated:" "$1" | tr '\n' ' ')"
    else
        pass "no kernel report line was truncated"
    fi
    check "$1" "final report reached the console" "report_kind: final"
    if has "$1" "report_kind: (panic|fault)"; then fail "panic or fault reported"; fi
    if has "$1" "^receipt: [^ ]+ seq=[0-9]+ invalid$"; then fail "a candidate produced no valid receipt"; fi
    cats="SEED0B_CLEANUP"
    local before after
    before=$(grep -oE "artifact_frames_free_before: [0-9]+" "$1" | awk '{print $2}' | tail -1)
    after=$(grep -oE "artifact_frames_free_after: [0-9]+" "$1" | awk '{print $2}' | tail -1)
    if [[ -n "${before}" && "${before}" == "${after}" ]]; then
        pass "every frame returned after all candidates (${before} free before and after)"
    else
        fail "frame accounting across candidates (before=${before:-?} after=${after:-?})"
    fi
    cats=""
}

# receipt_check SERIAL NAME PATTERN: the kernel's unsigned receipt for NAME
# must decode, bind the supplied artifact, match PATTERN, carry the digest
# the host recomputes, and sign/verify with the TEST ONLY receipt key.
receipt_check() {
    local serial="$1" name="$2" want="$3" line record kdigest out
    line=$(grep -E "^receipt: ${name//./\\.} seq=[0-9]+ digest=[0-9a-f]{64} record=[0-9a-f]{1024}$" "${serial}" | tail -1 || true)
    if [[ -z "${line}" ]]; then
        fail "${name} receipt emitted"
        return
    fi
    record=${line##*record=}
    kdigest=$(sed -E 's/.* digest=([0-9a-f]{64}) .*/\1/' <<<"${line}")
    local file="${work}/${rtag}-${name}.receipt"
    "${tool}" receipt from-hex "${record}" "${file}" >/dev/null
    if ! out=$("${tool}" receipt check "${file}" "${esp_art}/${name}" 2>&1); then
        fail "${name} receipt binds the supplied artifact (${out})"
        return
    fi
    if [[ "${out}" != *"digest=${kdigest} "* ]]; then
        fail "${name} receipt digest recomputed by the host"
        return
    fi
    if ! grep -qE -- "${want}" <<<"${out}"; then
        fail "${name} receipt records the observed outcome (${out})"
        return
    fi
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
# Categories a negative-matrix case supports beyond HOSTILE_MATRIX.
case_cats() {
    case "$1" in
        H0[1-9]-*|H10-*|H17-*|H18-*|H19-*|H20-*) echo "ARTIFACT_PARSE";;
        H1[1-6]-*) echo "ARTIFACT_SIGNATURE";;
        H21-*) echo "ARTIFACT_LOADED_BYTES ARTIFACT_IDENTITY";;
        H22-*|H23-*|H24-*) echo "ARTIFACT_WX";;
        H25-*|H26-*) echo "SEED0B_RESOURCE_BOUND";;
        H27-*|H28-*|H29-*) echo "ARTIFACT_ADMISSION";;
    esac
}

# ---- boot 1: qualification build -------------------------------------------
qual="${work}/qualification.txt"
rtag=qual
if [[ -n "${captured}" ]]; then
    tr -d '\r' <"${captured}" >"${qual}"
else
    boot "${work}/qualification.efi" "${qual}"
fi
common_checks "${qual}"
check "${qual}" "qualification build is labelled TEST ONLY" \
    "artifact_trust: seed0b-test qualification build — TEST ONLY"
check "${qual}" "receipts carry the ${tier_label} tier" "^artifact_receipt_tier: ${tier_label}$"

admitted_line() { # name, exec regex, caps -> regex for an admitted, reclaimed candidate
    echo "^artifact: ${1//./\\.} admitted id=$(id_prefix "$1") tier=seed0b-test exec=$2 bytes=identified=verified=admitted=mapped=executed wx=enforced caps=$3 revoked=yes reclaimed=yes frames=[0-9]+ "
}

cats="SEED0B_AUTHORIZED_READ SEED0B_WRITE_DENIED SEED0B_FORGED_DENIED ARTIFACT_IDENTITY ARTIFACT_ADMISSION ARTIFACT_LOADED_BYTES ARTIFACT_WX SEED0B_CLEANUP"
check "${qual}" "P26SEED (first SEED-0B capability artifact) read through its grant, WRITE and forged authority denied, exit 0, reclaimed" \
    "$(admitted_line P26SEED.AIEN exited:0x0 1)syscalls=9 reads=3 denials=5$"
cats="ARTIFACT_ADMISSION"
check "${qual}" "P26SEED granted exactly its READ request (granted ⊆ requested)" \
    "^grant: P26SEED\.AIEN\[0\] kind=object id=1 rights=0x1 bounds=0\+32 max_ops=4 max_bytes=32$"
if [[ $(grep -c "^grant: P26SEED\.AIEN\[" "${qual}") == 1 ]]; then pass "P26SEED holds exactly one capability"; else fail "P26SEED holds exactly one capability"; fi
cats="ADMISSION_RECEIPT SEED0B_AUTHORIZED_READ SEED0B_WRITE_DENIED SEED0B_FORGED_DENIED"
receipt_check "${qual}" P26SEED.AIEN "decision=Admitted tier=${tier_label} stage=0 reason=0x0 status=Exited exit=0 syscalls=9 reads_ok=3 denials=5 flags=0xff$"

cats="ARTIFACT_IDENTITY ARTIFACT_LOADED_BYTES SEED0B_CLEANUP"
check "${qual}" "P25EXEC admitted and executed its exact authenticated bytes, exit 0, caps revoked, reclaimed" \
    "$(admitted_line P25EXEC.AIEN exited:0x0 1)syscalls=3 reads=1 denials=1$"
cats="ARTIFACT_WX SEED0B_CLEANUP"
check "${qual}" "P25WX admitted then killed by W^X fault on its code page, reclaimed" \
    "$(admitted_line P25WX.AIEN fault:code-write 0)syscalls=0 reads=0 denials=0$"
cats="SEED0B_RESOURCE_BOUND SEED0B_CLEANUP"
check "${qual}" "P25SPIN admitted then killed at its time budget, reclaimed" \
    "$(admitted_line P25SPIN.AIEN timeout 0)syscalls=0 reads=0 denials=0$"
cats="ARTIFACT_SIGNATURE SEED0B_CLEANUP"
check "${qual}" "P25TAMP (payload byte flipped after signing) rejected BadSignature, reclaimed" \
    "^artifact: P25TAMP\.AIEN rejected stage=verified reason=BadSignature reclaimed=yes$"
cats="ADMISSION_RECEIPT"
receipt_check "${qual}" P25EXEC.AIEN "decision=Admitted .* status=Exited exit=0 syscalls=3 reads_ok=1 denials=1 flags=0xfd$"
receipt_check "${qual}" P25WX.AIEN "decision=Admitted .* status=Fault exit=0 syscalls=0 reads_ok=0 denials=0 flags=0xe4$"
receipt_check "${qual}" P25SPIN.AIEN "decision=Admitted .* status=Timeout exit=0 syscalls=0 reads_ok=0 denials=0 flags=0xe4$"
receipt_check "${qual}" P25TAMP.AIEN "decision=Rejected .* stage=3 reason=0x12 status=NotRun exit=0 syscalls=0 reads_ok=0 denials=0 flags=0x04$"

matrix_total=0 matrix_admitted=0
while read -r name decision a b c _; do
    [[ -n "${name}" ]] || continue
    matrix_total=$((matrix_total + 1))
    cats="HOSTILE_MATRIX SEED0B_CLEANUP $(case_cats "${name}")"
    if [[ "${decision}" == rejected ]]; then
        check "${qual}" "${name} refused at ${a} (${b}), never ran, reclaimed" \
            "^artifact: ${name//./\\.} rejected stage=${a} reason=${b} reclaimed=yes$"
        cats="HOSTILE_MATRIX ADMISSION_RECEIPT"
        receipt_check "${qual}" "${name}" "decision=Rejected .* stage=$(stage_code "${a}") reason=${c} status=NotRun exit=0 syscalls=0 reads_ok=0 denials=0 flags=0x04$"
    else
        matrix_admitted=$((matrix_admitted + 1))
        check "${qual}" "${name} admitted and contained (${a}), reclaimed" "$(admitted_line "${name}" "${a}" "${b}")"
        cats="HOSTILE_MATRIX ADMISSION_RECEIPT"
        receipt_check "${qual}" "${name}" "decision=Admitted .* status=$(status_of "${a}") "
    fi
done < <(sed 's/ #.*//' "${work}/expected.txt")
cats="ARTIFACT_ADMISSION HOSTILE_MATRIX"
check "${qual}" "H29 requested READ|WRITE and was granted READ only" \
    "^grant: H29-READ-WRITE-REQUEST\.AIEN\[0\] kind=object id=1 rights=0x1 "
if has "${qual}" "^grant: H28-"; then fail "H28 (WRITE-only request) received a capability"; else pass "H28 requested only WRITE and received no capability"; fi
cats=""
check "${qual}" "final report summarises every admission decision" \
    "artifacts: candidates=${candidate_count} admitted=$((4 + matrix_admitted)) rejected=$((1 + matrix_total - matrix_admitted))"

# ---- boot 2: ordinary build, empty production trust -------------------------
prod="${work}/production.txt"
rtag=prod
if [[ -z "${captured}" ]]; then
boot "${work}/production.efi" "${prod}"
common_checks "${prod}"
cats="ARTIFACT_SIGNATURE"
if has "${prod}" "seed0b-test qualification build"; then
    fail "ordinary build must not carry the qualification label"
fi
if has "${prod}" "^artifact: [^ ]+ admitted"; then
    fail "ordinary build admitted an artifact"
else
    pass "ordinary build admitted nothing"
fi
prod_expect() { # name -> "stage reason code" in the ordinary build
    local line
    line=$(sed 's/ #.*//' "${work}/expected.txt" | awk -v n="$1" '$1 == n')
    if [[ -n "${line}" ]] && read -r _ d s r c <<<"${line}" && [[ "${d}" == rejected && "${s}" == verified \
        && "${r}" != BadSignature && "${r}" != UntrustedSigner ]]; then
        echo "${s} ${r} ${c}"   # structural refusal precedes any trust decision
    else
        echo "verified UntrustedSigner 0x11"
    fi
}
for f in "${esp_art}"/*.AIEN; do
    name=$(basename "${f}")
    read -r s r c <<<"$(prod_expect "${name}")"
    cats="ARTIFACT_SIGNATURE SEED0B_CLEANUP"
    check "${prod}" "ordinary build refuses ${name} (${r}), reclaimed" \
        "^artifact: ${name//./\\.} rejected stage=${s} reason=${r} reclaimed=yes$"
    cats="ADMISSION_RECEIPT"
    receipt_check "${prod}" "${name}" "decision=Rejected .* stage=$(stage_code "${s}") reason=${c} status=NotRun .* flags=0x04$"
done
cats=""
check "${prod}" "final report summarises zero admitted" \
    "artifacts: candidates=${candidate_count} admitted=0 rejected=${candidate_count}"
fi

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then
    cp "${qual}" "${AIENOS_LOG_DIR}/qemu_artifact_qualification_serial.log"
    [[ -n "${captured}" ]] || cp "${prod}" "${AIENOS_LOG_DIR}/qemu_artifact_production_serial.log"
fi

# ---- canonical markers -----------------------------------------------------
markers=""
all_ok=1
for c in "${CATEGORIES[@]}"; do
    if [[ -n "${seen[$c]:-}" && -z "${bad[$c]:-}" ]]; then
        markers+="${c}: PASS"$'\n'
    else
        markers+="${c}: FAIL"$'\n'
        all_ok=0
    fi
done
[[ "${failed}" == 0 ]] || all_ok=0
if [[ "${all_ok}" == 1 ]]; then markers+="${final_marker}: PASS"; else markers+="${final_marker}: FAIL"; fi
echo "${markers}"

# ---- evidence record ---------------------------------------------------------
# Key fields of a candidate's report line (decision, outcome, W^X, caps,
# cleanup and counters), without the ArtifactId prefix.
observed() {
    grep -E "^artifact: ${1//./\\.} " "${qual}" | sed -E \
        -e 's/^artifact: [^ ]+ //' -e 's/ id=[0-9a-f]+ tier=[a-z0-9-]+//' \
        -e 's/bytes=identified=verified=admitted=mapped=executed/bytes=match/'
}
if [[ -n "${AIENOS_SEED0B_EVIDENCE:-}" ]]; then
    seed="${esp_art}/P26SEED.AIEN"
    seed_receipt="${work}/qual-P26SEED.AIEN.receipt"
    {
        if [[ -n "${captured}" ]]; then
            echo "# SEED-0B Machine 1 qualification evidence (captured console log)"
            echo
            echo "> TEST-ONLY SEED-0B qualification on Machine 1, checked from a captured console"
            echo "> log. The artifact and receipt keys are RFC 8032 test vectors (TEST 1 artifact"
            echo "> signer, TEST 2 receipt signer). This is not a production identity ceremony."
        else
            echo "# SEED-0B QEMU qualification evidence"
            echo
            echo "> TEST-ONLY SEED-0B qualification in QEMU. The artifact and receipt keys are"
            echo "> RFC 8032 test vectors (TEST 1 artifact signer, TEST 2 receipt signer)."
            echo "> This is not a production identity ceremony and not Machine 1 qualification."
        fi
        echo
        echo "Generated by \`scripts/qemu_artifact_test.sh\` on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
        echo
        echo "## Build and platform"
        echo
        echo '```text'
        echo "git_commit: ${commit}"
        echo "worktree_clean: $([[ -z "$(git status --porcelain 2>/dev/null)" ]] && echo yes || echo no)"
        echo "rustc: $(rustc -V)"
        echo "cargo: $(cargo -V)"
        if [[ -z "${captured}" ]]; then
            echo "qemu: $(qemu-system-aarch64 --version | head -1)"
            echo "qemu_machine: virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048"
            echo "aavmf_code: ${code_fd} sha256=$(sha256sum "${code_fd}" | cut -d' ' -f1)"
            echo "images: aienos-handoff.efi --features seed0b-qualification (boot 1), --features handoff (boot 2)"
        else
            echo "platform: Machine 1 (captured console log)"
            echo "image: aienos-handoff.efi --features seed0b-qualification,hardware-staging (see inputs MANIFEST.sha256)"
        fi
        echo "host: $(uname -srm)"
        echo '```'
        echo
        echo "## Canonical markers"
        echo
        echo '```text'
        echo "${markers}"
        echo '```'
        echo
        echo "## SEED-0B artifact: P26SEED.AIEN"
        echo
        echo '```text'
        echo "file_sha256: $(sha256sum "${seed}" | cut -d' ' -f1)"
        "${tool}" verify "${seed}" | sed 's/^/verify: /'
        "${tool}" inspect "${seed}" | grep -E "^(capability\[|resource_envelope:)" | sed 's/^/requested: /'
        grep -E "^grant: P26SEED\.AIEN" "${qual}" | sed 's/^/granted: /'
        grep -E "^artifact_(policy_digest|verifier_identity|receipt_tier|frames_free_(before|after)):" "${qual}"
        grep -E "^artifact: P26SEED\.AIEN " "${qual}"
        echo '```'
        echo
        echo "Expected allowed operation: \`OBJECT_READ\` through the granted handle at offsets 0 and 24 (and 0 again after the denied write)."
        echo "Expected denied operations: \`OBJECT_WRITE\` through the READ-only handle; \`OBJECT_READ\` with a forged-generation handle, a never-issued slot, the zero handle, and at offset 32 outside the grant."
        echo "Observed: exit 0 (every expectation met), 9 syscalls, 3 successful reads, 5 denials; capability revoked; every frame reclaimed."
        echo
        echo "## Admission receipt (P26SEED.AIEN)"
        echo
        echo '```text'
        grep -E "^receipt: P26SEED\.AIEN " "${qual}" | sed -E 's/ record=([0-9a-f]{64}).*/ record=\1…/'
        "${tool}" receipt inspect "${seed_receipt}"
        "${tool}" receipt verify "${seed_receipt}.signed"
        echo '```'
        echo
        echo "## Matrix (qualification boot)"
        echo
        echo "\`bytes=match\` abbreviates identified = verified = admitted = mapped = executed bytes."
        echo
        echo "| Candidate | Expected | Observed |"
        echo "|---|---|---|"
        for n in P26SEED.AIEN P25EXEC.AIEN P25WX.AIEN P25SPIN.AIEN P25TAMP.AIEN; do
            echo "| ${n} | see above | \`$(observed "${n}")\` |"
        done
        while IFS= read -r l; do
            n=${l%% *}
            what=${l#*# }
            exp=$(sed 's/ #.*//' <<<"${l}" | cut -d' ' -f2-)
            obs=$(observed "${n}")
            echo "| ${n} (${what//|/\\|}) | ${exp} | \`${obs//|/\\|}\` |"
        done <"${work}/expected.txt"
        echo
        if [[ -z "${captured}" ]]; then
            echo "Ordinary build: all ${candidate_count} candidates refused (structural reasons unchanged, all others UntrustedSigner), each reclaimed with a verified receipt."
        else
            echo "Captured log: ${captured} (sha256 $(sha256sum "${captured}" | cut -d' ' -f1)); staged inputs byte-identical to the deterministic pack."
        fi
        echo
        echo "Covered by host tests rather than QEMU (not inducible from outside the kernel): mapped-byte mismatch after copy, frame/shadow/scheduler reservation failure, writable code alias (W^X audit), executed-byte change."
    } >"${AIENOS_SEED0B_EVIDENCE}"
    echo "evidence written: ${AIENOS_SEED0B_EVIDENCE}"
fi

if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console: qualification build ----"
    cat "${qual}"
    if [[ -z "${captured}" ]]; then
        echo "---- serial console: ordinary build ----"
        cat "${prod}"
    fi
fi
[[ "${failed}" == 0 && "${all_ok}" == 1 ]] && echo "QEMU_ARTIFACT: PASS" || { echo "QEMU_ARTIFACT: FAIL"; exit 1; }
