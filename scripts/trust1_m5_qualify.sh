#!/usr/bin/env bash
# trust1_m5_qualify.sh: one native qualification entrypoint for TRUST-1 + M5.
#
# It refuses a dirty tree, records the exact commit and the machine it ran on
# (read-only: no sudo, no TPM writes, no efivar or boot-entry writes, no disk
# writes outside its own output folder), runs every software gate that exists
# today, lists every operator/hardware/unimplemented gate as NOT_RUN (never
# PASS) with its blocker class (BLOCKED_OPERATOR, BLOCKED_HARDWARE or
# MISSING_IMPLEMENTATION) as the reason, and writes one JSON receipt named by
# the sha256 of its own content. Verdicts are only PASS, FAIL or NOT_RUN: a
# blocker is the table's reason for not running, never a measured result.
#
# Usage: bash scripts/trust1_m5_qualify.sh [--with-qemu] [--out DIR]
#        bash scripts/trust1_m5_qualify.sh --self-test
#   --with-qemu  also run the QEMU suites (default off). Vetoed (NOT_RUN) while
#                ~/workspace/.spark-quiet exists.
#   --out DIR    where logs and the receipt go (default: a new temp folder
#                outside the tree). DIR may be evidence/: the receipt is the
#                only file the run adds there, written after the dirty-tree
#                re-check, ready to commit.
#   --self-test  fast negative controls of the verdict logic and the
#                dirty-tree refusal; runs no gate and touches no hardware.
#
# Overall verdict: QUALIFIED only if every canonical gate is PASS, otherwise
# NOT_QUALIFIED with the list of gates that are not PASS.
# Exit: 0 no software gate FAILed (NOT_RUN allowed, whatever its blocker),
#       1 at least one software gate FAILed or the run dirtied the tree,
#       2 usage error or dirty tree at start.
set -uo pipefail

# ===========================================================================
# CANONICAL GATE TABLE (the lead edits verdict mapping here)
#
# Fields, separated by '|':
#   id | kind | runner | notrun_rc | marker | description
# kind:
#   software  run now; PASS needs exit 0 AND the marker line in the log
#   cargo     like software, and the log must show N>0 passed, 0 failed
#   auto      like software if the runner's file exists, else NOT_RUN
#             with blocker MISSING_IMPLEMENTATION (being built in parallel)
#   qemu      software, only with --with-qemu and no .spark-quiet; else NOT_RUN
#   operator  NOT_RUN, blocker BLOCKED_OPERATOR; never run, never PASS
#   hardware  NOT_RUN, blocker BLOCKED_HARDWARE; never run, never PASS
#   missing   NOT_RUN, blocker MISSING_IMPLEMENTATION; never run, never PASS
# runner: name of a run_* function below ('-' for none).
# notrun_rc: exit code that means "a tool is missing" -> NOT_RUN ('-' none).
# marker: extended regex that must match a line of the log ('-' for none).
# ===========================================================================
GATE_TABLE='
t1_measurement_tools|software|run_measurement_tools|2|^TRUST-1 measurement tools self-test: ALL PASS$|TRUST-1 Gate 0/2 read-only tools self-test on a software TPM
t1_key_ceremony|software|run_key_ceremony|-|^TRUST-1 key ceremony self-test \(throwaway keys\): ALL PASS$|TRUST-1 Gate 3 key ceremony self-test with throwaway keys
t1_gate7_preflight|software|run_gate7_preflight|-|^GATE7_PREFLIGHT: PASS|TRUST-1 Gate 7 read-only pre-flight (depends on operator state)
t1_recovery_tools|software|run_recovery_tools|-|^RECOVERY_TOOLS: PASS|recovery initrd ships mount, EFI repair and boot-entry restore tools
store_torn_slot_c|software|run_store_c|-|^TORN_SLOT_HOST_EMULATION: PASS|Store C reference torn-write test (host block-device emulation)
store_native_c|software|run_store_c|-|^AIENOS_STORE_NATIVE: PASS$|C twin of the System Store v1 engine + sealed Store (host file-backed; golden vectors byte-identical to Rust)
store_rust_crosscheck|software|run_store_rust_xcheck|2|^STORE_RUST_CROSSCHECK: PASS$|Rust aienos-store-tool opens C-written stores and reads back the same generation and objects (C to Rust direction; NOT_RUN when the Rust tool is not built)
m5_crypto_crate|cargo|run_cargo_crypto|-|^test result: ok\.|cargo test -p aienos-crypto
m5_kernel_crypto_security|cargo|run_cargo_kernel|-|^test result: ok\.|cargo test -p aienos-kernel --lib (crypto:: security::)
t1_gate5_policy_sim|auto|run_gate5_sim|-|^TRUST1_GATE5_POLICY_SIM: PASS$|TRUST-1 Gate 5 policy simulator self-test
m5_native_test|auto|run_native_m5|-|^M5_NATIVE: PASS$|make -C native/m5 test
crypto_native_test|auto|run_native_crypto|-|^AIENOS_CRYPTO_NATIVE: PASS$|make -C native/crypto test
disk_native_test|auto|run_native_disk|-|^AIENOS_DISK_NATIVE: PASS$|make -C native/disk test (block layer + C NVMe driver vs a software controller model, host only)
qemu_secureboot_signing|qemu|run_qemu_sb|-|^TRUST-1 Gate 4 Secure Boot signing test: ALL PASS$|QEMU Secure Boot signing test (TRUST-1 Gate 4)
qemu_store_512b_crash|qemu|run_qemu_store512|-|^STORE_512B_CRASH_RECOVERY_QEMU: PASS$|QEMU Store crash recovery on 512-byte blocks
qemu_native_nvme|qemu|run_qemu_native_nvme|-|^AIENOS_STORE_NVME_QEMU: PASS$|C NVMe driver write/flush/reset/read-back on QEMU virtual NVMe (emulator only)
ck_m1_boot_qemu|qemu|run_qemu_ck_boot|3|^AIENOS_CK_M1: PASS( .*)?$|C kernel (native/boot + native/kernel, Lane 18) UEFI boot observables on QEMU, scripts/qemu_ck_boot_test.sh (emulator only)
ck_store_kernel_qemu|qemu|run_qemu_ck_store|3|^AIENOS_CK_M4_STORE: PASS( .*)?$|sealed C Store (native/store + native/m5, TEST keys) in the C kernel boot path on QEMU virtual NVMe, DMA confined by the emulated SMMU, scripts/qemu_ck_store_test.sh (emulator only; not a real device, not real keys)
ck_argus1_revoke_qemu|qemu|run_qemu_ck_argus|3|^AIENOS_CK_ARGUS1_REVOKE: PASS( .*)?$|ARGUS-1 narrow revoke inside the C kernel on QEMU, scripts/qemu_ck_store_test.sh (emulator only)
t1_gate0_second_offline_location|operator|-|-|-|Gate 0: second offline backup location
t1_gate0_cold_boot_pcr_stability|hardware|-|-|-|Gate 0: cold-boot PCR stability on Machine 1
t1_gate0_firmware_refresh_pause|operator|-|-|-|Gate 0: firmware refresh paused
t1_gate1_attended_recovery_boot|operator|-|-|-|Gate 1: attended recovery-stick boot
t1_gate2_reboot_campaign|hardware|-|-|-|Gate 2: reboot measurement campaign
t1_gate3_offline_key_ceremony|operator|-|-|-|Gate 3: offline owner key ceremony
t1_gate6|operator|-|-|-|Gate 6 (attended)
t1_gate7|hardware|-|-|-|Gate 7: attended owner-key enrollment boot, checkpoints A-E
t1_gate8|operator|-|-|-|Gate 8 (attended)
t1_gate9|operator|-|-|-|Gate 9 (attended)
m5_sealed_volume_keys_real_tpm|missing|-|-|-|M5: sealed volume keys bound to a real TPM
m5_store_encrypted_objects|software|run_store_c|-|^STORE_SEALED: PASS$|M5: encrypted objects in the C sealed Store (host file-backed only; not QEMU, not Machine 1)
m5_store_kernel_binding|missing|-|-|-|M5: sealed C Store bound into the kernel boot path on a real device with real keys (the QEMU binding with TEST keys is row ck_store_kernel_qemu; it does not count here)
m5_owner_signed_chain_machine1|missing|-|-|-|M5: owner-signed trust chain on Machine 1
m5_production_store_512b|missing|-|-|-|M5: production Store on 512-byte geometry on Machine 1 (C engine native/store + C NVMe driver native/disk are host/QEMU tested and the C kernel loads the Store in QEMU with TEST keys; no real-device run, not qualified on Machine 1)
t1_gate4_manifest_ab|missing|-|-|-|Gate 4: signed boot manifest + A/B slot selection in the loader (awaits the C/asm loader)
m5_migration_sig_test_key|auto|run_native_m5_migsig|-|^AIENOS_M5_MIGRATION_SIG: PASS$|M5: owner-signed migration record (native/m5 + native/sig Ed25519), host test with TEST keys only
m5_migration_owner_signature|operator|-|-|-|M5: migration signed by the real owner key (needs the Gate 3 offline key ceremony)
'
# ===========================================================================

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUIET_FLAG="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"

die() { echo "trust1_m5_qualify: $*" >&2; exit 2; }
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/}"; s="${s//$'\n'/\\n}"
    printf '"%s"' "$(printf '%s' "${s}" | tr -d '\000-\010\013\014\016-\037')"
}
sha_of() { sha256sum | cut -d' ' -f1; }

# ---------------------------------------------------------------- dirty tree
tree_state() { git -C "$1" status --porcelain --untracked-files=normal; }
refuse_if_dirty() {
    local st; st="$(tree_state "$1")" || die "git status failed in $1"
    if [[ -n "${st}" ]]; then
        echo "trust1_m5_qualify: refusing to run on a dirty tree. Commit, stash or remove these first:" >&2
        printf '%s\n' "${st}" >&2
        exit 2
    fi
}

# --------------------------------------------------------------- gate runners
# Each runner writes everything to stdout/stderr; the caller logs it.
run_measurement_tools() { bash "${repo_root}/scripts/test_trust1_measurement_tools.sh"; }
run_key_ceremony()      { bash "${repo_root}/scripts/test_trust1_key_ceremony.sh"; }
run_gate7_preflight()   { bash "${repo_root}/scripts/trust1_gate7_preflight.sh"; }
run_recovery_tools()    { bash "${repo_root}/scripts/verify_recovery_tools.sh"; }
# The native Makefiles run ./$(TEST), so OUT must be relative to the
# Makefile folder; it still points outside the tree.
native_make_test() {
    local dir="${repo_root}/native/$1" out="${work_dir}/build/$1"
    mkdir -p "${out}"
    make -C "${dir}" OUT="$(realpath --relative-to="${dir}" "${out}")" test
}
run_store_c()           { native_make_test store; }
# Rust cross-check of C-written stores: needs a built aienos-store-tool
# (RUST_STORE_TOOL, else target/release/aienos-store-tool); exit 2 = NOT_RUN.
run_store_rust_xcheck() {
    local dir="${repo_root}/native/store" out="${work_dir}/build/store-xcheck"
    mkdir -p "${out}"
    local rel; rel="$(realpath --relative-to="${dir}" "${out}")"
    make -C "${dir}" OUT="${rel}" "${rel}/store_xcheck" || return 1
    (cd "${dir}" && sh tests/rust_crosscheck.sh "./${rel}/store_xcheck" "${rel}")
}
run_cargo_crypto()      { (cd "${repo_root}" && cargo test -p aienos-crypto); }
run_cargo_kernel()      { (cd "${repo_root}" && cargo test -p aienos-kernel --lib -- crypto:: security::); }
run_gate5_sim()      { bash "${repo_root}/scripts/trust1_gate5_policy_sim.sh" selftest; }
run_native_m5()     { native_make_test m5; }
run_native_crypto() { native_make_test crypto; }
run_native_m5_migsig() { native_make_test m5; }
run_native_disk()   { native_make_test disk; }
run_qemu_native_nvme() { bash "${repo_root}/scripts/qemu_native_nvme_test.sh"; }
run_qemu_sb()       { bash "${repo_root}/scripts/qemu_secureboot_signing_test.sh"; }
run_qemu_store512() { bash "${repo_root}/scripts/qemu_store_512b_crash_test.sh"; }
# C kernel (Lane 18) QEMU scripts take the quiet flag themselves and print
# "AIENOS_CK_<gate>: PASS|FAIL|NOT_RUN". ck_child_gate SCRIPT GATE runs SCRIPT
# once per qualification run (the store script serves two rows) and maps:
# missing script or a NOT_RUN line -> exit 3 (the rows' notrun_rc); two
# different verdict lines -> 1; exit 3 without a NOT_RUN line -> 1; exit 1
# with this gate's PASS line and another gate's FAIL line -> 0 (the marker
# check still needs the PASS line); anything else -> the script's exit.
ck_scripts_dir="${repo_root}/scripts"
ck_child_gate() {
    local script="${ck_scripts_dir}/$1" gate="$2" out rc verdicts
    if [[ ! -f "${script}" ]]; then
        echo "$1 not present at this commit"; echo "AIENOS_CK_${gate}: NOT_RUN"; return 3
    fi
    mkdir -p "${work_dir}/build"
    out="${work_dir}/build/ck_${1%.sh}.out"
    if [[ -f "${out}.rc" ]]; then
        echo "(reusing this run's earlier $1 output)"
    else
        bash "${script}" >"${out}" 2>&1 </dev/null
        echo "$?" >"${out}.rc"
    fi
    cat "${out}"
    rc="$(cat "${out}.rc")"
    verdicts="$(sed -nE "s/^AIENOS_CK_${gate}: (PASS|FAIL|NOT_RUN)( .*)?\$/\\1/p" "${out}" | sort -u)"
    [[ "$(grep -c . <<<"${verdicts}")" -le 1 ]] || { echo "contradictory AIENOS_CK_${gate} lines"; return 1; }
    [[ "${verdicts}" == NOT_RUN ]] && return 3
    [[ "${rc}" == 3 ]] && return 1
    if [[ "${rc}" == 1 && "${verdicts}" == PASS ]] && grep -qE '^AIENOS_CK_[A-Z0-9_]+: FAIL( .*)?$' "${out}"; then
        return 0
    fi
    return "${rc}"
}
run_qemu_ck_boot()  { ck_child_gate qemu_ck_boot_test.sh M1; }
run_qemu_ck_store() { ck_child_gate qemu_ck_store_test.sh M4_STORE; }
run_qemu_ck_argus() { ck_child_gate qemu_ck_store_test.sh ARGUS1_REVOKE; }

# Is the implementation of an 'auto' gate present?
auto_present() {
    case "$1" in
        run_gate5_sim) [[ -f "${repo_root}/scripts/trust1_gate5_policy_sim.sh" ]] ;;
        run_native_m5) [[ -f "${repo_root}/native/m5/Makefile" ]] ;;
        run_native_crypto) [[ -f "${repo_root}/native/crypto/Makefile" ]] ;;
        run_native_m5_migsig) [[ -f "${repo_root}/native/m5/m5_owner_sig.c" ]] ;;
        run_native_disk) [[ -f "${repo_root}/native/disk/Makefile" ]] ;;
        *) declare -F "$1" >/dev/null ;;
    esac
}

# ----------------------------------------------------------- verdict logic
# classify_log KIND RC NOTRUN_RC MARKER LOG -> prints verdict and a reason.
classify_log() {
    local kind="$1" rc="$2" notrun_rc="$3" marker="$4" log="$5"
    if [[ "${notrun_rc}" != "-" && "${rc}" == "${notrun_rc}" ]]; then
        echo "NOT_RUN|exit ${rc}: a required tool is missing"; return
    fi
    if [[ "${rc}" != 0 ]]; then echo "FAIL|exit ${rc}"; return; fi
    if [[ "${marker}" != "-" ]] && ! grep -Eq -- "${marker}" "${log}"; then
        echo "FAIL|exit 0 but expected marker not found"; return
    fi
    if [[ "${kind}" == cargo ]]; then
        # Every 'test result' line must be ok with 0 failed; at least one
        # test must have run in total (a typo'd filter runs 0 tests).
        local passed failed bad
        passed="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' "${log}" | awk '{s+=$1} END {print s+0}')"
        failed="$(sed -n 's/^test result: .*; \([0-9][0-9]*\) failed;.*/\1/p' "${log}" | awk '{s+=$1} END {print s+0}')"
        bad="$(grep -c '^test result: FAILED' "${log}")"
        if [[ "${bad}" != 0 || "${failed}" != 0 ]]; then echo "FAIL|${failed} tests failed"; return; fi
        if [[ "${passed}" -le 0 ]]; then echo "FAIL|0 tests ran (filter matched nothing)"; return; fi
        echo "PASS|${passed} tests passed, 0 failed"; return
    fi
    echo "PASS|exit 0, marker found"
}

# evaluate_gate ID KIND RUNNER NOTRUN_RC MARKER -> appends one row to results.
# Row: id|kind|verdict|reason|log_sha256|log_lines|seconds
evaluate_gate() {
    local id="$1" kind="$2" runner="$3" notrun_rc="$4" marker="$5"
    local verdict reason log="${work_dir}/logs/${id}.log" rc t0 t1 out
    case "${kind}" in
        # Not checked by this script, so the verdict is NOT_RUN. The reason
        # starts with the blocker class from the table; that is the table's
        # claim about why, not a measured result.
        operator) results+=("${id}|${kind}|NOT_RUN|BLOCKED_OPERATOR: needs an attended operator step; this script cannot check it|-|0|0"); return ;;
        hardware) results+=("${id}|${kind}|NOT_RUN|BLOCKED_HARDWARE: needs attended hardware boots on Machine 1; this script cannot check it|-|0|0"); return ;;
        missing)  results+=("${id}|${kind}|NOT_RUN|MISSING_IMPLEMENTATION: the gate table lists no implementation to run|-|0|0"); return ;;
        auto)
            if ! auto_present "${runner}"; then
                results+=("${id}|${kind}|NOT_RUN|MISSING_IMPLEMENTATION: runner file not present at this commit|-|0|0"); return
            fi ;;
        qemu)
            if [[ "${with_qemu}" != 1 ]]; then
                results+=("${id}|${kind}|NOT_RUN|QEMU suites are off (pass --with-qemu)|-|0|0"); return
            fi
            if [[ -e "${QUIET_FLAG}" ]]; then
                results+=("${id}|${kind}|NOT_RUN|quiet flag ${QUIET_FLAG} is up; heavy runs refused|-|0|0"); return
            fi ;;
        software|cargo) ;;
        *) results+=("${id}|${kind}|FAIL|unknown kind in gate table|-|0|0"); return ;;
    esac
    if ! declare -F "${runner}" >/dev/null; then
        results+=("${id}|${kind}|FAIL|runner ${runner} is not defined|-|0|0"); return
    fi
    echo "--- [${id}] running ..." >&2
    t0="$(date +%s)"
    "${runner}" >"${log}" 2>&1 </dev/null
    rc=$?
    t1="$(date +%s)"
    out="$(classify_log "${kind}" "${rc}" "${notrun_rc}" "${marker}" "${log}")"
    verdict="${out%%|*}"; reason="${out#*|}"
    results+=("${id}|${kind}|${verdict}|${reason}|$(sha_of <"${log}")|$(wc -l <"${log}")|$((t1 - t0))")
    echo "--- [${id}] ${verdict} (${reason})" >&2
}

run_table() {
    local line id kind runner notrun_rc marker desc
    while IFS='|' read -r id kind runner notrun_rc marker desc; do
        [[ -n "${id}" ]] || continue
        evaluate_gate "${id}" "${kind}" "${runner}" "${notrun_rc}" "${marker}"
        descs["${id}"]="${desc}"
    done <<<"${GATE_TABLE}"
}

# count_results -> sets n_pass n_fail n_notrun n_blocked n_missing sw_fail
count_results() {
    n_pass=0; n_fail=0; n_notrun=0; n_blocked=0; n_missing=0; sw_fail=0; n_total=0
    local r v why
    for r in "${results[@]}"; do
        IFS='|' read -r _ _ v why _ <<<"${r}"
        if [[ "${v}" == NOT_RUN ]]; then
            case "${why}" in BLOCKED_OPERATOR:*|BLOCKED_HARDWARE:*) v=BLOCKED ;; MISSING_IMPLEMENTATION:*) v=MISSING ;; esac
        fi
        n_total=$((n_total + 1))
        case "${v}" in
            PASS) n_pass=$((n_pass + 1)) ;;
            FAIL) n_fail=$((n_fail + 1)); sw_fail=1 ;;
            NOT_RUN) n_notrun=$((n_notrun + 1)) ;;
            BLOCKED) n_blocked=$((n_blocked + 1)) ;;
            MISSING) n_missing=$((n_missing + 1)) ;;
            *) n_fail=$((n_fail + 1)); sw_fail=1 ;;
        esac
    done
}

# ---------------------------------------------------------- machine identity
# Read-only, never sudo. Anything unreadable is recorded as "not readable".
readf() { [[ -r "$1" ]] && tr -d '\000' <"$1" 2>/dev/null | head -c 256 | tr -d '\n' || echo "not readable"; }
read_hash() { [[ -r "$1" ]] && [[ -s "$1" ]] && sha_of <"$1" || echo "not readable"; }
efivar_byte() {
    local f="${EFIVARS}/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    [[ -r "${f}" ]] || { echo "not readable"; return; }
    od -An -tu1 -j4 -N1 "${f}" | tr -d ' '
}
collect_machine() {
    EFIVARS="${AIENOS_EFIVARS_DIR:-/sys/firmware/efi/efivars}"
    m_host="$(uname -n)"
    m_machine_id_sha="$(read_hash /etc/machine-id)"
    m_product="$(readf /sys/class/dmi/id/product_name)"
    m_board="$(readf /sys/class/dmi/id/board_name)"
    m_serial_sha="$(read_hash /sys/class/dmi/id/product_serial)"
    m_cpu="$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | sort -u | paste -sd';' -)"
    [[ -n "${m_cpu}" ]] || m_cpu="not readable"
    m_kernel="$(uname -r)"
    m_bios_version="$(readf /sys/class/dmi/id/bios_version)"
    m_bios_date="$(readf /sys/class/dmi/id/bios_date)"
    m_sb_efivar="$(efivar_byte SecureBoot)"
    m_setup_mode="$(efivar_byte SetupMode)"
    m_sb_mokutil="$(command -v mokutil >/dev/null && mokutil --sb-state 2>&1 | head -1 || echo "mokutil not installed")"
    # TPM: read-only getcap properties.
    m_tpm_present="no"; m_tpm_mfr="not readable"; m_tpm_vendor="not readable"; m_tpm_fw="not readable"
    if [[ -e /dev/tpmrm0 || -e /dev/tpm0 ]]; then
        m_tpm_present="yes"
        local caps
        if command -v tpm2_getcap >/dev/null && caps="$(tpm2_getcap properties-fixed 2>/dev/null)"; then
            m_tpm_mfr="$(awk '/^TPM2_PT_MANUFACTURER:/{f=1;next} f&&/value:/{gsub(/"/,"",$2);print $2;exit}' <<<"${caps}")"
            m_tpm_vendor="$(awk '/^TPM2_PT_VENDOR_STRING_[1-4]:/{f=1;next} f&&/value:/{gsub(/"/,"",$2);printf "%s",$2;f=0}' <<<"${caps}")"
            m_tpm_fw="$(awk '/^TPM2_PT_FIRMWARE_VERSION_[12]:/{f=1;next} f&&/raw:/{printf "%s%s",(n++?".":""),$2;f=0}' <<<"${caps}")"
        fi
    fi
    # PCR 0-15 sha256, the same read tpm_measurement_campaign.sh uses.
    pcr_lines=()
    local pcrs
    if command -v tpm2_pcrread >/dev/null && pcrs="$(tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 2>/dev/null)"; then
        mapfile -t pcr_lines < <(awk 'match($0, /^ *[0-9]+ *: *0x[0-9A-Fa-f]+/) {
            line=$0; gsub(/[ :]+/," ",line); sub(/^ /,"",line); split(line,f," ");
            printf "%d %s\n", f[1], tolower(substr(f[2],3)) }' <<<"${pcrs}" | sort -n)
    fi
    # Boot disk logical block size: /boot/efi (else /) -> parent disk.
    local src parent
    m_boot_disk="not readable"; m_lbs="not readable"
    src="$(findmnt -no SOURCE /boot/efi 2>/dev/null || findmnt -no SOURCE / 2>/dev/null)"
    if [[ -n "${src}" ]]; then
        parent="$(lsblk -no PKNAME "${src}" 2>/dev/null | head -1)"
        [[ -n "${parent}" ]] || parent="$(basename "${src}")"
        m_boot_disk="${parent}"
        [[ -r "/sys/block/${parent}/queue/logical_block_size" ]] && m_lbs="$(cat "/sys/block/${parent}/queue/logical_block_size")"
    fi
    # Full host capture through the existing tool (read-only). It may fail
    # without root (event log); that is recorded, not hidden.
    m_capture="not run"
    local cap="${work_dir}/host_capture"
    if bash "${repo_root}/scripts/tpm_measurement_campaign.sh" capture "${cap}" trust1_m5_qualify \
            >"${work_dir}/logs/host_capture.log" 2>&1 </dev/null; then
        m_capture="ok $(sed -n 's/^capture_digest=//p' "${work_dir}/logs/host_capture.log")"
    else
        m_capture="failed: $(grep -m1 -iE 'error|die|fail|not' "${work_dir}/logs/host_capture.log" | head -c 200)"
    fi
}

# --------------------------------------------------------------- receipt
write_receipt() {
    local tmp="${work_dir}/receipt.tmp" i r id kind v reason lsha lines secs first blocker
    {
        echo "{"
        echo "  \"schema\": \"aienos.trust1_m5_qualification.v2\","
        echo "  \"started_utc\": $(json_str "${started_utc}"),"
        echo "  \"finished_utc\": $(json_str "$(date -u +%FT%TZ)"),"
        echo "  \"commit\": $(json_str "${head_sha}"),"
        echo "  \"commit_subject\": $(json_str "${head_subject}"),"
        echo "  \"tree_clean_before\": ${tree_clean_before},"
        echo "  \"tree_clean_after\": ${tree_clean_after},"
        echo "  \"with_qemu_requested\": $([[ ${with_qemu} == 1 ]] && echo true || echo false),"
        echo "  \"quiet_flag_present\": $([[ -e ${QUIET_FLAG} ]] && echo true || echo false),"
        echo "  \"machine\": {"
        echo "    \"hostname\": $(json_str "${m_host}"),"
        echo "    \"machine_id_sha256\": $(json_str "${m_machine_id_sha}"),"
        echo "    \"dmi_product\": $(json_str "${m_product}"),"
        echo "    \"dmi_board\": $(json_str "${m_board}"),"
        echo "    \"dmi_serial_sha256\": $(json_str "${m_serial_sha}"),"
        echo "    \"cpu_model\": $(json_str "${m_cpu}"),"
        echo "    \"kernel\": $(json_str "${m_kernel}"),"
        echo "    \"firmware_version\": $(json_str "${m_bios_version}"),"
        echo "    \"firmware_date\": $(json_str "${m_bios_date}"),"
        echo "    \"secure_boot_efivar\": $(json_str "${m_sb_efivar}"),"
        echo "    \"setup_mode_efivar\": $(json_str "${m_setup_mode}"),"
        echo "    \"secure_boot_mokutil\": $(json_str "${m_sb_mokutil}"),"
        echo "    \"tpm_present\": $(json_str "${m_tpm_present}"),"
        echo "    \"tpm_manufacturer\": $(json_str "${m_tpm_mfr}"),"
        echo "    \"tpm_vendor_string\": $(json_str "${m_tpm_vendor}"),"
        echo "    \"tpm_firmware_version_raw\": $(json_str "${m_tpm_fw}"),"
        printf '    "pcr_sha256": {'
        if [[ ${#pcr_lines[@]} -eq 0 ]]; then
            printf '"status": "not readable"'
        else
            first=1
            for r in "${pcr_lines[@]}"; do
                [[ ${first} == 1 ]] || printf ', '
                first=0
                printf '"%s": "%s"' "${r%% *}" "${r#* }"
            done
        fi
        echo "},"
        echo "    \"boot_disk\": $(json_str "${m_boot_disk}"),"
        echo "    \"boot_disk_logical_block_size\": $(json_str "${m_lbs}"),"
        echo "    \"host_capture\": $(json_str "${m_capture}")"
        echo "  },"
        echo "  \"gates\": ["
        for i in "${!results[@]}"; do
            IFS='|' read -r id kind v reason lsha lines secs <<<"${results[$i]}"
            blocker="-"; [[ "${v}" == NOT_RUN && "${reason}" =~ ^(BLOCKED_OPERATOR|BLOCKED_HARDWARE|MISSING_IMPLEMENTATION): ]] && blocker="${BASH_REMATCH[1]}"
            printf '    {"id": %s, "kind": %s, "verdict": %s, "blocker": %s, "reason": %s, "description": %s, "log_sha256": %s, "log_lines": %s, "seconds": %s}' \
                "$(json_str "${id}")" "$(json_str "${kind}")" "$(json_str "${v}")" "$(json_str "${blocker}")" "$(json_str "${reason}")" \
                "$(json_str "${descs[${id}]:-}")" "$(json_str "${lsha}")" "${lines:-0}" "${secs:-0}"
            [[ $i -lt $((${#results[@]} - 1)) ]] && echo "," || echo ""
        done
        echo "  ],"
        echo "  \"counts\": {\"total\": ${n_total}, \"pass\": ${n_pass}, \"fail\": ${n_fail}, \"not_run\": ${n_notrun}, \"blocked\": ${n_blocked}, \"missing\": ${n_missing}},"
        echo "  \"verdict\": $(json_str "${overall}"),"
        printf '  "not_pass": ['
        first=1
        for r in "${not_pass[@]}"; do
            [[ ${first} == 1 ]] || printf ', '
            first=0; printf '%s' "$(json_str "${r}")"
        done
        echo "]"
        echo "}"
    } >"${tmp}"
    receipt_sha="$(sha_of <"${tmp}")"
    receipt_path="${out_dir}/trust1_m5_qualification_${receipt_sha}.json"
    mv "${tmp}" "${receipt_path}"
}

summarize() {
    local r id kind v reason
    not_pass=()
    printf '\n%-36s %-9s %-24s %s\n' GATE KIND VERDICT REASON
    for r in "${results[@]}"; do
        IFS='|' read -r id kind v reason _ <<<"${r}"
        printf '%-36s %-9s %-24s %s\n' "${id}" "${kind}" "${v}" "${reason}"
        [[ "${v}" == PASS ]] || not_pass+=("${id}:${v}")
    done
    count_results
    if [[ ${#not_pass[@]} -eq 0 && ${n_total} -gt 0 ]]; then overall=QUALIFIED; else overall=NOT_QUALIFIED; fi
    echo ""
    echo "Counts: total=${n_total} pass=${n_pass} fail=${n_fail} not_run=${n_notrun} blocked=${n_blocked} missing=${n_missing}"
    echo "Verdict: ${overall}"
}

# ----------------------------------------------------------------- self-test
self_test() {
    local st_fail=0 tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/trust1-m5-selftest.XXXXXX")" || exit 2
    work_dir="${tmp}"; mkdir -p "${work_dir}/logs"
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; st_fail=1; }
    expect() { # expect ID WANTED_VERDICT
        local r v
        for r in "${results[@]}"; do
            IFS='|' read -r id _ v _ <<<"${r}"
            if [[ "${id}" == "$1" ]]; then
                [[ "${v}" == "$2" ]] && ok "$1 -> $2" || bad "$1 -> ${v}, expected $2"
                return
            fi
        done
        bad "$1 has no result row"
    }
    expect_why() { # expect_why ID BLOCKER: the NOT_RUN reason names the blocker class
        local r v why
        for r in "${results[@]}"; do
            IFS='|' read -r id _ v why _ <<<"${r}"
            if [[ "${id}" == "$1" ]]; then
                [[ "${why}" == "$2:"* ]] && ok "$1 reason names $2" || bad "$1 reason '${why}' does not start with $2:"
                return
            fi
        done
        bad "$1 has no result row"
    }
    fake_fail()     { echo "boom"; return 1; }
    fake_nomarker() { echo "all good, honest"; return 0; }
    fake_pass()     { echo "FAKE: ALL PASS"; return 0; }
    fake_missing()  { echo "Error: tool not installed"; return 2; }
    fake_zero()     { printf 'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored\n'; return 0; }
    fake_cargo_ok() { printf 'test result: ok. 7 passed; 0 failed; 0 ignored\ntest result: ok. 0 passed; 0 failed; 0 ignored\n'; return 0; }
    fake_cargo_badrc() { printf 'test result: ok. 3 passed; 0 failed; 0 ignored\n'; return 101; }
    sentinel="${tmp}/ran"
    fake_sentinel() { : >"${sentinel}"; echo "FAKE: ALL PASS"; }
    with_qemu=1; results=()
    local saved_quiet="${QUIET_FLAG}"
    evaluate_gate neg_fail software fake_fail - -
    evaluate_gate neg_nomarker software fake_nomarker - '^FAKE: ALL PASS$'
    evaluate_gate pos_pass software fake_pass - '^FAKE: ALL PASS$'
    evaluate_gate notrun_rc2 software fake_missing 2 -
    evaluate_gate rc2_not_notrun software fake_missing - -
    evaluate_gate cargo_zero cargo fake_zero - '^test result: ok\.'
    evaluate_gate cargo_ok cargo fake_cargo_ok - '^test result: ok\.'
    evaluate_gate cargo_badrc cargo fake_cargo_badrc - '^test result: ok\.'
    evaluate_gate auto_absent auto run_does_not_exist_anywhere - -
    evaluate_gate op_never_pass operator fake_sentinel - -
    evaluate_gate hw_never_pass hardware fake_sentinel - -
    evaluate_gate miss_never_pass missing fake_sentinel - -
    QUIET_FLAG="${tmp}/quiet"; : >"${QUIET_FLAG}"
    evaluate_gate qemu_quiet qemu fake_sentinel - -
    with_qemu=0; rm -f "${QUIET_FLAG}"
    evaluate_gate qemu_off qemu fake_sentinel - -
    QUIET_FLAG="${saved_quiet}"
    expect neg_fail FAIL; expect neg_nomarker FAIL; expect pos_pass PASS
    expect notrun_rc2 NOT_RUN; expect rc2_not_notrun FAIL
    expect cargo_zero FAIL; expect cargo_ok PASS; expect cargo_badrc FAIL
    expect auto_absent NOT_RUN
    expect op_never_pass NOT_RUN; expect hw_never_pass NOT_RUN
    expect miss_never_pass NOT_RUN
    expect_why auto_absent MISSING_IMPLEMENTATION; expect_why miss_never_pass MISSING_IMPLEMENTATION
    expect_why op_never_pass BLOCKED_OPERATOR; expect_why hw_never_pass BLOCKED_HARDWARE
    expect qemu_quiet NOT_RUN; expect qemu_off NOT_RUN
    [[ ! -e "${sentinel}" ]] && ok "blocked/missing/vetoed gates never ran their runner" || bad "a blocked/missing/vetoed runner ran"

    # Counts come only from the table: 2 PASS, 5 FAIL, 3 NOT_RUN, 2 blocked, 2 missing.
    count_results
    [[ "${n_pass}/${n_fail}/${n_notrun}/${n_blocked}/${n_missing}/${n_total}" == "2/5/3/2/2/14" ]] \
        && ok "counts derived from the table (2/5/3/2/2 of 14)" \
        || bad "counts ${n_pass}/${n_fail}/${n_notrun}/${n_blocked}/${n_missing}/${n_total}, expected 2/5/3/2/2/14"
    [[ ${sw_fail} == 1 ]] && ok "a FAIL row sets the failing exit status" || bad "FAIL row did not set sw_fail"

    # Verdict: one non-PASS row is enough for NOT_QUALIFIED; all PASS -> QUALIFIED.
    summarize >/dev/null
    [[ "${overall}" == NOT_QUALIFIED ]] && ok "mixed table -> NOT_QUALIFIED" || bad "mixed table -> ${overall}"
    results=("a|software|PASS|x|-|0|0" "b|cargo|PASS|x|-|0|0")
    summarize >/dev/null
    [[ "${overall}" == QUALIFIED ]] && ok "all-PASS table -> QUALIFIED" || bad "all-PASS table -> ${overall}"
    results=("a|software|PASS|x|-|0|0" "b|operator|NOT_RUN|BLOCKED_OPERATOR: x|-|0|0")
    summarize >/dev/null
    count_results
    [[ "${overall}" == NOT_QUALIFIED && ${sw_fail} == 0 ]] && ok "PASS + BLOCKED -> NOT_QUALIFIED, exit 0" || bad "PASS + BLOCKED -> ${overall} sw_fail=${sw_fail}"

    # C kernel QEMU rows (ck_*): canned child scripts, no QEMU. Uses the
    # table's own runner, notrun_rc and marker for each row.
    ck_case() { # CASE ROW_ID WANTED SCRIPT_NAME RC LINES...
        local cs="$1" row="$2" want="$3" name="$4" crc="$5" rid rkind rrun rnrc rmark rdesc
        shift 5
        ck_scripts_dir="${tmp}/ck_${cs}"; mkdir -p "${ck_scripts_dir}"
        if [[ "${name}" != - ]]; then
            { echo '#!/usr/bin/env bash'; echo "echo x >>\"${ck_scripts_dir}/runs\""
              printf 'printf "%%s\\n"'; printf ' %q' "$@"; echo; echo "exit ${crc}"; } >"${ck_scripts_dir}/${name}"
        fi
        while IFS='|' read -r rid rkind rrun rnrc rmark rdesc; do
            [[ "${rid}" == "${row}" ]] || continue
            evaluate_gate "${cs}_${row}" "${rkind}" "${rrun}" "${rnrc}" "${rmark}" 2>/dev/null
        done <<<"${GATE_TABLE}"
        expect "${cs}_${row}" "${want}"
    }
    local saved_results=("${results[@]}")
    QUIET_FLAG="${tmp}/no_quiet_flag_here"; with_qemu=1; results=()
    rm -rf "${work_dir}/build"
    ck_case boot_pass ck_m1_boot_qemu PASS qemu_ck_boot_test.sh 0 'PASS  kernel: alive' 'AIENOS_CK_M1: PASS'
    rm -rf "${work_dir}/build"
    ck_case boot_notrun ck_m1_boot_qemu NOT_RUN qemu_ck_boot_test.sh 3 'NOT_RUN  quiet flag held' 'AIENOS_CK_M1: NOT_RUN'
    rm -rf "${work_dir}/build"
    ck_case boot_rc3_nomark ck_m1_boot_qemu FAIL qemu_ck_boot_test.sh 3 'killed'
    rm -rf "${work_dir}/build"
    ck_case boot_fail ck_m1_boot_qemu FAIL qemu_ck_boot_test.sh 1 'AIENOS_CK_M1: FAIL'
    rm -rf "${work_dir}/build"
    ck_case boot_both ck_m1_boot_qemu FAIL qemu_ck_boot_test.sh 0 'AIENOS_CK_M1: PASS' 'AIENOS_CK_M1: FAIL'
    rm -rf "${work_dir}/build"
    ck_case store_absent ck_store_kernel_qemu NOT_RUN -  0
    rm -rf "${work_dir}/build"
    ck_case mixed ck_store_kernel_qemu FAIL qemu_ck_store_test.sh 1 \
        'AIENOS_CK_M4_NVME: PASS' 'AIENOS_CK_M4_STORE: FAIL' 'AIENOS_CK_ARGUS1_REVOKE: PASS'
    ck_case mixed ck_argus1_revoke_qemu PASS qemu_ck_store_test.sh 1 \
        'AIENOS_CK_M4_NVME: PASS' 'AIENOS_CK_M4_STORE: FAIL' 'AIENOS_CK_ARGUS1_REVOKE: PASS'
    [[ "$(wc -l <"${tmp}/ck_mixed/runs")" == 1 ]] && ok "store script ran once for its two rows" || bad "store script ran $(wc -l <"${tmp}/ck_mixed/runs") times"
    rm -rf "${work_dir}/build"
    ck_case pass_rc2 ck_argus1_revoke_qemu FAIL qemu_ck_store_test.sh 2 'AIENOS_CK_ARGUS1_REVOKE: PASS'
    QUIET_FLAG="${saved_quiet}"; ck_scripts_dir="${repo_root}/scripts"; rm -rf "${work_dir}/build"
    results=("${saved_results[@]}")

    # The canonical table parses: every row has 6 fields and a known kind,
    # and no blocked/missing row carries a runner.
    local id kind runner nrc marker desc rows=0 tbad=0
    while IFS='|' read -r id kind runner nrc marker desc; do
        [[ -n "${id}" ]] || continue
        rows=$((rows + 1))
        case "${kind}" in
            software|cargo|qemu) declare -F "${runner}" >/dev/null || tbad=1 ;;
            auto) [[ "${runner}" != - ]] || tbad=1 ;;
            operator|hardware|missing) [[ "${runner}" == - ]] || tbad=1 ;;
            *) tbad=1 ;;
        esac
        [[ -n "${desc}" ]] || tbad=1
    done <<<"${GATE_TABLE}"
    [[ ${tbad} == 0 && ${rows} -gt 0 ]] && ok "canonical table: ${rows} rows well-formed" || bad "canonical table malformed"

    # JSON escaping and receipt naming by content hash.
    out_dir="${tmp}/out"; mkdir -p "${out_dir}"
    started_utc=x; head_sha=x; head_subject='quote " backslash \ tab	end'; tree_clean_before=true; tree_clean_after=true
    m_host=h; m_machine_id_sha=x; m_product=x; m_board=x; m_serial_sha=x; m_cpu=x; m_kernel=x
    m_bios_version=x; m_bios_date=x; m_sb_efivar=1; m_setup_mode=0; m_sb_mokutil=x; m_tpm_present=no
    m_tpm_mfr=x; m_tpm_vendor=x; m_tpm_fw=x; m_boot_disk=x; m_lbs=512; m_capture=x; pcr_lines=("0 ab" "1 cd")
    declare -gA descs=([a]=da [b]=db)
    write_receipt
    if [[ "$(sha_of <"${receipt_path}")" == "${receipt_sha}" && "${receipt_path}" == *"_${receipt_sha}.json" ]]; then
        ok "receipt name is the sha256 of its content"
    else
        bad "receipt name does not match its content hash"
    fi
    if command -v jq >/dev/null; then
        jq -e '.verdict == "NOT_QUALIFIED" and .counts.blocked == 1 and .gates[1].verdict == "NOT_RUN" and .gates[1].blocker == "BLOCKED_OPERATOR" and .gates[0].blocker == "-" and .tree_clean_before == true and .machine.pcr_sha256["1"] == "cd"' "${receipt_path}" >/dev/null \
            && ok "receipt is valid JSON (jq) with expected fields" || bad "receipt is not valid JSON or fields wrong"
    else
        echo "SKIP  jq not installed; JSON validity not machine-checked"
    fi

    # Dirty-tree refusal, end to end, on a private clone (never this tree).
    local clone="${tmp}/clone" rc
    if git clone -q --shared "${repo_root}" "${clone}" 2>/dev/null; then
        cp "${BASH_SOURCE[0]}" "${clone}/scripts/trust1_m5_qualify.sh"
        git -C "${clone}" add scripts/trust1_m5_qualify.sh
        git -C "${clone}" -c user.name=t -c user.email=t@t commit -qm selftest --allow-empty
        : >"${clone}/untracked_junk"
        bash "${clone}/scripts/trust1_m5_qualify.sh" --machine-only --out "${tmp}/o1" >/dev/null 2>&1; rc=$?
        [[ ${rc} == 2 ]] && ok "dirty tree (untracked file) refused, exit 2" || bad "dirty tree gave exit ${rc}, expected 2"
        rm -f "${clone}/untracked_junk"
        echo x >>"${clone}/README.md" 2>/dev/null || echo x >"${clone}/README.md"
        bash "${clone}/scripts/trust1_m5_qualify.sh" --machine-only --out "${tmp}/o2" >/dev/null 2>&1; rc=$?
        [[ ${rc} == 2 ]] && ok "dirty tree (modified tracked file) refused, exit 2" || bad "modified tree gave exit ${rc}, expected 2"
        git -C "${clone}" checkout -q -- . 2>/dev/null; git -C "${clone}" clean -qfd
        # A run that dirties the tree must exit 1.
        AIENOS_QUALIFY_TEST_DIRTY=1 bash "${clone}/scripts/trust1_m5_qualify.sh" --machine-only --out "${tmp}/o3" >/dev/null 2>&1; rc=$?
        [[ ${rc} == 1 ]] && ok "a run that dirties the tree exits 1" || bad "dirtying run gave exit ${rc}, expected 1"
        # --out inside the tree: exit 0 and the receipt is the only new file.
        git -C "${clone}" clean -qfd
        bash "${clone}/scripts/trust1_m5_qualify.sh" --machine-only --out "${clone}/evidence/qualify_st" >/dev/null 2>&1; rc=$?
        local added; added="$(git -C "${clone}" status --porcelain --untracked-files=all)"
        if [[ ${rc} == 0 && "${added}" =~ ^\?\?\ evidence/qualify_st/trust1_m5_qualification_[0-9a-f]{64}\.json$ ]]; then
            ok "--out inside the tree: exit 0, receipt is the only new file"
        else
            bad "--out inside the tree: exit ${rc}, tree change: ${added}"
        fi
    else
        bad "could not make a private clone for the dirty-tree test"
    fi

    rm -rf --one-file-system "${tmp}"
    if [[ ${st_fail} == 0 ]]; then echo "TRUST1_M5_QUALIFY_SELF_TEST: PASS"; exit 0; fi
    echo "TRUST1_M5_QUALIFY_SELF_TEST: FAIL"; exit 1
}

# ---------------------------------------------------------------------- main
main() {
    with_qemu=0; out_arg=""; mode=full
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --with-qemu) with_qemu=1 ;;
            --out) [[ $# -ge 2 ]] || die "--out needs a directory"; out_arg="$2"; shift ;;
            --self-test) mode=self ;;
            --machine-only) mode=machine ;;   # internal: identity + receipt, no gates
            -h|--help) sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
            *) die "unknown argument: $1" ;;
        esac
        shift
    done
    declare -gA descs=()
    results=()
    if [[ ${mode} == self ]]; then self_test; fi

    refuse_if_dirty "${repo_root}"
    local before; before="$(tree_state "${repo_root}")"
    # Measured, not assumed: refuse_if_dirty above exits on a dirty tree, and
    # this re-reads the state the receipt reports.
    if [[ -z "${before}" ]]; then tree_clean_before=true; else tree_clean_before=false; fi
    head_sha="$(git -C "${repo_root}" rev-parse HEAD)"
    head_subject="$(git -C "${repo_root}" log -1 --format=%s HEAD)"
    started_utc="$(date -u +%FT%TZ)"

    if [[ -n "${out_arg}" ]]; then
        # Resolved now, created only after the dirty-tree re-check, so an
        # in-tree DIR (evidence/) gets the receipt and nothing else.
        out_dir="$(realpath -m -- "${out_arg}")"
    else
        out_dir="$(mktemp -d "${TMPDIR:-/tmp}/trust1-m5-qualify.XXXXXX")" || die "mktemp failed"
    fi
    # Logs and builds always live outside the tree.
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/trust1-m5-work.XXXXXX")" || die "mktemp failed"
    mkdir -p "${work_dir}/logs" "${work_dir}/build"

    echo "TRUST-1 + M5 qualification at ${head_sha} (${head_subject})"
    collect_machine
    echo "Machine: ${m_host} | ${m_product} | firmware ${m_bios_version} (${m_bios_date}) | SecureBoot=${m_sb_efivar} SetupMode=${m_setup_mode} | TPM ${m_tpm_present} ${m_tpm_mfr} | boot disk ${m_boot_disk} LBS ${m_lbs}"
    if [[ ${mode} == full ]]; then
        run_table
    fi
    [[ "${AIENOS_QUALIFY_TEST_DIRTY:-0}" == 1 ]] && : >"${repo_root}/qualify_dirty_marker"

    # The run must not have changed the tree (the receipt is not written yet).
    local after; after="$(tree_state "${repo_root}")"
    tree_clean_after=true
    if [[ "${after}" != "${before}" ]]; then
        tree_clean_after=false
        echo "trust1_m5_qualify: the run changed the tree:" >&2
        printf '%s\n' "${after}" >&2
        results+=("tree_unchanged_after_run|software|FAIL|the run changed tracked or untracked files|-|0|0")
        descs[tree_unchanged_after_run]="the qualification run left the tree as it found it"
    fi

    summarize
    mkdir -p "${out_dir}" || die "cannot create ${out_dir}"
    write_receipt
    echo "Logs: ${work_dir}/logs"
    echo "Receipt: ${receipt_path}"
    echo "TRUST1_M5_QUALIFICATION: ${overall} (pass=${n_pass} fail=${n_fail} not_run=${n_notrun} blocked=${n_blocked} missing=${n_missing})"
    [[ ${sw_fail} == 0 ]] && exit 0 || exit 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
