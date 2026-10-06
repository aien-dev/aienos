#!/usr/bin/env bash
# qemu_ck_rollback_test.sh -- CK gate M0_ROLLBACK: one-time BootNext rollback
# with the AIENOS C kernel image as the candidate, in QEMU AArch64 with AAVMF.
#
# Design (ACCEPTED, no A/B slots, ADR 0024 Q3): docs/BOOT_HANDOFF_CONTRACT.md
# section 7 and 7.1, docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md. The Rust
# aienos-rollback-mock stays the stager (\EFI\BOOT\BOOTAA64.EFI: writes
# Boot0001 "Default Linux OS", Boot0000 "AIENOS Candidate", BootOrder=0001,
# BootNext=0000, resets) and the Default entry (\EFI\DEFAULT\default.efi).
# Only the candidate changes: \EFI\AIENOS\candidate.efi is a C kernel image
# built here with make. The Rust-mock run (scripts/qemu_native_rollback_test.sh)
# is untouched and keeps its own labels; this script prints CK_ROLLBACK_* and
# AIENOS_CK_M0_ROLLBACK lines only.
#
# Each case is a lane with its own fresh copy of AAVMF_VARS.fd (the emulated
# UEFI variable store) and its own ESP folder, four boots:
#   boot 1 stage    the mock stager sets BootNext=0000 and resets
#   boot 2 attempt  firmware consumes BootNext and starts (or fails to load)
#                   Boot0000
#   boot 3 default  the next boot (for rejected/absent the Default already ran
#                   in boot 2, so boot 3 is its first repeat)
#   boot 4 default  one more boot: still Default, no second candidate attempt
# After every boot the host reads the variable store file itself
# (native/kernel/tools/ck_uefi_vars.c, read-only), so the BootNext and
# BootOrder verdicts come from the firmware's own store, not from a guest print.
#
# Cases (lane -> candidate.efi):
#   normal     the default C core image: runs to "report_kind: final", PSCI reset
#   panic      TEST-only CK_TEST_ROLLBACK=bad-magic: the kernel refuses its
#              handoff ("panic: handoff: bad magic") and resets
#   cpu-fault  TEST-only CK_TEST_ROLLBACK=cpu-fault: BRK at EL1 after
#              "kernel: alive"; fault report ("report_kind: fault", EC 0x3c), reset
#   hang       TEST-only CK_TEST_ROLLBACK=hang: marker, then spins with
#              interrupts masked; the host checks it is still running
#              AIENOS_HANG_HOLD seconds later with no reset, then kills QEMU
#              (stands in for the operator power-cycle or an outside watchdog;
#              the stub disables the UEFI watchdog, there is none in the guest)
#   rejected   the default C image cut to its first 4096 bytes (PE headers
#              intact, sections missing): the firmware must refuse to load it
#   absent     Boot0000 names a file that does not exist (stager mode absent)
#
# Checks per lane (each its own PASS/FAIL line):
#   staged      after boot 1 the store holds BootNext=0000, BootOrder=0001,
#               Boot0000="AIENOS Candidate"
#   attempt     boot 2 shows the case's own evidence (above) and the firmware
#               line for Boot0000; QEMU ended by reset (exit 0), except hang
#   returned    the first boot after the attempt runs Boot0001 "Default Linux
#               OS" (BdsDxe line and the mock's BOOT_CURRENT=0001)
#   once        BootNext is absent in the store after boots 2, 3 and 4, and
#               the firmware dispatched Boot0000 in boot 2 only
#   order       BootOrder: 0001 first and Boot0000 never in it after any boot;
#               identical after boots 2, 3 and 4 (no later change); and equal
#               after boot 2 to the absent lane, where no candidate code ran
#               at all (the control). AAVMF itself appends its own
#               auto-created options (UiApp, UEFI Misc Device, EFI Internal
#               Shell) to BootOrder on the boot after the stager wrote
#               BootOrder=0001; the control lane shows that this is the
#               firmware, not the candidate. That firmware append is printed
#               as an observation (same class as the Machine 1 note in
#               docs/M0_NATIVE_BOOT_ROLLBACK_AUDIT.md row 7).
#
# Rows: native/kernel/GATES.md 42-46. QEMU only: a PASS here qualifies
# nothing physical. Never touches a real disk, NVRAM, firmware or key: every
# variable store is a temp copy of AAVMF_VARS.fd, every ESP a temp folder.
#
# Usage: bash scripts/qemu_ck_rollback_test.sh             (full run)
#        bash scripts/qemu_ck_rollback_test.sh --self-test (judges on canned
#             logs and store dumps, no QEMU)
# Environment: AAVMF_CODE, AAVMF_VARS, AIENOS_QEMU_TIMEOUT (per boot, 120 s),
# AIENOS_HANG_HOLD (10 s), AIENOS_QUIET_FLAG (read only), AIENOS_GATE_LOCK /
# AIENOS_GATE_TAG (exclusive QEMU gate lock), AIENOS_ROLLBACK_KEEP=DIR (copy
# the lane logs and store dumps there).
# Exit: 0 PASS, 1 FAIL, 2 missing tool, 3 NOT_RUN (quiet flag or lock held).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict_name="AIENOS_CK_M0_ROLLBACK"

failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

# ---------------------------------------------------------------------------
# Judges. Arguments are file paths; each returns 0 only on its own evidence.
# ---------------------------------------------------------------------------
# vget DUMP KEY -> value of "KEY=value" in a ck_uefi_vars dump, or "missing"
vget() { local v; v="$(sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n1)"; echo "${v:-missing}"; }
# order_ok DUMP: BootOrder present, 0001 first, 0000 nowhere in it
order_ok() {
    local o; o="$(vget "$1" BootOrder)"
    [[ "${o}" =~ ^0001(,[0-9A-F]{4})*$ ]] && [[ ",${o}," != *",0000,"* ]]
}
staged_ok() { # DUMP after boot 1
    [[ "$(vget "$1" BootNext)" == 0000 && "$(vget "$1" BootOrder)" == 0001 && \
       "$(vget "$1" Boot0000)" == "AIENOS Candidate" && "$(vget "$1" Boot0001)" == "Default Linux OS" ]]
}
starts0() { grep -ac 'BdsDxe: starting Boot0000 "AIENOS Candidate"' "$1" 2>/dev/null || true; }
has() { grep -aqF -- "$2" "$1" 2>/dev/null; }
# no_c_report LOG: no kernel end report of any kind
no_c_end() { ! grep -aqE '^report_kind: (final|panic|fault)' "$1" 2>/dev/null; }

# attempt_ok CASE LOG RC [HELD]
attempt_ok() {
    local case="$1" log="$2" rc="$3" held="${4:-0}"
    case "${case}" in
        normal)
            [[ "${rc}" == 0 && "$(starts0 "${log}")" == 1 ]] && has "${log}" "kernel_impl: c (native/kernel, Lane 18)" && \
            has "${log}" "kernel: alive" && has "${log}" "report_kind: final" && \
            has "${log}" "note: QEMU qualifies nothing physical" && \
            ! grep -aqE '^report_kind: (panic|fault)' "${log}" && ! has "${log}" "TEST-ONLY rollback candidate" ;;
        panic)
            [[ "${rc}" == 0 && "$(starts0 "${log}")" == 1 ]] && \
            has "${log}" "rollback_test: TEST-ONLY rollback candidate (bad-magic)" && \
            has "${log}" "report_kind: panic" && grep -aqx 'panic: handoff: bad magic' <(tr -d '\r' <"${log}") && \
            ! has "${log}" "kernel: alive" && ! has "${log}" "report_kind: final" ;;
        cpu-fault)
            [[ "${rc}" == 0 && "$(starts0 "${log}")" == 1 ]] && has "${log}" "kernel: alive" && \
            has "${log}" "rollback_test: TEST-ONLY rollback candidate (cpu-fault)" && \
            has "${log}" "report_kind: fault" && grep -aqE '^fault: vector=sync_el_spx el=1 .* ec=0x3c ' "${log}" && \
            ! has "${log}" "report_kind: final" ;;
        hang)
            [[ "${held}" == 1 && "$(starts0 "${log}")" == 1 ]] && has "${log}" "kernel: alive" && \
            has "${log}" "rollback_test: TEST-ONLY rollback candidate (hang)" && no_c_end "${log}" ;;
        rejected|absent)
            [[ "${rc}" == 0 && "$(starts0 "${log}")" == 0 ]] && has "${log}" "failed to load Boot0000" && \
            ! has "${log}" "kernel_impl: c" && has "${log}" 'BdsDxe: starting Boot0001 "Default Linux OS"' ;;
        *) return 1 ;;
    esac
}
returned_ok() { # LOG of the first boot that must be the Default
    has "$1" 'BdsDxe: starting Boot0001 "Default Linux OS"' && has "$1" "DEFAULT_OS: BOOT_CURRENT=0001"
}
# once_ok CASE V2 V3 V4 LOG2 LOG3 LOG4
once_ok() {
    local case="$1" want=1
    [[ "${case}" == rejected || "${case}" == absent ]] && want=0
    [[ "$(vget "$2" BootNext)" == absent && "$(vget "$3" BootNext)" == absent && "$(vget "$4" BootNext)" == absent ]] && \
    [[ "$(starts0 "$5")" == "${want}" && "$(starts0 "$6")" == 0 && "$(starts0 "$7")" == 0 ]] && \
    ! has "$6" "loading Boot0000" && ! has "$7" "loading Boot0000"
}
# order_lane_ok V1 V2 V3 V4 CONTROL_V2
order_lane_ok() {
    local o2; o2="$(vget "$2" BootOrder)"
    order_ok "$1" && order_ok "$2" && order_ok "$3" && order_ok "$4" && \
    [[ "$(vget "$3" BootOrder)" == "${o2}" && "$(vget "$4" BootOrder)" == "${o2}" ]] && \
    [[ -f "$5" && "$(vget "$5" BootOrder)" == "${o2}" ]]
}

if [[ "${1:-}" == --self-test ]]; then
    st=0; t="$(mktemp -d)"; trap 'rm -rf "${t}"' EXIT
    expect() { # label want(0|1) cmd...
        local label="$1" want="$2" rc=0; shift 2
        "$@" || rc=$?; [[ "${rc}" != 0 ]] && rc=1
        if [[ "${rc}" == "${want}" ]]; then echo "PASS  ${label}"; else echo "FAIL  ${label} (wanted ${want}, got ${rc})"; st=1; fi
    }
    printf 'uefi_vars: store=authenticated live=17 obsolete=6\nBootOrder=0001\nBootNext=0000\nBoot0000=AIENOS Candidate\nBoot0001=Default Linux OS\n' >"${t}/v1"
    printf 'uefi_vars: store=authenticated live=18 obsolete=14\nBootOrder=0001,0002,0003,0004\nBootNext=absent\nBoot0000=AIENOS Candidate\nBoot0001=Default Linux OS\n' >"${t}/v2"
    cp "${t}/v2" "${t}/ctl"
    expect "staged store accepted" 0 staged_ok "${t}/v1"
    expect "unstaged store (BootNext absent) refused as staged" 1 staged_ok "${t}/v2"
    sed 's/^BootOrder=0001$/BootOrder=0000,0001/' "${t}/v1" >"${t}/v1p"
    expect "stager that promoted Boot0000 refused as staged" 1 staged_ok "${t}/v1p"
    expect "order: settled lane equal to control accepted" 0 order_lane_ok "${t}/v1" "${t}/v2" "${t}/v2" "${t}/v2" "${t}/ctl"
    sed 's/^BootOrder=.*/BootOrder=0000,0001,0002,0003,0004/' "${t}/v2" >"${t}/vprom"
    expect "order: Boot0000 promoted into BootOrder refused" 1 order_lane_ok "${t}/v1" "${t}/vprom" "${t}/vprom" "${t}/vprom" "${t}/vprom"
    sed 's/^BootOrder=.*/BootOrder=0002,0001,0003,0004/' "${t}/v2" >"${t}/vfirst"
    expect "order: Default no longer first refused" 1 order_lane_ok "${t}/v1" "${t}/v2" "${t}/vfirst" "${t}/v2" "${t}/ctl"
    sed 's/^BootOrder=.*/BootOrder=0001,0003/' "${t}/v2" >"${t}/vdiff"
    expect "order: lane differs from the control refused" 1 order_lane_ok "${t}/v1" "${t}/vdiff" "${t}/vdiff" "${t}/vdiff" "${t}/ctl"
    expect "order: later boot changed BootOrder refused" 1 order_lane_ok "${t}/v1" "${t}/v2" "${t}/v2" "${t}/vdiff" "${t}/ctl"
    expect "order: missing control refused" 1 order_lane_ok "${t}/v1" "${t}/v2" "${t}/v2" "${t}/v2" "${t}/nocontrol"
    sed 's/^BootNext=absent$/BootNext=0000/' "${t}/v2" >"${t}/vnext"
    good2='BdsDxe: starting Boot0000 "AIENOS Candidate" from x'
    printf '%s\n' "${good2}" >"${t}/l2"; printf 'BdsDxe: starting Boot0001 "Default Linux OS" from x\n' >"${t}/l3"
    expect "once: BootNext gone after boots 2-4, one dispatch accepted" 0 once_ok normal "${t}/v2" "${t}/v2" "${t}/v2" "${t}/l2" "${t}/l3" "${t}/l3"
    expect "once: BootNext still set after boot 2 refused" 1 once_ok normal "${t}/vnext" "${t}/v2" "${t}/v2" "${t}/l2" "${t}/l3" "${t}/l3"
    expect "once: BootNext back after boot 4 refused" 1 once_ok normal "${t}/v2" "${t}/v2" "${t}/vnext" "${t}/l2" "${t}/l3" "${t}/l3"
    expect "once: second dispatch in boot 3 refused" 1 once_ok normal "${t}/v2" "${t}/v2" "${t}/v2" "${t}/l2" "${t}/l2" "${t}/l3"
    expect "once: rejected lane must show no dispatch" 1 once_ok rejected "${t}/v2" "${t}/v2" "${t}/v2" "${t}/l2" "${t}/l3" "${t}/l3"
    # attempt judges on canned serial logs
    { echo "${good2}"; echo "kernel_impl: c (native/kernel, Lane 18)"; echo "kernel: alive"; echo "report_kind: final"; echo "note: QEMU qualifies nothing physical"; } >"${t}/normal"
    expect "attempt normal: final report accepted" 0 attempt_ok normal "${t}/normal" 0
    expect "attempt normal: QEMU timeout (exit 124) refused" 1 attempt_ok normal "${t}/normal" 124
    { cat "${t}/normal"; echo "report_kind: panic"; } >"${t}/normalp"
    expect "attempt normal: a panic in the log refused" 1 attempt_ok normal "${t}/normalp" 0
    grep -v 'report_kind: final' "${t}/normal" >"${t}/nofinal"
    expect "attempt normal: no final report refused" 1 attempt_ok normal "${t}/nofinal" 0
    { echo "${good2}"; echo "rollback_test: TEST-ONLY rollback candidate (bad-magic): x"; echo "report_kind: panic"; printf 'panic: handoff: bad magic\r\n'; } >"${t}/panic"
    expect "attempt panic: bad magic refusal accepted" 0 attempt_ok panic "${t}/panic" 0
    sed 's/bad magic/unsupported version 2 (kernel reads CHANDOF3 only)/' "${t}/panic" >"${t}/panicv"
    expect "attempt panic: a different refusal reason refused" 1 attempt_ok panic "${t}/panicv" 0
    { echo "${good2}"; echo "kernel: alive"; echo "rollback_test: TEST-ONLY rollback candidate (cpu-fault): x"; echo "report_kind: fault"; echo "fault: vector=sync_el_spx el=1 esr=0xf200007b ec=0x3c far=0x0 elr=0x1"; } >"${t}/fault"
    expect "attempt cpu-fault: BRK fault report accepted" 0 attempt_ok cpu-fault "${t}/fault" 0
    sed 's/ec=0x3c/ec=0x25/' "${t}/fault" >"${t}/faultdab"
    expect "attempt cpu-fault: another exception class refused" 1 attempt_ok cpu-fault "${t}/faultdab" 0
    { echo "${good2}"; echo "kernel: alive"; echo "rollback_test: TEST-ONLY rollback candidate (hang): x"; } >"${t}/hang"
    expect "attempt hang: held and silent accepted" 0 attempt_ok hang "${t}/hang" 137 1
    expect "attempt hang: QEMU ended by itself refused" 1 attempt_ok hang "${t}/hang" 0 0
    { cat "${t}/hang"; echo "report_kind: final"; } >"${t}/hangend"
    expect "attempt hang: an end report after the marker refused" 1 attempt_ok hang "${t}/hangend" 137 1
    { echo 'BdsDxe: failed to load Boot0000 "AIENOS Candidate" from x: Not Found'; echo 'BdsDxe: starting Boot0001 "Default Linux OS" from x'; } >"${t}/absent"
    expect "attempt absent: load failure then Default accepted" 0 attempt_ok absent "${t}/absent" 0
    { cat "${t}/absent"; echo "${good2}"; } >"${t}/absentran"
    expect "attempt absent: a dispatched Boot0000 refused" 1 attempt_ok absent "${t}/absentran" 0
    printf 'BdsDxe: starting Boot0001 "Default Linux OS" from x\nDEFAULT_OS: BOOT_CURRENT=0001\n' >"${t}/l3d"
    expect "returned: Default boot accepted" 0 returned_ok "${t}/l3d"
    expect "returned: candidate boot again refused" 1 returned_ok "${t}/l2"
    if [[ ${st} == 0 ]]; then echo "CK_ROLLBACK_SELF_TEST: PASS"; exit 0; fi
    echo "CK_ROLLBACK_SELF_TEST: FAIL"; exit 1
fi

# ---------------------------------------------------------------------------
# Full run
# ---------------------------------------------------------------------------
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
qemu_timeout="${AIENOS_QEMU_TIMEOUT:-120}"
hang_hold="${AIENOS_HANG_HOLD:-10}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict_name}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict_name}: NOT_RUN"; exit 2; }
command -v cargo >/dev/null || { echo "cargo not installed (the stager/Default mock is Rust)"; echo "${verdict_name}: NOT_RUN"; exit 2; }

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
if [[ -e "${quiet_flag}" ]]; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${verdict_name}: NOT_RUN"
    exit 3
fi
gate_lock="${AIENOS_GATE_LOCK:-${HOME}/workspace/.qemu-gate-lock}"
gate_tag="${AIENOS_GATE_TAG:-qemu_ck_rollback_test $$}"
if ! ( set -C; echo "${gate_tag}" > "${gate_lock}" ) 2>/dev/null; then
    echo "NOT_RUN  QEMU gate lock ${gate_lock} is held: $(head -c 200 "${gate_lock}" 2>/dev/null || true)"
    echo "${verdict_name}: NOT_RUN"
    exit 3
fi
own_lock=1
release_lock() {
    if [[ "${own_lock}" == 1 ]]; then
        own_lock=0
        if [[ -f "${gate_lock}" ]] && grep -qxF -- "${gate_tag}" "${gate_lock}"; then rm -f "${gate_lock}"; fi
    fi
}
work="$(mktemp -d)"
qemu_pid=""
cleanup() {
    if [[ -n "${qemu_pid}" ]]; then kill -9 "${qemu_pid}" 2>/dev/null || true; fi
    if [[ -n "${AIENOS_ROLLBACK_KEEP:-}" ]]; then mkdir -p "${AIENOS_ROLLBACK_KEEP}" && cp -r "${work}/lanes" "${AIENOS_ROLLBACK_KEEP}/" 2>/dev/null || true; fi
    rm -rf "${work}"; release_lock
}
trap cleanup EXIT

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "============================================================"
echo "AIENOS CK M0_ROLLBACK: C kernel image as the one-time BootNext candidate (QEMU)"
echo "commit: ${commit}$( [[ -z "$(git status --porcelain 2>/dev/null)" ]] || echo ' (dirty tree)')"
echo "firmware: $(basename "${code_fd}") vars template sha256 $(sha256sum "${vars_fd}" | cut -c1-64)"
echo "============================================================"

echo "building aienos-rollback-mock (stager and Default, unchanged Rust mock) ..."
cargo build --quiet --release -p aienos-boot --target aarch64-unknown-uefi --features handoff --bin aienos-rollback-mock
mock="target/aarch64-unknown-uefi/release/aienos-rollback-mock.efi"
[[ -f "${mock}" ]] || { echo "mock build failed"; echo "${verdict_name}: FAIL"; exit 1; }

echo "building the C kernel images ..."
out_def="${repo_root}/target/native-kernel"
make -s -C native/kernel CROSS="${cross}" OUT="${out_def}" AIENOS_COMMIT="${commit}" >/dev/null
make -s -C native/kernel OUT="${out_def}" uefi-vars >/dev/null
vars_tool="${out_def}/host/ck_uefi_vars"
declare -A img=([normal]="${out_def}/BOOTAA64.EFI")
for m in bad-magic cpu-fault hang; do
    o="${repo_root}/target/native-kernel-test-rollback-${m}"
    make -s -C native/kernel CROSS="${cross}" OUT="${o}" AIENOS_COMMIT="${commit}" CK_TEST_ROLLBACK="${m}" >/dev/null
    img[${m}]="${o}/BOOTAA64.EFI"
done
img[panic]="${img[bad-magic]}"
head -c 4096 "${img[normal]}" >"${work}/truncated.efi"
img[rejected]="${work}/truncated.efi"
for k in normal panic cpu-fault hang rejected; do
    echo "candidate ${k}: sha256 $(sha256sum "${img[${k}]}" | cut -c1-64) bytes $(stat -c %s "${img[${k}]}")"
done
if grep -aqF "TEST-ONLY rollback candidate" "${img[normal]}"; then
    fail "the default C image carries a TEST-only rollback candidate"
fi
if "${vars_tool}" --self-test >"${work}/vars_selftest.log" 2>&1; then
    pass "ck_uefi_vars self-test ($(grep -c '^PASS' "${work}/vars_selftest.log") cases)"
else
    cat "${work}/vars_selftest.log"; fail "ck_uefi_vars self-test"
fi

qemu_args() { # VARS ESP LOG
    echo -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 2 -m 512 \
        -drive "if=pflash,format=raw,readonly=on,file=${code_fd}" \
        -drive "if=pflash,format=raw,file=$1" \
        -drive "if=none,id=esp,format=raw,file=fat:rw:$2" \
        -device virtio-blk-pci,drive=esp -display none -nic none -serial "file:$3" -no-reboot
}
boot() { # LANE N -> sets boot_rc; dumps the store to LANE/vN
    local d="$1" n="$2"
    set +e
    # shellcheck disable=SC2046
    timeout "${qemu_timeout}" qemu-system-aarch64 $(qemu_args "${d}/vars.fd" "${d}/esp" "${d}/boot${n}.log") </dev/null >"${d}/qemu${n}.out" 2>&1
    boot_rc=$?
    set -e
    "${vars_tool}" "${d}/vars.fd" >"${d}/v${n}" 2>&1 || true
}
hang_held=0
boot_hang() { # LANE N: start, wait for the marker, hold, then force the reset
    local d="$1" n="$2" log="$1/boot$2.log" waited=0 i
    hang_held=0
    # shellcheck disable=SC2046
    qemu-system-aarch64 $(qemu_args "${d}/vars.fd" "${d}/esp" "${log}") </dev/null >"${d}/qemu${n}.out" 2>&1 &
    qemu_pid=$!
    for ((i = 0; i < qemu_timeout * 2; i++)); do
        sleep 0.5
        if grep -aqF "rollback_test: TEST-ONLY rollback candidate (hang)" "${log}" 2>/dev/null; then waited=1; break; fi
        kill -0 "${qemu_pid}" 2>/dev/null || break
    done
    if [[ "${waited}" == 1 ]]; then
        sleep "${hang_hold}"
        if kill -0 "${qemu_pid}" 2>/dev/null && no_c_end "${log}"; then
            hang_held=1
            echo "hang: QEMU still running ${hang_hold} s after the hang marker, no end report; host forces the reset"
        fi
    fi
    kill -9 "${qemu_pid}" 2>/dev/null || true
    wait "${qemu_pid}" 2>/dev/null || true
    qemu_pid=""
    boot_rc=137
    "${vars_tool}" "${d}/vars.fd" >"${d}/v${n}" 2>&1 || true
}

lanes=(absent normal panic cpu-fault hang rejected) # absent first: it is the control
declare -A verdict=()
all_once=PASS; all_order=PASS
for lane in "${lanes[@]}"; do
    d="${work}/lanes/${lane}"
    mkdir -p "${d}/esp/EFI/BOOT" "${d}/esp/EFI/AIENOS" "${d}/esp/EFI/DEFAULT"
    cp "${vars_fd}" "${d}/vars.fd"
    cp "${mock}" "${d}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${mock}" "${d}/esp/EFI/DEFAULT/default.efi"
    if [[ "${lane}" == absent ]]; then
        echo absent >"${d}/esp/EFI/AIENOS/ROLLBACK_MODE.TXT"
    else
        echo normal >"${d}/esp/EFI/AIENOS/ROLLBACK_MODE.TXT"
        cp "${img[${lane}]}" "${d}/esp/EFI/AIENOS/candidate.efi"
    fi
    echo ""
    echo "--- [lane ${lane}] ---"
    "${vars_tool}" "${d}/vars.fd" >"${d}/v0" 2>&1 || true
    boot "${d}" 1; rc1=${boot_rc}
    if [[ "${lane}" == hang ]]; then boot_hang "${d}" 2; else boot "${d}" 2; fi
    rc2=${boot_rc}
    boot "${d}" 3; rc3=${boot_rc}
    boot "${d}" 4; rc4=${boot_rc}
    echo "qemu exits: stage=${rc1} attempt=${rc2} next=${rc3} repeat=${rc4}"
    echo "store after boot 1: $(grep -E '^Boot(Order|Next)=' "${d}/v1" | paste -sd' ')"
    echo "store after boot 2: $(grep -E '^Boot(Order|Next)=' "${d}/v2" | paste -sd' ')"
    echo "store after boot 4: $(grep -E '^Boot(Order|Next)=' "${d}/v4" | paste -sd' ')"
    first_default="${d}/boot3.log"
    [[ "${lane}" == rejected || "${lane}" == absent ]] && first_default="${d}/boot2.log"
    ok=1
    staged_ok "${d}/v1" && pass "${lane}: staged (BootNext=0000, BootOrder=0001, Boot0000 \"AIENOS Candidate\", read from the store)" \
        || { fail "${lane}: staged"; ok=0; }
    attempt_ok "${lane}" "${d}/boot2.log" "${rc2}" "${hang_held}" && pass "${lane}: attempt evidence in boot 2" \
        || { fail "${lane}: attempt evidence in boot 2 (exit ${rc2})"; ok=0; }
    returned_ok "${first_default}" && pass "${lane}: next boot is Boot0001 Default (BOOT_CURRENT=0001)" \
        || { fail "${lane}: return to Default"; ok=0; }
    returned_ok "${d}/boot4.log" && pass "${lane}: repeat boot is still Default" || { fail "${lane}: repeat boot"; ok=0; }
    once_ok "${lane}" "${d}/v2" "${d}/v3" "${d}/v4" "${d}/boot2.log" "${d}/boot3.log" "${d}/boot4.log" && \
        pass "${lane}: BootNext consumed once (absent in the store after boots 2-4; Boot0000 dispatched $( [[ ${lane} == rejected || ${lane} == absent ]] && echo 'never, load refused once' || echo 'in boot 2 only'))" \
        || { fail "${lane}: BootNext consumed exactly once"; ok=0; all_once=FAIL; }
    order_lane_ok "${d}/v1" "${d}/v2" "${d}/v3" "${d}/v4" "${work}/lanes/absent/v2" && \
        pass "${lane}: BootOrder 0001 first, no 0000, same after boots 2-4 and equal to the no-candidate control" \
        || { fail "${lane}: BootOrder"; ok=0; all_order=FAIL; }
    [[ "$(vget "${d}/v1" BootOrder)" != "$(vget "${d}/v2" BootOrder)" ]] && \
        echo "observation: AAVMF rewrote BootOrder $(vget "${d}/v1" BootOrder) -> $(vget "${d}/v2" BootOrder) in boot 2 (firmware auto-created options; the control lane shows the same)"
    verdict[${lane}]=$([[ ${ok} == 1 ]] && echo PASS || echo FAIL)
done

echo ""
echo "============================================================"
echo "Evidence kind: C-image, QEMU (AAVMF). Physical: NOT_RUN."
echo "CK_ROLLBACK_NORMAL: ${verdict[normal]}"
echo "CK_ROLLBACK_FAULT_PANIC: ${verdict[panic]}"
echo "CK_ROLLBACK_FAULT_CPU: ${verdict[cpu-fault]}"
echo "CK_ROLLBACK_TIMEOUT: ${verdict[hang]}"
echo "CK_ROLLBACK_REJECTED: ${verdict[rejected]}"
echo "CK_ROLLBACK_ABSENT: ${verdict[absent]}"
echo "CK_ROLLBACK_BOOTNEXT_CONSUMED: ${all_once}"
echo "CK_ROLLBACK_DEFAULT_UNCHANGED: ${all_order}"
if [[ "${failed}" == 0 ]]; then
    echo "${verdict_name}: PASS (QEMU only, C kernel image as candidate; physical NOT_RUN)"
    exit 0
fi
echo "${verdict_name}: FAIL"
exit 1
