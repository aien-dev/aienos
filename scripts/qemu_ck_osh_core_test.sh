#!/usr/bin/env bash
# AIENOS_CK_OSH_CORE gate (OSH-AIENOS-0): the Omega-native shell core (three compiled OSC units lex_run, parse_run,
# expand_run, packed by native/kernel/tests/fixtures/osh/make-osh-units.sh from omega's oscc output) runs as admitted EL0
# tasks under the C kernel and produces exactly the same step trace as on Linux. Differential: the same compiled bytes,
# two runners (omega: tests/osh/osh_trace.c; here: native/kernel/core/osh_test.c).
#
# Label: QEMU (aarch64 virt), TEST signer, not physical. Nothing here ran on a Spark or any real machine.
# The only key is the spec's THROWAWAY TEST key.
#
# Five containers are written into the sealed C Store of a GPT boot disk image: the three units, a copy of
# osh_lex.unit with one byte of its CODE flipped, and the launch gate's l01_launch_fns.unit (only its spin() is used,
# for control 4b). One boot of the qualification image built with
# CK_SEED0B_TEST_ANCHOR=1 CK_OSH_TEST=1. The kernel admits them, runs every embedded fixture script and prints the trace
# between osh_script_begin / osh_script_end lines. This gate cuts each trace out of the serial log and diffs it, byte for
# byte, against the committed omega trace (native/kernel/tests/fixtures/osh/trace/*.trace). Negative controls:
#   1  a 22-page workspace with the pointer range claiming 11456 cells      -> REFUSED 41, before the first instruction
#   2a a workspace passed with len 512 cells (emit_tok, w[17]=127)           -> TRAPPED trap_code 3 (BOUNDS), no stray write
#   2b the entry point with len 512 cells                                    -> RETURNED 213 (the unit's own size check)
#   3  one flipped byte in a unit's CODE                                     -> admission refuses, nothing of it ran
#   4a caller max_ticks 1 on the long shell fixture                          -> RETURNED inside the tick (ticks=0): LIMIT, see below
#   4b the same cap through the same launch path on l01 spin()               -> OUTCOME_UNKNOWN TICK_OVERRUN
#      LIMIT: every shell loop is bounded and every entry call has a step budget, so no single shell call lasts a whole
#      10 ms tick under QEMU TCG; the cap is therefore shown to bite on spin(), not on a shell unit.
#   5  a deliberately wrong expected trace line                              -> the diff of this script goes red
# Last line: AIENOS_CK_OSH_CORE: PASS|FAIL|NOT_RUN.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict=AIENOS_CK_OSH_CORE

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict}: NOT_RUN"; exit 2; }

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_osh_core_test $$}"
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
cleanup() { rm -rf "${work}"; release_flag; }
trap cleanup EXIT
failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out_prod="${AIENOS_CK_OUT_PROD:-${repo_root}/target/native-kernel}"
out_osh="${AIENOS_CK_OUT_OSH:-${repo_root}/target/native-kernel-osh-core-test}"
mk() { make -s -C native/kernel CROSS="${cross}" AIENOS_COMMIT="${commit}" "$@" >/dev/null; }

fix="native/kernel/tests/fixtures/osh"
# the generated header the kernel embeds must be what the committed fixture scripts give
"${fix}/gen-fixtures-h.sh" "${fix}/trace" "${work}/osh_fixtures.h"
if cmp -s "${work}/osh_fixtures.h" native/kernel/core/osh_fixtures.h; then pass "core/osh_fixtures.h is exactly what the fixture scripts generate"
else fail "core/osh_fixtures.h differs from the fixture scripts (run gen-fixtures-h.sh)"; fi
nsh=$(ls "${fix}"/trace/*.sh | wc -l); ntr=$(ls "${fix}"/trace/*.trace | wc -l)
[[ "${nsh}" == "${ntr}" && "${nsh}" -ge 8 ]] && pass "${nsh} fixture scripts, ${ntr} expected traces" || fail "fixture scripts (${nsh}) and traces (${ntr}) differ"

mk OUT="${out_osh}" CK_SEED0B_TEST_ANCHOR=1 CK_OSH_TEST=1 full
make -s -C native/kernel OUT="${out_prod}" store-image gpt-image >/dev/null
simg="${out_prod}/host/ck_store_image"

# negative control 3 input: osh_lex.unit with one byte of the CODE section flipped. The code offset is read from the
# container's section table (section 2 entry at 128 + 48, offset field at +4).
code_off=$(od -An -tu4 -j180 -N4 "${fix}/osh_lex.unit" | tr -d ' ')
cp "${fix}/osh_lex.unit" "${work}/osh_lex_flipped.unit"
orig=$(od -An -tx1 -j$((code_off + 100)) -N1 "${fix}/osh_lex.unit" | tr -d ' ')
flip=$(printf '%02x' $(( 0x${orig} ^ 0x01 )))
printf "\\x${flip}" | dd of="${work}/osh_lex_flipped.unit" bs=1 seek=$((code_off + 100)) conv=notrunc status=none
[[ "$(od -An -tx1 -j$((code_off + 100)) -N1 "${work}/osh_lex_flipped.unit" | tr -d ' ')" == "${flip}" ]] && pass "flipped one code byte at offset $((code_off + 100)) (${orig} -> ${flip})" || fail "code byte flip"

files=("${fix}/osh_lex.unit" "${fix}/osh_parse.unit" "${fix}/osh_expand.unit" "${work}/osh_lex_flipped.unit" "${fix}/../osc_unit/launch/l01_launch_fns.unit")
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
    nice -n 10 timeout "${AIENOS_QEMU_TIMEOUT:-900}" qemu-system-aarch64 \
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
boot "${out_osh}/full/BOOTAA64.EFI" "${serial}" "${work}/disk-run.img"
release_flag

label='QEMU \(aarch64 virt\), TEST signer, not physical'
check "${serial}" "left firmware and entered the kernel" "kernel: alive"
check "${serial}" "kernel read all five candidates from the boot disk Store" "^artifact_candidates: 5$"
if has "${serial}" "^report-truncated:"; then fail "kernel report lines were truncated"; else pass "no kernel report line was truncated"; fi
check "${serial}" "final report reached the console" "report_kind: final"
if has "${serial}" "report_kind: (panic|fault)"; then fail "panic or fault reported (a unit fault must stay contained)"; else pass "no kernel panic or fault report"; fi
for u in osh_lex osh_parse osh_expand; do
    check "${serial}" "${u} admitted (real oscc output, TEST signer)" "^osc_unit: ${u}\\.unit ACCEPT unit_digest=[0-9a-f]{64} program_id=[0-9a-f]{64} funcs=[0-9]+ caps=0 signer=TEST$"
done
check "${serial}" "totals: 5 seen, 4 accepted, 1 refused" "^osc_units: seen=5 accepted=4 refused=1 oversize=0 "
check "${serial}" "core line: 3 units, 11456 cells, 23 pages, input window 4096" "^osh_core: units=3 ws_cells=11456 ws_pages=23 input_max=4096; ${label}\$"
check "${serial}" "driver finished every script" "^osh_core_done: scripts=${nsh}; ${label}\$"
if has "${serial}" "^osh_fault:"; then fail "a launch did not return (osh_fault line)"; else pass "no launch failed during the traces"; fi

# ---- the differential: kernel trace vs committed omega trace, byte for byte ----
mkdir -p "${work}/got"
total_lines=0; matched=0
for t in "${fix}"/trace/*.trace; do
    n=$(basename "${t}" .trace)
    awk -v n="${n}" '$1=="osh_script_begin" && $2==n {on=1; next} $1=="osh_script_end" && $2==n {on=0} on' "${serial}" >"${work}/got/${n}.trace"
    l=$(wc -l <"${t}")
    if cmp -s "${work}/got/${n}.trace" "${t}"; then pass "trace ${n}: ${l} lines identical to the Linux trace"; matched=$((matched + 1)); total_lines=$((total_lines + l))
    else
        fail "trace ${n} differs from the Linux trace; first difference:"
        diff "${work}/got/${n}.trace" "${t}" | head -4 | cut -c1-200 || true
    fi
done
echo "traces matched: ${matched} of ${nsh} scripts, ${total_lines} trace lines byte-identical"
[[ "${matched}" == "${nsh}" ]] && pass "every fixture trace is byte-identical (interpreter and native on Linux == AIENOS EL0)" || fail "not every trace matched"

# ---- negative controls ----
tail_ref="ticks=0 budget=0 pages_mapped=0 page_tables_zeroed=1 slot_free=1"
check "${serial}" "control 1: 22-page workspace claiming 11456 cells -> REFUSED 41 before the first instruction (ticks=0, nothing mapped)" \
    "^osh_neg1: .* -> REFUSED_AT_ADMISSION code=41 name=LAUNCH_ARG_SHAPE ${tail_ref}; ${label}\$"
check "${serial}" "control 2a: workspace len 512 cells -> TRAPPED trap_code 3 (BOUNDS), cell 17 and every cell from 512 up unchanged" \
    "^osh_neg2a: .* -> TRAPPED trap_code=3 ticks=[0-9]+ budget=[0-9]+ pages_mapped=[1-9][0-9]* page_tables_zeroed=1 slot_free=1 cell17=127 cells_512_up_unchanged=1; ${label}\$"
check "${serial}" "control 2b: entry point with len 512 cells -> RETURNED 213 (WORKSPACE_SIZE, the unit's own check), nothing written from 512 up" \
    "^osh_neg2b: .* -> RETURNED value=213 ticks=[0-9]+ budget=[0-9]+ pages_mapped=[1-9][0-9]* page_tables_zeroed=1 slot_free=1 cells_512_up_unchanged=1; ${label}\$"
check "${serial}" "control 3: one flipped CODE byte -> admission REFUSED" "^osc_unit: osh_lex_flipped\\.unit REFUSED code=[0-9]+ name=[A-Z_]+$"
check "${serial}" "control 3: nothing of the flipped unit ran" "^osh_neg3: osh_lex_flipped\\.unit -> NOT_RUN \\(unit was not admitted\\); ${label}\$"
check "${serial}" "control 4a (limit): max_ticks 1 on the long shell fixture: finishes inside the first tick (ticks=0) or overruns (1); the units are loop-bounded" \
    "^osh_neg4a: .* -> (RETURNED value=[0-9]+ ticks=0|OUTCOME_UNKNOWN unknown_reason=2 ticks=1) budget=1 pages_mapped=[1-9][0-9]* page_tables_zeroed=1 slot_free=1 fixture=[a-z0-9_]+ in_len=[0-9]+ max_ticks=1; ${label}\$"
check "${serial}" "control 4b: the same max_ticks 1 cap on spin() -> OUTCOME_UNKNOWN TICK_OVERRUN (2) after exactly 1 tick" \
    "^osh_neg4b: .* -> OUTCOME_UNKNOWN unknown_reason=2 ticks=1 budget=1 pages_mapped=[1-9][0-9]* page_tables_zeroed=1 slot_free=1; ${label}\$"
check "${serial}" "control 4: the next shell launch on the same workspace returns" "^osh_neg4n: .* -> RETURNED value=[0-9]+ "
# control 5: a deliberately wrong expected line must turn the diff red, then the real one is restored
first="${fix}/trace/t01_words.trace"
cp "${first}" "${work}/wrong.trace"
sed -i '1s/ret=[0-9]*/ret=777/' "${work}/wrong.trace"
if cmp -s "${work}/got/t01_words.trace" "${work}/wrong.trace"; then fail "control 5: the diff stayed green on a wrong expected line (gate cannot go red)"
else pass "control 5: a deliberately wrong expected line (ret=777) turns the diff red"; fi
if cmp -s "${work}/got/t01_words.trace" "${first}"; then pass "control 5: with the real expected line restored the diff is green again"
else fail "control 5: restored comparison not green"; fi

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then cp "${serial}" "${AIENOS_LOG_DIR}/qemu_ck_osh_core_serial.log"; fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial (osc/osh lines, no trace) ----"; grep -E "^(osc_|osh_neg|osh_core|osh_fault|artifact|kernel|report_kind|panic|fault)" "${serial}" | head -80 || true
fi
echo "label: QEMU (aarch64 virt), TEST signer, not physical"
if [[ "${failed}" == 0 ]]; then echo "${verdict}: PASS"; else echo "${verdict}: FAIL"; exit 1; fi
