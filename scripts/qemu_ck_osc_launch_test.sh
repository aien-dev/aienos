#!/usr/bin/env bash
# AIENOS_CK_OSC_LAUNCH gate: task launch of an admitted OSC unit (C3-3a) in the C kernel, booted in
# QEMU AArch64 + UEFI (AAVMF). Contract: OSC_UNIT_ARTIFACT.md section 9 (aien-protocols PR #17).
#
# Label: QEMU (aarch64 virt), TEST signer, not physical. Nothing here ran on a Spark or any real machine.
# The only key is the spec's THROWAWAY TEST key. Every launch line the kernel prints carries the label.
#
# Two TEST-signed units are written into the sealed C Store of a GPT boot disk image and read back by the
# kernel's store stage (the path of qemu_ck_osc_unit_test.sh):
#   a01_valid_min.unit     the spec's vector unit (compiled by oscc): add, first_byte
#   l01_launch_fns.unit    hand-assembled test functions (tests/fixtures/osc_unit/launch/l01.S, built by
#                          make-l01.sh with the spec's own generator helpers): trap, spin, peek0, poke_rt,
#                          bare_brk, exec_stack, overflow, counter
# One boot of the qualification image built with CK_SEED0B_TEST_ANCHOR=1 CK_OSC_LAUNCH_TEST=1. After
# admission the kernel launches a fixed script of calls as EL0 tasks and prints one "osc_launch:" line each.
# This gate checks:
#   RETURNED with the exact value; refused bad-argument, unknown-name and out-of-window launches (nothing
#   ran); TRAPPED through the runtime trap service; a trap code outside 1..14 and a brk reached directly
#   are OUTCOME_UNKNOWN, never TRAPPED; budget exhaustion is OUTCOME_UNKNOWN (TICK_OVERRUN); a null read,
#   a write to OscRt, a jump into the stack (W^X) and a stack overflow are contained faults and a launch
#   right after each succeeds in the same boot; the task is torn down every time (no page left mapped,
#   slot reusable); a caller-owned workspace keeps its state across calls.
# Last line: AIENOS_CK_OSC_LAUNCH: PASS|FAIL|NOT_RUN.
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict=AIENOS_CK_OSC_LAUNCH

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict}: NOT_RUN"; exit 2; }

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_osc_launch_test $$}"
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
out_launch="${AIENOS_CK_OUT_LAUNCH:-${repo_root}/target/native-kernel-osc-launch-test}"
mk() { make -s -C native/kernel CROSS="${cross}" AIENOS_COMMIT="${commit}" "$@" >/dev/null; }
mk OUT="${out_launch}" CK_SEED0B_TEST_ANCHOR=1 CK_OSC_LAUNCH_TEST=1 full
make -s -C native/kernel OUT="${out_prod}" store-image gpt-image >/dev/null
simg="${out_prod}/host/ck_store_image"

fix="native/kernel/tests/fixtures/osc_unit"
files=("${fix}/vectors/a01_valid_min.unit" "${fix}/launch/l01_launch_fns.unit")
a01_line=$(grep -E '^a01_valid_min\.unit ' "${fix}/vectors/expected.txt")
a01_digest=$(sed -E 's/.* unit_digest=([0-9a-f]{64}) .*/\1/' <<<"${a01_line}")
[[ ${#a01_digest} == 64 ]] || fail "expected UnitDigest read from the frozen expected.txt"

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
boot "${out_launch}/full/BOOTAA64.EFI" "${serial}" "${work}/disk-run.img"
release_flag

check "${serial}" "left firmware and entered the kernel" "kernel: alive"
check "${serial}" "kernel read both candidates from the boot disk Store" "^artifact_candidates: 2$"
if has "${serial}" "^report-truncated:"; then fail "kernel report lines were truncated"; else pass "no kernel report line was truncated"; fi
check "${serial}" "final report reached the console" "report_kind: final"
if has "${serial}" "report_kind: (panic|fault)"; then fail "panic or fault reported (a unit fault must stay contained)"; else pass "no kernel panic or fault report: unit faults stayed contained"; fi
check "${serial}" "a01 admitted with the frozen UnitDigest" "^osc_unit: a01_valid_min\\.unit ACCEPT unit_digest=${a01_digest} "
check "${serial}" "l01 admitted (every hand-assembled word is in the OSC subset)" "^osc_unit: l01_launch_fns\\.unit ACCEPT .* funcs=8 caps=0 signer=TEST$"
check "${serial}" "totals: 2 seen, 2 accepted" "^osc_units: seen=2 accepted=2 refused=0 oversize=0 "
check "${serial}" "launch policy line, labelled" "^osc_launch_policy: units=2 code_max=65536 stack_max=65536 in_max=4096 ws=4 pages; 1 tick = 10 ms; QEMU \\(aarch64 virt\\), TEST signer, not physical$"

label='QEMU \(aarch64 virt\), TEST signer, not physical'
tail_run="ticks=[0-9]+ budget=[0-9]+ pages_mapped=[1-9][0-9]* pages_after=0 slot_free=1; ${label}\$"
tail_ref="ticks=0 budget=0 pages_mapped=0 pages_after=0 slot_free=1; ${label}\$"
# lline NAME UNIT CALL RESULT-REGEX [ref]: one launch line
lline() {
    local t="${tail_run}"
    [[ "${5:-}" == ref ]] && t="${tail_ref}"
    check "${serial}" "$1" "^osc_launch: $2 $3 -> $4 ${t}"
}
a=a01_valid_min.unit
l=l01_launch_fns.unit
lline "RETURNED with the exact value: add(1000000007,998244353) = 1998244360" $a 'add\(1000000007,998244353\)' 'RETURNED value=1998244360'
lline "refused bad argument count: add(5) is LAUNCH_ARG_SHAPE (41), nothing ran" $a 'add\(5\)' 'REFUSED_AT_ADMISSION code=41 name=LAUNCH_ARG_SHAPE' ref
lline "refused unknown name: nosuch is LAUNCH_BAD_ENTRY (40)" $a 'nosuch\(\)' 'REFUSED_AT_ADMISSION code=40 name=LAUNCH_BAD_ENTRY' ref
lline "refused wrong case: ADD is LAUNCH_BAD_ENTRY (40)" $a 'ADD\(1,2\)' 'REFUSED_AT_ADMISSION code=40 name=LAUNCH_BAD_ENTRY' ref
lline "RETURNED: first_byte over the read-only input window = 90 ('Z')" $a 'first_byte\(in\+0,4\)' 'RETURNED value=90'
lline "refused slice outside the caller's input window (ownership), LAUNCH_ARG_SHAPE (41)" $a 'first_byte\(4096,16\)' 'REFUSED_AT_ADMISSION code=41 name=LAUNCH_ARG_SHAPE' ref
lline "TRAPPED code 3 through the runtime trap service" $l 'trap\(3\)' 'TRAPPED trap_code=3'
lline "TRAPPED code 14 (the top of the table)" $l 'trap\(14\)' 'TRAPPED trap_code=14'
lline "trap code 15 is OUTCOME_UNKNOWN (TRAP_CODE_UNKNOWN=4), never TRAPPED" $l 'trap\(15\)' 'OUTCOME_UNKNOWN unknown_reason=4'
lline "a brk reached directly is OUTCOME_UNKNOWN (FAULT=1), never TRAPPED" $l 'bare_brk\(\)' 'OUTCOME_UNKNOWN unknown_reason=1'
check "${serial}" "budget exhaustion: spin() is OUTCOME_UNKNOWN (TICK_OVERRUN=2) after exactly 5 ticks of budget 5" \
    "^osc_launch: ${l} spin\\(\\) -> OUTCOME_UNKNOWN unknown_reason=2 ticks=5 budget=5 pages_mapped=[1-9][0-9]* pages_after=0 slot_free=1; ${label}\$"
lline "after the budget kill, the next launch succeeds: add(40,2) = 42" $a 'add\(40,2\)' 'RETURNED value=42'
lline "contained fault: a null read is OUTCOME_UNKNOWN (FAULT=1)" $l 'peek0\(\)' 'OUTCOME_UNKNOWN unknown_reason=1'
lline "after the fault, the next launch succeeds in the same boot: add(20,22) = 42" $a 'add\(20,22\)' 'RETURNED value=42'
lline "contained fault: a write to OscRt (read-only to the unit) is OUTCOME_UNKNOWN (FAULT=1)" $l 'poke_rt\(\)' 'OUTCOME_UNKNOWN unknown_reason=1'
lline "W^X: a jump into the stack (written code) is OUTCOME_UNKNOWN (FAULT=1), not RETURNED 42" $l 'exec_stack\(\)' 'OUTCOME_UNKNOWN unknown_reason=1'
lline "contained fault: a stack overflow is OUTCOME_UNKNOWN (FAULT=1)" $l 'overflow\(\)' 'OUTCOME_UNKNOWN unknown_reason=1'
lline "after four faults, the next launch succeeds: add(6,36) = 42" $a 'add\(6,36\)' 'RETURNED value=42'
# order: the successful launch comes after the fault it follows
ln() { grep -nE -- "^osc_launch: $1 $2 " "${serial}" | head -1 | cut -d: -f1; }
n_peek=$(ln "${l}" 'peek0\(\)'); n_add=$(ln "${a}" 'add\(20,22\)')
if [[ -n "${n_peek}" && -n "${n_add}" && "${n_add}" -gt "${n_peek}" ]]; then pass "the launch after the contained fault was run after it (line ${n_peek} then ${n_add})"
else fail "the launch after the contained fault was run after it"; fi
# workspace: first workspace counts 1,2,3 across three calls, a fresh one starts at 1 again
vals=$(grep -E -- "^osc_launch: ${l} counter\\(ws\\+0,1\\) -> RETURNED value=" "${serial}" | sed -E 's/.*value=([0-9]+) .*/\1/' | tr '\n' ' ')
if [[ "${vals}" == "1 2 3 1 " ]]; then pass "caller-owned workspace persists across calls: values 1 2 3, a fresh workspace starts again at 1"
else fail "workspace persistence (got: ${vals})"; fi
lline "refused misaligned cells pointer (ws+4): LAUNCH_ARG_SHAPE (41)" $l 'counter\(ws\+4,1\)' 'REFUSED_AT_ADMISSION code=41 name=LAUNCH_ARG_SHAPE' ref
check "${serial}" "summary: 9 returned, 2 trapped, 5 refused, 7 unknown" \
    "^osc_launches: returned=9 trapped=2 refused=5 unknown=7; ${label}\$"
# every launch line carries the label; the teardown columns never show a page left behind
nl=$(grep -c '^osc_launch: ' "${serial}" || true)
nlab=$(grep -cE "^osc_launch: .*; ${label}\$" "${serial}" || true)
[[ "${nl}" == 23 && "${nlab}" == 23 ]] && pass "all 23 launch lines carry the label" || fail "launch lines labelled (${nlab} of ${nl})"
if grep -E '^osc_launch: ' "${serial}" | grep -vqE 'pages_after=0 slot_free=1;'; then fail "a task left pages mapped or its slot busy"; else pass "every task was torn down: pages_after=0, slot_free=1"; fi

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then cp "${serial}" "${AIENOS_LOG_DIR}/qemu_ck_osc_launch_serial.log"; fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial (osc lines) ----"; grep -E "^(osc_|artifact|kernel|report_kind|panic|fault)" "${serial}" | head -80 || true
fi
echo "label: QEMU (aarch64 virt), TEST signer, not physical"
if [[ "${failed}" == 0 ]]; then echo "${verdict}: PASS"; else echo "${verdict}: FAIL"; exit 1; fi
