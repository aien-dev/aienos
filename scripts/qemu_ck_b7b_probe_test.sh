#!/usr/bin/env bash
# B7b preparation probe gate (aienos#286). Boots the C kernel core image built
# with CK_B7B_PROBE=1 in QEMU AArch64 (UEFI/AAVMF, EL2, iommu=smmuv3) and checks
# the probe lines of core/smmu_svc.c ck_b7b_probe. QEMU is not hardware: a PASS
# here qualifies nothing physical; on the DGX Spark the probe is the attended B7b
# step and needs Drake's go (docs/GB10_IORT_DECODE.md section 10).
#
# Modes:
#   (default)      probe image as it would boot on the Spark: segment 15 rid
#                  0x100. QEMU virt has no segment 15, so the probe must refuse,
#                  fail closed: route none, confine rc=-3 (nostream), nothing
#                  confined, "AIENOS_B7B_PROBE: REFUSED", the boot goes on (the
#                  SMP summary follows) and ends without a panic.
#                  Last line AIENOS_CK_B7B_PROBE: PASS|FAIL|NOT_RUN.
#   --positive     TEST-ONLY image (CK_B7B_PROBE_TEST_SEGMENT0=1) probing segment
#                  0 rid 0x100: the route names instance 0 stream 0x100, the
#                  confinement is granted on one page, IDR0/IDR1 are read with a
#                  SIDSIZE that covers stream 0x100, the unconfine returns 0 and
#                  the summary is CONFINED_AND_RELEASED.
#                  Last line AIENOS_CK_B7B_PROBE_POSITIVE: PASS|FAIL|NOT_RUN.
#   --self-test    canned serial logs for every failure mode below plus the
#                  Makefile refusals of the probe flags; no QEMU, no compile.
#                  Last line AIENOS_CK_B7B_PROBE_SELF_TEST: PASS|FAIL.
# Environment: AIENOS_QEMU_TIMEOUT (180 s), AIENOS_QUIET_FLAG (read only),
# AIENOS_GATE_LOCK / AIENOS_GATE_MINUTES, AIENOS_LOG_DIR, AIENOS_QEMU_VERBOSE.
# Prints NOT_RUN (exit 3) while the quiet flag or the QEMU gate lock is held.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mode=gate
case "${1:-}" in
    "") ;;
    --positive) mode=positive ;;
    --self-test) mode=self ;;
    *) echo "usage: $0 [--positive|--self-test]" >&2; exit 2 ;;
esac
test_marker="TEST-ONLY B7b probe on PCI segment 0"

# check_refused FILE: the Spark-target probe on a machine without segment 15.
check_refused() {
    local f="$1"
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; failed=1; }
    [[ "$(grep -cE '^b7b_probe: start segment=15 rid=0x100 window_bytes=4096 no_dma=yes$' "${f}" || true)" == 1 ]] \
        && ok "one probe start, segment 15 rid 0x100" || bad "expected exactly one 'b7b_probe: start segment=15 rid=0x100' line"
    grep -qE '^b7b_probe: route none \(smmus=[0-9]+\)$' "${f}" && ok "IORT has no route for segment 15" || bad "no 'route none' line"
    grep -qE '^b7b_probe: confine refused rc=-3 \(nostream\); nothing granted$' "${f}" \
        && ok "confinement refused with nostream" || bad "no 'confine refused rc=-3 (nostream)' line"
    if grep -qE '^b7b_probe: confined ' "${f}"; then bad "something was confined"; else ok "nothing confined"; fi
    [[ "$(grep -cE '^AIENOS_B7B_PROBE: ' "${f}" || true)" == 1 ]] && grep -qE '^AIENOS_B7B_PROBE: REFUSED$' "${f}" \
        && ok "one summary: REFUSED" || bad "summary is not exactly one 'AIENOS_B7B_PROBE: REFUSED'"
    if grep -qF "${test_marker}" "${f}"; then bad "TEST-ONLY segment-0 image booted"; else ok "Spark-target probe image (no TEST-ONLY marker)"; fi
    common_tail "${f}"
}

# check_positive FILE: TEST-ONLY segment-0 probe on QEMU's SMMUv3.
check_positive() {
    local f="$1" line sidsize
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; failed=1; }
    grep -qF "${test_marker}" "${f}" && ok "TEST-ONLY image announced itself" || bad "no TEST-ONLY announcement"
    [[ "$(grep -cE '^b7b_probe: start segment=0 rid=0x100 window_bytes=4096 no_dma=yes$' "${f}" || true)" == 1 ]] \
        && ok "one probe start, segment 0 rid 0x100" || bad "expected exactly one 'b7b_probe: start segment=0 rid=0x100' line"
    grep -qE '^b7b_probe: route instance=0 base=0x[0-9a-f]+ stream=0x100 rmr_nodes=0 \(smmus=1\)$' "${f}" \
        && ok "route: instance 0, stream 0x100" || bad "no route line for instance 0 stream 0x100"
    grep -qE '^b7b_probe: confined stream=0x100 smmu_base=0x[0-9a-f]+ iova=0x[0-9a-f]*000 len=0x1000$' "${f}" \
        && ok "one page confined on stream 0x100" || bad "no 'confined stream=0x100 ... len=0x1000' line"
    line="$(grep -E '^b7b_probe: instance=0 idr0=0x[0-9a-f]{8} idr1=0x[0-9a-f]{8} st_level=[0-3] sidsize=[0-9]+$' "${f}" || true)"
    sidsize="$(sed -nE 's/.* sidsize=([0-9]+)$/\1/p' <<<"${line}")"
    if [[ -n "${sidsize}" && "${sidsize}" -ge 9 ]]; then ok "IDR0/IDR1 read, SIDSIZE ${sidsize} covers stream 0x100"; else bad "no IDR line with SIDSIZE >= 9"; fi
    grep -qE '^b7b_probe: unconfine rc=0 \(ok\); stream 0x100 aborts again$' "${f}" && ok "unconfine rc=0" || bad "unconfine did not return 0"
    [[ "$(grep -cE '^AIENOS_B7B_PROBE: ' "${f}" || true)" == 1 ]] && grep -qE '^AIENOS_B7B_PROBE: CONFINED_AND_RELEASED$' "${f}" \
        && ok "one summary: CONFINED_AND_RELEASED" || bad "summary is not exactly one 'AIENOS_B7B_PROBE: CONFINED_AND_RELEASED'"
    common_tail "${f}"
}

# common_tail FILE: the probe ran after "kernel: alive", the boot went on to the
# SMP summary, and no panic or exception report followed.
common_tail() {
    local f="$1" a p s
    a="$(grep -nE '^kernel: alive$' "${f}" | head -1 | cut -d: -f1)"
    p="$(grep -nE '^b7b_probe: start ' "${f}" | head -1 | cut -d: -f1)"
    s="$(grep -nE '^smp: cpus=' "${f}" | head -1 | cut -d: -f1)"
    if [[ -n "${a}" && -n "${p}" && -n "${s}" && "${a}" -lt "${p}" && "${p}" -lt "${s}" ]]; then
        ok "probe ran after 'kernel: alive' and the boot went on (SMP summary follows)"
    else
        bad "probe not between 'kernel: alive' and the SMP summary (alive=${a:-none} probe=${p:-none} smp=${s:-none})"
    fi
    if grep -qE '^report_kind: panic|^panic:|^exception:' "${f}"; then bad "panic or exception after the probe"; else ok "no panic or exception"; fi
}

self_test() {
    local tmp st_fail=0
    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp}"' RETURN
    expect() { # NAME pass|fail CHECKER FILE
        local out; failed=0
        out="$("$3" "$4")"; failed=0; grep -q '^FAIL' <<<"${out}" && failed=1
        if [[ "$2" == pass && "${failed}" == 0 ]] || [[ "$2" == fail && "${failed}" == 1 ]]; then
            echo "PASS  self-test $1 -> $2"
        else
            echo "FAIL  self-test $1 expected $2: $(grep '^FAIL' <<<"${out}" | head -2 | paste -sd';' -)"; st_fail=1
        fi
    }
    cat >"${tmp}/refused" <<'LOG'
kernel: alive
kernel_el: EL1h
b7b_probe: start segment=15 rid=0x100 window_bytes=4096 no_dma=yes
b7b_probe: route none (smmus=1)
b7b_probe: confine refused rc=-3 (nostream); nothing granted
AIENOS_B7B_PROBE: REFUSED
smp: cpus=2 checked_in=2 psci_errors=0 distinct_mpidrs=2 wait_us=10 result=ok
report_kind: final
LOG
    cat >"${tmp}/positive" <<'LOG'
kernel: alive
b7b_probe: TEST-ONLY B7b probe on PCI segment 0 (QEMU positive path); never hardware evidence
b7b_probe: start segment=0 rid=0x100 window_bytes=4096 no_dma=yes
b7b_probe: route instance=0 base=0x9050000 stream=0x100 rmr_nodes=0 (smmus=1)
b7b_probe: confined stream=0x100 smmu_base=0x9050000 iova=0x7f000000 len=0x1000
b7b_probe: instance=0 idr0=0x0a0d7fbf idr1=0x00e73210 st_level=1 sidsize=16
b7b_probe: unconfine rc=0 (ok); stream 0x100 aborts again
AIENOS_B7B_PROBE: CONFINED_AND_RELEASED
smp: cpus=2 checked_in=2 psci_errors=0 distinct_mpidrs=2 wait_us=10 result=ok
report_kind: final
LOG
    expect refused-good pass check_refused "${tmp}/refused"
    expect positive-good pass check_positive "${tmp}/positive"
    # Refusal gate: anything granted, wrong target, forged summary, missing lines, panic, wrong order, TEST image.
    expect positive-log-on-refusal-gate fail check_refused "${tmp}/positive"
    sed 's/^b7b_probe: confine refused.*/b7b_probe: confined stream=0x100 smmu_base=0x9050000 iova=0x7f000000 len=0x1000/' "${tmp}/refused" >"${tmp}/r1"; expect refused-but-confined fail check_refused "${tmp}/r1"
    sed 's/segment=15/segment=14/' "${tmp}/refused" >"${tmp}/r2"; expect wrong-segment fail check_refused "${tmp}/r2"
    sed 's/rc=-3 (nostream)/rc=-2 (failed)/' "${tmp}/refused" >"${tmp}/r3"; expect refused-other-reason fail check_refused "${tmp}/r3"
    grep -v '^AIENOS_B7B_PROBE' "${tmp}/refused" >"${tmp}/r4"; expect no-summary fail check_refused "${tmp}/r4"
    { cat "${tmp}/refused"; echo "AIENOS_B7B_PROBE: REFUSED"; } >"${tmp}/r5"; expect two-summaries fail check_refused "${tmp}/r5"
    grep -v '^smp: cpus=' "${tmp}/refused" >"${tmp}/r6"; expect boot-stopped fail check_refused "${tmp}/r6"
    { cat "${tmp}/refused"; echo "report_kind: panic"; } >"${tmp}/r7"; expect panic fail check_refused "${tmp}/r7"
    grep -v '^kernel: alive' "${tmp}/refused" >"${tmp}/r8"; expect not-after-alive fail check_refused "${tmp}/r8"
    sed 's/^b7b_probe: route none.*/b7b_probe: route instance=1 base=0x13000000 stream=0x100 rmr_nodes=1 (smmus=3)/' "${tmp}/refused" >"${tmp}/r9"; expect route-found-on-refusal fail check_refused "${tmp}/r9"
    { echo "${test_marker} (QEMU positive path); never hardware evidence"; cat "${tmp}/refused"; } >"${tmp}/r10"; expect test-image-on-gate fail check_refused "${tmp}/r10"
    # Positive path: missing announcement, unconfine failure, short SIDSIZE, no IDR line, wrong length, forged summary.
    grep -v 'TEST-ONLY' "${tmp}/positive" >"${tmp}/p1"; expect positive-no-announcement fail check_positive "${tmp}/p1"
    sed 's/unconfine rc=0 (ok)/unconfine rc=-4 (earg)/' "${tmp}/positive" >"${tmp}/p2"; expect unconfine-fails fail check_positive "${tmp}/p2"
    sed 's/sidsize=16/sidsize=8/' "${tmp}/positive" >"${tmp}/p3"; expect sidsize-too-small fail check_positive "${tmp}/p3"
    grep -v 'idr0=' "${tmp}/positive" >"${tmp}/p4"; expect no-idr-line fail check_positive "${tmp}/p4"
    sed 's/len=0x1000/len=0x2000/' "${tmp}/positive" >"${tmp}/p5"; expect wrong-window fail check_positive "${tmp}/p5"
    sed 's/CONFINED_AND_RELEASED/FAIL/' "${tmp}/positive" >"${tmp}/p6"; expect positive-summary-fail fail check_positive "${tmp}/p6"

    # Makefile refusals: parse-time $(error), nothing is compiled (make -n).
    refuse() { # NAME MESSAGE MAKE-ARGS...
        local name="$1" msg="$2" out rc; shift 2
        out="$(make -n -s -C native/kernel "$@" OUT="${tmp}/o_${name}" 2>&1)"; rc=$?
        if [[ ${rc} != 0 ]] && grep -qF "${msg}" <<<"${out}" && [[ ! -e "${tmp}/o_${name}" ]]; then
            echo "PASS  self-test Makefile refuses ${name}"
        else
            echo "FAIL  self-test Makefile did not refuse ${name} (rc=${rc}): ${out:0:200}"; st_fail=1
        fi
    }
    refuse probe-bad-value "CK_B7B_PROBE must be empty or 1" CK_B7B_PROBE=2
    refuse seg0-without-probe "CK_B7B_PROBE_TEST_SEGMENT0 needs CK_B7B_PROBE=1" CK_B7B_PROBE_TEST_SEGMENT0=1
    refuse seg0-with-staging "CK_B7B_PROBE_TEST_SEGMENT0 (TEST-only QEMU positive path) cannot be combined with CK_HARDWARE_STAGING" \
        CK_B7B_PROBE=1 CK_B7B_PROBE_TEST_SEGMENT0=1 CK_HARDWARE_STAGING=1
    refuse probe-with-unsafe-dma "CK_B7B_PROBE cannot be combined with CK_QEMU_UNSAFE_DMA" CK_B7B_PROBE=1 CK_QEMU_UNSAFE_DMA=1
    if grep -qE '^#if defined\(CK_B7B_PROBE_TEST_SEGMENT0\) && defined\(CK_HARDWARE_STAGING\)$' native/kernel/core/smmu_svc.c; then
        echo "PASS  self-test core/smmu_svc.c also refuses the segment-0 probe in a hardware staging compile"
    else
        echo "FAIL  self-test core/smmu_svc.c lacks the #error guard"; st_fail=1
    fi

    [[ ${st_fail} == 0 ]] && { echo "AIENOS_CK_B7B_PROBE_SELF_TEST: PASS"; exit 0; }
    echo "AIENOS_CK_B7B_PROBE_SELF_TEST: FAIL"; exit 1
}
if [[ "${mode}" == self ]]; then
    set +e
    self_test
fi

# --------------------------------------------------------------- QEMU boot
verdict_name=AIENOS_CK_B7B_PROBE
[[ "${mode}" == positive ]] && verdict_name=AIENOS_CK_B7B_PROBE_POSITIVE

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict_name}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict_name}: NOT_RUN"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
if [[ "${mode}" == positive ]]; then
    out="${repo_root}/target/native-kernel-test-b7b-seg0"
    make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" CK_B7B_PROBE=1 CK_B7B_PROBE_TEST_SEGMENT0=1 >/dev/null
else
    out="${repo_root}/target/native-kernel-b7b-probe"
    make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" CK_B7B_PROBE=1 >/dev/null
fi

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take "qemu_ck_b7b_probe_test" "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "${verdict_name}: NOT_RUN"
    exit 3
fi
release_flag() { gh_lock_release; }
work="$(mktemp -d)"
cleanup() {
    rm -rf "${work}"
    release_flag
}
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${out}/BOOTAA64.EFI" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${vars_fd}" "${work}/vars.fd"
log="${work}/serial.log"

# Same machine as scripts/qemu_ck_smp_test.sh plus the SMMUv3 vIOMMU (as scripts/qemu_keyboard_test.sh).
started=$(date +%s)
set +e
timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 2 -m 2048 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
    -device virtio-blk-pci,drive=esp \
    -device ramfb -display none -nic none \
    -serial file:"${log}" -no-reboot
qemu_status=$?
set -e
elapsed=$(( $(date +%s) - started ))
release_flag

tr -d '\r' <"${log}" >"${work}/serial.txt"
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_b7b_probe_${mode}_serial.log"
echo "qemu exit ${qemu_status} after ${elapsed} s (commit ${commit:0:12}, ${mode})"

failed=0
if [[ "${mode}" == positive ]]; then
    results="$(check_positive "${work}/serial.txt")" || true
else
    results="$(check_refused "${work}/serial.txt")" || true
fi
grep -q '^FAIL' <<<"${results}" && failed=1
printf '%s\n' "${results}"
if [[ "${qemu_status}" == 0 ]]; then echo "PASS  QEMU exit 0 (PSCI reset)"; else echo "FAIL  QEMU exit ${qemu_status}"; failed=1; fi
grep -E '^b7b_probe: |^AIENOS_B7B_PROBE: |^smmu: ' "${work}/serial.txt" | sed 's/^/LOG   /'
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"
    cat "${work}/serial.txt"
fi
if [[ "${failed}" == 0 ]]; then
    echo "${verdict_name}: PASS"
    exit 0
fi
echo "${verdict_name}: FAIL"
exit 1
