#!/usr/bin/env bash
# Boot the AIENOS C kernel core (native/boot + native/kernel, Lane 18) in QEMU
# AArch64 with UEFI (AAVMF) and check the serial console with the same QEMU
# invocation and the same patterns as scripts/qemu_boot_test.sh (the Rust
# kernel's test). The guest starts at EL2 like Machine 1 and PSCI reset ends
# the run (-no-reboot). QEMU is not hardware: a PASS here qualifies nothing
# physical.
#
# Differences from qemu_boot_test.sh, all deliberate:
#  - builds with make (gcc + binutils), not cargo;
#  - takes the machine quiet flag itself (noclobber) and prints NOT_RUN if
#    another run holds it; AIENOS_QUIET_FLAG overrides the flag path and
#    AIENOS_QUIET_TAG the text written into it (the flag is removed only if
#    it still holds that text);
#  - the M3 checks (threads, el0, preempt, placement, ipc) print NOT_RUN: the
#    C kernel does not implement them yet, so they do not count;
#  - one added check: guard_page (the C kernel's guard-page fault self test);
#  - final line is AIENOS_CK_M1: PASS|FAIL|NOT_RUN.
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "AIENOS_CK_M1: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "AIENOS_CK_M1: NOT_RUN"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel"
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" >/dev/null

# Machine quiet flag: one heavy run at a time on the Spark.
quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_boot_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "AIENOS_CK_M1: NOT_RUN"
    exit 3
fi

work="$(mktemp -d)"
cleanup() {
    rm -rf "${work}"
    if [[ -f "${quiet_flag}" ]] && grep -qF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
}
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${out}/BOOTAA64.EFI" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${vars_fd}" "${work}/vars.fd"
log="${work}/serial.log"

# Issue #61: single-threaded TCG completed 120/120 soak boots; MTTCG hung in 1/40.
qemu_accel=(-accel tcg,thread=single)

started=$(date +%s)
set +e
timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3 "${qemu_accel[@]}" -cpu max -smp 4 -m 2048 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
    -device virtio-blk-pci,drive=esp \
    -device ramfb -display none -nic none \
    -serial file:"${log}" -no-reboot
qemu_status=$?
set -e
elapsed=$(( $(date +%s) - started ))
# Release the machine as soon as QEMU is gone.
if [[ -f "${quiet_flag}" ]] && grep -qF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi

tr -d '\r' <"${log}" >"${work}/serial.txt"
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_boot_serial.log"
failed=0
check() { # description, pattern
    if grep -q -- "$2" "${work}/serial.txt"; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        failed=1
    fi
}
not_run() { # description: M3 feature the C kernel does not have yet
    echo "NOT_RUN  $1 (not implemented in the C kernel yet)"
}
echo "qemu exit ${qemu_status} after ${elapsed} s (commit ${commit:0:12})"
check "pre-exit report printed" "report_kind: pre_exit"
check "image is this commit" "aienos_commit: ${commit}"
check "left firmware and entered the kernel" "kernel: alive"
check "kernel entered EL1h" "kernel_el: EL1h"
not_run "cooperative threads interleaved"
not_run "EL0 capability and fault isolation"
not_run "timer-driven preemption across runnable tasks"
not_run "deterministic MADT placement of preempt workers"
not_run "typed IPC with attenuated revocable delegation"
check "EL1 page tables and caches enabled" "mmu: enabled"
check "GICv3 enabled" "gic: v3"
if grep -qE 'timer_irq: ([0-9]+) ticks' "${work}/serial.txt"; then
    ticks=$(grep -oE 'timer_irq: ([0-9]+) ticks' "${work}/serial.txt" | tail -1 | grep -oE '[0-9]+')
    [[ "${ticks}" -ge 5 ]] && echo "PASS  timer IRQ delivered at least five ticks" || { echo "FAIL  timer IRQ delivered fewer than five ticks"; failed=1; }
else
    echo "FAIL  timer IRQ count reported"
    failed=1
fi
# Issue #27: the kernel left firmware's EL2 translation for AIENOS EL1 tables.
# The script re-checks the register values itself instead of trusting switched=yes.
switch_re='mmu_switch: firmware=EL2 firmware_mmu=on firmware_ttbr0=(0x[0-9a-f]+) aienos_root=(0x[0-9a-f]+) ttbr0_el1=(0x[0-9a-f]+) switched=yes'
switch_line=$(grep -E "${switch_re}" "${work}/serial.txt" | tail -1 || true)
if [[ "${switch_line}" =~ ${switch_re} ]]; then
    fw_root="${BASH_REMATCH[1]}"; aienos_root="${BASH_REMATCH[2]}"; el1_root="${BASH_REMATCH[3]}"
    if [[ "${aienos_root}" == "${el1_root}" && "${aienos_root}" != "${fw_root}" ]]; then
        echo "PASS  MMU switched from firmware tables (${fw_root}) to AIENOS tables (${aienos_root})"
    else
        echo "FAIL  MMU switch values inconsistent: ${switch_line}"
        failed=1
    fi
else
    echo "FAIL  MMU switch from firmware tables reported"
    failed=1
fi
check "GIC bases from the ACPI MADT, GICv3 architecture and ICC system registers" \
    "gic_madt: gicd=0x[0-9a-f]* gicr=0x[0-9a-f]* arch_rev=3 icc_sre=1"
# Issue #28: tick statistics. The dispatcher re-arms the timer 10 ms after each
# tick, so no interval may be shorter than half a period (a missing re-arm or a
# missing EOI would show as an interrupt storm or no second tick).
stats_re='timer_stats: intid=30 freq_hz=([0-9]+) period_us=([0-9]+) min_us=([0-9]+) avg_us=([0-9]+) max_us=([0-9]+)'
stats_line=$(grep -E "${stats_re}" "${work}/serial.txt" | tail -1 || true)
if [[ "${stats_line}" =~ ${stats_re} ]]; then
    period="${BASH_REMATCH[2]}"; min_us="${BASH_REMATCH[3]}"; avg_us="${BASH_REMATCH[4]}"; max_us="${BASH_REMATCH[5]}"
    if [[ "${period}" -gt 0 && $(( min_us * 2 )) -ge "${period}" && "${min_us}" -le "${avg_us}" && "${avg_us}" -le "${max_us}" ]]; then
        echo "PASS  tick statistics consistent (period ${period} us, min ${min_us} avg ${avg_us} max ${max_us})"
    else
        echo "FAIL  tick statistics out of range: ${stats_line}"
        failed=1
    fi
else
    echo "FAIL  tick statistics reported"
    failed=1
fi
# Added for the C kernel (the Rust kernel has no such test): every guard page
# faulted and the fault was contained.
check "guard pages fault and the fault is contained (C kernel addition)" "guard_page: ok fault=contained"
check "final report on the SPCR console" "report_kind: final"
check "no panic or fault" "report_kind: final"
if grep -qE "report_kind: (panic|fault)" "${work}/serial.txt"; then
    echo "FAIL  panic or fault reported"
    failed=1
fi
if [[ "${qemu_status}" == 124 ]]; then
    echo "FAIL  timed out (no reset)"
    failed=1
fi

if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"
    cat "${work}/serial.txt"
fi
[[ "${failed}" == 0 ]] && echo "AIENOS_CK_M1: PASS" || { echo "AIENOS_CK_M1: FAIL"; exit 1; }
