#!/usr/bin/env bash
# Boot the AIENOS handoff image in QEMU AArch64 with UEFI (AAVMF) and check the
# serial console for the pre-exit report, the kernel reaching `kernel: alive`,
# and the final report. The guest starts at EL2 like Machine 1, and PSCI reset
# ends the run (-no-reboot). No physical hardware is touched.
#
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features handoff --bin aienos-handoff

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp target/aarch64-unknown-uefi/release/aienos-handoff.efi "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
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

tr -d '\r' <"${log}" >"${work}/serial.txt"
failed=0
check() { # description, pattern
    if grep -q -- "$2" "${work}/serial.txt"; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        failed=1
    fi
}
echo "qemu exit ${qemu_status} after ${elapsed} s (commit ${commit:0:12})"
check "pre-exit report printed" "report_kind: pre_exit"
check "image is this commit" "aienos_commit: ${commit}"
check "left firmware and entered the kernel" "kernel: alive"
check "kernel entered EL1h" "kernel_el: EL1h"
check "cooperative threads interleaved" "threads: ok"
check "EL0 capability and fault isolation" "el0: ok write=granted forged=denied fault=contained exit=0"
check "timer-driven preemption across runnable tasks" "preempt: ok"
check "deterministic MADT placement of preempt workers" "placement: worker0=class0/core0 worker1=class0/core1"
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
[[ "${failed}" == 0 ]] && echo "QEMU_BOOT: PASS" || { echo "QEMU_BOOT: FAIL"; exit 1; }
