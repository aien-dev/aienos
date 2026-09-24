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
check "EL1 page tables and caches enabled" "mmu: enabled"
check "GICv3 enabled" "gic: v3"
if grep -qE 'timer_irq: ([0-9]+) ticks' "${work}/serial.txt"; then
    ticks=$(grep -oE 'timer_irq: ([0-9]+) ticks' "${work}/serial.txt" | tail -1 | grep -oE '[0-9]+')
    [[ "${ticks}" -ge 5 ]] && echo "PASS  timer IRQ delivered at least five ticks" || { echo "FAIL  timer IRQ delivered fewer than five ticks"; failed=1; }
else
    echo "FAIL  timer IRQ count reported"
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
