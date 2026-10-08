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
#  - prints NOT_RUN while the machine quiet flag (AIENOS_QUIET_FLAG) is held,
#    which it only reads, or while another gate holds the QEMU gate lock
#    (AIENOS_GATE_LOCK); both through scripts/lib_gate_hold.sh (aienos#278);
#  - the five M3 checks (threads, el0, preempt, placement, ipc) use the same
#    patterns and give their own verdict AIENOS_CK_M3, which is PASS only if
#    all five pass AND every M1 check of the same boot passes (no fault, no
#    panic, QEMU exit 0); the C kernel prints one extra line, ipc_detail,
#    which no check reads (native/kernel/GATES.md rows 16-20 list the
#    differences in how the C kernel does the work);
#  - two added checks: guard_page (the C kernel's guard-page fault self test)
#    and kernel entropy ("entropy: rndr ..."; no fallback source exists);
#  - stricter: any QEMU exit status other than 0 fails (the Rust script fails
#    only on the timeout status 124); PSCI reset with -no-reboot exits 0;
#  - the checks live in scripts/lib_ck_m1_checks.sh (shared with the Store gate);
#  - last two lines are AIENOS_CK_M3: and AIENOS_CK_M1: PASS|FAIL|NOT_RUN;
#  - AIENOS_QEMU_CPU overrides "-cpu max" for a manual negative run (e.g.
#    neoverse-n1, which has no FEAT_RNG/RNDR: M1 must FAIL on the entropy
#    row). scripts/ck_gates.sh unsets it, so receipts always use -cpu max.
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "AIENOS_CK_M3: NOT_RUN"; echo "AIENOS_CK_M1: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "AIENOS_CK_M3: NOT_RUN"; echo "AIENOS_CK_M1: NOT_RUN"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel"
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" >/dev/null

# Machine quiet flag (read only) and the QEMU gate lock (one gate at a time):
# scripts/lib_gate_hold.sh (aienos#278).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take qemu_ck_boot_test "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "AIENOS_CK_M3: NOT_RUN"
    echo "AIENOS_CK_M1: NOT_RUN"
    exit 3
fi
# Release only this run's own gate lock record, at most once.
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

# Issue #61: single-threaded TCG completed 120/120 soak boots; MTTCG hung in 1/40.
qemu_accel=(-accel tcg,thread=single)
qemu_cpu="${AIENOS_QEMU_CPU:-max}"

started=$(date +%s)
set +e
timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3 "${qemu_accel[@]}" -cpu "${qemu_cpu}" -smp 4 -m 2048 \
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
release_flag

tr -d '\r' <"${log}" >"${work}/serial.txt"
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_boot_serial.log"
failed=0
# shellcheck source=scripts/lib_ck_m1_checks.sh
source "${repo_root}/scripts/lib_ck_m1_checks.sh"
echo "qemu exit ${qemu_status} after ${elapsed} s (commit ${commit:0:12}, -cpu ${qemu_cpu})"
ck_m1_checks
m3_failed=0
ck_m3_checks

if [[ "${failed}" != 0 || "${m3_failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"
    cat "${work}/serial.txt"
fi
m3_verdict=PASS
[[ "${m3_failed}" == 0 && "${failed}" == 0 ]] || m3_verdict=FAIL
echo "AIENOS_CK_M3: ${m3_verdict}"
[[ "${failed}" == 0 ]] && echo "AIENOS_CK_M1: PASS" || echo "AIENOS_CK_M1: FAIL"
[[ "${failed}" == 0 && "${m3_verdict}" == PASS ]] || exit 1
