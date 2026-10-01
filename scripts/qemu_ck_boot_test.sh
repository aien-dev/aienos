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
#    it still holds exactly that text, and at most once per run);
#  - the five M3 checks (threads, el0, preempt, placement, ipc) use the same
#    patterns and give their own verdict AIENOS_CK_M3, which is PASS only if
#    all five pass AND every M1 check of the same boot passes (no fault, no
#    panic, QEMU exit 0); the C kernel prints one extra line, ipc_detail,
#    which no check reads (native/kernel/GATES.md rows 16-20 list the
#    differences in how the C kernel does the work);
#  - one added check: guard_page (the C kernel's guard-page fault self test);
#  - stricter: any QEMU exit status other than 0 fails (the Rust script fails
#    only on the timeout status 124); PSCI reset with -no-reboot exits 0;
#  - the checks live in scripts/lib_ck_m1_checks.sh (shared with the Store gate);
#  - last two lines are AIENOS_CK_M3: and AIENOS_CK_M1: PASS|FAIL|NOT_RUN.
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

# Machine quiet flag: one heavy run at a time on the Spark.
quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_boot_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "AIENOS_CK_M3: NOT_RUN"
    echo "AIENOS_CK_M1: NOT_RUN"
    exit 3
fi

own_flag=1
# Release the flag exactly once, and only while this run still owns it, so a
# later run that wrote the same tag never loses its flag to this EXIT trap.
release_flag() {
    if [[ "${own_flag}" == 1 ]]; then
        own_flag=0
        if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
    fi
}
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
release_flag

tr -d '\r' <"${log}" >"${work}/serial.txt"
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_boot_serial.log"
failed=0
# shellcheck source=scripts/lib_ck_m1_checks.sh
source "${repo_root}/scripts/lib_ck_m1_checks.sh"
echo "qemu exit ${qemu_status} after ${elapsed} s (commit ${commit:0:12})"
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
