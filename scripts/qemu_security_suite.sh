#!/usr/bin/env bash
# qemu_security_suite.sh: TRUST-1 Gate 4 Security Test Suite in QEMU AArch64
# Includes:
# 1. Software TPM 2.0 (swtpm) socket attachment
# 2. Soak test (configurable iterations, default 5)
# 3. Fault injection / tampered image rejection test
# 4. Strict exit code propagation and receipt output
# Zero Disk Secrets and Unslop compliant.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

# judge_corrupt_rejection LOG: Subtest 3 verdict from the console log of the
# corrupted-image boot. PASS needs positive evidence that the firmware ran and
# the console was captured (the AAVMF banner), and no "kernel: alive". A missing
# or empty log, or a log without the banner, is FAIL: QEMU that never started
# must not read as "the firmware rejected the image".
judge_corrupt_rejection() {
    local log="$1"
    if [[ ! -f "${log}" ]]; then
        echo "FAIL  Corrupted-image boot left no console log: nothing shows the firmware ran"; return 1
    fi
    if ! grep -q "UEFI firmware (version" "${log}"; then
        echo "FAIL  Corrupted-image console log has no firmware banner: QEMU or the firmware did not run, so no rejection was observed"; return 1
    fi
    if grep -q "kernel: alive" "${log}"; then
        echo "FAIL  Corrupted binary unexpectedly reached kernel alive"; return 1
    fi
    echo "PASS  Corrupted binary cleanly rejected by firmware without reaching kernel alive (firmware banner present)"
}

# --self-test: negative controls for judge_corrupt_rejection. No QEMU, no build.
if [[ "${1:-}" == --self-test ]]; then
    st=0; t="$(mktemp -d)"; trap 'rm -rf "${t}"' EXIT
    expect_rc() { # name want_rc log
        local rc=0; judge_corrupt_rejection "$3" >/dev/null || rc=$?
        if [[ "${rc}" == "$2" ]]; then echo "PASS  $1 -> exit ${rc}"; else echo "FAIL  $1: wanted ${2}, got ${rc}"; st=1; fi
    }
    printf 'UEFI firmware (version 2024.02 built at 12:48:22 on Jun  2 2026)\nBdsDxe: loading Boot0001 "UEFI Misc Device"\nBdsDxe: failed to load Boot0001\n' >"${t}/rejected.txt"
    expect_rc "firmware ran, image rejected (no kernel: alive)" 0 "${t}/rejected.txt"
    expect_rc "mutant: no log file at all (QEMU never started)" 1 "${t}/absent.txt"
    : >"${t}/empty.txt"; expect_rc "mutant: empty console log" 1 "${t}/empty.txt"
    printf 'qemu-system-aarch64: invalid option\n' >"${t}/nobanner.txt"; expect_rc "mutant: log without the firmware banner" 1 "${t}/nobanner.txt"
    { cat "${t}/rejected.txt"; echo "kernel: alive"; } >"${t}/booted.txt"; expect_rc "mutant: corrupted image reached kernel: alive" 1 "${t}/booted.txt"
    if [[ ${st} == 0 ]]; then echo "QEMU_SECURITY_SUITE_SELF_TEST: PASS"; exit 0; fi
    echo "QEMU_SECURITY_SUITE_SELF_TEST: FAIL"; exit 1
fi

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
ITERATIONS="${GATE4_SOAK_RUNS:-5}"

# Issue #61: MTTCG hung in 1/40 boots with -smp 1 and 1/40 with cortex-a76;
# single-threaded TCG completed 120/120 boots (40 initial plus 80 confirmation).
qemu_accel=(-accel tcg,thread=single)

command -v qemu-system-aarch64 >/dev/null || { echo "Error: qemu-system-aarch64 not installed" >&2; exit 2; }
command -v swtpm >/dev/null || { echo "Error: swtpm not installed" >&2; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "Error: AAVMF firmware not found" >&2; exit 2; }

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "Building aienos-handoff binary for Gate 4 suite..."
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features handoff --bin aienos-handoff

work="$(mktemp -d)"

cleanup() {
    if [[ -n "${SWTPM_PID:-}" ]] && kill -0 "${SWTPM_PID}" 2>/dev/null; then
        kill "${SWTPM_PID}" 2>/dev/null || true
    fi
    rm -rf "${work}"
}
trap cleanup EXIT

echo "=== Subtest 1: Software TPM 2.0 Integration & Live Boot ==="
tpm_dir="${work}/tpm"
mkdir -p "${tpm_dir}" "${work}/subtest1/esp/EFI/BOOT" "${work}/subtest1/esp/EFI/AIENOS"
touch "${work}/subtest1/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp target/aarch64-unknown-uefi/release/aienos-handoff.efi "${work}/subtest1/esp/EFI/BOOT/BOOTAA64.EFI"

swtpm socket --tpm2 \
    --tpmstate dir="${tpm_dir}" \
    --ctrl type=unixio,path="${tpm_dir}/swtpm-sock" \
    --flags not-need-init,startup-clear &
SWTPM_PID=$!
sleep 1

cp "${vars_fd}" "${work}/subtest1/vars.fd"
log="${work}/subtest1/serial_tpm.log"

set +e
timeout ${AIENOS_QEMU_TIMEOUT:-120} qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3 "${qemu_accel[@]}" -cpu max -smp 4 -m 2048 \
    -chardev socket,id=chrtpm,path="${tpm_dir}/swtpm-sock" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis-device,tpmdev=tpm0 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/subtest1/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/subtest1/esp" \
    -device virtio-blk-pci,drive=esp \
    -device ramfb -display none -nic none \
    -serial file:"${log}" -no-reboot
tpm_status=$?
set -e

tr -d "\r" <"${log}" >"${work}/subtest1/serial_tpm.txt"
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/subtest1/serial_tpm.txt" "${AIENOS_LOG_DIR}/gate4_tpm_serial.log"
if grep -q "kernel: alive" "${work}/subtest1/serial_tpm.txt" && grep -q "report_kind: final" "${work}/subtest1/serial_tpm.txt"; then
    echo "PASS  swTPM live boot reached kernel alive and final report"
else
    echo "FAIL  swTPM live boot did not complete cleanly"
    cat "${work}/subtest1/serial_tpm.txt"
    exit 1
fi

echo "=== Subtest 2: Soak Testing (${ITERATIONS} Sequential Boots) ==="
for i in $(seq 1 "${ITERATIONS}"); do
    soak_work="${work}/soak_${i}"
    mkdir -p "${soak_work}/esp/EFI/BOOT" "${soak_work}/esp/EFI/AIENOS"
    touch "${soak_work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp target/aarch64-unknown-uefi/release/aienos-handoff.efi "${soak_work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${soak_work}/vars.fd"
    soak_log="${soak_work}/serial_soak.log"
    set +e
    timeout ${AIENOS_QEMU_TIMEOUT:-120} qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 "${qemu_accel[@]}" -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${soak_work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${soak_work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -device ramfb -display none -nic none \
        -serial file:"${soak_log}" -no-reboot
    soak_status=$?
    set -e
    tr -d "\r" <"${soak_log}" >"${soak_work}/serial_soak.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${soak_work}/serial_soak.txt" "${AIENOS_LOG_DIR}/gate4_soak_${i}_serial.log"
    if grep -q "kernel: alive" "${soak_work}/serial_soak.txt" && grep -q "report_kind: final" "${soak_work}/serial_soak.txt"; then
        echo "PASS  Soak run ${i}/${ITERATIONS}: clean boot & reset"
    else
        echo "FAIL  Soak run ${i}/${ITERATIONS} failed"
        cat "${soak_work}/serial_soak.txt"
        exit 1
    fi
done

echo "=== Subtest 3: Fault Injection (Corrupted EFI Image) ==="
corrupt_work="${work}/corrupt"
mkdir -p "${corrupt_work}/esp/EFI/BOOT"
head -c 1024 /dev/urandom > "${corrupt_work}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${vars_fd}" "${corrupt_work}/vars.fd"
corrupt_log="${corrupt_work}/serial_corrupt.log"

set +e
timeout 30 qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3 "${qemu_accel[@]}" -cpu max -smp 4 -m 2048 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${corrupt_work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${corrupt_work}/esp" \
    -device virtio-blk-pci,drive=esp \
    -device ramfb -display none -nic none \
    -serial file:"${corrupt_log}" -no-reboot
corrupt_status=$?
set -e

if [[ -f "${corrupt_log}" ]]; then
    tr -d "\r" <"${corrupt_log}" >"${corrupt_work}/serial_corrupt.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${corrupt_work}/serial_corrupt.txt" "${AIENOS_LOG_DIR}/gate4_corrupt_serial.log"
fi
judge_corrupt_rejection "${corrupt_work}/serial_corrupt.txt" || exit 1

echo "TRUST-1 Gate 4 Security Suite: ALL TESTS PASS"
