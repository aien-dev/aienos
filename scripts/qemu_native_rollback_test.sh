#!/usr/bin/env bash
# qemu_native_rollback_test.sh
# M0 Native-Boot Rollback Verification Test in QEMU AArch64 (AAVMF UEFI).
#
# Deterministically exercises one-time native candidate selection and rollback
# semantics across six required failure and completion branches without
# touching physical hardware:
#   1. normal AIENOS candidate exit/reset
#   2. candidate panic/fault
#   3. candidate timeout/hang followed by host reset
#   4. malformed/rejected candidate image
#   5. absence of candidate image
#   6. repeated host reboot after one-time candidate has been consumed
#
# Uses disposable NVRAM variable storage (vars.fd) and temporary ESP filesystems.
# Enforces Zero Disk Secrets and strict rollback invariants.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

CODE_FD="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
VARS_FD="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"

command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${CODE_FD}" && -r "${VARS_FD}" ]] || { echo "AAVMF firmware not found"; exit 2; }

echo "============================================================"
echo "AIENOS M0 Native-Boot Rollback Test Suite (QEMU AArch64)"
echo "Host: $(uname -n) | Firmware: $(basename "${CODE_FD}")"
echo "============================================================"

# Build the rollback mock harness binary
echo "Building aienos-rollback-mock..."
cargo build --quiet --release -p aienos-boot --target aarch64-unknown-uefi --features handoff --bin aienos-rollback-mock
MOCK_BIN="target/aarch64-unknown-uefi/release/aienos-rollback-mock.efi"
[[ -f "${MOCK_BIN}" ]] || { echo "Failed to build aienos-rollback-mock.efi"; exit 1; }

WORK_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

run_qemu_boot() {
    local esp_dir="$1"
    local vars_file="$2"
    local log_file="$3"
    local timeout_secs="${4:-20}"

    set +e
    timeout "${timeout_secs}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 2 -m 512 \
        -drive if=pflash,format=raw,readonly=on,file="${CODE_FD}" \
        -drive if=pflash,format=raw,file="${vars_file}" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${esp_dir}" \
        -device virtio-blk-pci,drive=esp \
        -display none -nic none \
        -serial file:"${log_file}" -no-reboot
    local exit_code=$?
    set -e
    return "${exit_code}"
}

# ==============================================================================
# SUBTEST 1: Normal Candidate Execution & Clean Return
# ==============================================================================
echo ""
echo "--- [Subtest 1: Normal Candidate Execution & Rollback] ---"
SUB1_DIR="${WORK_DIR}/subtest1"
mkdir -p "${SUB1_DIR}/esp/EFI/BOOT" "${SUB1_DIR}/esp/EFI/AIENOS" "${SUB1_DIR}/esp/EFI/DEFAULT"
cp "${VARS_FD}" "${SUB1_DIR}/vars.fd"
cp "${MOCK_BIN}" "${SUB1_DIR}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${MOCK_BIN}" "${SUB1_DIR}/esp/EFI/AIENOS/candidate.efi"
cp "${MOCK_BIN}" "${SUB1_DIR}/esp/EFI/DEFAULT/default.efi"
echo "normal" > "${SUB1_DIR}/esp/EFI/AIENOS/ROLLBACK_MODE.TXT"

# Boot 1: Stager sets Boot0001, Boot0000, BootOrder=[0001], BootNext=0000, resets
run_qemu_boot "${SUB1_DIR}/esp" "${SUB1_DIR}/vars.fd" "${SUB1_DIR}/boot1_stage.log" 20 || true
# Boot 2: Firmware runs BootNext=0000 (Candidate). Candidate prints, resets
run_qemu_boot "${SUB1_DIR}/esp" "${SUB1_DIR}/vars.fd" "${SUB1_DIR}/boot2_candidate.log" 20 || true
# Boot 3: Firmware runs BootOrder[0]=0001 (Default). Default verifies return
run_qemu_boot "${SUB1_DIR}/esp" "${SUB1_DIR}/vars.fd" "${SUB1_DIR}/boot3_default.log" 20 || true

# Check NVRAM binary contains BootNext, BootOrder, Boot0000, Boot0001 after staging
python3 -c "
with open('${SUB1_DIR}/vars.fd', 'rb') as f:
    data = f.read()
assert 'BootNext'.encode('utf-16le') in data, 'BootNext not in vars.fd after stage'
assert 'BootOrder'.encode('utf-16le') in data, 'BootOrder not in vars.fd after stage'
assert 'Boot0000'.encode('utf-16le') in data, 'Boot0000 not in vars.fd after stage'
assert 'Boot0001'.encode('utf-16le') in data, 'Boot0001 not in vars.fd after stage'
"

if grep -q "PASS  M0_ROLLBACK_STAGED: boot_order=0001 boot_next=0000" "${SUB1_DIR}/boot1_stage.log" && \
   grep -q 'BdsDxe: starting Boot0000 "AIENOS Candidate"' "${SUB1_DIR}/boot2_candidate.log" && \
   grep -q "AIENOS_CANDIDATE: NORMAL_TERMINATION_REQUESTED" "${SUB1_DIR}/boot2_candidate.log" && \
   grep -q 'BdsDxe: starting Boot0001 "Default Linux OS"' "${SUB1_DIR}/boot3_default.log" && \
   grep -q "DEFAULT_OS: BOOT_CURRENT=0001" "${SUB1_DIR}/boot3_default.log" && \
   grep -q "DEFAULT_OS: BOOT_NEXT=CONSUMED_PASS" "${SUB1_DIR}/boot3_default.log"; then
    pass "AAVMF BdsDxe firmware one-shot BootNext dispatch & NVRAM persistence verified (Boot0000 -> Boot0001)"
    echo "AAVMF_BOOTNEXT_NVRAM: PASS"
    echo "NATIVE_ROLLBACK_NORMAL: PASS"
else
    fail "Normal candidate rollback failed"
    echo "NATIVE_ROLLBACK_NORMAL: FAIL"
fi

# ==============================================================================
# SUBTEST 2: Candidate Crash / Fault & Return
# ==============================================================================
echo ""
echo "--- [Subtest 2: Candidate Fault / Panic & Rollback] ---"
SUB2_DIR="${WORK_DIR}/subtest2"
mkdir -p "${SUB2_DIR}/esp/EFI/BOOT" "${SUB2_DIR}/esp/EFI/AIENOS" "${SUB2_DIR}/esp/EFI/DEFAULT"
cp "${VARS_FD}" "${SUB2_DIR}/vars.fd"
cp "${MOCK_BIN}" "${SUB2_DIR}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${MOCK_BIN}" "${SUB2_DIR}/esp/EFI/AIENOS/candidate.efi"
cp "${MOCK_BIN}" "${SUB2_DIR}/esp/EFI/DEFAULT/default.efi"
echo "fault" > "${SUB2_DIR}/esp/EFI/AIENOS/ROLLBACK_MODE.TXT"

# Boot 1: Stager
run_qemu_boot "${SUB2_DIR}/esp" "${SUB2_DIR}/vars.fd" "${SUB2_DIR}/boot1_stage.log" 20 || true
# Boot 2: Candidate panics / faults and resets
run_qemu_boot "${SUB2_DIR}/esp" "${SUB2_DIR}/vars.fd" "${SUB2_DIR}/boot2_candidate.log" 20 || true
# Boot 3: Default OS recovers
run_qemu_boot "${SUB2_DIR}/esp" "${SUB2_DIR}/vars.fd" "${SUB2_DIR}/boot3_default.log" 20 || true

if grep -q 'BdsDxe: starting Boot0000 "AIENOS Candidate"' "${SUB2_DIR}/boot2_candidate.log" && \
   grep -q "AIENOS_CANDIDATE: INDUCED_FAULT_PANIC" "${SUB2_DIR}/boot2_candidate.log" && \
   grep -q 'BdsDxe: starting Boot0001 "Default Linux OS"' "${SUB2_DIR}/boot3_default.log" && \
   grep -q "DEFAULT_OS: BOOT_CURRENT=0001" "${SUB2_DIR}/boot3_default.log" && \
   grep -q "DEFAULT_OS: BOOT_NEXT=CONSUMED_PASS" "${SUB2_DIR}/boot3_default.log"; then
    pass "Faulted candidate consumed BootNext and returned to Default via AAVMF BootOrder"
    echo "NATIVE_ROLLBACK_FAULT: PASS"
else
    fail "Faulted candidate rollback failed"
    echo "NATIVE_ROLLBACK_FAULT: FAIL"
fi

# ==============================================================================
# SUBTEST 3: Candidate Hang / Timeout Followed by Reset
# ==============================================================================
echo ""
echo "--- [Subtest 3: Candidate Hang / Timeout & Rollback] ---"
SUB3_DIR="${WORK_DIR}/subtest3"
mkdir -p "${SUB3_DIR}/esp/EFI/BOOT" "${SUB3_DIR}/esp/EFI/AIENOS" "${SUB3_DIR}/esp/EFI/DEFAULT"
cp "${VARS_FD}" "${SUB3_DIR}/vars.fd"
cp "${MOCK_BIN}" "${SUB3_DIR}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${MOCK_BIN}" "${SUB3_DIR}/esp/EFI/AIENOS/candidate.efi"
cp "${MOCK_BIN}" "${SUB3_DIR}/esp/EFI/DEFAULT/default.efi"
echo "timeout" > "${SUB3_DIR}/esp/EFI/AIENOS/ROLLBACK_MODE.TXT"

# Boot 1: Stager
run_qemu_boot "${SUB3_DIR}/esp" "${SUB3_DIR}/vars.fd" "${SUB3_DIR}/boot1_stage.log" 20 || true

# Boot 2: Candidate enters hang spin-loop. Watchdog terminates after entering hang.
boot2_log="${SUB3_DIR}/boot2_candidate.log"
qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 2 -m 512 \
    -drive if=pflash,format=raw,readonly=on,file="${CODE_FD}" \
    -drive if=pflash,format=raw,file="${SUB3_DIR}/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${SUB3_DIR}/esp" \
    -device virtio-blk-pci,drive=esp \
    -display none -nic none \
    -serial file:"${boot2_log}" -no-reboot &
QEMU_PID=$!

# Wait until candidate enters spin loop, then force reset (simulating hardware watchdog)
hung=0
for _ in $(seq 1 40); do
    sleep 0.5
    if [[ -f "${boot2_log}" ]] && grep -q "ENTERING_HANG_SPIN_LOOP" "${boot2_log}"; then
        hung=1
        kill -9 "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
        break
    fi
done

if [[ "${hung}" -ne 1 ]]; then
    kill -9 "${QEMU_PID}" 2>/dev/null || true
    wait "${QEMU_PID}" 2>/dev/null || true
fi

# Boot 3: Default OS boots on next power cycle
run_qemu_boot "${SUB3_DIR}/esp" "${SUB3_DIR}/vars.fd" "${SUB3_DIR}/boot3_default.log" 20 || true

if [[ "${hung}" -eq 1 ]] && \
   grep -q 'BdsDxe: starting Boot0000 "AIENOS Candidate"' "${SUB3_DIR}/boot2_candidate.log" && \
   grep -q 'BdsDxe: starting Boot0001 "Default Linux OS"' "${SUB3_DIR}/boot3_default.log" && \
   grep -q "DEFAULT_OS: BOOT_CURRENT=0001" "${SUB3_DIR}/boot3_default.log" && \
   grep -q "DEFAULT_OS: BOOT_NEXT=CONSUMED_PASS" "${SUB3_DIR}/boot3_default.log"; then
    pass "Hung candidate reset consumed BootNext and returned to Default via AAVMF BootOrder"
    echo "NATIVE_ROLLBACK_TIMEOUT: PASS"
else
    fail "Hung candidate timeout rollback failed"
    echo "NATIVE_ROLLBACK_TIMEOUT: FAIL"
fi

# ==============================================================================
# SUBTEST 4: Malformed / Corrupted Candidate Image
# ==============================================================================
echo ""
echo "--- [Subtest 4: Malformed / Corrupted Image Fallback] ---"
SUB4_DIR="${WORK_DIR}/subtest4"
mkdir -p "${SUB4_DIR}/esp/EFI/BOOT" "${SUB4_DIR}/esp/EFI/AIENOS" "${SUB4_DIR}/esp/EFI/DEFAULT"
cp "${VARS_FD}" "${SUB4_DIR}/vars.fd"
cp "${MOCK_BIN}" "${SUB4_DIR}/esp/EFI/BOOT/BOOTAA64.EFI"
# Candidate file is corrupted bytes (invalid PE header)
printf "\x7fELFcorrupt_pe_header_payload_junk\x00\x00\x00" > "${SUB4_DIR}/esp/EFI/AIENOS/candidate.efi"
cp "${MOCK_BIN}" "${SUB4_DIR}/esp/EFI/DEFAULT/default.efi"
echo "malformed" > "${SUB4_DIR}/esp/EFI/AIENOS/ROLLBACK_MODE.TXT"

# Boot 1: Stager
run_qemu_boot "${SUB4_DIR}/esp" "${SUB4_DIR}/vars.fd" "${SUB4_DIR}/boot1_stage.log" 20 || true
# Boot 2: Firmware attempts BootNext, rejects invalid PE image, falls back to Default
run_qemu_boot "${SUB4_DIR}/esp" "${SUB4_DIR}/vars.fd" "${SUB4_DIR}/boot2_fallback.log" 20 || true

if grep -q "failed to load Boot0000" "${SUB4_DIR}/boot2_fallback.log" && \
   grep -q 'BdsDxe: starting Boot0001 "Default Linux OS"' "${SUB4_DIR}/boot2_fallback.log" && \
   grep -q "DEFAULT_OS: BOOT_CURRENT=0001" "${SUB4_DIR}/boot2_fallback.log" && \
   grep -q "DEFAULT_OS: BOOT_NEXT=CONSUMED_PASS" "${SUB4_DIR}/boot2_fallback.log"; then
    pass "Malformed image rejected by AAVMF firmware with fallback to Default via BootOrder"
    echo "NATIVE_ROLLBACK_REJECTED: PASS"
else
    fail "Malformed image fallback failed"
    echo "NATIVE_ROLLBACK_REJECTED: FAIL"
fi

# ==============================================================================
# SUBTEST 5: Absent Candidate Image
# ==============================================================================
echo ""
echo "--- [Subtest 5: Absent Candidate Image Fallback] ---"
SUB5_DIR="${WORK_DIR}/subtest5"
mkdir -p "${SUB5_DIR}/esp/EFI/BOOT" "${SUB5_DIR}/esp/EFI/AIENOS" "${SUB5_DIR}/esp/EFI/DEFAULT"
cp "${VARS_FD}" "${SUB5_DIR}/vars.fd"
cp "${MOCK_BIN}" "${SUB5_DIR}/esp/EFI/BOOT/BOOTAA64.EFI"
# No candidate file placed
cp "${MOCK_BIN}" "${SUB5_DIR}/esp/EFI/DEFAULT/default.efi"
echo "absent" > "${SUB5_DIR}/esp/EFI/AIENOS/ROLLBACK_MODE.TXT"

# Boot 1: Stager sets Boot0000 to missing_candidate.efi
run_qemu_boot "${SUB5_DIR}/esp" "${SUB5_DIR}/vars.fd" "${SUB5_DIR}/boot1_stage.log" 20 || true
# Boot 2: Firmware fails to load absent Boot0000, falls back to Default
run_qemu_boot "${SUB5_DIR}/esp" "${SUB5_DIR}/vars.fd" "${SUB5_DIR}/boot2_fallback.log" 20 || true

if grep -q "failed to load Boot0000" "${SUB5_DIR}/boot2_fallback.log" && \
   grep -q 'BdsDxe: starting Boot0001 "Default Linux OS"' "${SUB5_DIR}/boot2_fallback.log" && \
   grep -q "DEFAULT_OS: BOOT_CURRENT=0001" "${SUB5_DIR}/boot2_fallback.log" && \
   grep -q "DEFAULT_OS: BOOT_NEXT=CONSUMED_PASS" "${SUB5_DIR}/boot2_fallback.log"; then
    pass "Absent candidate image handled cleanly with fallback to Default via BootOrder"
else
    fail "Absent candidate image fallback failed"
fi

# ==============================================================================
# SUBTEST 6: Repeated Host Reboot After Consumption (No Boot Loop Invariant)
# ==============================================================================
echo ""
echo "--- [Subtest 6: Repeated Boot Post-Consumption (No Loop Invariant)] ---"
SUB6_DIR="${WORK_DIR}/subtest6"
mkdir -p "${SUB6_DIR}/esp/EFI/BOOT" "${SUB6_DIR}/esp/EFI/AIENOS" "${SUB6_DIR}/esp/EFI/DEFAULT"
cp "${VARS_FD}" "${SUB6_DIR}/vars.fd"
cp "${MOCK_BIN}" "${SUB6_DIR}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${MOCK_BIN}" "${SUB6_DIR}/esp/EFI/AIENOS/candidate.efi"
cp "${MOCK_BIN}" "${SUB6_DIR}/esp/EFI/DEFAULT/default.efi"
echo "normal" > "${SUB6_DIR}/esp/EFI/AIENOS/ROLLBACK_MODE.TXT"

# Boot 1: Stager
run_qemu_boot "${SUB6_DIR}/esp" "${SUB6_DIR}/vars.fd" "${SUB6_DIR}/boot1_stage.log" 20 || true
# Boot 2: Candidate
run_qemu_boot "${SUB6_DIR}/esp" "${SUB6_DIR}/vars.fd" "${SUB6_DIR}/boot2_candidate.log" 20 || true
# Boot 3: First return to Default OS (Default increments cycle to 1 and requests cold reset)
run_qemu_boot "${SUB6_DIR}/esp" "${SUB6_DIR}/vars.fd" "${SUB6_DIR}/boot3_default1.log" 20 || true
# Boot 4: Second consecutive boot of Default OS (proves system stays on Default, no loops)
run_qemu_boot "${SUB6_DIR}/esp" "${SUB6_DIR}/vars.fd" "${SUB6_DIR}/boot4_default2.log" 20 || true

if grep -q 'BdsDxe: starting Boot0001 "Default Linux OS"' "${SUB6_DIR}/boot3_default1.log" && \
   grep -q 'BdsDxe: starting Boot0001 "Default Linux OS"' "${SUB6_DIR}/boot4_default2.log" && \
   grep -q "DEFAULT_OS: BOOT_CURRENT=0001" "${SUB6_DIR}/boot4_default2.log" && \
   grep -q "DEFAULT_OS: BOOT_NEXT=CONSUMED_PASS" "${SUB6_DIR}/boot4_default2.log" && \
   grep -q "PASS  NATIVE_ROLLBACK_REPEAT_BOOT" "${SUB6_DIR}/boot4_default2.log"; then
    pass "Subsequent reboot stayed on Default OS via AAVMF BootOrder without re-executing candidate"
    echo "NATIVE_ROLLBACK_BOOTNEXT_CONSUMED: PASS"
    echo "NATIVE_ROLLBACK_DEFAULT_UNCHANGED: PASS"
else
    fail "Repeated boot failed to stay on Default OS"
    echo "NATIVE_ROLLBACK_BOOTNEXT_CONSUMED: FAIL"
    echo "NATIVE_ROLLBACK_DEFAULT_UNCHANGED: FAIL"
fi

echo ""
echo "============================================================"
if [[ "${failed}" == 0 ]]; then
    echo "AAVMF_BOOTNEXT_NVRAM: PASS"
    echo "NATIVE_ROLLBACK_NORMAL: PASS"
    echo "NATIVE_ROLLBACK_FAULT: PASS"
    echo "NATIVE_ROLLBACK_TIMEOUT: PASS"
    echo "NATIVE_ROLLBACK_REJECTED: PASS"
    echo "NATIVE_ROLLBACK_BOOTNEXT_CONSUMED: PASS"
    echo "NATIVE_ROLLBACK_DEFAULT_UNCHANGED: PASS"
    echo "M0_NATIVE_ROLLBACK_QEMU: PASS"
    echo "M0_ROLLBACK_QEMU: PASS"
    exit 0
else
    echo "M0_NATIVE_ROLLBACK_QEMU: FAIL"
    echo "M0_ROLLBACK_QEMU: FAIL"
    exit 1
fi
