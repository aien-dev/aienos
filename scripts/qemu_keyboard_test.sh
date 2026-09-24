#!/usr/bin/env bash
# SEED-0A `input.keyboard.usb` proof in QEMU (ADR 0012): boot the handoff
# image built with the `usb-keyboard` feature on a qemu-xhci controller with
# a usb-kbd, wait until the AIENOS driver reports the keyboard ready after
# ExitBootServices, type keys through the QEMU monitor (`sendkey`), and check
# that the same text comes back on the serial console. Emulator only: it says
# nothing about Machine 1 hardware.
#
# A boot that shows no AIENOS output at all is retried (firmware hang before
# AIENOS runs, issue #61); any failure after AIENOS output fails at once.
#
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

keys=(a b c)
expected="abc"
attempts="${AIENOS_KEYBOARD_ATTEMPTS:-3}"
boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
machine="virt,virtualization=on,gic-version=3"

# DMA mode (M3 rule: no SMMU confinement means no DMA).
#   default                    QEMU SMMUv3 (iommu=smmuv3); the xHCI gets DMA
#                              only through a translated SMMU stream.
#   AIENOS_QEMU_SMMU=0         no SMMU, normal build: the keyboard must stay
#                              unavailable with bus mastering off (fail-closed).
#   AIENOS_UNSAFE_DMA_BYPASS=1 no SMMU, UNSAFE debug build that lets the xHCI
#                              DMA to physical memory unconfined. QEMU
#                              debugging only; never part of verify_all.sh.
bypass_feature="unsafe-debug-dma-without-smmu"
if [[ "${AIENOS_UNSAFE_DMA_BYPASS:-0}" == "1" ]]; then
    mode="unsafe-bypass"
    default_features="usb-keyboard,${bypass_feature}"
    target_dir="target/qemu-keyboard-unsafe-dma-bypass"
    echo "################################################################"
    echo "WARNING: AIENOS_UNSAFE_DMA_BYPASS=1: building ${bypass_feature}."
    echo "WARNING: xHCI DMA runs WITHOUT SMMU confinement. QEMU debug only."
    echo "WARNING: this run proves nothing about DMA isolation."
    echo "################################################################"
elif [[ "${AIENOS_QEMU_SMMU:-1}" == "1" ]]; then
    mode="smmu"
    machine+=",iommu=smmuv3"
    default_features="usb-keyboard"
    target_dir="target/qemu-keyboard"
else
    mode="fail-closed"
    default_features="usb-keyboard"
    target_dir="target/qemu-keyboard"
fi
features="${AIENOS_BUILD_FEATURES:-$default_features}"
if [[ "${mode}" != "unsafe-bypass" && ",${features}," == *",${bypass_feature},"* ]]; then
    echo "STOP: ${bypass_feature} requested without AIENOS_UNSAFE_DMA_BYPASS=1"
    exit 2
fi

# Own target directory: a keyboard-enabled image never lands where hardware
# staging or the other tests pick up the handoff image.
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 AIENOS_KEYBOARD_SECS=60 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features "${features}" --bin aienos-handoff \
    --target-dir "${target_dir}"

work="$(mktemp -d)"
qemu_pid=""
cleanup() {
    [[ -n "${qemu_pid}" ]] && kill "${qemu_pid}" 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    rm -rf "${work}"
}
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${target_dir}/aarch64-unknown-uefi/release/aienos-handoff.efi" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"

serial_has() { tr -d '\r' 2>/dev/null <"${work}/serial.log" | grep -q -- "$1"; }
qemu_running() { kill -0 "${qemu_pid}" 2>/dev/null; }

# Wait until the serial log contains one of the patterns or QEMU exits.
wait_for() { # seconds, pattern...
    local deadline=$(( $(date +%s) + $1 )); shift
    while (( $(date +%s) < deadline )) && qemu_running; do
        for p in "$@"; do serial_has "${p}" && return 0; done
        sleep 0.2
    done
    for p in "$@"; do serial_has "${p}" && return 0; done
    return 1
}

stop_qemu() {
    if [[ -n "${qemu_pid}" ]]; then
        kill "${qemu_pid}" 2>/dev/null || true
        wait "${qemu_pid}" 2>/dev/null || true
    fi
    qemu_pid=""
    exec 3>&- 2>/dev/null || true
}

boot_once() {
    cp "${vars_fd}" "${work}/vars.fd"
    rm -f "${work}/serial.log" "${work}/mon.in" "${work}/mon.out"
    mkfifo "${work}/mon.in" "${work}/mon.out"
    # Single-threaded TCG: multi-threaded TCG intermittently loses the
    # firmware's timer wake-up and hangs before AIENOS output (#61).
    local -a smmu_trace=()
    if [[ "${AIENOS_QEMU_SMMU_TRACE:-0}" == "1" ]]; then
        smmu_trace=(-d unimp,guest_errors -trace "smmuv3_*")
    fi
    qemu-system-aarch64 \
        "${smmu_trace[@]}" \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
        -device ramfb -display none -nic none \
        -chardev pipe,id=mon,path="${work}/mon" -mon chardev=mon,mode=readline \
        -serial file:"${work}/serial.log" -no-reboot &
    qemu_pid=$!
    # Drain monitor output so QEMU never blocks writing it.
    cat "${work}/mon.out" >/dev/null &
    exec 3>"${work}/mon.in"

    if ! wait_for "${boot_timeout}" "report_kind: pre_exit"; then
        echo "attempt ${attempt}: no AIENOS output within ${boot_timeout} s (firmware hang, issue #61)"
        stop_qemu
        return 2
    fi
    if wait_for "${boot_timeout}" "keyboard: ready" "keyboard: unavailable" "report_kind: panic" "report_kind: fault" \
        && serial_has "keyboard: ready"; then
        send_line() {
            local key
            for key in "$@"; do echo "sendkey ${key}" >&3; sleep 0.12; done
            echo "sendkey ret" >&3
            sleep 0.5
        }
        send_line "${keys[@]}"
        send_line h e l p
        send_line e l
        send_line m e m
        send_line e x i t
    fi
    local deadline=$(( $(date +%s) + 90 ))
    while qemu_running && (( $(date +%s) < deadline )); do sleep 0.5; done
    qemu_running && echo "QEMU still running after the keyboard phase"
    stop_qemu
    return 0
}

started=$(date +%s)
attempt=1
while :; do
    status=0
    boot_once || status=$?
    [[ "${status}" != 2 || "${attempt}" -ge "${attempts}" ]] && break
    attempt=$(( attempt + 1 ))
done
elapsed=$(( $(date +%s) - started ))

tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt" 2>/dev/null || true
failed=0
check() { # description, pattern
    if grep -q -- "$2" "${work}/serial.txt"; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        failed=1
    fi
}
check_absent() { # description, pattern
    if grep -q -- "$2" "${work}/serial.txt"; then
        echo "FAIL  $1"
        failed=1
    else
        echo "PASS  $1"
    fi
}
echo "attempts ${attempt}, ${elapsed} s (commit ${commit:0:12}), dma mode ${mode}, sent lines: abc, help, el, mem, exit"
check "left firmware and entered the kernel" "kernel: alive"
check "xHCI controller found before exit" "keyboard: xhci "
check "PCI segment swept for bus masters after exit" "dma_sweep: seg "
check_absent "no endpoint left with bus master stuck on" "dma_sweep: bme STUCK"
check "xHCI bus master off before the DMA gate" "xhci_pci: command=0x[0-9a-f]* bus_master=off"
if [[ "${mode}" == "fail-closed" ]]; then
    check "xHCI DMA denied without an SMMU" "dma_gate: xhci denied (NoSmmu), bus master stays off"
    check "keyboard fail-closed without an SMMU" "keyboard: unavailable (SMMU DMA isolation not active)"
    check_absent "xHCI never granted DMA" "dma_gate: xhci granted"
    check_absent "keyboard never attached" "keyboard: ready"
else
    check "keyboard attached by the AIENOS driver" "keyboard: ready"
    if [[ "${mode}" == "smmu" ]]; then
        check "IORT stream configured for xHCI DMA" "smmu: enabled"
        check "xHCI DMA window translated" "smmu_dma_window: xhci only, translation active"
        check "xHCI DMA granted only as confined" "dma_gate: xhci granted (Confined), bus master on"
    else
        check "unsafe bypass build announced on serial" "WARNING: UNSAFE DMA BYPASS BUILD"
        check "unsafe bypass grant announced on serial" "WARNING: UNSAFE DMA BYPASS ACTIVE"
        check "xHCI DMA granted through the unsafe bypass" "dma_gate: xhci granted (UnsafeBypass)"
    fi
    check "typed text echoed on the serial console" "keyboard_echo: ${expected}"
    check "line ended by Enter and reported" "keyboard_line: ${expected}\$"
    check "keyboard phase finished on Enter" "keyboard: done (enter)"
    check "help command output" "commands: help mem el report uptime exit"
    check "EL command output" "EL1"
    check "memory command output" "conventional_memory_kb:"
    check "keyboard phase finished on exit" "keyboard: done (exit)"
    check "xHCI bus master revoked after the keyboard phase" "dma_gate: xhci bus master revoked"
fi
if [[ "${mode}" != "unsafe-bypass" ]]; then
    check_absent "no unsafe DMA bypass in this image" "UNSAFE DMA BYPASS"
fi
if grep -qE "report_kind: (panic|fault)" "${work}/serial.txt"; then
    echo "FAIL  panic or fault reported"
    failed=1
fi

if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"
    cat "${work}/serial.txt"
fi
if [[ "${mode}" == "unsafe-bypass" ]]; then
    echo "WARNING: this was an UNSAFE DMA BYPASS run (no SMMU confinement)."
fi
[[ "${failed}" == 0 ]] && echo "QEMU_KEYBOARD: PASS (${mode})" || { echo "QEMU_KEYBOARD: FAIL (${mode})"; exit 1; }
