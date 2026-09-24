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

# Own target directory: a keyboard-enabled image never lands where hardware
# staging or the other tests pick up the handoff image.
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 AIENOS_KEYBOARD_SECS=60 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features usb-keyboard --bin aienos-handoff \
    --target-dir target/qemu-keyboard

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
cp target/qemu-keyboard/aarch64-unknown-uefi/release/aienos-handoff.efi "${work}/esp/EFI/BOOT/BOOTAA64.EFI"

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
    qemu-system-aarch64 \
        -M virt,virtualization=on -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
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
echo "attempts ${attempt}, ${elapsed} s (commit ${commit:0:12}), sent lines: abc, help, el, mem, exit"
check "left firmware and entered the kernel" "kernel: alive"
check "xHCI controller found before exit" "keyboard: xhci "
check "keyboard attached by the AIENOS driver" "keyboard: ready"
check "typed text echoed on the serial console" "keyboard_echo: ${expected}"
check "line ended by Enter and reported" "keyboard_line: ${expected}\$"
check "keyboard phase finished on Enter" "keyboard: done (enter)"
check "help command output" "commands: help mem el report uptime exit"
check "EL command output" "EL1"
check "memory command output" "conventional_memory_kb:"
check "keyboard phase finished on exit" "keyboard: done (exit)"
if grep -qE "report_kind: (panic|fault)" "${work}/serial.txt"; then
    echo "FAIL  panic or fault reported"
    failed=1
fi

if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"
    cat "${work}/serial.txt"
fi
[[ "${failed}" == 0 ]] && echo "QEMU_KEYBOARD: PASS" || { echo "QEMU_KEYBOARD: FAIL"; exit 1; }
