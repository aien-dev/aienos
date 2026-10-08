#!/usr/bin/env bash
# KEYBOARD gate for the AIENOS C kernel: rows 25-32 (C-only 30a-30c, 32a, 32b) of native/kernel/GATES.md
# "SEED-0A keyboard" (Rust oracle: scripts/qemu_keyboard_test.sh with SMMU=1
# and SMMU=0) plus the C-only rows 30a-30c (recovery access, line overflow).
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# Boots the full C image (make full) in QEMU AArch64 with UEFI (AAVMF), an
# NVMe disk (normal full boot), a qemu-xhci controller with a usb-kbd on it
# (the Rust gate's devices) and no NIC. The devices stage
# (native/kernel/dev/devices.c) runs the post-exit bus-master sweep first and
# the xHCI DMA fence (native/kernel/dev/xhci_fence.c) last; inside the
# confined grant the operator phase (native/kernel/dev/usb_kbd.c) drives the
# keyboard. Keys are typed from OUTSIDE the guest through the QEMU monitor
# ("sendkey", as the Rust gate does); the kernel never fakes the device.
#
#  boot kbd-smmu      iommu=smmuv3 (Rust SMMU=1). No key in the recovery
#                     window (normal boot by timeout), then the lines "abc",
#                     "help", "el", "mem", 65 x "x" (overflow) and "exit":
#   row 25  "keyboard: xhci SSSS:BB:DD.F mmio 0x.." (found on the ECAM walk)
#   row 26  "dma_sweep: seg 0000 bus .." before the first device DMA grant,
#           no "dma_sweep: bme STUCK"
#   row 27  "xhci_pci: command=0x.... bus_master=off" before the xHCI DMA gate
#   row 29  "keyboard: ready", "keyboard_echo: abc", "keyboard_line: abc",
#           "keyboard: done (enter)", all between the confined grant and the
#           revoke
#   row 30  "commands: help mem el report uptime exit", "EL1",
#           "conventional_memory_kb: N" (N > 0), "keyboard: done (exit)"
#   row 30a (C only) recovery access offered after "keyboard: ready" and
#           decided "choice=normal reason=timeout" before the shell starts
#   row 30c (C only) the 65-key line is refused ("keyboard_line: overflow
#           (line refused: 65 keys typed, limit 64)"), never echoed back as a
#           line and never run as a command
#   row 31  grant confined ("smmu_dma_window: xhci only, translation active",
#           "dma_gate: xhci granted (Confined), bus master on"), controller
#           halted, "dma_gate: xhci bus master revoked", COMMAND read back
#           "xhci_pci: after phase command=0x.... bus_master=off", "smmu: xhci
#           stream 0x.. returned to abort (rc=0)", in that order, all before
#           the "devices: xhci=fenced (rc=0)" line
#   row 32  no "report_kind: (panic|fault)", "report_kind: final", QEMU exit 0
#   row 32a (C only, every boot; NEXT-PHASE-3 cut 2) the ACPI platform walker runs on
#           QEMU's own tables: "acpi_scan: tables=N refused=0
#           first_refusal=0 devices=M" with N, M > 0, the positive control
#           "acpi_scan: control ARMH0011 <name> mmio=0x9000000+0x1000" (the
#           QEMU virt PL011 UART), "xhci_acpi: 0 platform controller(s)" (QEMU
#           virt describes no platform xHCI), and the PCI path is kept: no
#           "xhci_plat:" line and no fallback to platform controllers
#   row 32b (C only) hardware expectation, always NOT_RUN here: the exact lines the
#           DGX Spark should print, predicted by tools/ck_acpi_scan.c from
#           its firmware tables (native/kernel/tests/fixtures/
#           spark_xhci_acpi_expected.txt); never counted toward the verdict
#  boot kbd-nosmmu    no SMMU (Rust SMMU=0), same image, no keys:
#   rows 25, 26, 27, 32, 32a as above
#   row 28  "dma_gate: xhci denied (NoSmmu), bus master stays off", "keyboard:
#           unavailable (SMMU DMA isolation not active)", COMMAND read back
#           after the deny with bus_master=off, no "dma_gate: xhci granted",
#           no "keyboard: ready"
#   row 30a recovery access reported unavailable, normal boot
#           ("choice=normal reason=no-keyboard")
#  boot kbd-recovery  iommu=smmuv3, same image; "r" typed in the recovery window:
#   row 30b (C only) "recovery_access: choice=recovery reason=key-r"; then, in
#           order: xHCI bus master revoked, xHCI stream back to abort,
#           "devices: recovery halt nvme=released virtio_net=released
#           xhci=released", the stub's identity line (the SHA-256 this script
#           recomputes from the commit), "recovery_console: halted"; no shell,
#           no Store stage, no final report, no panic or fault, and QEMU still
#           running 3 s after the halt line (halted, not reset; the script
#           then stops QEMU)
# kbd-smmu and kbd-nosmmu must also pass every M1 check
# (scripts/lib_ck_m1_checks.sh); all boots carry no TEST-ONLY mutation
# banner, no "UNSAFE DMA BYPASS" and no "keyboard: hid NOT_IMPLEMENTED".
#
# --mutation (self-test of the DMA checks; TEST-ONLY images): builds
# "make full CK_TEST_XHCI_MUTATION=<m>" for each mutation and boots it once
# without keys; the named row must FAIL (and the boot must still reach
# "report_kind: final" with row 25 PASS, so the failure is the mutation's,
# not a dead boot):
#   bm-left-on     xHCI bus mastering switched back on after the sweep (smmu)  -> row 27
#   no-revoke      release skips the bus-master clear (smmu)                    -> row 31
#   grant-no-smmu  DMA granted without an SMMU (nosmmu)                         -> row 28
#   no-sweep       post-exit bus-master sweep skipped (nosmmu)                  -> row 26
# It also checks the build refuses a mutation together with
# CK_HARDWARE_STAGING=1 (and with CK_QEMU_UNSAFE_DMA=1), and that the default
# image carries no mutation banner.
#
# Env: AIENOS_QEMU_SMMU=1 runs only kbd-smmu and kbd-recovery, =0 only
# kbd-nosmmu (a partial run: the gate verdict is then NOT_RUN).
# Like the FPU/INFER/SCREEN children: NOT_RUN (exit 3) while the machine quiet
# flag (AIENOS_QUIET_FLAG, default ~/workspace/.spark-quiet) exists, which this
# script only reads and never writes, or while the QEMU gate lock
# (AIENOS_GATE_LOCK, default ~/workspace/.qemu-gate-lock, exclusive create) is
# held by another gate run.
# Final lines (normal run): one "KEYBOARD_ROW <n>: PASS|FAIL|NOT_RUN (...)"
# per row, "AIENOS_CK_KEYBOARD_DMA: PASS|FAIL (rows 25-28,31,32)" and
# "AIENOS_CK_KEYBOARD: PASS|FAIL|NOT_RUN (...)" (read by scripts/ck_gates.sh).
# Exit 0 when the gate PASSes, 1 FAIL, 2 missing tools, 3 NOT_RUN.
# --mutation: "AIENOS_CK_KEYBOARD_MUTATION: PASS|FAIL"; exit 0 / 1.
# Needs qemu-system-aarch64, AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64)
# and a C compiler.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mutation_run=0
case "${1:-}" in
    "") ;;
    --mutation) mutation_run=1 ;;
    *) echo "usage: $0 [--mutation]"; exit 2 ;;
esac
final_tag="AIENOS_CK_KEYBOARD"
[[ "${mutation_run}" == 0 ]] || final_tag="AIENOS_CK_KEYBOARD_MUTATION"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${final_tag}: NOT_RUN (qemu-system-aarch64 missing)"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${final_tag}: NOT_RUN (AAVMF missing)"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel"
mk() { make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" "$@"; }
mk full >/dev/null
default_efi="${out}/full/BOOTAA64.EFI"
mutations=(bm-left-on no-revoke grant-no-smmu no-sweep)
if [[ "${mutation_run}" == 1 ]]; then
    for m in "${mutations[@]}"; do mk full CK_TEST_XHCI_MUTATION="${m}" >/dev/null; done
fi

# Machine-wide quiet flag: read only, never written here (Drake's rule: no
# agent raises it without approval). If someone holds it: NOT_RUN.
# Machine quiet flag (read only) and the QEMU gate lock (one gate at a time):
# scripts/lib_gate_hold.sh (aienos#278).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check; then
    echo "NOT_RUN  ${gh_why}"
    echo "${final_tag}: NOT_RUN (quiet flag held)"
    exit 3
fi
if ! gh_lock_take qemu_ck_keyboard_test "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "${final_tag}: NOT_RUN (QEMU gate lock held)"
    exit 3
fi
# Release only this run's own gate lock record, at most once.
release_lock() { gh_lock_release; }
top="$(mktemp -d)"
qemu_pid=""
cleanup() {
    [[ -z "${qemu_pid}" ]] || kill "${qemu_pid}" 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    rm -rf "${top}"
    release_lock
}
trap cleanup EXIT

# shellcheck source=scripts/lib_ck_m1_checks.sh
source "${repo_root}/scripts/lib_ck_m1_checks.sh"
img_bytes=67108864
image="${top}/nvme.img"
truncate -s "${img_bytes}" "${image}"
m1_fail=0
boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
overflow_keys=65

serial_has() { tr -d '\r' 2>/dev/null <"${work}/serial.log" | grep -qE -- "$1"; }
qemu_running() { [[ -n "${qemu_pid}" ]] && kill -0 "${qemu_pid}" 2>/dev/null; }
# wait_for seconds ERE...: 0 once the serial log matches one, 1 on timeout or QEMU exit.
wait_for() {
    local deadline=$(( $(date +%s) + $1 )) p; shift
    while (( $(date +%s) < deadline )) && qemu_running; do
        for p in "$@"; do serial_has "${p}" && return 0; done
        sleep 0.2
    done
    for p in "$@"; do serial_has "${p}" && return 0; done
    return 1
}
# Keys go in through the QEMU monitor (outside the guest), 0.12 s apart.
send_keys() { local k; for k in "$@"; do echo "sendkey ${k}" >&3; sleep 0.12; done; }
send_line() { send_keys "$@" ret; sleep 0.5; }

# boot <name> <efi> smmu|nosmmu <action>: one QEMU boot; serial text in
# ${work}/serial.txt, QEMU status in qemu_status, for recovery boots
# halted_running=yes|no. action: none | shell | recovery.
boot() {
    work="${top}/$1"
    local action="$4"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    rm -f "${work}/mon.in" "${work}/mon.out"
    mkfifo "${work}/mon.in" "${work}/mon.out"
    : >"${work}/serial.log"
    local machine="virt,virtualization=on,gic-version=3"
    [[ "$3" != smmu ]] || machine+=",iommu=smmuv3"
    # Issue #61: single-threaded TCG (see qemu_boot_test.sh).
    timeout "${boot_timeout}" qemu-system-aarch64 \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${image}" \
        -device nvme,drive=nvme0,serial=aienos-kbd-test \
        -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
        -device ramfb -display none -nic none \
        -chardev pipe,id=mon,path="${work}/mon" -mon chardev=mon,mode=readline \
        -serial file:"${work}/serial.log" -no-reboot 2>"${work}/qemu.err" &
    qemu_pid=$!
    cat "${work}/mon.out" >/dev/null &   # drain monitor output so QEMU never blocks
    exec 3>"${work}/mon.in"
    halted_running=no
    case "${action}" in
        shell)
            # No key in the recovery window: the boot must continue by timeout.
            if wait_for "${boot_timeout}" '^keyboard: shell ready' '^keyboard: unavailable' '^report_kind: (panic|fault|final)'; then
                if serial_has '^keyboard: shell ready'; then
                    send_line a b c
                    send_line h e l p
                    send_line e l
                    send_line m e m
                    local -a xs=()
                    for ((i = 0; i < overflow_keys; i++)); do xs+=(x); done
                    send_line "${xs[@]}"
                    send_line e x i t
                fi
            fi ;;
        recovery)
            if wait_for "${boot_timeout}" '^recovery_access: waiting' '^recovery_access: unavailable' '^report_kind: (panic|fault|final)'; then
                if serial_has '^recovery_access: waiting'; then
                    send_keys r
                    if wait_for 60 '^recovery_console: halted' '^report_kind: (panic|fault|final)' && serial_has '^recovery_console: halted'; then
                        sleep 3
                        qemu_running && halted_running=yes
                    fi
                fi
            fi
            kill "${qemu_pid}" 2>/dev/null || true ;;
    esac
    set +e
    wait "${qemu_pid}"
    qemu_status=$?
    set -e
    qemu_pid=""
    exec 3>&- 2>/dev/null || true
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_keyboard_$1.log"
    echo "== boot $1 ($3, keys: ${action}): qemu exit ${qemu_status}$([[ "${action}" != recovery ]] || echo ", halted_running=${halted_running}")"
}

# Row bookkeeping: rowfail[n]=1 once any check of row n failed in this
# evaluation; rowmodes[n] lists the boots that checked it.
all_rows=(25 26 27 28 29 30 30a 30b 30c 31 32 32a)
declare -A rowfail rowmodes
reset_rows() { local r; for r in "${all_rows[@]}"; do rowfail[$r]=0; rowmodes[$r]=""; done; }
reset_rows
mode=""
note_mode() { [[ " ${rowmodes[$1]} " == *" ${mode} "* ]] || rowmodes[$1]="${rowmodes[$1]:+${rowmodes[$1]} }${mode}"; }
rpass() { note_mode "$1"; echo "ROW $1 PASS  ${mode}: $2"; }
rfail() { note_mode "$1"; rowfail[$1]=1; echo "ROW $1 FAIL  ${mode}: $2"; }
rcheck() { # row, description, ERE pattern
    if grep -qE -- "$3" "${work}/serial.txt"; then rpass "$1" "$2"; else rfail "$1" "$2"; fi
}
rabsent() { # row, description, ERE pattern
    if grep -qE -- "$3" "${work}/serial.txt"; then rfail "$1" "$2"; else rpass "$1" "$2"; fi
}
line_of() { { grep -nE -m1 -- "$1" "${work}/serial.txt" || true; } | cut -d: -f1; }
before() { # row, description, earlier ERE, later ERE: both present, earlier first
    local a b
    a="$(line_of "$3")"; b="$(line_of "$4")"
    if [[ -n "${a}" && -n "${b}" && "${a}" -lt "${b}" ]]; then rpass "$1" "$2 (lines ${a} < ${b})"
    else rfail "$1" "$2 (lines ${a:-none} ${b:-none})"; fi
}

# evaluate_dma smmu|nosmmu|recovery: rows 25-28 and 31 on ${work}/serial.txt.
evaluate_dma() {
    mode="$1"
    rcheck 25 "xHCI found on the ECAM walk (Rust: keyboard: xhci )" \
        '^keyboard: xhci 0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7] mmio 0x[0-9a-f]+ '
    evaluate_acpi
    rcheck 26 "post-exit bus-master sweep of the segment" \
        '^dma_sweep: seg 0000 bus [0-9a-f]{2}-[0-9a-f]{2} functions=[1-9][0-9]* bridges=[0-9]+ bridges_bme=[0-9]+ endpoints_bme_found=[0-9]+ still_enabled=0$'
    rabsent 26 "no endpoint left with bus master stuck on" '^dma_sweep: bme STUCK'
    before 26 "sweep before the first device DMA gate" '^dma_sweep: seg ' '^dma_gate: '
    before 26 "sweep before the xHCI is looked at" '^dma_sweep: seg ' '^keyboard: xhci '
    rcheck 27 "xHCI bus master off before the DMA gate (Rust: xhci_pci: command=0x.. bus_master=off)" \
        '^xhci_pci: command=0x[0-9a-f]{4} bus_master=off$'
    before 27 "COMMAND read back before the xHCI DMA gate" '^xhci_pci: command=' '^dma_gate: xhci '
    if [[ "${mode}" == nosmmu ]]; then
        rcheck 28 "xHCI DMA denied without an SMMU" '^dma_gate: xhci denied \(NoSmmu\), bus master stays off$'
        rcheck 28 "keyboard fail-closed without an SMMU" '^keyboard: unavailable \(SMMU DMA isolation not active\)$'
        rcheck 28 "COMMAND read back after the deny: bus master off" '^xhci_pci: after deny command=0x[0-9a-f]{4} bus_master=off$'
        rabsent 28 "xHCI never granted DMA" 'dma_gate: xhci granted'
        rabsent 28 "keyboard never attached" 'keyboard: ready'
        rabsent 28 "no xHCI SMMU window claimed without an SMMU" '^smmu_dma_window: xhci'
        rcheck 28 "devices stage reports the deny" '^devices: xhci=denied \(rc=-603\)$'
    else
        rcheck 31 "xHCI SMMU window (Rust: smmu_dma_window: xhci only, translation active)" \
            '^smmu_dma_window: xhci only, translation active iova=0x[0-9a-f]+ len=0x[0-9a-f]+ rid=0x[0-9a-f]+$'
        rcheck 31 "xHCI DMA granted only as confined" '^dma_gate: xhci granted \(Confined\), bus master on$'
        rabsent 31 "no unconfined xHCI grant" 'dma_gate: xhci granted \((UnsafeBypass|TestMutation)'
        rcheck 31 "controller halted before the revoke" '^xhci: halt before revoke usbcmd=0x[0-9a-f]{8} usbsts=0x[0-9a-f]{8} halted=yes$'
        rcheck 31 "xHCI bus master revoked after the phase" '^dma_gate: xhci bus master revoked$'
        rcheck 31 "COMMAND read back after the phase: bus master off" '^xhci_pci: after phase command=0x[0-9a-f]{4} bus_master=off$'
        rcheck 31 "xHCI SMMU stream returned to abort" '^smmu: xhci stream 0x[0-9a-f]+ returned to abort \(rc=0\)$'
        rabsent 31 "no revoke failure" '^dma_gate: xhci bus master revoke FAILED'
        before 31 "order: grant < revoke" '^dma_gate: xhci granted \(Confined\)' '^dma_gate: xhci bus master revoked$'
        before 31 "order: revoke < COMMAND read back" '^dma_gate: xhci bus master revoked$' '^xhci_pci: after phase command='
        before 31 "order: read back < stream abort" '^xhci_pci: after phase command=' '^smmu: xhci stream .* returned to abort'
        before 31 "order: stream abort < end of the xHCI phase (not a reset-time revoke)" \
            '^smmu: xhci stream .* returned to abort' '^devices: xhci=fenced \(rc=0\)$'
    fi
}

# evaluate_acpi: row 32a (every boot). QEMU virt has no platform xHCI, so the
# walker must find its tables, the UART control and zero controllers, and the
# PCI xHCI path must not fall back to the platform list.
evaluate_acpi() {
    rcheck 32a "ACPI walker read QEMU's DSDT/SSDTs with no refusal" \
        '^acpi_scan: tables=[1-9][0-9]* refused=0 first_refusal=0 devices=[1-9][0-9]* \(static scan; _STA not evaluated\)$'
    rcheck 32a "positive control: QEMU virt UART ARMH0011 at 0x9000000" \
        '^acpi_scan: control ARMH0011 [A-Z0-9_]{1,4} mmio=0x9000000\+0x1000$'
    rcheck 32a "no ACPI platform xHCI on QEMU virt" '^xhci_acpi: 0 platform controller\(s\)$'
    rabsent 32a "PCI path kept: no platform controller tried" '^(xhci_plat: |keyboard: (no PCI xHCI controller|none on the PCI xHCI))'
}

# evaluate_final smmu|nosmmu: row 32 for a boot that must end with the final report.
evaluate_final() {
    mode="$1"
    rabsent 32 "no panic or fault" '^report_kind: (panic|fault)'
    rcheck 32 "final report reached" 'report_kind: final'
    if [[ "${qemu_status}" == 0 ]]; then rpass 32 "QEMU exit 0 after PSCI reset"; else rfail 32 "QEMU exit ${qemu_status} (expected 0)"; fi
}

# evaluate_input smmu|nosmmu: rows 29, 30, 30a, 30c.
evaluate_input() {
    mode="$1"
    if [[ "${mode}" == nosmmu ]]; then
        rcheck 30a "recovery access reported unavailable, normal boot" \
            '^recovery_access: unavailable \(no operator keyboard: xhci=denied\); choice=normal reason=no-keyboard$'
        rabsent 30a "no recovery wait without a keyboard" '^recovery_access: waiting'
        return
    fi
    rcheck 29 "keyboard attached by the C driver (Rust: keyboard: ready)" '^keyboard: ready \(port [0-9]+, slot [0-9]+, endpoint 0x8[0-9a-f]\)$'
    before 29 "keyboard attached inside the confined grant" '^dma_gate: xhci granted \(Confined\)' '^keyboard: ready'
    rcheck 29 "typed text echoed (Rust: keyboard_echo: abc)" '^keyboard_echo: abc$'
    rcheck 29 "line ended by Enter and reported (Rust: keyboard_line: abc)" '^keyboard_line: abc$'
    rcheck 29 "keyboard phase line finished on Enter (Rust: keyboard: done (enter))" '^keyboard: done \(enter\)$'
    before 29 "typed line before the revoke" '^keyboard_line: abc$' '^dma_gate: xhci bus master revoked$'
    rcheck 30 "help command output" '^commands: help mem el report uptime exit$'
    rcheck 30 "EL command output" '^EL1$'
    rcheck 30 "memory command output" '^conventional_memory_kb: [1-9][0-9]*$'
    rcheck 30 "keyboard phase finished on exit" '^keyboard: done \(exit\)$'
    before 30 "exit before the revoke" '^keyboard: done \(exit\)$' '^dma_gate: xhci bus master revoked$'
    rcheck 30a "recovery window offered" '^recovery_access: waiting [0-9]+ ms for an operator key'
    rcheck 30a "no key: normal boot by timeout" '^recovery_access: choice=normal reason=timeout$'
    before 30a "keyboard ready < recovery window" '^keyboard: ready' '^recovery_access: waiting'
    before 30a "recovery decision < shell" '^recovery_access: choice=' '^keyboard: shell ready'
    rabsent 30a "no recovery console on a normal boot" '^recovery_console:'
    rcheck 30c "overlong line refused (fail closed)" \
        "^keyboard_line: overflow \\(line refused: ${overflow_keys} keys typed, limit 64\\)\$"
    rabsent 30c "overlong line never reported as a line" '^keyboard_line: x'
    rabsent 30c "overlong line never run as a command" '^unknown command: x'
}

# evaluate_recovery: rows 30b, 31 and the recovery boot's no-panic check.
evaluate_recovery() {
    mode=recovery
    local want
    want="$(printf 'AIENOS-CK-RECOVERY-IDENTITY-V1\0%s' "${commit}" | sha256sum | cut -d' ' -f1)"
    rcheck 29 "keyboard attached by the C driver" '^keyboard: ready \(port [0-9]+, slot [0-9]+, endpoint 0x8[0-9a-f]\)$'
    rcheck 30b "operator key r selects the recovery console" '^recovery_access: choice=recovery reason=key-r$'
    before 30b "order: choice < xHCI revoke" '^recovery_access: choice=recovery' '^dma_gate: xhci bus master revoked$'
    before 30b "order: xHCI stream abort < recovery halt line" '^smmu: xhci stream .* returned to abort \(rc=0\)$' '^devices: recovery halt '
    rcheck 30b "every device DMA released before the halt" '^devices: recovery halt nvme=released virtio_net=released xhci=released$'
    rcheck 30b "stub prints the identity digest (recomputed here from the commit)" \
        "^recovery_console: identity build_sha256=${want} commit=${commit} "
    before 30b "order: recovery halt line < identity" '^devices: recovery halt ' '^recovery_console: identity '
    before 30b "order: identity < halted" '^recovery_console: identity ' '^recovery_console: halted'
    rabsent 30b "no shell on the recovery path" '^keyboard: shell ready'
    rabsent 30b "no Store stage on the recovery path" '^stage store'
    rabsent 30b "no final report on the recovery path" 'report_kind: final'
    rabsent 30b "no panic or fault" '^report_kind: (panic|fault)'
    if [[ "${halted_running}" == yes ]]; then rpass 30b "QEMU still running 3 s after the halt line (halted, not reset)"
    else rfail 30b "QEMU was not running after the halt line (or the halt line never came)"; fi
}

image_checks() {
    check_absent "no TEST-ONLY mutation banner in the default image" "TEST-ONLY xHCI MUTATION"
    check_absent "no unsafe DMA bypass in this image" "UNSAFE DMA BYPASS"
    check_absent "no leftover NOT_IMPLEMENTED HID marker" "^keyboard: hid NOT_IMPLEMENTED"
    check "image is this commit" "aienos_commit: ${commit}"
}

if [[ "${mutation_run}" == 0 ]]; then
    modes=(smmu nosmmu recovery)
    case "${AIENOS_QEMU_SMMU:-}" in
        1) modes=(smmu recovery) ;;
        0) modes=(nosmmu) ;;
        "") ;;
        *) echo "AIENOS_QEMU_SMMU must be 1, 0 or unset"; release_lock; echo "${final_tag}: NOT_RUN (bad AIENOS_QEMU_SMMU)"; exit 2 ;;
    esac
    other_fail=0
    for md in "${modes[@]}"; do
        case "${md}" in
            smmu) boot kbd-smmu "${default_efi}" smmu shell ;;
            nosmmu) boot kbd-nosmmu "${default_efi}" nosmmu none ;;
            recovery) boot kbd-recovery "${default_efi}" smmu recovery ;;
        esac
        failed=0
        if [[ "${md}" != recovery ]]; then
            ck_m1_checks
            [[ "${failed}" == 0 ]] || m1_fail=1
        fi
        failed=0
        image_checks
        [[ "${failed}" == 0 ]] || other_fail=1
        failed=0
        evaluate_dma "${md}"
        if [[ "${md}" == recovery ]]; then
            evaluate_recovery
        else
            evaluate_input "${md}"
            evaluate_final "${md}"
        fi
        echo "RECOVERY_CHOICE kbd-${md}: $(grep -m1 -E '^recovery_access: (choice=|unavailable)' "${work}/serial.txt" || echo 'none recorded')"
    done
    release_lock
    any_fail=0
    for r in "${all_rows[@]}"; do any_fail=$(( any_fail | rowfail[$r] )); done
    if [[ "${m1_fail}${other_fail}" != 00 || -n "${AIENOS_QEMU_VERBOSE:-}" || "${any_fail}" != 0 ]]; then
        for s in "${top}"/*/serial.txt; do
            echo "---- serial console $(basename "$(dirname "${s}")") (device lines) ----"
            grep -E '^(keyboard|xhci|xhci_pci|dma_sweep|dma_gate|smmu|devices:|stage |report_kind:|recovery_|commands|EL[0-9]|conventional)' "${s}" | head -80 || true
        done
    fi
    dma_fail=$(( m1_fail | other_fail ))
    gate_fail=$(( m1_fail | other_fail ))
    partial=0
    [[ -z "${AIENOS_QEMU_SMMU:-}" ]] || partial=1
    echo "== per-row results (QEMU only; hardware NOT_RUN)"
    for r in "${all_rows[@]}"; do
        if [[ -z "${rowmodes[$r]}" ]]; then
            echo "KEYBOARD_ROW ${r}: NOT_RUN (not checked in this run's modes)"
            partial=1
        elif [[ "${rowfail[$r]}" == 0 && "${m1_fail}" == 0 ]]; then
            echo "KEYBOARD_ROW ${r}: PASS (${rowmodes[$r]})"
        else
            echo "KEYBOARD_ROW ${r}: FAIL (${rowmodes[$r]}$([[ "${m1_fail}" == 0 ]] || echo '; an M1 check failed'))"
            gate_fail=1
            case "${r}" in 25|26|27|28|31|32) dma_fail=1 ;; esac
        fi
    done
    echo "KEYBOARD_ROW 32b: NOT_RUN (hardware only; expected DGX Spark lines: native/kernel/tests/fixtures/spark_xhci_acpi_expected.txt)"
    [[ "${m1_fail}" == 0 ]] || echo "M1 checks failed on at least one boot: no row can pass"
    [[ "${other_fail}" == 0 ]] || echo "image checks failed (mutation banner, unsafe bypass, HID marker or commit)"
    if [[ "${dma_fail}" == 0 ]]; then echo "AIENOS_CK_KEYBOARD_DMA: PASS (rows 25-28,31,32; modes ${modes[*]})"; else echo "AIENOS_CK_KEYBOARD_DMA: FAIL (rows 25-28,31,32; modes ${modes[*]})"; fi
    if [[ "${gate_fail}" != 0 ]]; then
        echo "${final_tag}: FAIL (rows 25-32,30a-30c,32a; modes ${modes[*]}; QEMU only)"
        exit 1
    elif [[ "${partial}" != 0 ]]; then
        echo "${final_tag}: NOT_RUN (partial run, modes ${modes[*]}; every boot is needed for the gate)"
        exit 3
    fi
    echo "${final_tag}: PASS (rows 25-32,30a-30c,32a; boots kbd-smmu kbd-nosmmu kbd-recovery; QEMU only, hardware NOT_RUN)"
    exit 0
fi

# ---- --mutation: every mutation must make its row FAIL ----
mut_fail=0
mut_ok() { echo "MUTATION PASS  $1"; }
mut_bad() { echo "MUTATION FAIL  $1"; mut_fail=1; }
if grep -aqF "TEST-ONLY xHCI MUTATION" "${default_efi}"; then mut_bad "default image carries the mutation banner"; else mut_ok "default image carries no mutation banner"; fi
for combo in "CK_HARDWARE_STAGING=1" "CK_QEMU_UNSAFE_DMA=1"; do
    set +e
    msg="$(make -s -n -C native/kernel OUT="${top}/refuse" full CK_TEST_XHCI_MUTATION=no-revoke "${combo}" 2>&1)"
    st=$?
    set -e
    if [[ "${st}" != 0 ]] && grep -qE "CK_TEST_XHCI_MUTATION.*cannot be combined with ${combo%%=*}" <<<"${msg}"; then
        mut_ok "build refuses CK_TEST_XHCI_MUTATION with ${combo}"
    else
        mut_bad "build did not refuse CK_TEST_XHCI_MUTATION with ${combo} (status ${st}): $(head -c 200 <<<"${msg}")"
    fi
done
declare -A mut_mode=([bm-left-on]=smmu [no-revoke]=smmu [grant-no-smmu]=nosmmu [no-sweep]=nosmmu)
declare -A mut_row=([bm-left-on]=27 [no-revoke]=31 [grant-no-smmu]=28 [no-sweep]=26)
for m in "${mutations[@]}"; do
    efi="${out}/full-test-xhci-${m}/BOOTAA64.EFI"
    boot "mut-${m}" "${efi}" "${mut_mode[$m]}" none
    reset_rows
    evaluate_dma "${mut_mode[$m]}"
    evaluate_final "${mut_mode[$m]}"
    r="${mut_row[$m]}"
    if ! grep -qF "WARNING: TEST-ONLY xHCI MUTATION BUILD (CK_TEST_XHCI_MUTATION=${m}," "${work}/serial.txt"; then
        mut_bad "${m}: image did not announce the mutation"
    elif ! grep -q "report_kind: final" "${work}/serial.txt" || [[ "${rowfail[25]}" != 0 ]]; then
        mut_bad "${m}: boot did not reach the final report with the xHCI found (a dead boot proves nothing)"
    elif [[ "${rowfail[$r]}" == 1 ]]; then
        mut_ok "${m} (${mut_mode[$m]}): row ${r} FAILs as it must"
    else
        mut_bad "${m} (${mut_mode[$m]}): row ${r} still PASSES: the check does not catch this mutation"
    fi
done
release_lock
if [[ "${mut_fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for s in "${top}"/*/serial.txt; do
        echo "---- serial console $(basename "$(dirname "${s}")") (device lines) ----"
        grep -E '^(WARNING|keyboard|xhci|xhci_pci|dma_sweep|dma_gate|smmu|devices:|report_kind:)' "${s}" | head -60 || true
    done
fi
if [[ "${mut_fail}" == 0 ]]; then echo "${final_tag}: PASS (bm-left-on->27 no-revoke->31 grant-no-smmu->28 no-sweep->26)"; exit 0; fi
echo "${final_tag}: FAIL"
exit 1
