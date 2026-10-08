#!/usr/bin/env bash
# CONSOLE gate for the AIENOS C kernel (Campaign 3 cut C3-1a): rows 146-153 of
# native/kernel/GATES.md "C3-1a console session". C-only (no Rust oracle).
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# Boots the TEST-ONLY console session image (make full CK_CONSOLE_SESSION=1)
# in QEMU AArch64 with UEFI (AAVMF), an NVMe disk, a qemu-xhci controller with
# a usb-kbd and iommu=smmuv3. The image has a final boot stage "console"
# (native/kernel/dev/devices.c) that runs after every other boot step: serial
# (PL011, polled) and the USB keyboard (inside the xHCI DMA fence) feed one
# bounded line editor and the existing shell until "exit". Serial input comes
# from OUTSIDE the guest through a QEMU pipe chardev, USB keys through the QEMU
# monitor ("sendkey"); the kernel never fakes either device.
#
# Timeline after "console_session: ready" (T0, measured here on the host):
#   T0+70 s   serial "uptime", serial "el", usb "uptime", usb "help"
#   T0+130 s  the same again (sustained past the old 60 s shell limit)
#   then      interleave: serial "ab" + usb "xy" (dropped) + serial "c" Enter;
#             usb "el" prefix + serial "zz" (dropped) + usb Enter
#   then      overflow: 65 x from serial, 65 x from usb (both refused)
#   then      "exit" from usb: the session revokes
# (AIENOS_CONSOLE_T1 and AIENOS_CONSOLE_T2 override 70 and 130 for debugging.)
#
#   row 146  the session starts after every other boot step (after mm_usage,
#            before the final report), PL011 receive ready on the console UART
#            base the kernel already uses (no second address in the session code)
#   row 147  serial input echoed and run at ~70 s and ~130 s (uptime_ms past
#            the old 60 s limit each time)
#   row 148  USB keyboard input echoed and run at ~70 s and ~130 s
#   row 149  an overlong line is refused whole, from each source, never run
#   row 150  a line is owned by the first source; the other source's keys are
#            dropped and counted in a printed line; the line holds only the
#            owner's keys (both directions)
#   row 151  "exit" revokes inside the session: controller halted, bus master
#            revoked, COMMAND read back off, stream back to abort, in order,
#            before "console_session: end (exit) xhci=released"
#   row 152  the existing DMA rows hold for the session image: sweep before any
#            DMA grant, xHCI bus master off before the gate, both fences
#            (devices stage and session) confined and revoked, no bypass
#   row 153  no panic or fault, final report, QEMU exit 0, M1 checks
#
# --mutation (red before green): "make full CK_CONSOLE_SESSION=1
# CK_TEST_CONSOLE_MUTATION=bm-left-on-after-exit" leaves the xHCI bus master on
# after the session exit; with the SMMU on, row 151 must FAIL (and the boot
# must still reach the final report with row 146 passing, so the failure is
# the mutation's, not a dead boot). It also checks the build refuses the
# mutation with CK_HARDWARE_STAGING=1, CK_QEMU_UNSAFE_DMA=1 and without
# CK_CONSOLE_SESSION=1, and that the default image carries no session code.
#
# Like the other QEMU children: NOT_RUN (exit 3) while the machine quiet flag
# (AIENOS_QUIET_FLAG, default ~/workspace/.spark-quiet) exists, which this
# script only reads and never writes, or while the QEMU gate lock
# (AIENOS_GATE_LOCK, default ~/workspace/.qemu-gate-lock, exclusive create) is
# held by another gate run.
# Final lines: one "CONSOLE_ROW <n>: PASS|FAIL|NOT_RUN (...)" per row and
# "AIENOS_CK_CONSOLE: PASS|FAIL|NOT_RUN (...)" (read by scripts/ck_gates.sh).
# Exit 0 PASS, 1 FAIL, 2 missing tools, 3 NOT_RUN.
# --mutation: "AIENOS_CK_CONSOLE_MUTATION: PASS|FAIL"; exit 0 / 1.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mutation_run=0
case "${1:-}" in
    "") ;;
    --mutation) mutation_run=1 ;;
    *) echo "usage: $0 [--mutation]"; exit 2 ;;
esac
final_tag="AIENOS_CK_CONSOLE"
[[ "${mutation_run}" == 0 ]] || final_tag="AIENOS_CK_CONSOLE_MUTATION"

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
if [[ "${mutation_run}" == 1 ]]; then
    mk full CK_CONSOLE_SESSION=1 CK_TEST_CONSOLE_MUTATION=bm-left-on-after-exit >/dev/null
    session_efi="${out}/full-test-console-mutation/BOOTAA64.EFI"
else
    mk full CK_CONSOLE_SESSION=1 >/dev/null
    session_efi="${out}/full-console-session/BOOTAA64.EFI"
fi

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
if [[ -e "${quiet_flag}" ]]; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${final_tag}: NOT_RUN (quiet flag held)"
    exit 3
fi
gate_lock="${AIENOS_GATE_LOCK:-${HOME}/workspace/.qemu-gate-lock}"
gate_tag="${AIENOS_GATE_TAG:-qemu_ck_console_test $$}"
if ! ( set -C; echo "${gate_tag}" > "${gate_lock}" ) 2>/dev/null; then
    echo "NOT_RUN  QEMU gate lock ${gate_lock} is held: $(head -c 200 "${gate_lock}" 2>/dev/null || true)"
    echo "${final_tag}: NOT_RUN (QEMU gate lock held)"
    exit 3
fi
own_lock=1
release_lock() {
    if [[ "${own_lock}" == 1 ]]; then
        own_lock=0
        if [[ -f "${gate_lock}" ]] && grep -qxF -- "${gate_tag}" "${gate_lock}"; then rm -f "${gate_lock}"; fi
    fi
}
top="$(mktemp -d)"
qemu_pid=""
drain_pid=""
cleanup() {
    [[ -z "${qemu_pid}" ]] || kill "${qemu_pid}" 2>/dev/null || true
    [[ -z "${drain_pid}" ]] || kill "${drain_pid}" 2>/dev/null || true
    exec 3>&- 4>&- 2>/dev/null || true
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
boot_timeout="${AIENOS_QEMU_TIMEOUT:-700}"
t1="${AIENOS_CONSOLE_T1:-70}"
t2="${AIENOS_CONSOLE_T2:-130}"
overflow_keys=65

serial_has() { tr -d '\r' 2>/dev/null <"${work}/serial.log" | grep -qE -- "$1"; }
qemu_running() { [[ -n "${qemu_pid}" ]] && kill -0 "${qemu_pid}" 2>/dev/null; }
wait_for() { # seconds ERE...: 0 once the serial log matches one, 1 on timeout or QEMU exit
    local deadline=$(( $(date +%s) + $1 )) p; shift
    while (( $(date +%s) < deadline )) && qemu_running; do
        for p in "$@"; do serial_has "${p}" && return 0; done
        sleep 0.3
    done
    for p in "$@"; do serial_has "${p}" && return 0; done
    return 1
}
sleep_until() { local now; now=$(date +%s); (( $1 > now )) && sleep $(( $1 - now )) || true; }
# USB keys go in through the QEMU monitor (fd 3), serial bytes through the pipe chardev (fd 4).
usb_keys() { local k; for k in "$@"; do echo "sendkey ${k}" >&3; sleep 0.12; done; }
usb_line() { usb_keys "$@" ret; sleep 0.6; }
ser_text() { local c; for c in "$@"; do printf '%s' "${c}" >&4; sleep 0.05; done; }
ser_line() { ser_text "$@"; printf '\r' >&4; sleep 0.6; }
letters() { local s="$1" i; for ((i = 0; i < ${#s}; i++)); do printf '%s\n' "${s:i:1}"; done; }
ser_word() { mapfile -t _l < <(letters "$1"); ser_line "${_l[@]}"; }
usb_word() { mapfile -t _l < <(letters "$1"); usb_line "${_l[@]}"; }
xs() { local i; for ((i = 0; i < overflow_keys; i++)); do printf 'x\n'; done; }

# boot <name> <efi> <full|mutation>: one QEMU boot driven as described above.
boot() {
    work="${top}/$1"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    rm -f "${work}/mon.in" "${work}/mon.out" "${work}/ser.in" "${work}/ser.out"
    mkfifo "${work}/mon.in" "${work}/mon.out" "${work}/ser.in" "${work}/ser.out"
    : >"${work}/serial.log"
    timeout "${boot_timeout}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${image}" \
        -device nvme,drive=nvme0,serial=aienos-console-test \
        -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
        -device ramfb -display none -nic none \
        -chardev pipe,id=mon,path="${work}/mon" -mon chardev=mon,mode=readline \
        -chardev pipe,id=ser,path="${work}/ser" -serial chardev:ser -no-reboot 2>"${work}/qemu.err" &
    qemu_pid=$!
    cat "${work}/mon.out" >/dev/null &
    cat "${work}/ser.out" >>"${work}/serial.log" &
    drain_pid=$!
    exec 3>"${work}/mon.in" 4>"${work}/ser.in"
    t0=0
    if wait_for "${boot_timeout}" '^console_session: ready' '^report_kind: (panic|fault|final)' && serial_has '^console_session: ready'; then
        t0=$(date +%s)
        if [[ "$3" == full ]]; then
            sleep_until $(( t0 + t1 ))
            ser_word uptime; ser_word el; usb_word uptime; usb_word help
            sleep_until $(( t0 + t2 ))
            ser_word uptime; ser_word el; usb_word uptime; usb_word help
            # interleave A: serial owns the line, usb keys dropped
            ser_text a b; usb_keys x y; ser_text c; printf '\r' >&4; sleep 0.8
            # interleave B: usb owns the line, serial bytes dropped
            usb_keys e l; ser_text z z; usb_keys ret; sleep 0.8
            # overflow from each source
            mapfile -t _x < <(xs); ser_line "${_x[@]}"; usb_line "${_x[@]}"
            usb_word exit
        else
            sleep 3
            usb_word exit
        fi
    fi
    wait_for 120 '^report_kind: (panic|fault|final)' || true
    set +e
    wait "${qemu_pid}"
    qemu_status=$?
    set -e
    qemu_pid=""
    exec 3>&- 4>&- 2>/dev/null || true
    wait "${drain_pid}" 2>/dev/null || true
    drain_pid=""
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    # The session window: from its begin line to the stage's own result line.
    awk '/^console_session: begin/{on=1} on{print} /^stage console:/{if(on) exit}' "${work}/serial.txt" >"${work}/sess.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_console_$1.log"
    echo "== boot $1 (smmu, $3): qemu exit ${qemu_status}, session ready at host second ${t0}"
}

all_rows=(146 147 148 149 150 151 152 153)
declare -A rowfail rowchk
reset_rows() { local r; for r in "${all_rows[@]}"; do rowfail[$r]=0; rowchk[$r]=0; done; }
reset_rows
mode="smmu"
# f: the file the next checks read (serial.txt or the session window sess.txt).
f=serial.txt
rpass() { rowchk[$1]=$(( ${rowchk[$1]} + 1 )); echo "ROW $1 PASS  ${mode}: $2"; }
rfail() { rowchk[$1]=$(( ${rowchk[$1]} + 1 )); rowfail[$1]=1; echo "ROW $1 FAIL  ${mode}: $2"; }
rcheck() { if grep -qE -- "$3" "${work}/${f}"; then rpass "$1" "$2"; else rfail "$1" "$2"; fi; }
rabsent() { if grep -qE -- "$3" "${work}/${f}"; then rfail "$1" "$2"; else rpass "$1" "$2"; fi; }
line_of() { { grep -nE -m1 -- "$1" "${work}/${f}" || true; } | cut -d: -f1; }
before() {
    local a b
    a="$(line_of "$3")"; b="$(line_of "$4")"
    if [[ -n "${a}" && -n "${b}" && "${a}" -lt "${b}" ]]; then rpass "$1" "$2 (lines ${a} < ${b})"
    else rfail "$1" "$2 (lines ${a:-none} ${b:-none})"; fi
}
# uptimes <source>: the uptime_ms value printed after each "console_line: uptime source=<src>".
uptimes() {
    awk -v want="source=$1" '/^console_line: uptime source=/{ s=$NF; w=(s==want) } /^uptime_ms: /{ if (w) { print $2; w=0 } }' "${work}/${f}"
}

# row 146: placement and serial receive.
eval_start() {
    f=serial.txt
    rcheck 146 "console session begins" '^console_session: begin \(TEST-ONLY QEMU image, CK_CONSOLE_SESSION=1; QEMU only, hardware NOT_RUN\)$'
    before 146 "after the Store stage and the artifact loader's mm_usage" '^mm_usage: ' '^console_session: begin'
    before 146 "begin < ready" '^console_session: begin' '^console_session: ready '
    before 146 "ready < the stage result" '^console_session: ready ' '^stage console: ok rc=0$'
    before 146 "stage result < final report" '^stage console: ok rc=0$' '^report_kind: final'
    before 146 "after the devices stage fence" '^devices: xhci=' '^console_session: begin'
    rcheck 146 "PL011 receive ready on the console UART (QEMU virt PL011 at 0x9000000, UARTEN+RXE set)" \
        '^console_session: serial rx pl011 base=0x9000000 uartcr=0x[0-9a-f]{4} ready$'
    rcheck 146 "ready line says no time limit, no idle exit, ends on exit" \
        '^console_session: ready \(usb keyboard ready; no time limit, no idle exit; ends on exit\)$'
    rcheck 146 "USB keyboard attached inside the xHCI fence" '^console_session: usb keyboard attached \(port [0-9]+, slot [0-9]+, endpoint 0x8[0-9a-f]\), inside the xHCI fence$'
    rabsent 146 "no session time limit or idle exit fired" '^console_session: end \((timeout|idle)'
    if grep -nE '0x9000000|9000000' native/kernel/dev/usb_kbd.c native/kernel/dev/devices.c >/dev/null 2>&1; then
        rfail 146 "session code hard-codes a UART address"
    else rpass 146 "session code reads the console's UART base only (no second address)"; fi
}

# rows 147, 148: sustained input, per source.
eval_sustained() { # source row
    local s="$1" r="$2" ups
    f=serial.txt
    rcheck "${r}" "${s}: 'uptime' echoed and run (round 1 and 2)" "^console_line: uptime source=${s}$"
    [[ "$(grep -cE -- "^console_line: uptime source=${s}$" "${work}/${f}")" -ge 2 ]] && rpass "${r}" "${s}: two uptime lines" || rfail "${r}" "${s}: fewer than two uptime lines"
    rcheck "${r}" "${s}: echo line" '^console_echo: uptime$'
    ups="$(uptimes "${s}" | tr '\n' ' ')"
    local u1 u2
    u1="$(echo "${ups}" | awk '{print $1+0}')"; u2="$(echo "${ups}" | awk '{print $2+0}')"
    if [[ "${u1}" -ge $(( (t1 - 5) * 1000 )) ]]; then rpass "${r}" "${s}: first input ran ${u1} ms into the session (>= $(( (t1 - 5) * 1000 )))"
    else rfail "${r}" "${s}: first input uptime_ms=${u1:-none}"; fi
    if [[ "${u2}" -ge $(( (t2 - 5) * 1000 )) && "${u2}" -gt 60000 ]]; then rpass "${r}" "${s}: second input ran ${u2} ms into the session (past the old 60000 ms limit)"
    else rfail "${r}" "${s}: second input uptime_ms=${u2:-none}"; fi
    if [[ "${s}" == serial ]]; then
        rcheck "${r}" "serial: 'el' ran" '^console_line: el source=serial$'
        [[ "$(grep -cE -- '^EL1$' "${work}/${f}")" -ge 2 ]] && rpass "${r}" "serial: EL1 printed after both rounds" || rfail "${r}" "serial: EL1 missing"
    else
        rcheck "${r}" "usb: 'help' ran" '^console_line: help source=usb$'
        [[ "$(grep -cE -- '^commands: help mem el report uptime exit$' "${work}/${f}")" -ge 2 ]] && rpass "${r}" "usb: help output after both rounds" || rfail "${r}" "usb: help output missing"
    fi
}

eval_overflow() {
    f=serial.txt
    local s
    for s in serial usb; do
        rcheck 149 "${s}: overlong line refused whole" "^console_line: overflow \\(line refused: ${overflow_keys} keys typed, limit 64\\) source=${s}\$"
    done
    rabsent 149 "overlong line never reported as a line" '^console_line: x'
    rabsent 149 "overlong line never run as a command" '^unknown command: x'
    rabsent 149 "overlong line never echoed" '^console_echo: x'
}

eval_interleave() {
    f=serial.txt
    rcheck 150 "serial owned the line: only its keys ran" '^console_line: abc source=serial$'
    rcheck 150 "serial line's usb keys dropped and counted" '^console_input: dropped 2 key\(s\) from usb while serial owned the line$'
    rcheck 150 "the dropped keys ran as nothing" '^unknown command: abc$'
    rcheck 150 "usb owned the line: only its keys ran" '^console_line: el source=usb$'
    rcheck 150 "usb line's serial bytes dropped and counted" '^console_input: dropped 2 key\(s\) from serial while usb owned the line$'
    rabsent 150 "no mixed line (abcxy, elzz, xy, zz)" '^console_line: (abcxy|abxyc|elzz|xy|zz|el[a-z]+) source='
    before 150 "serial line before the usb line" '^console_line: abc source=serial$' '^console_line: el source=usb$'
}

eval_revoke() { # row 151 on the session window
    f=sess.txt
    rcheck 151 "session fence granted only as confined" '^dma_gate: xhci granted \(Confined\), bus master on$'
    rcheck 151 "session window: xHCI SMMU window" '^smmu_dma_window: xhci only, translation active iova=0x[0-9a-f]+ len=0x[0-9a-f]+ rid=0x[0-9a-f]+$'
    rcheck 151 "session exit seen" '^console_session: exit \(source=usb\)$'
    rcheck 151 "controller halted before the revoke" '^xhci: halt before revoke usbcmd=0x[0-9a-f]{8} usbsts=0x[0-9a-f]{8} halted=yes$'
    rcheck 151 "xHCI bus master revoked after the session" '^dma_gate: xhci bus master revoked$'
    rabsent 151 "no revoke failure" '^dma_gate: xhci bus master revoke FAILED'
    rcheck 151 "COMMAND read back after the session: bus master off" '^xhci_pci: after phase command=0x[0-9a-f]{4} bus_master=off$'
    rcheck 151 "xHCI SMMU stream returned to abort" '^smmu: xhci stream 0x[0-9a-f]+ returned to abort \(rc=0\)$'
    rcheck 151 "session ends with the controller released" '^console_session: end \(exit\) xhci=released$'
    before 151 "order: exit < halt" '^console_session: exit ' '^xhci: halt before revoke'
    before 151 "order: halt < revoke" '^xhci: halt before revoke' '^dma_gate: xhci bus master revoked$'
    before 151 "order: revoke < COMMAND read back" '^dma_gate: xhci bus master revoked$' '^xhci_pci: after phase command='
    before 151 "order: read back < stream abort" '^xhci_pci: after phase command=' '^smmu: xhci stream .* returned to abort'
    before 151 "order: stream abort < session end" '^smmu: xhci stream .* returned to abort' '^console_session: end '
}

eval_dma() { # row 152 on the whole log
    f=serial.txt
    rcheck 152 "post-exit bus-master sweep of the segment, nothing stuck" \
        '^dma_sweep: seg 0000 bus [0-9a-f]{2}-[0-9a-f]{2} functions=[1-9][0-9]* bridges=[0-9]+ bridges_bme=[0-9]+ endpoints_bme_found=[0-9]+ still_enabled=0$'
    rabsent 152 "no endpoint left with bus master stuck on" '^dma_sweep: bme STUCK'
    before 152 "sweep before the first device DMA gate" '^dma_sweep: seg ' '^dma_gate: '
    rcheck 152 "xHCI bus master off before the DMA gate" '^xhci_pci: command=0x[0-9a-f]{4} bus_master=off$'
    before 152 "COMMAND read back before the first xHCI DMA gate" '^xhci_pci: command=' '^dma_gate: xhci '
    local g; g="$(grep -cE -- '^dma_gate: xhci granted \(Confined\), bus master on$' "${work}/${f}")"
    [[ "${g}" == 2 ]] && rpass 152 "two confined grants (devices-stage shell and session)" || rfail 152 "confined grants: ${g} (expected 2)"
    g="$(grep -cE -- '^dma_gate: xhci bus master revoked$' "${work}/${f}")"
    [[ "${g}" -ge 2 ]] && rpass 152 "bus master revoked after each grant" || rfail 152 "revokes: ${g} (expected 2)"
    g="$(grep -cE -- '^smmu: xhci stream 0x[0-9a-f]+ returned to abort \(rc=0\)$' "${work}/${f}")"
    [[ "${g}" -ge 2 ]] && rpass 152 "stream back to abort after each grant" || rfail 152 "stream aborts: ${g} (expected 2)"
    rabsent 152 "no unconfined xHCI grant" 'dma_gate: xhci granted \((UnsafeBypass|TestMutation)'
    rabsent 152 "no unsafe DMA bypass in this image" 'UNSAFE DMA BYPASS'
    rabsent 152 "no xHCI fence mutation banner" 'TEST-ONLY xHCI MUTATION'
    rcheck 152 "devices stage shell still ran and revoked before the session" '^devices: xhci=fenced \(rc=0\)$'
    before 152 "devices-stage fence < session" '^devices: xhci=fenced \(rc=0\)$' '^console_session: begin'
    rcheck 152 "existing boot shell unchanged: it still reports its bounded limits" '^keyboard: shell ready \(60 s, idle 15 s\)$'
}

eval_final() { # row 153
    f=serial.txt
    rabsent 153 "no panic or fault" '^report_kind: (panic|fault)'
    rcheck 153 "final report reached" 'report_kind: final'
    if [[ "${qemu_status}" == 0 ]]; then rpass 153 "QEMU exit 0 after PSCI reset"; else rfail 153 "QEMU exit ${qemu_status} (expected 0)"; fi
}

image_checks() {
    check "image is this commit" "aienos_commit: ${commit}"
    check_absent "no xHCI fence mutation banner" "TEST-ONLY xHCI MUTATION"
}

if [[ "${mutation_run}" == 0 ]]; then
    boot console-smmu "${session_efi}" full
    failed=0
    ck_m1_checks
    [[ "${failed}" == 0 ]] || m1_fail=1
    failed=0
    image_checks
    [[ "${failed}" == 0 ]] || m1_fail=1
    eval_start
    eval_sustained serial 147
    eval_sustained usb 148
    eval_overflow
    eval_interleave
    eval_revoke
    eval_dma
    eval_final
    release_lock
    any_fail=0
    for r in "${all_rows[@]}"; do any_fail=$(( any_fail | rowfail[$r] )); done
    if [[ "${m1_fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" || "${any_fail}" != 0 ]]; then
        echo "---- serial console (session lines) ----"
        grep -E '^(console|uptime_ms|commands|EL[0-9]|unknown|dma_gate|xhci|smmu:|stage |report_kind:|devices:)' "${work}/serial.txt" | head -150 || true
    fi
    echo "== per-row results (QEMU only; hardware NOT_RUN)"
    gate_fail="${m1_fail}"
    for r in "${all_rows[@]}"; do
        if [[ "${rowchk[$r]}" == 0 ]]; then
            echo "CONSOLE_ROW ${r}: NOT_RUN (not checked)"; gate_fail=1
        elif [[ "${rowfail[$r]}" == 0 && "${m1_fail}" == 0 ]]; then
            echo "CONSOLE_ROW ${r}: PASS (smmu; ${rowchk[$r]} checks)"
        else
            echo "CONSOLE_ROW ${r}: FAIL (smmu$([[ "${m1_fail}" == 0 ]] || echo '; an M1 or image check failed'))"; gate_fail=1
        fi
    done
    if [[ "${gate_fail}" != 0 ]]; then
        echo "${final_tag}: FAIL (rows 146-153; QEMU only)"
        exit 1
    fi
    echo "${final_tag}: PASS (rows 146-153; serial + usb input at ~${t1} s and ~${t2} s, overflow, interleave, exit revoke; boot console-smmu; QEMU only, hardware NOT_RUN)"
    exit 0
fi

# ---- --mutation: bus master left on after the session exit must make row 151 FAIL ----
mut_fail=0
mut_ok() { echo "MUTATION PASS  $1"; }
mut_bad() { echo "MUTATION FAIL  $1"; mut_fail=1; }
if grep -aqF "console_session:" "${default_efi}"; then mut_bad "default image carries console session code"; else mut_ok "default image carries no console session code"; fi
for combo in "CK_HARDWARE_STAGING=1" "CK_QEMU_UNSAFE_DMA=1"; do
    set +e
    msg="$(make -s -n -C native/kernel OUT="${top}/refuse" full CK_CONSOLE_SESSION=1 "${combo}" 2>&1)"
    st=$?
    set -e
    if [[ "${st}" != 0 ]] && grep -qE "CK_CONSOLE_SESSION.*cannot be combined with ${combo%%=*}" <<<"${msg}"; then
        mut_ok "build refuses CK_CONSOLE_SESSION with ${combo}"
    else
        mut_bad "build did not refuse CK_CONSOLE_SESSION with ${combo} (status ${st}): $(head -c 200 <<<"${msg}")"
    fi
done
set +e
msg="$(make -s -n -C native/kernel OUT="${top}/refuse" full CK_TEST_CONSOLE_MUTATION=bm-left-on-after-exit 2>&1)"
st=$?
set -e
if [[ "${st}" != 0 ]] && grep -qF "CK_TEST_CONSOLE_MUTATION needs CK_CONSOLE_SESSION=1" <<<"${msg}"; then
    mut_ok "build refuses CK_TEST_CONSOLE_MUTATION without CK_CONSOLE_SESSION=1"
else
    mut_bad "build did not refuse the mutation without the session (status ${st})"
fi
boot console-mut "${session_efi}" mutation
reset_rows
eval_start
eval_revoke
eval_final
release_lock
if ! grep -qF "WARNING: TEST-ONLY console session MUTATION BUILD (CK_TEST_CONSOLE_MUTATION=bm-left-on-after-exit," "${work}/serial.txt"; then
    mut_bad "image did not announce the mutation"
elif ! grep -q "report_kind: final" "${work}/serial.txt" || [[ "${rowfail[146]}" != 0 ]]; then
    mut_bad "boot did not reach the final report with the session running (a dead boot proves nothing)"
elif [[ "${rowfail[151]}" == 1 ]]; then
    mut_ok "bus master left on after the session exit (smmu): row 151 FAILs as it must"
else
    mut_bad "bus master left on after the session exit: row 151 still PASSES: the check does not catch it"
fi
if [[ "${mut_fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console (session lines) ----"
    grep -E '^(WARNING|console|dma_gate|xhci|smmu:|report_kind:)' "${work}/serial.txt" | head -60 || true
fi
if [[ "${mut_fail}" == 0 ]]; then echo "${final_tag}: PASS (bm-left-on-after-exit->151)"; exit 0; fi
echo "${final_tag}: FAIL"
exit 1
