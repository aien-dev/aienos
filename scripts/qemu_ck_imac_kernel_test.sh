#!/usr/bin/env bash
# qemu_ck_imac_kernel_test.sh -- QEMU test for IMACKERN.EFI (AIENOS-IMAC-KERNEL-0,
# native/kernel/x86). QEMU is an emulator: a PASS here qualifies nothing about a
# 2017 iMac or any other real x86_64 machine.
#
# Builds IMACKERN.EFI, puts it on a FAT image as EFI/BOOT/BOOTX64.EFI attached as a
# SATA disk, and boots it twice in QEMU q35 with OVMF: "-cpu max" and "-cpu qemu64"
# (two CPU models; the kernel drives the local APIC in xAPIC mode on both). Each run
# must leave boot services, switch to the kernel's own page tables, prove the guard
# page, measure the TSC against the HPET, take 20 local APIC timer interrupts, print
# "kernel: alive", hold the screen and power QEMU off through ACPI S5 by itself.
# The kernel's report reaches the serial log through COM1, which QEMU has and the
# iMac does not. Needs qemu-system-x86_64, OVMF, mtools and an x86_64 gcc. Final line:
#     AIENOS_IMAC_KERNEL: PASS|FAIL|NOT_RUN [(...)]      exit 0 / 1 / 2 (tools) / 3 (NOT_RUN)
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
tag="AIENOS_IMAC_KERNEL"
code_fd="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
vars_fd="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
cross=""
if [ "$(uname -m)" != "x86_64" ]; then cross="x86_64-linux-gnu-"; fi
for t in qemu-system-x86_64 mformat mmd mcopy "${cross}gcc" "${cross}ld"; do
    command -v "${t}" >/dev/null || { echo "${tag}: NOT_RUN (${t} missing)"; exit 2; }
done
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "${tag}: NOT_RUN (no OVMF)"; exit 2; }
out="${IMACKERN_OUT:-${repo_root}/target/native-kernel-imac-kernel}"
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
make -s -C native/kernel X86_CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" imac-kernel >/dev/null

. "${repo_root}/scripts/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take qemu_ck_imac_kernel_test "${AIENOS_GATE_MINUTES:-60}"; then
    echo "${tag}: NOT_RUN (${gh_why})"
    exit 3
fi
work="$(mktemp -d)"
qpid=""
cleanup() {
    [[ -z "${qpid}" ]] || kill "${qpid}" 2>/dev/null || true
    rm -rf "${work}"
    gh_lock_release
}
trap cleanup EXIT

img="${work}/esp.img"
truncate -s 64M "${img}"
mformat -i "${img}" -F ::
mmd -i "${img}" ::/EFI ::/EFI/BOOT
mcopy -i "${img}" "${out}/IMACKERN.EFI" ::/EFI/BOOT/BOOTX64.EFI

fails=0
chk() { # description, file, pattern
    if grep -aqE -- "$3" "$2"; then echo "PASS  $1"; else echo "FAIL  $1 (no match for: $3)"; fails=$((fails + 1)); fi
}
run() { # name, -cpu model, expected APIC mode
    local name="$1" cpu="$2" mode="$3" log="${work}/$1.log" txt="${work}/$1.txt"
    cp "${vars_fd}" "${work}/vars.fd"
    qemu-system-x86_64 -M q35 -accel tcg -cpu "${cpu}" -smp 2 -m 1024 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file="${img}" -device ide-hd,drive=esp,bus=ide.0 \
        -display none -nic none -serial file:"${log}" -no-reboot &
    qpid=$!
    local self_exit=0
    for _ in $(seq 1 "${AIENOS_IMAC_KERNEL_WAIT:-300}"); do
        if ! kill -0 "${qpid}" 2>/dev/null; then self_exit=1; break; fi
        sleep 1
    done
    kill "${qpid}" 2>/dev/null || true
    wait "${qpid}" 2>/dev/null || true
    qpid=""
    tr -d '\r' <"${log}" >"${txt}" 2>/dev/null || : >"${txt}"
    echo "== run ${name} (-cpu ${cpu}) =="
    chk "${name}: title" "${txt}" '^AIENOS-IMAC-KERNEL-0$'
    chk "${name}: commit" "${txt}" "^aienos_commit: ${commit}\$"
    chk "${name}: GOP found" "${txt}" '^gop: ok '
    chk "${name}: RSDP" "${txt}" '^acpi_rsdp: 0x[0-9a-f]*[1-9a-f][0-9a-f]*$'
    chk "${name}: left boot services" "${txt}" '^exit_boot_services: ok attempts=[1-8]$'
    chk "${name}: descriptor tables" "${txt}" '^descriptors: gdt=5 tss=yes ist1=df,nmi,mc idt=256$'
    chk "${name}: handoff checked" "${txt}" '^handoff: CHANDOF3 ok$'
    chk "${name}: screen on the framebuffer" "${txt}" '^screen: gop [0-9]+x[0-9]+ .* map=wc scale=[1-4] grid=[0-9]+x[0-9]+$'
    chk "${name}: own page tables" "${txt}" '^paging: root=0x[0-9a-f]+ firmware_cr3=0x[0-9a-f]+ switched=yes top_gib=[0-9]+ pages_2m_wb=[1-9][0-9]* pages_2m_wc=[1-9][0-9]* pages_2m_uc=[1-9][0-9]* pt_frames=[0-9]+ fb=wc pat1=wc$'
    chk "${name}: heap" "${txt}" '^memory: frame_ranges=[1-9][0-9]* free_bytes=[1-9][0-9]* .* heap_test=ok$'
    chk "${name}: guard page fault contained" "${txt}" '^guard_page: ok fault=contained \(#PF cr2=0x[0-9a-f]+ error=0x[0-9a-f]+, not present\)$'
    chk "${name}: TSC timed by the HPET" "${txt}" '^timebase: hpet period_fs=[1-9][0-9]* tsc_hz=[1-9][0-9]*$'
    chk "${name}: APIC mode ${mode}" "${txt}" "^apic: mode=${mode} id=0 "
    chk "${name}: MADT two CPUs" "${txt}" '^madt: cpus=2 ioapics=1 ioapic_lines_masked=[1-9][0-9]*$'
    chk "${name}: 20 timer interrupts" "${txt}" '^timer_irq: 20 ticks in [0-9]+ ms$'
    chk "${name}: kernel alive" "${txt}" '^kernel: alive$'
    chk "${name}: DONE" "${txt}" '^AIENOS-IMAC-KERNEL-0 DONE$'
    chk "${name}: ACPI S5 power off" "${txt}" '^power: off via ACPI S5 pm1a=0x[0-9a-f]+ '
    if grep -aqE '^(panic|power: still running|power: halted)' "${txt}"; then
        echo "FAIL  ${name}: panic or failed power off"; fails=$((fails + 1))
    else
        echo "PASS  ${name}: no panic"
    fi
    [[ ${self_exit} == 1 ]] && echo "PASS  ${name}: QEMU powered off by itself" || { echo "FAIL  ${name}: QEMU still running"; fails=$((fails + 1)); }
    echo "---- ${name} serial ----"; cat "${txt}"; echo "----"
}
run max max xapic
run qemu64 qemu64 xapic
if [[ ${fails} == 0 ]]; then echo "${tag}: PASS"; exit 0; fi
echo "${tag}: FAIL (${fails} checks)"; exit 1
