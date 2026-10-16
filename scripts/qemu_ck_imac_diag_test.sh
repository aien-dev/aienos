#!/usr/bin/env bash
# qemu_ck_imac_diag_test.sh -- QEMU test for IMACDIAG.EFI (AIENOS-IMAC-BOOT-0,
# native/boot/diag_main.c + diag_x86.c). QEMU is an emulator: a PASS here
# qualifies nothing about a 2017 iMac or any other real x86_64 machine.
#
# Builds IMACDIAG.EFI, puts it on a FAT image as EFI/BOOT/BOOTX64.EFI attached as a
# SATA disk (q35 AHCI, like the iMac's internal drives), boots it in QEMU x86_64
# with OVMF, waits for the app to power QEMU off, reads \EFI\AIENOS\IMACBOOT.TXT and
# every \EFI\AIENOS\ACPI\*.BIN back with mtools and checks the firmware, CPU,
# SMBIOS, PCI, screen and disk lines, the ACPI copies, "DONE", and that the app
# wrote the file and asked for a shutdown.
# Needs qemu-system-x86_64, OVMF, mtools and an x86_64 gcc (x86_64-linux-gnu- on
# other hosts). Final line:
#     AIENOS_IMAC_DIAG: PASS|FAIL|NOT_RUN [(...)]      exit 0 / 1 / 2 (tools) / 3 (NOT_RUN)
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
tag="AIENOS_IMAC_DIAG"
code_fd="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
vars_fd="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
cross=""
if [ "$(uname -m)" != "x86_64" ]; then cross="x86_64-linux-gnu-"; fi
for t in qemu-system-x86_64 mformat mmd mcopy "${cross}gcc" "${cross}ld"; do
    command -v "${t}" >/dev/null || { echo "${tag}: NOT_RUN (${t} missing)"; exit 2; }
done
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "${tag}: NOT_RUN (no OVMF)"; exit 2; }
out="${IMACDIAG_OUT:-${repo_root}/target/native-kernel-imac-diag}"
make -s -C native/kernel X86_CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)" imac-diag >/dev/null

. "${repo_root}/scripts/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take qemu_ck_imac_diag_test "${AIENOS_GATE_MINUTES:-60}"; then
    echo "${tag}: NOT_RUN (${gh_why})"
    exit 3
fi
work="$(mktemp -d)"
cleanup() {
    [[ -z "${qpid:-}" ]] || kill "${qpid}" 2>/dev/null || true
    rm -rf "${work}"
    gh_lock_release
}
trap cleanup EXIT

img="${work}/esp.img"
truncate -s 64M "${img}"
mformat -i "${img}" -F ::
mmd -i "${img}" ::/EFI ::/EFI/BOOT
mcopy -i "${img}" "${out}/IMACDIAG.EFI" ::/EFI/BOOT/BOOTX64.EFI
cp "${vars_fd}" "${work}/vars.fd"
qemu-system-x86_64 -M q35 -accel tcg -cpu max -smp 2 -m 1024 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file="${img}" -device ide-hd,drive=esp,bus=ide.0 \
    -display none -nic none -serial file:"${work}/serial.log" -no-reboot &
qpid=$!
done_seen=0
self_exit=0
for _ in $(seq 1 ${AIENOS_IMAC_DIAG_WAIT:-300}); do
    grep -aq "AIENOS-IMAC-BOOT-0 DONE" "${work}/serial.log" 2>/dev/null && done_seen=1
    if ! kill -0 "${qpid}" 2>/dev/null; then self_exit=1; break; fi
    sleep 1
done
kill "${qpid}" 2>/dev/null || true
wait "${qpid}" 2>/dev/null || true
qpid=""

fails=0
chk() { # description, file, pattern
    if grep -aqE -- "$3" "$2"; then echo "PASS  $1"; else echo "FAIL  $1 (no match for: $3)"; fails=$((fails + 1)); fi
}
tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt" 2>/dev/null || : >"${work}/serial.txt"
[[ ${done_seen} == 1 ]] || { echo "FAIL  serial never showed DONE"; fails=$((fails + 1)); }
chk "serial: report_file written" "${work}/serial.txt" '^report_file: written '
chk "serial: shutdown requested" "${work}/serial.txt" "^reset: shutdown\$"
[[ ${self_exit} == 1 ]] && echo "PASS  QEMU stopped by itself after the shutdown" || { echo "FAIL  QEMU still running: ResetSystem did not power off"; fails=$((fails + 1)); }
r="${work}/IMACBOOT.TXT"
if mcopy -i "${img}" ::/EFI/AIENOS/IMACBOOT.TXT "${r}" 2>/dev/null; then
    echo "PASS  IMACBOOT.TXT read back from the image"
    chk "file: title" "${r}" '^AIENOS-IMAC-BOOT-0$'
    chk "file: vendor line" "${r}" '^firmware_vendor: .+'
    chk "file: UEFI spec revision" "${r}" '^uefi_spec_revision: [0-9]+\.[0-9]+$'
    chk "file: CPU vendor" "${r}" '^cpu_vendor: (GenuineIntel|AuthenticAMD)$'
    chk "file: CPU brand" "${r}" '^cpu_brand: .+'
    chk "file: CPU signature" "${r}" '^cpu_signature: family=0x[0-9a-f]+ model=0x[0-9a-f]+ stepping=[0-9]+ '
    chk "file: CPU features include long mode and SSE2" "${r}" '^cpu_features: .*\bsse2\b.*\blm\b'
    chk "file: CPU mode is ring 0, paged, long mode" "${r}" '^cpu_mode: cpl=0 paging=1 long_mode=1 '
    chk "file: memory summary" "${r}" '^memory_map: entries=[0-9]+ conventional_mib=[0-9]+ map_key=0x[0-9a-f]+$'
    chk "file: ACPI 2.0 table line" "${r}" '^table [0-9]+: .* ACPI 2\.0 at 0x'
    chk "file: RSDP line" "${r}" "^acpi_rsdp: rev=[0-9]+ .* xsdt=0x[0-9a-f]+\$"
    chk "file: MADT copied" "${r}" "^acpi_table: APIC .* checksum=ok via XSDT file=APIC.BIN written\$"
    chk "file: DSDT copied via FADT" "${r}" "^acpi_table: DSDT .* checksum=ok via FADT file=DSDT.BIN written\$"
    chk "file: no table failed" "${r}" "^acpi_dump: copied=[0-9]+ failed=0\$"
    chk "file: SMBIOS entry" "${r}" '^smbios: entry=[23] version=[0-9]+\.[0-9]+ '
    chk "file: SMBIOS system identity" "${r}" '^smbios_system: manufacturer=.+ product=.+ version='
    # q35: host bridge 8086:29c0 at 00:00.0 and the ICH9 AHCI controller 8086:2922 at 00:1f.2.
    chk "file: PCI host bridge" "${r}" '^pci: 00:00\.0 8086:29c0 .* host-bridge$'
    chk "file: PCI SATA (AHCI) controller" "${r}" '^pci: 00:1f\.2 8086:2922 rev=[0-9a-f]{2} class=010601 .* storage-sata$'
    chk "file: PCI display" "${r}" '^pci: .* class=0300[0-9a-f]{2} .* display-vga$'
    chk "file: PCI function count" "${r}" '^pci_functions: [1-9][0-9]*$'
    chk "file: GOP mode" "${r}" '^gop [0-9]+: mode=[0-9]+/[0-9]+ [1-9][0-9]*x[1-9][0-9]* '
    chk "file: the 64 MiB boot disk" "${r}" '^block [0-9]+: disk removable=[01] present=1 read_only=0 block_bytes=512 blocks=131072 mib=64$'
    chk "file: DONE" "${r}" '^AIENOS-IMAC-BOOT-0 DONE$'
    if grep -aqiE '^smbios.*serial' "${r}"; then echo "FAIL  an SMBIOS line mentions a serial number field"; fails=$((fails + 1)); else echo "PASS  no SMBIOS line carries a serial number field"; fi
    # Every table file named in the report is on the image, starts with its
    # signature and is exactly the length the report and its own header give.
    while read -r sig len file; do
        if mcopy -n -i "${img}" "::/EFI/AIENOS/ACPI/${file}" "${work}/${file}" 2>/dev/null \
            && [[ "$(head -c 4 "${work}/${file}")" == "${sig}" ]] \
            && [[ "$(stat -c %s "${work}/${file}")" == "${len}" ]] \
            && [[ "$(od -An -tu4 -j4 -N4 "${work}/${file}" | tr -d " ")" == "${len}" ]]; then
            echo "PASS  ACPI/${file}: signature ${sig}, ${len} bytes"
        else
            echo "FAIL  ACPI/${file}: missing, wrong signature or wrong length"; fails=$((fails + 1))
        fi
    done < <(sed -nE "s/^acpi_table: ([A-Z0-9_]{4}) rev=[0-9]+ len=([0-9]+) .* file=([A-Z0-9_]+\.BIN) written\$/\1 \2 \3/p" "${r}")
    echo "---- IMACBOOT.TXT ----"; cat "${r}"; echo "----"
else
    echo "FAIL  IMACBOOT.TXT not found in the image"; fails=$((fails + 1))
fi
if [[ ${fails} == 0 ]]; then echo "${tag}: PASS"; exit 0; fi
echo "${tag}: FAIL (${fails} checks)"; exit 1
