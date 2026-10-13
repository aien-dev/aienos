#!/usr/bin/env bash
# qemu_ck_pi5_diag_test.sh -- QEMU test for PI5DIAG.EFI (AIENOS-PI5-BOOT-0,
# native/boot/diag_main.c). QEMU is an emulator: a PASS here qualifies nothing
# about a Raspberry Pi 5.
#
# Builds PI5DIAG.EFI, puts it on a FAT image as EFI/BOOT/BOOTAA64.EFI, boots it in
# QEMU AArch64 with AAVMF (-no-reboot), waits for the app to cold-reset QEMU,
# reads \EFI\AIENOS\PI5BOOT0.TXT and every \EFI\AIENOS\ACPI\*.BIN back with mtools and
# checks: the title and vendor lines, a firmware table line (ACPI or Device Tree),
# the memory summary, "DONE", and that the app wrote the file (serial says so).
# Needs qemu-system-aarch64, AAVMF, mtools. Final line:
#     AIENOS_PI5_DIAG: PASS|FAIL|NOT_RUN [(...)]      exit 0 / 1 / 2 (tools) / 3 (NOT_RUN)
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
tag="AIENOS_PI5_DIAG"
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
for t in qemu-system-aarch64 mformat mmd mcopy; do
    command -v "${t}" >/dev/null || { echo "${tag}: NOT_RUN (${t} missing)"; exit 2; }
done
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "${tag}: NOT_RUN (no AAVMF)"; exit 2; }
cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
out="${PI5DIAG_OUT:-${repo_root}/target/native-kernel-pi5-diag}"
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)" pi5-diag >/dev/null

. "${repo_root}/scripts/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take qemu_ck_pi5_diag_test "${AIENOS_GATE_MINUTES:-60}"; then
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
mcopy -i "${img}" "${out}/PI5DIAG.EFI" ::/EFI/BOOT/BOOTAA64.EFI
cp "${vars_fd}" "${work}/vars.fd"
qemu-system-aarch64 -M virt -accel tcg -cpu max -m 1024 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file="${img}" -device virtio-blk-pci,drive=esp \
    -display none -nic none -serial file:"${work}/serial.log" -no-reboot &
qpid=$!
done_seen=0
self_exit=0
for _ in $(seq 1 ${AIENOS_PI5_DIAG_WAIT:-240}); do
    grep -aq "AIENOS-PI5-BOOT-0 DONE" "${work}/serial.log" 2>/dev/null && done_seen=1
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
chk "serial: cold reset requested" "${work}/serial.txt" "^reset: cold\$"
[[ ${self_exit} == 1 ]] && echo "PASS  QEMU stopped by itself after the reset (-no-reboot)" || { echo "FAIL  QEMU still running: ResetSystem did not reset"; fails=$((fails + 1)); }
if mcopy -i "${img}" ::/EFI/AIENOS/PI5BOOT0.TXT "${work}/PI5BOOT0.TXT" 2>/dev/null; then
    echo "PASS  PI5BOOT0.TXT read back from the image"
    chk "file: title" "${work}/PI5BOOT0.TXT" '^AIENOS-PI5-BOOT-0$'
    chk "file: vendor line" "${work}/PI5BOOT0.TXT" '^firmware_vendor: .+'
    chk "file: UEFI spec revision" "${work}/PI5BOOT0.TXT" '^uefi_spec_revision: [0-9]+\.[0-9]+$'
    chk "file: current EL" "${work}/PI5BOOT0.TXT" '^current_el: EL[0-3]$'
    chk "file: memory summary" "${work}/PI5BOOT0.TXT" '^memory_map: entries=[0-9]+ conventional_mib=[0-9]+ map_key=0x[0-9a-f]+$'
    chk "file: ACPI or Device Tree table line" "${work}/PI5BOOT0.TXT" '^table [0-9]+: .* (ACPI 1\.0|ACPI 2\.0|Device Tree) at 0x'
    chk "file: DONE" "${work}/PI5BOOT0.TXT" '^AIENOS-PI5-BOOT-0 DONE$'
    chk "file: milestone line" "${work}/PI5BOOT0.TXT" "^milestone: AIENOS-PI5-ACPI-0\$"
    chk "file: RSDP line" "${work}/PI5BOOT0.TXT" "^acpi_rsdp: rev=[0-9]+ .* xsdt=0x[0-9a-f]+\$"
    chk "file: MADT copied" "${work}/PI5BOOT0.TXT" "^acpi_table: APIC .* checksum=ok via XSDT file=APIC.BIN written\$"
    chk "file: DSDT copied via FADT" "${work}/PI5BOOT0.TXT" "^acpi_table: DSDT .* checksum=ok via FADT file=DSDT.BIN written\$"
    chk "file: no table failed" "${work}/PI5BOOT0.TXT" "^acpi_dump: copied=[0-9]+ failed=0\$"
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
    done < <(sed -nE "s/^acpi_table: ([A-Z0-9_]{4}) rev=[0-9]+ len=([0-9]+) .* file=([A-Z0-9_]+\.BIN) written\$/\1 \2 \3/p" "${work}/PI5BOOT0.TXT")
    echo "---- PI5BOOT0.TXT ----"; cat "${work}/PI5BOOT0.TXT"; echo "----"
else
    echo "FAIL  PI5BOOT0.TXT not found in the image"; fails=$((fails + 1))
fi
if [[ ${fails} == 0 ]]; then echo "${tag}: PASS"; exit 0; fi
echo "${tag}: FAIL (${fails} checks)"; exit 1
