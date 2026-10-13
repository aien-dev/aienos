#!/usr/bin/env bash
# qemu_native_sdhci_test.sh -- boot a bare-metal AArch64 payload that drives
# QEMU's emulated PCI SD Host Controller and SD card with the C driver in
# native/disk (disk_sdhci.c, the Pi 5 microSD driver).
#
# Two boots:
#   spec2-sdsc  host controller spec 2.00, 64 MiB card (standard capacity,
#               byte addressing, power-of-two clock divider)
#   spec3-sdhc  host controller spec 3.00, 4 GiB card (high capacity, block
#               addressing, 10-bit divided clock)
# Each boot writes, reads back, flushes, checks range refusal, re-initialises
# the controller and card and checks the data is still there. Afterwards this
# script reads block 5 out of the card image file and checks the marker the
# payload wrote, so the data is known to have reached the medium.
#
# Verdict line: AIENOS_DISK_SDHCI_QEMU: PASS | FAIL | NOT_RUN
# QEMU is an emulator. PASS here qualifies nothing about physical hardware.
#
# Respects the shared quiet flag: refuses to run (NOT_RUN, exit 0) while
# ~/workspace/.spark-quiet exists, which it only reads, or while another gate
# holds the QEMU gate lock (scripts/lib_gate_hold.sh, aienos#278).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
qemu_timeout="${AIENOS_QEMU_TIMEOUT:-60}"
out_rel="out"
out="${repo}/native/disk/qemu/${out_rel}"
. "${repo}/scripts/lib_gate_hold.sh"

if ! gh_quiet_check; then
    echo "NOT_RUN  ${gh_why}"
    echo "AIENOS_DISK_SDHCI_QEMU: NOT_RUN"
    exit 0
fi
for tool in qemu-system-aarch64 timeout make truncate dd; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "required tool ${tool} not found"
        echo "AIENOS_DISK_SDHCI_QEMU: NOT_RUN"
        exit 0
    fi
done

# One QEMU gate at a time; the gate lock record is removed only if it is still
# this run's own (never another run's hold).
if ! gh_lock_take qemu_native_sdhci_test "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "AIENOS_DISK_SDHCI_QEMU: NOT_RUN"
    exit 0
fi
cleanup() { gh_lock_release; }
trap cleanup EXIT

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
if ! make -s -C "${repo}/native/disk/qemu" OUT="${out_rel}" \
        CC="${cross}gcc" LD="${cross}ld" NM="${cross}nm" >"${repo}/native/disk/qemu/build.log" 2>&1; then
    tail -20 "${repo}/native/disk/qemu/build.log"
    echo "payload build failed"
    echo "AIENOS_DISK_SDHCI_QEMU: FAIL"
    exit 1
fi
rm -f "${repo}/native/disk/qemu/build.log"

mark="AIENOS-SDHCI-QEMU block 5 written by disk_sdhci.c"
verdict=0
run_one() { # name spec-version image-size
    local name="$1" spec="$2" size="$3"
    local img="${out}/sd-${name}.img" log="${out}/qemu-${name}.log" qrc
    rm -f "${img}" "${log}"
    truncate -s "${size}" "${img}"
    echo "== ${name}: sd-spec-version=${spec}, card ${size}"
    set +e
    timeout --kill-after=5 "${qemu_timeout}" qemu-system-aarch64 \
        -M virt,highmem=off -cpu cortex-a57 -m 256M -smp 1 \
        -nographic -monitor none -serial stdio -no-reboot \
        -kernel "${out}/sdhci_payload.elf" \
        -drive "file=${img},if=none,id=aienos_sd,format=raw" \
        -device "sdhci-pci,sd-spec-version=${spec}" \
        -device sd-card,drive=aienos_sd \
        </dev/null >"${log}" 2>&1
    qrc=$?
    set -e
    tr -d '\r' <"${log}" | grep -v '^$' | tail -12
    if [ "${qrc}" -eq 124 ] || [ "${qrc}" -eq 137 ]; then
        echo "QEMU did not power off within ${qemu_timeout} s"
    fi
    if ! tr -d '\r' <"${log}" | grep -qx 'SDHCI_QEMU_PAYLOAD: PASS' || [ "${qrc}" -ne 0 ]; then
        echo "${name}: FAIL"
        verdict=1
        return
    fi
    if [ "$(dd if="${img}" bs=512 skip=5 count=1 status=none | head -c "${#mark}")" != "${mark}" ]; then
        echo "${name}: marker not found in block 5 of the card image (FAIL)"
        verdict=1
        return
    fi
    echo "${name}: PASS (marker read back from the card image file)"
}

run_one spec2-sdsc 2 64M
run_one spec3-sdhc 3 4G
rm -f "${out}"/sd-*.img

if [ "${verdict}" -eq 0 ]; then
    echo "(QEMU emulated SD host controller and card only; not a physical-hardware qualification)"
    echo "AIENOS_DISK_SDHCI_QEMU: PASS"
    exit 0
fi
echo "AIENOS_DISK_SDHCI_QEMU: FAIL"
exit 1
