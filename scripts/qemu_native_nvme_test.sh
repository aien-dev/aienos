#!/usr/bin/env bash
# qemu_native_nvme_test.sh -- boot a bare-metal AArch64 payload that drives
# QEMU's emulated NVMe controller with the C driver in native/disk.
#
# Two namespaces on one controller: nsid 1 with 512 B LBAs, nsid 2 with
# 4 KiB LBAs. The payload writes, reads back, flushes, checks range refusal,
# resets the controller and checks the data is still there.
#
# Verdict line: AIENOS_STORE_NVME_QEMU: PASS | FAIL | NOT_RUN
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
    echo "AIENOS_STORE_NVME_QEMU: NOT_RUN"
    exit 0
fi
for tool in qemu-system-aarch64 timeout make; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "required tool ${tool} not found"
        echo "AIENOS_STORE_NVME_QEMU: NOT_RUN"
        exit 0
    fi
done

# One QEMU gate at a time; the gate lock record is removed only if it is still
# this run's own (never another run's hold).
if ! gh_lock_take qemu_native_nvme_test "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "AIENOS_STORE_NVME_QEMU: NOT_RUN"
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
    echo "AIENOS_STORE_NVME_QEMU: FAIL"
    exit 1
fi
rm -f "${repo}/native/disk/qemu/build.log"

img1="${out}/ns1.img"
img2="${out}/ns2.img"
log="${out}/qemu.log"
rm -f "${img1}" "${img2}" "${log}"
truncate -s 64M "${img1}"
truncate -s 64M "${img2}"

set +e
timeout --kill-after=5 "${qemu_timeout}" qemu-system-aarch64 \
    -M virt,highmem=off -cpu cortex-a57 -m 256M -smp 1 \
    -nographic -monitor none -serial stdio -no-reboot \
    -kernel "${out}/nvme_payload.elf" \
    -drive "file=${img1},if=none,id=nvm1,format=raw" \
    -drive "file=${img2},if=none,id=nvm2,format=raw" \
    -device nvme,id=nvme0,serial=aienos-lane11 \
    -device nvme-ns,drive=nvm1,bus=nvme0,nsid=1,logical_block_size=512,physical_block_size=512 \
    -device nvme-ns,drive=nvm2,bus=nvme0,nsid=2,logical_block_size=4096,physical_block_size=4096 \
    </dev/null >"${log}" 2>&1
qrc=$?
set -e

tr -d '\r' <"${log}" | grep -v '^$' | tail -25
if [ "${qrc}" -eq 124 ] || [ "${qrc}" -eq 137 ]; then
    echo "QEMU did not power off within ${qemu_timeout} s"
fi
if tr -d '\r' <"${log}" | grep -qx 'NVME_QEMU_PAYLOAD: PASS' && [ "${qrc}" -eq 0 ]; then
    echo "(QEMU emulated NVMe only; not a physical-hardware qualification)"
    echo "AIENOS_STORE_NVME_QEMU: PASS"
    exit 0
fi
echo "AIENOS_STORE_NVME_QEMU: FAIL"
exit 1
