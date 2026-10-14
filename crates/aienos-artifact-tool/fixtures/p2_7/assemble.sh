#!/usr/bin/env bash
# Reassemble every PI5-7 cut 3 probe from probe.S into OUT_DIR/<probe>/code.bin.
# The committed code.bin files are the Raspberry Pi 5 qualification inputs (kernel read at 0x210000, kernel
# write at 0x2000000, the addresses the Pi image's own mmu_switch / memory lines print); this script proves
# they are exactly what probe.S assembles to, and builds other platforms' variants (the QEMU twin gate
# passes the addresses its own kernel prints):
#   KREAD_ADDR=0x40000000 KWRITE_ADDR=0x4a000000 assemble.sh OUT_DIR
# Needs an AArch64 GNU `as` and `objcopy` (native on the Spark).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: assemble.sh OUT_DIR}"
as_bin="${AS:-as}"
objcopy_bin="${OBJCOPY:-objcopy}"
if [[ "$(uname -m)" != "aarch64" ]]; then
    as_bin="${AS:-aarch64-linux-gnu-as}"
    objcopy_bin="${OBJCOPY:-aarch64-linux-gnu-objcopy}"
fi
kread="${KREAD_ADDR:-0x210000}"
kwrite="${KWRITE_ADDR:-0x2000000}"
[[ "${kread}" =~ ^0x[0-9a-fA-F]{1,16}$ && "${kwrite}" =~ ^0x[0-9a-fA-F]{1,16}$ ]] || { echo "FAIL addresses must be 0x<hex>" >&2; exit 1; }

for probe in p27kread p27kwrite p27priv; do
    mkdir -p "${out}/${probe}"
    "${as_bin}" --defsym "KADDR=$([[ ${probe} == p27kread ]] && echo "${kread}" || echo "${kwrite}")" \
        -o "${out}/${probe}/probe.o" "${here}/${probe}/probe.S"
    # A probe must be fully resolved: no relocations, so the bytes the kernel authenticates are the bytes
    # that execute, with no loader fix-ups.
    if command -v readelf >/dev/null; then
        if readelf -r "${out}/${probe}/probe.o" | grep -q "Relocation section"; then
            echo "FAIL ${probe} has relocations" >&2
            exit 1
        fi
    fi
    "${objcopy_bin}" -O binary -j .text "${out}/${probe}/probe.o" "${out}/${probe}/code.bin"
done
