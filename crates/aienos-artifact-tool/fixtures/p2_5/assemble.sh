#!/usr/bin/env bash
# Reassemble every P2-5 probe from probe.S into OUT_DIR/<probe>/code.bin.
# The committed code.bin files are the qualification inputs; this script
# only exists to prove they are exactly what probe.S assembles to.
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

for probe in p25exec p25wx p25spin; do
    mkdir -p "${out}/${probe}"
    "${as_bin}" -o "${out}/${probe}/probe.o" "${here}/${probe}/probe.S"
    # A probe must be fully resolved: no relocations, so the bytes the kernel
    # authenticates are the bytes that execute, with no loader fix-ups.
    if command -v readelf >/dev/null; then
        if readelf -r "${out}/${probe}/probe.o" | grep -q "Relocation section"; then
            echo "FAIL  ${probe} has relocations" >&2
            exit 1
        fi
    fi
    "${objcopy_bin}" -O binary -j .text "${out}/${probe}/probe.o" "${out}/${probe}/code.bin"
done
