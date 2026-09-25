#!/usr/bin/env bash
# Reassemble the P2-6 SEED-0B probe from probe.S into OUT_DIR/<probe>/code.bin.
# The committed code.bin is the qualification input; this proves it is
# exactly what probe.S assembles to, with no relocations.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: assemble.sh OUT_DIR}"
as_bin="${AS:-as}"
objcopy_bin="${OBJCOPY:-objcopy}"
if [[ "$(uname -m)" != "aarch64" ]]; then
    as_bin="${AS:-aarch64-linux-gnu-as}"
    objcopy_bin="${OBJCOPY:-aarch64-linux-gnu-objcopy}"
fi

for probe in p26seed; do
    mkdir -p "${out}/${probe}"
    "${as_bin}" -o "${out}/${probe}/probe.o" "${here}/${probe}/probe.S"
    if command -v readelf >/dev/null; then
        if readelf -r "${out}/${probe}/probe.o" | grep -q "Relocation section"; then
            echo "FAIL  ${probe} has relocations" >&2
            exit 1
        fi
    fi
    "${objcopy_bin}" -O binary -j .text "${out}/${probe}/probe.o" "${out}/${probe}/code.bin"
done
