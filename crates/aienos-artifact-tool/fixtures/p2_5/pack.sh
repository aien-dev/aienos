#!/usr/bin/env bash
# Pack and sign the P2-5 probes with the TEST ONLY SEED-0B identity into
# OUT_DIR as P25EXEC.AIEN, P25WX.AIEN, P25SPIN.AIEN, and P25TAMP.AIEN
# (P25EXEC with one payload byte flipped after signing). Also writes
# OUT_DIR/ids.txt: "NAME ARTIFACT_ID" per signed probe.
#
# TOOL must be a debug aienos-artifact-tool built with
# --features seed0b-test-signing (release builds refuse that feature).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: pack.sh TOOL OUT_DIR}"
out="${2:?usage: pack.sh TOOL OUT_DIR}"
mkdir -p "${out}"
: >"${out}/ids.txt"

pack_one() { # probe, output name
    local probe="$1" name="$2"
    "${tool}" pack "${here}/${probe}/manifest.json" "${here}/${probe}/code.bin" \
        "${here}/${probe}/data.bin" "${out}/${probe}.unsigned.aien" >/dev/null
    "${tool}" sign "${out}/${probe}.unsigned.aien" "${out}/${name}" >/dev/null
    rm -f "${out}/${probe}.unsigned.aien"
    "${tool}" verify "${out}/${name}" >/dev/null
    echo "${name} $("${tool}" id "${out}/${name}")" >>"${out}/ids.txt"
}

pack_one p25exec P25EXEC.AIEN
pack_one p25wx P25WX.AIEN
pack_one p25spin P25SPIN.AIEN

# Tamper: flip the low bit of the first payload byte (first code byte) of
# the signed P25EXEC. Its ArtifactId changes, so the signature must fail.
cp "${out}/P25EXEC.AIEN" "${out}/P25TAMP.AIEN"
payload_offset=$(od -An -tu4 -j56 -N4 "${out}/P25TAMP.AIEN" | tr -d ' ')
byte=$(od -An -tu1 -j"${payload_offset}" -N1 "${out}/P25TAMP.AIEN" | tr -d ' ')
printf "$(printf '\\%03o' $((byte ^ 1)))" |
    dd of="${out}/P25TAMP.AIEN" bs=1 seek="${payload_offset}" conv=notrunc status=none
if "${tool}" verify "${out}/P25TAMP.AIEN" >/dev/null 2>&1; then
    echo "FAIL  tampered probe still verifies" >&2
    exit 1
fi
if cmp -s "${out}/P25EXEC.AIEN" "${out}/P25TAMP.AIEN"; then
    echo "FAIL  tampering did not change the file" >&2
    exit 1
fi
