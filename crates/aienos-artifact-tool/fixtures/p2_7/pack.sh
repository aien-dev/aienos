#!/usr/bin/env bash
# Pack and sign the PI5-7 cut 3 probes with the TEST ONLY SEED-0B identity (RFC 8032 TEST 1 key, public) into
# OUT_DIR as P27KREAD.AIEN, P27KWRITE.AIEN and P27PRIV.AIEN, and append "NAME ARTIFACT_ID" to OUT_DIR/ids.txt.
# CODE_DIR (optional) holds <probe>/code.bin variants from assemble.sh; default: the committed Pi code.bin.
#
# TOOL is the in-tree ck_artifact_tool (make -C native/kernel tool) or a debug aienos-artifact-tool built with
# --features seed0b-test-signing (release builds refuse that feature).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: pack.sh TOOL OUT_DIR [CODE_DIR]}"
out="${2:?usage: pack.sh TOOL OUT_DIR [CODE_DIR]}"
codes="${3:-}"
mkdir -p "${out}"
touch "${out}/ids.txt"

pack_one() { # probe, output name
    local probe="$1" name="$2" code="${here}/${1}/code.bin"
    if [[ -n "${codes}" ]]; then code="${codes}/${probe}/code.bin"; fi
    "${tool}" pack "${here}/${probe}/manifest.json" "${code}" \
        "${here}/${probe}/data.bin" "${out}/${probe}.unsigned.aien" >/dev/null
    "${tool}" sign "${out}/${probe}.unsigned.aien" "${out}/${name}" >/dev/null
    rm -f "${out}/${probe}.unsigned.aien"
    "${tool}" verify "${out}/${name}" >/dev/null
    echo "${name} $("${tool}" id "${out}/${name}")" >>"${out}/ids.txt"
}

pack_one p27kread P27KREAD.AIEN
pack_one p27kwrite P27KWRITE.AIEN
pack_one p27priv P27PRIV.AIEN
