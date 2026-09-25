#!/usr/bin/env bash
# Pack and sign the first SEED-0B capability artifact with the TEST ONLY
# SEED-0B identity into OUT_DIR/P26SEED.AIEN and append "NAME ARTIFACT_ID"
# to OUT_DIR/ids.txt.
#
# TOOL must be a debug aienos-artifact-tool built with
# --features seed0b-test-signing (release builds refuse that feature).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: pack.sh TOOL OUT_DIR}"
out="${2:?usage: pack.sh TOOL OUT_DIR}"
mkdir -p "${out}"
touch "${out}/ids.txt"

"${tool}" pack "${here}/p26seed/manifest.json" "${here}/p26seed/code.bin" \
    "${here}/p26seed/data.bin" "${out}/p26seed.unsigned.aien" >/dev/null
"${tool}" sign "${out}/p26seed.unsigned.aien" "${out}/P26SEED.AIEN" >/dev/null
rm -f "${out}/p26seed.unsigned.aien"
"${tool}" verify "${out}/P26SEED.AIEN" >/dev/null
echo "P26SEED.AIEN $("${tool}" id "${out}/P26SEED.AIEN")" >>"${out}/ids.txt"
