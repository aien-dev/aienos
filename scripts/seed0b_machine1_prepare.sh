#!/usr/bin/env bash
# P2-9 preparation ONLY: build the exact SEED-0B qualification inputs for an
# attended Machine 1 boot into OUT_DIR. This script never touches the ESP,
# BootOrder/BootNext, Secure Boot, TPM state or any firmware variable; the
# operator stages OUT_DIR by the attended procedure in
# docs/SEED0B_MACHINE1_QUALIFICATION.md.
#
# OUT_DIR/
#   BOOTAA64.EFI     aienos-handoff --features seed0b-qualification,hardware-staging
#   ARTIFACTS/       the same signed .AIEN bytes the QEMU qualification uses
#   ids.txt          NAME ARTIFACT_ID
#   expected.txt     negative-matrix expectations
#   MANIFEST.sha256  sha256 of every file above, plus the commit
set -euo pipefail

out_arg="${1:?usage: seed0b_machine1_prepare.sh OUT_DIR}"
# Resolve OUT_DIR against the caller's directory, and start from an empty one
# so no stale file can enter ARTIFACTS/ or MANIFEST.sha256.
mkdir -p "${out_arg}"
out="$(cd "${out_arg}" && pwd)"
if [[ -n "$(ls -A "${out}")" ]]; then
    echo "STOP: ${out} is not empty; prepare into a new or empty directory." >&2
    exit 1
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
case "${out}/" in
    "${repo_root}"/*)
        echo "STOP: OUT_DIR ${out} is inside the repository." >&2
        exit 1
        ;;
esac
if [[ -n "$(git status --porcelain)" ]]; then
    echo "STOP: worktree has uncommitted changes; qualification inputs must come from a commit." >&2
    exit 1
fi
commit="$(git rev-parse HEAD)"
mkdir -p "${out}/ARTIFACTS"

cargo build --quiet -p aienos-artifact-tool --features seed0b-test-signing
tool="target/debug/aienos-artifact-tool"
crates/aienos-artifact-tool/fixtures/p2_5/pack.sh "${tool}" "${out}/ARTIFACTS"
crates/aienos-artifact-tool/fixtures/p2_6/pack.sh "${tool}" "${out}/ARTIFACTS"
"${tool}" negative-corpus "${out}/ARTIFACTS" >/dev/null
mv "${out}/ARTIFACTS/ids.txt" "${out}/ids.txt"
mv "${out}/ARTIFACTS/expected.txt" "${out}/expected.txt"

AIENOS_COMMIT="${commit}" cargo build --quiet --release -p aienos-boot \
    --target aarch64-unknown-uefi --features seed0b-qualification,hardware-staging --bin aienos-handoff
cp target/aarch64-unknown-uefi/release/aienos-handoff.efi "${out}/BOOTAA64.EFI"
cargo run --quiet --release -p aienos-evidence -- verify-efi "${out}/BOOTAA64.EFI"

(
    cd "${out}"
    echo "# commit ${commit}"
    find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum
) >"${out}/MANIFEST.sha256"
echo "PREPARED: ${out} from commit ${commit}"
echo "P26SEED ArtifactId: $(awk '$1 == "P26SEED.AIEN" {print $2}' "${out}/ids.txt")"
echo "NOT STAGED. The image is unsigned: with Secure Boot on (required) it will not"
echo "boot until the TRUST-1 owner-signed chain exists. Follow the procedure."
