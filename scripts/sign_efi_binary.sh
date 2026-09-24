#!/usr/bin/env bash
# sign_efi_binary.sh: Signs an EFI executable with the disposable development signing key
# DISPOSABLE DEVELOPMENT/TEST MATERIAL ONLY.
# Invariant: This is NOT the TRUST-1 Q13 Owner Root or production Boot Signer.
# Invariant: NO PLAINTEXT SECRETS IN REPOSITORY OR BUILD ARTIFACTS. Unslop compliant.

set -euo pipefail

INPUT_EFI="${1:-target/aarch64-unknown-uefi/release/aienos-handoff.efi}"
OUTPUT_EFI="${2:-${INPUT_EFI}.signed}"
KEY_DIR="${HOME}/.config/atlas/boot-keys/dev-only"
KEY_FILE="${KEY_DIR}/dev_boot.key"
CERT_FILE="${KEY_DIR}/dev_boot.crt"

if [[ ! -f "${INPUT_EFI}" ]]; then
    echo "Error: Input EFI binary not found at ${INPUT_EFI}" >&2
    exit 1
fi

if [[ ! -f "${KEY_FILE}" || ! -f "${CERT_FILE}" ]]; then
    echo "Error: Development keys not found in ${KEY_DIR}. Run generate_owner_boot_keys.sh first." >&2
    exit 1
fi

echo "Signing ${INPUT_EFI} with development certificate..."
sbsign --key "${KEY_FILE}" --cert "${CERT_FILE}" --output "${OUTPUT_EFI}" "${INPUT_EFI}"

echo "Verifying signature on ${OUTPUT_EFI}..."
sbverify --cert "${CERT_FILE}" "${OUTPUT_EFI}"
echo "PASS: Binary successfully signed and verified with Disposable Dev Boot Key."
