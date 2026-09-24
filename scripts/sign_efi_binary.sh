#!/usr/bin/env bash
# sign_efi_binary.sh: Signs an EFI executable with the owner boot signing key
# Zero Disk Secrets and Unslop compliant.

set -euo pipefail

INPUT_EFI="${1:-target/aarch64-unknown-uefi/release/aienos-handoff.efi}"
OUTPUT_EFI="${2:-${INPUT_EFI}.signed}"
KEY_DIR="${HOME}/.config/atlas/boot-keys"
KEY_FILE="${KEY_DIR}/owner_boot.key"
CERT_FILE="${KEY_DIR}/owner_boot.crt"

if [[ ! -f "${INPUT_EFI}" ]]; then
    echo "Error: Input EFI binary not found at ${INPUT_EFI}" >&2
    exit 1
fi

if [[ ! -f "${KEY_FILE}" || ! -f "${CERT_FILE}" ]]; then
    echo "Error: Owner keys not found in ${KEY_DIR}. Run generate_owner_boot_keys.sh first." >&2
    exit 1
fi

echo "Signing ${INPUT_EFI} with owner certificate..."
sbsign --key "${KEY_FILE}" --cert "${CERT_FILE}" --output "${OUTPUT_EFI}" "${INPUT_EFI}"

echo "Verifying signature on ${OUTPUT_EFI}..."
sbverify --cert "${CERT_FILE}" "${OUTPUT_EFI}"
echo "PASS: Binary successfully signed and verified with Owner Boot Key."
