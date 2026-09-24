#!/usr/bin/env bash
# generate_owner_boot_keys.sh: Generates disposable development/test MOK signing key
# DISPOSABLE DEVELOPMENT/TEST MATERIAL ONLY.
# Invariant: This is NOT the TRUST-1 Q13 Owner Root or production Boot Signer.
# The production root of trust requires an air-gapped offline ceremony (Gate 3).
# Keys generated here are strictly for local development and test MOK database enrollment.
# Invariant: NO PLAINTEXT SECRETS IN REPOSITORY OR BUILD ARTIFACTS. Unslop compliant.

set -euo pipefail

KEY_DIR="${1:-$HOME/.config/atlas/boot-keys/dev-only}"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

KEY_FILE="$KEY_DIR/dev_boot.key"
CERT_FILE="$KEY_DIR/dev_boot.crt"
DER_FILE="$KEY_DIR/dev_boot.der"

if [[ -f "$KEY_FILE" && -f "$CERT_FILE" ]]; then
    echo "Development boot keys already exist in $KEY_DIR."
else
    echo "Generating disposable development RSA 4096-bit signing key..."
    openssl req -new -x509 -newkey rsa:4096 -nodes -days 365 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=AIENOS Disposable Dev Boot Key/O=AIEN/C=US/"
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"

    openssl x509 -in "$CERT_FILE" -outform DER -out "$DER_FILE"
    echo "Generated $CERT_FILE and $DER_FILE"
fi

FINGERPRINT=$(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256)
echo "Development Boot Key SHA-256 Fingerprint: $FINGERPRINT"
echo "Public DER certificate for test MOK enrollment at: $DER_FILE"
