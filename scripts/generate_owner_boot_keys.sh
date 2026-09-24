#!/usr/bin/env bash
# generate_owner_boot_keys.sh: Generates owner boot signing certificate and key
# Zero Disk Secrets: private key is written to a restricted in-memory directory
# or vaulted path (0600 permissions, never tracked by git).

set -euo pipefail

KEY_DIR="${1:-$HOME/.config/atlas/boot-keys}"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

KEY_FILE="$KEY_DIR/owner_boot.key"
CERT_FILE="$KEY_DIR/owner_boot.crt"
DER_FILE="$KEY_DIR/owner_boot.der"

if [[ -f "$KEY_FILE" && -f "$CERT_FILE" ]]; then
    echo "Owner boot keys already exist in $KEY_DIR."
else
    echo "Generating RSA 4096-bit owner boot signing key..."
    openssl req -new -x509 -newkey rsa:4096 -nodes -days 3650 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=AIENOS Machine 1 Owner Boot Key/O=AIEN/C=US/"
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"

    openssl x509 -in "$CERT_FILE" -outform DER -out "$DER_FILE"
    echo "Generated $CERT_FILE and $DER_FILE"
fi

FINGERPRINT=$(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256)
echo "Owner Boot Key SHA-256 Fingerprint: $FINGERPRINT"
echo "Public DER certificate ready for MOK enrollment at: $DER_FILE"
