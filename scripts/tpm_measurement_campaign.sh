#!/usr/bin/env bash
# tpm_measurement_campaign.sh: Non-destructive capture of TPM PCR banks and event log
# Strict Unslop / Zero Disk Secrets compliant

set -euo pipefail

OUT_DIR="${1:-evidence/tpm_campaign_$(date -u +%Y%m%d_%H%M%SZ)}"
mkdir -p "$OUT_DIR"

echo "Capturing complete TPM PCR banks..."
tpm2_pcrread sha1 > "$OUT_DIR/pcr_sha1.txt" 2>&1 || true
tpm2_pcrread sha256 > "$OUT_DIR/pcr_sha256.txt" 2>&1 || true
tpm2_pcrread sha384 > "$OUT_DIR/pcr_sha384.txt" 2>&1 || true

echo "Capturing TPM binary BIOS measurements..."
if [ -r /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    cp /sys/kernel/security/tpm0/binary_bios_measurements "$OUT_DIR/binary_bios_measurements.bin"
    sha256sum "$OUT_DIR/binary_bios_measurements.bin" > "$OUT_DIR/binary_bios_measurements.sha256"
    tpm2_eventlog "$OUT_DIR/binary_bios_measurements.bin" > "$OUT_DIR/eventlog_parsed.yaml" 2>&1 || true
else
    echo "Warning: /sys/kernel/security/tpm0/binary_bios_measurements not readable" > "$OUT_DIR/eventlog_error.txt"
fi

echo "Capturing Secure Boot state..."
mokutil --sb-state > "$OUT_DIR/secure_boot_state.txt" 2>&1 || true

echo "TPM measurement campaign output saved to $OUT_DIR"
