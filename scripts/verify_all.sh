#!/usr/bin/env bash
# AIENOS End-to-End Build and Evidence Verification Harness
# Enforces sequential integration gates on the host DGX Spark environment.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "============================================================"
echo "AIENOS Integration Verification Harness"
echo "Host: $(uname -n) | Arch: $(uname -m) | Kernel: $(uname -r)"
echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "============================================================"

# Step 1: Gate 1 Verification (Config A Reference Bundle)
echo ""
echo "--- [Gate 1 Verification: Config A Freeze] ---"
if [[ ! -f "evidence/config_a_reference_bundle.json" ]]; then
    echo "Running freeze_reality.sh..."
    ./scripts/freeze_reality.sh
fi
./scripts/verify_evidence.sh "evidence/config_a_reference_bundle.json"

# Step 2: Host component test suite
echo ""
echo "--- [Host Component Testing: Workspace Crates] ---"
cargo test --workspace

# Step 3: Linting & Zero-Warning Enforcement
echo ""
echo "--- [Clippy Verification: -D warnings] ---"
cargo clippy --workspace --all-targets -- -D warnings

# Step 4: Bare-metal library compilation check (not a boot test)
echo ""
echo "--- [Bare-Metal Target Compilation Check] ---"
cargo check -p aienos-kernel --target aarch64-unknown-none --no-default-features
cargo build -p aienos-kernel --target aarch64-unknown-none --no-default-features

# Step 5: Build an AArch64 UEFI diagnostic image and inspect its PE header.
# This verifies the firmware entry artifact format, not a hardware boot.
echo ""
echo "--- [AArch64 UEFI Image Builds] ---"
cargo build --release -p aienos-boot --target aarch64-unknown-uefi --features firmware --bin aienos-boot
cargo run --quiet --release -p aienos-evidence -- verify-efi target/aarch64-unknown-uefi/release/aienos-boot.efi
cargo build --release -p aienos-boot --target aarch64-unknown-uefi --features handoff --bin aienos-handoff
cargo run --quiet --release -p aienos-evidence -- verify-efi target/aarch64-unknown-uefi/release/aienos-handoff.efi

echo ""
echo "============================================================"
echo "HOST VERIFICATIONS PASSED."
echo "Config A: observed capture and three local inference samples verified."
echo "Kernel: aarch64-unknown-none library compiles. Native boot remains untested."
echo "UEFI: diagnostic and GB10-discovering handoff images build; hardware boot remains untested."
echo "============================================================"
