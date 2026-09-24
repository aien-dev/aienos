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

# Step 6: QEMU AArch64 UEFI Boot Verification (Emulator Boot Test)
echo ""
echo "--- [QEMU AArch64 UEFI Boot Verification] ---"
if command -v qemu-system-aarch64 >/dev/null && [[ -r "${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}" ]]; then
    ./scripts/qemu_boot_test.sh
else
    echo "SKIPPED: qemu-system-aarch64 or AAVMF firmware not present on host."
fi

echo ""
echo "============================================================"
echo "HOST VERIFICATIONS PASSED."
echo "Config A: observed capture verified. M0 stays open until native-boot rollback is tested."
echo "Kernel: aarch64-unknown-none library compiles. Native boot remains untested."
echo "UEFI: diagnostic and GB10-discovering handoff images build; hardware boot remains untested."
echo "============================================================"

# Step 7: TRUST-1 Gate 4 Security Suite (swTPM, Soak, Fault Injection)
echo ""
echo "--- [TRUST-1 Gate 4 Security Suite Verification] ---"
if command -v qemu-system-aarch64 >/dev/null && command -v swtpm >/dev/null && [[ -r "${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}" ]]; then
    GATE4_SOAK_RUNS=3 ./scripts/qemu_security_suite.sh
else
    echo "SKIPPED: qemu-system-aarch64, swtpm, or AAVMF firmware not present on host."
fi

# Step 8: TRUST-1 Gate 1 Standalone Recovery Verification (Zero-Disk Boot)
echo ""
echo "--- [TRUST-1 Gate 1 Standalone Recovery Verification] ---"
if command -v qemu-system-aarch64 >/dev/null; then
    ./scripts/qemu_verify_recovery_media.sh
else
    echo "SKIPPED: qemu-system-aarch64 not present on host."
fi

# Step 9: Recovery Media Tooling Manifest (issue #17; host-side, no real
# devices, no root -- extracts the built initrd and checks file presence).
echo ""
echo "--- [Recovery Media Tooling Manifest] ---"
if command -v gzip >/dev/null && command -v cpio >/dev/null; then
    ./scripts/verify_recovery_tools.sh
else
    echo "SKIPPED: gzip or cpio not present on host."
fi
