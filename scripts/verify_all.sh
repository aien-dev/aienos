#!/usr/bin/env bash
# AIENOS End-to-End Build and Evidence Verification Harness
# Enforces sequential integration gates on the host DGX Spark environment.

set -euo pipefail
#
# AIENOS_STRICT=1 turns every SKIPPED step into a failure, so a green strict
# run proves every step really ran. AIENOS_LOG_DIR=<dir> makes the QEMU
# scripts copy their serial logs into <dir> (used by scripts/m3_receipt.sh).
# Without either variable the behaviour is unchanged.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then
    mkdir -p "${AIENOS_LOG_DIR}"
    AIENOS_LOG_DIR="$(cd "${AIENOS_LOG_DIR}" && pwd)"
    export AIENOS_LOG_DIR
fi
cd "${REPO_ROOT}"

skipped() {
    echo "SKIPPED: $*"
    if [[ "${AIENOS_STRICT:-0}" == "1" ]]; then
        echo "STRICT FAIL: a step was skipped under AIENOS_STRICT=1 ($*)" >&2
        exit 1
    fi
}

echo "============================================================"
echo "AIENOS Integration Verification Harness"
echo "Host: $(uname -n) | Arch: $(uname -m) | Kernel: $(uname -r)"
echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Strict: ${AIENOS_STRICT:-0} | Serial log dir: ${AIENOS_LOG_DIR:-none}"
echo "============================================================"

# Step 1: Gate 1 Verification (Config A Reference Bundle)
echo ""
echo "--- [Gate 1 Verification: Config A Freeze] ---"
if [[ ! -f "evidence/config_a_reference_bundle.json" ]]; then
    echo "Running freeze_reality.sh..."
    ./scripts/freeze_reality.sh
fi
./scripts/verify_evidence.sh "evidence/config_a_reference_bundle.json"
echo "PASS  Gate 1 Config A reference bundle verified"

# Step 1b: Formatting
echo ""
echo "--- [Formatting: cargo fmt --check] ---"
cargo fmt --all --check
echo "PASS  formatting: cargo fmt --all --check"

# Step 2: Host component test suite
echo ""
echo "--- [Host Component Testing: Workspace Crates] ---"
cargo test --workspace
echo "PASS  host tests: cargo test --workspace"
echo "PASS  ABI conformance: frozen wire format golden bytes and roundtrips verified"

# Step 3: Linting & Zero-Warning Enforcement
echo ""
echo "--- [Clippy Verification: -D warnings] ---"
cargo clippy --workspace --all-targets -- -D warnings
echo "PASS  clippy: zero warnings with -D warnings"

# Step 4: Bare-metal library compilation check (not a boot test)
echo ""
echo "--- [Bare-Metal Target Compilation Check] ---"
cargo check -p aienos-kernel --target aarch64-unknown-none --no-default-features
cargo build -p aienos-kernel --target aarch64-unknown-none --no-default-features
echo "PASS  AArch64 build: aienos-kernel for aarch64-unknown-none"

# Step 5: Build an AArch64 UEFI diagnostic image and inspect its PE header.
# This verifies the firmware entry artifact format, not a hardware boot.
echo ""
echo "--- [AArch64 UEFI Image Builds] ---"
cargo build --release -p aienos-boot --target aarch64-unknown-uefi --features firmware --bin aienos-boot
cargo run --quiet --release -p aienos-evidence -- verify-efi target/aarch64-unknown-uefi/release/aienos-boot.efi
cargo build --release -p aienos-boot --target aarch64-unknown-uefi --features handoff --bin aienos-handoff
cargo run --quiet --release -p aienos-evidence -- verify-efi target/aarch64-unknown-uefi/release/aienos-handoff.efi
echo "PASS  AArch64 build: aienos-boot.efi and aienos-handoff.efi PE headers verified"

# Step 6: QEMU AArch64 UEFI Boot Verification (Emulator Boot Test)
echo ""
echo "--- [QEMU AArch64 UEFI Boot Verification] ---"
if command -v qemu-system-aarch64 >/dev/null && [[ -r "${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}" ]]; then
    ./scripts/qemu_boot_test.sh
else
    skipped "qemu-system-aarch64 or AAVMF firmware not present on host."
fi

# Step 6b: SEED-0A USB keyboard candidate, proven in QEMU only (ADR 0012).
echo ""
echo "--- [SEED-0A USB Keyboard in QEMU (input.keyboard.usb)] ---"
if command -v qemu-system-aarch64 >/dev/null && [[ -r "${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}" ]]; then
    # Never an unsafe DMA bypass build here: clear any inherited override.
    unset AIENOS_UNSAFE_DMA_BYPASS AIENOS_BUILD_FEATURES
    # Default mode: keyboard DMA only through a QEMU SMMUv3 stream.
    AIENOS_QEMU_SMMU=1 ./scripts/qemu_keyboard_test.sh
else
    skipped "qemu-system-aarch64 or AAVMF firmware not present on host."
fi

# Step 6c: SMMUv3 DMA confinement of the xHCI keyboard, QEMU only.
echo ""
echo "--- [SMMUv3 DMA Confinement in QEMU] ---"
if command -v qemu-system-aarch64 >/dev/null && [[ -r "${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}" ]]; then
    ./scripts/qemu_smmu_test.sh
    # No SMMU and no bypass: the keyboard must stay unavailable, DMA off.
    AIENOS_QEMU_SMMU=0 ./scripts/qemu_keyboard_test.sh
else
    skipped "qemu-system-aarch64 or AAVMF firmware not present on host."
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
    skipped "qemu-system-aarch64, swtpm, or AAVMF firmware not present on host."
fi

# Step 8: TRUST-1 Gate 1 Standalone Recovery Verification (Zero-Disk Boot)
echo ""
echo "--- [TRUST-1 Gate 1 Standalone Recovery Verification] ---"
if command -v qemu-system-aarch64 >/dev/null; then
    ./scripts/qemu_verify_recovery_media.sh
else
    skipped "qemu-system-aarch64 not present on host."
fi

# Step 9: Recovery Media Tooling Manifest (issue #17; host-side, no real
# devices, no root -- extracts the built initrd and checks file presence).
echo ""
echo "--- [Recovery Media Tooling Manifest] ---"
if command -v gzip >/dev/null && command -v cpio >/dev/null; then
    ./scripts/verify_recovery_tools.sh
else
    skipped "gzip or cpio not present on host."
fi
