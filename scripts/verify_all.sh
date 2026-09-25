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
cargo test --workspace -- --format=pretty
echo "PASS  host tests: cargo test --workspace -- --format=pretty"
echo "PASS  ABI conformance: frozen wire format golden bytes and roundtrips verified"

# Step 3: Linting & Zero-Warning Enforcement
echo ""
echo "--- [Clippy Verification: -D warnings] ---"
cargo clippy --workspace --all-targets -- -D warnings
echo "PASS  clippy: zero warnings with -D warnings"

# Step 3b: target-only code (bare-metal kernel, UEFI images) is invisible to
# the host clippy run above, so lint each shipped target/feature set too.
echo ""
echo "--- [Clippy Verification: AArch64 targets, -D warnings] ---"
cargo clippy -p aienos-kernel --target aarch64-unknown-none --no-default-features -- -D warnings
cargo clippy -p aienos-kernel --target aarch64-unknown-none --no-default-features --features seed0b-test-anchor -- -D warnings
for features in firmware handoff seed0b-qualification usb-keyboard nvme-read nvme-write store-qual; do
    cargo clippy -p aienos-boot --target aarch64-unknown-uefi --features "${features}" --bins -- -D warnings
done
echo "PASS  clippy: aarch64-unknown-none kernel and aarch64-unknown-uefi images, zero warnings"

# Step 3c: TEST-ONLY SEED-0B qualification code paths are feature-gated and
# so absent from the default runs above; test and lint them explicitly.
echo ""
echo "--- [SEED-0B qualification features: tests and clippy] ---"
cargo test -p aienos-artifact --features seed0b-test-anchor
cargo test -p aienos-artifact-tool --features seed0b-test-signing
cargo clippy -p aienos-artifact-tool --all-targets --features seed0b-test-signing -- -D warnings
if cargo build --release -p aienos-artifact-tool --features seed0b-test-signing >/dev/null 2>&1; then
    echo "FAIL  release build accepted the TEST-ONLY SEED-0B signing identity" >&2
    exit 1
fi
echo "PASS  SEED-0B qualification features tested and linted; release build refuses the test signing identity"

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

# Step 6a: P2-5 Binary Artifact loader. Signed candidates are staged,
# verified, admitted, run at EL0 from their exact authenticated bytes under
# W^X, and reclaimed; the ordinary build rejects every one (QEMU only).
echo ""
echo "--- [P2-5 Binary Artifact Loader in QEMU] ---"
if command -v qemu-system-aarch64 >/dev/null && [[ -r "${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}" ]]; then
    ./scripts/qemu_artifact_test.sh
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

# Step 6d: M0 Native-Boot Rollback Verification (QEMU only).
echo ""
echo "--- [M0 Native-Boot Rollback Verification in QEMU] ---"
if command -v qemu-system-aarch64 >/dev/null && [[ -r "${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}" ]]; then
    ./scripts/qemu_native_rollback_test.sh
else
    skipped "qemu-system-aarch64 or AAVMF firmware not present on host."
fi

# Step 6e: P3 native NVMe driver and System Store v1 over NVMe (QEMU only).
# Read and write/flush in both DMA modes (SMMU-confined, and fail-closed with
# no SMMU), 4K root-write atomicity, the 4K Store crash/reboot campaign and the
# 512-byte Store campaign. Never an unsafe DMA bypass build here.
echo ""
echo "--- [P3 NVMe + System Store v1 in QEMU] ---"
if command -v qemu-system-aarch64 >/dev/null && [[ -r "${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}" ]]; then
    unset AIENOS_UNSAFE_DMA_BYPASS AIENOS_BUILD_FEATURES
    AIENOS_QEMU_SMMU=1 ./scripts/qemu_nvme_test.sh
    AIENOS_QEMU_SMMU=0 ./scripts/qemu_nvme_test.sh
    AIENOS_QEMU_SMMU=1 ./scripts/qemu_nvme_rw_test.sh
    AIENOS_QEMU_SMMU=0 ./scripts/qemu_nvme_rw_test.sh
    ./scripts/qemu_nvme_atomicity_test.sh
    ./scripts/qemu_store_crash_test.sh
    ./scripts/qemu_store_512b_crash_test.sh
else
    skipped "qemu-system-aarch64 or AAVMF firmware not present on host."
fi

echo ""
echo "============================================================"
echo "HOST VERIFICATIONS PASSED."
echo "Config A: observed capture verified. M0 native-boot rollback proven in QEMU."
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
