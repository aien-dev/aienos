#!/usr/bin/env bash
# tests/p3-store-crash-qemu/test_disk_lifecycle.sh
#
# Verification and Unit Test Suite for disk_lifecycle.sh
# Tests determinism, safety assertions, copy-on-write isolation,
# digest calculations, and disposal semantics.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIFECYCLE="${SCRIPT_DIR}/disk_lifecycle.sh"

TEST_WORK_DIR=$(mktemp -d "/tmp/aienos_disk_test_XXXXXX")
trap 'rm -rf "${TEST_WORK_DIR}"' EXIT

PASSED_COUNT=0
FAILED_COUNT=0

assert_eq() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"

    if [[ "${expected}" == "${actual}" ]]; then
        echo "  [PASS] ${test_name}"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo "  [FAIL] ${test_name}: expected '${expected}', got '${actual}'" >&2
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
}

assert_success() {
    local test_name="$1"
    shift
    if "$@"; then
        echo "  [PASS] ${test_name}"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo "  [FAIL] ${test_name}: command failed: $*" >&2
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
}

assert_failure() {
    local test_name="$1"
    shift
    set +e
    "$@" >/dev/null 2>&1
    local status=$?
    set -e
    if [[ ${status} -ne 0 ]]; then
        echo "  [PASS] ${test_name} (failed as expected with code ${status})"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo "  [FAIL] ${test_name}: command unexpectedly succeeded: $*" >&2
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
}

echo "=== Running P3 Disk Lifecycle Qualification Test Suite ==="

# -----------------------------------------------------------------------------
# Test 1: Deterministic Zero Base Creation and Sizing
# -----------------------------------------------------------------------------
echo "[1/10] Testing deterministic zeroed base image generation..."
BASE_4M="${TEST_WORK_DIR}/base_4m.img"
assert_success "Create 4 MiB base image" "${LIFECYCLE}" create-base "${BASE_4M}" 4 zero

ACTUAL_SIZE_4M=$(stat -c %s "${BASE_4M}")
EXPECTED_SIZE_4M=$(( 4 * 1024 * 1024 ))
assert_eq "4 MiB image byte size is exact" "${EXPECTED_SIZE_4M}" "${ACTUAL_SIZE_4M}"

DIGEST_4M_1=$("${LIFECYCLE}" hash-image "${BASE_4M}")
# Recreate and check determinism
rm -f "${BASE_4M}"
"${LIFECYCLE}" create-base "${BASE_4M}" 4 zero >/dev/null
DIGEST_4M_2=$("${LIFECYCLE}" hash-image "${BASE_4M}")
assert_eq "Zeroed base image hash is deterministic" "${DIGEST_4M_1}" "${DIGEST_4M_2}"

# Test sparse image produces identical zero digest
BASE_4M_SPARSE="${TEST_WORK_DIR}/base_4m_sparse.img"
"${LIFECYCLE}" create-base "${BASE_4M_SPARSE}" 4 sparse >/dev/null
DIGEST_SPARSE=$("${LIFECYCLE}" hash-image "${BASE_4M_SPARSE}")
assert_eq "Sparse base image hash matches zeroed base image hash" "${DIGEST_4M_1}" "${DIGEST_SPARSE}"

# -----------------------------------------------------------------------------
# Test 2: Deterministic 64 MiB NVMe Zero Image Canonical Digest
# -----------------------------------------------------------------------------
echo "[2/10] Testing canonical 64 MiB NVMe image..."
BASE_64M="${TEST_WORK_DIR}/base_64m.img"
"${LIFECYCLE}" create-base "${BASE_64M}" 64 zero >/dev/null
DIGEST_64M=$("${LIFECYCLE}" hash-image "${BASE_64M}")
KNOWN_ZERO_64M="3b6a07d0d404fab4e23b6d34bc6696a6a312dd92821332385e5af7c01c421351"
assert_eq "64 MiB zero image matches known canonical SHA-256" "${KNOWN_ZERO_64M}" "${DIGEST_64M}"

# -----------------------------------------------------------------------------
# Test 3: Deterministic Byte Pattern Generation (0xAA, 0xFF)
# -----------------------------------------------------------------------------
echo "[3/10] Testing deterministic pattern image generation..."
PAT_AA_1="${TEST_WORK_DIR}/pattern_aa_1.img"
PAT_AA_2="${TEST_WORK_DIR}/pattern_aa_2.img"
"${LIFECYCLE}" create-base "${PAT_AA_1}" 2 0xAA >/dev/null
"${LIFECYCLE}" create-base "${PAT_AA_2}" 2 0xAA >/dev/null

HASH_AA_1=$("${LIFECYCLE}" hash-image "${PAT_AA_1}")
HASH_AA_2=$("${LIFECYCLE}" hash-image "${PAT_AA_2}")
assert_eq "0xAA pattern image is deterministic across runs" "${HASH_AA_1}" "${HASH_AA_2}"
assert_success "verify-identical on matching pattern images" "${LIFECYCLE}" verify-identical "${PAT_AA_1}" "${PAT_AA_2}"

PAT_FF="${TEST_WORK_DIR}/pattern_ff.img"
"${LIFECYCLE}" create-base "${PAT_FF}" 2 0xFF >/dev/null
HASH_FF=$("${LIFECYCLE}" hash-image "${PAT_FF}")
assert_success "verify-changed between 0xAA and 0xFF images" "${LIFECYCLE}" verify-changed "${HASH_AA_1}" "${HASH_FF}"

# -----------------------------------------------------------------------------
# Test 4: Host Device & System Path Safety Guard
# -----------------------------------------------------------------------------
echo "[4/10] Testing host device safety guards (avoiding host system interaction)..."
assert_failure "Reject /dev/null" "${LIFECYCLE}" create-base "/dev/null" 1
assert_failure "Reject /dev/zero" "${LIFECYCLE}" create-base "/dev/zero" 1
assert_failure "Reject /dev/sda" "${LIFECYCLE}" create-base "/dev/sda" 1
assert_failure "Reject /dev/nvme0n1" "${LIFECYCLE}" create-base "/dev/nvme0n1" 1
assert_failure "Reject relative escape to /dev" "${LIFECYCLE}" create-base "${TEST_WORK_DIR}/../../dev/nvme0" 1
assert_failure "Reject root system path /etc/nvme.img" "${LIFECYCLE}" create-base "/etc/nvme.img" 1
assert_failure "Reject root system path /boot/nvme.img" "${LIFECYCLE}" create-base "/boot/nvme.img" 1

# Test symlink pointing to device
SYMLINK_DEV="${TEST_WORK_DIR}/symlink_to_dev"
ln -s /dev/null "${SYMLINK_DEV}"
assert_failure "Reject symlink pointing to /dev/null" "${LIFECYCLE}" create-base "${SYMLINK_DEV}" 1
assert_failure "Reject hashing symlink to /dev/null" "${LIFECYCLE}" hash-image "${SYMLINK_DEV}"
assert_failure "Reject wiping symlink to /dev/null" "${LIFECYCLE}" wipe-instance "${SYMLINK_DEV}"
rm -f "${SYMLINK_DEV}"

# -----------------------------------------------------------------------------
# Test 5: Per-Test Instance Isolation
# -----------------------------------------------------------------------------
echo "[5/10] Testing instance isolation from base image..."
INST_1="${TEST_WORK_DIR}/inst_1.img"
"${LIFECYCLE}" create-instance "${BASE_4M}" "${INST_1}" >/dev/null

PRE_BASE_DIGEST=$("${LIFECYCLE}" hash-image "${BASE_4M}")
PRE_INST_DIGEST=$("${LIFECYCLE}" hash-image "${INST_1}")
assert_eq "Initial instance digest matches base digest" "${PRE_BASE_DIGEST}" "${PRE_INST_DIGEST}"

# Simulate simulated guest crash write: mutate instance at block 512
printf "AIENOS_CRASH_TEST_CORRUPT_BLOCK" | dd of="${INST_1}" bs=1 seek=2048 conv=notrunc status=none
POST_BASE_DIGEST=$("${LIFECYCLE}" hash-image "${BASE_4M}")
POST_INST_DIGEST=$("${LIFECYCLE}" hash-image "${INST_1}")

assert_eq "Base image remains completely untouched after instance mutation" "${PRE_BASE_DIGEST}" "${POST_BASE_DIGEST}"
assert_success "verify-changed detects instance modification" "${LIFECYCLE}" verify-changed "${PRE_INST_DIGEST}" "${POST_INST_DIGEST}"
assert_success "verify-changed confirms instance differs from base" "${LIFECYCLE}" verify-changed "${BASE_4M}" "${INST_1}"

# -----------------------------------------------------------------------------
# Test 6: Cross-Test Multi-Instance Isolation
# -----------------------------------------------------------------------------
echo "[6/10] Testing cross-test multi-instance isolation..."
INST_2="${TEST_WORK_DIR}/inst_2.img"
"${LIFECYCLE}" create-instance "${BASE_4M}" "${INST_2}" >/dev/null

INST_2_DIGEST=$("${LIFECYCLE}" hash-image "${INST_2}")
assert_eq "Instance 2 remains untouched by Instance 1 mutation" "${PRE_BASE_DIGEST}" "${INST_2_DIGEST}"
assert_success "Instance 2 remains identical to base" "${LIFECYCLE}" verify-identical "${BASE_4M}" "${INST_2}"
assert_success "Instance 1 and Instance 2 are strictly isolated" "${LIFECYCLE}" verify-changed "${INST_1}" "${INST_2}"

# -----------------------------------------------------------------------------
# Test 7: Diff Images Capability
# -----------------------------------------------------------------------------
echo "[7/10] Testing binary diffing..."
assert_success "diff-images on identical images" "${LIFECYCLE}" diff-images "${BASE_4M}" "${INST_2}"
assert_failure "diff-images on mutated image detects difference" "${LIFECYCLE}" diff-images "${BASE_4M}" "${INST_1}"

# -----------------------------------------------------------------------------
# Test 8: Disposable Lifecycle / Wipe Semantics
# -----------------------------------------------------------------------------
echo "[8/10] Testing disposable wipe lifecycle..."
assert_success "Wipe instance 1" "${LIFECYCLE}" wipe-instance "${INST_1}"
[[ ! -f "${INST_1}" ]]
assert_eq "Instance 1 is removed from filesystem" "0" "$?"

assert_success "Idempotent wipe on already wiped instance" "${LIFECYCLE}" wipe-instance "${INST_1}"
assert_success "Wipe instance 2" "${LIFECYCLE}" wipe-instance "${INST_2}"

# -----------------------------------------------------------------------------
# Test 9: Output Contract (Pure hash on stdout)
# -----------------------------------------------------------------------------
echo "[9/10] Testing hash-image output contract..."
RAW_HASH=$("${LIFECYCLE}" hash-image "${BASE_4M}")
# Validate that stdout contains only 64 hex characters and newline
assert_eq "Hash is 64 characters long" "64" "${#RAW_HASH}"
[[ "${RAW_HASH}" =~ ^[0-9a-f]{64}$ ]]
assert_eq "Hash is lowercase hexadecimal" "0" "$?"

# -----------------------------------------------------------------------------
# Test 10: Sourced Library Interface
# -----------------------------------------------------------------------------
echo "[10/10] Testing bash sourced library interface..."
(
    # Subshell to verify sourcing
    source "${LIFECYCLE}"
    LIB_BASE="${TEST_WORK_DIR}/lib_base.img"
    disk_create_base "${LIB_BASE}" 1 zero >/dev/null
    LIB_HASH=$(disk_hash_image "${LIB_BASE}")
    [[ -n "${LIB_HASH}" ]]
    disk_wipe_instance "${LIB_BASE}"
)
assert_eq "Sourced functions run properly in calling shell" "0" "$?"

echo "=========================================================="
echo "Summary: ${PASSED_COUNT} passed, ${FAILED_COUNT} failed"
echo "=========================================================="

if [[ ${FAILED_COUNT} -ne 0 ]]; then
    exit 1
fi
echo "ALL TESTS PASSED: Deterministic Disposable Disk Lifecycle verified."
