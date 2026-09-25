#!/usr/bin/env bash
# tests/p3-store-crash-qemu/test_run_campaign.sh
#
# Unit and integration test suite for the P3 Campaign Orchestrator (run_campaign.sh).
# Validates orchestrator lifecycle, command options, evidence binding, and error paths.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCHESTRATOR="${SCRIPT_DIR}/run_campaign.sh"

TEST_WORK_DIR="$(mktemp -d -t aienos_orchestrator_test_XXXXXX)"
trap 'rm -rf "${TEST_WORK_DIR}"' EXIT

PASSED=0
FAILED=0

assert_eq() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [[ "${expected}" == "${actual}" ]]; then
        echo "  [PASS] ${desc}"
        PASSED=$(( PASSED + 1 ))
    else
        echo "  [FAIL] ${desc} (expected '${expected}', got '${actual}')"
        FAILED=$(( FAILED + 1 ))
    fi
}

assert_file_exists() {
    local desc="$1"
    local path="$2"
    if [[ -f "${path}" ]]; then
        echo "  [PASS] ${desc}"
        PASSED=$(( PASSED + 1 ))
    else
        echo "  [FAIL] ${desc} (file not found: '${path}')"
        FAILED=$(( FAILED + 1 ))
    fi
}

assert_file_not_exists() {
    local desc="$1"
    local path="$2"
    if [[ ! -e "${path}" ]]; then
        echo "  [PASS] ${desc}"
        PASSED=$(( PASSED + 1 ))
    else
        echo "  [FAIL] ${desc} (file unexpectedly exists: '${path}')"
        FAILED=$(( FAILED + 1 ))
    fi
}

echo "=== Running P3 Campaign Orchestrator Test Suite ==="

# -----------------------------------------------------------------------------
# Test 1: CLI Help & Options
# -----------------------------------------------------------------------------
echo "[1/7] Testing CLI help and flag parsing..."
help_out="$("${ORCHESTRATOR}" --help)"
if echo "${help_out}" | grep -q "AIENOS P3 Store Crash/Reboot Campaign Orchestrator"; then
    echo "  [PASS] --help displays banner"
    PASSED=$(( PASSED + 1 ))
else
    echo "  [FAIL] --help missing expected banner"
    FAILED=$(( FAILED + 1 ))
fi

set +e
invalid_out="$("${ORCHESTRATOR}" --nonexistent-option 2>&1)"
inv_rc=$?
set -e
assert_eq "Invalid flag returns non-zero" "1" "${inv_rc}"

# -----------------------------------------------------------------------------
# Test 2: Checkpoint Validation
# -----------------------------------------------------------------------------
echo "[2/7] Testing checkpoint validation in orchestrator..."
set +e
bad_cp_out="$("${ORCHESTRATOR}" -c invalid_checkpoint_name --mock 2>&1)"
bad_cp_rc=$?
set -e
assert_eq "Unknown checkpoint rejected with non-zero exit" "1" "${bad_cp_rc}"

# -----------------------------------------------------------------------------
# Test 3: Single Checkpoint Run (Kill Mode)
# -----------------------------------------------------------------------------
echo "[3/7] Testing single checkpoint execution (kill mode)..."
out_dir_kill="${TEST_WORK_DIR}/results_kill"
set +e
"${ORCHESTRATOR}" -c during_catalog --action kill --mock -o "${out_dir_kill}" >/dev/null 2>&1
kill_rc=$?
set -e
assert_eq "Kill run exits with code 0" "0" "${kill_rc}"

result_json="${out_dir_kill}/run_1_during_catalog_kill/result.json"
assert_file_exists "result.json written" "${result_json}"

res_verdict="$(python3 -c "import json; d=json.load(open('${result_json}')); print(d['assertion_result'])")"
res_class="$(python3 -c "import json; d=json.load(open('${result_json}')); print(d['classification'])")"
assert_eq "during_catalog verdict is PASS" "PASS" "${res_verdict}"
assert_eq "during_catalog classified as OLD" "OLD" "${res_class}"

# -----------------------------------------------------------------------------
# Test 4: Single Checkpoint Run (Reset Mode)
# -----------------------------------------------------------------------------
echo "[4/7] Testing single checkpoint execution (reset mode via QMP)..."
out_dir_reset="${TEST_WORK_DIR}/results_reset"
set +e
"${ORCHESTRATOR}" -c after_payload --action reset --mock -o "${out_dir_reset}" >/dev/null 2>&1
reset_rc=$?
set -e
assert_eq "Reset run exits with code 0" "0" "${reset_rc}"

ctrl_json="${out_dir_reset}/run_1_after_payload_reset/controller.json"
assert_file_exists "controller.json written" "${ctrl_json}"
ctrl_act="$(python3 -c "import json; d=json.load(open('${ctrl_json}')); print(d['action'])")"
assert_eq "controller action recorded as reset" "reset" "${ctrl_act}"

# -----------------------------------------------------------------------------
# Test 5: Post-Commit Point Checkpoint (after_final_flush -> NEW)
# -----------------------------------------------------------------------------
echo "[5/7] Testing post-commit durability point (after_final_flush)..."
out_dir_commit="${TEST_WORK_DIR}/results_commit"
set +e
"${ORCHESTRATOR}" -c after_final_flush --action kill --mock -o "${out_dir_commit}" >/dev/null 2>&1
commit_rc=$?
set -e
assert_eq "after_final_flush exits with code 0" "0" "${commit_rc}"

commit_result="${out_dir_commit}/run_1_after_final_flush_kill/result.json"
commit_class="$(python3 -c "import json; d=json.load(open('${commit_result}')); print(d['classification'])")"
commit_gen="$(python3 -c "import json; d=json.load(open('${commit_result}')); print(d['recovered_generation'])")"
assert_eq "after_final_flush classified as NEW" "NEW" "${commit_class}"
assert_eq "after_final_flush advanced to generation 2" "2" "${commit_gen}"

# -----------------------------------------------------------------------------
# Test 6: Ephemeral Disk Cleanup & Retention
# -----------------------------------------------------------------------------
echo "[6/7] Testing disposable disk instance lifecycle (wipe vs keep)..."
out_dir_wipe="${TEST_WORK_DIR}/results_wipe"
"${ORCHESTRATOR}" -c before_first_write --action clean --mock -o "${out_dir_wipe}" >/dev/null 2>&1
assert_file_not_exists "Ephemeral instance wiped by default" "${out_dir_wipe}/run_1_before_first_write_clean/nvme0_instance.img"

out_dir_keep="${TEST_WORK_DIR}/results_keep"
"${ORCHESTRATOR}" -c before_first_write --action clean --mock --keep-images -o "${out_dir_keep}" >/dev/null 2>&1
assert_file_exists "Ephemeral instance retained with --keep-images" "${out_dir_keep}/run_1_before_first_write_clean/nvme0_instance.img"

# -----------------------------------------------------------------------------
# Test 7: Structured Evidence Schema Verification
# -----------------------------------------------------------------------------
echo "[7/7] Testing structured record fields contract..."
python3 -c "
import json, sys
data = json.load(open('${result_json}'))
required_fields = [
    'repo_sha',
    'guest_artifact_digest',
    'qemu_version',
    'aavmf_digest',
    'disk_initial_digest',
    'crash_checkpoint',
    'checkpoint_canonical',
    'qemu_exit_mode',
    'resulting_image_digest',
    'recovered_generation',
    'recovered_root',
    'classification',
    'expected_classification',
    'assertion_result',
    'is_recoverable'
]
for f in required_fields:
    assert f in data, f'Missing required field: {f}'
assert data['assertion_result'] in ('PASS', 'FAIL')
assert data['classification'] in ('OLD', 'NEW')
print('  [PASS] All 15 required structured fields present and validated')
"
PASSED=$(( PASSED + 1 ))

echo "============================================================"
echo "Campaign Orchestrator Test Summary: ${PASSED} passed, ${FAILED} failed"
echo "============================================================"

if [[ ${FAILED} -eq 0 ]]; then
    echo "P3_CAMPAIGN_ORCHESTRATOR_TEST: PASS"
    exit 0
else
    echo "P3_CAMPAIGN_ORCHESTRATOR_TEST: FAIL"
    exit 1
fi
