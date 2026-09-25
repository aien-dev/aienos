#!/usr/bin/env bash
# tests/p3-store-crash-qemu/test_crash_controller.sh
#
# Verification and Unit Test Suite for crash_controller.sh / crash_controller.py
# Tests all 11 named persistence checkpoints, all termination modes (kill, reset, clean),
# watchdog timeouts, and stream formats.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTROLLER="${SCRIPT_DIR}/crash_controller.sh"

TEST_WORK_DIR=$(mktemp -d "/tmp/aienos_crash_ctrl_test_XXXXXX")
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

echo "============================================================"
echo "AIENOS P3 Crash Controller Test Suite"
echo "Target: ${CONTROLLER}"
echo "============================================================"

# -----------------------------------------------------------------------------
# Test Group 1: Checkpoint Discovery and Validation
# -----------------------------------------------------------------------------
echo ""
echo "--- [Group 1: Checkpoint Listing and Validation] ---"

assert_success "List checkpoints outputs all 11 checkpoints" \
    "${CONTROLLER}" list-checkpoints

CHECKPOINTS_TO_TEST=(
    "before first write:before_first_write"
    "during payload writes:during_payload_writes"
    "after payload:after_payload"
    "during Catalog:during_catalog"
    "after Catalog:after_catalog"
    "during CommitRecord:during_commit_record"
    "before first flush:before_first_flush"
    "after first flush:after_first_flush"
    "during inactive Superblock write:during_inactive_superblock_write"
    "before final flush:before_final_flush"
    "after final flush:after_final_flush"
)

for entry in "${CHECKPOINTS_TO_TEST[@]}"; do
    display="${entry%%:*}"
    canonical="${entry##*:}"
    out="$("${CONTROLLER}" validate-checkpoint "${display}")"
    if echo "${out}" | grep -q "${canonical}"; then
        echo "  [PASS] Validate checkpoint '${display}' -> canonical '${canonical}'"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo "  [FAIL] Validate checkpoint '${display}': did not match '${canonical}' (got '${out}')" >&2
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

assert_failure "Reject non-existent checkpoint" \
    "${CONTROLLER}" validate-checkpoint "non_existent_checkpoint_phase"

# -----------------------------------------------------------------------------
# Test Group 2: Hard Kill (SIGKILL / Power-Loss) Action
# -----------------------------------------------------------------------------
echo ""
echo "--- [Group 2: Hard Kill Action at Checkpoint] ---"

SERIAL_KILL="${TEST_WORK_DIR}/serial_kill.log"
: > "${SERIAL_KILL}"

sleep 60 &
DUMMY_PID=$!

JSON_KILL="${TEST_WORK_DIR}/kill_report.json"

("${CONTROLLER}" watch \
    --serial "${SERIAL_KILL}" \
    --checkpoint "during payload writes" \
    --action kill \
    --pid "${DUMMY_PID}" \
    --json-output "${JSON_KILL}" \
    --timeout 5) &
WATCH_PID=$!

sleep 0.1
echo "[ 0.123 ] CHECKPOINT: during payload writes [block=10]" >> "${SERIAL_KILL}"

wait "${WATCH_PID}"
WATCH_RC=$?
assert_eq "Hard kill watcher exits with code 0 on checkpoint match" "0" "${WATCH_RC}"

if kill -0 "${DUMMY_PID}" 2>/dev/null; then
    echo "  [FAIL] Target PID ${DUMMY_PID} survived SIGKILL" >&2
    kill -9 "${DUMMY_PID}" 2>/dev/null || true
    FAILED_COUNT=$((FAILED_COUNT + 1))
else
    echo "  [PASS] Target PID ${DUMMY_PID} verified dead after hard kill"
    PASSED_COUNT=$((PASSED_COUNT + 1))
fi

if [[ -f "${JSON_KILL}" ]] && grep -q '"status": "PASS"' "${JSON_KILL}" && grep -q '"action": "kill"' "${JSON_KILL}"; then
    echo "  [PASS] JSON telemetry report verified with PASS status"
    PASSED_COUNT=$((PASSED_COUNT + 1))
else
    echo "  [FAIL] JSON report invalid or missing" >&2
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

# -----------------------------------------------------------------------------
# Test Group 3: Cold Reset Action via Mock QMP Socket
# -----------------------------------------------------------------------------
echo ""
echo "--- [Group 3: Cold Reset Action via QMP] ---"

QMP_SOCK="${TEST_WORK_DIR}/qmp.sock"
python3 -c "
import socket, os, json, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind('${QMP_SOCK}')
s.listen(1)
conn, _ = s.accept()
conn.sendall(json.dumps({'QMP': {'version': {'qemu': {'major': 8, 'minor': 2, 'micro': 0}, 'package': ''}, 'capabilities': []}}).encode('utf-8') + b'\r\n')
req1 = conn.recv(1024)
conn.sendall(b'{\"return\": {}}\r\n')
req2 = conn.recv(1024)
assert b'system_reset' in req2, 'system_reset not found in request: ' + repr(req2)
conn.sendall(b'{\"return\": {}}\r\n')
conn.close()
s.close()
" &
QMP_PID=$!

SERIAL_RESET="${TEST_WORK_DIR}/serial_reset.log"
: > "${SERIAL_RESET}"

("${CONTROLLER}" watch \
    --serial "${SERIAL_RESET}" \
    --checkpoint "before first flush" \
    --action reset \
    --qmp "${QMP_SOCK}" \
    --timeout 5) &
WATCH_RESET_PID=$!

sleep 0.1
echo "CHECKPOINT: before first flush" >> "${SERIAL_RESET}"

wait "${WATCH_RESET_PID}"
RESET_RC=$?
wait "${QMP_PID}"
QMP_RC=$?

assert_eq "Cold reset watcher exit code" "0" "${RESET_RC}"
assert_eq "Mock QMP server exit code (received system_reset)" "0" "${QMP_RC}"

# -----------------------------------------------------------------------------
# Test Group 4: Clean Control Baseline Action
# -----------------------------------------------------------------------------
echo ""
echo "--- [Group 4: Clean Baseline Run] ---"

SERIAL_CLEAN="${TEST_WORK_DIR}/serial_clean.log"
: > "${SERIAL_CLEAN}"

sleep 60 &
BASELINE_PID=$!

("${CONTROLLER}" watch \
    --serial "${SERIAL_CLEAN}" \
    --checkpoint "after final flush" \
    --action clean \
    --pid "${BASELINE_PID}" \
    --timeout 5) &
WATCH_CLEAN_PID=$!

sleep 0.1
echo "CHECKPOINT: after final flush" >> "${SERIAL_CLEAN}"

wait "${WATCH_CLEAN_PID}"
CLEAN_RC=$?
assert_eq "Clean baseline watcher exit code" "0" "${CLEAN_RC}"

if kill -0 "${BASELINE_PID}" 2>/dev/null; then
    echo "  [PASS] Target PID ${BASELINE_PID} remains alive in clean baseline run"
    PASSED_COUNT=$((PASSED_COUNT + 1))
    kill -9 "${BASELINE_PID}" 2>/dev/null || true
else
    echo "  [FAIL] Target PID was terminated in clean baseline run" >&2
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

# -----------------------------------------------------------------------------
# Test Group 5: Watchdog Timeout & Process Cleanup
# -----------------------------------------------------------------------------
echo ""
echo "--- [Group 5: Watchdog Timeout Handling] ---"

SERIAL_TIMEOUT="${TEST_WORK_DIR}/serial_timeout.log"
: > "${SERIAL_TIMEOUT}"

sleep 60 &
HUNG_PID=$!

set +e
"${CONTROLLER}" watch \
    --serial "${SERIAL_TIMEOUT}" \
    --checkpoint "during inactive Superblock write" \
    --action kill \
    --pid "${HUNG_PID}" \
    --timeout 1.0 >/dev/null 2>&1
TIMEOUT_RC=$?
set -e

assert_eq "Watchdog timer returns exit code 124" "124" "${TIMEOUT_RC}"

if kill -0 "${HUNG_PID}" 2>/dev/null; then
    echo "  [FAIL] Hung process was not killed on watchdog timeout" >&2
    kill -9 "${HUNG_PID}" 2>/dev/null || true
    FAILED_COUNT=$((FAILED_COUNT + 1))
else
    echo "  [PASS] Hung process was killed on watchdog timeout"
    PASSED_COUNT=$((PASSED_COUNT + 1))
fi

# -----------------------------------------------------------------------------
# Test Group 6: FIFO Pipe Serial Input
# -----------------------------------------------------------------------------
echo ""
echo "--- [Group 6: Named FIFO Pipe Stream Input] ---"

FIFO_SERIAL="${TEST_WORK_DIR}/serial_fifo.pipe"
mkfifo "${FIFO_SERIAL}"

sleep 60 &
FIFO_TEST_PID=$!

("${CONTROLLER}" watch \
    --serial "${FIFO_SERIAL}" \
    --checkpoint "after Catalog" \
    --action kill \
    --pid "${FIFO_TEST_PID}" \
    --timeout 5) &
WATCH_FIFO_PID=$!

sleep 0.1
# Write directly into FIFO
echo "CHECKPOINT: after Catalog" > "${FIFO_SERIAL}"

wait "${WATCH_FIFO_PID}"
FIFO_RC=$?
assert_eq "FIFO pipe checkpoint watcher exit code" "0" "${FIFO_RC}"

if kill -0 "${FIFO_TEST_PID}" 2>/dev/null; then
    echo "  [FAIL] Target PID survived FIFO kill" >&2
    kill -9 "${FIFO_TEST_PID}" 2>/dev/null || true
    FAILED_COUNT=$((FAILED_COUNT + 1))
else
    echo "  [PASS] Target PID killed via FIFO pipe checkpoint stream"
    PASSED_COUNT=$((PASSED_COUNT + 1))
fi

# -----------------------------------------------------------------------------
# Test Group 7: Supervisor Run Mode
# -----------------------------------------------------------------------------
echo ""
echo "--- [Group 7: Supervisor Run Mode] ---"

SERIAL_SUPER="${TEST_WORK_DIR}/serial_super.log"

set +e
"${CONTROLLER}" run \
    --checkpoint "during CommitRecord" \
    --action kill \
    --serial "${SERIAL_SUPER}" \
    --timeout 5 \
    -- bash -c "sleep 0.15; echo 'CHECKPOINT: during CommitRecord' >> '${SERIAL_SUPER}'; sleep 30" >/dev/null 2>&1
SUPER_RC=$?
set -e

assert_eq "Supervisor run mode exits 0 after killing child at checkpoint" "0" "${SUPER_RC}"

# -----------------------------------------------------------------------------
# Final Summary
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "AIENOS Crash Controller Test Results: ${PASSED_COUNT} passed, ${FAILED_COUNT} failed"
echo "============================================================"

if [[ ${FAILED_COUNT} -eq 0 ]]; then
    echo "P3_CRASH_CONTROLLER_TEST: PASS"
    exit 0
else
    echo "P3_CRASH_CONTROLLER_TEST: FAIL"
    exit 1
fi
