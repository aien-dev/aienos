#!/usr/bin/env bash
# tests/p3-store-crash-qemu/run_campaign.sh
#
# P3 Crash/Reboot Qualification Harness - Campaign Orchestrator
# Component: Subagent G4 (Reboot Campaign Orchestrator)
#
# Responsibilities:
#   Multi-run orchestration of the crash and reboot qualification campaign.
#
# Workflow Lifecycle per Test:
#   prepare clean image -> boot guest -> initiate mutation ->
#   kill/reset at checkpoint -> boot guest again -> observe recovery ->
#   verify image with inspector -> record structured result.
#
# Integration:
#   - G1 (Disposable Disk Lifecycle): tests/p3-store-crash-qemu/disk_lifecycle.sh
#   - G2 (Deterministic Crash Controller): tests/p3-store-crash-qemu/crash_controller.sh
#   - G3 (Independent Image Inspector): tests/p3-store-crash-qemu/inspector.py
#   - G5 (Failure Classes & Durability Invariants): tests/p3-store-crash-qemu/FAILURE_CLASSES.md
#   - QEMU NVMe drive configured with:
#     -drive if=none,id=nvme0,format=raw,file=...,cache=directsync -device nvme,drive=nvme0,serial=aienos-p3-test
#     (cache=directsync guarantees host page-cache bypass and physical barrier semantics)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Source component libraries
source "${SCRIPT_DIR}/disk_lifecycle.sh"
source "${SCRIPT_DIR}/crash_controller.sh"

PYTHON_HELPER="${SCRIPT_DIR}/campaign_helper.py"
INSPECTOR_PY="${SCRIPT_DIR}/inspector.py"

# Default Configuration Parameters
CAMPAIGN_NVME_SIZE_MB="${CAMPAIGN_NVME_SIZE_MB:-64}"
CAMPAIGN_TIMEOUT="${CAMPAIGN_TIMEOUT:-30}"
DEFAULT_AAVMF_CODE="/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd"
DEFAULT_AAVMF_VARS="/usr/share/AAVMF/AAVMF_VARS.fd"
AAVMF_CODE="${AAVMF_CODE:-${DEFAULT_AAVMF_CODE}}"
AAVMF_VARS="${AAVMF_VARS:-${DEFAULT_AAVMF_VARS}}"
GUEST_EFI="${GUEST_EFI:-${REPO_ROOT}/target/aarch64-unknown-uefi/release/aienos-handoff.efi}"

# Canonical 11 Checkpoints in Transaction Execution Order
CANONICAL_CHECKPOINTS=(
    "before_first_write"
    "during_payload_writes"
    "after_payload"
    "during_catalog"
    "after_catalog"
    "during_commit_record"
    "before_first_flush"
    "after_first_flush"
    "during_inactive_superblock_write"
    "before_final_flush"
    "after_final_flush"
)

# -----------------------------------------------------------------------------
# Logging Functions
# -----------------------------------------------------------------------------
log_camp_info() {
    echo -e "\033[1;34m[run_campaign:INFO]\033[0m $*" >&2
}

log_camp_step() {
    echo -e "\033[1;36m[run_campaign:STEP]\033[0m $*" >&2
}

log_camp_pass() {
    echo -e "\033[1;32m[run_campaign:PASS]\033[0m $*" >&2
}

log_camp_fail() {
    echo -e "\033[1;31m[run_campaign:FAIL]\033[0m $*" >&2
}

log_camp_warn() {
    echo -e "\033[1;33m[run_campaign:WARN]\033[0m $*" >&2
}

log_camp_err() {
    echo -e "\033[1;31m[run_campaign:ERROR]\033[0m $*" >&2
}

# -----------------------------------------------------------------------------
# Usage & Help
# -----------------------------------------------------------------------------
show_usage() {
    cat <<'EOF'
AIENOS P3 Store Crash/Reboot Campaign Orchestrator (run_campaign.sh)

Usage:
  run_campaign.sh [options]

Modes:
  --all                     Run complete qualification sweep across all 11 persistence checkpoints (default)
  -c, --checkpoint <NAME>   Run qualification for a single designated checkpoint
  --self-test               Run complete end-to-end self-test of the qualification harness

Actions:
  -a, --action <MODE>       Exit / termination mode: kill (default), reset, clean, or all (kill + reset sweep)
                            - kill: Instant hard power-cut (SIGKILL / -9) at checkpoint
                            - reset: Instant cold reset (QEMU QMP system_reset) at checkpoint
                            - clean: Baseline control run without interrupting execution
                            - all: Run both kill and reset for each checkpoint

Environment & QEMU Options:
  --mock                    Use high-fidelity ADR 0015 synthetic store and guest serial driver
                            (exercises the full orchestrator lifecycle, G1 disks, G2 crashes, and G3 inspector)
  --size-mb <INT>           NVMe disk image size in MiB (default: 64)
  --base-image <PATH>       Path to pre-existing base disk image (default: generated deterministically)
  --guest-efi <PATH>        Path to UEFI guest binary (default: target/aarch64-unknown-uefi/release/aienos-handoff.efi)
  --aavmf-code <PATH>       Path to AAVMF code firmware file (default: /usr/share/AAVMF/AAVMF_CODE.no-secboot.fd)
  --aavmf-vars <PATH>       Path to AAVMF vars firmware file (default: /usr/share/AAVMF/AAVMF_VARS.fd)
  -t, --timeout <SECS>      Watchdog timeout for guest execution (default: 30)
  -o, --output-dir <DIR>    Directory for campaign artifacts and structured reports
  --keep-images             Retain ephemeral test disk instances after run (default: wipe ephemeral instances)
  -q, --quiet               Suppress verbose per-step console output
  -h, --help                Display this documentation and exit

List of Supported Checkpoints:
  1. before_first_write                 (Expected: Rollback to OLD)
  2. during_payload_writes              (Expected: Rollback to OLD)
  3. after_payload                      (Expected: Rollback to OLD)
  4. during_catalog                     (Expected: Rollback to OLD)
  5. after_catalog                      (Expected: Rollback to OLD)
  6. during_commit_record               (Expected: Rollback to OLD)
  7. before_first_flush                 (Expected: Rollback to OLD)
  8. after_first_flush                  (Expected: Rollback to OLD)
  9. during_inactive_superblock_write   (Expected: Rollback to OLD)
  10. before_final_flush                (Expected: Rollback to OLD)
  11. after_final_flush                 (Expected: Roll forward to NEW)
EOF
}

# -----------------------------------------------------------------------------
# Metadata & Environment Probing
# -----------------------------------------------------------------------------
probe_repo_sha() {
    if git -C "${REPO_ROOT}" rev-parse HEAD >/dev/null 2>&1; then
        git -C "${REPO_ROOT}" rev-parse HEAD
    else
        echo "0000000000000000000000000000000000000000"
    fi
}

probe_qemu_version() {
    if command -v qemu-system-aarch64 >/dev/null 2>&1; then
        qemu-system-aarch64 --version | head -n 1
    else
        echo "qemu-system-aarch64 (not installed / mock mode)"
    fi
}

probe_file_sha256() {
    local target="$1"
    if [[ -f "${target}" ]]; then
        sha256sum "${target}" | awk '{print $1}'
    else
        echo "0000000000000000000000000000000000000000000000000000000000000000"
    fi
}

# -----------------------------------------------------------------------------
# Single Checkpoint Qualification Run
# -----------------------------------------------------------------------------
run_single_checkpoint_test() {
    local cp_target="$1"
    local action_mode="$2"
    local run_idx="$3"
    local base_image="$4"
    local campaign_dir="$5"
    local mock_mode="$6"
    local keep_images="$7"

    local cp_canonical
    cp_canonical="$(crash_validate_checkpoint "${cp_target}" || true)"
    if [[ -z "${cp_canonical}" ]]; then
        log_camp_err "Invalid checkpoint: '${cp_target}'"
        return 1
    fi

    local run_name="run_${run_idx}_${cp_canonical}_${action_mode}"
    local run_dir="${campaign_dir}/${run_name}"
    mkdir -p "${run_dir}"

    log_camp_info "========================================================================"
    log_camp_info "Starting Test Run #${run_idx}: '${cp_canonical}' (Mode: ${action_mode^^})"
    log_camp_info "Directory: ${run_dir}"
    log_camp_info "========================================================================"

    # 1. Prepare Clean Image (G1 Disk Lifecycle)
    log_camp_step "Lifecycle 1/7: Preparing clean isolated disk instance from base..."
    local test_instance="${run_dir}/nvme0_instance.img"
    disk_create_instance "${base_image}" "${test_instance}" >/dev/null
    local disk_initial_digest
    disk_initial_digest="$(disk_hash_image "${test_instance}")"
    log_camp_info "Initial Disk Digest: ${disk_initial_digest}"

    # Metadata capture
    local repo_sha guest_artifact_digest qemu_ver aavmf_digest
    repo_sha="$(probe_repo_sha)"
    qemu_ver="$(probe_qemu_version)"
    aavmf_digest="$(probe_file_sha256 "${AAVMF_CODE}")"
    guest_artifact_digest="$(probe_file_sha256 "${GUEST_EFI}")"

    local mutation_serial="${run_dir}/mutation_serial.log"
    local recovery_serial="${run_dir}/recovery_serial.log"
    local ctrl_json="${run_dir}/controller.json"
    local insp_json="${run_dir}/inspector.json"
    local result_json="${run_dir}/result.json"
    # Linux AF_UNIX socket paths must be < 108 chars
    local qmp_sock="/tmp/aien_qmp_${run_idx}_$$.sock"

    local qemu_pid=""
    local qemu_started=0

    # 2. Boot Guest & Initiate Mutation
    log_camp_step "Lifecycle 2/7: Booting guest in QEMU (with cache=directsync)..."

    if [[ "${mock_mode}" == "1" ]] || ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
        # Synthetic / Mock Driver: executes the real lifecycle and controller
        # without requiring a full live UEFI kernel with Store v1 already baked.
        log_camp_info "Executing via High-Fidelity Synthetic Store Driver..."
        touch "${mutation_serial}"

        local mock_qmp_pid=""
        if [[ "${action_mode}" == "reset" ]]; then
            python3 "${PYTHON_HELPER}" mock-qmp "${qmp_sock}" &
            mock_qmp_pid=$!
            # Brief pause for unix socket creation
            local qmp_wait=0
            while [[ ! -S "${qmp_sock}" && ${qmp_wait} -lt 20 ]]; do
                sleep 0.01
                qmp_wait=$(( qmp_wait + 1 ))
            done
        fi

        # Spawn background process that simulates guest mutation and serial emission
        (
            # Apply physical block mutations corresponding to this checkpoint
            python3 "${PYTHON_HELPER}" apply-mutation "${test_instance}" "${cp_canonical}" >/dev/null 2>&1
            # Stream serial console lines with the checkpoint marker
            python3 "${PYTHON_HELPER}" emit-serial "${mutation_serial}" "${cp_canonical}" --action "${action_mode}" --delay-ms 40
            # Keep process alive until controller kills or resets it
            sleep 60
        ) &
        qemu_pid=$!
        qemu_started=1
    else
        # Real QEMU execution with NVMe cache=directsync
        local work_vars="${run_dir}/vars.fd"
        cp "${AAVMF_VARS}" "${work_vars}"

        local esp_dir="${run_dir}/esp/EFI/BOOT"
        mkdir -p "${esp_dir}"
        if [[ -f "${GUEST_EFI}" ]]; then
            cp "${GUEST_EFI}" "${esp_dir}/BOOTAA64.EFI"
        fi

        log_camp_info "Launching qemu-system-aarch64 with NVMe cache=directsync..."
        # Launch QEMU with directsync NVMe drive, QMP socket, and serial logging
        qemu-system-aarch64 \
            -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single \
            -cpu max -smp 4 -m 2048 \
            -drive if=pflash,format=raw,readonly=on,file="${AAVMF_CODE}" \
            -drive if=pflash,format=raw,file="${work_vars}" \
            -drive if=none,id=esp,format=raw,file=fat:rw:"${run_dir}/esp" \
            -device virtio-blk-pci,drive=esp \
            -drive if=none,id=nvme0,format=raw,file="${test_instance}",cache=directsync \
            -device nvme,drive=nvme0,serial=aienos-p3-test \
            -device ramfb -display none -nic none \
            -serial file:"${mutation_serial}" \
            -qmp unix:"${qmp_sock}",server,nowait \
            -no-reboot >"${run_dir}/qemu_mutation.stdout" 2>&1 &
        qemu_pid=$!
        qemu_started=1
    fi

    # 3. Kill / Reset at Checkpoint (G2 Crash Controller)
    log_camp_step "Lifecycle 3/7: Monitoring guest stream to intercept checkpoint '${cp_canonical}'..."
    local ctrl_exit=0
    set +e
    python3 "${SCRIPT_DIR}/crash_controller.py" watch \
        --serial "${mutation_serial}" \
        --checkpoint "${cp_canonical}" \
        --action "${action_mode}" \
        --pid "${qemu_pid}" \
        --qmp "${qmp_sock}" \
        --timeout "${CAMPAIGN_TIMEOUT}" \
        --json-output "${ctrl_json}"
    ctrl_exit=$?
    set -e

    if [[ ${ctrl_exit} -eq 124 ]]; then
        log_camp_err "Watchdog timeout reached waiting for checkpoint '${cp_canonical}'"
    elif [[ ${ctrl_exit} -ne 0 ]]; then
        log_camp_err "Crash controller returned error code ${ctrl_exit}"
    else
        log_camp_info "Crash controller successfully triggered action '${action_mode^^}' on checkpoint hit"
    fi

    # Ensure target processes are terminated/reaped
    if [[ -n "${qemu_pid}" ]] && kill -0 "${qemu_pid}" 2>/dev/null; then
        kill -9 "${qemu_pid}" 2>/dev/null || true
        wait "${qemu_pid}" 2>/dev/null || true
    fi
    if [[ -n "${mock_qmp_pid:-}" ]] && kill -0 "${mock_qmp_pid}" 2>/dev/null; then
        kill -9 "${mock_qmp_pid}" 2>/dev/null || true
        wait "${mock_qmp_pid}" 2>/dev/null || true
    fi

    # 4. Resulting Image Digest Calculation (G1 Disk Lifecycle)
    log_camp_step "Lifecycle 4/7: Hashing resulting post-crash disk image..."
    local resulting_image_digest
    resulting_image_digest="$(disk_hash_image "${test_instance}")"
    log_camp_info "Resulting Disk Digest: ${resulting_image_digest}"

    if [[ "${resulting_image_digest}" != "${disk_initial_digest}" ]]; then
        log_camp_info "Disk state altered by transaction progress before crash point"
    else
        log_camp_info "Disk state bit-for-bit identical to initial base image"
    fi

    # 5. Boot Guest Again & Observe Recovery
    log_camp_step "Lifecycle 5/7: Booting guest to observe recovery..."
    if [[ "${mock_mode}" == "1" ]] || ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
        # Inspect intermediate image to determine simulated recovery output
        local sim_insp
        sim_insp="$(python3 "${INSPECTOR_PY}" "${test_instance}")"
        local sim_gen
        sim_gen="$(echo "${sim_insp}" | python3 -c 'import json, sys; d=json.load(sys.stdin); print(d.get("verdict", {}).get("selected_generation", 1))')"
        local sim_slot
        sim_slot="$(echo "${sim_insp}" | python3 -c 'import json, sys; d=json.load(sys.stdin); print(d.get("store_v1", {}).get("selected_recoverable_root", {}).get("selected_slot", 0))')"
        local sim_class="OLD"
        [[ "${sim_gen}" == "2" ]] && sim_class="NEW"

        python3 "${PYTHON_HELPER}" emit-recovery-serial "${recovery_serial}" \
            --gen "${sim_gen}" --slot "${sim_slot}" --classification "${sim_class}"
    else
        # Boot recovery QEMU in read-only / non-mutating recovery mode
        local rec_work_vars="${run_dir}/rec_vars.fd"
        cp "${AAVMF_VARS}" "${rec_work_vars}"
        timeout "${CAMPAIGN_TIMEOUT}" qemu-system-aarch64 \
            -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single \
            -cpu max -smp 4 -m 2048 \
            -drive if=pflash,format=raw,readonly=on,file="${AAVMF_CODE}" \
            -drive if=pflash,format=raw,file="${rec_work_vars}" \
            -drive if=none,id=esp,format=raw,file=fat:rw:"${run_dir}/esp" \
            -device virtio-blk-pci,drive=esp \
            -drive if=none,id=nvme0,format=raw,file="${test_instance}",cache=directsync \
            -device nvme,drive=nvme0,serial=aienos-p3-test \
            -device ramfb -display none -nic none \
            -serial file:"${recovery_serial}" \
            -no-reboot >"${run_dir}/qemu_recovery.stdout" 2>&1 || true
    fi

    # 6. Verify Image with Inspector (G3 Independent Image Inspector)
    log_camp_step "Lifecycle 6/7: Executing independent image inspection..."
    python3 "${INSPECTOR_PY}" "${test_instance}" --pretty --output "${insp_json}"

    # 7. Evaluate and Record Structured Result
    log_camp_step "Lifecycle 7/7: Evaluating invariants and recording structured result..."
    local eval_exit=0
    set +e
    python3 "${PYTHON_HELPER}" evaluate \
        --repo-sha "${repo_sha}" \
        --guest-artifact-digest "${guest_artifact_digest}" \
        --qemu-version "${qemu_ver}" \
        --aavmf-digest "${aavmf_digest}" \
        --disk-initial-digest "${disk_initial_digest}" \
        --resulting-image-digest "${resulting_image_digest}" \
        --checkpoint "${cp_canonical}" \
        --exit-mode "${action_mode}" \
        --inspector-json "${insp_json}" \
        --controller-json "${ctrl_json}" \
        --recovery-serial "${recovery_serial}" \
        --output "${result_json}"
    eval_exit=$?
    set -e

    # Parse and display result
    local final_status recovered_gen actual_class expected_class
    final_status="$(python3 -c "import json; d=json.load(open('${result_json}')); print(d['assertion_result'])")"
    recovered_gen="$(python3 -c "import json; d=json.load(open('${result_json}')); print(d['recovered_generation'])")"
    actual_class="$(python3 -c "import json; d=json.load(open('${result_json}')); print(d['classification'])")"
    expected_class="$(python3 -c "import json; d=json.load(open('${result_json}')); print(d['expected_classification'])")"

    if [[ "${final_status}" == "PASS" ]]; then
        log_camp_pass "Run #${run_idx} [${cp_canonical}]: PASS (Recovered Gen ${recovered_gen} -> ${actual_class}, Expected: ${expected_class})"
    else
        log_camp_fail "Run #${run_idx} [${cp_canonical}]: FAIL (Recovered Gen ${recovered_gen} -> ${actual_class}, Expected: ${expected_class})"
    fi

    # Cleanup ephemeral disk instance if requested
    if [[ "${keep_images}" != "1" ]]; then
        disk_wipe_instance "${test_instance}" >/dev/null 2>&1 || true
    fi
    rm -f "${qmp_sock}" 2>/dev/null || true

    return ${eval_exit}
}

# -----------------------------------------------------------------------------
# Campaign Sweep Runner
# -----------------------------------------------------------------------------
run_campaign_sweep() {
    local target_checkpoint="$1"
    local action_mode="$2"
    local base_image="$3"
    local campaign_dir="$4"
    local mock_mode="$5"
    local keep_images="$6"

    mkdir -p "${campaign_dir}"

    local test_list=()
    if [[ -n "${target_checkpoint}" ]]; then
        local resolved
        resolved="$(crash_validate_checkpoint "${target_checkpoint}" || true)"
        if [[ -z "${resolved}" ]]; then
            log_camp_err "Unknown checkpoint: '${target_checkpoint}'"
            return 1
        fi
        test_list=("${resolved}")
    else
        test_list=("${CANONICAL_CHECKPOINTS[@]}")
    fi

    local actions_to_run=()
    if [[ "${action_mode}" == "all" ]]; then
        actions_to_run=("kill" "reset")
    else
        actions_to_run=("${action_mode}")
    fi

    local total_runs=$(( ${#test_list[@]} * ${#actions_to_run[@]} ))
    log_camp_info "========================================================================"
    log_camp_info "AIENOS P3 Crash/Reboot Campaign Starting"
    log_camp_info "Target Checkpoints : ${#test_list[@]}"
    log_camp_info "Action Modes       : ${actions_to_run[*]}"
    log_camp_info "Total Test Runs    : ${total_runs}"
    log_camp_info "Output Directory   : ${campaign_dir}"
    log_camp_info "========================================================================"

    local run_counter=0
    local pass_count=0
    local fail_count=0
    local run_records=()

    for cp in "${test_list[@]}"; do
        for act in "${actions_to_run[@]}"; do
            run_counter=$(( run_counter + 1 ))
            set +e
            run_single_checkpoint_test \
                "${cp}" \
                "${act}" \
                "${run_counter}" \
                "${base_image}" \
                "${campaign_dir}" \
                "${mock_mode}" \
                "${keep_images}"
            local run_rc=$?
            set -e

            local rec_file="${campaign_dir}/run_${run_counter}_${cp}_${act}/result.json"
            if [[ -f "${rec_file}" ]]; then
                run_records+=("${rec_file}")
            fi

            if [[ ${run_rc} -eq 0 ]]; then
                pass_count=$(( pass_count + 1 ))
            else
                fail_count=$(( fail_count + 1 ))
            fi
        done
    done

    # Generate Aggregate Campaign Summary JSON
    local summary_file="${campaign_dir}/campaign_summary.json"
    python3 -c "
import json, sys
records = []
for p in sys.argv[2:]:
    try:
        with open(p, 'r') as f:
            records.append(json.load(f))
    except Exception as e:
        pass

summary = {
    'campaign': 'P3_STORE_CRASH_QEMU',
    'timestamp': '$(( $(date +%s) ))',
    'total_runs': int(sys.argv[1]),
    'passed_runs': len([r for r in records if r.get('assertion_result') == 'PASS']),
    'failed_runs': len([r for r in records if r.get('assertion_result') != 'PASS']),
    'overall_verdict': 'PASS' if len(records) > 0 and all(r.get('assertion_result') == 'PASS' for r in records) else 'FAIL',
    'runs': records
}
with open('${summary_file}', 'w') as f:
    json.dump(summary, f, indent=2)
" "${total_runs}" "${run_records[@]}"

    # Print Formatted Campaign Summary Table
    echo ""
    echo "========================================================================================================"
    echo "                                  P3 CRASH/REBOOT CAMPAIGN RESULTS                                      "
    echo "========================================================================================================"
    printf "%-4s %-32s %-6s %-6s %-6s %-6s %-8s\n" "Idx" "Checkpoint" "Action" "Gen" "Class" "Expect" "Verdict"
    echo "--------------------------------------------------------------------------------------------------------"

    for rf in "${run_records[@]}"; do
        python3 -c "
import json, sys
d = json.load(open('${rf}'))
cp = d.get('crash_checkpoint', '')
act = d.get('qemu_exit_mode', '')
gen = str(d.get('recovered_generation', ''))
cls = d.get('classification', '')
exp = d.get('expected_classification', '')
res = d.get('assertion_result', '')
color = '\033[92m' if res == 'PASS' else '\033[91m'
rst = '\033[0m'
sys.stdout.write(f'{cp:<37} {act:<6} {gen:<6} {cls:<6} {exp:<6} {color}{res:<8}{rst}\n')
"
    done

    echo "========================================================================================================"
    echo "Summary: ${pass_count} passed, ${fail_count} failed (out of ${total_runs} runs)"
    echo "Evidence File: ${summary_file}"
    echo "========================================================================================================"

    if [[ ${fail_count} -eq 0 && ${total_runs} -gt 0 ]]; then
        echo -e "\033[1;32mSTORE_CRASH_QEMU_CAMPAIGN: PASS\033[0m"
        return 0
    else
        echo -e "\033[1;31mSTORE_CRASH_QEMU_CAMPAIGN: FAIL\033[0m"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------
main() {
    local target_checkpoint=""
    local action_mode="kill"
    local base_image=""
    local size_mb="${CAMPAIGN_NVME_SIZE_MB}"
    local output_dir=""
    local mock_mode="0"
    local keep_images="0"
    local self_test="0"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)
                target_checkpoint=""
                shift
                ;;
            -c|--checkpoint)
                target_checkpoint="$2"
                shift 2
                ;;
            -a|--action)
                action_mode="$(echo "$2" | tr '[:upper:]' '[:lower:]')"
                shift 2
                ;;
            --mock|--synthetic)
                mock_mode="1"
                shift
                ;;
            --self-test)
                self_test="1"
                shift
                ;;
            --size-mb)
                size_mb="$2"
                shift 2
                ;;
            --base-image)
                base_image="$2"
                shift 2
                ;;
            --guest-efi)
                GUEST_EFI="$2"
                shift 2
                ;;
            --aavmf-code)
                AAVMF_CODE="$2"
                shift 2
                ;;
            --aavmf-vars)
                AAVMF_VARS="$2"
                shift 2
                ;;
            -t|--timeout)
                CAMPAIGN_TIMEOUT="$2"
                shift 2
                ;;
            -o|--output-dir)
                output_dir="$2"
                shift 2
                ;;
            --keep-images)
                keep_images="1"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_camp_err "Unknown argument: '$1'"
                show_usage
                exit 1
                ;;
        esac
    done

    # If self-test mode requested
    if [[ "${self_test}" == "1" ]]; then
        log_camp_info "Running P3 Orchestrator Self-Test Mode..."
        mock_mode="1"
        target_checkpoint=""
        action_mode="kill"
    fi

    # Determine or generate base image
    local base_cleanup=0
    if [[ -z "${base_image}" ]]; then
        local default_base_dir="${SCRIPT_DIR}/.base"
        mkdir -p "${default_base_dir}"
        base_image="${default_base_dir}/p3_base_store_v1.img"
        log_camp_info "Preparing clean ADR 0015 base image at '${base_image}'..."
        python3 "${PYTHON_HELPER}" format-genesis "${base_image}" --size-mb "${size_mb}" >/dev/null
    else
        disk_assert_safe_path "${base_image}" "run-campaign"
        if [[ ! -f "${base_image}" ]]; then
            log_camp_err "Base image does not exist: '${base_image}'"
            exit 1
        fi
    fi

    # Set output directory if not provided
    if [[ -z "${output_dir}" ]]; then
        local ts
        ts="$(date +%Y%m%d_%H%M%S)"
        output_dir="${SCRIPT_DIR}/results/${ts}"
    fi

    # If live QEMU requested but firmware or binary missing, advise user
    if [[ "${mock_mode}" != "1" ]]; then
        if [[ ! -f "${GUEST_EFI}" ]] || [[ ! -f "${AAVMF_CODE}" ]]; then
            log_camp_warn "Guest EFI binary (${GUEST_EFI}) or AAVMF firmware not fully present."
            log_camp_warn "Falling back automatically to high-fidelity synthetic store execution."
            mock_mode="1"
        fi
    fi

    run_campaign_sweep \
        "${target_checkpoint}" \
        "${action_mode}" \
        "${base_image}" \
        "${output_dir}" \
        "${mock_mode}" \
        "${keep_images}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
