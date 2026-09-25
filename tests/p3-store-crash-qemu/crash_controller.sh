#!/usr/bin/env bash
# tests/p3-store-crash-qemu/crash_controller.sh
#
# P3 Crash/Reboot Qualification Harness - Deterministic Crash Controller
# Component: Subagent G2 (Deterministic Crash Controller)
#
# Responsibilities:
#   Own mechanisms for terminating or resetting QEMU at named test persistence checkpoints.
#
# Requirements:
#   1. Named Checkpoints to support:
#      - before first write
#      - during payload writes
#      - after payload
#      - during Catalog
#      - after Catalog
#      - during CommitRecord
#      - before first flush
#      - after first flush
#      - during inactive Superblock write
#      - before final flush
#      - after final flush
#
#   2. Mechanism:
#      - Do NOT fake checkpoints with host timing assumptions.
#      - The guest must emit an unambiguous checkpoint marker before the harness acts
#        (e.g. via serial line output 'CHECKPOINT: <name>' or specific I/O event).
#      - The controller monitors guest serial stream, matches target checkpoint marker,
#        and immediately acts:
#        * Hard kill (kill -9 on QEMU process to simulate instant loss of power)
#        * Cold reset (QEMU monitor command system_reset via QMP or HMP monitor socket/pipe)
#        * Clean exit (for control baseline runs without interrupting execution)
#      - Must handle watchdog timeouts (if guest hangs before reaching marker).
#
#   3. Interface:
#      - Reusable standalone CLI tool and sourced bash library.
#      - Clear logging of checkpoint hit, termination mode, and exit timing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_ENGINE="${SCRIPT_DIR}/crash_controller.py"

# -----------------------------------------------------------------------------
# Supported Canonical Checkpoints
# -----------------------------------------------------------------------------
readonly CHECKPOINT_1="before_first_write"
readonly CHECKPOINT_2="during_payload_writes"
readonly CHECKPOINT_3="after_payload"
readonly CHECKPOINT_4="during_catalog"
readonly CHECKPOINT_5="after_catalog"
readonly CHECKPOINT_6="during_commit_record"
readonly CHECKPOINT_7="before_first_flush"
readonly CHECKPOINT_8="after_first_flush"
readonly CHECKPOINT_9="during_inactive_superblock_write"
readonly CHECKPOINT_10="before_final_flush"
readonly CHECKPOINT_11="after_final_flush"

# -----------------------------------------------------------------------------
# Logging Functions
# -----------------------------------------------------------------------------
crash_log_info() {
    if [[ "${CRASH_CONTROLLER_QUIET:-0}" != "1" ]]; then
        echo "[crash_controller:INFO] $*" >&2
    fi
}

crash_log_hit() {
    echo "[crash_controller:HIT] $*" >&2
}

crash_log_warn() {
    echo "[crash_controller:WARN] $*" >&2
}

crash_log_err() {
    echo "[crash_controller:ERROR] $*" >&2
}

crash_log_fatal() {
    crash_log_err "$*"
    exit 1
}

# -----------------------------------------------------------------------------
# Checkpoint Normalization & Validation (Bash Native)
# -----------------------------------------------------------------------------
crash_normalize_name() {
    local raw="$1"
    # Lowercase, replace hyphens and underscores with space, collapse spaces
    echo "${raw}" | tr '[:upper:]' '[:lower:]' | tr '_-' '  ' | sed -e 's/[[:punct:]]/ /g' -e 's/[[:space:]]\+/ /g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

crash_validate_checkpoint() {
    local input="$1"
    local norm
    norm="$(crash_normalize_name "${input}")"

    case "${norm}" in
        "before first write"|"before write"|"pre write"|"before_first_write")
            echo "${CHECKPOINT_1}"
            return 0
            ;;
        "during payload writes"|"during payload write"|"payload writes"|"payload write"|"during_payload_writes")
            echo "${CHECKPOINT_2}"
            return 0
            ;;
        "after payload"|"after payload writes"|"payload done"|"after_payload")
            echo "${CHECKPOINT_3}"
            return 0
            ;;
        "during catalog"|"during catalog write"|"catalog write"|"during_catalog")
            echo "${CHECKPOINT_4}"
            return 0
            ;;
        "after catalog"|"after catalog write"|"catalog done"|"after_catalog")
            echo "${CHECKPOINT_5}"
            return 0
            ;;
        "during commitrecord"|"during commit record"|"commit record write"|"during_commit_record")
            echo "${CHECKPOINT_6}"
            return 0
            ;;
        "before first flush"|"before flush 1"|"pre first flush"|"before_first_flush")
            echo "${CHECKPOINT_7}"
            return 0
            ;;
        "after first flush"|"after flush 1"|"post first flush"|"after_first_flush")
            echo "${CHECKPOINT_8}"
            return 0
            ;;
        "during inactive superblock write"|"during inactive superblock"|"during superblock write"|"during_inactive_superblock_write")
            echo "${CHECKPOINT_9}"
            return 0
            ;;
        "before final flush"|"before flush 2"|"pre final flush"|"before_final_flush")
            echo "${CHECKPOINT_10}"
            return 0
            ;;
        "after final flush"|"after flush 2"|"post final flush"|"commit complete"|"after_final_flush")
            echo "${CHECKPOINT_11}"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

crash_list_checkpoints() {
    cat <<'EOF'
Idx  Canonical ID                        Display Name
---------------------------------------------------------------------------
1    before_first_write                  before first write
     Desc: Prior to submitting any write commands to block media (media untouched).
2    during_payload_writes               during payload writes
     Desc: During emission of payload extent data blocks before catalog or commit record.
3    after_payload                       after payload
     Desc: After all payload extent data blocks are submitted to block device.
4    during_catalog                      during Catalog
     Desc: During emission and write of Catalog metadata blocks.
5    after_catalog                       after Catalog
     Desc: After Catalog metadata blocks are completely submitted to device.
6    during_commit_record                during CommitRecord
     Desc: During emission and write of the CommitRecord block.
7    before_first_flush                  before first flush
     Desc: Before issuing the first hardware cache flush barrier (payload + catalog + commit).
8    after_first_flush                   after first flush
     Desc: Immediately following confirmation of the first hardware cache flush barrier.
9    during_inactive_superblock_write    during inactive Superblock write
     Desc: During write of the inactive Superblock slot with new generation and CRC.
10   before_final_flush                  before final flush
     Desc: After inactive superblock write, before issuing final hardware cache flush barrier.
11   after_final_flush                   after final flush
     Desc: Immediately following confirmation of final flush (transaction committed).
EOF
}

# -----------------------------------------------------------------------------
# Action Execution: Hard Kill, Cold Reset, Clean Exit
# -----------------------------------------------------------------------------
crash_kill_pid() {
    local pid="$1"
    if [[ -z "${pid}" ]]; then
        crash_log_err "crash_kill_pid: No PID specified"
        return 1
    fi

    local t_start
    t_start=$(date +%s%N 2>/dev/null || date +%s)
    crash_log_info "Executing HARD KILL (SIGKILL / power-cut) on PID ${pid}"

    if ! kill -0 "${pid}" 2>/dev/null; then
        crash_log_warn "PID ${pid} is already terminated"
        return 0
    fi

    # Instant power cut: kill -9
    kill -9 "${pid}" 2>/dev/null || true

    # Confirm termination
    local deadline=$(( $(date +%s) + 2 ))
    while kill -0 "${pid}" 2>/dev/null && (( $(date +%s) < deadline )); do
        sleep 0.005 2>/dev/null || sleep 1
    done

    local t_end
    t_end=$(date +%s%N 2>/dev/null || date +%s)
    local lat_ms="0"
    if [[ "${#t_start}" -gt 10 && "${#t_end}" -gt 10 ]]; then
        lat_ms=$(awk "BEGIN {printf \"%.3f\", (${t_end} - ${t_start}) / 1000000.0}")
    fi

    if kill -0 "${pid}" 2>/dev/null; then
        crash_log_warn "PID ${pid} still running after SIGKILL"
        return 1
    else
        crash_log_info "PID ${pid} reaped in ${lat_ms} ms"
        return 0
    fi
}

crash_reset_qemu() {
    local qmp_sock="${1:-}"
    local mon_path="${2:-}"

    local t_start
    t_start=$(date +%s%N 2>/dev/null || date +%s)

    if [[ -n "${qmp_sock}" && -S "${qmp_sock}" ]]; then
        crash_log_info "Executing COLD RESET via QMP socket: ${qmp_sock}"
        if command -v python3 >/dev/null 2>&1 && [[ -f "${PYTHON_ENGINE}" ]]; then
            python3 "${PYTHON_ENGINE}" trigger-action reset --qmp "${qmp_sock}"
            return $?
        elif command -v nc >/dev/null 2>&1; then
            # QMP handshake: qmp_capabilities then system_reset
            {
                sleep 0.05
                echo '{"execute": "qmp_capabilities"}'
                sleep 0.05
                echo '{"execute": "system_reset"}'
                sleep 0.05
            } | nc -U "${qmp_sock}" >/dev/null 2>&1 || true
            return 0
        fi
    fi

    if [[ -n "${mon_path}" ]]; then
        crash_log_info "Executing COLD RESET via Monitor path: ${mon_path}"
        if [[ -p "${mon_path}" || -p "${mon_path}.in" ]]; then
            local pipe="${mon_path}"
            [[ -p "${mon_path}.in" ]] && pipe="${mon_path}.in"
            echo "system_reset" > "${pipe}"
            return 0
        elif [[ -S "${mon_path}" ]]; then
            if command -v nc >/dev/null 2>&1; then
                echo "system_reset" | nc -U "${mon_path}" >/dev/null 2>&1 || true
                return 0
            elif command -v socat >/dev/null 2>&1; then
                echo "system_reset" | socat - UNIX-CONNECT:"${mon_path}" >/dev/null 2>&1 || true
                return 0
            fi
        fi
    fi

    crash_log_err "crash_reset_qemu: No valid QMP socket or monitor path available for system_reset"
    return 1
}

# -----------------------------------------------------------------------------
# Serial Watcher (Bash Native Fallback)
# -----------------------------------------------------------------------------
crash_watch_serial_bash() {
    local serial_file="$1"
    local target_checkpoint="$2"
    local action="$3"
    local pid="${4:-}"
    local qmp_sock="${5:-}"
    local mon_path="${6:-}"
    local timeout_secs="${7:-30}"
    local custom_marker="${8:-}"

    local canonical=""
    if [[ -n "${target_checkpoint}" ]]; then
        canonical="$(crash_validate_checkpoint "${target_checkpoint}" || echo "")"
        if [[ -z "${canonical}" && -z "${custom_marker}" ]]; then
            crash_log_fatal "Unknown checkpoint name: '${target_checkpoint}'"
        fi
    fi

    local norm_target
    norm_target="$(crash_normalize_name "${target_checkpoint}")"

    crash_log_info "Starting bash-native serial monitor on '${serial_file}' (action: ${action}, timeout: ${timeout_secs}s)"

    # Wait for serial file to appear
    local wait_deadline=$(( $(date +%s) + 5 ))
    while [[ ! -e "${serial_file}" ]] && (( $(date +%s) < wait_deadline )); do
        sleep 0.05
    done
    [[ -e "${serial_file}" ]] || touch "${serial_file}"

    local start_time
    start_time=$(date +%s)
    local deadline=$(( start_time + timeout_secs ))

    local hit=0
    local matched_line=""

    # Tail the file without blocking pipeline
    exec 4< "${serial_file}"
    while (( $(date +%s) < deadline )); do
        local line
        while IFS= read -r -u 4 line || [[ -n "${line}" ]]; do
            if [[ -z "${line}" ]]; then
                continue
            fi

            local match=0
            if [[ -n "${custom_marker}" ]]; then
                if [[ "${line}" =~ ${custom_marker} ]]; then
                    match=1
                fi
            else
                local norm_line
                norm_line="$(crash_normalize_name "${line}")"
                if [[ "${norm_line}" == *"checkpoint "* && "${norm_line}" == *"${norm_target}"* ]]; then
                    match=1
                elif [[ "${line}" =~ CHECKPOINT:[[:space:]]*${target_checkpoint} ]]; then
                    match=1
                elif [[ -n "${canonical}" && "${norm_line}" == *"${canonical}"* ]]; then
                    match=1
                fi
            fi

            if [[ ${match} -eq 1 ]]; then
                hit=1
                matched_line="${line}"
                break 2
            fi
        done

        # If PID died unexpectedly
        if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
            crash_log_err "Target PID ${pid} died unexpectedly before checkpoint reached"
            exec 4<&-
            return 1
        fi

        sleep 0.005 2>/dev/null || sleep 0.01
    done
    exec 4<&-

    local now
    now=$(date +%s)
    local elapsed=$(( now - start_time ))

    if [[ ${hit} -eq 0 ]]; then
        crash_log_err "WATCHDOG TIMEOUT: checkpoint '${target_checkpoint}' was NOT observed within ${timeout_secs}s"
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            crash_log_warn "Killing hung process ${pid} after watchdog expiration"
            crash_kill_pid "${pid}" || true
        fi
        echo ""
        echo "--- CRASH CONTROLLER REPORT ---"
        echo "CHECKPOINT_HIT: NONE"
        echo "TERMINATION_MODE: ${action}"
        echo "EXIT_TIMING_SEC: ${elapsed}"
        echo "CRASH_CONTROLLER_STATUS: TIMEOUT"
        return 124
    fi

    crash_log_hit "Observed checkpoint: '${matched_line}' (elapsed: ${elapsed}s)"

    # Execute action
    local act_ok=1
    case "${action}" in
        kill|hard-kill|hard_kill|power-cut)
            crash_kill_pid "${pid}"
            act_ok=$?
            ;;
        reset|cold-reset|cold_reset|system_reset)
            crash_reset_qemu "${qmp_sock}" "${mon_path}"
            act_ok=$?
            ;;
        clean|clean-exit|none|baseline)
            crash_log_info "Clean action: continuing execution without interruption"
            act_ok=0
            ;;
        *)
            crash_log_err "Unknown action: ${action}"
            act_ok=1
            ;;
    esac

    echo ""
    echo "--- CRASH CONTROLLER REPORT ---"
    echo "CHECKPOINT_HIT: ${canonical:-custom_marker}"
    echo "CHECKPOINT_DISPLAY: ${target_checkpoint}"
    echo "CHECKPOINT_RAW_LINE: ${matched_line}"
    echo "TERMINATION_MODE: ${action}"
    echo "EXIT_TIMING_SEC: ${elapsed}"
    if [[ ${act_ok} -eq 0 ]]; then
        echo "CRASH_CONTROLLER_STATUS: PASS"
        return 0
    else
        echo "CRASH_CONTROLLER_STATUS: ERROR"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Primary Dispatcher: Uses Python Engine when Available, Falls Back to Bash
# -----------------------------------------------------------------------------
crash_watch_serial() {
    local serial_file="$1"
    local target_checkpoint="$2"
    local action="$3"
    local pid="${4:-}"
    local qmp_sock="${5:-}"
    local mon_path="${6:-}"
    local timeout_secs="${7:-30}"
    local custom_marker="${8:-}"
    local json_out="${9:-}"

    if command -v python3 >/dev/null 2>&1 && [[ -f "${PYTHON_ENGINE}" ]]; then
        local py_args=(
            python3 "${PYTHON_ENGINE}"
            --serial "${serial_file}"
            --action "${action}"
            --timeout "${timeout_secs}"
        )
        [[ -n "${target_checkpoint}" ]] && py_args+=(--checkpoint "${target_checkpoint}")
        [[ -n "${custom_marker}" ]] && py_args+=(--marker "${custom_marker}")
        [[ -n "${pid}" ]] && py_args+=(--pid "${pid}")
        [[ -n "${qmp_sock}" ]] && py_args+=(--qmp "${qmp_sock}")
        [[ -n "${mon_path}" ]] && py_args+=(--monitor "${mon_path}")
        [[ -n "${json_out}" ]] && py_args+=(--json-output "${json_out}")
        [[ "${CRASH_CONTROLLER_QUIET:-0}" == "1" ]] && py_args+=(--quiet)

        "${py_args[@]}"
        return $?
    else
        crash_watch_serial_bash \
            "${serial_file}" \
            "${target_checkpoint}" \
            "${action}" \
            "${pid}" \
            "${qmp_sock}" \
            "${mon_path}" \
            "${timeout_secs}" \
            "${custom_marker}"
        return $?
    fi
}

# -----------------------------------------------------------------------------
# Supervisor Run Mode
# Launches QEMU command in background, manages PID, monitors serial, triggers action
# -----------------------------------------------------------------------------
crash_run_supervisor() {
    local target_checkpoint="$1"
    local action="$2"
    local serial_file="$3"
    local timeout_secs="$4"
    local qmp_sock="$5"
    local mon_path="$6"
    local json_out="$7"
    shift 7

    if [[ $# -eq 0 ]]; then
        crash_log_fatal "crash_run_supervisor: No QEMU command specified after '--'"
    fi

    # Ensure serial file directory exists
    mkdir -p "$(dirname "${serial_file}")"
    : > "${serial_file}"

    crash_log_info "Supervisor launching QEMU in background: $*"
    "$@" &
    local qemu_pid=$!

    crash_log_info "QEMU running as PID ${qemu_pid}. Arming crash controller..."

    local rc=0
    set +e
    crash_watch_serial \
        "${serial_file}" \
        "${target_checkpoint}" \
        "${action}" \
        "${qemu_pid}" \
        "${qmp_sock}" \
        "${mon_path}" \
        "${timeout_secs}" \
        "" \
        "${json_out}"
    rc=$?
    set -e

    # Wait for process exit if it was killed or clean
    wait "${qemu_pid}" 2>/dev/null || true
    return "${rc}"
}

# -----------------------------------------------------------------------------
# CLI Usage
# -----------------------------------------------------------------------------
crash_usage() {
    cat <<'EOF'
Usage: crash_controller.sh <command> [options]

Commands:
  list-checkpoints                   List all 11 supported checkpoints
  validate-checkpoint <name>         Validate checkpoint name or alias
  watch [options]                    Monitor serial stream and act on checkpoint
  run [options] -- <command...>      Supervise QEMU command and act on checkpoint
  trigger-action <action> [options]  Immediately trigger kill, reset, or clean

Watch / Run Options:
  -c, --checkpoint <name>            Target named checkpoint
  -a, --action <kill|reset|clean>    Termination mode (default: kill)
  -s, --serial <path>                Serial output path (file, fifo, or socket)
  -p, --pid <pid>                    Target QEMU PID (mandatory for kill)
  --qmp <path>                       QEMU QMP unix domain socket (for reset)
  --monitor <path>                   QEMU HMP monitor socket or pipe (for reset)
  -t, --timeout <seconds>            Watchdog timeout in seconds (default: 30)
  -m, --marker <regex>               Custom explicit regex marker override
  -o, --json-output <file>           Path to save structured JSON result
  -q, --quiet                        Suppress informational logs

Supported Named Checkpoints:
  1.  before first write
  2.  during payload writes
  3.  after payload
  4.  during Catalog
  5.  after Catalog
  6.  during CommitRecord
  7.  before first flush
  8.  after first flush
  9.  during inactive Superblock write
  10. before final flush
  11. after final flush
EOF
}

# -----------------------------------------------------------------------------
# Main Entrypoint
# -----------------------------------------------------------------------------
main() {
    if [[ $# -eq 0 ]]; then
        crash_usage
        exit 1
    fi

    local cmd="$1"
    shift

    case "${cmd}" in
        list-checkpoints|list_checkpoints|--list-checkpoints)
            if command -v python3 >/dev/null 2>&1 && [[ -f "${PYTHON_ENGINE}" ]]; then
                python3 "${PYTHON_ENGINE}" list-checkpoints
            else
                crash_list_checkpoints
            fi
            exit 0
            ;;

        validate-checkpoint|validate_checkpoint|--validate-checkpoint)
            if [[ $# -lt 1 ]]; then
                crash_log_err "Usage: crash_controller.sh validate-checkpoint <name>"
                exit 1
            fi
            local cp_name="$1"
            if command -v python3 >/dev/null 2>&1 && [[ -f "${PYTHON_ENGINE}" ]]; then
                python3 "${PYTHON_ENGINE}" validate-checkpoint "${cp_name}"
                exit $?
            else
                local canon
                if canon="$(crash_validate_checkpoint "${cp_name}")"; then
                    echo "VALID: ${canon}"
                    exit 0
                else
                    echo "INVALID: '${cp_name}' is not recognized" >&2
                    exit 1
                fi
            fi
            ;;

        trigger-action|trigger_action)
            if [[ $# -lt 1 ]]; then
                crash_log_err "Usage: crash_controller.sh trigger-action <kill|reset|clean> [--pid <pid>]"
                exit 1
            fi
            local act="$1"
            shift
            local pid=""
            local qmp=""
            local mon=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -p|--pid) pid="$2"; shift 2 ;;
                    --qmp) qmp="$2"; shift 2 ;;
                    --monitor) mon="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            case "${act}" in
                kill) crash_kill_pid "${pid}" ;;
                reset) crash_reset_qemu "${qmp}" "${mon}" ;;
                clean) exit 0 ;;
                *) crash_log_fatal "Unknown action: ${act}" ;;
            esac
            exit $?
            ;;

        run)
            local cp=""
            local act="kill"
            local serial=""
            local timeout="30"
            local qmp=""
            local mon=""
            local json_out=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -c|--checkpoint) cp="$2"; shift 2 ;;
                    -a|--action) act="$2"; shift 2 ;;
                    -s|--serial) serial="$2"; shift 2 ;;
                    -t|--timeout) timeout="$2"; shift 2 ;;
                    --qmp) qmp="$2"; shift 2 ;;
                    --monitor) mon="$2"; shift 2 ;;
                    -o|--json-output) json_out="$2"; shift 2 ;;
                    -q|--quiet) CRASH_CONTROLLER_QUIET=1; shift ;;
                    --) shift; break ;;
                    *) crash_log_err "Unknown run option: $1"; exit 1 ;;
                esac
            done
            if [[ -z "${cp}" || -z "${serial}" ]]; then
                crash_log_fatal "run mode requires --checkpoint and --serial"
            fi
            crash_run_supervisor "${cp}" "${act}" "${serial}" "${timeout}" "${qmp}" "${mon}" "${json_out}" "$@"
            exit $?
            ;;

        watch)
            local cp=""
            local act="kill"
            local serial=""
            local pid=""
            local timeout="30"
            local qmp=""
            local mon=""
            local marker=""
            local json_out=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -c|--checkpoint) cp="$2"; shift 2 ;;
                    -a|--action) act="$2"; shift 2 ;;
                    -s|--serial) serial="$2"; shift 2 ;;
                    -p|--pid) pid="$2"; shift 2 ;;
                    -t|--timeout) timeout="$2"; shift 2 ;;
                    --qmp) qmp="$2"; shift 2 ;;
                    --monitor) mon="$2"; shift 2 ;;
                    -m|--marker) marker="$2"; shift 2 ;;
                    -o|--json-output) json_out="$2"; shift 2 ;;
                    -q|--quiet) CRASH_CONTROLLER_QUIET=1; shift ;;
                    -h|--help) crash_usage; exit 0 ;;
                    *) crash_log_err "Unknown watch option: $1"; exit 1 ;;
                esac
            done
            if [[ -z "${serial}" ]]; then
                crash_log_fatal "watch mode requires --serial <path>"
            fi
            if [[ -z "${cp}" && -z "${marker}" ]]; then
                crash_log_fatal "watch mode requires --checkpoint <name> or --marker <regex>"
            fi
            crash_watch_serial "${serial}" "${cp}" "${act}" "${pid}" "${qmp}" "${mon}" "${timeout}" "${marker}" "${json_out}"
            exit $?
            ;;

        -h|--help|help)
            crash_usage
            exit 0
            ;;

        # Flag-first shorthand syntax (e.g. crash_controller.sh --checkpoint ... --action ...)
        -*)
            # Re-invoke watch with all args
            main watch "${cmd}" "$@"
            ;;

        *)
            crash_log_err "Unknown subcommand: '${cmd}'"
            crash_usage
            exit 1
            ;;
    esac
}

# If script is executed directly, call main. If sourced, do nothing and export functions.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
