#!/usr/bin/env bash
# tests/p3-store-crash-qemu/disk_lifecycle.sh
#
# P3 Crash/Reboot Qualification Harness - Disposable Disk Lifecycle
# Component: Subagent G1 (Disposable Disk Lifecycle)
#
# Responsibilities:
#   1. Clean base image generation:
#      - Deterministic creation of initial raw block image (e.g. 64 MiB or configured NVMe size)
#        with known initial pattern or zeroing.
#      - Strict avoidance of any host system-disk or physical device interaction.
#        Everything must live in isolated ephemeral test directories or tmp.
#   2. Per-test copy:
#      - Snapshotting / copy-on-write or explicit copying of the base image for each test run
#        to ensure strict isolation between crash tests.
#   3. Digest calculation:
#      - Pre-run SHA-256 digest of the block image before guest execution.
#      - Post-run SHA-256 digest of the block image after crash/exit.
#      - Direct verification that bits on disk changed or remained identical.
#   4. Reusable CLI and sourced library interface.

set -euo pipefail

# -----------------------------------------------------------------------------
# Logging and Diagnostics
# -----------------------------------------------------------------------------
log_info() {
    if [[ "${DISK_LIFECYCLE_QUIET:-0}" != "1" ]]; then
        echo "[disk_lifecycle] $*" >&2
    fi
}

log_err() {
    echo "[disk_lifecycle:ERROR] $*" >&2
}

log_fatal() {
    log_err "$*"
    exit 1
}

# -----------------------------------------------------------------------------
# Host Device & System Path Safety Guard
#
# Strictly prohibits any interaction with host block devices, character devices,
# or protected system filesystem hierarchies.
# -----------------------------------------------------------------------------
disk_assert_safe_path() {
    local target="$1"
    local op="${2:-operation}"

    if [[ -z "${target}" ]]; then
        log_err "${op}: target path cannot be empty"
        return 1
    fi

    # Immediate rejection if target directly exists as a device node
    if [[ -b "${target}" ]]; then
        log_err "${op}: STRICT SAFETY VIOLATION: '${target}' is an active block device!"
        return 1
    fi
    if [[ -c "${target}" ]]; then
        log_err "${op}: STRICT SAFETY VIOLATION: '${target}' is a character device!"
        return 1
    fi

    # Canonicalize path using realpath -m (resolves symlinks and relative paths,
    # even for paths where components or the file do not yet exist).
    local canon
    if command -v realpath >/dev/null 2>&1; then
        canon="$(realpath -m "${target}")"
    else
        canon="$(readlink -f "${target}" 2>/dev/null || echo "${target}")"
    fi

    # Strictly reject any path that touches device namespaces
    case "${canon}" in
        /dev|/dev/*)
            log_err "${op}: STRICT SAFETY VIOLATION: '${target}' resolves to device namespace '${canon}'"
            return 1
            ;;
        /sys|/sys/*)
            log_err "${op}: STRICT SAFETY VIOLATION: '${target}' resolves to sysfs namespace '${canon}'"
            return 1
            ;;
        /proc|/proc/*)
            log_err "${op}: STRICT SAFETY VIOLATION: '${target}' resolves to procfs namespace '${canon}'"
            return 1
            ;;
        /|/boot|/boot/*|/etc|/etc/*|/usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*|/lib|/lib/*|/lib64|/lib64/*|/root|/root/*)
            log_err "${op}: STRICT SAFETY VIOLATION: '${target}' resolves to protected system path '${canon}'"
            return 1
            ;;
    esac

    # If canonical path already exists, verify it is a regular file or directory (if dir check)
    if [[ -e "${canon}" ]]; then
        if [[ -b "${canon}" || -c "${canon}" ]]; then
            log_err "${op}: STRICT SAFETY VIOLATION: canonical target '${canon}' is a device node!"
            return 1
        fi
        if [[ -d "${canon}" ]]; then
            log_err "${op}: target '${target}' is an existing directory, expected disk image file"
            return 1
        fi
        if [[ -S "${canon}" || -p "${canon}" ]]; then
            log_err "${op}: target '${target}' is a socket or FIFO"
            return 1
        fi
    fi

    return 0
}

# -----------------------------------------------------------------------------
# Function: disk_create_base
#
# Deterministically generates a raw block image of configured size (in MiB)
# filled with zeroes or a deterministic repeating byte pattern.
#
# Usage: disk_create_base <path> <size_mb> [pattern]
#   pattern:
#     - "zero" | "0" (default): All 0x00 bytes (fsync guaranteed)
#     - "sparse": Fast sparse zeroed file using truncate
#     - "0x<HEX>" (e.g. 0xAA, 0xFF, 0x5A): Repeating single-byte pattern
# -----------------------------------------------------------------------------
disk_create_base() {
    local target_path="$1"
    local size_mb="$2"
    local pattern="${3:-zero}"

    disk_assert_safe_path "${target_path}" "create-base" || return 1

    if ! [[ "${size_mb}" =~ ^[1-9][0-9]*$ ]]; then
        log_err "create-base: size_mb must be a positive integer, got '${size_mb}'"
        return 1
    fi

    local parent_dir
    parent_dir="$(dirname "${target_path}")"
    if [[ -n "${parent_dir}" && ! -d "${parent_dir}" ]]; then
        mkdir -p "${parent_dir}"
    fi

    # Remove existing image if present
    if [[ -e "${target_path}" ]]; then
        rm -f "${target_path}"
    fi

    log_info "Creating base disk image '${target_path}' (${size_mb} MiB, pattern: ${pattern})..."

    case "${pattern}" in
        zero|0|"")
            # Write zeroed blocks deterministically with full sync
            dd if=/dev/zero of="${target_path}" bs=1M count="${size_mb}" status=none conv=fsync
            ;;
        sparse)
            # Create sparse zeroed file
            truncate -s "${size_mb}M" "${target_path}"
            ;;
        0x*|0X*)
            local hex_val="${pattern#0x}"
            hex_val="${hex_val#0X}"
            if [[ ${#hex_val} -ne 2 || ! "${hex_val}" =~ ^[0-9a-fA-F]{2}$ ]]; then
                log_err "create-base: byte pattern must be 2 hex digits, e.g. 0xAA, got '${pattern}'"
                return 1
            fi
            local dec_val
            dec_val=$(( 16#${hex_val} ))
            local octal_val
            octal_val=$(printf '%03o' "${dec_val}")

            # Stream deterministic repeating byte pattern without triggering SIGPIPE in pipefail
            local total_bytes=$(( size_mb * 1024 * 1024 ))
            head -c "${total_bytes}" /dev/zero | tr '\0' "\\${octal_val}" | dd of="${target_path}" bs=1M status=none conv=fsync
            ;;
        *)
            log_err "create-base: unsupported pattern '${pattern}'. Supported: zero, sparse, 0x<HEX>"
            return 1
            ;;
    esac

    # Ensure secure permissions (only owner read/write)
    chmod 0600 "${target_path}"

    local digest
    digest=$(disk_hash_image "${target_path}")
    log_info "Base image created: ${target_path} (${size_mb} MiB, sha256: ${digest})"

    echo "${target_path}"
    return 0
}

# -----------------------------------------------------------------------------
# Function: disk_create_instance
#
# Creates an isolated copy of the base image for a specific crash test run.
# Utilizes copy-on-write (--reflink=auto) when supported by host filesystem,
# falling back gracefully to explicit full copying.
#
# Usage: disk_create_instance <base_path> <test_instance_path>
# -----------------------------------------------------------------------------
disk_create_instance() {
    local base_path="$1"
    local instance_path="$2"

    disk_assert_safe_path "${base_path}" "create-instance (base)" || return 1
    disk_assert_safe_path "${instance_path}" "create-instance (instance)" || return 1

    if [[ ! -f "${base_path}" ]]; then
        log_err "create-instance: base image '${base_path}' does not exist or is not a regular file"
        return 1
    fi

    # Base and instance must not be identical paths
    local canon_base canon_inst
    canon_base="$(realpath -m "${base_path}")"
    canon_inst="$(realpath -m "${instance_path}")"
    if [[ "${canon_base}" == "${canon_inst}" ]]; then
        log_err "create-instance: instance path cannot be identical to base path ('${base_path}')"
        return 1
    fi

    local parent_dir
    parent_dir="$(dirname "${instance_path}")"
    if [[ -n "${parent_dir}" && ! -d "${parent_dir}" ]]; then
        mkdir -p "${parent_dir}"
    fi

    # Remove existing instance if present
    if [[ -e "${instance_path}" ]]; then
        rm -f "${instance_path}"
    fi

    # Snapshot/copy using reflink if available for speed and isolation
    cp --reflink=auto --preserve=mode,timestamps "${base_path}" "${instance_path}"
    chmod 0600 "${instance_path}"
    sync "${instance_path}"

    log_info "Created isolated test instance: ${instance_path} (from base: ${base_path})"
    echo "${instance_path}"
    return 0
}

# -----------------------------------------------------------------------------
# Function: disk_hash_image
#
# Computes the raw SHA-256 digest of the block image.
#
# Usage: disk_hash_image <path>
# Output: 64-character lowercase hex digest on stdout
# -----------------------------------------------------------------------------
disk_hash_image() {
    local target_path="$1"

    disk_assert_safe_path "${target_path}" "hash-image" || return 1

    if [[ ! -f "${target_path}" ]]; then
        log_err "hash-image: image file '${target_path}' does not exist or is not a regular file"
        return 1
    fi

    sha256sum "${target_path}" | awk '{print $1}'
}

# -----------------------------------------------------------------------------
# Function: disk_wipe_instance
#
# Safely destroys and removes an ephemeral test instance image.
# Idempotent: returns success if file does not exist.
#
# Usage: disk_wipe_instance <test_instance_path>
# -----------------------------------------------------------------------------
disk_wipe_instance() {
    local instance_path="$1"

    disk_assert_safe_path "${instance_path}" "wipe-instance" || return 1

    if [[ ! -e "${instance_path}" ]]; then
        log_info "Instance already wiped or does not exist: ${instance_path}"
        return 0
    fi

    if [[ ! -f "${instance_path}" ]]; then
        log_err "wipe-instance: refusing to wipe non-regular file '${instance_path}'"
        return 1
    fi

    rm -f "${instance_path}"

    if [[ -e "${instance_path}" ]]; then
        log_err "wipe-instance: failed to remove '${instance_path}'"
        return 1
    fi

    log_info "Wiped test instance: ${instance_path}"
    return 0
}

# -----------------------------------------------------------------------------
# Verification Helpers
# -----------------------------------------------------------------------------

# Internal helper to resolve a parameter to a SHA-256 digest
_resolve_digest() {
    local val="$1"
    if [[ "${val}" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "${val,,}"
    elif [[ -f "${val}" ]]; then
        disk_hash_image "${val}"
    else
        log_err "Cannot resolve SHA-256 digest from '${val}' (not a 64-hex hash and not an existing file)"
        return 1
    fi
}

# Verifies that two images (or image and hash, or two hashes) are identical.
disk_verify_identical() {
    local target1="$1"
    local target2="$2"

    local d1 d2
    d1="$(_resolve_digest "${target1}")" || return 1
    d2="$(_resolve_digest "${target2}")" || return 1

    if [[ "${d1}" == "${d2}" ]]; then
        log_info "IDENTICAL: ${d1}"
        echo "${d1}"
        return 0
    else
        log_err "MISMATCH: digests differ!"
        log_err "  1: ${d1} (${target1})"
        log_err "  2: ${d2} (${target2})"
        return 1
    fi
}

# Verifies that two images (or image and hash, or two hashes) have changed.
disk_verify_changed() {
    local target1="$1"
    local target2="$2"

    local d1 d2
    d1="$(_resolve_digest "${target1}")" || return 1
    d2="$(_resolve_digest "${target2}")" || return 1

    if [[ "${d1}" != "${d2}" ]]; then
        log_info "CHANGED: ${d1} -> ${d2}"
        echo "${d2}"
        return 0
    else
        log_err "UNEXPECTED IDENTICAL: block image digests are identical (${d1})"
        return 1
    fi
}

# Compares two disk images byte-by-byte and summarizes differences.
disk_diff_images() {
    local img1="$1"
    local img2="$2"

    disk_assert_safe_path "${img1}" "diff-images (1)" || return 1
    disk_assert_safe_path "${img2}" "diff-images (2)" || return 1

    if [[ ! -f "${img1}" || ! -f "${img2}" ]]; then
        log_err "diff-images: both arguments must be existing regular files"
        return 1
    fi

    local size1 size2
    size1=$(stat -c %s "${img1}")
    size2=$(stat -c %s "${img2}")

    if [[ "${size1}" -ne "${size2}" ]]; then
        log_err "diff-images: image sizes differ: ${img1}=${size1} bytes, ${img2}=${size2} bytes"
        return 1
    fi

    if cmp -s "${img1}" "${img2}"; then
        log_info "diff-images: images are binary identical (${size1} bytes)"
        echo "IDENTICAL: ${size1} bytes"
        return 0
    else
        local diff_count
        diff_count=$(cmp -l "${img1}" "${img2}" 2>/dev/null | head -n 1000 | wc -l || true)
        log_info "diff-images: images differ (at least ${diff_count} differing bytes found)"
        echo "DIFFERENT: at least ${diff_count} differing bytes"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# CLI Entry Point
# -----------------------------------------------------------------------------
usage() {
    cat << 'EOF'
Usage: disk_lifecycle.sh <subcommand> [arguments...]

Deterministic Disposable Disk Lifecycle for P3 crash/reboot qualification.

Subcommands:
  create-base <path> <size_mb> [pattern]
      Deterministically create a raw NVMe block image.
      pattern: zero (default), sparse, or 0x<HEX> (e.g. 0xAA)

  create-instance <base_path> <test_instance_path>
      Create an isolated snapshot (reflink / CoW copy) for a test run.

  hash-image <path>
      Compute SHA-256 digest of block image (prints 64-char hex to stdout).

  wipe-instance <test_instance_path>
      Safely and idempotently destroy an ephemeral test instance image.

  verify-identical <target1> <target2>
      Verify that two files or digests are identical. Returns 0 on match.

  verify-changed <target1> <target2>
      Verify that two files or digests differ. Returns 0 on difference.

  diff-images <path1> <path2>
      Inspect binary differences between two disk images.

Global options:
  -h, --help    Show this help message.

Environment variables:
  DISK_LIFECYCLE_QUIET=1    Suppress informational messages on stderr.
EOF
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi

    local cmd="$1"
    shift

    case "${cmd}" in
        create-base|create_base)
            if [[ $# -lt 2 || $# -gt 3 ]]; then
                log_err "Usage: disk_lifecycle.sh create-base <path> <size_mb> [pattern]"
                exit 1
            fi
            disk_create_base "$1" "$2" "${3:-zero}"
            ;;
        create-instance|create_instance)
            if [[ $# -ne 2 ]]; then
                log_err "Usage: disk_lifecycle.sh create-instance <base_path> <test_instance_path>"
                exit 1
            fi
            disk_create_instance "$1" "$2"
            ;;
        hash-image|hash_image)
            if [[ $# -ne 1 ]]; then
                log_err "Usage: disk_lifecycle.sh hash-image <path>"
                exit 1
            fi
            disk_hash_image "$1"
            ;;
        wipe-instance|wipe_instance)
            if [[ $# -ne 1 ]]; then
                log_err "Usage: disk_lifecycle.sh wipe-instance <test_instance_path>"
                exit 1
            fi
            disk_wipe_instance "$1"
            ;;
        verify-identical|verify_identical)
            if [[ $# -ne 2 ]]; then
                log_err "Usage: disk_lifecycle.sh verify-identical <target1> <target2>"
                exit 1
            fi
            disk_verify_identical "$1" "$2"
            ;;
        verify-changed|verify_changed)
            if [[ $# -ne 2 ]]; then
                log_err "Usage: disk_lifecycle.sh verify-changed <target1> <target2>"
                exit 1
            fi
            disk_verify_changed "$1" "$2"
            ;;
        diff-images|diff_images)
            if [[ $# -ne 2 ]]; then
                log_err "Usage: disk_lifecycle.sh diff-images <path1> <path2>"
                exit 1
            fi
            disk_diff_images "$1" "$2"
            ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            log_err "Unknown subcommand: '${cmd}'"
            usage
            exit 1
            ;;
    esac
}

# If script is executed directly, call main. If sourced, do nothing and export functions.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
