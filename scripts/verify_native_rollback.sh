#!/usr/bin/env bash
# verify_native_rollback.sh
# Host-side automated verifier for AIENOS native-boot rollback observations.
#
# Consumes pre-boot and post-return evidence captures and determines whether
# rollback invariants held.
#
# Stable result verdicts:
#   PASS     - All rollback invariants satisfied.
#   FAIL     - One or more invariants violated (e.g. BootOrder changed, root modified, BootNext stuck).
#   BLOCKED  - Hardware qualification blocked by trust chain / Secure Boot.
#   INCOMP   - Incomplete evidence or missing required capture files.

set -euo pipefail

usage() {
    cat <<EOF
Usage:
  Capture pre-boot baseline:
    $0 --capture-pre <OUT_JSON>

  Capture post-return evidence:
    $0 --capture-post <OUT_JSON>

  Verify pre/post observations:
    $0 --verify --pre <PRE_JSON> --post <POST_JSON> [--candidate <IMAGE_EFI>]
EOF
    exit 2
}

capture_state() {
    local out_file="$1"
    local sb_state="unknown"
    local secure_boot_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    
    if [[ -r "${secure_boot_var}" ]]; then
        local b
        b="$(od -An -t u1 -j 4 -N 1 "${secure_boot_var}" 2>/dev/null | tr -d ' ' || echo "")"
        if [[ "${b}" == "1" ]]; then
            sb_state="enabled"
        elif [[ "${b}" == "0" ]]; then
            sb_state="disabled"
        fi
    fi

    if [[ "${sb_state}" == "unknown" ]] && command -v mokutil >/dev/null 2>&1; then
        if mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
            sb_state="enabled"
        else
            sb_state="disabled"
        fi
    fi

    local boot_current=""
    local boot_order=""
    local boot_next=""
    if command -v efibootmgr >/dev/null 2>&1; then
        boot_current="$(efibootmgr 2>/dev/null | sed -n 's/^BootCurrent: //p' || echo "")"
        boot_order="$(efibootmgr 2>/dev/null | sed -n 's/^BootOrder: //p' || echo "")"
        boot_next="$(efibootmgr 2>/dev/null | sed -n 's/^BootNext: //p' || echo "")"
    fi

    local root_dev root_uuid root_opts
    root_dev="$(findmnt -no SOURCE / 2>/dev/null || echo "")"
    root_uuid="$(findmnt -no UUID / 2>/dev/null || echo "")"
    root_opts="$(findmnt -no OPTIONS / 2>/dev/null || echo "")"

    local esp_dev esp_uuid esp_opts
    esp_dev="$(findmnt -no SOURCE /boot/efi 2>/dev/null || echo "")"
    esp_uuid="$(findmnt -no UUID /boot/efi 2>/dev/null || echo "")"
    esp_opts="$(findmnt -no OPTIONS /boot/efi 2>/dev/null || echo "")"

    local commit=""
    commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

    cat >"${out_file}" <<EOF
{
  "captured_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(uname -n)",
  "kernel": "$(uname -r)",
  "git_commit": "${commit}",
  "secure_boot": "${sb_state}",
  "boot_current": "${boot_current}",
  "boot_order": "${boot_order}",
  "boot_next": "${boot_next}",
  "root": {
    "device": "${root_dev}",
    "uuid": "${root_uuid}",
    "options": "${root_opts}"
  },
  "esp": {
    "device": "${esp_dev}",
    "uuid": "${esp_uuid}",
    "options": "${esp_opts}"
  }
}
EOF
    echo "Captured state to ${out_file}"
}

verify_observations() {
    local pre_file="$1"
    local post_file="$2"
    # $3 (--candidate) is accepted for the record; the verdict does not use it.

    if [[ ! -f "${pre_file}" || ! -f "${post_file}" ]]; then
        echo "ERROR: Capture file(s) missing or unreadable"
        echo "VERDICT: INCOMP"
        exit 1
    fi

    # The comparison, report and verdict live in Rust: `aienos-evidence
    # verify-rollback` exits 0 PASS, 1 FAIL, 3 BLOCKED, 2 unparseable capture.
    local repo_root evidence_bin
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    evidence_bin="${repo_root}/target/release/aienos-evidence"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" ]]; then
        # Under sudo, build as the invoking user: their toolchain is on their
        # PATH (not sudo's secure_path) and target/ stays owned by them.
        sudo -u "${SUDO_USER}" -H bash -lc \
            'cd "$1" && cargo build --quiet --release -p aienos-evidence' _ "${repo_root}" \
            || { echo "ERROR: Could not build aienos-evidence"; echo "VERDICT: INCOMP"; exit 1; }
    else
        (cd "${repo_root}" && cargo build --quiet --release -p aienos-evidence) \
            || { echo "ERROR: Could not build aienos-evidence"; echo "VERDICT: INCOMP"; exit 1; }
    fi

    exec "${evidence_bin}" verify-rollback "${pre_file}" "${post_file}"
}

action=""
pre_file=""
post_file=""
candidate=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --capture-pre)
            action="capture"
            pre_file="${2:-}"
            [[ -n "${pre_file}" ]] || usage
            shift 2
            ;;
        --capture-post)
            action="capture"
            post_file="${2:-}"
            [[ -n "${post_file}" ]] || usage
            shift 2
            ;;
        --verify)
            action="verify"
            shift
            ;;
        --pre)
            pre_file="${2:-}"
            shift 2
            ;;
        --post)
            post_file="${2:-}"
            shift 2
            ;;
        --candidate)
            candidate="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown argument: $1"
            usage
            ;;
    esac
done

if [[ "${action}" == "capture" ]]; then
    target="${pre_file:-${post_file}}"
    capture_state "${target}"
elif [[ "${action}" == "verify" ]]; then
    [[ -n "${pre_file}" && -n "${post_file}" ]] || usage
    verify_observations "${pre_file}" "${post_file}" "${candidate}"
else
    usage
fi
