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
    local candidate_img="${3:-}"

    if [[ ! -f "${pre_file}" || ! -f "${post_file}" ]]; then
        echo "ERROR: Capture file(s) missing or unreadable"
        echo "VERDICT: INCOMP"
        exit 1
    fi

    # Read fields using python3 JSON parser
    python3 - <<PYEOF
import json, sys

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: Cannot parse {path}: {e}")
        sys.exit(2)

pre = load_json("${pre_file}")
post = load_json("${post_file}")
candidate = "${candidate_img}"

errors = []
blocked_reasons = []

# 1. Secure Boot checks
sb_pre = pre.get("secure_boot", "").lower()
sb_post = post.get("secure_boot", "").lower()

if sb_pre != "enabled":
    blocked_reasons.append(f"Pre-boot Secure Boot is not enabled: {sb_pre}")
if sb_post != "enabled":
    blocked_reasons.append(f"Post-boot Secure Boot is not enabled: {sb_post}")
if sb_pre != sb_post:
    errors.append(f"Secure Boot state changed from '{sb_pre}' to '{sb_post}'")

# 2. BootOrder preservation
bo_pre = [x.strip() for x in pre.get("boot_order", "").split(",") if x.strip()]
bo_post = [x.strip() for x in post.get("boot_order", "").split(",") if x.strip()]

if not bo_pre:
    errors.append("Pre-boot BootOrder is empty")
if not bo_post:
    errors.append("Post-boot BootOrder is empty")

# Check that the default entry (first in pre-order) is still the first in post-order
if bo_pre and bo_post:
    if bo_pre[0] != bo_post[0]:
        errors.append(f"Permanent default boot entry altered: pre was {bo_pre[0]}, post is {bo_post[0]}")
    # All original pre-entries must be present and preserve relative order
    common_post = [x for x in bo_post if x in bo_pre]
    if common_post != bo_pre:
        errors.append(f"BootOrder sequence changed: pre={bo_pre}, filtered_post={common_post}")

# 3. Return to default OS (BootCurrent == default)
cur_post = post.get("boot_current", "").strip()
if bo_pre and cur_post != bo_pre[0]:
    errors.append(f"Post-boot did not return to default entry: expected {bo_pre[0]}, got {cur_post}")

# 4. BootNext consumption
next_post = post.get("boot_next", "").strip()
if next_post:
    errors.append(f"BootNext was not consumed by firmware: still set to {next_post}")

# 5. Root filesystem invariants
root_pre = pre.get("root", {})
root_post = post.get("root", {})
if root_pre.get("uuid") and root_pre.get("uuid") != root_post.get("uuid"):
    errors.append(f"Root UUID changed: pre={root_pre.get('uuid')}, post={root_post.get('uuid')}")
if "rw" not in root_post.get("options", "").split(","):
    errors.append(f"Root filesystem not mounted rw after return: {root_post.get('options')}")

# 6. ESP filesystem invariants
esp_pre = pre.get("esp", {})
esp_post = post.get("esp", {})
if esp_pre.get("uuid") and esp_pre.get("uuid") != esp_post.get("uuid"):
    errors.append(f"ESP UUID changed: pre={esp_pre.get('uuid')}, post={esp_post.get('uuid')}")

# Output summary
print("=== NATIVE BOOT ROLLBACK VERIFICATION REPORT ===")
print(f"Pre-capture:  {pre.get('captured_utc')} on {pre.get('host')}")
print(f"Post-capture: {post.get('captured_utc')} on {post.get('host')}")
print(f"Secure Boot:  before={sb_pre}, after={sb_post}")
print(f"BootOrder:    before={bo_pre}, after={bo_post}")
print(f"BootCurrent:  after={cur_post} (expected={bo_pre[0] if bo_pre else 'unknown'})")
print(f"BootNext:     after={'<empty>' if not next_post else next_post}")
print(f"Root UUID:    {root_post.get('uuid')} (matched={root_pre.get('uuid') == root_post.get('uuid')})")
print(f"ESP UUID:     {esp_post.get('uuid')} (matched={esp_pre.get('uuid') == esp_post.get('uuid')})")

if blocked_reasons:
    print("\n--- BLOCKED REASONS ---")
    for b in blocked_reasons:
        print(f"* {b}")
    print("\nVERDICT: BLOCKED")
    sys.exit(3)

if errors:
    print("\n--- VIOLATIONS ---")
    for err in errors:
        print(f"* FAIL: {err}")
    print("\nVERDICT: FAIL")
    sys.exit(1)

print("\nAll rollback assertions verified.")
print("VERDICT: PASS")
sys.exit(0)
PYEOF
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
