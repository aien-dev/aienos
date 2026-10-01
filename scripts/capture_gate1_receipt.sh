#!/usr/bin/env bash
# capture_gate1_receipt.sh: write the TRUST-1 Gate 1 (standalone RAM recovery
# media) receipt from checks that actually ran. Nothing in the receipt is
# assumed: every field is either measured here or marked NOT_RUN.
#
# What it checks:
#   host  The recovery image (a gzip'd cpio archive) opens, has /init, and
#         carries every recovery tool the build script packages.
#   QEMU  Only with --boot (boots THIS image in QEMU with zero disks attached
#         and requires the image's own completion line) or --serial-log FILE
#         (reads the console log of an earlier zero-disk boot; the receipt
#         then says the log is not bound to this image's hash).
#   hardware  Never checked here. Internal NVMe unmounted and the ATLAS_RECOV
#         stick protected are facts about Machine 1, so they stay NOT_RUN
#         until the attended exercise records them.
#
# Usage: capture_gate1_receipt.sh [--boot | --serial-log FILE]
# Env:   AIENOS_GATE1_INITRD   image to check (default /tmp/aienos-recovery-standalone-initrd.img,
#                              built if missing)
#        AIENOS_GATE1_OUT_DIR  where the receipt goes (default evidence/); the
#                              file is named by its own sha256 and never overwritten
#        AIENOS_GATE1_KERNEL   kernel for --boot (default newest /boot/vmlinuz-*)
# Last line: GATE1_RECEIPT: PASS | FAIL | NOT_RUN <receipt path>. PASS needs host
# PASS, a bound QEMU boot (--boot) and a clean tree; anything less is NOT_RUN.
# Exit: 1 on FAIL, 2 on usage or setup errors, 0 otherwise (read the marker).
# Invariant: NO PLAINTEXT SECRETS IN REPOSITORY OR BUILD ARTIFACTS.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

mode="none"
serial_log=""
case "${1:-}" in
    "") ;;
    --boot) mode="boot" ;;
    --serial-log) mode="log"; serial_log="${2:-}"; [[ -n "${serial_log}" ]] || { echo "usage: $0 [--boot | --serial-log FILE]" >&2; exit 2; } ;;
    *) echo "usage: $0 [--boot | --serial-log FILE]" >&2; exit 2 ;;
esac

INITRD_IMG="${AIENOS_GATE1_INITRD:-/tmp/aienos-recovery-standalone-initrd.img}"
OUT_DIR="${AIENOS_GATE1_OUT_DIR:-${REPO_ROOT}/evidence}"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

json_str() { printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"; }

# ---- Source identity -------------------------------------------------------
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
if [[ "${commit}" == unknown ]]; then tree_dirty="unknown"
elif [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then tree_dirty="true"
else tree_dirty="false"; fi

# ---- Host checks on the image ----------------------------------------------
if [[ ! -f "${INITRD_IMG}" && -z "${AIENOS_GATE1_INITRD:-}" ]]; then
    bash "${REPO_ROOT}/scripts/build_standalone_recovery_initrd.sh" "${INITRD_IMG}"
fi

host_status="PASS"
host_notes=()
host_fail() { host_status="FAIL"; host_notes+=("$1"); echo "FAIL  host: $1"; }

initrd_sha="null"; initrd_size="null"; init_status="FAIL"
# Every tool build_standalone_recovery_initrd.sh copies into bin/.
EXPECTED=(busybox sh bash lsblk blkid mount umount mkdir cat grep sed sha256sum age
          sbverify fusermount3 tpm2_pcrread efibootmgr findmnt cryptsetup fsck.vfat
          mkfs.vfat fsck.ext4 chroot gocryptfs)
present=(); missing=()
if [[ ! -f "${INITRD_IMG}" ]]; then
    host_fail "image not found: ${INITRD_IMG}"
    missing=("${EXPECTED[@]}")
else
    initrd_sha=$(json_str "$(sha256sum "${INITRD_IMG}" | awk '{print $1}')")
    initrd_size=$(stat -c%s "${INITRD_IMG}")
    if ! gzip -t "${INITRD_IMG}" 2>/dev/null; then
        host_fail "image is not a valid gzip stream"
    elif ! gzip -dc "${INITRD_IMG}" | cpio -t --quiet > "${WORK_DIR}/list" 2>/dev/null; then
        host_fail "image is not a readable cpio archive"
    fi
    sed -e 's|^\./||' "${WORK_DIR}/list" 2>/dev/null > "${WORK_DIR}/names" || : > "${WORK_DIR}/names"
    init_status="PASS"
    grep -qx 'init' "${WORK_DIR}/names" || { init_status="FAIL"; host_fail "image has no /init (rdinit=/init would not start)"; }
    for t in "${EXPECTED[@]}"; do
        if grep -qx "bin/${t}" "${WORK_DIR}/names"; then present+=("/bin/${t}"); else missing+=("/bin/${t}"); fi
    done
    [[ ${#missing[@]} -eq 0 ]] || host_fail "image lacks ${#missing[@]} recovery tool(s): ${missing[*]}"
fi
[[ "${host_status}" == FAIL ]] || echo "PASS  host: image opens, has /init and all ${#EXPECTED[@]} recovery tools"

# ---- QEMU zero-disk boot ----------------------------------------------------
qemu_status="NOT_RUN"; qemu_note="not requested (pass --boot or --serial-log FILE)"
qemu_bound="false"; kernel_path="null"; kernel_sha="null"; log_sha="null"
markers=("AIENOS Standalone Hardware Recovery Core"
         "TEST MODE DETECTED: automated recovery verification complete")

if [[ "${mode}" == boot ]]; then
    quiet="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
    kernel="${AIENOS_GATE1_KERNEL:-$(ls -1t /boot/vmlinuz-* 2>/dev/null | head -n 1 || true)}"
    if [[ -e "${quiet}" ]]; then
        qemu_note="quiet flag ${quiet} is held; boot skipped"
    elif ! command -v qemu-system-aarch64 >/dev/null; then
        qemu_note="qemu-system-aarch64 not installed"
    elif [[ "$(uname -m)" != aarch64 && -z "${AIENOS_GATE1_KERNEL:-}" ]]; then
        qemu_note="host is $(uname -m); set AIENOS_GATE1_KERNEL to an AArch64 kernel"
    elif [[ "${host_status}" != PASS ]]; then
        qemu_note="host checks failed; image not booted"
    elif [[ -z "${kernel}" ]] || ! { cp "${kernel}" "${WORK_DIR}/vmlinuz" 2>/dev/null || sudo -n cp "${kernel}" "${WORK_DIR}/vmlinuz" 2>/dev/null; }; then
        qemu_note="kernel not readable: ${kernel:-none found}"
    else
        kernel_path=$(json_str "${kernel}")
        kernel_sha=$(json_str "$(sha256sum "${WORK_DIR}/vmlinuz" | awk '{print $1}')")
        serial_log="${WORK_DIR}/serial.log"
        set +e
        timeout "${AIENOS_QEMU_TIMEOUT:-60}" qemu-system-aarch64 \
            -M virt -cpu max -smp 2 -m 1024 \
            -kernel "${WORK_DIR}/vmlinuz" -initrd "${INITRD_IMG}" \
            -append "rdinit=/init aienos.test=1 console=ttyAMA0 panic=1 quiet" \
            -display none -nic none -serial file:"${serial_log}" -no-reboot
        set -e
        qemu_bound="true"
    fi
elif [[ "${mode}" == log ]]; then
    [[ -f "${serial_log}" ]] || { echo "serial log not found: ${serial_log}" >&2; exit 2; }
    qemu_note="console log supplied; the image that produced it is not bound to this receipt's image hash"
fi

if [[ -n "${serial_log}" && -f "${serial_log}" ]]; then
    log_sha=$(json_str "$(sha256sum "${serial_log}" | awk '{print $1}')")
    tr -d '\r' < "${serial_log}" > "${WORK_DIR}/serial.txt"
    qemu_status="PASS"
    for m in "${markers[@]}"; do
        if ! grep -qF -- "${m}" "${WORK_DIR}/serial.txt"; then
            qemu_status="FAIL"; echo "FAIL  QEMU: console never printed: ${m}"
        fi
    done
    if [[ "${qemu_status}" == PASS ]]; then
        echo "PASS  QEMU: zero-disk boot reached the recovery completion line"
        [[ "${qemu_bound}" != true ]] || qemu_note="booted this image with zero disks attached"
    else
        qemu_note="zero-disk boot did not reach the recovery completion line"
    fi
fi
echo "${qemu_status}  QEMU: ${qemu_note}"

# ---- Verdict ----------------------------------------------------------------
if [[ "${host_status}" == FAIL || "${qemu_status}" == FAIL ]]; then status="FAIL"
elif [[ "${qemu_status}" == PASS && "${qemu_bound}" == true && "${tree_dirty}" == false ]]; then status="PASS"
else status="NOT_RUN"; fi

json_list() { local first=1; printf '['; for x in "$@"; do [[ $first == 1 ]] || printf ', '; first=0; json_str "$x"; done; printf ']'; }
notes_json=$(json_list "${host_notes[@]+"${host_notes[@]}"}")

mkdir -p "${OUT_DIR}"
tmp_receipt="${WORK_DIR}/receipt.json"
cat > "${tmp_receipt}" << JSON_EOF
{
  "gate": "TRUST-1 Gate 1",
  "name": "standalone_ram_recovery_media",
  "status": "${status}",
  "status_rule": "PASS needs host PASS, a QEMU zero-disk boot of this exact image and a clean tree at a known commit; any FAIL is FAIL; otherwise NOT_RUN",
  "evidence_levels": {
    "host": "${host_status}",
    "qemu": "${qemu_status}",
    "hardware": "NOT_RUN"
  },
  "commit": $(json_str "${commit}"),
  "tree_dirty": $( [[ "${tree_dirty}" == unknown ]] && echo '"unknown"' || echo "${tree_dirty}"),
  "captured_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "host": $(json_str "$(uname -n)"),
  "arch": "$(uname -m)",
  "artifacts": {
    "standalone_initrd": {
      "path": $(json_str "${INITRD_IMG}"),
      "size_bytes": ${initrd_size},
      "sha256": ${initrd_sha},
      "host_check_failures": ${notes_json}
    },
    "qemu_kernel": { "path": ${kernel_path}, "sha256": ${kernel_sha} },
    "qemu_serial_log_sha256": ${log_sha}
  },
  "checks": {
    "init_entrypoint_present": "${init_status}",
    "recovery_tools_packaged": "$( [[ ${#missing[@]} -eq 0 ]] && echo PASS || echo FAIL)",
    "qemu_zero_disk_boot": "${qemu_status}",
    "qemu_boot_bound_to_image_hash": ${qemu_bound},
    "qemu_note": $(json_str "${qemu_note}"),
    "internal_nvme_unmounted": "NOT_RUN",
    "atlas_recov_protected": "NOT_RUN",
    "hardware_note": "Machine 1 facts; only the attended exercise can record them",
    "secrets_policy": "NO PLAINTEXT SECRETS IN REPOSITORY OR BUILD ARTIFACTS"
  },
  "utilities_packaged": $(json_list "${present[@]+"${present[@]}"}"),
  "utilities_missing": $(json_list "${missing[@]+"${missing[@]}"}")
}
JSON_EOF

receipt_sha=$(sha256sum "${tmp_receipt}" | awk '{print $1}')
RECEIPT_FILE="${OUT_DIR}/gate1_recovery_receipt_${receipt_sha}.json"
cp "${tmp_receipt}" "${RECEIPT_FILE}"
echo "GATE1_RECEIPT: ${status} ${RECEIPT_FILE}"
[[ "${status}" != FAIL ]] || exit 1
exit 0
