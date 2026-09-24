#!/usr/bin/env bash
# Collect and judge the evidence from an AIENOS first-boot attempt. Read-only.
# Run under `aien-proof hold --resource machine-1` so the full output becomes
# an audit event in the hardware-test ledger.
#
# Gate (M2 first native boot): Machine 1 left firmware, entered native AIENOS
# code with no Linux underneath, left independently recoverable evidence, and
# returned to the existing system without damaging it.
set -uo pipefail

esp="${AIENOS_ESP_DIR:-/boot/efi/EFI/AIENOS}"
staged_file="${esp}/STAGED.TXT"
report_file="${esp}/BOOTREPORT.TXT"
image="${esp}/aienos-handoff.efi"
report_var="${AIENOS_REPORT_VAR:-/sys/firmware/efi/efivars/AienosBootReportV1-a1e05b0e-7c3d-4f51-9b6a-2d8e4c1f0a37}"

field() { sed -n "s/^$1: //p" <<<"$2" | head -1; }
check() { # name, pass(0/1), detail
    if [[ "$2" == 1 ]]; then echo "PASS  $1: $3"; else echo "FAIL  $1: $3"; failed=1; fi
}
failed=0

echo "== staging record (${staged_file})"
staged="$(cat "${staged_file}" 2>/dev/null)"
if [[ -z "${staged}" ]]; then
    echo "missing: nothing was staged, or the file is unreadable"
    echo "M2_GATE: UNPROVEN"
    exit 1
fi
printf '%s\n' "${staged}"
commit="$(field aienos_commit "${staged}")"

echo "== staged image"
digest_now="$(sha256sum "${image}" 2>/dev/null | cut -d' ' -f1)"
echo "sha256: ${digest_now:-missing}"

echo "== pre-exit report (${report_file})"
pre="$(cat "${report_file}" 2>/dev/null)"
printf '%s\n' "${pre:-missing}"

echo "== native firmware-variable report"
native=""
if [[ -r "${report_var}" ]]; then
    # efivarfs prefixes the value with 4 bytes of attributes.
    native="$(tail -c +5 "${report_var}")"
fi
printf '%s\n' "${native:-missing}"

echo "== current boot state"
boot_state="$(efibootmgr)"
printf '%s\n' "${boot_state}" | sed -n '1,4p'
echo "kernel: $(uname -r)"
echo "root: $(findmnt -no OPTIONS / | cut -d, -f1)"

echo "== verdict"
check "image_unchanged" "$([[ -n "${digest_now}" && "${digest_now}" == "$(field image_sha256 "${staged}")" ]] && echo 1 || echo 0)" \
    "staged ${commit:0:12}, image ${digest_now:0:16}"
check "left_firmware_into_aienos" "$([[ "$(field aienos_commit "${pre}")" == "${commit}" ]] && echo 1 || echo 0)" \
    "pre-exit report from this commit, last stage $(field last_stage "${pre}")"
check "native_code_after_firmware_exit" "$([[ -n "${native}" && "$(field aienos_commit "${native}")" == "${commit}" ]] && echo 1 || echo 0)" \
    "firmware variable written by AIENOS after ExitBootServices (kind $(field report_kind "${native}"))"
check "kernel_alive" "$(grep -qx "kernel: alive" <<<"${native}" && echo 1 || echo 0)" \
    "last stage $(field last_stage "${native}")"
check "boot_next_consumed" "$(grep -q "^BootNext:" <<<"${boot_state}" && echo 0 || echo 1)" \
    "no pending one-time boot"
check "boot_order_unchanged" "$([[ "$(field BootOrder "${boot_state}")" == "$(field boot_order_before "${staged}")" ]] && echo 1 || echo 0)" \
    "$(field BootOrder "${boot_state}")"
check "linux_entry_booted" "$([[ "$(field BootCurrent "${boot_state}")" == "$(field boot_current_before "${staged}")" ]] && echo 1 || echo 0)" \
    "BootCurrent $(field BootCurrent "${boot_state}")"
check "linux_kernel_unchanged" "$([[ "$(uname -r)" == "$(field linux_kernel_before "${staged}")" ]] && echo 1 || echo 0)" \
    "$(uname -r)"
check "root_filesystem_writable" "$([[ "$(findmnt -no OPTIONS / | cut -d, -f1)" == "rw" ]] && echo 1 || echo 0)" "/"

if [[ "${failed}" == 0 ]]; then
    echo "M2_GATE: PASS"
else
    echo "M2_GATE: FAIL"
    exit 1
fi
