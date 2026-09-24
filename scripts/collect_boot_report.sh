#!/usr/bin/env bash
# Read the reports left by an AIENOS handoff boot, from Linux. Read-only.
#   pre-exit report:  written to the EFI system partition before firmware exit
#   native report:    written to a firmware variable by the AIENOS kernel
set -euo pipefail

report_file="/boot/efi/EFI/AIENOS/BOOTREPORT.TXT"
report_var="/sys/firmware/efi/efivars/AienosBootReport-a1e05b0e-7c3d-4f51-9b6a-2d8e4c1f0a37"
image="/boot/efi/EFI/AIENOS/aienos-handoff.efi"

echo "== staged image"
if [[ -r "${image}" ]]; then
    echo "sha256: $(sha256sum "${image}" | cut -d" " -f1)"
else
    echo "missing: ${image}"
fi

echo "== pre-exit report (${report_file})"
if [[ -r "${report_file}" ]]; then
    cat "${report_file}"
else
    echo "missing: the image did not reach the pre-exit save, or the file was not readable"
fi

echo "== native kernel report (${report_var})"
if [[ -r "${report_var}" ]]; then
    # efivarfs prefixes the value with 4 bytes of attributes.
    native="$(tail -c +5 "${report_var}")"
    printf '%s\n' "${native}"
    if grep -qx "kernel: alive" <<<"${native}"; then
        echo "NATIVE_BOOT_OK"
    else
        echo "NATIVE_BOOT_INCOMPLETE"
    fi
else
    echo "missing: the kernel did not run, or the firmware refused runtime variable writes"
    echo "NATIVE_BOOT_UNPROVEN"
fi
