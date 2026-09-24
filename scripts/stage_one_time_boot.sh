#!/usr/bin/env bash
# Stage the AIENOS handoff image for exactly one boot on this machine.
#
# Dry run by default: prints what it would do and changes nothing.
# With --apply (needs sudo) it copies the image to the EFI system partition,
# creates a boot entry WITHOUT adding it to BootOrder, and sets BootNext to it.
# The firmware consumes BootNext on that boot, so the following boot returns to
# the normal BootOrder (Linux) whether AIENOS succeeds, hangs, or is powered off.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

apply=0
[[ "${1:-}" == "--apply" ]] && apply=1

image="target/aarch64-unknown-uefi/release/aienos-handoff.efi"
esp="/boot/efi"
loader='\EFI\AIENOS\aienos-handoff.efi'
label="AIENOS handoff (one-time)"
secure_boot_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

cargo build --quiet --release -p aienos-boot --target aarch64-unknown-uefi \
    --features handoff --bin aienos-handoff
cargo run --quiet --release -p aienos-evidence -- verify-efi "${image}"

if [[ -r "${secure_boot_var}" ]] && [[ "$(od -An -t u1 -j 4 -N 1 "${secure_boot_var}" | tr -d ' ')" == "1" ]]; then
    echo "STOP: Secure Boot is enabled. Firmware will refuse the unsigned AIENOS image."
    echo "Turn Secure Boot off in the firmware setup screen, or sign the image and enroll the key, then rerun."
    exit 1
fi

source_dev="$(findmnt -no SOURCE "${esp}")"
disk="/dev/$(lsblk -no PKNAME "${source_dev}")"
part="$(cat "/sys/class/block/$(basename "${source_dev}")/partition")"
order_before="$(efibootmgr | sed -n 's/^BootOrder: //p')"
digest="$(sha256sum "${image}" | cut -d' ' -f1)"

echo "image:       ${image} (sha256 ${digest})"
echo "copy to:     ${esp}/EFI/AIENOS/aienos-handoff.efi"
echo "boot entry:  '${label}' on ${disk} partition ${part}, loader ${loader}"
echo "BootOrder:   ${order_before} (left unchanged)"
echo "BootNext:    set to the AIENOS entry for one boot only"

if [[ "${apply}" -ne 1 ]]; then
    echo "Dry run. Rerun with --apply to stage."
    exit 0
fi

sudo install -D -m 0644 "${image}" "${esp}/EFI/AIENOS/aienos-handoff.efi"
entry="$(efibootmgr | sed -n "s/^Boot\([0-9A-F]\{4\}\)\*\{0,1\} ${label}.*/\1/p" | head -1)"
if [[ -z "${entry}" ]]; then
    sudo efibootmgr --quiet --create-only --disk "${disk}" --part "${part}" \
        --label "${label}" --loader "${loader}"
    entry="$(efibootmgr | sed -n "s/^Boot\([0-9A-F]\{4\}\)\*\{0,1\} ${label}.*/\1/p" | head -1)"
fi
[[ -n "${entry}" ]] || { echo "boot entry was not created"; exit 1; }

order_after="$(efibootmgr | sed -n 's/^BootOrder: //p')"
if [[ "${order_after}" != "${order_before}" ]]; then
    sudo efibootmgr --quiet --bootorder "${order_before}"
fi
sudo efibootmgr --quiet --bootnext "${entry}"

efibootmgr | sed -n '1,4p'
echo "Staged: the next boot runs Boot${entry} once. Reboot when you are at the machine."
echo "After it returns to Linux, run scripts/collect_boot_report.sh."
