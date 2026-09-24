#!/usr/bin/env bash
# Stage the AIENOS first-boot evidence image for exactly one boot.
#
# Dry run by default: prints what it would do and changes nothing.
# With --apply (needs sudo) it copies the image to the EFI system partition,
# writes \EFI\AIENOS\STAGED.TXT (commit, image digest, prior boot state),
# creates a boot entry WITHOUT adding it to BootOrder, and sets BootNext.
# The firmware consumes BootNext on that boot, so the following boot returns to
# the normal BootOrder (Linux) whether AIENOS succeeds, hangs, or is powered off.
# Run it under `aien-proof hold --resource machine-1` so the attempt is recorded.
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

if [[ -n "$(git status --porcelain)" ]]; then
    echo "STOP: the checkout has uncommitted changes; the boot must map to one exact commit."
    exit 1
fi
commit="$(git rev-parse HEAD)"

AIENOS_COMMIT="${commit}" cargo build --quiet --release -p aienos-boot \
    --target aarch64-unknown-uefi --features handoff,hardware-staging --bin aienos-handoff
cargo run --quiet --release -p aienos-evidence -- verify-efi "${image}"

if [[ -r "${secure_boot_var}" ]] && [[ "$(od -An -t u1 -j 4 -N 1 "${secure_boot_var}" | tr -d ' ')" == "1" ]]; then
    echo "STOP: Secure Boot is enabled. Firmware will refuse the unsigned AIENOS image."
    echo "Turn Secure Boot off in the firmware setup screen, then rerun."
    exit 1
fi

source_dev="$(findmnt -no SOURCE "${esp}")"
disk="/dev/$(lsblk -no PKNAME "${source_dev}")"
part="$(cat "/sys/class/block/$(basename "${source_dev}")/partition")"
order_before="$(efibootmgr | sed -n 's/^BootOrder: //p')"
current_before="$(efibootmgr | sed -n 's/^BootCurrent: //p')"
digest="$(sha256sum "${image}" | cut -d' ' -f1)"
staged_by="${AIEN_AGENT_ID:-${USER:-unknown}}"

record="$(mktemp)"
trap 'rm -f "${record}"' EXIT
cat >"${record}" <<EOF
aienos_commit: ${commit}
image_sha256: ${digest}
staged_by: ${staged_by}
staged_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
boot_current_before: ${current_before}
boot_order_before: ${order_before}
linux_kernel_before: $(uname -r)
EOF

echo "commit:      ${commit}"
echo "image:       ${image} (sha256 ${digest})"
echo "copy to:     ${esp}/EFI/AIENOS/aienos-handoff.efi and STAGED.TXT"
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
echo "aienos_boot_entry: ${entry}" >>"${record}"
sudo install -m 0644 "${record}" "${esp}/EFI/AIENOS/STAGED.TXT"
sudo efibootmgr --quiet --bootnext "${entry}"

cat "${record}"
efibootmgr | sed -n '1,4p'
echo "Staged: the next boot runs Boot${entry} once. Reboot when you are at the machine."
echo "After it returns to Linux, collect under the same key (docs/NATIVE_BOOT_ONE_TIME.md)."
