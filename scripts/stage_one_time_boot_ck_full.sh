#!/usr/bin/env bash
# Stage the FULL C kernel hardware image (native/kernel `make full
# CK_HARDWARE_STAGING=1`: devices stage with the xHCI keyboard and recovery
# access hook, NVMe and Store stages) on Machine 1 for exactly one attended
# boot. NEXT-PHASE-3 cut 2. Variant of scripts/stage_one_time_boot_ck.sh,
# which stages the inference image (no devices stage, so no keyboard).
#
#   scripts/stage_one_time_boot_ck_full.sh --dry-run   print every command, touch nothing
#   scripts/stage_one_time_boot_ck_full.sh --apply     do it (needs sudo; operator only)
#
# Exactly one of the two is required; there is no default mode.
#
# Owner files (the hardware staging image refuses the TEST Store keys and
# TEST machine id; native/kernel/README.md, "Owner provisioning"):
#   AIENOS_OWNER_PUBKEYS=<owner public keys file>
#   AIENOS_MACHINE_ID=<machine id file>
# The labelled TEST-FIXTURE files under native/kernel/tests/fixtures/owner/
# are refused here: they are for build checks, not for a boot.
#
# --dry-run runs only read-only probes (git, findmnt, lsblk, efibootmgr
# without arguments, the Secure Boot variable) and prints every command
# --apply would run, in order. It builds nothing, writes nothing, creates no
# file or directory, and calls no sudo.
#
# --apply, in order:
#   1. builds the hardware staging image with CK_FB_HOLD_S=120 (the last
#      report stays on screen for two minutes before the reset) and checks
#      it carries the platform xHCI discovery and no TEST-only marker;
#   2. sudo scripts/verify_native_rollback.sh --capture-pre (before BootNext,
#      which the capture requires absent);
#   3. copies the image to \EFI\AIENOS on the ESP (the only scratch
#      directory, docs/NATIVE_BOOT_ONE_TIME.md invariant 4) with a
#      STAGED-CK-FULL.TXT record;
#   4. creates a boot entry WITHOUT adding it to BootOrder (BootOrder is
#      restored if anything changed it), checks that Boot0004 AIENOSRECOV is
#      still there, and sets BootNext once.
#
# It never reboots. The firmware consumes BootNext on that boot, so the next
# boot after it returns to the normal BootOrder (Linux). The boot itself is
# attended: Drake at the machine, AIENOSRECOV stick inserted (Boot0004).
# What the screen should show is in native/kernel/README.md ("Physical
# attended boot") and is predicted from this machine's firmware tables by
# `make -C native/kernel acpi-scan` (tools/ck_acpi_scan.c).
#
# UNVERIFIED (no hardware run yet): that the full image leaves the internal
# disk unwritten on the Spark. By construction its Store stage refuses
# (production key source BLOCKED_OPERATOR) and NVMe DMA is granted only
# through the SMMU; no hardware run has confirmed it.
# No Python.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mode=""
case "${1:-}" in
    --dry-run) mode=dry ;;
    --apply) mode=apply ;;
    *) echo "usage: $0 --dry-run | --apply" >&2; exit 2 ;;
esac
[[ $# -eq 1 ]] || { echo "usage: $0 --dry-run | --apply" >&2; exit 2; }

disk="/dev/nvme0n1"
esp="/boot/efi"
owner_pubkeys="${AIENOS_OWNER_PUBKEYS:-}"
machine_id="${AIENOS_MACHINE_ID:-}"
out="${repo_root}/target/native-kernel-full-staging"
image="${out}/full-hardware-staging/BOOTAA64.EFI"
loader='\EFI\AIENOS\aienos-ck-full.efi'
label="AIENOS C kernel full (one-time)"
recov_entry="0004"
recov_label="AIENOSRECOV"
hold_s=120
secure_boot_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${AIENOS_STAGE_OUT:-${HOME}/workspace/evidence-out/NP3/staging}/${stamp}"

stops=()
stop() { stops+=("$*"); echo "STOP: $*"; }

# Print a command; run it only with --apply.
run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    [[ "${mode}" == apply ]] || return 0
    "$@"
}

echo "mode: ${mode}"

# ---- read-only pre-flight ----
if [[ -n "$(git status --porcelain)" ]]; then
    stop "the checkout has uncommitted changes; the boot must map to one exact commit"
fi
commit="$(git rev-parse HEAD)"
echo "commit:        ${commit}"

for f in owner_pubkeys machine_id; do
    v="${!f}"
    if [[ -z "${v}" ]]; then
        stop "${f} file not given (set AIENOS_OWNER_PUBKEYS and AIENOS_MACHINE_ID)"
    elif [[ ! -f "${v}" ]]; then
        stop "${f} file not found: ${v}"
    elif [[ "$(basename "${v}")" == TEST-FIXTURE* ]]; then
        stop "${f} is a labelled TEST-FIXTURE file (${v}); a boot needs the operator's own file"
    else
        echo "${f}: ${v}"
    fi
done

esp_dev="$(findmnt -no SOURCE "${esp}" 2>/dev/null || true)"
esp_opts="$(findmnt -no OPTIONS "${esp}" 2>/dev/null || true)"
[[ -n "${esp_dev}" ]] || stop "the ESP is not mounted at ${esp}"
esp_disk="/dev/$(lsblk -no PKNAME "${esp_dev}" 2>/dev/null | head -1)"
esp_part="$(cat "/sys/class/block/$(basename "${esp_dev:-none}")/partition" 2>/dev/null || true)"
echo "esp:           ${esp_dev:-?} partition ${esp_part:-?} of ${esp_disk} (${esp_opts%%,*})"
[[ "${esp_disk}" == "${disk}" ]] || stop "the ESP is not on ${disk}"
[[ ",${esp_opts}," == *",rw,"* ]] || stop "the ESP is not mounted read-write"

if [[ -r "${secure_boot_var}" ]] && [[ "$(od -An -t u1 -j 4 -N 1 "${secure_boot_var}" | tr -d ' ')" == "1" ]]; then
    stop "Secure Boot is enabled; the firmware will refuse the unsigned C image"
else
    echo "secure boot:   off or unreadable (recorded only; development decision 2026-10-01)"
fi

boot_state="$(efibootmgr 2>/dev/null || true)"
[[ -n "${boot_state}" ]] || stop "efibootmgr gave no output"
order_before="$(sed -n 's/^BootOrder: //p' <<<"${boot_state}")"
current_before="$(sed -n 's/^BootCurrent: //p' <<<"${boot_state}")"
next_before="$(sed -n 's/^BootNext: //p' <<<"${boot_state}")"
recov_line="$(grep -E "^Boot${recov_entry}\*? " <<<"${boot_state}" || true)"
echo "BootCurrent:   ${current_before}"
echo "BootOrder:     ${order_before} (never changed)"
[[ -z "${next_before}" ]] || stop "BootNext is already set (${next_before}); another staging is pending"
if [[ "${recov_line}" == *"${recov_label}"* ]]; then
    echo "recovery:      Boot${recov_entry} ${recov_label} present (kept untouched)"
else
    stop "Boot${recov_entry} ${recov_label} not present: insert the recovery stick and check docs/RECOVERY_MEDIA_MACHINE1.md (got: '${recov_line:-none}')"
fi
existing="$(sed -n "s/^Boot\([0-9A-F]\{4\}\)\*\{0,1\} ${label}.*/\1/p" <<<"${boot_state}" | head -1)"
echo "boot entry:    '${label}' ${existing:+exists as Boot${existing}}${existing:-will be created (create-only, not in BootOrder)}"
echo "evidence:      ${evidence_dir}"
echo "screen hold:   ${hold_s} s before the reset (CK_FB_HOLD_S)"

if [[ "${mode}" == apply && ${#stops[@]} -gt 0 ]]; then
    echo "STOPPED before touching anything: ${#stops[@]} pre-flight problem(s) above."
    exit 1
fi

echo
echo "commands (--apply runs them in this order; --dry-run only prints them):"

# ---- 1. build ----
cross=""
[[ "$(uname -m)" == aarch64 ]] || cross="aarch64-linux-gnu-"
run make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" full \
    CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${owner_pubkeys:-<owner pubkeys file>}" \
    CK_MACHINE_ID="${machine_id:-<machine id file>}" CK_FB_HOLD_S="${hold_s}"
if [[ "${mode}" == apply ]]; then
    grep -aqF "screen: gop " "${image}" || { echo "STOP: the image has no screen console"; exit 1; }
    grep -aqF "xhci_acpi: " "${image}" || { echo "STOP: the image has no platform xHCI discovery"; exit 1; }
    grep -aqF "recovery_access: " "${image}" || { echo "STOP: the image has no recovery access hook"; exit 1; }
    for m in "TEST-ONLY" "TEST Store" "TEST machine id"; do
        if grep -aqF "${m}" "${image}"; then echo "STOP: the image carries a TEST marker (${m})"; exit 1; fi
    done
    digest="$(sha256sum "${image}" | cut -d' ' -f1)"
    echo "image sha256:  ${digest}"
else
    echo "+ (check the image: screen console, xhci_acpi discovery and recovery_access present; no TEST-ONLY, TEST Store or TEST machine id marker)"
    digest="(computed after the build)"
fi

# ---- 2. pre-boot capture (BootNext still absent) ----
run mkdir -p "${evidence_dir}"
run sudo scripts/verify_native_rollback.sh --capture-pre "${evidence_dir}/pre_boot_capture.json"

# ---- 3. ESP scratch directory \EFI\AIENOS ----
record="${evidence_dir}/STAGED-CK-FULL.TXT"
if [[ "${mode}" == apply ]]; then
    cat >"${record}" <<EOF
aienos_commit: ${commit}
image: C kernel full hardware staging image (make full CK_HARDWARE_STAGING=1), CK_FB_HOLD_S=${hold_s}
image_sha256: ${digest}
owner_pubkeys_sha256: $(sha256sum "${owner_pubkeys}" | cut -d' ' -f1)
machine_id_sha256: $(sha256sum "${machine_id}" | cut -d' ' -f1)
staged_by: ${AIEN_AGENT_ID:-${USER:-unknown}}
staged_at_utc: ${stamp}
boot_current_before: ${current_before}
boot_order_before: ${order_before}
recovery_entry: Boot${recov_entry} ${recov_label}
linux_kernel_before: $(uname -r)
EOF
else
    echo "+ (write ${record}: commit, image and owner file digests, prior boot state)"
fi
run sudo install -D -m 0644 "${image}" "${esp}/EFI/AIENOS/aienos-ck-full.efi"

# ---- 4. one-time boot entry ----
entry="${existing}"
if [[ -z "${entry}" ]]; then
    run sudo efibootmgr --quiet --create-only --disk "${disk}" --part "${esp_part:-<esp partition>}" \
        --label "${label}" --loader "${loader}"
    if [[ "${mode}" == apply ]]; then
        entry="$(efibootmgr | sed -n "s/^Boot\([0-9A-F]\{4\}\)\*\{0,1\} ${label}.*/\1/p" | head -1)"
        [[ -n "${entry}" ]] || { echo "STOP: the boot entry was not created"; exit 1; }
    fi
fi
entry="${entry:-NNNN}"
[[ "${entry}" != "${recov_entry}" ]] || { echo "STOP: the new entry took the recovery entry's number"; exit 1; }
if [[ "${mode}" == apply ]]; then
    order_after="$(efibootmgr | sed -n 's/^BootOrder: //p')"
    if [[ "${order_after}" != "${order_before}" ]]; then
        run sudo efibootmgr --quiet --bootorder "${order_before}"
    fi
    efibootmgr | grep -qE "^Boot${recov_entry}\*? .*${recov_label}" \
        || { echo "STOP: Boot${recov_entry} ${recov_label} is gone; BootNext NOT set"; exit 1; }
    echo "aienos_boot_entry: ${entry}" >>"${record}"
else
    echo "+ (only if BootOrder changed: sudo efibootmgr --quiet --bootorder ${order_before})"
    echo "+ (check Boot${recov_entry} ${recov_label} still present, else stop before BootNext)"
fi
run sudo install -m 0644 "${record}" "${esp}/EFI/AIENOS/STAGED-CK-FULL.TXT"
run sudo efibootmgr --quiet --bootnext "${entry}"

echo
if [[ "${mode}" == dry ]]; then
    if [[ ${#stops[@]} -gt 0 ]]; then
        echo "Dry run: nothing touched. --apply would STOP now on ${#stops[@]} pre-flight problem(s) above."
    else
        echo "Dry run: nothing touched. Pre-flight clean; --apply would stage the boot above."
    fi
    exit 0
fi
cat "${record}"
efibootmgr | sed -n '1,4p'
echo "Staged: the next boot runs Boot${entry} once. Nothing was rebooted."
echo "Reboot only with the operator at the machine and the ${recov_label} stick inserted."
echo "After the return to Linux: sudo scripts/verify_native_rollback.sh --capture-post."
