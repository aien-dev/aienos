#!/usr/bin/env bash
# Stage the B7b PROBE build of the FULL C kernel hardware image (native/kernel
# `make full CK_B7B_PROBE=1 CK_HARDWARE_STAGING=1`) on Machine 1 for exactly
# one attended boot: the B7b campaign (aienos#286, docs/campaigns/
# B7B-PHYSICAL-BOOT-PREP.md, go/no-go item G7). Variant of
# scripts/stage_one_time_boot_ck_full.sh; the only differences are the probe
# flag, the double build with digest comparison, the probe image checks and
# the names (output folder, ESP file, boot-entry label, record, evidence dir).
#
#   scripts/stage_one_time_boot_ck_b7b.sh --dry-run   print every command, touch nothing
#   scripts/stage_one_time_boot_ck_b7b.sh --apply     do it (needs sudo; operator only)
#
# Exactly one of the two is required; there is no default mode.
#
# What the probe image does on the Spark (core/smmu_svc.c ck_b7b_probe, run in
# kmain before the device stages): confine PCI segment 15 requester 0x100 (the
# GB10) once on a one-page window on SMMUv3 instance 1, read SMMU_IDR0/IDR1,
# unconfine, print AIENOS_B7B_PROBE: CONFINED_AND_RELEASED (or REFUSED / FAIL),
# then continue through the normal full-image stages (xHCI keyboard, recovery
# access hook, NVMe, Store: the Store refuses, production key source
# BLOCKED_OPERATOR) to the final report and the reset. No device moves data
# for the probe; the GPU is not programmed. Expected lines: docs/
# GB10_IORT_DECODE.md section 10 (expected, not observed).
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
#   1. builds the probe hardware staging image TWICE, in two output folders,
#      with CK_FB_HOLD_S=120 (the last report stays on screen for two minutes
#      before the reset), and STOPs unless the two digests are equal (the
#      reproducibility check of docs/native/PREFLIGHT-AND-RECOVERY.md
#      section 1, done here because scripts/ck_repro_build.sh does not build
#      staging images); checks the image carries the probe for segment 15,
#      the platform xHCI discovery and the recovery hook, and no TEST marker;
#   2. sudo scripts/verify_native_rollback.sh --capture-pre (before BootNext,
#      which the capture requires absent);
#   3. copies the image to \EFI\AIENOS on the ESP (the only scratch
#      directory, docs/NATIVE_BOOT_ONE_TIME.md invariant 4) with a
#      STAGED-CK-B7B.TXT record;
#   4. creates a boot entry WITHOUT adding it to BootOrder (BootOrder is
#      restored if anything changed it), checks that Boot0004 AIENOSRECOV is
#      still there, and sets BootNext once.
#
# It never reboots. The firmware consumes BootNext on that boot, so the next
# boot after it returns to the normal BootOrder (Linux). The boot itself is
# attended: Drake at the machine, AIENOSRECOV stick inserted (Boot0004),
# camera on, witness present (B7B-PHYSICAL-BOOT-PREP.md sections 2 to 5).
#
# Carried unknowns (B7B-PHYSICAL-BOOT-PREP.md section 8), unchanged by this
# script: whether the GB10 or HDA0 attempts DMA while SMMUv3 B stays enabled
# with every stream aborting; whether the real IORT routes segment 15 rid
# 0x100 to instance 1. The screen hold and reset of the probe image are the
# full image's own (the probe returns to kmain and the normal final report
# and reset follow), so they are expected to match the full image; UNVERIFIED
# on the real console until the window.
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
out="${repo_root}/target/native-kernel-b7b-staging"
out_b="${out}-build-b"
image="${out}/full-hardware-staging/BOOTAA64.EFI"
image_b="${out_b}/full-hardware-staging/BOOTAA64.EFI"
loader='\EFI\AIENOS\aienos-ck-b7b.efi'
label="AIENOS C kernel B7b probe (one-time)"
recov_entry="0004"
recov_label="AIENOSRECOV"
hold_s=120
secure_boot_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${AIENOS_STAGE_OUT:-${HOME}/workspace/evidence-out/B7B/staging}/${stamp}"

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
        v="$(realpath -- "${v}")" # make -C native/kernel resolves relative paths from there
        printf -v "${f}" %s "${v}"
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

# ---- 1. build, twice, and compare (the probe image's reproducibility check) ----
cross=""
[[ "$(uname -m)" == aarch64 ]] || cross="aarch64-linux-gnu-"
for o in "${out}" "${out_b}"; do
    run make -s -C native/kernel CROSS="${cross}" OUT="${o}" AIENOS_COMMIT="${commit}" full \
        CK_B7B_PROBE=1 CK_HARDWARE_STAGING=1 \
        CK_OWNER_PUBKEYS="${owner_pubkeys:-<owner pubkeys file>}" \
        CK_MACHINE_ID="${machine_id:-<machine id file>}" CK_FB_HOLD_S="${hold_s}"
done
if [[ "${mode}" == apply ]]; then
    digest="$(sha256sum "${image}" | cut -d' ' -f1)"
    digest_b="$(sha256sum "${image_b}" | cut -d' ' -f1)"
    [[ "${digest}" == "${digest_b}" ]] \
        || { echo "STOP: the two probe builds differ (${digest} vs ${digest_b}); the image is not reproducible"; exit 1; }
    grep -aqF "b7b_probe: start segment=" "${image}" || { echo "STOP: the image carries no B7b probe"; exit 1; }
    grep -aqF "screen: gop " "${image}" || { echo "STOP: the image has no screen console"; exit 1; }
    grep -aqF "xhci_acpi: " "${image}" || { echo "STOP: the image has no platform xHCI discovery"; exit 1; }
    grep -aqF "recovery_access: " "${image}" || { echo "STOP: the image has no recovery access hook"; exit 1; }
    for m in "TEST-ONLY" "TEST Store" "TEST machine id" "segment 0"; do
        if grep -aqF "${m}" "${image}"; then echo "STOP: the image carries a TEST marker (${m})"; exit 1; fi
    done
    echo "image sha256:  ${digest} (build A and build B equal)"
else
    echo "+ (compare the two digests: STOP if they differ)"
    echo "+ (check the image: B7b probe for segment 15, screen console, xhci_acpi discovery and recovery_access present; no TEST-ONLY, TEST Store, TEST machine id or segment 0 marker)"
    digest="(computed after the build)"
    digest_b="(computed after the build)"
fi
# ---- 2. pre-boot capture (BootNext still absent) ----
run mkdir -p "${evidence_dir}"
run sudo scripts/verify_native_rollback.sh --capture-pre "${evidence_dir}/pre_boot_capture.json"

# ---- 3. ESP scratch directory \EFI\AIENOS ----
record="${evidence_dir}/STAGED-CK-B7B.TXT"
if [[ "${mode}" == apply ]]; then
    cat >"${record}" <<EOF
aienos_commit: ${commit}
image: C kernel B7b probe hardware staging image (make full CK_B7B_PROBE=1 CK_HARDWARE_STAGING=1), CK_FB_HOLD_S=${hold_s}
image_sha256_build_b: ${digest_b}
probe: PCI segment 15 requester 0x100 on SMMUv3 instance 1, one page, no DMA
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
run sudo install -D -m 0644 "${image}" "${esp}/EFI/AIENOS/aienos-ck-b7b.efi"

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
run sudo install -m 0644 "${record}" "${esp}/EFI/AIENOS/STAGED-CK-B7B.TXT"
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
echo "After the return to Linux: sudo scripts/verify_native_rollback.sh --capture-post ${evidence_dir}/post_boot_capture.json,"
echo "then --pre ${evidence_dir}/pre_boot_capture.json --post ${evidence_dir}/post_boot_capture.json --verify; write the screen lines next to the record."
