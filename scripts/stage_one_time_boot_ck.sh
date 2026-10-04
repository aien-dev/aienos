#!/usr/bin/env bash
# Stage the C kernel (native/kernel) inference image plus its MODEL.MAP on
# Machine 1 for exactly one attended boot (L6, aienos#34 lane 6; L6-C screen
# console). Variant of scripts/stage_one_time_boot.sh, which stages the Rust
# aienos-handoff image.
#
#   scripts/stage_one_time_boot_ck.sh --dry-run   print every command, touch nothing
#   scripts/stage_one_time_boot_ck.sh --apply     do it (needs sudo; operator only)
#
# Exactly one of the two is required; there is no default mode.
#
# --dry-run runs only read-only probes (git, findmnt, lsblk, lsattr, stat,
# efibootmgr without arguments, the Secure Boot variable) and prints every
# command --apply would run, in order. It builds nothing, writes nothing,
# creates no file or directory, and calls no sudo.
#
# --apply, in order:
#   1. builds the infer image (core-only C kernel + crates/aienos-infer-kernel,
#      the image the L6 handoff chose: no NVMe stage, the model comes through
#      the firmware's own Block I/O before ExitBootServices) with
#      CK_FB_HOLD_S=120 so the last report stays on screen for two minutes
#      before the reset, and the host tool ck_model_map;
#   2. sudo chattr +i on the model file, FIRST, so its blocks cannot move
#      between the map and the boot;
#   3. sudo ck_model_map make MODEL.MAP --fiemap --part-start auto --disk
#      /dev/nvme0n1, then sudo ck_model_map check (reads every extent by LBA
#      from the raw disk and recomputes the SHA-256: the same bytes the
#      firmware will read);
#   4. sudo scripts/verify_native_rollback.sh --capture-pre (before BootNext,
#      which the capture requires absent);
#   5. copies the image and MODEL.MAP to \EFI\AIENOS on the ESP (the only
#      scratch directory, docs/NATIVE_BOOT_ONE_TIME.md invariant 4) with a
#      STAGED-CK.TXT record;
#   6. creates a boot entry WITHOUT adding it to BootOrder (BootOrder is
#      restored if anything changed it), checks that Boot0004 AIENOSRECOV is
#      still there, and sets BootNext once.
#
# It never reboots. The firmware consumes BootNext on that boot, so the next
# boot after it returns to the normal BootOrder (Linux). The boot itself is
# attended: Drake at the machine, AIENOSRECOV stick inserted (Boot0004).
# The model stays immutable until the operator runs, after the return:
#   sudo chattr -i <model>
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
model="${AIENOS_MODEL:-${HOME}/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf}"
pinned_sha=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1
out="${repo_root}/target/native-kernel-l6c-staging"
lib="${repo_root}/target/infer-kernel/aarch64-unknown-none/release/libaienos_infer_kernel.a"
image="${out}/BOOTAA64.EFI"
map_tool="${out}/host/ck_model_map"
map="${out}/MODEL.MAP"
loader='\EFI\AIENOS\aienos-ck.efi'
label="AIENOS C kernel (one-time)"
recov_entry="0004"
recov_label="AIENOSRECOV"
hold_s=120
secure_boot_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${AIENOS_STAGE_OUT:-${HOME}/workspace/evidence-out/L6C/staging}/${stamp}"

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

[[ -f "${model}" ]] || stop "model file not found: ${model}"
model_dev="$(findmnt -no SOURCE -T "${model}" 2>/dev/null || true)"
model_disk="/dev/$(lsblk -no PKNAME "${model_dev}" 2>/dev/null | head -1)"
echo "model:         ${model} on ${model_dev:-?} (disk ${model_disk})"
[[ "${model_disk}" == "${disk}" ]] || stop "the model's filesystem is not a plain partition of ${disk} (got '${model_dev}' on '${model_disk}'): the firmware reads raw LBAs"
echo "model attrs:   $(lsattr "${model}" 2>/dev/null | cut -d' ' -f1 || echo '?')"

esp_dev="$(findmnt -no SOURCE "${esp}" 2>/dev/null || true)"
esp_opts="$(findmnt -no OPTIONS "${esp}" 2>/dev/null || true)"
[[ -n "${esp_dev}" ]] || stop "the ESP is not mounted at ${esp}"
esp_disk="/dev/$(lsblk -no PKNAME "${esp_dev}" 2>/dev/null | head -1)"
esp_part="$(cat "/sys/class/block/$(basename "${esp_dev:-none}")/partition" 2>/dev/null || true)"
echo "esp:           ${esp_dev:-?} partition ${esp_part:-?} of ${esp_disk} (${esp_opts%%,*})"
[[ "${esp_disk}" == "${disk}" ]] || stop "the ESP is not on ${disk} (MODEL.MAP is read from the boot volume, the model from ${disk})"
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
run env CARGO_TARGET_DIR="${repo_root}/target/infer-kernel" cargo build -q --release \
    --target aarch64-unknown-none --manifest-path crates/aienos-infer-kernel/Cargo.toml
run make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" \
    CK_INFER_LIB="${lib}" CK_FB_HOLD_S="${hold_s}"
run make -s -C native/kernel OUT="${out}" model-map
if [[ "${mode}" == apply ]]; then
    grep -aqF "screen: gop " "${image}" || { echo "STOP: the image has no screen console"; exit 1; }
    if grep -aqF "TEST-ONLY stale handoff" "${image}"; then echo "STOP: TEST-only stale handoff image"; exit 1; fi
    digest="$(sha256sum "${image}" | cut -d' ' -f1)"
    echo "image sha256:  ${digest}"
else
    digest="(computed after the build)"
fi

# ---- 2. freeze the model's blocks, then 3. map and check ----
run sudo chattr +i "${model}"
run sudo "${map_tool}" make "${map}" --file "${model}" --disk "${disk}" --fiemap --part-start auto
run sudo chown "$(id -u):$(id -g)" "${map}"
run sudo "${map_tool}" check "${map}" --disk "${disk}"
run "${map_tool}" show "${map}"
if [[ "${mode}" == apply ]]; then
    "${map_tool}" show "${map}" | grep -q "${pinned_sha}" \
        || { echo "STOP: MODEL.MAP does not declare the pinned model hash ${pinned_sha}"; exit 1; }
fi

# ---- 4. pre-boot capture (BootNext still absent) ----
run mkdir -p "${evidence_dir}"
run sudo scripts/verify_native_rollback.sh --capture-pre "${evidence_dir}/pre_boot_capture.json"

# ---- 5. ESP scratch directory \EFI\AIENOS ----
record="${evidence_dir}/STAGED-CK.TXT"
if [[ "${mode}" == apply ]]; then
    cat >"${record}" <<EOF
aienos_commit: ${commit}
image: C kernel infer image (core-only + aienos-infer-kernel), CK_FB_HOLD_S=${hold_s}
image_sha256: ${digest}
model: ${model}
model_sha256_pinned: ${pinned_sha}
model_map_sha256: $(sha256sum "${map}" | cut -d' ' -f1)
staged_by: ${AIEN_AGENT_ID:-${USER:-unknown}}
staged_at_utc: ${stamp}
boot_current_before: ${current_before}
boot_order_before: ${order_before}
recovery_entry: Boot${recov_entry} ${recov_label}
linux_kernel_before: $(uname -r)
EOF
else
    echo "+ (write ${record}: commit, image and map digests, prior boot state)"
fi
run sudo install -D -m 0644 "${image}" "${esp}/EFI/AIENOS/aienos-ck.efi"
run sudo install -D -m 0644 "${map}" "${esp}/EFI/AIENOS/MODEL.MAP"

# ---- 6. one-time boot entry ----
entry="${existing}"
if [[ -z "${entry}" ]]; then
    run sudo efibootmgr --quiet --create-only --disk "${disk}" --part "${esp_part}" \
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
run sudo install -m 0644 "${record}" "${esp}/EFI/AIENOS/STAGED-CK.TXT"
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
echo "After the return to Linux: sudo scripts/verify_native_rollback.sh --capture-post, then sudo chattr -i ${model}."
