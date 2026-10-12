#!/usr/bin/env bash
# Stage the C kernel PRODUCTION SERVICE image with resident CPU inference
# (native v1 P06 / gate N3, aienos#34; docs/ATTENDED_SESSION_N1.md item B2)
# plus its MODEL.MAP for exactly one attended boot. Same shape as
# scripts/stage_one_time_boot_ck_b7b.sh (build twice, compare, stage once,
# BootNext once); the image is the one supported hardware inference build
# (docs/NATIVE_PACKAGE.md, "Service image with inference"):
#
#   make full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=<file>
#        CK_MACHINE_ID=<file> CK_INFER_LIB=<libaienos_infer_kernel.a>
#        CK_FB_HOLD_S=120
#
# Its only model source is the boot disk (MODEL.MAP read by the UEFI stub
# through the firmware's Block I/O); the QEMU fw_cfg ingest is compiled out.
#
#   scripts/stage_one_time_boot_ck_service.sh --dry-run [TARGET]
#   scripts/stage_one_time_boot_ck_service.sh --apply   [TARGET]
#
# Exactly one of --dry-run / --apply is required; there is no default mode.
# TARGET (optional): --target-image IMG --extents LBA:COUNT[,LBA:COUNT...]
#   [--allow-dirty]. Stage a GPT disk IMAGE instead of this machine (desk and
#   QEMU use: scripts/qemu_ck_service_disk_test.sh). IMG must already hold an
#   ESP (FAT, EFI System type) and the model bytes at the listed extents (file
#   order, 512-byte LBAs; ck_gpt_image esp-model-aienos prints them). The
#   files go into the image's ESP with mtools; the image's removable-media
#   path \EFI\BOOT\BOOTAA64.EFI stands in for BootNext. No sudo, no
#   efibootmgr, no chattr. --allow-dirty is accepted only with --target-image.
# Without TARGET it stages this machine: /dev/nvme0n1, the ESP at /boot/efi,
# BootNext (needs sudo; operator only).
#
# Owner files (the hardware staging image refuses the TEST Store keys and the
# TEST machine id; native/kernel/README.md, "Owner provisioning"):
#   AIENOS_OWNER_PUBKEYS=<owner public keys file>  AIENOS_MACHINE_ID=<machine id file>
# The labelled TEST-FIXTURE files under native/kernel/tests/fixtures/owner/
# are refused. AIENOS_MODEL overrides the model path (pinned sha256 below).
#
# --dry-run prints every write --apply would do, in order, each with its
# destination, size and SHA-256, and performs none of them: nothing is written
# to the target disk or image, the ESP, the model file (no chattr) or the
# firmware boot variables, and no sudo is called. To know those digests it
# builds the image twice into its own folders under target/ (the same two
# builds --apply makes) and makes MODEL.MAP in a temporary folder; with
# --target-image both are exact, on this machine the MODEL.MAP digest needs a
# raw read of /dev/nvme0n1 (root) and is printed as "at --apply". The QEMU
# gate checks that a dry run leaves a scratch image byte-identical (cmp).
#
# --apply, in order:
#   1. builds the service image TWICE in two clean folders with CK_FB_HOLD_S=120
#      and STOPs unless the digests are equal; checks it carries the resident
#      session, the boot-disk model source and no fw_cfg / TEST marker;
#   2. (machine) sudo chattr +i on the model, FIRST, so its blocks cannot move;
#   3. ck_model_map make + check (reads every extent back by LBA and
#      recomputes the SHA-256: the bytes the firmware will read); STOP unless
#      the map declares the pinned model hash;
#   4. (machine) sudo scripts/verify_native_rollback.sh --capture-pre;
#   5. writes the image, MODEL.MAP and a STAGED-CK-SERVICE.TXT record to
#      \EFI\AIENOS on the ESP (image mode: also \EFI\BOOT\BOOTAA64.EFI);
#   6. (machine) creates a boot entry WITHOUT adding it to BootOrder, checks
#      Boot0004 AIENOSRECOV is still there, sets BootNext once.
# It never reboots. The attended session (docs/ATTENDED_SESSION_N1.md) then
# types `unlock <64-hex recovery secret>`, `prompt ...`, `approve`, `remember
# ...`, `shutdown`, and after the cold restart `unlock`, `recall`, `facts`.
# Hardware: NOT_RUN. No Python.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

usage() { echo "usage: $0 --dry-run|--apply [--target-image IMG --extents LBA:COUNT[,...] [--allow-dirty]]" >&2; exit 2; }
mode=""
case "${1:-}" in
    --dry-run) mode=dry ;;
    --apply) mode=apply ;;
    *) usage ;;
esac
shift
target_img="" extents="" allow_dirty=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-image) [[ $# -ge 2 ]] || usage; target_img="$2"; shift 2 ;;
        --extents) [[ $# -ge 2 ]] || usage; extents="$2"; shift 2 ;;
        --allow-dirty) allow_dirty=1; shift ;;
        *) usage ;;
    esac
done
if [[ -z "${target_img}" ]]; then
    [[ -z "${extents}" && "${allow_dirty}" == 0 ]] || { echo "--extents and --allow-dirty need --target-image" >&2; exit 2; }
else
    [[ -n "${extents}" ]] || { echo "--target-image needs --extents" >&2; exit 2; }
    [[ "${extents}" =~ ^[0-9]+:[0-9]+(,[0-9]+:[0-9]+)*$ ]] || { echo "--extents must be LBA:COUNT[,LBA:COUNT...]" >&2; exit 2; }
fi

disk="/dev/nvme0n1"
esp="/boot/efi"
owner_pubkeys="${AIENOS_OWNER_PUBKEYS:-}"
machine_id="${AIENOS_MACHINE_ID:-}"
model="${AIENOS_MODEL:-${HOME}/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf}"
pinned_sha=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1
out="${repo_root}/target/native-kernel-service-staging"
out_b="${out}-build-b"
image="${out}/full-service-hardware-staging/BOOTAA64.EFI"
image_b="${out_b}/full-service-hardware-staging/BOOTAA64.EFI"
lib="${repo_root}/target/infer-kernel/aarch64-unknown-none/release/libaienos_infer_kernel.a"
map_tool="${out}/host/ck_model_map"
loader='\EFI\AIENOS\aienos-ck-service.efi'
label="AIENOS C kernel service (one-time)"
recov_entry="0004"
recov_label="AIENOSRECOV"
hold_s=120
secure_boot_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${AIENOS_STAGE_OUT:-${HOME}/workspace/evidence-out/N3/staging}/${stamp}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

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
sha() { sha256sum "$1" | cut -d' ' -f1; }
# One line per write: what, where, how many bytes, which digest.
announce() { # dest src
    printf 'write %s bytes=%s sha256=%s\n' "$1" "$(stat -c %s "$2")" "$(sha "$2")"
}

echo "mode: ${mode}${target_img:+ (target image ${target_img})}"

# ---- read-only pre-flight ----
if [[ -n "$(git status --porcelain)" ]]; then
    if [[ "${allow_dirty}" == 1 ]]; then
        echo "tree:          DIRTY, allowed (--allow-dirty, target image only: a desk or QEMU stage, never a boot)"
    else
        stop "the checkout has uncommitted changes; the boot must map to one exact commit"
    fi
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
        stop "${f} is a labelled TEST-FIXTURE file (${v}); a stage needs the operator's own file"
    else
        v="$(realpath -- "${v}")" # make -C native/kernel resolves relative paths from there
        printf -v "${f}" %s "${v}"
        echo "${f}: ${v} sha256=$(sha "${v}")"
    fi
done
[[ -f "${model}" ]] || stop "model file not found: ${model}"

esp_off="" esp_part="" current_before="" order_before="" existing=""
if [[ -n "${target_img}" ]]; then
    [[ -f "${target_img}" ]] || stop "target image not found: ${target_img}"
    command -v mcopy >/dev/null && command -v mmd >/dev/null || stop "mtools (mcopy, mmd) not installed"
    # The ESP from the image's own primary GPT (512-byte LBAs): header at LBA 1,
    # partition entries at the LBA it names; type C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
    if [[ -f "${target_img}" && "$(od -An -c -j 512 -N 8 "${target_img}" | tr -d ' ')" == "EFIPART" ]]; then
        ent_lba="$(od -An -tu8 -j $((512 + 72)) -N 8 "${target_img}" | tr -d ' ')"
        n_ent="$(od -An -tu4 -j $((512 + 80)) -N 4 "${target_img}" | tr -d ' ')"
        ent_sz="$(od -An -tu4 -j $((512 + 84)) -N 4 "${target_img}" | tr -d ' ')"
        for ((i = 0; i < n_ent && i < 128; i++)); do
            o=$((ent_lba * 512 + i * ent_sz))
            if [[ "$(od -An -tx1 -j "${o}" -N 16 "${target_img}" | tr -d ' \n')" == 28732ac11ff8d211ba4b00a0c93ec93b ]]; then
                esp_first="$(od -An -tu8 -j $((o + 32)) -N 8 "${target_img}" | tr -d ' ')"
                esp_off=$((esp_first * 512))
                esp_part=$((i + 1))
                break
            fi
        done
        [[ -n "${esp_off}" ]] || stop "the target image has no EFI System partition"
        echo "esp:           partition ${esp_part:-?} of ${target_img} at byte ${esp_off:-?} (mtools)"
    else
        stop "the target image has no primary GPT (no EFI PART at LBA 1)"
    fi
    echo "boot:          image mode: \\EFI\\BOOT\\BOOTAA64.EFI (removable-media path) stands in for BootNext; no NVRAM write"
else
    [[ "${allow_dirty}" == 0 ]] || stop "--allow-dirty is refused without --target-image"
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
fi
echo "screen hold:   ${hold_s} s before the reset (CK_FB_HOLD_S)"

if [[ ${#stops[@]} -gt 0 ]]; then
    if [[ "${mode}" == apply ]]; then
        echo "STOPPED before touching anything: ${#stops[@]} pre-flight problem(s) above."
        exit 1
    fi
    echo
    echo "Dry run: nothing touched. --apply would STOP now on ${#stops[@]} pre-flight problem(s) above."
    exit 0
fi

# ---- 1. build twice in clean folders, compare, check the image (both modes:
#         the dry run needs the digests; it writes only under target/) ----
echo
echo "build (both modes; writes only under ${repo_root}/target):"
cross=""
[[ "$(uname -m)" == aarch64 ]] || cross="aarch64-linux-gnu-"
echo "+ cargo build --release --target aarch64-unknown-none -p aienos-infer-kernel (crates/aienos-infer-kernel)"
CARGO_TARGET_DIR="${repo_root}/target/infer-kernel" cargo build -q --release --target aarch64-unknown-none \
    --manifest-path crates/aienos-infer-kernel/Cargo.toml
for o in "${out}" "${out_b}"; do
    rm -rf "${o}"
    echo "+ make full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=${owner_pubkeys} CK_MACHINE_ID=${machine_id} CK_INFER_LIB=${lib} CK_FB_HOLD_S=${hold_s} OUT=${o}"
    make -s -C native/kernel CROSS="${cross}" OUT="${o}" AIENOS_COMMIT="${commit}" full \
        CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${owner_pubkeys}" CK_MACHINE_ID="${machine_id}" \
        CK_INFER_LIB="${lib}" CK_FB_HOLD_S="${hold_s}" >"${tmp}/make.log" 2>&1 \
        || { tail -20 "${tmp}/make.log"; echo "STOP: the service image did not build"; exit 1; }
done
make -s -C native/kernel OUT="${out}" model-map >/dev/null
digest="$(sha "${image}")"
digest_b="$(sha "${image_b}")"
[[ "${digest}" == "${digest_b}" ]] \
    || { echo "STOP: the two service builds differ (${digest} vs ${digest_b}); the image is not reproducible"; exit 1; }
grep -aqF "infer: resident open" "${image}" || { echo "STOP: the image carries no resident inference session"; exit 1; }
grep -aqF "infer_source_mode: boot-disk model" "${image}" || { echo "STOP: the image has no boot-disk model source"; exit 1; }
grep -aqF "lifecycle: ready" "${image}" || { echo "STOP: the image carries no resident lifecycle"; exit 1; }
for m in "fw_cfg" "opt/aienos/model" "TEST-ONLY" "TEST Store" "TEST machine id" "AIENCONT"; do
    if grep -aqF "${m}" "${image}"; then echo "STOP: the image carries a QEMU or TEST marker (${m})"; exit 1; fi
done
echo "image sha256:  ${digest} (build A and build B equal; resident session, boot-disk model only, no fw_cfg or TEST marker)"
echo "lib sha256:    $(sha "${lib}")"

# ---- 3. MODEL.MAP (image mode: in a temporary folder, exact in both modes) ----
map="${tmp}/MODEL.MAP"
if [[ -n "${target_img}" ]]; then
    map_args=()
    IFS=, read -ra exts <<<"${extents}"
    for e in "${exts[@]}"; do map_args+=(--extent "${e}"); done
    "${map_tool}" make "${map}" --file "${model}" --disk "${target_img}" "${map_args[@]}" >/dev/null
    "${map_tool}" check "${map}" --disk "${target_img}" >/dev/null \
        || { echo "STOP: MODEL.MAP check failed against ${target_img} (the extents do not hold the model)"; exit 1; }
    "${map_tool}" show "${map}" | grep -q "${pinned_sha}" \
        || { echo "STOP: MODEL.MAP does not declare the pinned model hash ${pinned_sha}"; exit 1; }
    echo "model map:     extents ${extents} checked against ${target_img} (read back, sha256 = pinned ${pinned_sha:0:16}...)"
else
    run sudo chattr +i "${model}"
    if [[ "${mode}" == apply ]]; then
        run sudo "${map_tool}" make "${map}" --file "${model}" --disk "${disk}" --fiemap --part-start auto
        run sudo chown "$(id -u):$(id -g)" "${map}"
        run sudo "${map_tool}" check "${map}" --disk "${disk}"
        "${map_tool}" show "${map}" | grep -q "${pinned_sha}" \
            || { echo "STOP: MODEL.MAP does not declare the pinned model hash ${pinned_sha}"; exit 1; }
    else
        echo "+ sudo ${map_tool} make MODEL.MAP --file ${model} --disk ${disk} --fiemap --part-start auto"
        echo "+ sudo ${map_tool} check MODEL.MAP --disk ${disk}  (STOP unless it declares ${pinned_sha})"
    fi
fi

# ---- 4. pre-boot capture (machine only; BootNext still absent) ----
if [[ -z "${target_img}" ]]; then
    run mkdir -p "${evidence_dir}"
    run sudo scripts/verify_native_rollback.sh --capture-pre "${evidence_dir}/pre_boot_capture.json"
fi

# ---- 5. the record and the ESP writes ----
record="${tmp}/STAGED-CK-SERVICE.TXT"
map_digest="$([[ -f "${map}" ]] && sha "${map}" || echo "at --apply (needs a raw read of ${disk})")"
cat >"${record}" <<EOF
aienos_commit: ${commit}
image: C kernel production service image with resident CPU inference (make full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_INFER_LIB=..), CK_FB_HOLD_S=${hold_s}
image_sha256: ${digest}
image_sha256_build_b: ${digest_b}
infer_lib_sha256: $(sha "${lib}")
model: ${model}
model_sha256_pinned: ${pinned_sha}
model_map_sha256: ${map_digest}
owner_pubkeys_sha256: $(sha "${owner_pubkeys}")
machine_id_sha256: $(sha "${machine_id}")
target: ${target_img:-${disk} (ESP ${esp})}
staged_by: ${AIEN_AGENT_ID:-${USER:-unknown}}
staged_at_utc: ${stamp}
boot_current_before: ${current_before:-n/a (image)}
boot_order_before: ${order_before:-n/a (image)}
EOF
echo
echo "writes (--apply performs them in this order; --dry-run performs none):"
if [[ -n "${target_img}" ]]; then
    mt="${target_img}@@${esp_off}"
    echo "mkdir ESP:/EFI/AIENOS and ESP:/EFI/BOOT in ${target_img} (when absent)"
    announce "ESP:/EFI/AIENOS/aienos-ck-service.efi" "${image}"
    announce "ESP:/EFI/AIENOS/MODEL.MAP" "${map}"
    announce "ESP:/EFI/AIENOS/STAGED-CK-SERVICE.TXT" "${record}"
    announce "ESP:/EFI/BOOT/BOOTAA64.EFI" "${image}"
    if [[ "${mode}" == apply ]]; then
        mdir -i "${mt}" ::/EFI >/dev/null 2>&1 || mmd -i "${mt}" ::/EFI
        mdir -i "${mt}" ::/EFI/AIENOS >/dev/null 2>&1 || mmd -i "${mt}" ::/EFI/AIENOS
        mdir -i "${mt}" ::/EFI/BOOT >/dev/null 2>&1 || mmd -i "${mt}" ::/EFI/BOOT
        mcopy -o -i "${mt}" "${image}" ::/EFI/AIENOS/aienos-ck-service.efi
        mcopy -o -i "${mt}" "${map}" ::/EFI/AIENOS/MODEL.MAP
        mcopy -o -i "${mt}" "${record}" ::/EFI/AIENOS/STAGED-CK-SERVICE.TXT
        mcopy -o -i "${mt}" "${image}" ::/EFI/BOOT/BOOTAA64.EFI
        # Read back: every staged file equals what was announced.
        for p in "EFI/AIENOS/aienos-ck-service.efi:${image}" "EFI/AIENOS/MODEL.MAP:${map}" \
                 "EFI/AIENOS/STAGED-CK-SERVICE.TXT:${record}" "EFI/BOOT/BOOTAA64.EFI:${image}"; do
            mcopy -n -i "${mt}" "::/${p%%:*}" "${tmp}/readback"
            cmp -s "${tmp}/readback" "${p#*:}" || { echo "STOP: ${p%%:*} read back differs"; exit 1; }
            rm -f "${tmp}/readback"
        done
        echo "staged:        4 files written to the ESP of ${target_img} and read back equal"
    fi
else
    announce "${esp}/EFI/AIENOS/aienos-ck-service.efi" "${image}"
    if [[ -f "${map}" ]]; then announce "${esp}/EFI/AIENOS/MODEL.MAP" "${map}"
    else echo "write ${esp}/EFI/AIENOS/MODEL.MAP bytes=4096 sha256=(at --apply: needs a raw read of ${disk})"; fi
    announce "${esp}/EFI/AIENOS/STAGED-CK-SERVICE.TXT" "${record}"
    echo "write ${evidence_dir}/STAGED-CK-SERVICE.TXT (the same record)"
    echo "write NVRAM Boot#### '${label}' -> ${loader} (create-only, not in BootOrder) and BootNext once"
    if [[ "${mode}" == apply ]]; then
        cp "${record}" "${evidence_dir}/STAGED-CK-SERVICE.TXT"
        run sudo install -D -m 0644 "${image}" "${esp}/EFI/AIENOS/aienos-ck-service.efi"
        run sudo install -D -m 0644 "${map}" "${esp}/EFI/AIENOS/MODEL.MAP"
    fi
    # ---- 6. one-time boot entry ----
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
        echo "aienos_boot_entry: ${entry}" >>"${evidence_dir}/STAGED-CK-SERVICE.TXT"
    else
        echo "+ (only if BootOrder changed: sudo efibootmgr --quiet --bootorder ${order_before})"
        echo "+ (check Boot${recov_entry} ${recov_label} still present, else stop before BootNext)"
    fi
    run sudo install -m 0644 "${evidence_dir}/STAGED-CK-SERVICE.TXT" "${esp}/EFI/AIENOS/STAGED-CK-SERVICE.TXT"
    run sudo efibootmgr --quiet --bootnext "${entry}"
fi

echo
if [[ "${mode}" == dry ]]; then
    echo "Dry run: nothing touched. Pre-flight clean; --apply would perform the writes above."
    exit 0
fi
if [[ -n "${target_img}" ]]; then
    echo "Staged image ${target_img}: boot it with the ESP's removable path; nothing else was touched."
    exit 0
fi
cat "${evidence_dir}/STAGED-CK-SERVICE.TXT"
efibootmgr | sed -n '1,4p'
echo "Staged: the next boot runs Boot${entry} once. Nothing was rebooted."
echo "Reboot only with the operator at the machine and the ${recov_label} stick inserted."
echo "After the return to Linux: sudo scripts/verify_native_rollback.sh --capture-post, then sudo chattr -i ${model}."
