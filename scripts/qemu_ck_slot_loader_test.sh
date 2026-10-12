#!/usr/bin/env bash
# qemu_ck_slot_loader_test.sh -- QEMU gate for SLOTLDR.EFI, the AIENOS signed
# A/B image slot loader (native/boot/slot_loader.c; native v1 plan P11 cut 2a,
# gate N7; docs/NATIVE_IMAGE_SLOTS.md section 7). QEMU is an emulator: a PASS
# here qualifies nothing physical (hardware NOT_RUN).
#
# Setup: the boot disk is a FAT directory (fat:rw:, as scripts/qemu_ck_boot_test.sh)
# whose EFI/BOOT/BOOTAA64.EFI is SLOTLDR.EFI built with CK_TEST_SLOT_KEY=1
# (RFC 8032 TEST 1). A second virtio disk holds a GPT with one slots partition
# (ck_gpt_image layout "slots"); ck_slot_tool slots-image writes the control
# record and the two slots into it. The slot payloads are the unchanged core
# image built twice, with AIENOS_COMMIT slotA-<commit> and slotB-<commit>, so
# the serial line "aienos_commit: slotX-" names the slot that really ran. The
# core image prints its report and resets (PSCI); with -no-reboot QEMU exits 0.
# Every row also asks the host tool (ck_slot_tool select, same slot_select.c)
# for its decision over the same files and requires the loader to agree.
#
# Rows (each check prints PASS or FAIL with the serial line it needed):
#  1 fresh media, control active=A, A valid, B empty: boots A (active).
#  2 B staged (tries 3): boots 1-3 boot B (candidate_try) with tries 2, 1, 0
#    committed before the jump and read back from the disk by the tool;
#    boot 4 boots A (candidate_exhausted_active) and writes nothing.
#  3 B manifest flipped in its signed bytes: "signature does not verify", boots A.
#  4 B signed by RFC 8032 TEST 2 (not trusted): "signer_id names no trusted key", boots A.
#  5 B image flipped, manifest intact: "image SHA-512 mismatch", boots A.
#  6 torn control write (the staging record's body half written, no commit
#    header): the previous record is recovered, boots A (active), B not tried.
#  7 both slots invalid: "recovery_required (A: ...; B: ...)", the loader returns
#    to the firmware, no kernel runs (QEMU is stopped by the row timeout).
#  8 B validly signed but below the generation floor: refused, boots A.
#  P11 cut 2b (the service kernel promotes / abandons; svc/slot_service.c), one NVMe
#  disk with the Store and slots partitions, "shutdown" sent once the lifecycle is ready:
#  9 healthy candidate B: the kernel promotes it (active=B, floor 2); next boot
#    is a steady boot of B, nothing written.
# 10 candidate that never becomes healthy (Store LOCKED): last try spent, not
#    promoted; next boot falls back to A and the kernel abandons B (flags 0x01).
# 11 negative control: the service image started without SLOTLDR finds no boot
#    record and writes nothing.
#
# Output: one PASS/FAIL line per check, then
#     AIENOS_CK_SLOT_LOADER: PASS|FAIL|NOT_RUN [(...)]
# NOT_RUN (exit 3) while the machine quiet flag is held (read only) or another
# gate holds the QEMU gate lock (scripts/lib_gate_hold.sh, aienos#278); exit 2
# when QEMU or AAVMF is missing. No Python.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
tag="AIENOS_CK_SLOT_LOADER"
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${tag}: NOT_RUN (no qemu-system-aarch64)"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${tag}: NOT_RUN (no AAVMF)"; exit 2; }
cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo 0000000000000000000000000000000000000000)"
out="${repo_root}/target/native-kernel-slot-loader"
mk() { make -s -C native/kernel CROSS="${cross}" "$@" >/dev/null; }
mk OUT="${out}" AIENOS_COMMIT="${commit}" CK_TEST_SLOT_KEY=1 slot-loader slot-tool gpt-image
mk OUT="${out}/payload-a" AIENOS_COMMIT="slotA-${commit}"
mk OUT="${out}/payload-b" AIENOS_COMMIT="slotB-${commit}"
# P11 cut 2b service payloads (rows 9-11): TEST-key service image as A and B, the plain
# service image (no production keys: stays LOCKED) as L.
mk OUT="${out}/svc-a" AIENOS_COMMIT="slotA-${commit}" CK_SERVICE=1 CK_SERVICE_TEST_KEYS=1 full
mk OUT="${out}/svc-b" AIENOS_COMMIT="slotB-${commit}" CK_SERVICE=1 CK_SERVICE_TEST_KEYS=1 full
mk OUT="${out}/svc-l" AIENOS_COMMIT="slotL-${commit}" CK_SERVICE=1 full
tool="${out}/host/ck_slot_tool"
gpt="${out}/host/ck_gpt_image"
img_a="${out}/payload-a/BOOTAA64.EFI"
img_b="${out}/payload-b/BOOTAA64.EFI"
svc_a="${out}/svc-a/full-service-testkeys/BOOTAA64.EFI"
svc_b="${out}/svc-b/full-service-testkeys/BOOTAA64.EFI"
svc_l="${out}/svc-l/full-service/BOOTAA64.EFI"

. "${repo_root}/scripts/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take qemu_ck_slot_loader_test "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "${tag}: NOT_RUN (${gh_why})"
    exit 3
fi
work="$(mktemp -d)"
cleanup() {
    [[ -z "${qpid:-}" ]] || kill "${qpid}" 2>/dev/null || true
    rm -rf "${work}"
    gh_lock_release
}
trap cleanup EXIT

fails=0
checks=0
boots=0
qemu_secs=0
ok() { checks=$((checks + 1)); echo "PASS  $*"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); echo "FAIL  $*"; }

# ---- fixtures: ESP, slots disk, manifests, control records -----------------------
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${out}/SLOTLDR.EFI" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
disk="${work}/slots.img"
gline="$("${gpt}" create "${disk}" 512 48 slots)"
first="$(sed -n 's/.*slots_first_lba=\([0-9]*\).*/\1/p' <<<"${gline}")"
last="$(sed -n 's/.*slots_last_lba=\([0-9]*\).*/\1/p' <<<"${gline}")"
[[ -n "${first}" && -n "${last}" ]] || { echo "FAIL  ck_gpt_image gave no slots geometry: ${gline}"; echo "${tag}: FAIL"; exit 1; }
cp "${disk}" "${work}/blank.img"

mm() { # name image generation [policy] [--test2]
    "${tool}" make-manifest --image "$2" --generation "$3" --policy-generation "${4:-0}" --commit "${commit}" \
        --provenance "slot loader gate" --timestamp 1760000000 --out "${work}/$1.u" >/dev/null
    "${tool}" sign-test "${work}/$1.u" --out "${work}/$1" ${5:-} >/dev/null
}
mm A1 "${img_a}" 1
mm A2 "${img_a}" 2 2
mm B1 "${img_b}" 1
mm B2 "${img_b}" 2
mm B2k2 "${img_b}" 2 0 --test2
"${tool}" control-init --active 0 --out "${work}/c_init_a" >/dev/null
"${tool}" stage "${work}/c_init_a" --slot 1 --generation 2 --out "${work}/c_stage_b" >/dev/null
"${tool}" control-init --active 1 --out "${work}/c_f0" >/dev/null
"${tool}" stage "${work}/c_f0" --slot 0 --generation 2 --out "${work}/c_f1" >/dev/null
"${tool}" promote "${work}/c_f1" --slot 0 --generation 2 --policy-generation 2 --out "${work}/c_f2" >/dev/null
"${tool}" stage "${work}/c_f2" --slot 1 --generation 3 --out "${work}/c_floor" >/dev/null

geo=""
slots() { # slots-image args...: fresh disk, then write
    cp "${work}/blank.img" "${disk}"
    geo="$("${tool}" slots-image --disk "${disk}" --bs 512 --first "${first}" --last "${last}" "$@" | grep "^slots:" || true)"
    [[ -n "${geo}" ]] || bad "slots-image refused: $*"
}
geo_val() { sed -n "s/.* $1=\([0-9]*\).*/\1/p" <<<"${geo}"; }
flip() { # file byte-offset: xor 0x01
    local b
    b="$(od -An -tu1 -j "$2" -N1 "$1" | tr -d ' ')"
    # shellcheck disable=SC2059
    printf "$(printf '\\%03o' $((b ^ 1)))" | dd of="$1" bs=1 seek="$2" conv=notrunc status=none
}
region() { # extract the 4-unit control region to $1
    dd if="${disk}" of="$1" bs=512 skip="${first}" count=32 status=none
}
ctl_now() { # the control record as the tool recovers it from the disk
    region "${work}/region.now"
    "${tool}" control-recover --region "${work}/region.now" | grep -E '^(control|seq)' | tr '\n' ' ' || true
}

# ---- one boot ------------------------------------------------------------------
boot() { # name timeout-seconds
    local name="$1" to="$2" t0 rc
    cp "${vars_fd}" "${work}/vars.fd"
    t0="$(date +%s)"
    set +e
    timeout "${to}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=slots,format=raw,file="${disk}" \
        -device virtio-blk-pci,drive=slots \
        -device ramfb -display none -nic none \
        -serial file:"${work}/${name}.raw" -no-reboot
    rc=$?
    set -e
    boots=$((boots + 1))
    qemu_secs=$((qemu_secs + $(date +%s) - t0))
    tr -d '\r' <"${work}/${name}.raw" >"${work}/${name}.log"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/${name}.log" "${AIENOS_LOG_DIR}/qemu_ck_slot_loader_${name}.log"
    echo "boot ${name}: qemu exit ${rc} after $(( $(date +%s) - t0 )) s"
    last_rc="${rc}"
    last_log="${work}/${name}.log"
}
has() { # row label fixed-text
    if grep -qF -- "$3" "${last_log}"; then ok "row $1: $2 [$3]"; else bad "row $1: $2 (no serial line containing: $3)"; show=1; fi
}
lacks() { # row label fixed-text
    if grep -qF -- "$3" "${last_log}"; then bad "row $1: $2 (serial has: $3)"; show=1; else ok "row $1: $2 [no \"$3\"]"; fi
}
ran() { # row slot(A|B): the payload of that slot ran to its kernel and reset cleanly
    has "$1" "slot $2 payload ran" "aienos_commit: slot$2-${commit}"
    has "$1" "kernel entered" "kernel: alive"
    if [[ "${last_rc}" == 0 ]]; then ok "row $1: QEMU exit 0 (PSCI reset)"; else bad "row $1: QEMU exit ${last_rc}"; show=1; fi
}
ctl_is() { # row label expected-substring
    local c
    c="$(ctl_now)"
    if grep -qF -- "$3" <<<"${c}"; then ok "row $1: $2 [disk: ${c}]"; else bad "row $1: $2 (disk control: ${c}; want ${3})"; fi
}
tool_agrees() { # row control-file a-spec b-spec expected-decision
    local cap d
    cap="$(geo_val image_cap)"
    d="$("${tool}" select --control "$2" --a "$3" --b "$4" --test-key --cap "${cap}" | grep '^decision:' || true)"
    if grep -qF -- "$5" <<<"${d}"; then ok "row $1: host tool decides the same [${d}]"; else bad "row $1: host tool decision ${d}; want ${5}"; fi
}
row_end() { # row
    if [[ "${show:-0}" == 1 ]]; then echo "---- serial (last 60 lines) of row $1 ----"; tail -n 60 "${last_log}"; fi
    show=0
}

A1="${work}/A1,${img_a}"
A2="${work}/A2,${img_a}"
B1="${work}/B1,${img_b}"
B2="${work}/B2,${img_b}"
B2k2="${work}/B2k2,${img_b}"

# ---- row 1: fresh media, A valid, B empty --------------------------------------
slots --a "${A1}" --control "${work}/c_init_a"
boot r1 180
has 1 "TEST key announced" "slot_loader: TEST-ONLY key"
has 1 "slots partition found" "slot_loader: slots partition first_lba=${first} last_lba=${last}"
has 1 "empty slot B refused" "slot_loader: slot B refused (bad magic)"
has 1 "decision" "slot_loader: boot=A reason=active gen=1 tries=0 floor=0"
has 1 "chained stub sees the boot volume (LoadImage device path)" "model_map: absent (no \\EFI\\AIENOS\\MODEL.MAP on the boot volume)"
ran 1 A
ctl_is 1 "control untouched" "seq=1 control: active=0 candidate=none tries=0"
tool_agrees 1 "${work}/c_init_a" "${A1}" none "boot_slot=A reason=active loader_write=0"
row_end 1

# ---- row 2: candidate B, three tries, then rollback to A -----------------------
slots --a "${A1}" --b "${B2}" --control "${work}/c_stage_b"
tool_agrees 2 "${work}/c_stage_b" "${A1}" "${B2}" "boot_slot=B reason=candidate_try loader_write=1"
for t in 2 1 0; do
    boot "r2-tries${t}" 180
    has 2 "candidate try committed before the jump" "slot_loader: control committed seq=$((4 - t)) tries=${t}"
    has 2 "decision" "slot_loader: boot=B reason=candidate_try gen=2 tries=${t} floor=0"
    ran 2 B
    ctl_is 2 "tries on disk after the boot" "seq=$((4 - t)) control: active=0 candidate=1 tries=${t} "
    row_end 2
done
region "${work}/c_exhausted.region"
"${tool}" control-recover --region "${work}/c_exhausted.region" --out "${work}/c_exhausted" >/dev/null
boot r2-exhausted 180
has 2 "decision after the third try" "slot_loader: boot=A reason=candidate_exhausted_active gen=1 tries=0 floor=0"
lacks 2 "nothing written when exhausted" "slot_loader: control committed"
ran 2 A
ctl_is 2 "control unchanged (candidate left for the kernel to abandon, cut 2b)" "seq=4 control: active=0 candidate=1 tries=0 "
tool_agrees 2 "${work}/c_exhausted" "${A1}" "${B2}" "boot_slot=A reason=candidate_exhausted_active loader_write=0"
row_end 2

# ---- row 3: B manifest flipped inside the signed bytes --------------------------
slots --a "${A1}" --b "${B2}" --control "${work}/c_stage_b"
flip "${disk}" $(( $(geo_val b_off) + 321 ))   # timestamp byte 1: still well formed, signature broken
boot r3 180
has 3 "B refused" "slot_loader: slot B refused (signature does not verify)"
has 3 "decision" "slot_loader: boot=A reason=candidate_invalid_active gen=1 tries=3 floor=0"
lacks 3 "no try consumed" "slot_loader: control committed"
ran 3 A
ctl_is 3 "control untouched" "seq=1 control: active=0 candidate=1 tries=3 "
row_end 3

# ---- row 4: B signed by an untrusted key (RFC 8032 TEST 2) ----------------------
slots --a "${A1}" --b "${B2k2}" --control "${work}/c_stage_b"
boot r4 180
has 4 "B refused" "slot_loader: slot B refused (signer_id names no trusted key)"
has 4 "decision" "slot_loader: boot=A reason=candidate_invalid_active gen=1 tries=3 floor=0"
ran 4 A
tool_agrees 4 "${work}/c_stage_b" "${A1}" "${B2k2}" "boot_slot=A reason=candidate_invalid_active loader_write=0"
row_end 4

# ---- row 5: B image tampered, manifest intact ------------------------------------
slots --a "${A1}" --b "${B2}" --control "${work}/c_stage_b"
flip "${disk}" $(( $(geo_val b_off) + 4096 + 1000 ))
boot r5 180
has 5 "B refused" "slot_loader: slot B refused (image SHA-512 mismatch)"
has 5 "decision" "slot_loader: boot=A reason=candidate_invalid_active gen=1 tries=3 floor=0"
ran 5 A
row_end 5

# ---- row 6: torn control write ---------------------------------------------------
slots --a "${A1}" --b "${B2}" --control "${work}/c_init_a"
region "${work}/r6.old"
cp "${work}/r6.old" "${work}/r6.full"
"${tool}" control-commit --region "${work}/r6.full" --record "${work}/c_stage_b" >/dev/null
if cmp -s -n 4096 "${work}/r6.old" "${work}/r6.full"; then torn_off=8192; else torn_off=0; fi
# Power cut after half of the new body: 2048 bytes of it land, its commit header never does.
dd if="${work}/r6.full" of="${disk}" bs=1 skip="${torn_off}" seek=$(( first * 512 + torn_off )) count=2048 \
    conv=notrunc status=none
ctl_is 6 "host tool recovers the previous record" "seq=1 control: active=0 candidate=none tries=0"
tool_agrees 6 "${work}/c_init_a" "${A1}" "${B2}" "boot_slot=A reason=active loader_write=0"
# Control: had the staging record landed whole, the decision would have been a try of B.
d6="$("${tool}" select --control "${work}/c_stage_b" --a "${A1}" --b "${B2}" --test-key --cap "$(geo_val image_cap)" | grep "^decision:" || true)"
if grep -qF "boot_slot=B reason=candidate_try" <<<"${d6}"; then ok "row 6: control: the unfinished record would have tried B [${d6}]"; else bad "row 6: control decision ${d6}; want a try of B"; fi
boot r6 180
has 6 "previous record recovered" "slot_loader: control seq=1 active=A candidate=- tries=0"
has 6 "decision per the old record" "slot_loader: boot=A reason=active gen=1 tries=0 floor=0"
lacks 6 "B not tried" "reason=candidate_try"
ran 6 A
row_end 6

# ---- row 7: both slots invalid -> recovery required --------------------------------
slots --a "${A1}" --b "${B2k2}" --control "${work}/c_init_a"
flip "${disk}" $(( $(geo_val a_off) + 4096 + 1000 ))
boot r7 "${AIENOS_SLOT_RECOVERY_TIMEOUT:-60}"
has 7 "recovery required, both reasons" "slot_loader: recovery_required (A: image SHA-512 mismatch; B: signer_id names no trusted key)"
lacks 7 "no slot started" "slot_loader: starting slot"
lacks 7 "no kernel ran" "kernel: alive"
lacks 7 "no payload ran" "aienos_commit: slot"
ctl_is 7 "control untouched" "seq=1 control: active=0 candidate=none tries=0"
row_end 7

# ---- row 8: B below the generation floor ---------------------------------------------
slots --a "${A2}" --b "${B1}" --control "${work}/c_floor"
boot r8 180
has 8 "B valid but below the floor" "slot_loader: slot B valid gen=1 policy=0"
has 8 "floor named" "(below the generation floor)"
has 8 "decision" "slot_loader: boot=A reason=candidate_invalid_active gen=2 tries=3 floor=2"
lacks 8 "no try consumed" "slot_loader: control committed"
ran 8 A
tool_agrees 8 "${work}/c_floor" "${A2}" "${B1}" "boot_slot=A reason=candidate_invalid_active loader_write=0"
row_end 8


# ==== P11 cut 2b: the service kernel promotes / abandons (svc/slot_service.c) =====
# One NVMe disk (ck_gpt_image layout aienos-slots: AIENOS Store partition + slots
# partition), the ESP as above. Payloads: the TEST-key service image built twice
# (slotA- / slotB- commits: Store formats, continuity provisions, lifecycle READY =
# healthy) and the plain service image as slot L (no production keys in a QEMU
# build: the Store stays LOCKED = never healthy). The operator line "shutdown" is
# sent over the PL011 pipe once the lifecycle is ready; the image then resets.
gline="$("${gpt}" create "${work}/svc.img" 512 64 aienos-slots)"
first="$(sed -n 's/.*slots_first_lba=\([0-9]*\).*/\1/p' <<<"${gline}")"
last="$(sed -n 's/.*slots_last_lba=\([0-9]*\).*/\1/p' <<<"${gline}")"
[[ -n "${first}" && -n "${last}" ]] || { bad "ck_gpt_image aienos-slots gave no slots geometry: ${gline}"; first=0; last=0; }
disk="${work}/svc.img"
cp "${disk}" "${work}/blank.img"
mm SA1 "${svc_a}" 1
mm SB2 "${svc_b}" 2 2
mm SL2 "${svc_l}" 2 2
SA1="${work}/SA1,${svc_a}"
SB2="${work}/SB2,${svc_b}"
SL2="${work}/SL2,${svc_l}"
# c_stage_b with tries 1: the loader's own decision applied twice (select --out).
slots --a "${SA1}" --b "${SL2}" --control "${work}/c_stage_b"
cap_s="$(geo_val image_cap)"
"${tool}" select --control "${work}/c_stage_b" --a "${SA1}" --b "${SL2}" --test-key --cap "${cap_s}" --out "${work}/c_t2" >/dev/null || true
"${tool}" select --control "${work}/c_t2" --a "${SA1}" --b "${SL2}" --test-key --cap "${cap_s}" --out "${work}/c_t1" >/dev/null || true

qpid=""
sboot() { # name timeout-seconds [efi]: ESP with SLOTLDR (or efi), NVMe ${disk}; "shutdown" once ready
    local name="$1" to="$2" efi="${3:-${out}/SLOTLDR.EFI}" w t0 rc dpid
    w="${work}/s-${name}"
    mkdir -p "${w}/esp/EFI/BOOT" "${w}/esp/EFI/AIENOS"
    touch "${w}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "${efi}" "${w}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${w}/vars.fd"
    mkfifo "${w}/ser.in" "${w}/ser.out"
    : >"${w}/serial.raw"
    t0="$(date +%s)"
    timeout "${to}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${w}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${w}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${disk}" \
        -device nvme,drive=nvme0,serial=aienos-slot-test \
        -device ramfb -display none -nic none -monitor none \
        -chardev pipe,id=ser,path="${w}/ser" -serial chardev:ser -no-reboot 2>"${w}/qemu.err" &
    qpid=$!
    cat "${w}/ser.out" >>"${w}/serial.raw" &
    dpid=$!
    exec 4>"${w}/ser.in"
    while kill -0 "${qpid}" 2>/dev/null; do
        if tr -d '\r' <"${w}/serial.raw" | grep -qE '^lifecycle: ready state=|^report_kind: (panic|fault|final)'; then break; fi
        sleep 1
    done
    if tr -d '\r' <"${w}/serial.raw" | grep -q '^lifecycle: ready state='; then
        sleep 1
        printf 'shutdown\r' >&4 || true
    fi
    set +e
    wait "${qpid}"
    rc=$?
    set -e
    qpid=""
    exec 4>&- 2>/dev/null || true
    wait "${dpid}" 2>/dev/null || true
    boots=$((boots + 1))
    qemu_secs=$((qemu_secs + $(date +%s) - t0))
    tr -d '\r' <"${w}/serial.raw" >"${w}/serial.log"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${w}/serial.log" "${AIENOS_LOG_DIR}/qemu_ck_slot_loader_${name}.log"
    echo "boot ${name}: qemu exit ${rc} after $(( $(date +%s) - t0 )) s"
    last_rc="${rc}"
    last_log="${w}/serial.log"
}
before() { # row label first-text second-text: both present, first earlier
    local a b
    a="$({ grep -nF -m1 -- "$3" "${last_log}" || true; } | cut -d: -f1)"
    b="$({ grep -nF -m1 -- "$4" "${last_log}" || true; } | cut -d: -f1)"
    if [[ -n "${a}" && -n "${b}" && "${a}" -lt "${b}" ]]; then ok "row $1: $2 (lines ${a} < ${b})"; else bad "row $1: $2 (lines ${a:-none} ${b:-none})"; show=1; fi
}
svc_to="${AIENOS_SLOT_SERVICE_TIMEOUT:-420}"

# ---- row 9: candidate B healthy -> promoted by the kernel; next boot steady ------
slots --a "${SA1}" --b "${SB2}" --control "${work}/c_stage_b"
sboot r9-try "${svc_to}"
has 9 "candidate try committed by the loader" "slot_loader: control committed seq=2 tries=2"
has 9 "boot record handed over" "slot_loader: boot record handed over type=0x80000a1e slot=B reason=candidate_try seq=2"
has 9 "kernel read the record" "slot: booted slot B reason=candidate_try generation=2 tries=2 control_seq=2"
has 9 "kernel promoted B after health" "slot: promoted slot B to active generation=2 floor=2 seq=3"
has 9 "health: lifecycle READY" "lifecycle: ready state=ready store=open"
before 9 "continuity committed before the promotion" "continuity: PROVISIONED" "slot: promoted slot B"
ran 9 B
ctl_is 9 "control on disk: B active, floor raised to its policy generation" "seq=3 control: active=1 candidate=none tries=0 flags=0x00 floor=2 last_good=2"
sboot r9-steady "${svc_to}"
has 9 "next boot: B is the active slot" "slot_loader: boot=B reason=active gen=2 tries=0 floor=2"
lacks 9 "next boot: loader writes nothing" "slot_loader: control committed"
has 9 "next boot: kernel writes nothing" "slot: nothing to write (nothing to write) active=B"
ran 9 B
ctl_is 9 "control unchanged by the steady boot" "seq=3 control: active=1 candidate=none tries=0"
row_end 9

# ---- row 10: candidate never healthy -> not promoted; exhausted -> abandoned; A stays
slots --a "${SA1}" --b "${SL2}" --control "${work}/c_t1"
ctl_is 10 "fixture: candidate B with one try left" "seq=1 control: active=0 candidate=1 tries=1"
sboot r10-locked "${svc_to}"
has 10 "last try committed" "slot_loader: control committed seq=2 tries=0"
has 10 "candidate L booted" "aienos_commit: slotL-${commit}"
has 10 "Store stays locked (no keys)" "lifecycle: ready state=locked"
has 10 "kernel waits for health" "slot: candidate B waiting for health (tries left 0): not promoted yet"
has 10 "stop order says not promoted" "slot: candidate B NOT promoted this boot"
lacks 10 "no promotion" "slot: promoted"
ctl_is 10 "control: tries spent, nothing promoted" "seq=2 control: active=0 candidate=1 tries=0 flags=0x00"
sboot r10-exhausted "${svc_to}"
has 10 "loader falls back to A" "slot_loader: boot=A reason=candidate_exhausted_active gen=1 tries=0"
has 10 "kernel read the record" "slot: booted slot A reason=candidate_exhausted_active"
has 10 "kernel abandoned the candidate" "slot: candidate abandoned (marked failed) active=A stays seq=3"
ran 10 A
ctl_is 10 "control: candidate cleared, failed flag, A still active" "seq=3 control: active=0 candidate=none tries=0 flags=0x01"
region "${work}/c10.region"
"${tool}" control-recover --region "${work}/c10.region" --out "${work}/c10" >/dev/null || true
tool_agrees 10 "${work}/c10" "${SA1}" "${SL2}" "boot_slot=A reason=active loader_write=0"
row_end 10

# ---- row 11: negative control: no boot record (service started without SLOTLDR) ---
slots --a "${SA1}" --b "${SB2}" --control "${work}/c_stage_b"
sboot r11-direct "${svc_to}" "${svc_a}"
has 11 "kernel says it has no record" "slot: no boot record (not started by SLOTLDR.EFI): slot service idle, nothing written"
has 11 "healthy service" "lifecycle: ready state=ready store=open"
lacks 11 "no promotion without the loader's record" "slot: promoted"
ctl_is 11 "control untouched" "seq=1 control: active=0 candidate=1 tries=3"
row_end 11

gh_lock_release
echo "slot loader gate: ${boots} boots, ${checks} checks, ${fails} failures, QEMU ${qemu_secs} s (commit ${commit:0:12}; QEMU only, hardware NOT_RUN)"
if [[ "${fails}" == 0 ]]; then
    echo "${tag}: PASS (11 rows, ${boots} boots, ${checks} checks; QEMU, not hardware)"
else
    echo "${tag}: FAIL (${fails} of ${checks} checks)"
    exit 1
fi
