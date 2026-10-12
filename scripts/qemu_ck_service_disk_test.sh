#!/usr/bin/env bash
# SERVICE_DISK gate for the AIENOS C kernel (native v1 P06 / gate N3,
# aienos#34): rows 200-211 of native/kernel/GATES.md "SERVICE_DISK". C-only.
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# The production service image with resident CPU inference, exactly as built
# for the machine (make full CK_SERVICE=1 CK_HARDWARE_STAGING=1
# CK_OWNER_PUBKEYS= CK_MACHINE_ID= CK_INFER_LIB=, CK_FB_HOLD_S=120), staged by
# scripts/stage_one_time_boot_ck_service.sh onto ONE emulated NVMe disk that
# holds the ESP (image + MODEL.MAP), the model bytes (three out-of-order
# extents) and the all-zero AIENOS partition for the sealed Store. No fw_cfg
# model, no CK_TEST_* flag, no test-keys image: the owner files (a fresh
# Ed25519 public key, a random machine id and Store uuid) and the 32-byte
# recovery secrets are generated for this run and never stored.
#
#   bash scripts/qemu_ck_service_disk_test.sh               the whole gate (~30-45 min TCG)
#   bash scripts/qemu_ck_service_disk_test.sh --build-only  rows 200-201 only (make refusals
#                                                           and the accepted line, no QEMU,
#                                                           no Rust target needed)
#
#   row 200  build refusals: each `make` line must FAIL with its message:
#            CK_INFER_LIB + CK_HARDWARE_STAGING without CK_SERVICE (the one-shot
#            probe); + CK_SERVICE_TEST_KEYS; + CK_TEST_FWCFG_ARTIFACTS; + CK_RUST_LIBS;
#            + CK_QEMU_UNSAFE_DMA; + CK_CONSOLE_SESSION; + CK_TEST_STORE_CRASH;
#            + CK_TEST_CONTINUITY; staging without owner files
#   row 201  the supported line is accepted by make (parse, make -n)
#   row 202  the built image (twice, equal digests, by the staging script) carries
#            the resident session and the boot-disk source and no fw_cfg code,
#            fw_cfg symbol, TEST Store marker or TEST-ONLY banner; the QEMU
#            inference images keep their TEST-ONLY fw_cfg announcement
#   row 203  staging --dry-run against the scratch image: every write printed with
#            its sha256, "nothing touched", the image byte-identical (cmp);
#            --apply then changes it (cmp differs: the check is not vacuous) and
#            writes exactly the digests the dry run announced
#   row 204  boot 1 (blank Store): the stub reads MODEL.MAP from the ESP and the
#            model by firmware Block I/O, the kernel recomputes the pinned
#            sha256, `infer: resident open`, no fw_cfg line; the Store stage
#            refuses the production key source (LOCKED, owner provisioned at
#            build time); `unlock <secret>` formats the production Store with
#            the recovery keyslot (genesis) and continuity provisions with
#            source=operator and the owner root key
#   row 205  boot 1: `prompt What is the capital of France?` -> golden reply ids
#            -> `approve` commits it; `remember prefer short notes` -> record 1;
#            `facts` lists it; evidence counters; stop order closes the session
#            (every frame returned) and the Store; QEMU exit 0; M1 checks
#   row 206  boot 2 = cold restart of QEMU on the SAME disk image file: a wrong
#            secret is refused, the right one opens the Store (no reformat),
#            continuity RESUMES the same agent, `recall` returns the approved
#            reply and `facts` the fact from the disk (neither retyped), QEMU
#            exit 0, M1 checks
#   row 207  secret hygiene: neither secret's hex in any serial log; no TEST
#            banner or TEST machine id line in any boot
#   row 208  negative control A: the same image with MODEL.MAP deleted and the
#            model OFFERED on fw_cfg: `model_map: absent`, `infer: ingest REFUSED
#            (no boot-disk model`, no fw_cfg ingest; after unlock `prompt` is
#            refused ("no inference unit"), evidence inference=none
#   row 209  negative control B: MODEL.MAP with a corrupted declared sha256: the
#            stub reads the bytes, the kernel refuses to decode (`sha256
#            mismatch`), no resident session, prompt refused
#   row 210  limits (declared): QEMU only; the Spark console receive path, the
#            AIENOS partition on the Spark NVMe and the owner key ceremony are
#            separate items; int8 stays off
# Final line: AIENOS_CK_SERVICE_DISK: PASS|FAIL|NOT_RUN. No Python.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
final_tag="AIENOS_CK_SERVICE_DISK"
build_only=0
case "${1:-}" in
    "") ;;
    --build-only) build_only=1 ;;
    *) echo "usage: $0 [--build-only]" >&2; exit 2 ;;
esac

fail=0
ok() { echo "ROW $1 PASS  $2"; }
bad() { echo "ROW $1 FAIL  $2"; fail=1; }
cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
top="$(mktemp -d)"
qemu_pid=""
drain_pid=""
locked=0
cleanup() {
    [[ -z "${qemu_pid}" ]] || kill "${qemu_pid}" 2>/dev/null || true
    [[ -z "${drain_pid}" ]] || kill "${drain_pid}" 2>/dev/null || true
    exec 4>&- 2>/dev/null || true
    rm -rf "${top}"
    [[ "${locked}" == 0 ]] || gh_lock_release
}
trap cleanup EXIT
trap 'echo "${final_tag}: FAIL (script stopped at line ${LINENO})"' ERR

# --- rows 200-201: build refusals and the accepted line (make -n: parse only) ---
fix="${repo_root}/native/kernel/tests/fixtures/owner"
own_fx="${fix}/TEST-FIXTURE-owner-pubkeys.txt"
mach_fx="${fix}/TEST-FIXTURE-machine-id.txt"
lib_any="${top}/libaienos_infer_kernel.a" # make -n never reads it
prod=(full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own_fx}" CK_MACHINE_ID="${mach_fx}" CK_INFER_LIB="${lib_any}")
refused() { # label, expected message, make args...
    local label="$1" want="$2" msg st; shift 2
    set +e; msg="$(make -s -n -C native/kernel OUT="${top}/refuse" "$@" 2>&1)"; st=$?; set -e
    if [[ "${st}" != 0 ]] && grep -qF -- "${want}" <<<"${msg}"; then ok 200 "refused: ${label}"
    else bad 200 "NOT refused (status ${st}): ${label}: $(tail -c 200 <<<"${msg}")"; fi
}
refused "inference + staging without CK_SERVICE (one-shot probe)" \
    "CK_INFER_LIB with CK_HARDWARE_STAGING needs CK_SERVICE=1" \
    full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own_fx}" CK_MACHINE_ID="${mach_fx}" CK_INFER_LIB="${lib_any}"
refused "core probe image + staging" "CK_INFER_LIB with CK_HARDWARE_STAGING needs CK_SERVICE=1" \
    CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own_fx}" CK_MACHINE_ID="${mach_fx}" CK_INFER_LIB="${lib_any}"
refused "+ CK_SERVICE_TEST_KEYS" "CK_SERVICE_TEST_KEYS (TEST keys) cannot be combined with CK_HARDWARE_STAGING" \
    "${prod[@]}" CK_SERVICE_TEST_KEYS=1
refused "+ CK_TEST_FWCFG_ARTIFACTS (fw_cfg test source)" \
    "CK_TEST_FWCFG_ARTIFACTS (QEMU fw_cfg test source) cannot be combined with CK_HARDWARE_STAGING" \
    "${prod[@]}" CK_TEST_FWCFG_ARTIFACTS=1
refused "+ CK_RUST_LIBS" "CK_RUST_LIBS (FP probe, QEMU gate only) cannot be combined with CK_HARDWARE_STAGING" \
    "${prod[@]}" CK_RUST_LIBS="${top}/libfpu.a"
refused "+ CK_QEMU_UNSAFE_DMA" "CK_QEMU_UNSAFE_DMA (unconfined DMA, QEMU debug only) cannot be combined with CK_HARDWARE_STAGING" \
    "${prod[@]}" CK_QEMU_UNSAFE_DMA=1
refused "+ CK_CONSOLE_SESSION" "CK_CONSOLE_SESSION (QEMU test console session) cannot be combined with CK_HARDWARE_STAGING" \
    "${prod[@]}" CK_CONSOLE_SESSION=1
refused "+ CK_TEST_STORE_CRASH" "CK_SERVICE cannot be combined with a CK_TEST_* flag" \
    "${prod[@]}" CK_TEST_STORE_CRASH=1
refused "+ CK_TEST_CONTINUITY" "CK_SERVICE cannot be combined with a CK_TEST_* flag" \
    "${prod[@]}" CK_TEST_CONTINUITY=1
refused "staging without owner files" "CK_HARDWARE_STAGING refuses the TEST Store keys and TEST machine id" \
    full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_INFER_LIB="${lib_any}"
set +e; msg="$(make -s -n -C native/kernel OUT="${top}/accept" "${prod[@]}" 2>&1)"; st=$?; set -e
if [[ "${st}" == 0 ]] && grep -qF -- "-DCK_INFER_DISK_ONLY=1" <<<"${msg}" && grep -qF -- "-DCK_INFER_RESIDENT=1" <<<"${msg}"; then
    ok 201 "accepted: make full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS CK_MACHINE_ID CK_INFER_LIB (-DCK_INFER_DISK_ONLY=1 -DCK_INFER_RESIDENT=1)"
else
    bad 201 "the supported line was not accepted with the disk-only flags (status ${st}): $(grep -m1 -i error <<<"${msg}" || true)"
fi
set +e; msg="$(make -s -n -C native/kernel OUT="${top}/accept2" full CK_SERVICE=1 CK_SERVICE_TEST_KEYS=1 CK_INFER_LIB="${lib_any}" 2>&1)"; st=$?; set -e
if [[ "${st}" == 0 ]] && ! grep -qF -- "-DCK_INFER_DISK_ONLY" <<<"${msg}"; then ok 201 "QEMU test-keys inference image unchanged (accepted, keeps the fw_cfg source)"
else bad 201 "QEMU test-keys inference image changed (status ${st})"; fi

if [[ "${build_only}" == 1 ]]; then
    if [[ "${fail}" == 0 ]]; then echo "${final_tag}_BUILD: PASS (make only; nothing booted)"; exit 0; fi
    echo "${final_tag}_BUILD: FAIL"; exit 1
fi

# --- prerequisites (NOT_RUN, never a silent pass) ---
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
model="${AIENOS_MODEL:-${HOME}/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf}"
notrun=""
command -v qemu-system-aarch64 >/dev/null || notrun="qemu-system-aarch64 missing"
[[ -n "${notrun}" || ( -r "${code_fd}" && -r "${vars_fd}" ) ]] || notrun="AAVMF missing"
[[ -n "${notrun}" || -r "${model}" ]] || notrun="model file ${model} missing"
for t in cargo openssl mkfs.vfat mcopy mmd mdel; do [[ -n "${notrun}" ]] || command -v "${t}" >/dev/null || notrun="${t} missing"; done
if [[ -z "${notrun}" ]] && { ! rustc --print target-list 2>/dev/null | grep -qx aarch64-unknown-none \
   || ! [[ -d "$(rustc --print sysroot)/lib/rustlib/aarch64-unknown-none/lib" ]]; }; then
    notrun="Rust target aarch64-unknown-none not installed"
fi
if [[ -n "${notrun}" ]]; then echo "NOT_RUN  ${notrun}"; echo "${final_tag}: NOT_RUN (${notrun})"; exit 2; fi

. "${repo_root}/scripts/lib_gate_hold.sh"
if ! gh_quiet_check; then echo "NOT_RUN  ${gh_why}"; echo "${final_tag}: NOT_RUN (quiet flag held)"; exit 3; fi
if ! gh_lock_take qemu_ck_service_disk_test "${AIENOS_GATE_MINUTES:-120}"; then echo "NOT_RUN  ${gh_why}"; echo "${final_tag}: NOT_RUN (QEMU gate lock held)"; exit 3; fi
locked=1
source "${repo_root}/scripts/lib_ck_m1_checks.sh"

# --- generated owner files and recovery secrets (this run only) ---
own="${top}/owner"
mkdir -p "${own}"
openssl genpkey -algorithm ed25519 -out "${own}/k.pem" 2>/dev/null
pk="$(openssl pkey -in "${own}/k.pem" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')"
rm -f "${own}/k.pem" # the private half is never kept: nothing in this gate signs
rnd() { od -An -tx1 -N "$1" /dev/urandom | tr -d ' \n'; }
printf '# owner file generated by scripts/qemu_ck_service_disk_test.sh for one QEMU run (private half discarded)\nowner_root_ed25519 %s\n' "${pk}" >"${own}/owner-pubkeys.txt"
printf '# machine file generated by scripts/qemu_ck_service_disk_test.sh for one QEMU run\nmachine_id %s\nstore_uuid %s\n' "$(rnd 32)" "$(rnd 16)" >"${own}/machine-id.txt"
secret_ok="$(rnd 32)"
secret_bad="$(rnd 32)"
[[ "${secret_ok}" != "${secret_bad}" && ${#secret_ok} == 64 ]] || { echo "${final_tag}: FAIL (secret generation)"; exit 1; }

# --- scratch disk: ESP + model (3 out-of-order extents) + AIENOS partition ---
make -s -C native/kernel OUT="${top}/host" gpt-image model-map >/dev/null
img="${top}/disk.img"
model_bytes="$(stat -c %s "${model}")"
esp_mib=64 store_mib=64
total_mib=$(( (model_bytes + 1048575) / 1048576 + esp_mib + store_mib + 16 ))
gpt_out="$("${top}/host/host/ck_gpt_image" create "${img}" 512 "${total_mib}" esp-model-aienos "${esp_mib}" "${model}" "${store_mib}")"
esp_first="$(sed -nE '1s/.* esp_first_lba=([0-9]+).*/\1/p' <<<"${gpt_out}")"
extents="$(sed -nE '1s/.* model_extents=([0-9:,]+).*/\1/p' <<<"${gpt_out}")"
[[ -n "${esp_first}" && -n "${extents}" ]] || { echo "ck_gpt_image esp-model-aienos gave no geometry"; echo "${final_tag}: FAIL"; exit 1; }
"${top}/host/host/ck_gpt_image" find "${img}" 512 | grep -q '^aienos first_lba=' || { echo "kernel GPT parser found no AIENOS partition"; echo "${final_tag}: FAIL"; exit 1; }
mkfs.vfat -F 32 -s 1 -S 512 --offset "${esp_first}" "${img}" $(( esp_mib * 1024 )) >/dev/null 2>&1
echo "disk: ${img} ${total_mib} MiB, ESP at LBA ${esp_first}, model extents ${extents}, AIENOS ${store_mib} MiB"

# --- rows 202-203: staging dry run (cmp) then apply ---
stage=(env AIENOS_OWNER_PUBKEYS="${own}/owner-pubkeys.txt" AIENOS_MACHINE_ID="${own}/machine-id.txt" AIENOS_MODEL="${model}"
       bash scripts/stage_one_time_boot_ck_service.sh)
dirty=()
[[ -z "$(git status --porcelain)" ]] || dirty=(--allow-dirty)
cp --sparse=always "${img}" "${top}/disk.before"
set +e
"${stage[@]}" --dry-run --target-image "${img}" --extents "${extents}" "${dirty[@]}" >"${top}/dry.txt" 2>&1; st=$?
set -e
if [[ "${st}" == 0 ]] && grep -q '^Dry run: nothing touched. Pre-flight clean' "${top}/dry.txt"; then ok 203 "dry run completed, pre-flight clean"; else bad 203 "dry run status ${st}: $(tail -3 "${top}/dry.txt" | tr '\n' ' ')"; fi
n_writes="$(grep -cE '^write ESP:/EFI/(AIENOS|BOOT)/[A-Za-z0-9._-]+ bytes=[0-9]+ sha256=[0-9a-f]{64}$' "${top}/dry.txt" || true)"
if [[ "${n_writes}" == 4 ]]; then ok 203 "dry run printed 4 writes, each with bytes and sha256"; else bad 203 "dry run printed ${n_writes} well-formed writes (want 4)"; fi
if cmp -s "${img}" "${top}/disk.before"; then ok 203 "dry run left the scratch image byte-identical (cmp)"; else bad 203 "dry run CHANGED the scratch image"; fi
grep -E '^(image sha256|write )' "${top}/dry.txt" | sed 's/^/  dry: /'
set +e
"${stage[@]}" --apply --target-image "${img}" --extents "${extents}" "${dirty[@]}" >"${top}/apply.txt" 2>&1; st=$?
set -e
if [[ "${st}" == 0 ]] && grep -q '^staged:        4 files written to the ESP' "${top}/apply.txt"; then ok 203 "apply staged 4 files and read them back equal"; else bad 203 "apply status ${st}: $(tail -3 "${top}/apply.txt" | tr '\n' ' ')"; fi
if cmp -s "${img}" "${top}/disk.before"; then bad 203 "apply left the image unchanged (the cmp check would be vacuous)"; else ok 203 "apply changed the image (the dry-run cmp is not vacuous)"; fi
rm -f "${top}/disk.before"
for f in aienos-ck-service.efi MODEL.MAP; do
    d="$(grep -E "^write ESP:/EFI/AIENOS/${f} " "${top}/dry.txt" | sed -nE 's/.* sha256=([0-9a-f]{64})$/\1/p')"
    a="$(grep -E "^write ESP:/EFI/AIENOS/${f} " "${top}/apply.txt" | sed -nE 's/.* sha256=([0-9a-f]{64})$/\1/p')"
    if [[ -n "${d}" && "${d}" == "${a}" ]]; then ok 203 "${f}: apply wrote the digest the dry run announced (${d:0:16})"; else bad 203 "${f}: dry ${d:-none} vs apply ${a:-none}"; fi
done
mt="${img}@@$(( esp_first * 512 ))"
staged_efi="${top}/staged.efi"
mcopy -n -i "${mt}" ::/EFI/BOOT/BOOTAA64.EFI "${staged_efi}"
if grep -q "build A and build B equal" "${top}/apply.txt"; then ok 202 "built twice in clean folders, equal digests"; else bad 202 "no reproducibility line from the staging script"; fi
if grep -aqF "infer: resident open" "${staged_efi}" && grep -aqF "infer_source_mode: boot-disk model" "${staged_efi}"; then ok 202 "staged image carries the resident session and the boot-disk source"; else bad 202 "staged image lacks the resident session or the boot-disk source"; fi
s="$(grep -aoE "fw_cfg|opt/aienos/model|QEMU0002|TEST-ONLY|TEST Store|TEST machine id|AIEN-TEST-BOOT01" "${staged_efi}" | sort -u | tr '\n' ' ' || true)"
if [[ -z "${s}" ]]; then ok 202 "staged image carries no fw_cfg, TEST-ONLY or TEST Store marker"; else bad 202 "staged image carries: ${s}"; fi
staged_elf="${repo_root}/target/native-kernel-service-staging/full-service-hardware-staging/aienos-ck.elf"
y="$("${cross}nm" "${staged_elf}" | grep -E ' (fw_select|fw_read|fw_find|fw_dma_read|fwcfg_from_dsdt|ck_store_test_keys|ck_store_test_uuid)$' | tr '\n' ' ' || true)"
if [[ -z "${y}" ]]; then ok 202 "no fw_cfg or TEST key symbol in the ELF"; else bad 202 "symbols present: ${y}"; fi

# --- QEMU: one NVMe disk (ESP + model + Store), PL011 serial from outside ---
ser_line() { printf '%s\r' "$1" >&4; sleep 1.2; }
serial_has() { tr -d '\r' 2>/dev/null <"${work}/serial.log" | grep -qE -- "$1"; }
wait_for() { local deadline=$(( $(date +%s) + $1 )); shift
    while (( $(date +%s) < deadline )); do for p in "$@"; do serial_has "${p}" && return 0; done
        kill -0 "${qemu_pid}" 2>/dev/null || break; sleep 1; done
    for p in "$@"; do serial_has "${p}" && return 0; done; return 1; }
ser_wait() { wait_for "${2:-300}" "$1" '^report_kind: (panic|fault|final)' || true; }
has() { grep -qE -- "$1" "${work}/serial.txt"; }
rcheck() { if has "$3"; then ok "$1" "$2"; else bad "$1" "$2"; fi; }
rabsent() { if has "$3"; then bad "$1" "$2 (present)"; else ok "$1" "$2"; fi; }
line_of() { { grep -nE -m1 -- "$1" "${work}/serial.txt" || true; } | cut -d: -f1; }
before() { local a b; a="$(line_of "$3")"; b="$(line_of "$4")"
    if [[ -n "${a}" && -n "${b}" && "${a}" -lt "${b}" ]]; then ok "$1" "$2 (lines ${a} < ${b})"; else bad "$1" "$2 (lines ${a:-none} ${b:-none})"; fi; }
boot_to="${AIENOS_QEMU_INFER_TIMEOUT:-2700}"
cp "${vars_fd}" "${top}/vars.fd" # one machine: the same NVRAM file for both main boots
boot() { # name disk-image driver [extra qemu args...]
    local name="$1" disk="$2" drv="$3"; shift 3
    work="${top}/${name}"
    mkdir -p "${work}"
    mkfifo "${work}/ser.in" "${work}/ser.out"
    : >"${work}/serial.log"
    local vars="${BOOT_VARS:-${top}/vars.fd}"
    timeout "${boot_to}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m 4096 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${vars}" \
        -drive if=none,id=nvme0,format=raw,file="${disk}" \
        -device nvme,drive=nvme0,serial=aienos-service-disk \
        -device ramfb -display none -nic none -monitor none \
        -chardev pipe,id=ser,path="${work}/ser" -serial chardev:ser -no-reboot "$@" 2>"${work}/qemu.err" &
    qemu_pid=$!
    cat "${work}/ser.out" >>"${work}/serial.log" &
    drain_pid=$!
    exec 4>"${work}/ser.in"
    local t0; t0=$(date +%s)
    if wait_for "${boot_to}" '^lifecycle: ready state=' '^report_kind: (panic|fault|final)' && serial_has '^lifecycle: ready state='; then
        sleep 1
        "${drv}"
    fi
    wait_for 600 '^report_kind: (panic|fault|final)' || true
    set +e; wait "${qemu_pid}"; qemu_status=$?; set -e
    qemu_pid=""
    exec 4>&- 2>/dev/null || true
    wait "${drain_pid}" 2>/dev/null || true
    drain_pid=""
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_service_disk_${name}.log"
    echo "== boot $(basename "${work}"): qemu exit ${qemu_status} after $(( $(date +%s) - t0 )) s"
}
m1() {
    failed=0
    ck_m1_checks >"${work}/m1.txt" 2>&1 || true
    if [[ "${failed}" == 0 ]]; then ok "$1" "M1 checks"; else bad "$1" "M1 checks: $(grep -E "^FAIL" "${work}/m1.txt" | head -3 | tr "\n" " ")"; fi
}
infer_wait="${AIENOS_QEMU_INFER_WAIT:-1800}"
drive_main1() {
    ser_line status
    ser_line "unlock ${secret_ok}"; ser_wait '^(lifecycle: unlock ok|lifecycle: REFUSED verb=unlock)'
    ser_line status
    ser_line "prompt What is the capital of France?"
    wait_for "${infer_wait}" '^lifecycle: (reply pending|generation cancelled|REFUSED verb=prompt)' '^report_kind: (panic|fault|final)' || true
    ser_line approve; ser_wait '^lifecycle: (approve committed|REFUSED verb=approve)'
    ser_line "remember prefer short notes"; ser_wait '^lifecycle: (remembered|REFUSED verb=remember)'
    ser_line facts; ser_wait '^lifecycle: (facts records=|facts none|REFUSED verb=facts)'
    ser_line evidence
    ser_line shutdown
}
drive_main2() {
    ser_line "unlock ${secret_bad}"; ser_wait '^(lifecycle: unlock ok|lifecycle: REFUSED verb=unlock)'
    ser_line "unlock ${secret_ok}"; ser_wait '^(lifecycle: unlock ok|lifecycle: REFUSED verb=unlock)'
    ser_line status
    ser_line recall; ser_wait '^lifecycle: recall'
    ser_line facts; ser_wait '^lifecycle: (facts records=|facts none|REFUSED verb=facts)'
    ser_line evidence
    ser_line shutdown
}
drive_neg() {
    ser_line "unlock ${secret_ok}"; ser_wait '^(lifecycle: unlock ok|lifecycle: REFUSED verb=unlock)'
    ser_line "prompt What is the capital of France?"; ser_wait '^lifecycle: (REFUSED verb=prompt|reply pending|generating)'
    ser_line evidence
    ser_line shutdown
}
re_open='^infer: resident open rc=0 tensors=147 vocab=128256 layers=16 kv_capacity=64 max_new=16 max_prompt_bytes=256 heap_reserve_kib=64 heap_used_kib=[0-9]+ open_us=[0-9]+$'
re_recall='^lifecycle: recall gen=4 kind=reply id=[0-9a-f]{8} bytes=[0-9]+ text="aienos\.reply\.v1.prompt: What is the capital of France\?.reply: The capital of France is Paris\.'
frames_kept() {
    local l b a; l="$(grep -E -m1 '^infer: unloaded ' "${work}/serial.txt" || true)"
    b="$(sed -nE 's/.* frames_free_before=([0-9]+).*/\1/p' <<<"${l}")"; a="$(sed -nE 's/.* frames_free_after=([0-9]+).*/\1/p' <<<"${l}")"
    if [[ -n "${b}" && "${b}" == "${a}" ]] && grep -qE '^infer: unloaded .* rc=0,0$' <<<"${l}"; then ok "$1" "$2 (${b} = ${a})"; else bad "$1" "$2 (before=${b:-none} after=${a:-none})"; fi; }
disk_model_rows() { # row: the model came from the disk, by the map, with the pinned digest
    rcheck "$1" "stub read MODEL.MAP from the ESP" "^model_map: ok len=${model_bytes} extents=3 sector=512 disk=[0-9a-f]{32}\$"
    rcheck "$1" "boot-disk source declared" '^infer_source_mode: boot-disk model \(MODEL\.MAP read by the UEFI stub'
    rcheck "$1" "model handed over from the disk (3 extents)" "^infer: disk base=0x[0-9a-f]+ size=${model_bytes} extents=3 read_us=[0-9]+ block_size=512\$"
    rcheck "$1" "kernel recomputed the pinned sha256" '^infer: sha256=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1 '
    rabsent "$1" "no fw_cfg ingest line" '^(infer_source_mode: TEST-ONLY|infer: fw_cfg|infer: ingest bytes=)'
}

# --- negative control A: no MODEL.MAP, the model offered on fw_cfg (row 208) ---
neg_img="${top}/neg.img"
cp --sparse=always "${img}" "${neg_img}"
mdel -i "${neg_img}@@$(( esp_first * 512 ))" ::/EFI/AIENOS/MODEL.MAP
cp "${vars_fd}" "${top}/vars.neg"
BOOT_VARS="${top}/vars.neg" boot neg-nomap "${neg_img}" drive_neg -fw_cfg "name=opt/aienos/model,file=${model}"
rcheck 208 "stub found no MODEL.MAP" '^model_map: absent'
rcheck 208 "kernel refused: no boot-disk model, no other source" '^infer: ingest REFUSED \(no boot-disk model: MODEL\.MAP absent or refused by the stub; this image has no other model source\)$'
rabsent 208 "the fw_cfg model was NOT ingested although QEMU offered it" '^(infer_source_mode|infer: fw_cfg|infer: ingest bytes=|infer: resident open)'
rcheck 208 "unlock ok (the Store path is unaffected)" '^lifecycle: unlock ok state=ready$'
rcheck 208 "prompt refused: no inference unit" '^lifecycle: REFUSED verb=prompt state=ready reason="no inference unit in this image"$'
rcheck 208 "evidence inference=none" '^lifecycle: evidence .* inference=none '
rabsent 208 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 208 "QEMU exit 0"; else bad 208 "QEMU exit ${qemu_status}"; fi

# --- negative control B: MODEL.MAP with a corrupted declared sha256 (row 209) ---
cp --sparse=always "${img}" "${neg_img}"
"${top}/host/host/ck_model_map" make "${top}/BAD.MAP" --file "${model}" --disk "${neg_img}" \
    $(IFS=,; for e in ${extents}; do printf -- '--extent %s ' "${e}"; done) --corrupt-sha >/dev/null
mcopy -o -i "${neg_img}@@$(( esp_first * 512 ))" "${top}/BAD.MAP" ::/EFI/AIENOS/MODEL.MAP
cp "${vars_fd}" "${top}/vars.neg"
BOOT_VARS="${top}/vars.neg" boot neg-badsha "${neg_img}" drive_neg
rcheck 209 "stub accepted the map and read the bytes" "^model_map: ok len=${model_bytes} extents=3 "
rcheck 209 "kernel refused to decode: sha256 mismatch" '^infer: sha256 mismatch declared=[0-9a-f]{64}$'
rabsent 209 "no resident session" '^infer: resident open'
rcheck 209 "prompt refused: no inference unit" '^lifecycle: REFUSED verb=prompt state=ready reason="no inference unit in this image"$'
rabsent 209 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 209 "QEMU exit 0"; else bad 209 "QEMU exit ${qemu_status}"; fi
rm -f "${neg_img}"

# --- boot 1: the staged disk, blank Store (rows 204-205) ---
boot main-1 "${img}" drive_main1
disk_model_rows 204
rcheck 204 "resident session open" "${re_open}"
before 204 "resident open < lifecycle ready" '^infer: resident open rc=0' '^lifecycle: ready state=locked'
rcheck 204 "owner provisioned at build time (public only)" '^owner: provisioned at build time \(public only\): owner_root_ed25519 sha256=[0-9a-f]{16} store_uuid='
rcheck 204 "Store stage refused the production key source: LOCKED" '^store: REFUSED proof=keyed step="production Store key source" rc=-?[0-9]+ '
rcheck 204 "lifecycle came up locked" '^lifecycle: ready state=locked store=locked'
rcheck 204 "blank AIENOS partition formatted as a production store" '^store: blank disk \(all-zero anchor \+ Store head\): formatted production store$'
rcheck 204 "recovery keyslot genesis" '^store: key source=recovery-keyslot genesis=1 '
rcheck 204 "unlock ok, genesis, generation 2 boot 1" '^store: unlock ok source=recovery-keyslot slot=1 genesis=1 generation=2 boot_count=1$'
rcheck 204 "continuity genesis from the owner root key (operator source)" '^continuity: genesis source=operator provenance=owner-root-pk\+store-uuid '
rcheck 204 "identity PROVISIONED" '^continuity: PROVISIONED agent=[0-9a-f]{64} incarnation=1 '
rcheck 204 "lifecycle unlocked to ready" '^lifecycle: unlock ok state=ready$'
rcheck 205 "golden reply ids" '^lifecycle: reply ids=791 6864 315 9822 374 12366 13 128009 tokens=8 prompt_ids=17 steps=25 us=[0-9]+$'
rcheck 205 "reply is the pending proposal" '^lifecycle: reply pending state=serve proposed="reply: The capital of France is Paris\.\??" \(approve \| deny \| cancel\)$'
rcheck 205 "approve committed the reply at generation 4" '^lifecycle: approve committed gen=4 id=[0-9a-f]{8} state=ready$'
rcheck 205 "remembered as record 1 at generation 6" '^lifecycle: remembered id=1 t=1 store_gen=6 bytes=18 text="prefer short notes"$'
rcheck 205 "facts lists it, chain verified" '^lifecycle: facts records=1 shown=1 journal_bytes=192 chain=ok$'
rcheck 205 "evidence counters" '^lifecycle: evidence requests=[0-9]+ refused=0 invalid=0 tasks=0 approved=1 denied=0 cancelled=0 overlong=0 last_commit_gen=4 last_id=[0-9a-f]{8} prompts=1 replies=1 gen_cancelled=0 gen_failed=0 recalls=0 inference=resident remembers=1 facts=1 cortex=open records=1$'
rcheck 205 "resident close" '^infer: resident close rc=0 '
frames_kept 205 "unload returned every frame"
before 205 "unload < stop order" '^infer: unloaded ' '^lifecycle: stop order store=closed'
rcheck 205 "stop order closed the Store" '^lifecycle: stop order store=closed nvme=released state=stop requests=[0-9]+$'
rabsent 205 "operator input accepted (no console-input refusal)" '^lifecycle: REFUSED console input'
rabsent 205 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 205 "QEMU exit 0"; else bad 205 "QEMU exit ${qemu_status}"; fi
m1 205
agent="$(grep -oE '^continuity: PROVISIONED agent=[0-9a-f]{64}' "${work}/serial.txt" | head -1 | sed 's/.*agent=//')"
[[ -n "${agent}" ]] || agent="NO_AGENT"

# --- boot 2: cold restart, SAME disk image file (row 206) ---
boot main-2 "${img}" drive_main2
disk_model_rows 206
rcheck 206 "resident session open again" "${re_open}"
rcheck 206 "wrong secret refused by the keyslot tag, still locked" '^store: unlock REFUSED proof=keyed step="recovery secret rejected \(K_vol unwrap tag failed\); disk not opened" rc=-?[0-9]+ \([A-Za-z_]+\); still LOCKED, disk not reformatted$'
rabsent 206 "not reformatted" '^store: blank disk'
rcheck 206 "Store opened at generation 6 (no genesis)" '^store: opened generation=6 boot_count=1 prev_commit=[0-9a-f]+ anchor=[a-z_-]+$'
rcheck 206 "unlock ok, no genesis" '^store: unlock ok source=recovery-keyslot slot=1 genesis=0 generation=7 boot_count=2$'
rcheck 206 "continuity RESUMED the same agent" "^continuity: RESUMED agent=${agent} incarnation=2 "
rabsent 206 "no second genesis" '^continuity: (PROVISIONED|genesis)'
rcheck 206 "recall returns the approved reply from the disk" "${re_recall}"
rcheck 206 "facts answers the fact from the disk" '^lifecycle: fact id=1 t=1 store_gen=6 text="prefer short notes"$'
rabsent 206 "neither the prompt nor the fact retyped" '^> (prompt|remember) '
rcheck 206 "evidence: one refused unlock, one recall, facts, nothing generated" '^lifecycle: evidence requests=[0-9]+ refused=1 invalid=0 tasks=0 approved=0 denied=0 cancelled=0 overlong=0 last_commit_gen=0 last_id=00000000 prompts=0 replies=0 gen_cancelled=0 gen_failed=0 recalls=1 inference=resident remembers=0 facts=1 cortex=open records=1$'
frames_kept 206 "unload returned every frame"
rcheck 206 "stop order closed the Store" '^lifecycle: stop order store=closed nvme=released state=stop requests=[0-9]+$'
rabsent 206 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 206 "QEMU exit 0"; else bad 206 "QEMU exit ${qemu_status}"; fi
m1 206

# --- row 207: secret hygiene, no TEST markers, across every boot ---
for b in neg-nomap neg-badsha main-1 main-2; do
    work="${top}/${b}"
    rabsent 207 "${b}: right secret hex never in the serial log" "${secret_ok}"
    rabsent 207 "${b}: wrong secret hex never in the serial log" "${secret_bad}"
    rabsent 207 "${b}: no TEST banner, TEST machine id or TEST Store line" '(TEST-ONLY|TEST machine id|formatted TEST store)'
done

if [[ "${fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for b in neg-nomap neg-badsha main-1 main-2; do echo "---- ${b} serial (selected lines) ----"
        grep -E '^(model_map|infer|lifecycle|store|continuity|owner|report_kind|> )' "${top}/${b}/serial.txt" | head -60 || true; done
fi
echo "ROW 210 LIMIT  QEMU only (hardware NOT_RUN); Spark console input, the AIENOS partition on the Spark NVMe and the owner key ceremony are separate items; int8 off"
if [[ "${fail}" == 0 ]]; then echo "${final_tag}: PASS (QEMU only; hardware NOT_RUN)"; exit 0; fi
echo "${final_tag}: FAIL"; exit 1
