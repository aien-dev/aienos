#!/usr/bin/env bash
# M4 continuity qualification in QEMU (ADR 0016, Proposed): the same AIEN
# identity and committed memory survive cold restarts over System Store v1 on
# the native NVMe driver, and no boot path ever mints a replacement identity.
#
# Geometry: 4096-byte LBA (atomic-root qualified namespace). Every boot is a
# fresh QEMU process (cold restart); only the NVMe image persists.
#
# Emits CONTINUITY_QEMU: PASS only when every step passes. QEMU only; no
# Machine 1 claim. The continuity encodings are format version 0 (Proposed).
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
img_bytes=67108864
lba_bytes=4096
cfg_offset=$(( 32 * lba_bytes ))
store_offset=$(( 64 * lba_bytes ))
machine="virt,virtualization=on,gic-version=3,iommu=smmuv3"
target_dir="target/qemu-continuity"

echo "=== Building aienos-handoff (continuity-qual) and aienos-store-tool ==="
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
git diff --quiet HEAD 2>/dev/null || commit="${commit}-dirty"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features continuity-qual --bin aienos-handoff \
    --target-dir "${target_dir}" || { echo "build failed"; exit 2; }
cargo build --quiet --release -p aienos-store-tool || { echo "store tool build failed"; exit 2; }
tool="target/release/aienos-store-tool"

work="$(mktemp -d)"
qemu_pid=""
cleanup() { [[ -n "${qemu_pid}" ]] && kill -9 "${qemu_pid}" 2>/dev/null || true; rm -rf "${work}"; }
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${target_dir}/aarch64-unknown-uefi/release/aienos-handoff.efi" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"

image="${work}/nvme.img"
serial="${work}/serial.log"
fail=0

fresh_image() { rm -f "${image}"; truncate -s "${img_bytes}" "${image}"; }
write_cfg() { "${tool}" cfg "${image}" "${cfg_offset}" "$1" 0 >/dev/null || { echo "cfg write failed"; exit 2; }; }
digest() { sha256sum "${image}" | cut -d' ' -f1; }
pass() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

# run_qemu <marker> [kill]: one cold boot; returns when QEMU exits (or is killed).
run_qemu() {
    cp -f "${vars_fd}" "${work}/vars.fd"
    rm -f "${serial}"
    qemu-system-aarch64 \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${image}" \
        -device nvme,drive=nvme0,serial=aienos-continuity,logical_block_size=${lba_bytes},physical_block_size=${lba_bytes} \
        -display none -nic none -serial file:"${serial}" -no-reboot &
    qemu_pid=$!
    local deadline=$(( $(date +%s) + boot_timeout ))
    while (( $(date +%s) < deadline )); do
        grep -q -- "$1" "${serial}" 2>/dev/null && break
        kill -0 "${qemu_pid}" 2>/dev/null || break
        sleep 0.1
    done
    if [[ "${2:-}" == "kill" ]]; then
        kill -9 "${qemu_pid}" 2>/dev/null || true
    fi
    wait "${qemu_pid}" 2>/dev/null || true
    qemu_pid=""
}

# boot_mode <mode>: cfg + cold boot until the guest resets.
boot_mode() { write_cfg "$1"; run_qemu "AIENOS_NEVER_PRINTED_MARKER"; }

# cont <WORD>: the last "CONTINUITY: WORD ..." line of this boot (empty if none).
cont() { tr -d '\r' <"${serial}" | grep -oE "CONTINUITY: $1( .*)?$" | tail -1; }
field() { sed -nE "s/.* $1=([0-9a-f]+).*/\1/p" <<<"$2"; }

echo "=== 1. Refusals: no boot path mints an identity ==="
fresh_image
before=$(digest); boot_mode 6; after=$(digest)
if [[ -n "$(cont 'STOP \(store Unformatted\)')" && "${before}" == "${after}" ]]; then
    pass "resume on blank media stops (store Unformatted) and writes nothing"
else
    bad "resume on blank media: $(tr -d '\r' <"${serial}" | grep 'CONTINUITY:' | head -2)"
fi

fresh_image
write_cfg 1; run_qemu "STORE_CHECKPOINT_QEMU"        # formatted Store with data, no identity
grep -q "STORE_CHECKPOINT_QEMU: PASS" "${serial}" || bad "could not build a formatted, unprovisioned store"
before=$(digest); boot_mode 6; after=$(digest)
if [[ -n "$(cont UNPROVISIONED)" && "${before}" == "${after}" ]]; then
    pass "resume on a formatted but unprovisioned store stops UNPROVISIONED and writes nothing"
else
    bad "unprovisioned resume: $(tr -d '\r' <"${serial}" | grep 'CONTINUITY:' | head -2)"
fi

echo "=== 2. Provisioning happens once ==="
fresh_image
boot_mode 5
line=$(cont PROVISIONED)
agent=$(field agent "${line}")
if [[ ${#agent} == 64 && "${line}" == *"incarnation=1 sequence=1 cortex=0 branches=1 "* ]]; then
    pass "provisioned agent ${agent:0:16}... (incarnation 1, empty memory, root branch)"
else
    bad "provision: ${line:-$(tr -d '\r' <"${serial}" | grep 'CONTINUITY:' | head -2)}"
fi
provisioned_img="${work}/provisioned.img"; cp "${image}" "${provisioned_img}"

before=$(digest); boot_mode 5; after=$(digest)
if [[ -n "$(cont 'STOP \(AlreadyProvisioned\)')" && "${before}" == "${after}" ]]; then
    pass "a second provisioning request is refused and writes nothing"
else
    bad "re-provision: $(tr -d '\r' <"${serial}" | grep 'CONTINUITY:' | head -2)"
fi

cp "${image}" "${work}/keep.img"; fresh_image; boot_mode 5
other=$(field agent "$(cont PROVISIONED)")
if [[ ${#other} == 64 && "${other}" != "${agent}" ]]; then
    pass "independent provisioning draws a different identity from RNDR"
else
    bad "second fresh provisioning gave '${other}'"
fi
cp "${work}/keep.img" "${image}"

echo "=== 3. Memory and lineage survive cold restarts ==="
boot_mode 7
r=$(cont RESUMED); m=$(cont REMEMBERED)
memory=$(field memory "${m}")
if [[ "$(field agent "${r}")" == "${agent}" && "${r}" == *"incarnation=2 sequence=2 cortex=0 branches=1 "* && \
      "$(field agent "${m}")" == "${agent}" && "${m}" == *"incarnation=2 sequence=3 cortex=1 branches=2 "* ]]; then
    pass "resume + remember: incarnation 2, one Cortex fact and one forked branch committed"
else
    bad "remember: resumed='${r}' remembered='${m}'"
fi

inc=3; seq=4
for n in 1 2; do
    boot_mode 6
    r=$(cont RESUMED)
    if [[ "$(field agent "${r}")" == "${agent}" && "$(field memory "${r}")" == "${memory}" && \
          "${r}" == *"incarnation=${inc} sequence=${seq} cortex=1 branches=2 "* ]]; then
        pass "cold restart ${n}: same agent, same memory ${memory}, same lineage, incarnation ${inc}"
    else
        bad "cold restart ${n}: '${r}'"
    fi
    inc=$(( inc + 1 )); seq=$(( seq + 1 ))
done
base="${work}/remembered.img"; cp "${image}" "${base}"

echo "=== 4. SIGKILL at every Store checkpoint of a continuity commit ==="
cp "${base}" "${image}"; boot_mode 8
new_memory=$(field memory "$(cont COMMITTED)")
[[ -n "${new_memory}" && "${new_memory}" != "${memory}" ]] || bad "reference commit did not produce new memory"
checkpoints=(before_first_write after_payloads after_catalog after_commit_record \
             after_first_flush after_superblock_write after_final_flush)
for cp in "${checkpoints[@]}"; do
    cp "${base}" "${image}"; write_cfg 8
    run_qemu "CHECKPOINT: ${cp}" kill
    saw=0; grep -q -- "CHECKPOINT: ${cp}" "${serial}" && saw=1
    boot_mode 6
    r=$(cont RESUMED); got=$(field memory "${r}")
    case "${cp}" in
        after_final_flush)      want="${new_memory}" ;;
        after_superblock_write) want="either" ;;
        *)                      want="${memory}" ;;
    esac
    ok=0
    if [[ "${saw}" == 1 && "$(field agent "${r}")" == "${agent}" ]]; then
        if [[ "${want}" == either ]]; then
            [[ "${got}" == "${memory}" || "${got}" == "${new_memory}" ]] && ok=1
        else
            [[ "${got}" == "${want}" ]] && ok=1
        fi
    fi
    state="old"; [[ "${got}" == "${new_memory}" ]] && state="new"
    if [[ "${ok}" == 1 ]]; then
        pass "kill at ${cp}: same agent, ${state} memory"
    else
        bad "kill at ${cp}: saw=${saw} '${r}'"
    fi
done

echo "=== 5. Degraded mount resumes read-only ==="
cp "${base}" "${image}"
"${tool}" inject "${image}" "${store_offset}" inactive seeded_garbage >/dev/null || bad "inject failed"
before=$(digest); boot_mode 6; after=$(digest)
r=$(cont RESUMED_READONLY)
if [[ "$(field agent "${r}")" == "${agent}" && "$(field memory "${r}")" == "${memory}" && "${before}" == "${after}" ]]; then
    pass "malformed peer superblock: same agent and memory, read-only, nothing written"
else
    bad "degraded: '${r:-$(tr -d '\r' <"${serial}" | grep 'CONTINUITY:' | head -2)}'"
fi

echo
echo "=== Summary (commit ${commit}) ==="
if [[ "${fail}" == 0 ]]; then
    echo "CONTINUITY_QEMU: PASS"
else
    echo "CONTINUITY_QEMU: FAIL"
    exit 1
fi
echo "CONTINUITY_NATIVE: NOT CLAIMED (Machine 1 waits on TRUST-1)"
