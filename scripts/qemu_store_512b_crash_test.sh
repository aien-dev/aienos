#!/usr/bin/env bash
# System Store v1 over the native NVMe driver: 512-byte-LBA QEMU qualification.
#
# Geometry: 512-byte LBA (the native DGX Spark geometry, AWUPF=0: one logical
# block is the power-fail atomic unit). A Store root write is 4096 bytes
# (8 logical blocks), so the device does not promise it lands atomically.
#
# Tier 1  STORE_512B_CRASH_OBSERVED_QEMU
#   QEMU is killed (SIGKILL) at each engine checkpoint, then reopened through the
#   real NVMe path. This models a VM/process crash: every write QEMU accepted is
#   in the host file, flushed or not. It is not a power-loss model (volatile
#   cache loss is covered by the #133 atomicity qualification).
# Tier 2a STORE_512B_ROOT_TEAR_CLOSURE
#   Host proof on the Tier 1 images: the image killed at after_first_flush and
#   the image killed at after_final_flush differ only inside one superblock
#   slot, and every sector-granular tear of that write (all 2^8 subsets)
#   reproduces either the old or the new slot bytes. So on this format a torn
#   root write can only leave a state Tier 1 already booted.
# Tier 2b STORE_512B_INJECTED_ROOT_RECOVERY_QEMU
#   Deterministic media-corruption injection, not a crash: one defect per case
#   is written into the inactive slot of the after_first_flush image by
#   aienos-store-tool (the kernel's own encoder and CRC), then the guest reopens.
#
# Emits STORE_512B_CRASH_RECOVERY_QEMU: PASS only when all tiers pass.
# Test-only. QEMU only. No ADR 0015, recovery, Store-format, NVMe-policy, or
# Machine 1 changes. P3_STORE_QEMU and P3_STORE_NATIVE remain unclaimed.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
img_bytes=67108864
lba_bytes=512
cfg_offset=$(( 256 * lba_bytes ))
store_offset=$(( 512 * lba_bytes ))

machine="virt,virtualization=on,gic-version=3,iommu=smmuv3"
target_dir="target/qemu-store-512b-crash"

echo "=== Building aienos-handoff (store-qual) and aienos-store-tool ==="
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
git diff --quiet HEAD 2>/dev/null || commit="${commit}-dirty"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features store-qual --bin aienos-handoff \
    --target-dir "${target_dir}" || { echo "build failed"; exit 2; }
cargo build --quiet --release -p aienos-store-tool || { echo "store tool build failed"; exit 2; }
tool="target/release/aienos-store-tool"

work="$(mktemp -d)"
qemu_pid=""
cleanup() { [[ -n "${qemu_pid}" ]] && kill -9 "${qemu_pid}" 2>/dev/null || true; rm -rf "${work}"; }
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS" "${work}/saved"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${target_dir}/aarch64-unknown-uefi/release/aienos-handoff.efi" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"

image="${work}/nvme.img"
serial="${work}/serial.log"

fresh_image() { rm -f "${image}"; truncate -s "${img_bytes}" "${image}"; }
write_cfg() { "${tool}" cfg "${image}" "${cfg_offset}" "$1" "$2" >/dev/null || { echo "cfg write failed"; exit 2; }; }

# run_qemu <marker> [kill]
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
        -device nvme,drive=nvme0,serial=aienos-store-512b-crash,logical_block_size=${lba_bytes},physical_block_size=${lba_bytes} \
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

# Fields of this run's single STORE_REOPEN_512B_QEMU line (serial is per run).
reopen_fields() {
    local line
    line="$(grep -oE "STORE_REOPEN_512B_QEMU: generation=[0-9]+ state=[A-Za-z]+ peer_classification=[A-Za-z]+" "${serial}" | tail -1)"
    gen="$(sed -nE 's/.*generation=([0-9]+).*/\1/p' <<<"${line}")"
    st="$(sed -nE 's/.*state=([A-Za-z]+).*/\1/p' <<<"${line}")"
    pclass="$(sed -nE 's/.*peer_classification=([A-Za-z]+).*/\1/p' <<<"${line}")"
}

checkpoints=(before_first_write after_payloads after_catalog after_commit_record \
             after_first_flush after_superblock_write after_final_flush)

fail=0
integration_pass=0
reopen_pass=0
tier1_pass=0
tier2a_pass=0
tier2b_pass=0
: > "${work}/results_tier1.txt"
: > "${work}/results_tier2b.txt"

# --- integration smoke (no crash): provision, transact, reopen -------------
echo "=== Integration Smoke (512-byte LBA) ==="
fresh_image; write_cfg 3 0
run_qemu "STORE_CHECKPOINT_QEMU"
if grep -q "STORE_512B_NONATOMIC_QUALIFICATION: ACTIVE" "${serial}" && \
   grep -q "STORE_NVME_INTEGRATION_QEMU: PASS" "${serial}" && \
   grep -q "STORE_CHECKPOINT_QEMU: PASS" "${serial}"; then
    integration_pass=1
    echo "PASS  integration smoke (provision + transact, 512b non-atomic qualification active)"
else
    echo "FAIL  integration smoke"
    fail=1
    grep -E "STORE_512B_NONATOMIC_QUALIFICATION|STORE_NVME_INTEGRATION_QEMU|STORE_CHECKPOINT_QEMU" "${serial}" | sed 's/^/      /'
fi

write_cfg 4 0
run_qemu "STORE_REOPEN_QEMU:"
reopen_fields
if [[ "${gen}" == 2 && "${st}" == Valid && "${pclass}" == Valid ]] && \
   grep -q "STORE_REOPEN_QEMU: PASS" "${serial}"; then
    reopen_pass=1
    echo "PASS  reopen smoke (generation=2 state=Valid peer=Valid)"
else
    echo "FAIL  reopen smoke"
    fail=1
    grep -E "STORE_REOPEN_512B_QEMU|STORE_REOPEN_QEMU" "${serial}" | sed 's/^/      /'
fi

# --- Tier 1: checkpoint SIGKILL campaign ------------------------------------
echo
echo "=== Tier 1: Checkpoint SIGKILL Campaign ==="
expect_for() { # checkpoint
    case "$1" in
        after_superblock_write) echo "N_NP1" ;;
        after_final_flush)      echo "NP1" ;;
        *)                      echo "N" ;;
    esac
}

for settle in 0 3; do
    N=$(( 1 + settle )); NP1=$(( 2 + settle ))
    for cp in "${checkpoints[@]}"; do
        fresh_image; write_cfg 3 "${settle}"
        run_qemu "CHECKPOINT: ${cp}" kill
        saw_cp=0; grep -q -- "CHECKPOINT: ${cp}" "${serial}" && saw_cp=1
        # Keep the crashed image for Tier 2 before the verify boot touches it.
        cp "${image}" "${work}/saved/s${settle}_${cp}.img"
        write_cfg 4 "${settle}"
        run_qemu "STORE_REOPEN_QEMU:"
        guest_reopen=0; grep -q "STORE_REOPEN_QEMU: PASS" "${serial}" && guest_reopen=1
        guest_slot=1
        if [[ "${settle}" -ge 3 ]]; then
            guest_slot=0; grep -q "STORE_SLOT_REUSE_QEMU: PASS" "${serial}" && guest_slot=1
        fi
        reopen_fields
        exp="$(expect_for "${cp}")"
        gen_ok=0
        case "${exp}" in
            N)     [[ "${gen}" == "${N}" ]] && gen_ok=1 ;;
            NP1)   [[ "${gen}" == "${NP1}" ]] && gen_ok=1 ;;
            N_NP1) [[ "${gen}" == "${N}" || "${gen}" == "${NP1}" ]] && gen_ok=1 ;;
        esac
        ok=0
        if [[ "${saw_cp}" == 1 && "${gen_ok}" == 1 && "${guest_reopen}" == 1 && "${guest_slot}" == 1 \
              && "${st}" == Valid ]]; then ok=1; fi
        printf 'settle=%s cp=%-24s saw=%s reopen=%s slot=%s gen=%s state=%-16s peer=%-13s expect=%-5s -> %s\n' \
            "${settle}" "${cp}" "${saw_cp}" "${guest_reopen}" "${guest_slot}" "${gen:-none}" "${st:-none}" \
            "${pclass:-none}" "${exp}" "$([ "${ok}" = 1 ] && echo OK || echo BAD)" >> "${work}/results_tier1.txt"
        if [[ "${ok}" != 1 ]]; then fail=1; fi
    done
done
cat "${work}/results_tier1.txt"
tier1_pass=1
grep -q ' -> BAD' "${work}/results_tier1.txt" && tier1_pass=0
[[ "${tier1_pass}" == 1 ]] && echo "STORE_512B_CRASH_OBSERVED_QEMU: PASS" || echo "STORE_512B_CRASH_OBSERVED_QEMU: FAIL"

# --- Tier 2a: root tear closure on the real Tier 1 images -------------------
echo
echo "=== Tier 2a: Root Tear Closure (host proof over Tier 1 images) ==="
tier2a_pass=1
for settle in 0 3; do
    if ! "${tool}" tear-closure "${work}/saved/s${settle}_after_first_flush.img" \
            "${work}/saved/s${settle}_after_final_flush.img" "${store_offset}" "${lba_bytes}" \
            | sed "s/^/settle=${settle} /"; then
        tier2a_pass=0; fail=1
        echo "settle=${settle} STORE_ROOT_TEAR_CLOSURE: FAIL"
    fi
done
[[ "${tier2a_pass}" == 1 ]] && echo "STORE_512B_ROOT_TEAR_CLOSURE: PASS" || echo "STORE_512B_ROOT_TEAR_CLOSURE: FAIL"

# --- Tier 2b: deterministic injected-root recovery --------------------------
echo
echo "=== Tier 2b: Injected Root Recovery (media corruption, one defect per case) ==="
# Base: settle-0 image killed at after_first_flush (gen 1 in slot 0, gen 2
# objects durable, slot 1 zero). Source: the real gen-2 superblock from the
# after_final_flush image. graph_bad_newer uses the after_payloads image,
# where the gen-2 catalog and commit record were never written.
base_flush="${work}/saved/s0_after_first_flush.img"
base_payloads="${work}/saved/s0_after_payloads.img"
source_root="${work}/saved/s0_after_final_flush.img"

# case  base  tool-case  expected-outcome
inject_cases=(
    "bad_crc             flush     bad_crc             degraded:Malformed"
    "wrong_magic         flush     wrong_magic         degraded:Malformed"
    "nonzero_reserved    flush     nonzero_reserved    degraded:Malformed"
    "wrong_slot_id       flush     wrong_slot_id       degraded:Malformed"
    "region_mismatch     flush     region_mismatch     degraded:Malformed"
    "seeded_garbage      flush     seeded_garbage      degraded:Malformed"
    "unsupported_version flush     unsupported_version refuse:UnsupportedVersion"
    "graph_bad_newer     payloads  new_root            degraded:GraphBadNewer"
    "control_new_root    flush     new_root            valid:gen2"
)

tier2b_pass=1
for row in "${inject_cases[@]}"; do
    read -r name base tcase expect <<<"${row}"
    if [[ "${base}" == flush ]]; then cp "${base_flush}" "${image}"; else cp "${base_payloads}" "${image}"; fi
    if ! "${tool}" inject "${image}" "${store_offset}" 1 "${tcase}" "${source_root}" >"${work}/inject.txt" 2>&1; then
        echo "case=${name} injection refused: $(cat "${work}/inject.txt")" >> "${work}/results_tier2b.txt"
        tier2b_pass=0; fail=1; continue
    fi
    write_cfg 4 0
    run_qemu "STORE_REOPEN_QEMU:"
    gen=""; st=""; pclass=""
    reopen_fields
    active=0; grep -q "STORE_512B_NONATOMIC_QUALIFICATION: ACTIVE" "${serial}" && active=1
    ro=0; grep -q "STORE_DEGRADED_READONLY_QEMU: PASS" "${serial}" && ro=1
    ok=0
    case "${expect}" in
        degraded:*)
            [[ "${active}" == 1 && "${gen}" == 1 && "${st}" == DegradedRecovery && \
               "${pclass}" == "${expect#degraded:}" && "${ro}" == 1 ]] && \
               grep -q "STORE_REOPEN_QEMU: PASS" "${serial}" && ok=1 ;;
        refuse:*)
            grep -q "STORE_REOPEN_QEMU: FAIL (open ${expect#refuse:})" "${serial}" && [[ -z "${gen}" ]] && ok=1 ;;
        valid:gen2)
            [[ "${gen}" == 2 && "${st}" == Valid && "${pclass}" == Valid ]] && \
               grep -q "STORE_REOPEN_QEMU: PASS" "${serial}" && ok=1 ;;
    esac
    printf 'case=%-20s %-32s gen=%s state=%-16s peer=%-13s readonly=%s expect=%-28s -> %s\n' \
        "${name}" "$(cut -d' ' -f4 "${work}/inject.txt")" "${gen:-none}" "${st:-none}" "${pclass:-none}" "${ro}" \
        "${expect}" "$([ "${ok}" = 1 ] && echo OK || echo BAD)" >> "${work}/results_tier2b.txt"
    if [[ "${ok}" != 1 ]]; then tier2b_pass=0; fail=1; fi
done
cat "${work}/results_tier2b.txt"
[[ "${tier2b_pass}" == 1 ]] && echo "STORE_512B_INJECTED_ROOT_RECOVERY_QEMU: PASS" || echo "STORE_512B_INJECTED_ROOT_RECOVERY_QEMU: FAIL"

echo
echo "=== Final Summary (commit ${commit}) ==="
[[ "${integration_pass}" == 1 && "${reopen_pass}" == 1 ]] && echo "STORE_NVME_INTEGRATION_512B_QEMU: PASS" || echo "STORE_NVME_INTEGRATION_512B_QEMU: FAIL"
[[ "${tier1_pass}" == 1 ]] && echo "STORE_512B_CRASH_OBSERVED_QEMU: PASS" || echo "STORE_512B_CRASH_OBSERVED_QEMU: FAIL"
[[ "${tier2a_pass}" == 1 ]] && echo "STORE_512B_ROOT_TEAR_CLOSURE: PASS" || echo "STORE_512B_ROOT_TEAR_CLOSURE: FAIL"
[[ "${tier2b_pass}" == 1 ]] && echo "STORE_512B_INJECTED_ROOT_RECOVERY_QEMU: PASS" || echo "STORE_512B_INJECTED_ROOT_RECOVERY_QEMU: FAIL"

if [[ "${fail}" == 0 && "${integration_pass}" == 1 && "${reopen_pass}" == 1 && "${tier1_pass}" == 1 \
      && "${tier2a_pass}" == 1 && "${tier2b_pass}" == 1 ]]; then
    echo "STORE_512B_CRASH_RECOVERY_QEMU: PASS"
else
    echo "STORE_512B_CRASH_RECOVERY_QEMU: FAIL"
    exit 1
fi

echo "P3_STORE_QEMU: NOT CLAIMED (QEMU campaign; native persistence conditions separate)"
echo "P3_STORE_NATIVE: NOT CLAIMED"
