#!/usr/bin/env bash
# System Store v1 over the native NVMe driver: 512-byte-LBA QEMU crash/reboot campaign.
#
# Geometry: 512-byte LBA (the native DGX Spark geometry, AWUPF=0, non-atomic root).
# The Store root write is 4096 bytes (8 logical blocks), which exceeds AWUPF.
#
# Exercises two tiers of qualification:
# - Tier 1: Observational checkpoint / SIGKILL campaign (STORE_512B_CRASH_OBSERVED_QEMU)
# - Tier 2: Deterministic torn root recovery campaign (STORE_512B_TORN_ROOT_RECOVERY_QEMU)
#
# Emits STORE_512B_CRASH_RECOVERY_QEMU: PASS only when both tiers succeed.
#
# Test-only. QEMU only. No production ADR 0015, recovery, Store-format, NVMe-policy,
# or Machine 1 changes. P3_STORE_QEMU and P3_STORE_NATIVE remain strictly unclaimed.
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
cfg_lba=256
store_base_lba=512
slot0_byte_offset=$(( store_base_lba * lba_bytes ))
slot1_byte_offset=$(( (store_base_lba + 8) * lba_bytes ))

machine="virt,virtualization=on,gic-version=3,iommu=smmuv3"
target_dir="target/qemu-store-512b-crash"

echo "=== Building aienos-handoff with store-qual for 512b crash test ==="
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features store-qual --bin aienos-handoff \
    --target-dir "${target_dir}" || { echo "build failed"; exit 2; }

work="$(mktemp -d)"
qemu_pid=""
cleanup() { [[ -n "${qemu_pid}" ]] && kill -9 "${qemu_pid}" 2>/dev/null || true; rm -rf "${work}"; }
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${target_dir}/aarch64-unknown-uefi/release/aienos-handoff.efi" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"

image="${work}/nvme.img"
serial="${work}/serial.log"
cfgfile="${work}/cfg.bin"

fresh_image() { rm -f "${image}"; truncate -s "${img_bytes}" "${image}"; }

write_cfg() { # mode settle
    python3 -c "open('${cfgfile}','wb').write(bytes([$1,$2]) + bytes(4094))"
    dd if="${cfgfile}" of="${image}" bs="${lba_bytes}" seek="${cfg_lba}" conv=notrunc status=none
}

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

checkpoints=(before_first_write after_payloads after_catalog after_commit_record \
             after_first_flush after_superblock_write after_final_flush)

fail=0
integration_pass=0
tier1_pass=0
tier2_pass=0
reopen_pass=0
slot_pass=0
: > "${work}/results_tier1.txt"
: > "${work}/results_tier2.txt"

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
if grep -q "STORE_REOPEN_512B_QEMU: generation=2 state=Valid peer_classification=Valid" "${serial}" && \
   grep -q "STORE_REOPEN_QEMU: PASS" "${serial}"; then
    reopen_pass=1
    echo "PASS  reopen smoke (mode=4 verify, peer_classification=Valid)"
else
    echo "FAIL  reopen smoke"
    fail=1
    grep -E "STORE_REOPEN_512B_QEMU|STORE_REOPEN_QEMU" "${serial}" | sed 's/^/      /'
fi

# --- Tier 1: Observational checkpoint / SIGKILL campaign -------------------
echo
echo "=== Tier 1: Observational Checkpoint / SIGKILL Campaign ==="
expect_for() { # checkpoint settle
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
        write_cfg 4 "${settle}"
        run_qemu "STORE_REOPEN_QEMU:"
        guest_reopen=0; grep -q "STORE_REOPEN_QEMU: PASS" "${serial}" && guest_reopen=1
        guest_slot=1
        if [[ "${settle}" -ge 3 ]]; then
            guest_slot=0; grep -q "STORE_SLOT_REUSE_QEMU: PASS" "${serial}" && guest_slot=1
        fi
        gen="$(grep -oE "STORE_REOPEN_512B_QEMU: generation=[0-9]+" "${serial}" | tail -1 | grep -oE '[0-9]+$')"
        st="$(grep -oE "STORE_REOPEN_512B_QEMU: generation=[0-9]+ state=[A-Za-z]+" "${serial}" | tail -1 | sed 's/.*state=//')"
        pclass="$(grep -oE "peer_classification=[A-Za-z]+" "${serial}" | tail -1 | sed 's/.*peer_classification=//')"
        exp="$(expect_for "${cp}")"
        gen_ok=0
        case "${exp}" in
            N)     [[ "${gen}" == "${N}" ]] && gen_ok=1 ;;
            NP1)   [[ "${gen}" == "${NP1}" ]] && gen_ok=1 ;;
            N_NP1) [[ "${gen}" == "${N}" || "${gen}" == "${NP1}" ]] && gen_ok=1 ;;
        esac
        ok=0
        if [[ "${saw_cp}" == "1" && "${gen_ok}" == "1" && "${guest_reopen}" == "1" && "${guest_slot}" == "1" ]]; then ok=1; fi
        printf 'settle=%s cp=%-24s saw=%s reopen=%s slot=%s gen=%s state=%-16s peer=%-10s expect=%-5s -> %s\n' \
            "${settle}" "${cp}" "${saw_cp}" "${guest_reopen}" "${guest_slot}" "${gen:-none}" "${st:-none}" "${pclass:-none}" "${exp}" \
            "$([ "${ok}" = 1 ] && echo OK || echo BAD)" >> "${work}/results_tier1.txt"
        if [[ "${ok}" != "1" ]]; then fail=1; fi
    done
done

cat "${work}/results_tier1.txt"

tier1_pass=1
grep -q ' -> BAD' "${work}/results_tier1.txt" && tier1_pass=0

if [[ "${tier1_pass}" == 1 ]]; then
    echo "STORE_512B_CRASH_OBSERVED_QEMU: PASS"
else
    echo "STORE_512B_CRASH_OBSERVED_QEMU: FAIL"
fi

# --- Tier 2: Deterministic Torn Root Recovery Campaign --------------------
echo
echo "=== Tier 2: Deterministic Torn Root Recovery Campaign ==="

# Step 2a: Obtain golden genesis image template
fresh_image; write_cfg 3 0
run_qemu "CHECKPOINT: before_first_write" kill
if ! grep -q "STORE_512B_NONATOMIC_QUALIFICATION: ACTIVE" "${serial}"; then
    echo "FAIL  could not produce clean genesis template"
    exit 1
fi
cp "${image}" "${work}/genesis_template.img"

torn_cases=(
    torn_1_of_8_blocks
    torn_2_of_8_blocks
    torn_4_of_8_blocks
    torn_7_of_8_blocks
    torn_tail_only
    bad_crc
    wrong_magic
    dirty_reserved
    arbitrary_garbage
)

inject_slot1() { # image_path case_name
    python3 - "${1}" "${2}" << 'EOF'
import sys, os

image_path = sys.argv[1]
case_name = sys.argv[2]

with open(image_path, 'r+b') as f:
    f.seek(262144) # LBA 512 * 512 (Slot 0)
    slot0 = f.read(4096)

    # Build candidate slot 1
    sb = bytearray(slot0)
    sb[44:48] = (1).to_bytes(4, 'little') # slot_id = 1
    sb[56:64] = (2).to_bytes(8, 'little') # generation = 2
    sb[168:172] = bytes(4)

    def crc32c(data: bytes) -> int:
        crc = 0xffffffff
        for b in data:
            crc ^= b
            for _ in range(8):
                mask = 0xffffffff if (crc & 1) else 0
                crc = (crc >> 1) ^ (0x82f63b78 & mask)
        return (~crc) & 0xffffffff

    c = crc32c(bytes(sb))
    sb[168:172] = c.to_bytes(4, 'little')

    pre = bytearray([0xaa] * 4096)
    if case_name == 'torn_1_of_8_blocks':
        pre[:512] = sb[:512]
        payload = bytes(pre)
    elif case_name == 'torn_2_of_8_blocks':
        pre[:1024] = sb[:1024]
        payload = bytes(pre)
    elif case_name == 'torn_4_of_8_blocks':
        pre[:2048] = sb[:2048]
        payload = bytes(pre)
    elif case_name == 'torn_7_of_8_blocks':
        pre[:3584] = sb[:3584]
        payload = bytes(pre)
    elif case_name == 'torn_tail_only':
        pre[512:] = sb[512:]
        payload = bytes(pre)
    elif case_name == 'bad_crc':
        sb[168] ^= 0xff
        payload = bytes(sb)
    elif case_name == 'wrong_magic':
        sb[:8] = b'AIENBAD1'
        payload = bytes(sb)
    elif case_name == 'dirty_reserved':
        sb[200] = 0x42
        payload = bytes(sb)
    elif case_name == 'arbitrary_garbage':
        payload = os.urandom(4096)
    else:
        raise ValueError('unknown case: ' + case_name)

    f.seek(266240) # LBA 520 * 512 (Slot 1)
    f.write(payload)
EOF
}

tier2_ok=1
for tc in "${torn_cases[@]}"; do
    cp "${work}/genesis_template.img" "${image}"
    inject_slot1 "${image}" "${tc}"
    write_cfg 4 0 # MODE_VERIFY_512B, settle=0
    run_qemu "STORE_REOPEN_QEMU:"

    saw_active=0; grep -q "STORE_512B_NONATOMIC_QUALIFICATION: ACTIVE" "${serial}" && saw_active=1
    saw_degraded=0; grep -q "state=DegradedRecovery" "${serial}" && saw_degraded=1
    saw_malformed=0; grep -q "peer_classification=Malformed" "${serial}" && saw_malformed=1
    saw_readonly=0; grep -q "STORE_DEGRADED_READONLY_QEMU: PASS" "${serial}" && saw_readonly=1
    saw_reopen=0; grep -q "STORE_REOPEN_QEMU: PASS" "${serial}" && saw_reopen=1

    gen="$(grep -oE "STORE_REOPEN_512B_QEMU: generation=[0-9]+" "${serial}" | tail -1 | grep -oE '[0-9]+$')"
    st="$(grep -oE "STORE_REOPEN_512B_QEMU: generation=[0-9]+ state=[A-Za-z]+" "${serial}" | tail -1 | sed 's/.*state=//')"
    pclass="$(grep -oE "peer_classification=[A-Za-z]+" "${serial}" | tail -1 | sed 's/.*peer_classification=//')"

    tc_ok=0
    if [[ "${saw_active}" == "1" && "${saw_degraded}" == "1" && "${saw_malformed}" == "1" && \
          "${saw_readonly}" == "1" && "${saw_reopen}" == "1" && "${gen}" == "1" ]]; then
        tc_ok=1
    else
        tier2_ok=0
        fail=1
    fi

    printf 'case=%-20s gen=%s state=%-16s peer=%-10s readonly_pass=%s reopen_pass=%s -> %s\n' \
        "${tc}" "${gen:-none}" "${st:-none}" "${pclass:-none}" "${saw_readonly}" "${saw_reopen}" \
        "$([ "${tc_ok}" = 1 ] && echo OK || echo BAD)" >> "${work}/results_tier2.txt"
done

cat "${work}/results_tier2.txt"

if [[ "${tier2_ok}" == 1 ]]; then
    tier2_pass=1
    echo "STORE_512B_TORN_ROOT_RECOVERY_QEMU: PASS"
else
    echo "STORE_512B_TORN_ROOT_RECOVERY_QEMU: FAIL"
fi

echo
echo "=== Final Summary ==="
[[ "${integration_pass}" == 1 ]] && echo "STORE_NVME_INTEGRATION_512B_QEMU: PASS" || echo "STORE_NVME_INTEGRATION_512B_QEMU: FAIL"
[[ "${tier1_pass}" == 1 ]] && echo "STORE_512B_CRASH_OBSERVED_QEMU: PASS" || echo "STORE_512B_CRASH_OBSERVED_QEMU: FAIL"
[[ "${tier2_pass}" == 1 ]] && echo "STORE_512B_TORN_ROOT_RECOVERY_QEMU: PASS" || echo "STORE_512B_TORN_ROOT_RECOVERY_QEMU: FAIL"

if [[ "${fail}" == 0 && "${tier1_pass}" == 1 && "${tier2_pass}" == 1 ]]; then
    echo "STORE_512B_CRASH_RECOVERY_QEMU: PASS"
else
    echo "STORE_512B_CRASH_RECOVERY_QEMU: FAIL"
    exit 1
fi

echo "P3_STORE_QEMU: NOT CLAIMED (QEMU campaign; native persistence conditions separate)"
echo "P3_STORE_NATIVE: NOT CLAIMED"
