#!/usr/bin/env bash
# System Store v1 over the native NVMe driver: QEMU crash/reboot campaign.
#
# Geometry: 4096-byte LBA (the atomic-root qualified namespace). The Store root
# write is one logical block, satisfying the atomic-root predicate.
#
# Chain exercised in-guest: NvmeController -> BoundedNvme -> StoreDeviceAdapter
# -> Store. For each canonical checkpoint the guest begins generation N+1, the
# host kills QEMU abruptly at the checkpoint marker, then reboots and reopens
# from media; recovery must be generation N or N+1 with a valid graph.
#
# Test-only. QEMU only. No ADR 0015, recovery, Store-format, NVMe-policy, or
# Machine 1 changes.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

# rows_all_ok FILE WANT: true only when FILE holds exactly WANT result rows
# (lines with " -> ") and every one ends in "-> OK". A missing file, a short
# campaign, an extra row or any BAD row is false, so a loop that never ran
# (or stopped early) cannot read as PASS.
rows_all_ok() {
    local f="$1" want="$2" total=0 ok=0
    [[ -f "${f}" ]] || { echo "      rows: ${f##*/} missing (want ${want})"; return 1; }
    total=$(grep -c ' -> ' "${f}" || true)
    ok=$(grep -c ' -> OK$' "${f}" || true)
    if [[ "${want}" -gt 0 && "${total}" == "${want}" && "${ok}" == "${want}" ]]; then return 0; fi
    echo "      rows: ${f##*/} has ${total} rows, ${ok} OK; want exactly ${want} OK"
    return 1
}

# --verdict-self-test: feed the verdict check broken result files (no QEMU,
# no build) and require FAIL for each, PASS only for the complete table.
if [[ "${1:-}" == --verdict-self-test ]]; then
    t="$(mktemp -d)"; st=0
    want_rows() { # NAME WANT EXPECT(0 pass|1 fail) LINES...
        local name="$1" want="$2" expect="$3"; shift 3
        printf '%s' "" > "${t}/r"; for l in "$@"; do printf '%s\n' "${l}" >> "${t}/r"; done
        local got=0; rows_all_ok "${t}/r" "${want}" >/dev/null || got=1
        if [[ "${got}" == "${expect}" ]]; then echo "PASS  ${name} -> $([ "${got}" = 0 ] && echo PASS || echo FAIL)"
        else echo "FAIL  ${name} gave the wrong verdict"; st=1; fi
    }
    want_rows "empty results (campaign never ran)" 3 1
    want_rows "one row short (campaign stopped early)" 3 1 "a -> OK" "b -> OK"
    want_rows "one BAD row" 3 1 "a -> OK" "b -> BAD" "c -> OK"
    want_rows "one extra row" 3 1 "a -> OK" "b -> OK" "c -> OK" "d -> OK"
    want_rows "zero rows wanted is never a pass" 0 1
    want_rows "complete, all OK" 3 0 "a -> OK" "b -> OK" "c -> OK"
    rm -f "${t}/r"; rows_all_ok "${t}/r" 3 >/dev/null && { echo "FAIL  missing file read as PASS"; st=1; } || echo "PASS  missing results file -> FAIL"
    rm -rf "${t}"
    [[ "${st}" == 0 ]] && { echo "STORE_CRASH_VERDICT_SELF_TEST: PASS"; exit 0; }
    echo "STORE_CRASH_VERDICT_SELF_TEST: FAIL"; exit 1
fi

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
img_bytes=67108864
lba_bytes=4096
bounds_lba=$(( img_bytes / lba_bytes ))
cfg_lba=32
machine="virt,virtualization=on,gic-version=3,iommu=smmuv3"
target_dir="target/qemu-store-crash"

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
tree_dirty=unknown
if [[ "${commit}" != unknown ]]; then
    if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then tree_dirty=true; commit="${commit}-dirty"; else tree_dirty=false; fi
fi
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features store-qual --bin aienos-handoff \
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

fresh_image() { rm -f "${image}"; truncate -s "${img_bytes}" "${image}"; }

write_cfg() { # mode settle
    "${tool}" cfg "${image}" "$(( cfg_lba * lba_bytes ))" "$1" "$2" >/dev/null || { echo "cfg write failed"; exit 2; }
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
        -device nvme,drive=nvme0,serial=aienos-store-crash,logical_block_size=${lba_bytes},physical_block_size=${lba_bytes} \
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
crash_pass=0
reopen_pass=0
slot_pass=0
: > "${work}/results.txt"

# --- integration smoke (no crash): provision, transact, reopen -------------
fresh_image; write_cfg 1 0
run_qemu "STORE_CHECKPOINT_QEMU"
if grep -q "STORE_NVME_INTEGRATION_QEMU: PASS" "${serial}" && \
   grep -q "STORE_CHECKPOINT_QEMU: PASS" "${serial}"; then
    integration_pass=1; echo "PASS  integration smoke (provision + transact)"
else
    echo "FAIL  integration smoke"; fail=1
    grep -E "STORE_NVME_INTEGRATION_QEMU|STORE_CHECKPOINT_QEMU" "${serial}" | sed 's/^/      /'
fi
write_cfg 2 0
run_qemu "STORE_REOPEN_QEMU:"
if grep -q "STORE_REOPEN_QEMU: PASS" "${serial}"; then echo "PASS  reopen smoke"; else echo "FAIL  reopen smoke"; fail=1; fi

# --- crash campaign --------------------------------------------------------
# Per-checkpoint expectation from the implementation: the inactive-superblock
# write is the durable commit point. Before it, recovery must be N; at it the
# Store contract permits N or N+1 (emulator durability); after the final flush
# it must be N+1.
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
        fresh_image; write_cfg 1 "${settle}"
        run_qemu "CHECKPOINT: ${cp}" kill
        saw_cp=0; grep -q -- "CHECKPOINT: ${cp}" "${serial}" && saw_cp=1
        write_cfg 2 "${settle}"
        run_qemu "STORE_REOPEN_QEMU:"
        guest_reopen=0; grep -q "STORE_REOPEN_QEMU: PASS" "${serial}" && guest_reopen=1
        guest_slot=1
        if [[ "${settle}" -ge 3 ]]; then
            guest_slot=0; grep -q "STORE_SLOT_REUSE_QEMU: PASS" "${serial}" && guest_slot=1
        fi
        gen="$(grep -oE "STORE_REOPEN_QEMU: generation=[0-9]+" "${serial}" | tail -1 | grep -oE '[0-9]+$')"
        st="$(grep -oE "STORE_REOPEN_QEMU: generation=[0-9]+ state=[A-Za-z]+" "${serial}" | tail -1 | sed 's/.*state=//')"
        exp="$(expect_for "${cp}")"
        gen_ok=0
        case "${exp}" in
            N)     [[ "${gen}" == "${N}" ]] && gen_ok=1 ;;
            NP1)   [[ "${gen}" == "${NP1}" ]] && gen_ok=1 ;;
            N_NP1) [[ "${gen}" == "${N}" || "${gen}" == "${NP1}" ]] && gen_ok=1 ;;
        esac
        ok=0
        if [[ "${saw_cp}" == "1" && "${gen_ok}" == "1" && "${guest_reopen}" == "1" && "${guest_slot}" == "1" ]]; then ok=1; fi
        printf 'settle=%s cp=%-18s saw=%s guest_reopen=%s guest_slot=%s recovered=%s state=%s expect=%s -> %s\n' \
            "${settle}" "${cp}" "${saw_cp}" "${guest_reopen}" "${guest_slot}" "${gen:-none}" "${st:-none}" "${exp}" \
            "$([ "${ok}" = 1 ] && echo OK || echo BAD)" >> "${work}/results.txt"
        if [[ "${ok}" != "1" ]]; then fail=1; fi
    done
done

# Exactly one OK row per (settle, checkpoint); a short or empty table is FAIL.
# Slot reuse is checked on the settle=3 rows: all of them must be present and OK.
crash_pass=0; reopen_pass=0; slot_pass=0
if rows_all_ok "${work}/results.txt" $(( 2 * ${#checkpoints[@]} )); then crash_pass=1; reopen_pass=1; else fail=1; fi
grep '^settle=3 ' "${work}/results.txt" > "${work}/results_settle3.txt" 2>/dev/null || true
rows_all_ok "${work}/results_settle3.txt" ${#checkpoints[@]} && slot_pass=1

echo "---- crash campaign results ----"
cat "${work}/results.txt"
if [[ "${fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- final serial ----"; cat "${serial}"
fi

echo
echo "=== Summary (commit ${commit}, tree_dirty=${tree_dirty}, evidence level: QEMU only) ==="
[[ "${integration_pass}" == 1 ]] && echo "STORE_NVME_INTEGRATION_QEMU: PASS" || echo "STORE_NVME_INTEGRATION_QEMU: FAIL"
[[ "${crash_pass}" == 1 && "${fail}" == 0 ]] && echo "STORE_CHECKPOINT_CRASH_QEMU: PASS" || echo "STORE_CHECKPOINT_CRASH_QEMU: FAIL"
[[ "${reopen_pass}" == 1 && "${fail}" == 0 ]] && echo "STORE_REOPEN_QEMU: PASS" || echo "STORE_REOPEN_QEMU: FAIL"
[[ "${slot_pass}" == 1 ]] && echo "STORE_SLOT_REUSE_QEMU: PASS" || echo "STORE_SLOT_REUSE_QEMU: FAIL"

if [[ "${fail}" == 0 && "${integration_pass}" == 1 && "${crash_pass}" == 1 && "${reopen_pass}" == 1 && "${slot_pass}" == 1 ]]; then
    echo "STORE_V1_QEMU: PASS"
else
    echo "STORE_V1_QEMU: NOT EARNED"
    echo "P3_STORE_QEMU: NOT CLAIMED (QEMU campaign; native persistence conditions separate)"
    exit 1
fi
echo "P3_STORE_QEMU: NOT CLAIMED (QEMU campaign; native persistence conditions separate)"
