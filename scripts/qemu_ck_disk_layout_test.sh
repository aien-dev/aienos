#!/usr/bin/env bash
# DISK_LAYOUT gate for the AIENOS C kernel (CK-4, audit row R2 of
# track4-aienos-trust.md): the kernel writes to a disk only inside the one
# partition whose GPT type GUID is the AIENOS type
# 38DAAC89-5EAD-4B40-8B1E-3687A7418061 (native/kernel/dev/disk_part.h), and
# every write goes through the bounds-checked translation layer ck_part_xlate.
# QEMU AArch64 + UEFI (AAVMF) + NVMe, same base invocation as
# scripts/qemu_ck_store_test.sh. QEMU is not hardware: a PASS here qualifies
# nothing physical.
#
# Images (native/kernel/Makefile):
#  - make full: the default (safe) image, booted with an SMMUv3.
#  - make full CK_TEST_DISK_XLATE_BYPASS=1: TEST-ONLY mutation image whose
#    translation layer drops the partition offset and checks only the whole
#    disk's bounds (refused under CK_HARDWARE_STAGING by the Makefile and by
#    an #error in dev/disk_part.h). It must make this gate's positive checks
#    FAIL; it never counts toward a PASS.
# Disk images: native/kernel/tools/ck_gpt_image.c, 64 MiB: protective MBR,
# primary + backup GPT, sentinel-a [1,9) MiB filled, AIENOS [9,57) MiB all
# zero, sentinel-b [57,63) MiB filled.
#
# Positive (default image): one 512 B disk booted twice, one 4096 B disk booted
#   once. Each boot: M1 checks (scripts/lib_ck_m1_checks.sh); "disk: gpt ok"
#   with the AIENOS range the image tool wrote; partition LBA 0 -> disk LBA =
#   partition start; write past the partition end refused; the NVMe rw probe's
#   disk LBA inside the partition; stage store ok and a Store commit; every
#   byte outside the partition unchanged (sha256 with the partition cut out)
#   and the partition itself changed (not all zero any more); no bypass text.
# Hostile (default image, 512 B, each a fresh disk): no-gpt (no protective
#   MBR, no GPT), bad CRC32 on BOTH headers, bad entry-array CRC32 on BOTH
#   arrays, AIENOS partition ending past the disk, no AIENOS partition. Each:
#   the host tool's own parser run ("ck_gpt_image find") refuses with the same
#   reason; the kernel prints "disk: no AIENOS partition, refusing writes
#   (gpt: <reason>, ...)", no "disk: gpt ok", no rw probe, the Store is
#   refused with no boot disk, and the whole image sha256 is unchanged.
#   Firmware caveat: EDK2/AAVMF PartitionDxe may repair a GPT when only ONE
#   copy is bad (it rewrites it from the good copy), so the QEMU hostile images
#   corrupt both copies. Single-copy corruption (bad primary CRC alone, bad
#   primary entries alone, bad backup header or entries alone) is covered
#   without firmware by the host test dev/tests/disk_part_test.c
#   (make -C native/kernel stage-test).
# Mutation: the bypass image on a fresh good 512 B disk must announce itself
#   and must FAIL the positive checks (its translation self-check reports
#   "NOT REFUSED", so the Store is never reached); the default image file must
#   not contain the bypass warning text.
#
# Takes the machine quiet flag itself like qemu_ck_store_test.sh
# (AIENOS_QUIET_FLAG / AIENOS_QUIET_TAG). Any QEMU exit status other than 0
# fails (via the M1 checks). Final line: AIENOS_CK_DISK_LAYOUT:
# PASS|FAIL|NOT_RUN. Needs qemu-system-aarch64 and AAVMF.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

verdicts() { echo "AIENOS_CK_DISK_LAYOUT: $1"; }
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; verdicts NOT_RUN; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; verdicts NOT_RUN; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel"
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" full CK_TEST_DISK_XLATE_BYPASS=1 >/dev/null
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" full >/dev/null
make -s -C native/kernel OUT="${out}" gpt-image >/dev/null
gpt_tool="${out}/host/ck_gpt_image"
safe_efi="${out}/full/BOOTAA64.EFI"
bypass_efi="${out}/full-test-xlate-bypass/BOOTAA64.EFI"

# Machine quiet flag: one heavy run at a time on the Spark.
quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_disk_layout_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    verdicts NOT_RUN
    exit 3
fi
own_flag=1
release_flag() {
    if [[ "${own_flag}" == 1 ]]; then
        own_flag=0
        if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
    fi
}
top="$(mktemp -d)"
cleanup() {
    rm -rf "${top}"
    release_flag
}
trap cleanup EXIT

# shellcheck source=scripts/lib_ck_m1_checks.sh
source "${repo_root}/scripts/lib_ck_m1_checks.sh"
mib=64
gate_fail=0
fail_into_gate() { if [[ "${failed}" != 0 ]]; then gate_fail=1; fi; failed=0; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

# new_disk IMG BS LAYOUT [CORRUPTION...]: create it; sets part_first/part_last
# (the AIENOS range as WRITTEN by the tool; 0 0 when the layout has none).
new_disk() {
    local img="$1" bs="$2" lay="$3" l re='^gpt_image bs=[0-9]+ blocks=[0-9]+ aienos_first_lba=([0-9]+) aienos_last_lba=([0-9]+)$'
    shift 3
    l=$("${gpt_tool}" create "${img}" "${bs}" "${mib}" "${lay}" "$@") || l=""
    if [[ "${l}" =~ ${re} ]]; then part_first="${BASH_REMATCH[1]}"; part_last="${BASH_REMATCH[2]}"
    else echo "FAIL  GPT disk image ${lay} not created (${l})"; part_first=0; part_last=0; gate_fail=1; fi
}
# outside_sha IMG BS: sha256 of the image with the AIENOS partition cut out.
outside_sha() {
    { head -c $(( part_first * $2 )) "$1"; tail -c +$(( (part_last + 1) * $2 + 1 )) "$1"; } | sha256sum | cut -d' ' -f1
}
# inside_sha IMG BS: sha256 of the AIENOS partition bytes only.
inside_sha() {
    # head reads the file itself and tail drains all of head's output, so no
    # producer is cut off early (a "tail | head" pipe dies of SIGPIPE under pipefail).
    head -c $(( (part_last + 1) * $2 )) "$1" | tail -c $(( (part_last - part_first + 1) * $2 )) | sha256sum | cut -d' ' -f1
}
# zero_sha BS: sha256 of an all-zero AIENOS partition of the current size.
zero_sha() {
    head -c $(( (part_last - part_first + 1) * $1 )) /dev/zero | sha256sum | cut -d' ' -f1
}

# boot <name> <efi> <disk image> <block bytes>: one QEMU boot with an SMMUv3;
# leaves the serial text in ${work}/serial.txt and the exit status in
# qemu_status, then runs the M1 checks (into failed).
boot() {
    work="${top}/$1"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    local nvme_dev="nvme,drive=nvme0,serial=aienos-disk-layout"
    [[ "$4" == 512 ]] || nvme_dev="${nvme_dev},logical_block_size=$4,physical_block_size=$4"
    set +e
    # Issue #61: single-threaded TCG (see qemu_boot_test.sh).
    timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="$3" \
        -device "${nvme_dev}" \
        -device ramfb -display none -nic none \
        -serial file:"${work}/serial.log" -no-reboot
    qemu_status=$?
    set -e
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_disk_layout_$1.log"
    echo "== boot $1: qemu exit ${qemu_status}"
    failed=0
    ck_m1_checks
}

# positive_checks BS IMG OUTSIDE_REF ZERO_INSIDE_REF FIRST_BOOT(1|0): the
# partition-aware footprint on a good disk. Sets failed=1 on any failure.
positive_checks() {
    local bs="$1" img="$2" oref="$3" zref="$4" first="$5"
    check "GPT parsed (primary+backup CRC32), AIENOS partition found where the image tool wrote it" \
        "^disk: gpt ok primary+backup crc32 entries=128 used=3 aienos_index=1 first_lba=${part_first} last_lba=${part_last} "
    check "partition LBA 0 translates to the partition start" "^disk: xlate part_lba=0 -> disk_lba=${part_first} (rc=0)$"
    check "write past the partition end refused by the translation layer" \
        "^disk: write past partition end part_lba=[0-9]* -> refused "
    check_absent "no AIENOS-partition refusal on the good disk" "disk: no AIENOS partition"
    local pre='^nvme: rw probe part_lba=([0-9]+) disk_lba=([0-9]+) bytes=4096 write\+flush\+readback match \(rc=0\)$'
    local pl; pl=$(grep -E "${pre}" "${work}/serial.txt" | tail -1 || true)
    if [[ "${pl}" =~ ${pre} ]] && (( BASH_REMATCH[2] == BASH_REMATCH[1] + part_first )) \
        && (( BASH_REMATCH[2] >= part_first && BASH_REMATCH[2] + 4096 / bs - 1 <= part_last )); then
        echo "PASS  rw probe landed inside the AIENOS partition (disk_lba ${BASH_REMATCH[2]})"
    else
        echo "FAIL  rw probe not inside [${part_first},${part_last}] or not matched (${pl:-no line})"; failed=1
    fi
    check "NVMe bound by the devices stage" "devices: pci=ok nvme=bound"
    check "stage devices ok" "stage devices: ok"
    check "stage store ok" "stage store: ok"
    check_absent "Store not refused" "store: REFUSED"
    check "Store committed a generation on the partition" "^store: committed generation=[0-9]* boot_count=[0-9]*$"
    if [[ "${first}" == 1 ]]; then
        check "blank partition formatted as a TEST store" "store: blank disk (all-zero anchor + Store head): formatted TEST store"
    else
        check_absent "existing Store on the partition not reformatted" "formatted TEST store"
    fi
    local now; now=$(outside_sha "${img}" "${bs}")
    [[ "${now}" == "${oref}" ]] && echo "PASS  MBR, primary+backup GPT and both sentinel partitions byte-identical" \
        || { echo "FAIL  bytes outside the AIENOS partition changed (${oref:0:16} -> ${now:0:16})"; failed=1; }
    now=$(inside_sha "${img}" "${bs}")
    [[ "${now}" != "${zref}" ]] && echo "PASS  the AIENOS partition itself was written" \
        || { echo "FAIL  the AIENOS partition is still all zero"; failed=1; }
}

# --- Positive -------------------------------------------------------------
for bs in 512 4096; do
    image="${top}/good-${bs}.img"
    new_disk "${image}" "${bs}" aienos-middle
    oref=$(outside_sha "${image}" "${bs}")
    zref=$(zero_sha "${bs}")
    [[ "$(inside_sha "${image}" "${bs}")" == "${zref}" ]] || { echo "FAIL  fresh AIENOS partition not all zero"; gate_fail=1; }
    nboots=1; [[ "${bs}" == 512 ]] && nboots=2
    for (( k = 1; k <= nboots; k++ )); do
        boot "good-${bs}-boot${k}" "${safe_efi}" "${image}" "${bs}"
        positive_checks "${bs}" "${image}" "${oref}" "${zref}" "$(( k == 1 ))"
        check_absent "no translation-bypass text in this image" "DISK TRANSLATION BYPASS"
        fail_into_gate
    done
done

# --- Hostile --------------------------------------------------------------
# name | layout and corruptions | reason printed by ck_gpt_strerror (dev/disk_part.c)
hostile=(
    "no-gpt|no-gpt|no protective MBR"
    "bad-header-crc|aienos-middle bad-primary-crc bad-backup-crc|primary header CRC32 mismatch"
    "bad-entry-crc|aienos-middle bad-primary-entries bad-backup-entries|entry array CRC32 mismatch"
    "aienos-outside|aienos-outside|partition outside the usable range"
    "no-aienos|no-aienos|no AIENOS partition type"
)
for row in "${hostile[@]}"; do
    IFS='|' read -r name spec reason <<<"${row}"
    image="${top}/hostile-${name}.img"
    # shellcheck disable=SC2086 # spec is a layout plus corruption words
    new_disk "${image}" 512 ${spec}
    host=$("${gpt_tool}" find "${image}" 512 || true)
    [[ "${host}" == "refused: ${reason} rc="* ]] && echo "PASS  host parser refuses ${name}: ${reason}" \
        || { echo "FAIL  host parser on ${name}: expected '${reason}', got '${host}'"; gate_fail=1; }
    before=$(sha "${image}")
    boot "hostile-${name}" "${safe_efi}" "${image}" 512
    check "NVMe LBA 0 read before the GPT decision" "nvme: read lba=0 blocks=1 ok"
    check "${name}: refused, fail closed" "^disk: no AIENOS partition, refusing writes (gpt: ${reason}, rc=-4[0-9][0-9])$"
    check_absent "${name}: no partition accepted" "^disk: gpt ok"
    check_absent "${name}: no rw probe (nothing written)" "nvme: rw probe"
    check "${name}: NVMe not bound" "devices: pci=ok nvme=unbound"
    check "${name}: stage devices fails" "^stage devices: FAIL rc=-4[0-9][0-9]$"
    check "${name}: Store refused without a boot disk" 'store: REFUSED proof=io step="no boot disk"'
    check_absent "${name}: nothing committed" "store: committed"
    after=$(sha "${image}")
    [[ "${after}" == "${before}" ]] && echo "PASS  ${name}: whole image byte-identical after the boot" \
        || { echo "FAIL  ${name}: image changed (${before:0:16} -> ${after:0:16})"; failed=1; }
    fail_into_gate
done

# --- Mutation -------------------------------------------------------------
if grep -qaF "DISK TRANSLATION BYPASS" "${safe_efi}"; then
    echo "FAIL  default image contains the translation-bypass text"; gate_fail=1
else
    echo "PASS  default image has no translation-bypass text"
fi
image="${top}/mutant-512.img"
new_disk "${image}" 512 aienos-middle
oref=$(outside_sha "${image}" 512)
zref=$(zero_sha 512)
boot "mutant-xlate-bypass" "${bypass_efi}" "${image}" 512
check "mutant image announces the TEST-ONLY translation bypass" \
    "WARNING: TEST-ONLY DISK TRANSLATION BYPASS BUILD (CK_TEST_DISK_XLATE_BYPASS=1"
mutant_boot="${failed}"
fail_into_gate
echo "-- positive checks against the mutant (must FAIL):"
positive_checks 512 "${image}" "${oref}" "${zref}" 1
if [[ "${mutant_boot}" == 0 && "${failed}" != 0 ]]; then
    echo "PASS  translation bypass makes DISK_LAYOUT fail (mutant killed)"
else
    echo "FAIL  translation bypass mutant survived the positive checks (or did not boot cleanly)"; gate_fail=1
fi
failed=0

echo
if [[ "${gate_fail}" == 0 ]]; then verdicts PASS; exit 0; fi
verdicts FAIL
exit 1
