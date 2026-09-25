#!/usr/bin/env bash
# QEMU NVMe power-fail atomicity qualification for the System Store root write.
#
# Configures a disposable namespace with a 4096-byte logical block size and
# requires the guest to observe block_size=4096 (lbads=12) with a power-fail
# atomic guarantee covering the single-block Store superblock:
#   NVME_STORE_ROOT_ATOMICITY_QEMU: PASS
#
# This does not weaken the Store contract: the 4096-byte Store unit is one
# logical block on this namespace. It is emulator qualification, not Machine 1
# evidence. Read/write durability markers are not asserted here.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
img_bytes=67108864
lba_bytes=4096
bounds_lba=$(( img_bytes / lba_bytes ))
machine="virt,virtualization=on,gic-version=3,iommu=smmuv3"
target_dir="target/qemu-nvme-atomicity"

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features nvme-write --bin aienos-handoff \
    --target-dir "${target_dir}"

work="$(mktemp -d)"
qemu_pid=""
cleanup() { [[ -n "${qemu_pid}" ]] && kill "${qemu_pid}" 2>/dev/null || true; rm -rf "${work}"; }
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${target_dir}/aarch64-unknown-uefi/release/aienos-handoff.efi" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"

image="${work}/nvme.img"
truncate -s "${img_bytes}" "${image}"
echo "nvme image: ${img_bytes} bytes, ${bounds_lba} x ${lba_bytes} B LBAs"

cp "${vars_fd}" "${work}/vars.fd"
rm -f "${work}/serial.log"
qemu-system-aarch64 \
    -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
    -device virtio-blk-pci,drive=esp \
    -drive if=none,id=nvme0,format=raw,file="${image}" \
    -device nvme,drive=nvme0,serial=aienos-nvme-atomicity,logical_block_size=${lba_bytes},physical_block_size=${lba_bytes} \
    -device ramfb -display none -nic none \
    -serial file:"${work}/serial.log" -no-reboot &
qemu_pid=$!

deadline=$(( $(date +%s) + boot_timeout ))
while (( $(date +%s) < deadline )) && kill -0 "${qemu_pid}" 2>/dev/null; do
    grep -q -- "NVME_STORE_ROOT_ATOMICITY_QEMU" "${work}/serial.log" 2>/dev/null && break
    sleep 0.2
done
kill "${qemu_pid}" 2>/dev/null || true
wait "${qemu_pid}" 2>/dev/null || true

serial="$(tr -d '\r' <"${work}/serial.log" 2>/dev/null || true)"
failed=0
check() { if printf '%s' "${serial}" | grep -q -- "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; failed=1; fi; }

echo "---- observed ----"
printf '%s\n' "${serial}" | grep -E 'NVME_IDENTIFY_QEMU|NVME_GEOMETRY_QEMU|NVME_ATOMICITY_IDENTIFY_QEMU|NVME_STORE_ROOT_ATOMICITY_QEMU' || true
echo "-------------------"
check "controller and namespace identify completed" "NVME_IDENTIFY_QEMU: PASS"
check "namespace geometry is 4096-byte LBA" "NVME_GEOMETRY_QEMU: PASS (nsid=1 block_count=${bounds_lba} block_size=${lba_bytes})"
check "atomicity Identify observed with 4096-byte LBA" "NVME_ATOMICITY_IDENTIFY_QEMU: block_size=${lba_bytes} lbads=12"
check "Store root write is power-fail atomic and boundary-safe" "NVME_STORE_ROOT_ATOMICITY_QEMU: PASS"

[[ "${failed}" == 0 ]] && echo "QEMU_NVME_ATOMICITY_4K: PASS" || { echo "QEMU_NVME_ATOMICITY_4K: FAIL"; exit 1; }
