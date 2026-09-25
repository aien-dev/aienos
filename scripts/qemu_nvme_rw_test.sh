#!/usr/bin/env bash
# P3 native NVMe WRITE + FLUSH durability proof in QEMU (disposable media).
#
# Two boots over ONE raw image file:
#   boot 1  writes a deterministic pattern to a read-write LBA and issues a
#           real NVMe Flush, then the host reads the image file back and checks
#           the exact bytes and SHA-256 (power-off persistence).
#   boot 2  boots again on the same image and reads the target natively; the
#           kernel reports durability across the restart.
#
# Read side (sentinel LBA 2048) is unchanged from scripts/qemu_nvme_test.sh.
# Write side targets LBA 4096 with the 16-byte magic "AIENOS-NVME-RW01" x32.
# The image starts with "AIENOS-NVME-OLD0" x32 there.
#
# DMA rule (M3): no SMMU confinement means no DMA. Mirrors the read harness:
#   default                    QEMU SMMUv3; NVMe DMA only via a translated stream.
#   AIENOS_QEMU_SMMU=0         no SMMU, normal build: NVMe stays unavailable,
#                              no write, bus mastering off (fail-closed).
#
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
#
# scripts/verify_all.sh step 6e runs this harness in both DMA modes.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

attempts="${AIENOS_NVME_ATTEMPTS:-3}"
boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
if [[ "${AIENOS_QEMU_SMMU:-1}" == "1" ]]; then
    mode="smmu"
    machine="virt,virtualization=on,gic-version=3,iommu=smmuv3"
else
    mode="fail-closed"
    machine="virt,virtualization=on,gic-version=3"
fi
target_dir="target/qemu-nvme-rw"

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features nvme-write --bin aienos-handoff \
    --target-dir "${target_dir}"

work="$(mktemp -d)"
qemu_pid=""
cleanup() {
    [[ -n "${qemu_pid}" ]] && kill "${qemu_pid}" 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    rm -rf "${work}"
}
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${target_dir}/aarch64-unknown-uefi/release/aienos-handoff.efi" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"

# ---------------------------------------------------------------------------
# Disposable media. 64 MiB raw, 131072 LBAs of 512 bytes.
#   sentinel (read)  LBA 2048 : "AIENOS-NVME-SENT" x32
#   rw target        LBA 4096 : "AIENOS-NVME-OLD0" x32  (host seed)
#   written pattern  LBA 4096 : "AIENOS-NVME-RW01" x32  (guest write)
#   bounds write     LBA 131072 (== block_count), must be rejected OutOfRange
#   write error      NSID 0xffffffff, must return a nonzero completion status
# ---------------------------------------------------------------------------
img_bytes=67108864
lba_bytes=512
sentinel_lba=2048
rw_lba=4096
bounds_lba=$(( img_bytes / lba_bytes ))

pattern() { # magic -> 512-byte file
    local out="$1" magic="$2"
    : > "${out}"
    for _ in {1..32}; do printf '%s' "${magic}" >> "${out}"; done
    [[ "$(wc -c <"${out}")" == "512" ]] || { echo "STOP: payload must be 512 bytes"; exit 2; }
}

image="${work}/nvme.img"
pattern "${work}/sentinel.bin" 'AIENOS-NVME-SENT'
pattern "${work}/old.bin" 'AIENOS-NVME-OLD0'
pattern "${work}/new.bin" 'AIENOS-NVME-RW01'
sentinel_sha="$(sha256sum "${work}/sentinel.bin" | cut -d' ' -f1)"
old_sha="$(sha256sum "${work}/old.bin" | cut -d' ' -f1)"
new_sha="$(sha256sum "${work}/new.bin" | cut -d' ' -f1)"

truncate -s "${img_bytes}" "${image}"
dd if="${work}/sentinel.bin" of="${image}" bs="${lba_bytes}" seek="${sentinel_lba}" conv=notrunc status=none
dd if="${work}/old.bin" of="${image}" bs="${lba_bytes}" seek="${rw_lba}" conv=notrunc status=none
[[ "$(dd if="${image}" bs="${lba_bytes}" skip="${rw_lba}" count=1 status=none | sha256sum | cut -d' ' -f1)" == "${old_sha}" ]] \
    || { echo "STOP: OLD seed not at LBA ${rw_lba}"; exit 2; }

echo "nvme image: ${img_bytes} bytes, ${bounds_lba} x ${lba_bytes} B LBAs"
echo "sentinel LBA ${sentinel_lba} sha256 ${sentinel_sha}"
echo "rw old   LBA ${rw_lba} sha256 ${old_sha}"
echo "rw new   LBA ${rw_lba} sha256 ${new_sha}"

serial_has() { tr -d '\r' 2>/dev/null <"${work}/serial.log" | grep -q -- "$1"; }
qemu_running() { kill -0 "${qemu_pid}" 2>/dev/null; }
wait_for() { # seconds, pattern...
    local deadline=$(( $(date +%s) + $1 )); shift
    while (( $(date +%s) < deadline )) && qemu_running; do
        for p in "$@"; do serial_has "${p}" && return 0; done
        sleep 0.2
    done
    for p in "$@"; do serial_has "${p}" && return 0; done
    return 1
}
stop_qemu() {
    if [[ -n "${qemu_pid}" ]]; then
        kill "${qemu_pid}" 2>/dev/null || true
        wait "${qemu_pid}" 2>/dev/null || true
    fi
    qemu_pid=""
    exec 3>&- 2>/dev/null || true
}

# One boot against the shared image. $1 is the terminal marker to wait for.
boot_once() {
    cp "${vars_fd}" "${work}/vars.fd"
    rm -f "${work}/serial.log"
    qemu-system-aarch64 \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${image}" \
        -device nvme,drive=nvme0,serial=aienos-nvme-rw-test \
        -device ramfb -display none -nic none \
        -serial file:"${work}/serial.log" -no-reboot &
    qemu_pid=$!

    if ! wait_for "${boot_timeout}" "report_kind: pre_exit"; then
        echo "no AIENOS output within ${boot_timeout} s (firmware hang, issue #61)"
        stop_qemu
        return 2
    fi
    wait_for "${boot_timeout}" "$1" "report_kind: panic" "report_kind: fault" || true
    local deadline=$(( $(date +%s) + 20 ))
    while qemu_running && (( $(date +%s) < deadline )); do sleep 0.5; done
    stop_qemu
    return 0
}

started=$(date +%s)
if [[ "${mode}" == "smmu" ]]; then
    terminal="NVME_WRITE_ERROR_QEMU"
else
    terminal="nvme: unavailable (SMMU DMA isolation not active)"
fi
attempt=1
while :; do
    status=0
    boot_once "${terminal}" || status=$?
    [[ "${status}" != 2 || "${attempt}" -ge "${attempts}" ]] && break
    attempt=$(( attempt + 1 ))
done
elapsed=$(( $(date +%s) - started ))
tr -d '\r' <"${work}/serial.log" >"${work}/serial_boot1.txt" 2>/dev/null || true

# boot 2: same image, expect persistence across the restart.
if [[ "${mode}" == "smmu" ]]; then
    boot_once "NVME_DURABILITY_QEMU" || true
    tr -d '\r' <"${work}/serial.log" >"${work}/serial_boot2.txt" 2>/dev/null || true
fi

[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial_boot1.txt" "${AIENOS_LOG_DIR}/qemu_nvme_rw_serial.log" 2>/dev/null || true
boot1="${work}/serial_boot1.txt"
failed=0
check() { if grep -q -- "$2" "${boot1}"; then echo "PASS  $1"; else echo "FAIL  $1"; failed=1; fi; }
check_absent() { if grep -q -- "$2" "${boot1}"; then echo "FAIL  $1"; failed=1; else echo "PASS  $1"; fi; }

if [[ "${mode}" == "smmu" ]]; then
    check "ECAM discovery found the NVMe class device" "NVME_DISCOVERY_QEMU: PASS"
    check "controller and namespace identify completed" "NVME_IDENTIFY_QEMU: PASS"
    check "namespace geometry matches the image" "NVME_GEOMETRY_QEMU: PASS (nsid=1 block_count=${bounds_lba} block_size=${lba_bytes})"
    check "NVMe power-fail atomicity fields observed" "NVME_ATOMICITY_IDENTIFY_QEMU:"
    if grep -q -- "NVME_STORE_ROOT_ATOMICITY_QEMU: PASS" "${boot1}"; then
        echo "PASS  Store root-write power-fail atomicity satisfied"
    else
        echo "INFO  Store root-write power-fail atomicity NOT proven on this namespace"
        grep -o -- "NVME_ATOMICITY_IDENTIFY_QEMU:.*" "${boot1}" | head -1 | sed 's/^/INFO  /' || true
        grep -o -- "NVME_STORE_ROOT_ATOMICITY_QEMU:.*" "${boot1}" | head -1 | sed 's/^/INFO  /' || true
    fi
    check "read sentinel LBA returned exact bytes and SHA-256" "NVME_READ_QEMU: PASS (lba=${sentinel_lba} blocks=1 bytes=512 sha256=${sentinel_sha})"
    check "read past the namespace end is rejected" "NVME_BOUNDS_QEMU: PASS"
    check "device-reported read error is surfaced" "NVME_ERROR_QEMU: PASS"
    check "write past the namespace end is rejected" "NVME_WRITE_BOUNDS_QEMU: PASS"
    check "native write returned exact bytes and SHA-256" "NVME_WRITE_QEMU: PASS (lba=${rw_lba} blocks=1 bytes=512 sha256=${new_sha})"
    check "native flush completed" "NVME_FLUSH_QEMU: PASS"
    check "write then flush then read-back matched" "NVME_DURABILITY_QEMU: PASS (lba=${rw_lba} blocks=1 bytes=512 sha256=${new_sha})"
    check "invalid-namespace write surfaced a device error" "NVME_WRITE_ERROR_QEMU: PASS"
    check "IORT stream configured for NVMe DMA" "smmu: enabled"
    check "NVMe DMA granted only as confined" "dma_gate: nvme granted (Confined), bus master on"
    check "NVMe bus master revoked after the phase" "dma_gate: nvme bus master revoked"

    # Host persistence check: the image file must now hold the written pattern.
    host_sha="$(dd if="${image}" bs="${lba_bytes}" skip="${rw_lba}" count=1 status=none | sha256sum | cut -d' ' -f1)"
    if [[ "${host_sha}" == "${new_sha}" ]]; then
        echo "PASS  host read-back after power off equals the written bytes"
    else
        echo "FAIL  host read-back ${host_sha} != written ${new_sha}"
        failed=1
    fi

    # Boot 2: the kernel must observe the persisted pattern natively.
    if grep -q -- "NVME_DURABILITY_QEMU: PASS (persisted lba=${rw_lba}" "${work}/serial_boot2.txt" 2>/dev/null; then
        echo "PASS  restart read-back observed the persisted pattern natively"
    else
        echo "FAIL  restart read-back did not observe the persisted pattern"
        failed=1
    fi
else
    check "discovery found the device before the DMA gate" "NVME_DISCOVERY_QEMU: PASS"
    check "NVMe DMA denied without an SMMU" "dma_gate: nvme denied (NoSmmu), bus master stays off"
    check "NVMe controller fail-closed without an SMMU" "nvme: unavailable (SMMU DMA isolation not active)"
    check_absent "no write marker without DMA" "NVME_WRITE_QEMU: PASS"
    check_absent "no flush marker without DMA" "NVME_FLUSH_QEMU: PASS"
    check_absent "no durability marker without DMA" "NVME_DURABILITY_QEMU: PASS"
fi
if grep -qE "report_kind: (panic|fault)" "${boot1}"; then
    echo "FAIL  panic or fault reported (boot 1)"
    failed=1
fi
if [[ -f "${work}/serial_boot2.txt" ]] && grep -qE "report_kind: (panic|fault)" "${work}/serial_boot2.txt"; then
    echo "FAIL  panic or fault reported (boot 2)"
    failed=1
fi

if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console (boot 1) ----"
    cat "${boot1}"
    [[ -f "${work}/serial_boot2.txt" ]] && { echo "---- serial console (boot 2) ----"; cat "${work}/serial_boot2.txt"; }
fi
[[ "${failed}" == 0 ]] && echo "QEMU_NVME_RW: PASS (${mode})" || { echo "QEMU_NVME_RW: FAIL (${mode})"; exit 1; }
