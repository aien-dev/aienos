#!/usr/bin/env bash
# P3 native NVMe read substrate proof in QEMU (read-only qualification).
#
# Boot the handoff image built with the `nvme-read` feature with a raw,
# disposable NVMe namespace attached as
#   -drive if=none,id=nvme0,... -device nvme,drive=nvme0,serial=aienos-nvme-test
# and let the native AIENOS driver drive the controller directly after
# ExitBootServices: ECAM discovery, BAR0 MMIO, polled admin/I/O queues, and a
# read of a deterministic sentinel LBA. The host builds the same sentinel and
# checks the exact bytes and SHA-256 the kernel reports.
#
# Read-only: the driver only issues Identify and Read commands. No media write,
# flush, format or namespace-management command is claimed or exercised.
#
# DMA rule (M3): no SMMU confinement means no DMA. Mirrors
# scripts/qemu_keyboard_test.sh:
#   default                    QEMU SMMUv3 (iommu=smmuv3); the NVMe function
#                              gets DMA only through a translated stream.
#   AIENOS_QEMU_SMMU=0         no SMMU, normal build: the controller must stay
#                              unavailable with bus mastering off (fail-closed).
#   AIENOS_UNSAFE_DMA_BYPASS=1 no SMMU, UNSAFE debug build that lets the NVMe
#                              function DMA to physical memory unconfined.
#                              QEMU debugging only; never part of verify_all.sh.
#
# A boot that shows no AIENOS output at all is retried (firmware hang before
# AIENOS runs, issue #61); any failure after AIENOS output fails at once.
#
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
#
# NOTE: scripts/verify_all.sh is intentionally NOT edited here. Wiring this
# harness into verify_all.sh (a dedicated QEMU step plus the aarch64 clippy
# feature loop in step 3b) is a follow-up change owned by the integration
# lane.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

attempts="${AIENOS_NVME_ATTEMPTS:-3}"
boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
machine="virt,virtualization=on,gic-version=3"

# DMA mode (M3 rule: no SMMU confinement means no DMA), as in qemu_keyboard_test.sh.
bypass_feature="unsafe-debug-nvme-dma-without-smmu"
if [[ "${AIENOS_UNSAFE_DMA_BYPASS:-0}" == "1" ]]; then
    mode="unsafe-bypass"
    default_features="nvme-read,${bypass_feature}"
    target_dir="target/qemu-nvme-unsafe-dma-bypass"
    echo "################################################################"
    echo "WARNING: AIENOS_UNSAFE_DMA_BYPASS=1: building ${bypass_feature}."
    echo "WARNING: NVMe DMA runs WITHOUT SMMU confinement. QEMU debug only."
    echo "WARNING: this run proves nothing about DMA isolation."
    echo "################################################################"
elif [[ "${AIENOS_QEMU_SMMU:-1}" == "1" ]]; then
    mode="smmu"
    machine+=",iommu=smmuv3"
    default_features="nvme-read"
    target_dir="target/qemu-nvme"
else
    mode="fail-closed"
    default_features="nvme-read"
    target_dir="target/qemu-nvme"
fi
features="${AIENOS_BUILD_FEATURES:-$default_features}"
if [[ "${mode}" != "unsafe-bypass" && ",${features}," == *",${bypass_feature},"* ]]; then
    echo "STOP: ${bypass_feature} requested without AIENOS_UNSAFE_DMA_BYPASS=1"
    exit 2
fi

# Own target directory: an NVMe-enabled image never lands where hardware
# staging or the other tests pick up the handoff image.
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features "${features}" --bin aienos-handoff \
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
# Deterministic, disposable raw NVMe image (64 MiB), built with the same
# tools the repo already uses (dd / od / printf / truncate / sha256sum).
#
# Geometry:
#   image      : 64 MiB = 67108864 bytes = 131072 LBAs of 512 bytes
#   sentinel   : LBA 2048 (offset 1048576), one 512-byte block
#   payload    : the 16-byte magic "AIENOS-NVME-SENT" repeated 32 times
#   bounds LBA : 131072 (== block_count), must be rejected OutOfRange
# ---------------------------------------------------------------------------
magic='AIENOS-NVME-SENT'
img_bytes=67108864
lba_bytes=512
sent_lba=2048
sent_offset=$(( sent_lba * lba_bytes ))
bounds_lba=$(( img_bytes / lba_bytes ))

image="${work}/nvme.img"
sentinel="${work}/sentinel.bin"
# 16 bytes * 32 = 512 bytes, exactly one LBA, no newline.
: > "${sentinel}"
for _ in {1..32}; do printf '%s' "${magic}" >> "${sentinel}"; done
[[ "$(wc -c <"${sentinel}")" == "512" ]] || { echo "STOP: sentinel must be exactly 512 bytes"; exit 2; }
# Sparse zero image of the exact namespace size, then drop the sentinel block in.
truncate -s "${img_bytes}" "${image}"
dd if="${sentinel}" of="${image}" bs="${lba_bytes}" seek="${sent_lba}" conv=notrunc status=none
[[ "$(wc -c <"${image}")" == "${img_bytes}" ]] || { echo "STOP: NVMe image is not ${img_bytes} bytes"; exit 2; }

sentinel_sha="$(sha256sum "${sentinel}")"
sentinel_sha="${sentinel_sha%% *}"
readback_sha="$(dd if="${image}" bs="${lba_bytes}" skip="${sent_lba}" count=1 status=none | sha256sum)"
readback_sha="${readback_sha%% *}"
if [[ "${readback_sha}" != "${sentinel_sha}" ]]; then
    echo "STOP: sentinel block was not written at LBA ${sent_lba} (offset ${sent_offset})"
    exit 2
fi
echo "nvme image: ${img_bytes} bytes, ${bounds_lba} x ${lba_bytes} B LBAs"
echo "sentinel: LBA ${sent_lba} offset ${sent_offset}, magic '${magic}' x32, sha256 ${sentinel_sha}"

serial_has() { tr -d '\r' 2>/dev/null <"${work}/serial.log" | grep -q -- "$1"; }
qemu_running() { kill -0 "${qemu_pid}" 2>/dev/null; }

# Wait until the serial log contains one of the patterns or QEMU exits.
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

boot_once() {
    cp "${vars_fd}" "${work}/vars.fd"
    rm -f "${work}/serial.log" "${work}/mon.in" "${work}/mon.out"
    mkfifo "${work}/mon.in" "${work}/mon.out"
    # Single-threaded TCG: multi-threaded TCG intermittently loses the
    # firmware's timer wake-up and hangs before AIENOS output (#61).
    local -a smmu_trace=()
    if [[ "${AIENOS_QEMU_SMMU_TRACE:-0}" == "1" ]]; then
        smmu_trace=(-d unimp,guest_errors -trace "smmuv3_*")
    fi
    # The NVMe namespace is a fresh image rebuilt above for every run; QEMU
    # only ever sees reads from the guest driver.
    qemu-system-aarch64 \
        "${smmu_trace[@]}" \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${image}" \
        -device nvme,drive=nvme0,serial=aienos-nvme-test \
        -device ramfb -display none -nic none \
        -chardev pipe,id=mon,path="${work}/mon" -mon chardev=mon,mode=readline \
        -serial file:"${work}/serial.log" -no-reboot &
    qemu_pid=$!
    # Drain monitor output so QEMU never blocks writing it.
    cat "${work}/mon.out" >/dev/null &
    exec 3>"${work}/mon.in"

    if ! wait_for "${boot_timeout}" "report_kind: pre_exit"; then
        echo "attempt ${attempt}: no AIENOS output within ${boot_timeout} s (firmware hang, issue #61)"
        stop_qemu
        return 2
    fi
    # The native NVMe phase runs after the final report, so the last marker is
    # the terminal signal; a panic or fault also ends the phase.
    wait_for "${boot_timeout}" "NVME_ERROR_QEMU: PASS" "report_kind: panic" "report_kind: fault" || true
    local deadline=$(( $(date +%s) + 30 ))
    while qemu_running && (( $(date +%s) < deadline )); do sleep 0.5; done
    qemu_running && echo "QEMU still running after the NVMe phase"
    stop_qemu
    return 0
}

started=$(date +%s)
attempt=1
while :; do
    status=0
    boot_once || status=$?
    [[ "${status}" != 2 || "${attempt}" -ge "${attempts}" ]] && break
    attempt=$(( attempt + 1 ))
done
elapsed=$(( $(date +%s) - started ))

tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt" 2>/dev/null || true
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_nvme_serial.log" 2>/dev/null || true
failed=0
check() { # description, pattern
    if grep -q -- "$2" "${work}/serial.txt"; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        failed=1
    fi
}
check_absent() { # description, pattern
    if grep -q -- "$2" "${work}/serial.txt"; then
        echo "FAIL  $1"
        failed=1
    else
        echo "PASS  $1"
    fi
}
echo "attempts ${attempt}, ${elapsed} s (commit ${commit:0:12}), dma mode ${mode}"

# The six required native read markers. They must only appear once the
# NVMe function has been granted DMA; in fail-closed mode they must be absent.
if [[ "${mode}" != "fail-closed" ]]; then
    check "ECAM discovery found the NVMe class device" "NVME_DISCOVERY_QEMU: PASS"
    check "controller and namespace identify completed" "NVME_IDENTIFY_QEMU: PASS"
    check "namespace geometry matches the image" \
        "NVME_GEOMETRY_QEMU: PASS (nsid=1 block_count=${bounds_lba} block_size=${lba_bytes})"
    check "sentinel LBA read back exact bytes and SHA-256" \
        "NVME_READ_QEMU: PASS (lba=${sent_lba} blocks=1 bytes=512 sha256=${sentinel_sha})"
    check "read past the namespace end is rejected before any command" "NVME_BOUNDS_QEMU: PASS"
    check "device-reported command error is surfaced" "NVME_ERROR_QEMU: PASS"
fi

if [[ "${mode}" == "fail-closed" ]]; then
    check "discovery found the device before the DMA gate" "NVME_DISCOVERY_QEMU: PASS"
    check "NVMe DMA denied without an SMMU" "dma_gate: nvme denied (NoSmmu), bus master stays off"
    check "NVMe controller fail-closed without an SMMU" "nvme: unavailable (SMMU DMA isolation not active)"
    check_absent "NVMe controller never granted DMA" "dma_gate: nvme granted"
    check_absent "NVMe controller never identified" "NVME_IDENTIFY_QEMU"
    check_absent "NVMe read never ran" "NVME_READ_QEMU"
else
    if [[ "${mode}" == "smmu" ]]; then
        check "IORT stream configured for NVMe DMA" "smmu: enabled"
        check "NVMe DMA window translated" "smmu_dma_window: nvme only, translation active"
        check "NVMe DMA granted only as confined" "dma_gate: nvme granted (Confined), bus master on"
    else
        check "unsafe bypass build announced on serial" "WARNING: UNSAFE NVME DMA BYPASS BUILD"
        check "unsafe bypass grant announced on serial" "WARNING: UNSAFE NVME DMA BYPASS ACTIVE"
        check "NVMe DMA granted through the unsafe bypass" "dma_gate: nvme granted (UnsafeBypass)"
    fi
    check "NVMe bus master revoked after the read phase" "dma_gate: nvme bus master revoked"
fi
if [[ "${mode}" != "unsafe-bypass" ]]; then
    check_absent "no unsafe DMA bypass in this image" "UNSAFE NVME DMA BYPASS"
fi
if grep -qE "report_kind: (panic|fault)" "${work}/serial.txt"; then
    echo "FAIL  panic or fault reported"
    failed=1
fi

if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"
    cat "${work}/serial.txt"
fi
if [[ "${mode}" == "unsafe-bypass" ]]; then
    echo "WARNING: this was an UNSAFE NVME DMA BYPASS run (no SMMU confinement)."
fi
[[ "${failed}" == 0 ]] && echo "QEMU_NVME: PASS (${mode})" || { echo "QEMU_NVME: FAIL (${mode})"; exit 1; }
