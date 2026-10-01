#!/usr/bin/env bash
# Store gate for the AIENOS C kernel (Lane 18): boots the full C image (core +
# devices, security and Store stages) in QEMU AArch64 with UEFI (AAVMF) and an
# NVMe disk, using the base QEMU invocation of scripts/qemu_boot_test.sh plus
# the NVMe device flags of the Rust NVMe/Store QEMU tests. QEMU is not
# hardware: a PASS here qualifies nothing physical.
#
# Images (native/kernel/Makefile):
#  - make full: the default build. With an SMMUv3 (QEMU iommu=smmuv3, found
#    through the ACPI IORT) the NVMe stream is confined to its DMA window
#    (boots 1-4); without one NVMe DMA must be refused (boot 5).
#  - make full CK_QEMU_UNSAFE_DMA=1: TEST-ONLY build with the unconfined NVMe
#    DMA bypass, kept so the bypass path stays honest (boot 6 only).
#
# Per NVMe geometry (512 B blocks like qemu_nvme_test.sh, 4 KiB blocks like
# qemu_store_crash_test.sh / qemu_continuity_test.sh), on one fresh 64 MiB
# all-zero disk image:
#  boots 1-3  same image each time. Every boot must pass all M1 checks
#             (scripts/lib_ck_m1_checks.sh, the same checks as
#             qemu_ck_boot_test.sh), stage devices/security/store ok, the NVMe
#             observables, the caps and argus narrow-revoke lines, and the
#             Store line: boot_count 1,2,3; committed generation strictly
#             increasing (and each boot opens the previous boot's generation);
#             prev_commit=none on boot 1 and this commit on boots 2 and 3.
#  boot 4     after XOR 0xa5 over the first 2 x 4096 bytes of the Store region
#             (the Store superblock; same corruption as svc/tests/stage_test.c):
#             must be refused as proof=structural with nothing committed, and
#             the image sha256 must be the same before and after the boot.
#  boot 5     default image, no SMMU, same disk: NVMe DMA denied, no
#             unsafe-bypass text, Store refused (no disk), image unchanged.
#  boot 6     TEST-ONLY bypass image, no SMMU, same (corrupt) disk: the bypass
#             warnings and grant are printed, the Store is still refused as
#             structural and the image is unchanged.
# SMMU observables (boots 1-4; patterns of qemu_nvme_test.sh where the Rust
# kernel has them): "smmu: enabled", "smmu_dma_window: nvme only, translation
# active", "dma_gate: nvme granted (Confined), bus master on", absent
# "UNSAFE NVME DMA BYPASS"; C only (differs): "smmu_negative: refused dma
# outside window ... page=intact ... recovery_read=ok" (the controller is
# pointed at a page outside the window, the SMMU must report a translation
# fault for exactly that page and the page must be unchanged) and "smmu: nvme
# stream 0x.. returned to abort" after the bus master is revoked.
#
# Patterns copied verbatim from the Rust scripts (qemu_nvme_test.sh):
#   "WARNING: UNSAFE NVME DMA BYPASS BUILD", "WARNING: UNSAFE NVME DMA BYPASS
#   ACTIVE", "dma_gate: nvme granted (UnsafeBypass)", "dma_gate: nvme bus
#   master revoked", "dma_gate: nvme denied (NoSmmu), bus master stays off",
#   "nvme: unavailable (SMMU DMA isolation not active)", absent "dma_gate: nvme
#   granted" and absent "UNSAFE NVME DMA BYPASS" in the safe image, and
#   "report_kind: (panic|fault)" (via the M1 checks).
# Patterns that differ (the C kernel prints its own line format; the Rust
#   NVME_*_QEMU and STORE_* marker lines have no C equivalent):
#   "nvme: discovery " (Rust NVME_DISCOVERY_QEMU), "nvme: identify ok "
#   (NVME_IDENTIFY_QEMU), "nvme: geometry nsid=1 block_count=N block_size=B"
#   (NVME_GEOMETRY_QEMU, same values), "nvme: bounds read lba=N -> refused"
#   (NVME_BOUNDS_QEMU), "nvme: read lba=0 blocks=1 ok" and "nvme: rw probe ...
#   match" (NVME_READ_QEMU reads a host sentinel; the C kernel reads LBA 0 and
#   write/flush/reads back then restores its scratch unit), "devices: pci=ok
#   nvme=bound", "stage <name>: ok|FAIL", "store: ..." lines, "caps: ok ..."
#   and "argus: ok narrow_revoke=1 ...". The Rust NVME_ERROR_QEMU check (a
#   device-reported command error) has no C counterpart and is not run.
# Boots 1-4 add iommu=smmuv3 to the machine like the Rust Store scripts.
# NVMe shutdown (C-only gate, no Rust counterpart): on every boot where the
# NVMe bus master was on (boots 1-4 and 6) the kernel must print exactly one
# "nvme: shutdown normal cc=..->.. csts=.. shst=complete" line with CC.SHN read
# back as 01b and CSTS.SHST as 10b, before "dma_gate: nvme bus master
# revoked"; QEMU's own trace (pci_nvme_mmio_shutdown_set, pci_cfg_write) must
# show the shutdown landing between the BME set and BME clear writes. Boot 5
# must show no shutdown. Every boot must show the ck_reset quiesce hook.
#
# Takes the machine quiet flag itself like qemu_ck_boot_test.sh
# (AIENOS_QUIET_FLAG / AIENOS_QUIET_TAG; released at most once, only if it
# still holds exactly this run's text). Any QEMU exit status other than 0 fails.
# Final lines: AIENOS_CK_M4_NVME, AIENOS_CK_M4_STORE, AIENOS_CK_ARGUS1_REVOKE,
# AIENOS_CK_SMMU, AIENOS_CK_NVME_SHUTDOWN, each PASS|FAIL|NOT_RUN. A boot that
# fails an M1 check fails all five.
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

verdicts() { # one value for all three
    echo "AIENOS_CK_M4_NVME: $1"
    echo "AIENOS_CK_M4_STORE: $1"
    echo "AIENOS_CK_ARGUS1_REVOKE: $1"
    echo "AIENOS_CK_SMMU: $1"
    echo "AIENOS_CK_NVME_SHUTDOWN: $1"
}
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; verdicts NOT_RUN; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; verdicts NOT_RUN; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel"
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" full CK_QEMU_UNSAFE_DMA=1 >/dev/null
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" full >/dev/null
unsafe_efi="${out}/full-qemu-unsafe-dma/BOOTAA64.EFI"
safe_efi="${out}/full/BOOTAA64.EFI"

# Machine quiet flag: one heavy run at a time on the Spark.
quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_store_test $$}"
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
printf '%s\n' pci_nvme_mmio_shutdown_set pci_nvme_mmio_shutdown_cleared pci_cfg_write >"${top}/trace.events"
cleanup() {
    rm -rf "${top}"
    release_flag
}
trap cleanup EXIT

# shellcheck source=scripts/lib_ck_m1_checks.sh
source "${repo_root}/scripts/lib_ck_m1_checks.sh"
img_bytes=67108864
m1_fail=0; nvme_fail=0; store_fail=0; argus_fail=0; smmu_fail=0; shut_fail=0
fail_into() { # bucket variable name: move the current failed flag into it
    if [[ "${failed}" != 0 ]]; then printf -v "$1" 1; fi
    failed=0
}
sha() { sha256sum "$1" | cut -d' ' -f1; }

# boot <name> <efi> <disk image> <block bytes> <serial> [smmu]: one QEMU boot
# (with "smmu" the machine gets an SMMUv3); leaves
# the serial text in ${work}/serial.txt and the exit status in qemu_status.
boot() {
    work="${top}/$1"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    local nvme_dev="nvme,drive=nvme0,serial=$5"
    [[ "$4" == 512 ]] || nvme_dev="${nvme_dev},logical_block_size=$4,physical_block_size=$4"
    local machine="virt,virtualization=on,gic-version=3"
    [[ "${6:-}" != smmu ]] || machine+=",iommu=smmuv3"
    set +e
    # Issue #61: single-threaded TCG (see qemu_boot_test.sh).
    timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="$3" \
        -device "${nvme_dev}" \
        -device ramfb -display none -nic none \
        -serial file:"${work}/serial.log" -no-reboot \
        -D "${work}/trace.log" -trace events="${top}/trace.events"
    qemu_status=$?
    set -e
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_store_$1.log"
    echo "== boot $1: qemu exit ${qemu_status}"
    failed=0
    ck_m1_checks
    fail_into m1_fail
}
# field <regex with one group>: first group of the last matching line.
field() {
    local line
    line=$(grep -E "$1" "${work}/serial.txt" | tail -1 || true)
    [[ "${line}" =~ $1 ]] && echo "${BASH_REMATCH[1]}" || echo ""
}
nvme_checks() { # block bytes, confined|bypass: the bound NVMe path
    local bs="$1" count=$(( img_bytes / $1 ))
    if [[ "$2" == confined ]]; then
        check "SMMUv3 enabled from the IORT" "smmu: enabled"
        check "NVMe DMA window mapped through the SMMU" "smmu_dma_window: nvme only, translation active"
        check "NVMe DMA granted confined" "dma_gate: nvme granted (Confined), bus master on"
        check_absent "no unsafe DMA bypass in this image" "UNSAFE NVME DMA BYPASS"
        check_absent "no unconfined grant" "dma_gate: nvme granted (UnsafeBypass)"
        check "DMA outside the window faulted, page intact, controller still usable (differs)" \
            "smmu_negative: refused dma outside window iova=0x[0-9a-f]* faults=[1-9][0-9]* type=0x10 sid=0x[0-9a-f]* addr=0x[0-9a-f]* page=intact cmd_rc=-\?[0-9]* recovery_read=ok$"
        check "NVMe stream returned to abort after the revoke (differs)" "smmu: nvme stream 0x[0-9a-f]* returned to abort (rc=0)"
        fail_into smmu_fail
    else
        check "TEST-ONLY bypass build announced on serial" "WARNING: UNSAFE NVME DMA BYPASS BUILD"
        check "TEST-ONLY bypass grant announced on serial" "WARNING: UNSAFE NVME DMA BYPASS ACTIVE"
        check "NVMe DMA granted through the TEST-ONLY bypass" "dma_gate: nvme granted (UnsafeBypass)"
        check_absent "no SMMU window claimed by the bypass" "smmu_dma_window:"
    fi
    check "ECAM discovery found the NVMe class device (differs)" "nvme: discovery "
    check "controller and namespace identify completed (differs)" "nvme: identify ok "
    check "namespace geometry matches the image (differs)" \
        "nvme: geometry nsid=1 block_count=${count} block_size=${bs}$"
    check "read past the namespace end is rejected before any command (differs)" \
        "nvme: bounds read lba=${count} -> refused"
    check "LBA 0 read (differs)" "nvme: read lba=0 blocks=1 ok"
    check "scratch unit write+flush+readback matched (differs)" "nvme: rw probe lba=[0-9]* bytes=4096 write+flush+readback match"
    check "NVMe bound by the devices stage (differs)" "devices: pci=ok nvme=bound"
    check "stage devices ok (differs)" "stage devices: ok"
    check "NVMe bus master revoked after the read phase" "dma_gate: nvme bus master revoked"
    check_absent "no bus master revoke failure (differs)" "bus master revoke FAILED"
    fail_into nvme_fail
}
# shutdown_checks: the bound NVMe path must do an NVMe normal shutdown
# (CC.SHN = 01b, then CSTS.SHST = 10b) before the bus-master revoke. Three
# independent views: the kernel's register readback on serial, the serial
# order, and QEMU's own device trace (pci_nvme_mmio_shutdown_set must fall
# between the guest setting BME in the NVMe command register and clearing it).
shutdown_checks() {
    local sre='^nvme: shutdown normal cc=0x([0-9a-f]{8})->0x([0-9a-f]{8}) csts=0x([0-9a-f]{8}) shst=([A-Za-z-]+) waited_us=([0-9]+)$'
    local n line ls lr order
    n=$(grep -cE "${sre}" "${work}/serial.txt" || true)
    line=$(grep -E "${sre}" "${work}/serial.txt" | tail -1 || true)
    if [[ "${n}" == 1 && "${line}" =~ ${sre} ]]; then
        local cc_a=$(( 16#${BASH_REMATCH[2]} )) csts=$(( 16#${BASH_REMATCH[3]} )) res="${BASH_REMATCH[4]}"
        if (( ((cc_a >> 14) & 3) == 1 )); then echo "PASS  CC.SHN read back as 01b (normal shutdown requested)"
        else echo "FAIL  CC.SHN read back as $(( (cc_a >> 14) & 3 )), expected 1"; failed=1; fi
        if (( ((csts >> 2) & 3) == 2 )) && [[ "${res}" == complete ]]; then
            echo "PASS  CSTS.SHST read back as 10b (shutdown complete, waited ${BASH_REMATCH[5]} us)"
        else echo "FAIL  shutdown not complete: ${line}"; failed=1; fi
    else
        echo "FAIL  exactly one NVMe shutdown line reported (found ${n})"; failed=1
    fi
    ls=$(grep -nE '^nvme: shutdown normal ' "${work}/serial.txt" | head -1 | cut -d: -f1)
    lr=$(grep -n 'dma_gate: nvme bus master revoked' "${work}/serial.txt" | head -1 | cut -d: -f1)
    if [[ -n "${ls}" && -n "${lr}" && "${ls}" -lt "${lr}" ]]; then echo "PASS  shutdown reported before the bus-master revoke (serial order)"
    else echo "FAIL  shutdown not before the bus-master revoke (serial lines ${ls:-none} / ${lr:-none})"; failed=1; fi
    order=$(grep -E '^pci_nvme_mmio_shutdown_set|^pci_cfg_write nvme [0-9a-f:.]+ @0x4 <- 0x[0-9a-f]+$' "${work}/trace.log" 2>/dev/null | {
        on=0; s=0; out=none
        while read -r a _ _ _ _ v; do
            if [[ "${a}" == pci_nvme_mmio_shutdown_set ]]; then (( on )) && s=1
            elif (( v & 4 )); then on=1; s=0
            elif (( on )); then if (( s )); then out=ok; else out=bad; fi; on=0
            fi
        done
        echo "${out}"; })
    [[ "${order}" == ok ]] && echo "PASS  QEMU device trace: shutdown set while BME on, then BME cleared" \
        || { echo "FAIL  QEMU device trace order (${order})"; failed=1; }
    check_absent "no fallback disable needed (normal shutdown completed)" "nvme: shutdown fallback disable"
    check "reset quiesce hook ran after the release (differs)" "devices: quiesce before reset nvme=already-released"
    fail_into shut_fail
}
argus_checks() {
    check "capabilities: grant, attenuate, deny amplify/forged/revoked, RNDR token (differs)" \
        "caps: ok granted=yes attenuated=yes amplify=denied forged=denied revoked=denied office_token=rndr$"
    check "ARGUS narrow revoke: revoked denied, unrelated granted, authority unchanged (differs)" \
        "argus: ok narrow_revoke=1 revoked=denied unrelated=granted authority=unchanged$"
    check "stage security ok (differs)" "stage security: ok"
    fail_into argus_fail
}
store_fail_msg() { echo "FAIL  $1"; store_fail=1; }

for bs in 512 4096; do
    if [[ "${bs}" == 512 ]]; then serial=aienos-nvme-test; else serial=aienos-continuity; fi
    image="${top}/nvme-${bs}.img"
    truncate -s "${img_bytes}" "${image}"
    prev_gen=""
    for k in 1 2 3; do
        boot "${bs}-boot${k}" "${safe_efi}" "${image}" "${bs}" "${serial}" smmu
        nvme_checks "${bs}" confined
        shutdown_checks
        argus_checks
        check "stage store ok (differs)" "stage store: ok"
        check_absent "Store not refused (differs)" "store: REFUSED"
        if [[ "${k}" == 1 ]]; then
            check "blank disk formatted as a TEST store (differs)" \
                "store: blank disk (all-zero anchor + Store head): formatted TEST store"
        else
            check_absent "existing Store not reformatted (differs)" "formatted TEST store"
        fi
        fail_into store_fail
        open_re='^store: opened generation=([0-9]+) boot_count=([0-9]+) prev_commit=([^ ]+) anchor=([a-z?-]+)$'
        commit_re='^store: committed generation=([0-9]+) boot_count=([0-9]+)$'
        oline=$(grep -E "${open_re}" "${work}/serial.txt" | tail -1 || true)
        cline=$(grep -E "${commit_re}" "${work}/serial.txt" | tail -1 || true)
        if [[ "${oline}" =~ ${open_re} ]]; then
            o_gen="${BASH_REMATCH[1]}"; o_bc="${BASH_REMATCH[2]}"; o_prev="${BASH_REMATCH[3]}"; o_anchor="${BASH_REMATCH[4]}"
        else
            o_gen=""; o_bc=""; o_prev=""; o_anchor=""
        fi
        if [[ "${cline}" =~ ${commit_re} ]]; then c_gen="${BASH_REMATCH[1]}"; c_bc="${BASH_REMATCH[2]}"; else c_gen=""; c_bc=""; fi
        if [[ -z "${o_gen}" || -z "${c_gen}" ]]; then
            store_fail_msg "Store opened and committed lines reported (boot ${k})"
        else
            echo "      store boot ${k}: opened gen=${o_gen} boot_count=${o_bc} prev_commit=${o_prev:0:12} anchor=${o_anchor}; committed gen=${c_gen} boot_count=${c_bc}"
            [[ "${c_bc}" == "${k}" && "${o_bc}" == $(( k - 1 )) ]] && echo "PASS  boot_count ${k}" \
                || store_fail_msg "boot_count ${c_bc} (opened ${o_bc}), expected ${k}"
            [[ "${c_gen}" == $(( o_gen + 1 )) ]] && echo "PASS  commit advanced the generation by one" \
                || store_fail_msg "committed generation ${c_gen} after opening ${o_gen}"
            if [[ -n "${prev_gen}" ]]; then
                [[ "${c_gen}" -gt "${prev_gen}" && "${o_gen}" == "${prev_gen}" ]] \
                    && echo "PASS  generation strictly increasing and opened at the previous boot's commit (${prev_gen} -> ${c_gen})" \
                    || store_fail_msg "generation ${o_gen}->${c_gen} does not follow previous commit ${prev_gen}"
            fi
            if [[ "${k}" == 1 ]]; then
                [[ "${o_prev}" == none ]] && echo "PASS  prev_commit none on the first boot" \
                    || store_fail_msg "prev_commit ${o_prev} on the first boot, expected none"
            else
                [[ "${o_prev}" == "${commit}" ]] && echo "PASS  prev_commit is this commit" \
                    || store_fail_msg "prev_commit ${o_prev}, expected ${commit}"
            fi
            prev_gen="${c_gen}"
        fi
    done

    # Boot 4: corrupt the Store superblock on the host image.
    store_lba=$(field '^store: TEST identity.* store lba=([0-9]+) ')
    soff=$(( ${store_lba:-0} * bs ))
    if [[ -z "${store_lba}" || "${soff}" != 16384 ]]; then
        store_fail_msg "Store region offset ${soff} (lba ${store_lba:-?}), expected byte 16384 (4 anchor units)"
        soff=16384
    fi
    sha_clean=$(sha "${image}")
    # XOR 0xa5 over 2 x 4096 bytes, as svc/tests/stage_test.c does (shell only).
    fmt=""
    for b in $(od -An -v -tu1 -j "${soff}" -N 8192 "${image}"); do fmt+=$(printf '\\%03o' $(( b ^ 0xa5 ))); done
    printf "${fmt}" | dd of="${image}" bs=4096 seek=$(( soff / 4096 )) conv=notrunc status=none
    sha_corrupt=$(sha "${image}")
    [[ "${sha_corrupt}" != "${sha_clean}" && $(stat -c %s "${image}") == "${img_bytes}" ]] \
        && echo "PASS  host corrupted the Store superblock (8192 bytes at ${soff})" \
        || store_fail_msg "host corruption did not change the image"
    boot "${bs}-boot4-corrupt" "${safe_efi}" "${image}" "${bs}" "${serial}" smmu
    nvme_checks "${bs}" confined
    shutdown_checks
    argus_checks
    check "corrupt Store refused as structural (differs)" "store: REFUSED proof=structural "
    check "corrupt Store left as found, not reformatted (differs)" "disk left as found, not reformatted"
    check "stage store failed (differs)" "stage store: FAIL"
    check_absent "nothing committed on the corrupt Store (differs)" "store: committed"
    check_absent "corrupt Store not reformatted (differs)" "formatted TEST store"
    fail_into store_fail
    sha_after=$(sha "${image}")
    [[ "${sha_after}" == "${sha_corrupt}" ]] && echo "PASS  image sha256 unchanged by the refused boot (${sha_after:0:16})" \
        || store_fail_msg "image changed by the refused boot (${sha_corrupt:0:16} -> ${sha_after:0:16})"

    # Boot 5: default image, NVMe DMA must stay refused.
    boot "${bs}-boot5-safe" "${safe_efi}" "${image}" "${bs}" "${serial}"
    check "discovery found the device before the DMA gate (differs)" "nvme: discovery "
    check "NVMe DMA denied without an SMMU" "dma_gate: nvme denied (NoSmmu), bus master stays off"
    check "NVMe controller fail-closed without an SMMU" "nvme: unavailable (SMMU DMA isolation not active)"
    check_absent "NVMe controller never granted DMA" "dma_gate: nvme granted"
    check_absent "no unsafe DMA bypass in this image" "UNSAFE NVME DMA BYPASS"
    check_absent "NVMe controller never identified (differs)" "nvme: identify"
    check_absent "no NVMe shutdown without a bound controller (differs)" "nvme: shutdown normal"
    check "reset quiesce hook found nothing live (differs)" "devices: quiesce before reset nvme=already-released"
    check "NVMe left unbound (differs)" "devices: pci=ok nvme=unbound"
    fail_into nvme_fail
    check "Store refused without a disk (differs)" 'store: REFUSED proof=io step="no boot disk"'
    fail_into store_fail
    argus_checks
    sha_safe=$(sha "${image}")
    [[ "${sha_safe}" == "${sha_corrupt}" ]] && echo "PASS  image sha256 unchanged by the fail-closed boot" \
        || store_fail_msg "image changed by the fail-closed boot"

    # Boot 6: TEST-ONLY bypass image, no SMMU. Kept so the bypass path stays
    # honest: it must announce itself, and the corrupt Store is still refused.
    boot "${bs}-boot6-bypass" "${unsafe_efi}" "${image}" "${bs}" "${serial}"
    nvme_checks "${bs}" bypass
    shutdown_checks
    argus_checks
    check "corrupt Store refused under the bypass image too (differs)" "store: REFUSED proof=structural "
    check_absent "nothing committed under the bypass image (differs)" "store: committed"
    fail_into store_fail
    sha_bypass=$(sha "${image}")
    [[ "${sha_bypass}" == "${sha_corrupt}" ]] && echo "PASS  image sha256 unchanged by the bypass boot" \
        || store_fail_msg "image changed by the bypass boot"
done
release_flag

if [[ "${m1_fail}${nvme_fail}${store_fail}${argus_fail}${smmu_fail}${shut_fail}" != 000000 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for s in "${top}"/*/serial.txt; do
        echo "---- serial console $(basename "$(dirname "${s}")") (stage lines) ----"
        grep -E '^(stage |smmu|nvme:|dma_gate:|WARNING|devices:|store:|caps:|argus:|report_kind:|pci_nvme_mmio_shutdown)' "${s}" | head -60 || true
    done
fi
[[ "${m1_fail}" != 0 ]] && echo "M1 checks failed on at least one boot: no verdict can pass"
v() { [[ "${m1_fail}" == 0 && "$1" == 0 ]] && echo PASS || echo FAIL; }
# Confined mode is part of the NVMe gate: an SMMU failure fails it too.
echo "AIENOS_CK_M4_NVME: $(v "$(( nvme_fail | smmu_fail ))")"
echo "AIENOS_CK_M4_STORE: $(v "${store_fail}")"
echo "AIENOS_CK_ARGUS1_REVOKE: $(v "${argus_fail}")"
echo "AIENOS_CK_SMMU: $(v "${smmu_fail}")"
echo "AIENOS_CK_NVME_SHUTDOWN: $(v "${shut_fail}")"
[[ "${m1_fail}${nvme_fail}${store_fail}${argus_fail}${smmu_fail}${shut_fail}" == 000000 ]] || exit 1
