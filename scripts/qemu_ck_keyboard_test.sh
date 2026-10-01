#!/usr/bin/env bash
# KEYBOARD gate for the AIENOS C kernel, DMA-safety half only: rows 25-28, 31
# and 32 of native/kernel/GATES.md "SEED-0A keyboard" (Rust oracle:
# scripts/qemu_keyboard_test.sh with SMMU=1 and SMMU=0). Rows 29-30 (keyboard
# attached, typed line echoed, console shell) stay NOT_RUN
# (MISSING_IMPLEMENTATION: the C kernel has no USB HID driver and no console
# shell), so the KEYBOARD gate itself stays NOT_RUN whatever this prints.
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# Boots the full C image (make full) in QEMU AArch64 with UEFI (AAVMF), an
# NVMe disk (normal full boot), a qemu-xhci controller with a usb-kbd on it
# (the Rust gate's devices) and no NIC. The devices stage
# (native/kernel/dev/devices.c) runs the post-exit bus-master sweep first and
# the xHCI DMA fence (native/kernel/dev/xhci_fence.c) last.
#
#  boot kbd-smmu    iommu=smmuv3 (Rust SMMU=1):
#   row 25  "keyboard: xhci SSSS:BB:DD.F mmio 0x.." (found on the ECAM walk)
#   row 26  "dma_sweep: seg 0000 bus .." before the first device DMA grant,
#           no "dma_sweep: bme STUCK"
#   row 27  "xhci_pci: command=0x.... bus_master=off" before the xHCI DMA gate
#   row 31  grant confined ("smmu_dma_window: xhci only, translation active",
#           "dma_gate: xhci granted (Confined), bus master on"), controller
#           halted, "dma_gate: xhci bus master revoked", COMMAND read back
#           "xhci_pci: after phase command=0x.... bus_master=off", "smmu: xhci
#           stream 0x.. returned to abort (rc=0)", in that order, all before
#           the "devices: xhci=fenced (rc=0)" line (so a later reset-time
#           quiesce revoke cannot stand in for it)
#   row 32  no "report_kind: (panic|fault)", "report_kind: final", QEMU exit 0
#  boot kbd-nosmmu  no SMMU (Rust SMMU=0), same image:
#   rows 25, 26, 27, 32 as above
#   row 28  "dma_gate: xhci denied (NoSmmu), bus master stays off", "keyboard:
#           unavailable (SMMU DMA isolation not active)", COMMAND read back
#           after the deny with bus_master=off, no "dma_gate: xhci granted",
#           no "keyboard: ready"
# Both boots must also pass every M1 check (scripts/lib_ck_m1_checks.sh) and
# carry no TEST-ONLY mutation banner and no "UNSAFE DMA BYPASS".
#
# --mutation (self-test of the checks above; TEST-ONLY images): builds
# "make full CK_TEST_XHCI_MUTATION=<m>" for each mutation and boots it once;
# the named row must FAIL (and the boot must still reach "report_kind: final"
# with row 25 PASS, so the failure is the mutation's, not a dead boot):
#   bm-left-on     xHCI bus mastering switched back on after the sweep (smmu)  -> row 27
#   no-revoke      release skips the bus-master clear (smmu)                    -> row 31
#   grant-no-smmu  DMA granted without an SMMU (nosmmu)                         -> row 28
#   no-sweep       post-exit bus-master sweep skipped (nosmmu)                  -> row 26
# It also checks the build refuses a mutation together with
# CK_HARDWARE_STAGING=1 (and with CK_QEMU_UNSAFE_DMA=1), and that the default
# image carries no mutation banner.
#
# Env: AIENOS_QEMU_SMMU=1 or 0 runs only that boot (default: both).
# Takes the machine quiet flag itself like the other qemu_ck_* scripts
# (AIENOS_QUIET_FLAG / AIENOS_QUIET_TAG).
# Final lines (normal run): one "KEYBOARD_ROW <n>: PASS|FAIL|NOT_RUN (...)"
# per row 25-32, "AIENOS_CK_KEYBOARD_DMA: PASS|FAIL (rows 25-28,31,32)" and
# "AIENOS_CK_KEYBOARD: NOT_RUN (MISSING_IMPLEMENTATION: ...)". Exit 0 when
# the DMA rows PASS, 1 FAIL, 2 missing tools, 3 NOT_RUN (quiet flag held).
# --mutation: "AIENOS_CK_KEYBOARD_MUTATION: PASS|FAIL"; exit 0 / 1.
# Needs qemu-system-aarch64, AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64)
# and a C compiler.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mutation_run=0
case "${1:-}" in
    "") ;;
    --mutation) mutation_run=1 ;;
    *) echo "usage: $0 [--mutation]"; exit 2 ;;
esac
final_tag="AIENOS_CK_KEYBOARD_DMA"
[[ "${mutation_run}" == 0 ]] || final_tag="AIENOS_CK_KEYBOARD_MUTATION"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${final_tag}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${final_tag}: NOT_RUN"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel"
mk() { make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" "$@"; }
mk full >/dev/null
default_efi="${out}/full/BOOTAA64.EFI"
mutations=(bm-left-on no-revoke grant-no-smmu no-sweep)
if [[ "${mutation_run}" == 1 ]]; then
    for m in "${mutations[@]}"; do mk full CK_TEST_XHCI_MUTATION="${m}" >/dev/null; done
fi

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_keyboard_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${final_tag}: NOT_RUN"
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
img_bytes=67108864
image="${top}/nvme.img"
truncate -s "${img_bytes}" "${image}"
m1_fail=0

# boot <name> <efi> smmu|nosmmu: one QEMU boot; serial text in ${work}/serial.txt.
boot() {
    work="${top}/$1"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    local machine="virt,virtualization=on,gic-version=3"
    [[ "$3" != smmu ]] || machine+=",iommu=smmuv3"
    set +e
    # Issue #61: single-threaded TCG (see qemu_boot_test.sh).
    timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${image}" \
        -device nvme,drive=nvme0,serial=aienos-kbd-test \
        -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 \
        -device ramfb -display none -nic none \
        -serial file:"${work}/serial.log" -no-reboot
    qemu_status=$?
    set -e
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_keyboard_$1.log"
    echo "== boot $1 ($3): qemu exit ${qemu_status}"
}

# Row bookkeeping: rowfail[n]=1 once any check of row n failed in this
# evaluation; rowmodes[n] lists the boots that checked it.
declare -A rowfail rowmodes
reset_rows() { for r in 25 26 27 28 31 32; do rowfail[$r]=0; rowmodes[$r]=""; done; }
reset_rows
mode=""
note_mode() { [[ " ${rowmodes[$1]} " == *" ${mode} "* ]] || rowmodes[$1]="${rowmodes[$1]:+${rowmodes[$1]} }${mode}"; }
rpass() { note_mode "$1"; echo "ROW $1 PASS  ${mode}: $2"; }
rfail() { note_mode "$1"; rowfail[$1]=1; echo "ROW $1 FAIL  ${mode}: $2"; }
rcheck() { # row, description, ERE pattern
    if grep -qE -- "$3" "${work}/serial.txt"; then rpass "$1" "$2"; else rfail "$1" "$2"; fi
}
rabsent() { # row, description, ERE pattern
    if grep -qE -- "$3" "${work}/serial.txt"; then rfail "$1" "$2"; else rpass "$1" "$2"; fi
}
line_of() { { grep -nE -m1 -- "$1" "${work}/serial.txt" || true; } | cut -d: -f1; }
before() { # row, description, earlier ERE, later ERE: both present, earlier first
    local a b
    a="$(line_of "$3")"; b="$(line_of "$4")"
    if [[ -n "${a}" && -n "${b}" && "${a}" -lt "${b}" ]]; then rpass "$1" "$2 (lines ${a} < ${b})"
    else rfail "$1" "$2 (lines ${a:-none} ${b:-none})"; fi
}

# evaluate smmu|nosmmu: every DMA-safety row check on ${work}/serial.txt.
evaluate() {
    mode="$1"
    rcheck 25 "xHCI found on the ECAM walk (Rust: keyboard: xhci )" \
        '^keyboard: xhci 0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7] mmio 0x[0-9a-f]+ '
    rcheck 26 "post-exit bus-master sweep of the segment" \
        '^dma_sweep: seg 0000 bus [0-9a-f]{2}-[0-9a-f]{2} functions=[1-9][0-9]* bridges=[0-9]+ bridges_bme=[0-9]+ endpoints_bme_found=[0-9]+ still_enabled=0$'
    rabsent 26 "no endpoint left with bus master stuck on" '^dma_sweep: bme STUCK'
    before 26 "sweep before the first device DMA gate" '^dma_sweep: seg ' '^dma_gate: '
    before 26 "sweep before the xHCI is looked at" '^dma_sweep: seg ' '^keyboard: xhci '
    rcheck 27 "xHCI bus master off before the DMA gate (Rust: xhci_pci: command=0x.. bus_master=off)" \
        '^xhci_pci: command=0x[0-9a-f]{4} bus_master=off$'
    before 27 "COMMAND read back before the xHCI DMA gate" '^xhci_pci: command=' '^dma_gate: xhci '
    if [[ "${mode}" == nosmmu ]]; then
        rcheck 28 "xHCI DMA denied without an SMMU" '^dma_gate: xhci denied \(NoSmmu\), bus master stays off$'
        rcheck 28 "keyboard fail-closed without an SMMU" '^keyboard: unavailable \(SMMU DMA isolation not active\)$'
        rcheck 28 "COMMAND read back after the deny: bus master off" '^xhci_pci: after deny command=0x[0-9a-f]{4} bus_master=off$'
        rabsent 28 "xHCI never granted DMA" 'dma_gate: xhci granted'
        rabsent 28 "keyboard never attached" 'keyboard: ready'
        rabsent 28 "no xHCI SMMU window claimed without an SMMU" '^smmu_dma_window: xhci'
        rcheck 28 "devices stage reports the deny" '^devices: xhci=denied \(rc=-603\)$'
    else
        rcheck 31 "xHCI SMMU window (Rust: smmu_dma_window: xhci only, translation active)" \
            '^smmu_dma_window: xhci only, translation active iova=0x[0-9a-f]+ len=0x[0-9a-f]+ rid=0x[0-9a-f]+$'
        rcheck 31 "xHCI DMA granted only as confined" '^dma_gate: xhci granted \(Confined\), bus master on$'
        rabsent 31 "no unconfined xHCI grant" 'dma_gate: xhci granted \((UnsafeBypass|TestMutation)'
        rcheck 31 "controller halted before the revoke" '^xhci: halt before revoke usbcmd=0x[0-9a-f]{8} usbsts=0x[0-9a-f]{8} halted=yes$'
        rcheck 31 "xHCI bus master revoked after the phase" '^dma_gate: xhci bus master revoked$'
        rcheck 31 "COMMAND read back after the phase: bus master off" '^xhci_pci: after phase command=0x[0-9a-f]{4} bus_master=off$'
        rcheck 31 "xHCI SMMU stream returned to abort" '^smmu: xhci stream 0x[0-9a-f]+ returned to abort \(rc=0\)$'
        rabsent 31 "no revoke failure" '^dma_gate: xhci bus master revoke FAILED'
        before 31 "order: grant < revoke" '^dma_gate: xhci granted \(Confined\)' '^dma_gate: xhci bus master revoked$'
        before 31 "order: revoke < COMMAND read back" '^dma_gate: xhci bus master revoked$' '^xhci_pci: after phase command='
        before 31 "order: read back < stream abort" '^xhci_pci: after phase command=' '^smmu: xhci stream .* returned to abort'
        before 31 "order: stream abort < end of the xHCI phase (not a reset-time revoke)" \
            '^smmu: xhci stream .* returned to abort' '^devices: xhci=fenced \(rc=0\)$'
    fi
    rabsent 32 "no panic or fault" '^report_kind: (panic|fault)'
    rcheck 32 "final report reached" 'report_kind: final'
    if [[ "${qemu_status}" == 0 ]]; then rpass 32 "QEMU exit 0 after PSCI reset"; else rfail 32 "QEMU exit ${qemu_status} (expected 0)"; fi
}

if [[ "${mutation_run}" == 0 ]]; then
    modes=(smmu nosmmu)
    case "${AIENOS_QEMU_SMMU:-}" in
        1) modes=(smmu) ;;
        0) modes=(nosmmu) ;;
        "") ;;
        *) echo "AIENOS_QEMU_SMMU must be 1, 0 or unset"; release_flag; echo "${final_tag}: NOT_RUN"; exit 2 ;;
    esac
    other_fail=0
    for md in "${modes[@]}"; do
        boot "kbd-${md}" "${default_efi}" "${md}"
        failed=0
        ck_m1_checks
        [[ "${failed}" == 0 ]] || m1_fail=1
        failed=0
        check_absent "no TEST-ONLY mutation banner in the default image" "TEST-ONLY xHCI MUTATION"
        check_absent "no unsafe DMA bypass in this image" "UNSAFE DMA BYPASS"
        check "honest marker: no USB HID driver yet (rows 29-30 NOT_RUN)" \
            "^keyboard: hid NOT_IMPLEMENTED\|^keyboard: unavailable (SMMU DMA isolation not active)$"
        [[ "${failed}" == 0 ]] || other_fail=1
        failed=0
        evaluate "${md}"
    done
    release_flag
    if [[ "${m1_fail}${other_fail}" != 00 || -n "${AIENOS_QEMU_VERBOSE:-}" ]] || (( rowfail[25] + rowfail[26] + rowfail[27] + rowfail[28] + rowfail[31] + rowfail[32] )); then
        for s in "${top}"/*/serial.txt; do
            echo "---- serial console $(basename "$(dirname "${s}")") (device lines) ----"
            grep -E '^(keyboard|xhci|xhci_pci|dma_sweep|dma_gate|smmu|devices:|stage |report_kind:)' "${s}" | head -60 || true
        done
    fi
    dma_fail=$(( m1_fail | other_fail ))
    echo "== per-row results (QEMU only; hardware NOT_RUN)"
    for r in 25 26 27 28 31 32; do
        if [[ -z "${rowmodes[$r]}" ]]; then
            echo "KEYBOARD_ROW ${r}: NOT_RUN (not checked in this run's modes)"
            [[ -n "${AIENOS_QEMU_SMMU:-}" ]] || dma_fail=1
        elif [[ "${rowfail[$r]}" == 0 && "${m1_fail}" == 0 ]]; then
            echo "KEYBOARD_ROW ${r}: PASS (${rowmodes[$r]})"
        else
            echo "KEYBOARD_ROW ${r}: FAIL (${rowmodes[$r]}$([[ "${m1_fail}" == 0 ]] || echo '; an M1 check failed'))"
            dma_fail=1
        fi
    done
    echo "KEYBOARD_ROW 29: NOT_RUN (MISSING_IMPLEMENTATION: no USB HID driver in the C kernel)"
    echo "KEYBOARD_ROW 30: NOT_RUN (MISSING_IMPLEMENTATION: no console shell in the C kernel)"
    [[ "${m1_fail}" == 0 ]] || echo "M1 checks failed on at least one boot: the DMA rows cannot pass"
    [[ "${other_fail}" == 0 ]] || echo "image checks failed (mutation banner, unsafe bypass or HID marker)"
    if [[ "${dma_fail}" == 0 ]]; then echo "${final_tag}: PASS (rows 25-28,31,32; modes ${modes[*]})"; else echo "${final_tag}: FAIL (rows 25-28,31,32; modes ${modes[*]})"; fi
    echo "AIENOS_CK_KEYBOARD: NOT_RUN (MISSING_IMPLEMENTATION: no USB HID driver or console shell in the C kernel; rows 29-30)"
    [[ "${dma_fail}" == 0 ]] && exit 0
    exit 1
fi

# ---- --mutation: every mutation must make its row FAIL ----
mut_fail=0
mut_ok() { echo "MUTATION PASS  $1"; }
mut_bad() { echo "MUTATION FAIL  $1"; mut_fail=1; }
if grep -aqF "TEST-ONLY xHCI MUTATION" "${default_efi}"; then mut_bad "default image carries the mutation banner"; else mut_ok "default image carries no mutation banner"; fi
for combo in "CK_HARDWARE_STAGING=1" "CK_QEMU_UNSAFE_DMA=1"; do
    set +e
    msg="$(make -s -n -C native/kernel OUT="${top}/refuse" full CK_TEST_XHCI_MUTATION=no-revoke "${combo}" 2>&1)"
    st=$?
    set -e
    if [[ "${st}" != 0 ]] && grep -qE "CK_TEST_XHCI_MUTATION.*cannot be combined with ${combo%%=*}" <<<"${msg}"; then
        mut_ok "build refuses CK_TEST_XHCI_MUTATION with ${combo}"
    else
        mut_bad "build did not refuse CK_TEST_XHCI_MUTATION with ${combo} (status ${st}): $(head -c 200 <<<"${msg}")"
    fi
done
declare -A mut_mode=([bm-left-on]=smmu [no-revoke]=smmu [grant-no-smmu]=nosmmu [no-sweep]=nosmmu)
declare -A mut_row=([bm-left-on]=27 [no-revoke]=31 [grant-no-smmu]=28 [no-sweep]=26)
for m in "${mutations[@]}"; do
    efi="${out}/full-test-xhci-${m}/BOOTAA64.EFI"
    boot "mut-${m}" "${efi}" "${mut_mode[$m]}"
    reset_rows
    evaluate "${mut_mode[$m]}"
    r="${mut_row[$m]}"
    if ! grep -qF "WARNING: TEST-ONLY xHCI MUTATION BUILD (CK_TEST_XHCI_MUTATION=${m}," "${work}/serial.txt"; then
        mut_bad "${m}: image did not announce the mutation"
    elif ! grep -q "report_kind: final" "${work}/serial.txt" || [[ "${rowfail[25]}" != 0 ]]; then
        mut_bad "${m}: boot did not reach the final report with the xHCI found (a dead boot proves nothing)"
    elif [[ "${rowfail[$r]}" == 1 ]]; then
        mut_ok "${m} (${mut_mode[$m]}): row ${r} FAILs as it must"
    else
        mut_bad "${m} (${mut_mode[$m]}): row ${r} still PASSES: the check does not catch this mutation"
    fi
done
release_flag
if [[ "${mut_fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for s in "${top}"/*/serial.txt; do
        echo "---- serial console $(basename "$(dirname "${s}")") (device lines) ----"
        grep -E '^(WARNING|keyboard|xhci|xhci_pci|dma_sweep|dma_gate|smmu|devices:|report_kind:)' "${s}" | head -60 || true
    done
fi
if [[ "${mut_fail}" == 0 ]]; then echo "${final_tag}: PASS (bm-left-on->27 no-revoke->31 grant-no-smmu->28 no-sweep->26)"; exit 0; fi
echo "${final_tag}: FAIL"
exit 1
