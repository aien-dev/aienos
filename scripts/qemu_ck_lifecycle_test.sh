#!/usr/bin/env bash
# LIFECYCLE gate for the AIENOS C kernel (native v1 plan P03): rows 160-167 of
# native/kernel/GATES.md "LIFECYCLE resident production lifecycle". C-only.
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# Boots two CK_SERVICE images in QEMU AArch64 (AAVMF, NVMe disk, iommu=smmuv3),
# operator input over the PL011 serial from OUTSIDE the guest (pipe chardev):
#   service   make full CK_SERVICE=1: the production entry. The production key
#             source refuses (no in-kernel K_vol unwrap, P04), so the lifecycle
#             must come up LOCKED, refuse every task and unlock, still answer
#             status/help/evidence, and shut down in order.
#   testkeys  make full CK_SERVICE=1 CK_SERVICE_TEST_KEYS=1 (TEST-ONLY): the
#             Store opens with TEST keys so READY/SERVE run: a task is proposed,
#             approve commits it to the Store, deny and cancel drop tasks, a
#             second task while one is pending is refused, an overlong line is
#             refused whole, evidence counts agree, shutdown closes the Store
#             before the NVMe release before the final report.
#
#   row 160  service image: lifecycle starts after mm_usage, state=locked,
#            store=locked; the Store stage refused with BlockedOperator and
#            released the NVMe; no TEST key banner
#   row 161  locked: task and unlock REFUSED (state stays locked), status/help/
#            evidence answered
#   row 162  locked shutdown: stop order store=was-locked, then stage result,
#            then final report; no panic/fault; QEMU exit 0; M1 checks
#   row 163  testkeys image: announces TEST-ONLY banner, Store open, NVMe kept
#            bound for the service lifetime (no dma_gate revoke before ready)
#   row 164  serve: task -> pending with the proposed note; approve -> committed
#            with a Store generation and object id; state back to ready
#   row 165  deny and cancel drop pending tasks; a second task while pending is
#            refused; approve with nothing pending is refused
#   row 166  bounds: a 65-byte line is refused whole and never run; evidence
#            shows tasks=3 approved=1 denied=1 cancelled=1 overlong=1
#   row 167  stop order: store=closed, then dma_gate nvme bus master revoked,
#            then smmu stream back to abort, then stage lifecycle ok, then the
#            final report; QEMU exit 0; M1 checks
#   build    the default (diagnostic) image carries no lifecycle; CK_SERVICE is
#            refused with CK_CONSOLE_SESSION, CK_QEMU_UNSAFE_DMA and a CK_TEST_*
#            flag; CK_SERVICE_TEST_KEYS is refused with CK_HARDWARE_STAGING
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
final_tag="AIENOS_CK_LIFECYCLE"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${final_tag}: NOT_RUN (qemu-system-aarch64 missing)"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${final_tag}: NOT_RUN (AAVMF missing)"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel"
mk() { make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" "$@"; }
mk full >/dev/null
mk full CK_SERVICE=1 >/dev/null
mk full CK_SERVICE=1 CK_SERVICE_TEST_KEYS=1 >/dev/null
mk gpt-image >/dev/null
gpt_tool="${out}/host/ck_gpt_image"
default_efi="${out}/full/BOOTAA64.EFI"
service_efi="${out}/full-service/BOOTAA64.EFI"
testkeys_efi="${out}/full-service-testkeys/BOOTAA64.EFI"

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check; then echo "NOT_RUN  ${gh_why}"; echo "${final_tag}: NOT_RUN (quiet flag held)"; exit 3; fi
if ! gh_lock_take qemu_ck_lifecycle_test "${AIENOS_GATE_MINUTES:-40}"; then echo "NOT_RUN  ${gh_why}"; echo "${final_tag}: NOT_RUN (QEMU gate lock held)"; exit 3; fi
top="$(mktemp -d)"
qemu_pid=""
drain_pid=""
cleanup() {
    [[ -z "${qemu_pid}" ]] || kill "${qemu_pid}" 2>/dev/null || true
    [[ -z "${drain_pid}" ]] || kill "${drain_pid}" 2>/dev/null || true
    exec 4>&- 2>/dev/null || true
    rm -rf "${top}"
    gh_lock_release
}
trap cleanup EXIT

source "${repo_root}/scripts/lib_ck_m1_checks.sh"
boot_timeout="${AIENOS_QEMU_TIMEOUT:-600}"
fail=0
ok() { echo "ROW $1 PASS  $2"; }
bad() { echo "ROW $1 FAIL  $2"; fail=1; }
has() { grep -qE -- "$1" "${work}/serial.txt"; }
rcheck() { if has "$3"; then ok "$1" "$2"; else bad "$1" "$2"; fi; }
rabsent() { if has "$3"; then bad "$1" "$2 (present)"; else ok "$1" "$2"; fi; }
line_of() { { grep -nE -m1 -- "$1" "${work}/serial.txt" || true; } | cut -d: -f1; }
before() { local a b; a="$(line_of "$3")"; b="$(line_of "$4")"
    if [[ -n "${a}" && -n "${b}" && "${a}" -lt "${b}" ]]; then ok "$1" "$2 (lines ${a} < ${b})"; else bad "$1" "$2 (lines ${a:-none} ${b:-none})"; fi; }
serial_has() { tr -d '\r' 2>/dev/null <"${work}/serial.log" | grep -qE -- "$1"; }
wait_for() { local deadline=$(( $(date +%s) + $1 )); shift
    while (( $(date +%s) < deadline )); do for p in "$@"; do serial_has "${p}" && return 0; done
        kill -0 "${qemu_pid}" 2>/dev/null || break; sleep 1; done
    for p in "$@"; do serial_has "${p}" && return 0; done; return 1; }
ser_line() { printf '%s\r' "$1" >&4; sleep 1.2; }

boot() { # name efi
    work="${top}/$1"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    # GPT boot disk (tools/ck_gpt_image.c, as the Store gate): protective MBR,
    # primary + backup GPT, sentinels, AIENOS partition all zero (Store at genesis).
    "${gpt_tool}" create "${work}/nvme.img" 512 64 aienos-middle >/dev/null
    mkfifo "${work}/ser.in" "${work}/ser.out"
    : >"${work}/serial.log"
    timeout "${boot_timeout}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${work}/nvme.img" \
        -device nvme,drive=nvme0,serial=aienos-lifecycle-test \
        -device ramfb -display none -nic none -monitor none \
        -chardev pipe,id=ser,path="${work}/ser" -serial chardev:ser -no-reboot 2>"${work}/qemu.err" &
    qemu_pid=$!
    cat "${work}/ser.out" >>"${work}/serial.log" &
    drain_pid=$!
    exec 4>"${work}/ser.in"
    if wait_for "${boot_timeout}" '^lifecycle: ready state=' '^report_kind: (panic|fault|final)' && serial_has '^lifecycle: ready state='; then
        sleep 1
        "$3"
    fi
    wait_for 120 '^report_kind: (panic|fault|final)' || true
    set +e; wait "${qemu_pid}"; qemu_status=$?; set -e
    qemu_pid=""
    exec 4>&- 2>/dev/null || true
    wait "${drain_pid}" 2>/dev/null || true
    drain_pid=""
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_lifecycle_$1.log"
    echo "== boot $1: qemu exit ${qemu_status}"
}

drive_locked() {
    ser_line status; ser_line "task write a note"; ser_line unlock; ser_line help; ser_line evidence; ser_line shutdown
}
drive_ready() {
    ser_line status
    ser_line "task draft the plan"
    ser_line "task second while pending"
    ser_line approve
    ser_line approve
    ser_line "task to be denied"; ser_line deny
    ser_line "task to be cancelled"; ser_line cancel
    ser_line "$(printf 'x%.0s' $(seq 65))"
    ser_line evidence
    ser_line shutdown
}

m1() { # row: the shared M1 checks read ${work}/serial.txt and set failed
    failed=0
    ck_m1_checks >"${work}/m1.txt" 2>&1 || true
    if [[ "${failed}" == 0 ]]; then ok "$1" "M1 checks"; else bad "$1" "M1 checks: $(grep -E "^FAIL" "${work}/m1.txt" | head -3 | tr "\n" " ")"; fi
}

# --- build-shape checks ---
if grep -aqF "lifecycle: ready" "${default_efi}"; then bad build "default image carries the resident lifecycle"; else ok build "default image carries no resident lifecycle"; fi
if grep -aqF "TEST-ONLY service image" "${service_efi}"; then bad build "production service image carries the TEST key banner"; else ok build "production service image carries no TEST key banner"; fi
for combo in "CK_CONSOLE_SESSION=1" "CK_QEMU_UNSAFE_DMA=1" "CK_TEST_STORE_CRASH=1"; do
    set +e; msg="$(make -s -n -C native/kernel OUT="${top}/refuse" full CK_SERVICE=1 "${combo}" 2>&1)"; st=$?; set -e
    if [[ "${st}" != 0 ]] && grep -qE "CK_SERVICE cannot be combined with" <<<"${msg}"; then ok build "refuses CK_SERVICE with ${combo}"; else bad build "did not refuse CK_SERVICE with ${combo} (status ${st})"; fi
done
set +e; msg="$(make -s -n -C native/kernel OUT="${top}/refuse" full CK_SERVICE=1 CK_SERVICE_TEST_KEYS=1 CK_HARDWARE_STAGING=1 2>&1)"; st=$?; set -e
if [[ "${st}" != 0 ]] && grep -qF "CK_SERVICE_TEST_KEYS (TEST keys) cannot be combined with CK_HARDWARE_STAGING" <<<"${msg}"; then ok build "refuses TEST keys with CK_HARDWARE_STAGING"; else bad build "did not refuse TEST keys with CK_HARDWARE_STAGING (status ${st})"; fi

# --- boot 1: production service image, LOCKED ---
boot service "${service_efi}" drive_locked
before 160 "lifecycle after mm_usage" '^mm_usage: ' '^lifecycle: ready state=locked store=locked'
rcheck 160 "Store stage refused with the production key source (BlockedOperator), disk not read" '^store: REFUSED proof=keyed step="production Store key source" rc=-2002 \(service image stays LOCKED'
before 160 "NVMe released by the refused Store stage before the lifecycle" '^dma_gate: nvme bus master revoked' '^lifecycle: ready state=locked'
rabsent 160 "no TEST key banner" 'TEST-ONLY service image'
rcheck 161 "task refused while locked" '^lifecycle: REFUSED verb=task state=locked reason="locked: no production Store"'
rcheck 161 "unlock refused, still locked" '^lifecycle: REFUSED verb=unlock state=locked reason="production key source refused: still locked"'
rcheck 161 "unlock asked the production key source again" '^store: unlock REFUSED proof=keyed step="production Store key source" rc=-2002'
rcheck 161 "status answered" '^lifecycle: state=locked store=locked pending=- requests='
rcheck 161 "help answered" '^lifecycle: verbs: status unlock task <text> approve deny cancel evidence help shutdown$'
rcheck 161 "evidence answered" '^lifecycle: evidence requests=5 refused=2 invalid=0 tasks=0 approved=0'
rcheck 162 "stop order with no Store" '^lifecycle: stop order store=was-locked nvme=released state=stop requests=6$'
before 162 "stop order < stage result" '^lifecycle: stop order' '^stage lifecycle: ok rc=0$'
before 162 "stage result < final report" '^stage lifecycle: ok rc=0$' '^report_kind: final'
rabsent 162 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 162 "QEMU exit 0"; else bad 162 "QEMU exit ${qemu_status}"; fi
m1 162

# --- boot 2: TEST-ONLY test-keys image, READY/SERVE ---
boot testkeys "${testkeys_efi}" drive_ready
rcheck 163 "TEST-ONLY banner" '^lifecycle: TEST-ONLY service image \(CK_SERVICE_TEST_KEYS=1: TEST Store keys; QEMU only, never a production boot\)$'
rcheck 163 "Store open, NVMe kept bound for the service lifetime" '^store: service lifetime: Store open, NVMe stays bound until the lifecycle stop order$'
rcheck 163 "lifecycle ready" '^lifecycle: ready state=ready store=open \(operator input: serial\)$'
if [[ -n "$(line_of '^dma_gate: nvme bus master revoked')" && "$(line_of '^dma_gate: nvme bus master revoked')" -lt "$(line_of '^lifecycle: ready state=ready')" ]]; then bad 163 "NVMe revoked before the lifecycle (service lifetime broken)"; else ok 163 "no NVMe revoke before the lifecycle"; fi
rcheck 164 "task proposed" '^lifecycle: task pending state=serve proposed="note: draft the plan" \(approve \| deny \| cancel\)$'
rcheck 164 "approve committed to the Store" '^lifecycle: approve committed gen=[0-9]+ id=[0-9a-f]{8} state=ready$'
rcheck 165 "second task while pending refused" '^lifecycle: REFUSED verb=task state=serve reason="a task is pending: approve, deny or cancel it first"'
rcheck 165 "approve with nothing pending refused" '^lifecycle: REFUSED verb=approve state=ready reason="nothing pending"'
rcheck 165 "deny drops" '^lifecycle: denied state=ready$'
rcheck 165 "cancel drops" '^lifecycle: cancelled state=ready$'
rcheck 166 "overlong line refused whole" '^lifecycle: REFUSED verb=invalid reason="line longer than 64 bytes"$'
rcheck 166 "evidence counts" '^lifecycle: evidence requests=10 refused=2 invalid=0 tasks=3 approved=1 denied=1 cancelled=1 overlong=1 last_commit_gen=[0-9]+ last_id=[0-9a-f]{8}$'
rcheck 167 "stop order closed the Store" '^lifecycle: stop order store=closed nvme=released state=stop requests=11$'
before 167 "lifecycle ready < NVMe revoke (revoke only at the stop order)" '^lifecycle: ready state=ready' '^dma_gate: nvme bus master revoked'
before 167 "NVMe revoke < stop order line" '^dma_gate: nvme bus master revoked' '^lifecycle: stop order store=closed'
before 167 "stop order < stage result" '^lifecycle: stop order store=closed' '^stage lifecycle: ok rc=0$'
before 167 "stage result < final report" '^stage lifecycle: ok rc=0$' '^report_kind: final'
rabsent 167 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 167 "QEMU exit 0"; else bad 167 "QEMU exit ${qemu_status}"; fi
m1 167

if [[ "${fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for b in service testkeys; do echo "---- ${b} serial (lifecycle lines) ----"; grep -E '^(lifecycle|store|stage lifecycle|dma_gate|smmu: nvme|report_kind|mm_usage)' "${top}/${b}/serial.txt" | head -60 || true; done
fi
if [[ "${fail}" == 0 ]]; then echo "${final_tag}: PASS (QEMU only; hardware NOT_RUN)"; exit 0; fi
echo "${final_tag}: FAIL"; exit 1
