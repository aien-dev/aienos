#!/usr/bin/env bash
# LIFECYCLE gate for the AIENOS C kernel (native v1 plan P03 + P04 cut 1 + P05
# cut 1 + P06 cut 2): rows 160-176 of native/kernel/GATES.md "LIFECYCLE resident
# production lifecycle". C-only.
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# Boots two CK_SERVICE images in QEMU AArch64 (AAVMF, NVMe disk, iommu=smmuv3),
# operator input over the PL011 serial from OUTSIDE the guest (pipe chardev):
#   service   make full CK_SERVICE=1: the production entry. The production key
#             source (TPM Slot 0) refuses, so the lifecycle comes up LOCKED with
#             the NVMe kept bound, refuses every task and a bare unlock, still
#             answers status/help/evidence, and shuts down in order. Booted a
#             second and third time (P04 cut 1): `unlock <64-hex recovery secret>`
#             runs the ADR 0017 Slot 1 keyslot path: genesis on the blank disk
#             (K_vol from the entropy service, manifest committed with the boot
#             record), a note approved and committed, shutdown; then on the SAME
#             disk a wrong secret is refused by the keyslot tag and the right one
#             unwraps K_vol and reopens the Store at the next generation. The
#             secret is echoed as '*' and never appears in the serial log.
#   testkeys  make full CK_SERVICE=1 CK_SERVICE_TEST_KEYS=1 (TEST-ONLY): the
#             Store opens with TEST keys so READY/SERVE run: a task is proposed,
#             approve commits it to the Store, deny and cancel drop tasks, a
#             second task while one is pending is refused, an overlong line is
#             refused whole, evidence counts agree, shutdown closes the Store
#             before the NVMe release before the final report.
#
#   row 160  service image: lifecycle starts after mm_usage, state=locked,
#            store=locked; the Store stage refused with BlockedOperator and
#            kept the NVMe bound for a later unlock; no TEST key banner
#   row 161  locked: task and a bare unlock REFUSED (state stays locked),
#            status/help/evidence answered
#   row 162  locked shutdown: stop order store=was-locked after the NVMe
#            revoke, then stage result, then final report; no panic/fault;
#            QEMU exit 0; M1 checks
#   row 163  testkeys image: announces TEST-ONLY banner, Store open, NVMe kept
#            bound for the service lifetime (no dma_gate revoke before ready)
#   row 164  serve: task -> pending with the proposed note; approve -> committed
#            with a Store generation and object id; state back to ready
#   row 165  deny and cancel drop pending tasks; a second task while pending is
#            refused; approve with nothing pending is refused
#   row 166  bounds: a 97-byte line is refused whole and never run; evidence
#            shows tasks=3 approved=1 denied=1 cancelled=1 overlong=1
#   row 167  stop order: store=closed, then dma_gate nvme bus master revoked,
#            then smmu stream back to abort, then stage lifecycle ok, then the
#            final report; QEMU exit 0; M1 checks
#   row 168  unlock genesis (service image, blank disk): `unlock deadbeef` refused
#            (64 hex digits expected); `unlock <secret>` formats a production
#            Store with the keyslot manifest (genesis=1, generation 2, boot 1),
#            lifecycle ready, a note approved and committed, stop order closes
#   row 169  unlock resume (same disk): wrong secret refused (RecoverySecretRejected,
#            disk not reformatted, still locked); right secret unwraps K_vol,
#            Store opened at generation 3 boot_count 1, committed generation 4
#   row 170  secret hygiene: the typed secret is echoed as 64 '*' and the hex
#            never appears in either serial log; no TEST key banner
#   row 171  P05 cut 1 continuity GENESIS (unlock boot, after `unlock ok`): the
#            production continuity service provisions the identity (AgentRoot,
#            AgentState, Manifest incarnation 1) and the ALLEN subject (sequence 1)
#            in one transaction (generation 3); `status` reports continuity=provisioned
#   row 172  P05 cut 1 continuity RESUME (relock boot): the subject is RESTORED
#            (sequence 1), the identity RESUMED at incarnation 2 (generation 6) with
#            the same agent id; no second genesis; status continuity=resumed
#   row 173  shape: the locked boot prints no continuity line; the test-keys image
#            provisions before `Store open`; the service image carries the
#            production continuity layer and no TEST mode selection (AIENCONT)
#   row 174  P06 cut 2 (boot 5, test-keys image built with CK_INFER_LIB, model over
#            the TEST-ONLY fw_cfg channel, -m 4096): the model and one bounded
#            session are resident from boot (`infer: resident open rc=0`, before
#            `lifecycle: ready`); `prompt What is the capital of France?` generates
#            the golden reply (ids 791 6864 315 9822 374 12366 13 128009, 17
#            prompt ids, 25 steps) which becomes the pending proposal; `approve`
#            commits it as one sealed reply object (kind 'R1')
#   row 175  `prompt Say hello.` then `cancel` stops generation between steps
#            (steps >= 1, produced 0, state ready, nothing pending); `recall` reads
#            the newest approved object back through the sealed Store (kind=reply,
#            the prompt and "The capital of France is Paris."); boot 6 (same
#            disk, cold boot): continuity RESUMED, `recall` answers from the disk
#   row 176  evidence counters (prompts=2 replies=1 gen_cancelled=1 gen_failed=0
#            inference=resident); stop order: `infer: resident close` and
#            `infer: unloaded` (every frame returned) before the stop order line;
#            QEMU exit 0; M1 checks. Separate verdict AIENOS_CK_LIFECYCLE_INFER:
#            NOT_RUN (never a silent pass) when the model file, cargo or the Rust
#            target aarch64-unknown-none is missing; TCG needs ~25 min for it
#   row 179  P06 cut 4 (test-keys boot 2): `remember prefer short notes` creates
#            the Cortex journal (one sealed header transaction) and appends one
#            CX_CLAIM record (one sealed transaction); `facts` in the same boot
#            lists it with the chain verified; evidence counts remembers/facts;
#            the journal closes (heap frames returned) before the stop order
#   row 180  production genesis boot (boot 3): the same two verbs on the
#            production Store after the approved note; stop order requests=9
#   row 181  cold production boot (boot 4): `facts` alone answers the fact from
#            the disk (records=1, digest and chain re-verified at open); the fact
#            is never typed in that boot; the Store opens at generation 6 (journal open at 8:
#            note 4, journal header 5, fact 6, boot record 7, continuity resume 8)
#   row 182  P04 cut 2a SecurityManifest, TEST-key Store (boot 2): the boot
#            transaction commits `store: security manifest sequence=1 generation=2
#            keyslot=none previous=genesis` (no KeySlotManifest on a TEST Store)
#   row 183  P04 cut 2a SecurityManifest, production Store: genesis (boot 3)
#            `sequence=1 generation=2 keyslot=bound previous=genesis`; cold resume
#            (boot 4) `sequence=2 generation=7 keyslot=bound previous=linked` (the
#            manifest read back verified under K_root_auth, bound the keyslot the
#            keyed open bound, carried key_epoch 1 and the manifest count)
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
if ! gh_lock_take qemu_ck_lifecycle_test "${AIENOS_GATE_MINUTES:-75}"; then echo "NOT_RUN  ${gh_why}"; echo "${final_tag}: NOT_RUN (QEMU gate lock held)"; exit 3; fi
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
boot_to="${boot_timeout}" # per boot; the inference boots raise it
boot_mem=2048             # MiB; the inference boots need the model in RAM
boot_extra=()             # extra QEMU arguments (the fw_cfg model channel)
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
ser_wait() { wait_for 180 "$1" '^report_kind: (panic|fault|final)' || true; }
# QEMU-only recovery secrets (public test values, 32 bytes as 64 hex; never a production secret)
secret_ok="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
secret_bad="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1eff"

boot() { # name efi driver [nvme.img to reuse]
    work="${top}/$1"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    # GPT boot disk (tools/ck_gpt_image.c, as the Store gate): protective MBR,
    # primary + backup GPT, sentinels, AIENOS partition all zero (Store at genesis).
    if [[ -n "${4:-}" ]]; then cp "$4" "${work}/nvme.img"; else "${gpt_tool}" create "${work}/nvme.img" 512 64 aienos-middle >/dev/null; fi
    mkfifo "${work}/ser.in" "${work}/ser.out"
    : >"${work}/serial.log"
    timeout "${boot_to}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m "${boot_mem}" \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${work}/nvme.img" \
        -device nvme,drive=nvme0,serial=aienos-lifecycle-test \
        -device ramfb -display none -nic none -monitor none \
        -chardev pipe,id=ser,path="${work}/ser" -serial chardev:ser -no-reboot "${boot_extra[@]}" 2>"${work}/qemu.err" &
    qemu_pid=$!
    cat "${work}/ser.out" >>"${work}/serial.log" &
    drain_pid=$!
    exec 4>"${work}/ser.in"
    if wait_for "${boot_to}" '^lifecycle: ready state=' '^report_kind: (panic|fault|final)' && serial_has '^lifecycle: ready state='; then
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
    ser_line "$(printf 'x%.0s' $(seq 97))"
    ser_line "remember prefer short notes"; ser_wait '^lifecycle: (remembered|REFUSED verb=remember)'
    ser_line facts; ser_wait '^lifecycle: (facts records=|facts none|REFUSED verb=facts)'
    ser_line evidence
    ser_line shutdown
}

drive_unlock() {
    ser_line "unlock deadbeef"
    ser_line "unlock ${secret_ok}"; ser_wait '^(lifecycle: unlock ok|lifecycle: REFUSED verb=unlock)'
    ser_line status
    ser_line "task write a note"; ser_line approve; ser_wait '^lifecycle: (approve committed|REFUSED verb=approve)'
    ser_line "remember prefer short notes"; ser_wait '^lifecycle: (remembered|REFUSED verb=remember)'
    ser_line facts; ser_wait '^lifecycle: (facts records=|facts none|REFUSED verb=facts)'
    ser_line evidence
    ser_line shutdown
}
# P06 cut 2: the resident model answers a prompt, the reply is approved and
# committed, a second prompt is cancelled between steps, recall reads the disk.
infer_wait="${AIENOS_QEMU_INFER_WAIT:-1800}"
drive_infer() {
    ser_line status
    ser_line "prompt What is the capital of France?"
    wait_for "${infer_wait}" '^lifecycle: (reply pending|generation cancelled|REFUSED verb=prompt)' '^report_kind: (panic|fault|final)' || true
    ser_line approve; ser_wait '^lifecycle: (approve committed|REFUSED verb=approve)'
    ser_line "prompt Say hello."
    sleep 5
    ser_line cancel
    wait_for 900 '^lifecycle: (generation cancelled|reply pending|REFUSED verb=prompt)' '^report_kind: (panic|fault|final)' || true
    ser_line evidence
    ser_line recall
    ser_line shutdown
}
drive_infer_recall() {
    ser_line status; ser_line recall; ser_line evidence; ser_line shutdown
}
drive_relock() {
    ser_line "unlock ${secret_bad}"; ser_wait '^(lifecycle: unlock ok|lifecycle: REFUSED verb=unlock)'
    ser_line status
    ser_line "unlock ${secret_ok}"; ser_wait '^(lifecycle: unlock ok|lifecycle: REFUSED verb=unlock)'
    ser_line status
    ser_line facts; ser_wait '^lifecycle: (facts records=|facts none|REFUSED verb=facts)'
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
if grep -aqF "continuity: REFUSED" "${service_efi}" && ! grep -aqF "AIENCONT" "${service_efi}" && ! grep -aqF "RECOVERY_OPERATOR_KEY" "${service_efi}"; then ok 173 "service image carries the production continuity layer and no TEST mode selection"; else bad 173 "service image continuity shape wrong (layer missing, or AIENCONT / TEST operator key present)"; fi
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
rcheck 160 "Store LOCKED keeps the NVMe bound for a later unlock" '^store: service lifetime: Store LOCKED, NVMe stays bound for `unlock <64-hex recovery secret>` or the lifecycle stop order$'
if [[ -n "$(line_of '^dma_gate: nvme bus master revoked')" && "$(line_of '^dma_gate: nvme bus master revoked')" -lt "$(line_of '^lifecycle: ready state=locked')" ]]; then bad 160 "NVMe revoked before the locked lifecycle (unlock would have no disk)"; else ok 160 "no NVMe revoke before the locked lifecycle"; fi
rabsent 160 "no TEST key banner" 'TEST-ONLY service image'
rcheck 161 "task refused while locked" '^lifecycle: REFUSED verb=task state=locked reason="locked: no production Store"'
rcheck 161 "unlock refused, still locked" '^lifecycle: REFUSED verb=unlock state=locked reason="production key source refused: still locked"'
rcheck 161 "unlock asked the production key source again" '^store: unlock REFUSED proof=keyed step="production Store key source" rc=-2002'
rcheck 161 "status answered" '^lifecycle: state=locked store=locked pending=- requests='
rcheck 161 "help answered" '^lifecycle: verbs: status unlock \[<64-hex recovery secret>\] task <text> prompt <text> approve deny cancel recall remember <text> facts evidence help shutdown$'
rcheck 161 "evidence answered" '^lifecycle: evidence requests=5 refused=2 invalid=0 tasks=0 approved=0'
rcheck 162 "stop order with no Store" '^lifecycle: stop order store=was-locked nvme=released state=stop requests=6$'
before 162 "locked lifecycle ready < NVMe revoke (revoke only at the stop order)" '^lifecycle: ready state=locked' '^dma_gate: nvme bus master revoked'
before 162 "NVMe revoke < stop order line" '^dma_gate: nvme bus master revoked' '^lifecycle: stop order store=was-locked'
before 162 "stop order < stage result" '^lifecycle: stop order' '^stage lifecycle: ok rc=0$'
before 162 "stage result < final report" '^stage lifecycle: ok rc=0$' '^report_kind: final'
rabsent 162 "no panic or fault" '^report_kind: (panic|fault)'
rabsent 173 "no continuity line while locked" '^(continuity|allen): '
if [[ "${qemu_status}" == 0 ]]; then ok 162 "QEMU exit 0"; else bad 162 "QEMU exit ${qemu_status}"; fi
m1 162

# --- boot 2: TEST-ONLY test-keys image, READY/SERVE ---
boot testkeys "${testkeys_efi}" drive_ready
rcheck 163 "TEST-ONLY banner" '^lifecycle: TEST-ONLY service image \(CK_SERVICE_TEST_KEYS=1: TEST Store keys; QEMU only, never a production boot\)$'
rcheck 163 "Store open, NVMe kept bound for the service lifetime" '^store: service lifetime: Store open, NVMe stays bound until the lifecycle stop order$'
rcheck 163 "lifecycle ready" '^lifecycle: ready state=ready store=open \(operator input: serial\)$'
rcheck 182 "TEST-key Store: security manifest sequence 1 at genesis, no keyslot" '^store: security manifest sequence=1 generation=2 keyslot=none previous=genesis$'
rcheck 173 "test-keys image provisions continuity at boot" '^continuity: PROVISIONED agent=[0-9a-f]{64} incarnation=1 sequence=1 cortex=0 branches=1$'
before 173 "PROVISIONED < Store open line" '^continuity: PROVISIONED' '^store: service lifetime: Store open'
if [[ -n "$(line_of '^dma_gate: nvme bus master revoked')" && "$(line_of '^dma_gate: nvme bus master revoked')" -lt "$(line_of '^lifecycle: ready state=ready')" ]]; then bad 163 "NVMe revoked before the lifecycle (service lifetime broken)"; else ok 163 "no NVMe revoke before the lifecycle"; fi
rcheck 164 "task proposed" '^lifecycle: task pending state=serve proposed="note: draft the plan" \(approve \| deny \| cancel\)$'
rcheck 164 "approve committed to the Store" '^lifecycle: approve committed gen=[0-9]+ id=[0-9a-f]{8} state=ready$'
rcheck 165 "second task while pending refused" '^lifecycle: REFUSED verb=task state=serve reason="a task is pending: approve, deny or cancel it first"'
rcheck 165 "approve with nothing pending refused" '^lifecycle: REFUSED verb=approve state=ready reason="nothing pending"'
rcheck 165 "deny drops" '^lifecycle: denied state=ready$'
rcheck 165 "cancel drops" '^lifecycle: cancelled state=ready$'
rcheck 166 "overlong line refused whole" '^lifecycle: REFUSED verb=invalid reason="line longer than 96 bytes"$'
rcheck 166 "evidence counts" '^lifecycle: evidence requests=12 refused=2 invalid=0 tasks=3 approved=1 denied=1 cancelled=1 overlong=1 last_commit_gen=[0-9]+ last_id=[0-9a-f]{8} prompts=0 replies=0 gen_cancelled=0 gen_failed=0 recalls=0 inference=none remembers=1 facts=1 cortex=open records=1$'
rcheck 167 "stop order closed the Store" '^lifecycle: stop order store=closed nvme=released state=stop requests=13$'
rcheck 179 "remember created the journal (header transaction, no records yet)" '^lifecycle: cortex open records=0 chunks=1 journal_bytes=32 store_gen=[0-9]+ heap_used_kib=[0-9]+ chain=ok$'
rcheck 179 "remembered as record 1 (one sealed transaction)" '^lifecycle: remembered id=1 t=1 store_gen=[0-9]+ bytes=18 text="prefer short notes"$'
rcheck 179 "facts lists the fact in the same boot" '^lifecycle: fact id=1 t=1 store_gen=[0-9]+ text="prefer short notes"$'
rcheck 179 "facts summary, chain verified" '^lifecycle: facts records=1 shown=1 journal_bytes=192 chain=ok$'
rcheck 179 "journal closed first in the stop order" '^lifecycle: cortex closed records=1 appends=2 reads=[0-9]+ refused=0 heap_peak_kib=[0-9]+$'
before 179 "cortex closed < stop order line" '^lifecycle: cortex closed' '^lifecycle: stop order store=closed'
rabsent 179 "no refusal of remember or facts" '^lifecycle: REFUSED verb=(remember|facts)'
before 167 "lifecycle ready < NVMe revoke (revoke only at the stop order)" '^lifecycle: ready state=ready' '^dma_gate: nvme bus master revoked'
before 167 "NVMe revoke < stop order line" '^dma_gate: nvme bus master revoked' '^lifecycle: stop order store=closed'
before 167 "stop order < stage result" '^lifecycle: stop order store=closed' '^stage lifecycle: ok rc=0$'
before 167 "stage result < final report" '^stage lifecycle: ok rc=0$' '^report_kind: final'
rabsent 167 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 167 "QEMU exit 0"; else bad 167 "QEMU exit ${qemu_status}"; fi
m1 167

# --- boot 3: production service image, blank disk, recovery keyslot GENESIS ---
boot unlock "${service_efi}" drive_unlock
rcheck 168 "lifecycle came up locked" '^lifecycle: ready state=locked store=locked'
rcheck 168 "short secret refused (64 hex digits expected)" '^store: unlock REFUSED proof=keyed step="recovery secret syntax" rc=-2004 \(64 hex digits expected, got 8\)$'
rcheck 168 "blank disk formatted as a production store" '^store: blank disk \(all-zero anchor \+ Store head\): formatted production store$'
rcheck 168 "key source line: recovery keyslot genesis" '^store: key source=recovery-keyslot genesis=1 \(K_vol source: the Slot 1 recovery descriptor; TPM Slot 0 BLOCKED_HARDWARE; no rotation\)$'
rcheck 168 "store committed generation 2 boot 1" '^store: committed generation=2 boot_count=1$'
rcheck 183 "production genesis: security manifest sequence 1 binds the keyslot" '^store: security manifest sequence=1 generation=2 keyslot=bound previous=genesis$'
rcheck 168 "unlock ok" '^store: unlock ok source=recovery-keyslot slot=1 genesis=1 generation=2 boot_count=1$'
rcheck 168 "lifecycle unlocked to ready" '^lifecycle: unlock ok state=ready$'
rcheck 168 "status open" '^lifecycle: state=ready store=open pending=- requests='
rcheck 168 "task proposed" '^lifecycle: task pending state=serve proposed="note: write a note" \(approve \| deny \| cancel\)$'
rcheck 168 "approve committed generation 4 (after the continuity genesis at 3)" '^lifecycle: approve committed gen=4 id=[0-9a-f]{8} state=ready$'
rcheck 171 "genesis inputs declared" '^continuity: genesis source=qualification provenance=store-uuid-only \(identity and ALLEN subject in one transaction\)$'
rcheck 171 "identity PROVISIONED incarnation 1" '^continuity: PROVISIONED agent=[0-9a-f]{64} incarnation=1 sequence=1 cortex=0 branches=1$'
rcheck 171 "ALLEN subject GENESIS sequence 1" '^allen: GENESIS subject=[0-9a-f]{64} sequence=1 lineage=[0-9a-f]{64} intents=0 active=0 knowledge=0$'
before 171 "unlock ok < PROVISIONED" '^store: unlock ok' '^continuity: PROVISIONED'
before 171 "PROVISIONED < lifecycle unlock ok" '^continuity: PROVISIONED' '^lifecycle: unlock ok'
rcheck 171 "status reports continuity" '^lifecycle: state=ready store=open pending=- requests=[0-9]+ continuity=provisioned agent=[0-9a-f]{16} incarnation=1 subject_seq=1$'
unlock_agent="$(grep -oE '^continuity: PROVISIONED agent=[0-9a-f]{64}' "${top}/unlock/serial.txt" | head -1 | sed 's/.*agent=//')"
[[ -n "${unlock_agent}" ]] || unlock_agent="NO_AGENT"
rcheck 168 "stop order closed the Store" '^lifecycle: stop order store=closed nvme=released state=stop requests=9$'
rcheck 180 "production Store: journal created after the note (header at generation 5)" '^lifecycle: cortex open records=0 chunks=1 journal_bytes=32 store_gen=5 heap_used_kib=[0-9]+ chain=ok$'
rcheck 180 "production Store: fact committed at generation 6" '^lifecycle: remembered id=1 t=1 store_gen=6 bytes=18 text="prefer short notes"$'
rcheck 180 "production Store: facts lists it" '^lifecycle: facts records=1 shown=1 journal_bytes=192 chain=ok$'
rcheck 180 "evidence counts the two verbs" '^lifecycle: evidence requests=8 refused=1 invalid=0 tasks=1 approved=1 denied=0 cancelled=0 overlong=0 last_commit_gen=4 last_id=[0-9a-f]{8} prompts=0 replies=0 gen_cancelled=0 gen_failed=0 recalls=0 inference=none remembers=1 facts=1 cortex=open records=1$'
rabsent 180 "no refusal of remember or facts" '^lifecycle: REFUSED verb=(remember|facts)'
before 168 "stop order < stage result" '^lifecycle: stop order store=closed' '^stage lifecycle: ok rc=0$'
rabsent 168 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 168 "QEMU exit 0"; else bad 168 "QEMU exit ${qemu_status}"; fi
m1 168
rabsent 170 "secret hex never in the serial log (genesis boot)" "${secret_ok}"
rcheck 170 "typed secret echoed as 64 '*'" '^> unlock \*{64}$'
rabsent 170 "no TEST key banner" 'TEST-ONLY service image'
unlock_img="${top}/unlock/nvme.img"

# --- boot 4: same disk, wrong secret refused, right secret resumes ---
boot relock "${service_efi}" drive_relock "${unlock_img}"
rcheck 169 "lifecycle came up locked" '^lifecycle: ready state=locked store=locked'
rcheck 169 "wrong secret refused by the keyslot tag" '^store: unlock REFUSED proof=keyed step="recovery secret rejected \(K_vol unwrap tag failed\); disk not opened" rc=-2004 \(RecoverySecretRejected\); still LOCKED, disk not reformatted$'
rcheck 169 "lifecycle still locked after the wrong secret" '^lifecycle: REFUSED verb=unlock state=locked reason="production key source refused: still locked"$'
rcheck 169 "status still locked" '^lifecycle: state=locked store=locked pending=- requests=2 continuity=none$'
rabsent 169 "not reformatted" '^store: blank disk'
rcheck 169 "key source line: recovery keyslot resume" '^store: key source=recovery-keyslot genesis=0 '
rcheck 169 "store opened at generation 6 (keyslot + boot record + continuity genesis + note + journal header + fact), boot_count 1" '^store: opened generation=6 boot_count=1 prev_commit=[0-9a-f]+ anchor=valid-resume$'
rcheck 169 "store committed generation 7 boot 2" '^store: committed generation=7 boot_count=2$'
rcheck 183 "production resume: security manifest sequence 2 links the genesis one, keyslot bound" '^store: security manifest sequence=2 generation=7 keyslot=bound previous=linked$'
rabsent 183 "no SecurityManifest refusal in any boot" '^store: (unlock )?REFUSED proof=keyed step="SecurityManifest'
rcheck 169 "unlock ok, no genesis" '^store: unlock ok source=recovery-keyslot slot=1 genesis=0 generation=7 boot_count=2$'
rcheck 172 "ALLEN subject RESTORED sequence 1" '^allen: RESTORED subject=[0-9a-f]{64} sequence=1 lineage=[0-9a-f]{64} intents=0 active=0 knowledge=0$'
rcheck 172 "identity RESUMED incarnation 2, same agent as the genesis boot" "^continuity: RESUMED agent=${unlock_agent} incarnation=2 sequence=2 cortex=0 branches=1\$"
rabsent 172 "no second genesis" '^continuity: (PROVISIONED|genesis)'
rabsent 172 "no degraded mount" '^continuity: (degraded|RESUMED_READONLY|REFUSED)'
before 172 "unlock ok < RESUMED" '^store: unlock ok' '^continuity: RESUMED'
before 172 "RESUMED < lifecycle unlock ok" '^continuity: RESUMED' '^lifecycle: unlock ok'
rcheck 172 "status reports resumed" "^lifecycle: state=ready store=open pending=- requests=[0-9]+ continuity=resumed agent=${unlock_agent:0:16} incarnation=2 subject_seq=1\$"
rcheck 169 "lifecycle unlocked to ready" '^lifecycle: unlock ok state=ready$'
rcheck 169 "evidence: one refused unlock" '^lifecycle: evidence requests=6 refused=1 invalid=0 tasks=0 approved=0'
rcheck 169 "stop order closed the Store" '^lifecycle: stop order store=closed nvme=released state=stop requests=7$'
rcheck 181 "cold boot: journal opened from the disk, chain verified (1 record, 2 chunks)" '^lifecycle: cortex open records=1 chunks=2 journal_bytes=192 store_gen=8 heap_used_kib=[0-9]+ chain=ok$'
rcheck 181 "cold boot: the fact answers from the disk, not restated" '^lifecycle: fact id=1 t=1 store_gen=6 text="prefer short notes"$'
rcheck 181 "cold boot: facts summary" '^lifecycle: facts records=1 shown=1 journal_bytes=192 chain=ok$'
rabsent 181 "cold boot: the fact was never typed in this boot" '^> remember '
rabsent 181 "cold boot: nothing remembered in this boot" '^lifecycle: remembered '
rcheck 181 "cold boot: evidence shows facts only" '^lifecycle: evidence requests=6 refused=1 invalid=0 tasks=0 approved=0 denied=0 cancelled=0 overlong=0 last_commit_gen=0 last_id=00000000 prompts=0 replies=0 gen_cancelled=0 gen_failed=0 recalls=0 inference=none remembers=0 facts=1 cortex=open records=1$'
rcheck 181 "cold boot: journal closed before the stop order" '^lifecycle: cortex closed records=1 appends=0 reads=[0-9]+ refused=0 heap_peak_kib=[0-9]+$'
before 181 "cold boot: cortex closed < stop order" '^lifecycle: cortex closed' '^lifecycle: stop order store=closed'
rabsent 169 "no panic or fault" '^report_kind: (panic|fault)'
if [[ "${qemu_status}" == 0 ]]; then ok 169 "QEMU exit 0"; else bad 169 "QEMU exit ${qemu_status}"; fi
m1 169
rabsent 170 "secret hex never in the serial log (resume boot)" "${secret_ok}"
rabsent 170 "wrong secret hex never in the serial log" "${secret_bad}"

# --- boots 5 and 6: test-keys image with the resident inference session (P06 cut 2) ---
infer_tag="AIENOS_CK_LIFECYCLE_INFER"
infer_boots=""
model="${AIENOS_MODEL:-${HOME}/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf}"
infer_notrun=""
[[ -r "${model}" ]] || infer_notrun="model file ${model} missing"
[[ -n "${infer_notrun}" ]] || command -v cargo >/dev/null || infer_notrun="cargo not installed"
if [[ -z "${infer_notrun}" ]] && { ! rustc --print target-list 2>/dev/null | grep -qx aarch64-unknown-none \
   || ! [[ -d "$(rustc --print sysroot)/lib/rustlib/aarch64-unknown-none/lib" ]]; }; then
    infer_notrun="Rust target aarch64-unknown-none not installed (rustup target add aarch64-unknown-none)"
fi
[[ -z "${AIENOS_LIFECYCLE_SKIP_INFER:-}" ]] || infer_notrun="AIENOS_LIFECYCLE_SKIP_INFER set"
if [[ -n "${infer_notrun}" ]]; then
    echo "${infer_tag}: NOT_RUN (${infer_notrun})"
else
    fail_before_infer="${fail}"
    lib="${repo_root}/target/infer-kernel/aarch64-unknown-none/release/libaienos_infer_kernel.a"
    CARGO_TARGET_DIR="${repo_root}/target/infer-kernel" cargo build -q --release --target aarch64-unknown-none \
        --manifest-path crates/aienos-infer-kernel/Cargo.toml
    out_infer="${out}-lifecycle-infer" # own OUT: same FULL_NAME as the plain test-keys image
    make -s -C native/kernel CROSS="${cross}" OUT="${out_infer}" AIENOS_COMMIT="${commit}" full CK_SERVICE=1 CK_SERVICE_TEST_KEYS=1 CK_INFER_LIB="${lib}" >/dev/null
    infer_efi="${out_infer}/full-service-testkeys/BOOTAA64.EFI"
    if grep -aqF "infer: resident open" "${infer_efi}" && ! grep -aqF "infer: resident open" "${testkeys_efi}"; then ok 174 "only the CK_INFER_LIB service image carries the resident session"; else bad 174 "resident session shape wrong (missing from the inference image, or present in the plain test-keys image)"; fi
    re_open='^infer: resident open rc=0 tensors=147 vocab=128256 layers=16 kv_capacity=64 max_new=16 max_prompt_bytes=256 heap_reserve_kib=64 heap_used_kib=[0-9]+ open_us=[0-9]+$'
    re_recall='^lifecycle: recall gen=[0-9]+ kind=reply id=[0-9a-f]{8} bytes=[0-9]+ text="aienos\.reply\.v1.prompt: What is the capital of France\?.reply: The capital of France is Paris\.'
    frames_kept() { # row label: the unload line returned every frame (free after = free before)
        local l b a; l="$(grep -E -m1 '^infer: unloaded ' "${work}/serial.txt" || true)"
        b="$(sed -nE 's/.* frames_free_before=([0-9]+).*/\1/p' <<<"${l}")"; a="$(sed -nE 's/.* frames_free_after=([0-9]+).*/\1/p' <<<"${l}")"
        if [[ -n "${b}" && "${b}" == "${a}" ]] && grep -qE '^infer: unloaded .* rc=0,0$' <<<"${l}"; then ok "$1" "$2 (${b} = ${a})"; else bad "$1" "$2 (before=${b:-none} after=${a:-none})"; fi; }
    boot_to="${AIENOS_QEMU_INFER_TIMEOUT:-2700}"; boot_mem=4096; boot_extra=(-fw_cfg "name=opt/aienos/model,file=${model}")
    boot infer "${infer_efi}" drive_infer
    infer_boots="infer"
    rcheck 174 "TEST-ONLY fw_cfg model source declared" '^infer_source_mode: TEST-ONLY QEMU fw_cfg model ingest'
    rcheck 174 "resident session open with the declared limits" "${re_open}"
    before 174 "resident open < lifecycle ready" '^infer: resident open rc=0' '^lifecycle: ready state=ready store=open'
    rcheck 174 "TEST-ONLY banner" '^lifecycle: TEST-ONLY service image'
    rcheck 174 "generating line" '^lifecycle: generating prompt="What is the capital of France\?" \(cancel stops it between steps\)$'
    rcheck 174 "golden reply ids (17 prompt ids, 25 steps)" '^lifecycle: reply ids=791 6864 315 9822 374 12366 13 128009 tokens=8 prompt_ids=17 steps=25 us=[0-9]+$'
    rcheck 174 "reply is the pending proposal" '^lifecycle: reply pending state=serve proposed="reply: The capital of France is Paris\.\??" \(approve \| deny \| cancel\)$'
    rcheck 174 "approve committed the reply object" '^lifecycle: approve committed gen=[0-9]+ id=[0-9a-f]{8} state=ready$'
    rcheck 175 "second prompt cancelled between steps (produced 0, nothing pending)" '^lifecycle: generation cancelled steps=[1-9][0-9]* prompt_ids=[0-9]+ produced=0 us=[0-9]+ state=ready$'
    rabsent 175 "the cancel was not refused" '^lifecycle: REFUSED verb=cancel'
    rabsent 175 "no prompt refused" '^lifecycle: REFUSED verb=prompt'
    rcheck 175 "recall (same boot) reads the reply back through the sealed Store" "${re_recall}"
    rcheck 176 "evidence counters" '^lifecycle: evidence requests=5 refused=0 invalid=0 tasks=0 approved=1 denied=0 cancelled=0 overlong=0 last_commit_gen=[0-9]+ last_id=[0-9a-f]{8} prompts=2 replies=1 gen_cancelled=1 gen_failed=0 recalls=0 inference=resident remembers=0 facts=0 cortex=none records=0$'
    rcheck 176 "resident close" '^infer: resident close rc=0 heap_used_kib=[0-9]+ heap_peak_kib=[0-9]+$'
    frames_kept 176 "unload returned every frame"
    before 176 "resident close < unload line" '^infer: resident close rc=0' '^infer: unloaded '
    before 176 "unload line < stop order" '^infer: unloaded ' '^lifecycle: stop order store=closed'
    rcheck 176 "stop order closed the Store" '^lifecycle: stop order store=closed nvme=released state=stop requests=7$'
    before 176 "stop order < stage result" '^lifecycle: stop order store=closed' '^stage lifecycle: ok rc=0$'
    rabsent 176 "no panic or fault" '^report_kind: (panic|fault)'
    if [[ "${qemu_status}" == 0 ]]; then ok 176 "QEMU exit 0"; else bad 176 "QEMU exit ${qemu_status}"; fi
    m1 176
    infer_img="${top}/infer/nvme.img"
    # boot 6: same disk, cold boot; recall answers from the disk, nothing in memory
    boot_to="${AIENOS_QEMU_INFER_TIMEOUT:-2700}"; boot_mem=4096
    boot infer-recall "${infer_efi}" drive_infer_recall "${infer_img}"
    infer_boots="infer infer-recall"
    boot_to="${boot_timeout}"; boot_mem=2048; boot_extra=()
    rcheck 175 "cold boot: resident session open again" "${re_open}"
    rcheck 175 "cold boot: continuity RESUMED on the same disk" '^continuity: RESUMED agent=[0-9a-f]{64} incarnation=2 '
    rabsent 175 "cold boot: no second genesis" '^continuity: PROVISIONED'
    rcheck 175 "cold boot: recall returns the approved reply from the disk" "${re_recall}"
    rcheck 175 "cold boot: evidence shows one recall, no prompt" '^lifecycle: evidence requests=3 refused=0 invalid=0 tasks=0 approved=0 denied=0 cancelled=0 overlong=0 last_commit_gen=0 last_id=00000000 prompts=0 replies=0 gen_cancelled=0 gen_failed=0 recalls=1 inference=resident remembers=0 facts=0 cortex=none records=0$'
    frames_kept 175 "cold boot: unload returned every frame"
    rcheck 175 "cold boot: stop order closed the Store" '^lifecycle: stop order store=closed nvme=released state=stop requests=4$'
    rabsent 175 "cold boot: no panic or fault" '^report_kind: (panic|fault)'
    if [[ "${qemu_status}" == 0 ]]; then ok 175 "cold boot: QEMU exit 0"; else bad 175 "cold boot: QEMU exit ${qemu_status}"; fi
    m1 175
    if [[ "${fail}" == "${fail_before_infer}" ]]; then echo "${infer_tag}: PASS (QEMU only; hardware NOT_RUN)"; else echo "${infer_tag}: FAIL"; fi
fi

if [[ "${fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for b in service testkeys unlock relock ${infer_boots}; do echo "---- ${b} serial (lifecycle lines) ----"; grep -E '^(lifecycle|store|continuity|allen|infer|stage lifecycle|dma_gate|smmu: nvme|report_kind|mm_usage)' "${top}/${b}/serial.txt" | head -80 || true; done
fi
if [[ "${fail}" == 0 ]]; then echo "${final_tag}: PASS (QEMU only; hardware NOT_RUN)"; exit 0; fi
echo "${final_tag}: FAIL"; exit 1
