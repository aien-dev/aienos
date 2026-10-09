#!/usr/bin/env bash
# AIENOS_CK_OSH_OP gate (OSH-AIENOS-OP, aien-architecture#158): a REAL capability-authorized operation through the shared
# OSH interface. The same three compiled shell units (lex_run, parse_run, expand_run) run as admitted EL0 tasks; on a ready
# pipeline the request record goes to the adapter's operation layer (native/kernel/core/osh_op.c) instead of a fake status.
# Operation: `klog <words>` writes "osh_op_out: <words>" to the console. Capability: WRITE on the console-log resource in
# the session's kernel IPC capability table (domain 1). The OSH_CORE gate (qemu_ck_osh_core_test.sh, fixture traces) is
# unchanged and separate; this gate does not run the fixtures.
#
# Label: QEMU (aarch64 virt), TEST signer, not physical. Nothing here ran on a Spark or any real machine.
# Cases (one boot, CK_SEED0B_TEST_ANCHOR=1 CK_OSH_TEST=1 CK_OSH_OP_TEST=1):
#   allow           WRITE held: two lines and two "grant used" receipts on the console (the second shows $? = the real status 0 flowing back into the shell core)
#   deny_no_cap     no capability: DENIED, no bytes, outcome FAILED_NO_EFFECT, a security receipt line
#   deny_read_only  READ only: DENIED, no bytes
#   revoked         revoked between request build and effect: REVOKED, no bytes
#   interrupt       interrupt before pipeline 2 of 3: pipeline 1 done, 2 CANCELLED, 3 never runs, status 130
#   lost            adapter lost after the effect: bytes appear once; restart reports OUTCOME_UNKNOWN with the digest, never replays
#   after_restart   a new request after the loss is a new decision and runs
#   unsupported     pipe, redirection, unknown command: NOT_SUPPORTED / NOT_FOUND before any effect
# every case: capability released at the end, no EL0 task slot left held.
# Last line: AIENOS_CK_OSH_OP: PASS|FAIL|NOT_RUN.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict=AIENOS_CK_OSH_OP
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict}: NOT_RUN"; exit 2; }

# Machine quiet flag (read only) and the QEMU gate lock (one gate at a time):
# scripts/lib_gate_hold.sh (aienos#278).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take "qemu_ck_osh_op_test" "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "${verdict}: NOT_RUN"
    exit 3
fi
# Release only this run's own gate lock record, at most once.
release_flag() { gh_lock_release; }
work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; release_flag; }
trap cleanup EXIT
failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out_prod="${AIENOS_CK_OUT_PROD:-${repo_root}/target/native-kernel}"
out_osh="${AIENOS_CK_OUT_OSH:-${repo_root}/target/native-kernel-osh-op-test}"
mk() { make -s -C native/kernel CROSS="${cross}" AIENOS_COMMIT="${commit}" "$@" >/dev/null; }

fix="native/kernel/tests/fixtures/osh"
mk OUT="${out_osh}" CK_SEED0B_TEST_ANCHOR=1 CK_OSH_TEST=1 CK_OSH_OP_TEST=1 full
make -s -C native/kernel OUT="${out_prod}" store-image gpt-image >/dev/null
simg="${out_prod}/host/ck_store_image"

files=("${fix}/osh_lex.unit" "${fix}/osh_parse.unit" "${fix}/osh_expand.unit")
disk="${work}/nvme.img"
"${out_prod}/host/ck_gpt_image" create "${disk}" 512 64 aienos-middle >/dev/null || fail "GPT boot disk image created"
if "${simg}" build "${disk}" 512 "${files[@]}" >"${work}/build.txt" 2>&1; then pass "boot disk built: $(head -1 "${work}/build.txt")"
else fail "boot disk build: $(head -3 "${work}/build.txt" | tr '\n' ' ')"; fi

boot() { # image, serial text output, disk image
    local esp="${work}/esp" log="${work}/serial.log" started status
    rm -rf "${esp}"
    mkdir -p "${esp}/EFI/BOOT" "${esp}/EFI/AIENOS"
    touch "${esp}/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$1" "${esp}/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    started=$(date +%s)
    set +e
    nice -n 10 timeout "${AIENOS_QEMU_TIMEOUT:-900}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${esp}" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="$3" \
        -device nvme,drive=nvme0,serial=aienos-nvme-test \
        -device ramfb -display none -nic none \
        -serial file:"${log}" -no-reboot
    status=$?
    set -e
    tr -d '\r' <"${log}" >"$2"
    echo "qemu exit ${status} after $(( $(date +%s) - started )) s (commit ${commit:0:12})"
    [[ "${status}" == 0 ]] || fail "QEMU exit status ${status} (124 = timeout)"
}
has() { grep -qE -- "$2" "$1"; }
check() { if has "$1" "$3"; then pass "$2"; else fail "$2"; fi; }

serial="${work}/serial.txt"
boot "${out_osh}/full/BOOTAA64.EFI" "${serial}" "${disk}"
release_flag

label='QEMU \(aarch64 virt\), TEST signer, not physical'
count() { grep -cE -- "$2" "$1" || true; }
exact() { # description, regex, expected count
    local n; n="$(count "${serial}" "$2")"
    if [[ "${n}" == "$3" ]]; then pass "$1 (${n})"; else fail "$1: expected $3, got ${n}"; fi
}
check "${serial}" "left firmware and entered the kernel" "kernel: alive"
check "${serial}" "kernel read all three candidates from the boot disk Store" "^artifact_candidates: 3$"
for u in osh_lex osh_parse osh_expand; do
    check "${serial}" "${u} admitted (real oscc output, TEST signer)" "^osc_unit: ${u}\\.unit ACCEPT unit_digest=[0-9a-f]{64} program_id=[0-9a-f]{64} funcs=[0-9]+ caps=0 signer=TEST$"
done
check "${serial}" "core line: 3 units" "^osh_core: units=3 ws_cells=11456 ws_pages=23 input_max=4096; ${label}\$"
check "${serial}" "report reached the console" "report_kind: final"
if has "${serial}" "report_kind: (panic|fault)"; then fail "panic or fault reported"; else pass "no kernel panic or fault report"; fi
if has "${serial}" "^osh_fault:"; then fail "a shell launch did not return"; else pass "every shell launch returned"; fi
exact "no fixture trace ran in this build" "^osh_script_begin" 0
check "${serial}" "all eight cases ran" "^osh_op_done: cases=8; ${label}\$"

P="^osh_op_pipeline: case="
E="^osh_op_end: case="
# allow
exact "allow: the real effect, line 1 on the console" "^osh_op_out: hello from osh\$" 1
exact "allow: line 2 carries \$? = the real status 0 back through the shell core" "^osh_op_out: status=0\$" 1
exact "allow: both pipelines COMPLETED with status 0" "${P}allow n=[12] status=0 error=OK outcome=COMPLETED stop=0 crashed=0 request_digest=[0-9a-f]{64}; ${label}\$" 2
check "${serial}" "allow: 2 console writes, no task slot held, capability released" "${E}allow rc=0 final_status=0 sink_calls=2 launches=[0-9]+ slots_held=0 cap_table_empty=1 cap_released=1; ${label}\$"
# denials
for c in deny_no_cap deny_read_only; do
    check "${serial}" "${c}: refused DENIED before any effect (status 126, FAILED_NO_EFFECT)" "${P}${c} n=1 status=126 error=DENIED outcome=FAILED_NO_EFFECT stop=0 crashed=0 request_digest=[0-9a-f]{64}; ${label}\$"
    check "${serial}" "${c}: no console write, capability released" "${E}${c} rc=0 final_status=126 sink_calls=0 launches=[0-9]+ slots_held=0 cap_table_empty=1 cap_released=1; ${label}\$"
    check "${serial}" "${c}: a security receipt names the denial, principal and capability" "^osh_op_receipt: seq=1 op=console_write result=DENIED request_digest=[0-9a-f]{64} effect=none principal=[0-9a-f]{64} cap_domain=1 cap_index=[0-9]+ cap_generation=[0-9]+ resource_class=1 operation=1 case=${c}; ${label}\$"
done
check "${serial}" "revoked: REVOKED at the effect boundary, FAILED_NO_EFFECT" "${P}revoked n=1 status=126 error=REVOKED outcome=FAILED_NO_EFFECT stop=0 crashed=0 "
check "${serial}" "revoked: no console write, capability released" "${E}revoked rc=0 final_status=126 sink_calls=0 launches=[0-9]+ slots_held=0 cap_table_empty=1 cap_released=1; "
check "${serial}" "revoked: receipt names REVOKED" "^osh_op_receipt: seq=1 op=console_write result=REVOKED "
exact "no refused case wrote any secret marker" "^osh_op_out: .*SECRET" 0
# interrupt
check "${serial}" "interrupt: pipeline 1 completed" "${P}interrupt n=1 status=0 error=OK outcome=COMPLETED "
check "${serial}" "interrupt: pipeline 2 INTERRUPTED, CANCELLED, list stops, status 130" "${P}interrupt n=2 status=130 error=INTERRUPTED outcome=CANCELLED stop=1 crashed=0 "
exact "interrupt: pipeline 3 never ran" "${P}interrupt n=3 " 0
check "${serial}" "interrupt: one console write, status 130, capability released, no task slot held" "${E}interrupt rc=1 final_status=130 sink_calls=1 launches=[0-9]+ slots_held=0 cap_table_empty=1 cap_released=1; "
exact "interrupt: 'one' printed, 'two' and 'three' not" "^osh_op_out: one\$" 1
exact "interrupt: 'two'/'three' absent" "^osh_op_out: (two|three)\$" 0
# lost
exact "lost: the effect happened exactly once" "^osh_op_out: LOST-MARKER\$" 1
check "${serial}" "lost: outcome open (OUTCOME_UNKNOWN, crashed)" "${P}lost n=1 status=70 error=OUTCOME_UNKNOWN outcome=OUTCOME_UNKNOWN stop=1 crashed=1 "
check "${serial}" "lost: restart reports the open intent as OUTCOME_UNKNOWN with its digest, replayed=0" "^osh_op_record: seq=1 outcome=OUTCOME_UNKNOWN request_digest=[0-9a-f]{64} replayed=0 case=lost; "
check "${serial}" "lost: restart found 1 open intent, a 2nd scan 0, no console write added, restarted adapter holds no capability" "^osh_op_restart: case=lost open_intents=1 second_scan=0 sink_calls_before=1 sink_calls_after=1 held_cap=0; "
exact "lost: still exactly one LOST-MARKER after restart (never replayed)" "^osh_op_out: LOST-MARKER\$" 1
check "${serial}" "lost: capability released" "${E}lost rc=1 final_status=70 sink_calls=1 launches=[0-9]+ slots_held=0 cap_table_empty=1 cap_released=1; "
exact "after_restart: a new request is a new decision and runs" "^osh_op_out: fresh decision\$" 1
# unsupported
check "${serial}" "unsupported: a pipe is NOT_SUPPORTED before any effect" "${P}unsupported n=1 status=126 error=NOT_SUPPORTED outcome=NOT_STARTED "
check "${serial}" "unsupported: a redirection is NOT_SUPPORTED" "${P}unsupported n=2 status=126 error=NOT_SUPPORTED outcome=NOT_STARTED "
check "${serial}" "unsupported: an unknown command is NOT_FOUND (127)" "${P}unsupported n=3 status=127 error=NOT_FOUND outcome=NOT_STARTED "
check "${serial}" "unsupported: no console write, no task slot held" "${E}unsupported rc=0 final_status=127 sink_calls=0 launches=[0-9]+ slots_held=0 cap_table_empty=1 cap_released=1; "
# totals
G="^osh_op_receipt: seq=[0-9]+ op=console_write result=OK request_digest=[0-9a-f]{64} effect=console_write principal=[0-9a-f]{64} cap_domain=1 cap_index=[0-9]+ cap_generation=[0-9]+ resource_class=1 operation=1"
exact "grant used: one security receipt per console write, 5 in all" "${G} case=[a-z_]+; ${label}\$" 5
exact "grant used: allow wrote 2 lines, 2 receipts" "${G} case=allow; " 2
exact "grant used: even the lost-after-effect case has its receipt" "${G} case=lost; " 1
exact "grant used: no receipt for a refused case" "^osh_op_receipt: .* result=OK .* case=(deny_no_cap|deny_read_only|revoked|unsupported); " 0
exact "the whole boot wrote exactly five console lines through the operation" "^osh_op_out: " 5
exact "no case leaked a task slot" "^osh_op_end: .* slots_held=[1-9]" 0
exact "every case released its capability" "^osh_op_end: .* cap_released=1; " 8
# control: a wrong expectation must turn the check red, then the right one green
if has "${serial}" "^osh_op_out: hello from osh DOES-NOT-APPEAR\$"; then fail "control: the gate cannot go red"; else pass "control: a deliberately wrong expected console line is not found (red), the real one is (above)"; fi

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then cp "${serial}" "${AIENOS_LOG_DIR}/qemu_ck_osh_op_serial.log"; fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial (osh_op lines) ----"; grep -E "^(osc_|osh_|artifact|kernel|report_kind|panic|fault)" "${serial}" | head -120 || true
fi
echo "label: QEMU (aarch64 virt), TEST signer, not physical"
if [[ "${failed}" == 0 ]]; then echo "${verdict}: PASS"; else echo "${verdict}: FAIL"; exit 1; fi
