#!/usr/bin/env bash
# Boot the AIENOS C kernel core image in QEMU AArch64 (UEFI/AAVMF, EL2 like
# Machine 1, -smp 4) and check the secondary-core bring-up of core/smp.c:
# PSCI CPU_ON for every MADT core except the boot core, each core on its own
# stack with the MMU on the boot core's tables, checked in (its own MPIDR
# reported) and parked in WFE; the boot core waits with a bounded timeout.
# Last line: AIENOS_CK_SMP: PASS|FAIL|NOT_RUN (read by scripts/ck_gates.sh).
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# FAIL when (the script re-checks the lines itself, it does not trust the
# kernel's result=ok): a core never checks in; PSCI CPU_ON returns any error
# code; an MPIDR is duplicated or missing (boot + secondaries must be exactly
# the -smp N distinct values, each secondary must report the MPIDR it was
# started for); a secondary reports EL != 1, MMU off, other tables or a stack
# outside its own; the MADT core count differs from -smp N; the summary line
# is missing or not ok; the TEST-ONLY mutation image was booted; the boot
# panics or faults; QEMU exits non-zero.
#
# Usage: bash scripts/qemu_ck_smp_test.sh               the gate (default image)
#        bash scripts/qemu_ck_smp_test.sh --mutation    TEST-ONLY image built with
#            CK_TEST_SMP_SKIP_CPU=1 (CPU_ON skipped for one core): the gate
#            checks must FAIL on it; ends AIENOS_CK_SMP_MUTATION: PASS when
#            they do (the mutation is killed), FAIL when they pass
#        bash scripts/qemu_ck_smp_test.sh --self-test   canned serial logs for
#            every failure mode above, plus the Makefile refusals of the
#            mutation flag (with CK_HARDWARE_STAGING, bad value); no QEMU,
#            no compile (make -n stops at parse time). Ends
#            AIENOS_CK_SMP_SELF_TEST: PASS|FAIL
# Environment: AIENOS_CK_SMP_CPUS (default 4), AIENOS_QEMU_TIMEOUT (180 s),
# AIENOS_QUIET_FLAG / AIENOS_QUIET_TAG (as scripts/qemu_ck_boot_test.sh),
# AIENOS_LOG_DIR (copy of the serial log), AIENOS_QEMU_VERBOSE.
# Takes the machine quiet flag itself and prints NOT_RUN if another run holds
# it (exit 3). Needs qemu-system-aarch64 and AAVMF.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mode=gate
case "${1:-}" in
    "") ;;
    --mutation) mode=mutation ;;
    --self-test) mode=self ;;
    *) echo "usage: $0 [--mutation|--self-test]" >&2; exit 2 ;;
esac
ncpus="${AIENOS_CK_SMP_CPUS:-4}"
[[ "${ncpus}" =~ ^[0-9]+$ && "${ncpus}" -ge 2 && "${ncpus}" -le 16 ]] || { echo "AIENOS_CK_SMP_CPUS must be 2..16" >&2; exit 2; }
mut_marker="TEST-ONLY SMP mutation"

# smp_check_log FILE N: one PASS/FAIL line per check; sets smp_failed=1 on
# any failure (never resets it). Pure text checks, used by the gate, the
# mutation run and the self-test alike.
smp_check_log() {
    local f="$1" n="$2" line boot_re cpu_re sum_re tgt seen
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; smp_failed=1; }
    boot_re='^smp: boot_mpidr=0x([0-9a-f]+) madt_cpus=([0-9]+) conduit=(smc|hvc) psci_version=([0-9]+)\.([0-9]+)$'
    if [[ "$(grep -cE "${boot_re}" "${f}" || true)" != 1 ]]; then
        bad "exactly one smp: boot_mpidr line"
        return
    fi
    line="$(grep -E "${boot_re}" "${f}")"
    local boot_mpidr madt
    boot_mpidr="$(sed -E "s/${boot_re}/\\1/" <<<"${line}")"
    madt="$(sed -E "s/${boot_re}/\\2/" <<<"${line}")"
    [[ "${madt}" == "${n}" ]] && ok "MADT lists ${n} cores (-smp ${n})" || bad "MADT lists ${madt} cores, QEMU has ${n}"
    if grep -qE '^smp: FAIL' "${f}"; then bad "kernel reported $(grep -E '^smp: FAIL' "${f}" | head -1)"; else ok "no smp: FAIL line"; fi

    # PSCI CPU_ON: one call per secondary, every one SUCCESS.
    local on_n on_ok
    on_n="$(grep -cE '^smp_cpu_on: target=0x[0-9a-f]+ ' "${f}" || true)"
    on_ok="$(grep -cE '^smp_cpu_on: target=0x[0-9a-f]+ psci_rc=0 \(SUCCESS\)$' "${f}" || true)"
    [[ "${on_n}" == $((n - 1)) ]] && ok "CPU_ON issued for ${on_n} secondary cores" || bad "CPU_ON lines ${on_n}, expected $((n - 1))"
    if [[ "${on_ok}" == "${on_n}" && "${on_n}" -gt 0 ]]; then
        ok "PSCI CPU_ON returned SUCCESS for every core"
    else
        bad "PSCI CPU_ON error or skip: $(grep -E '^smp_cpu_on: ' "${f}" | grep -vE 'psci_rc=0 \(SUCCESS\)$' | head -3 | paste -sd';' -)"
    fi

    # Check-in: every secondary on EL1, MMU on our tables, its own stack,
    # reporting the MPIDR it was started for.
    cpu_re='^smp_cpu: target=0x([0-9a-f]+) checked_in=yes seen_mpidr=0x([0-9a-f]+) el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe$'
    local in_n mism=0 mpidrs="${boot_mpidr}"
    in_n="$(grep -cE "${cpu_re}" "${f}" || true)"
    if grep -qE '^smp_cpu: target=0x[0-9a-f]+ checked_in=no' "${f}"; then
        bad "core never checked in: $(grep -E '^smp_cpu: .*checked_in=no' "${f}" | head -3 | paste -sd';' -)"
    fi
    if grep -E '^smp_cpu: ' "${f}" | grep -qvE "${cpu_re}|checked_in=no"; then
        bad "secondary state wrong: $(grep -E '^smp_cpu: ' "${f}" | grep -vE "${cpu_re}|checked_in=no" | head -2 | paste -sd';' -)"
    fi
    [[ "${in_n}" == $((n - 1)) ]] && ok "${in_n} secondary cores checked in on EL1, MMU on our tables, own stack, parked in WFE" \
        || bad "checked-in secondaries ${in_n}, expected $((n - 1))"
    while IFS= read -r line; do
        [[ -n "${line}" ]] || continue
        tgt="$(sed -E "s/${cpu_re}/\\1/" <<<"${line}")"
        seen="$(sed -E "s/${cpu_re}/\\2/" <<<"${line}")"
        [[ "${tgt}" == "${seen}" ]] || mism=1
        grep -qE "^smp_cpu_on: target=0x${tgt} psci_rc=0 \\(SUCCESS\\)$" "${f}" || mism=1
        mpidrs+=$'\n'"${seen}"
    done < <(grep -E "${cpu_re}" "${f}" || true)
    [[ "${mism}" == 0 ]] && ok "each secondary reports the MPIDR it was started for" || bad "a secondary reported another MPIDR or was not started by CPU_ON"
    local total distinct
    total="$(grep -c . <<<"${mpidrs}")"
    distinct="$(sort -u <<<"${mpidrs}" | grep -c .)"
    if [[ "${total}" == "${n}" && "${distinct}" == "${n}" ]]; then
        ok "per-core MPIDRs distinct and complete: $(paste -sd, - <<<"${mpidrs}" | sed 's/[0-9a-f]\+/0x&/g')"
    else
        bad "MPIDRs duplicated or missing: ${total} reported, ${distinct} distinct, ${n} expected"
    fi

    sum_re="^smp: cpus=${n} started=${n} checked_in=${n} psci_errors=0 distinct_mpidrs=${n} wait_us=[0-9]+ result=ok$"
    [[ "$(grep -cE "${sum_re}" "${f}" || true)" == 1 ]] && ok "summary: all ${n} cores, no PSCI error, bounded wait, result=ok" \
        || bad "summary line missing or not ok: $(grep -E '^smp: cpus=' "${f}" | head -1)"

    grep -q "kernel: alive" "${f}" && ok "kernel alive" || bad "kernel never reached kernel: alive"
    grep -q "report_kind: final" "${f}" && ok "final report reached" || bad "no final report"
    if grep -qE 'report_kind: (panic|fault)' "${f}"; then bad "panic or fault report"; else ok "no panic or fault"; fi
}

# ----------------------------------------------------------------- self-test
self_test() {
    local tmp st_fail=0 f
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/ck-smp-selftest.XXXXXX")"
    trap 'rm -rf --one-file-system "${tmp}"' EXIT
    # good_log N: what a correct boot prints (MPIDRs 0..N-1 as QEMU virt gives).
    good_log() {
        local n="$1" i
        echo "kernel: alive"
        echo "smp: boot_mpidr=0x0 madt_cpus=${n} conduit=smc psci_version=1.1"
        for ((i = 1; i < n; i++)); do echo "smp_cpu_on: target=0x${i} psci_rc=0 (SUCCESS)"; done
        for ((i = 1; i < n; i++)); do
            echo "smp_cpu: target=0x${i} checked_in=yes seen_mpidr=0x${i} el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe"
        done
        echo "smp: cpus=${n} started=${n} checked_in=${n} psci_errors=0 distinct_mpidrs=${n} wait_us=1234 result=ok"
        echo "report_kind: final"
    }
    expect() { # NAME pass|fail FILE
        local out
        smp_failed=0
        out="$(smp_check_log "$3" 4)"
        smp_failed=0
        grep -q '^FAIL' <<<"${out}" && smp_failed=1
        if [[ "$2" == pass && "${smp_failed}" == 0 ]] || [[ "$2" == fail && "${smp_failed}" == 1 ]]; then
            echo "PASS  self-test $1 -> $2"
        else
            echo "FAIL  self-test $1: expected $2"; printf '%s\n' "${out}" | sed 's/^/      /'; st_fail=1
        fi
    }
    good_log 4 >"${tmp}/good"; expect good pass "${tmp}/good"
    # A core that never checks in (kernel honest).
    sed -e 's/^smp_cpu: target=0x3 .*/smp_cpu: target=0x3 checked_in=no/' \
        -e 's/checked_in=4 psci_errors=0 distinct_mpidrs=4 wait_us=1234 result=ok/checked_in=3 psci_errors=0 distinct_mpidrs=4 wait_us=5000000 result=FAIL/' \
        "${tmp}/good" >"${tmp}/nocheckin"; expect never-checks-in fail "${tmp}/nocheckin"
    # A core line missing while the kernel summary still claims ok.
    grep -v '^smp_cpu: target=0x2 ' "${tmp}/good" >"${tmp}/missingline"; expect missing-core-line fail "${tmp}/missingline"
    # Duplicate MPIDR: two cores report 0x1 (summary forged ok).
    sed 's/^smp_cpu: target=0x2 checked_in=yes seen_mpidr=0x2/smp_cpu: target=0x2 checked_in=yes seen_mpidr=0x1/' \
        "${tmp}/good" >"${tmp}/dup"; expect duplicate-mpidr fail "${tmp}/dup"
    # Secondary reports the boot core's MPIDR (duplicate with boot).
    sed 's/^smp_cpu: target=0x3 checked_in=yes seen_mpidr=0x3/smp_cpu: target=0x3 checked_in=yes seen_mpidr=0x0/' \
        "${tmp}/good" >"${tmp}/dupboot"; expect duplicate-boot-mpidr fail "${tmp}/dupboot"
    # MADT lists fewer cores than QEMU has (a missing MPIDR), lines consistent with 3.
    good_log 3 >"${tmp}/three"; expect madt-missing-core fail "${tmp}/three"
    # PSCI error code (ALREADY_ON), check-in line forged yes.
    sed 's/^smp_cpu_on: target=0x2 psci_rc=0 (SUCCESS)$/smp_cpu_on: target=0x2 psci_rc=-4 (ALREADY_ON)/' \
        "${tmp}/good" >"${tmp}/psci"; expect psci-error fail "${tmp}/psci"
    # The mutation image's skip line.
    sed 's/^smp_cpu_on: target=0x3 psci_rc=0 (SUCCESS)$/smp_cpu_on: target=0x3 psci_rc=SKIPPED (TEST-ONLY SMP mutation)/' \
        "${tmp}/good" >"${tmp}/skip"; expect cpu-on-skipped fail "${tmp}/skip"
    # Secondary on the wrong tables / MMU off / EL2.
    sed 's/^\(smp_cpu: target=0x1 .*\) ttbr0_match=yes/\1 ttbr0_match=no/' "${tmp}/good" >"${tmp}/ttbr"; expect wrong-tables fail "${tmp}/ttbr"
    sed 's/^\(smp_cpu: target=0x1 .*\) mmu=on/\1 mmu=off/' "${tmp}/good" >"${tmp}/mmu"; expect mmu-off fail "${tmp}/mmu"
    sed 's/^\(smp_cpu: target=0x1 .*\) el=1/\1 el=2/' "${tmp}/good" >"${tmp}/el"; expect wrong-el fail "${tmp}/el"
    # Kernel says FAIL somewhere, or no summary, or no smp lines at all.
    { cat "${tmp}/good"; echo "smp: FAIL duplicate mpidr=0x1 in the MADT"; } >"${tmp}/kfail"; expect kernel-fail-line fail "${tmp}/kfail"
    grep -v '^smp: cpus=' "${tmp}/good" >"${tmp}/nosum"; expect no-summary fail "${tmp}/nosum"
    printf 'kernel: alive\nreport_kind: final\n' >"${tmp}/none"; expect no-smp-lines fail "${tmp}/none"
    { cat "${tmp}/good"; echo "report_kind: panic"; } >"${tmp}/panic"; expect panic fail "${tmp}/panic"

    # Makefile refusals: parse-time $(error), nothing is compiled (make -n).
    local out rc
    out="$(make -n -s -C native/kernel CK_TEST_SMP_SKIP_CPU=1 CK_HARDWARE_STAGING=1 OUT="${tmp}/o1" 2>&1)"; rc=$?
    if [[ ${rc} != 0 ]] && grep -qF "CK_TEST_SMP_SKIP_CPU (TEST-only SMP mutation) cannot be combined with CK_HARDWARE_STAGING" <<<"${out}"; then
        echo "PASS  self-test mutation flag refused with CK_HARDWARE_STAGING"
    else
        echo "FAIL  self-test mutation flag not refused with CK_HARDWARE_STAGING (rc=${rc}): ${out:0:200}"; st_fail=1
    fi
    out="$(make -n -s -C native/kernel CK_TEST_SMP_SKIP_CPU=2 OUT="${tmp}/o2" 2>&1)"; rc=$?
    if [[ ${rc} != 0 ]] && grep -qF "CK_TEST_SMP_SKIP_CPU must be empty or 1" <<<"${out}"; then
        echo "PASS  self-test mutation flag value other than 1 refused"
    else
        echo "FAIL  self-test bad mutation flag value accepted (rc=${rc})"; st_fail=1
    fi
    [[ ! -e "${tmp}/o1" && ! -e "${tmp}/o2" ]] && echo "PASS  self-test refusals built nothing" || { echo "FAIL  self-test a refused build wrote output"; st_fail=1; }
    if grep -qE '^#if defined\(CK_TEST_SMP_SKIP_CPU\) && defined\(CK_HARDWARE_STAGING\)$' native/kernel/core/smp.c; then
        echo "PASS  self-test core/smp.c also refuses the mutation in a hardware staging compile"
    else
        echo "FAIL  self-test core/smp.c lacks the #error guard"; st_fail=1
    fi

    [[ ${st_fail} == 0 ]] && { echo "AIENOS_CK_SMP_SELF_TEST: PASS"; exit 0; }
    echo "AIENOS_CK_SMP_SELF_TEST: FAIL"; exit 1
}
if [[ "${mode}" == self ]]; then
    set +e
    self_test
fi

# --------------------------------------------------------------- QEMU boot
verdict_name=AIENOS_CK_SMP
[[ "${mode}" == mutation ]] && verdict_name=AIENOS_CK_SMP_MUTATION

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict_name}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict_name}: NOT_RUN"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
if [[ "${mode}" == mutation ]]; then
    out="${repo_root}/target/native-kernel-test-smp-skip"
    make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" CK_TEST_SMP_SKIP_CPU=1 >/dev/null
else
    out="${repo_root}/target/native-kernel"
    make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" >/dev/null
fi

# Machine quiet flag: one heavy run at a time on the Spark.
quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_smp_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${verdict_name}: NOT_RUN"
    exit 3
fi
own_flag=1
release_flag() {
    if [[ "${own_flag}" == 1 ]]; then
        own_flag=0
        if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
    fi
}
work="$(mktemp -d)"
cleanup() {
    rm -rf "${work}"
    release_flag
}
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${out}/BOOTAA64.EFI" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${vars_fd}" "${work}/vars.fd"
log="${work}/serial.log"

# Same machine as scripts/qemu_ck_boot_test.sh (issue #61: single-threaded TCG).
started=$(date +%s)
set +e
timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp "${ncpus}" -m 2048 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
    -device virtio-blk-pci,drive=esp \
    -device ramfb -display none -nic none \
    -serial file:"${log}" -no-reboot
qemu_status=$?
set -e
elapsed=$(( $(date +%s) - started ))
release_flag

tr -d '\r' <"${log}" >"${work}/serial.txt"
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_smp_${mode}_serial.log"
echo "qemu exit ${qemu_status} after ${elapsed} s (commit ${commit:0:12}, -smp ${ncpus}, ${mode})"

smp_failed=0
results="$(smp_check_log "${work}/serial.txt" "${ncpus}")" || true
grep -q '^FAIL' <<<"${results}" && smp_failed=1
printf '%s\n' "${results}"
if [[ "${qemu_status}" == 0 ]]; then echo "PASS  QEMU exit 0 (PSCI reset)"; else echo "FAIL  QEMU exit ${qemu_status}"; smp_failed=1; fi

if [[ "${mode}" == mutation ]]; then
    # The mutation must be the reason: the TEST-ONLY image announced itself,
    # skipped one CPU_ON, and that core never checked in.
    killed=1
    grep -qF "${mut_marker} build" "${work}/serial.txt" && echo "PASS  mutation image announced itself" || { echo "FAIL  mutation image did not announce itself"; killed=0; }
    grep -qE '^smp_cpu_on: target=0x[0-9a-f]+ psci_rc=SKIPPED' "${work}/serial.txt" && echo "PASS  one CPU_ON skipped" || { echo "FAIL  no CPU_ON was skipped"; killed=0; }
    grep -qE '^smp_cpu: target=0x[0-9a-f]+ checked_in=no$' "${work}/serial.txt" && echo "PASS  the skipped core never checked in" || { echo "FAIL  no core reported missing"; killed=0; }
    if [[ -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then echo "---- serial console ----"; cat "${work}/serial.txt"; fi
    if [[ "${killed}" == 1 && "${smp_failed}" == 1 ]]; then
        echo "AIENOS_CK_SMP_MUTATION: PASS (gate checks FAIL on the CPU_ON-skip image; mutation killed)"
        exit 0
    fi
    echo "AIENOS_CK_SMP_MUTATION: FAIL (mutation survived or did not run as built)"
    exit 1
fi

if grep -qF "${mut_marker}" "${work}/serial.txt"; then echo "FAIL  gate image is the TEST-ONLY mutation build"; smp_failed=1; else echo "PASS  default image (no TEST-ONLY mutation)"; fi
if [[ "${smp_failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"
    cat "${work}/serial.txt"
fi
if [[ "${smp_failed}" == 0 ]]; then
    echo "AIENOS_CK_SMP: PASS"
    exit 0
fi
echo "AIENOS_CK_SMP: FAIL"
exit 1
