# Shared AIENOS C kernel M1 checks (Lane 18). Sourced by qemu_ck_boot_test.sh
# and qemu_ck_store_test.sh so both gates run the identical M1 checks; the
# patterns are those of qemu_boot_test.sh (the Rust kernel's test) except
# where qemu_ck_boot_test.sh's header lists a deliberate difference.
# Not executable on its own. Callers set: work (serial text in
# ${work}/serial.txt), commit, qemu_status; ck_m1_checks sets failed=1 on any
# failure and never resets it. ck_m3_checks (Lane 25) runs the five M3 checks
# of qemu_boot_test.sh with the same patterns and sets m3_failed=1 on any
# failure; it does not touch failed, so the M1 verdict is unchanged.

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

ck_m1_checks() {
    check "pre-exit report printed" "report_kind: pre_exit"
    check "image is this commit" "aienos_commit: ${commit}"
    check "left firmware and entered the kernel" "kernel: alive"
    check "kernel entered EL1h" "kernel_el: EL1h"
    check "EL1 page tables and caches enabled" "mmu: enabled"
    check "GICv3 enabled" "gic: v3"
    if grep -qE 'timer_irq: ([0-9]+) ticks' "${work}/serial.txt"; then
        ticks=$(grep -oE 'timer_irq: ([0-9]+) ticks' "${work}/serial.txt" | tail -1 | grep -oE '[0-9]+')
        [[ "${ticks}" -ge 5 ]] && echo "PASS  timer IRQ delivered at least five ticks" || { echo "FAIL  timer IRQ delivered fewer than five ticks"; failed=1; }
    else
        echo "FAIL  timer IRQ count reported"
        failed=1
    fi
    # Issue #27: the kernel left firmware's EL2 translation for AIENOS EL1 tables.
    # The script re-checks the register values itself instead of trusting switched=yes.
    switch_re='mmu_switch: firmware=EL2 firmware_mmu=on firmware_ttbr0=(0x[0-9a-f]+) aienos_root=(0x[0-9a-f]+) ttbr0_el1=(0x[0-9a-f]+) switched=yes'
    switch_line=$(grep -E "${switch_re}" "${work}/serial.txt" | tail -1 || true)
    if [[ "${switch_line}" =~ ${switch_re} ]]; then
        fw_root="${BASH_REMATCH[1]}"; aienos_root="${BASH_REMATCH[2]}"; el1_root="${BASH_REMATCH[3]}"
        if [[ "${aienos_root}" == "${el1_root}" && "${aienos_root}" != "${fw_root}" ]]; then
            echo "PASS  MMU switched from firmware tables (${fw_root}) to AIENOS tables (${aienos_root})"
        else
            echo "FAIL  MMU switch values inconsistent: ${switch_line}"
            failed=1
        fi
    else
        echo "FAIL  MMU switch from firmware tables reported"
        failed=1
    fi
    check "GIC bases from the ACPI MADT, GICv3 architecture and ICC system registers" \
        "gic_madt: gicd=0x[0-9a-f]* gicr=0x[0-9a-f]* arch_rev=3 icc_sre=1"
    # Issue #28: tick statistics. The dispatcher re-arms the timer 10 ms after each
    # tick, so no interval may be shorter than half a period (a missing re-arm or a
    # missing EOI would show as an interrupt storm or no second tick).
    stats_re='timer_stats: intid=30 freq_hz=([0-9]+) period_us=([0-9]+) min_us=([0-9]+) avg_us=([0-9]+) max_us=([0-9]+)'
    stats_line=$(grep -E "${stats_re}" "${work}/serial.txt" | tail -1 || true)
    if [[ "${stats_line}" =~ ${stats_re} ]]; then
        period="${BASH_REMATCH[2]}"; min_us="${BASH_REMATCH[3]}"; avg_us="${BASH_REMATCH[4]}"; max_us="${BASH_REMATCH[5]}"
        if [[ "${period}" -gt 0 && $(( min_us * 2 )) -ge "${period}" && "${min_us}" -le "${avg_us}" && "${avg_us}" -le "${max_us}" ]]; then
            echo "PASS  tick statistics consistent (period ${period} us, min ${min_us} avg ${avg_us} max ${max_us})"
        else
            echo "FAIL  tick statistics out of range: ${stats_line}"
            failed=1
        fi
    else
        echo "FAIL  tick statistics reported"
        failed=1
    fi
    # Added for the C kernel (the Rust kernel has no such test): every guard page
    # faulted and the fault was contained.
    check "guard pages fault and the fault is contained (C kernel addition)" "guard_page: ok fault=contained"
    check "final report on the SPCR console" "report_kind: final"
    check "no panic or fault" "report_kind: final"
    if grep -qE "report_kind: (panic|fault)" "${work}/serial.txt"; then
        echo "FAIL  panic or fault reported"
        failed=1
    fi
    if [[ "${qemu_status}" == 124 ]]; then
        echo "FAIL  timed out (no reset)"
        failed=1
    elif [[ "${qemu_status}" != 0 ]]; then
        # Stricter than qemu_boot_test.sh (which fails only on 124): PSCI
        # SYSTEM_RESET under -no-reboot makes QEMU exit 0, so any other status is a
        # QEMU crash or abort even if the markers were already flushed.
        echo "FAIL  qemu exited with status ${qemu_status} (expected 0 after PSCI reset)"
        failed=1
    fi
}

ck_m3_checks() {
    # Same five patterns as qemu_boot_test.sh lines 63-67 (the Rust M3 rows).
    m3_check() { # description, pattern
        if grep -q -- "$2" "${work}/serial.txt"; then
            echo "PASS  $1"
        else
            echo "FAIL  $1"
            m3_failed=1
        fi
    }
    m3_check "cooperative threads interleaved" "threads: ok"
    m3_check "EL0 capability and fault isolation" "el0: ok write=granted forged=denied fault=contained exit=0"
    m3_check "timer-driven preemption across runnable tasks" "preempt: ok"
    m3_check "deterministic MADT placement of preempt workers" "placement: worker0=class0/core0 worker1=class0/core1"
    m3_check "typed IPC with attenuated revocable delegation" "ipc: ok message=delivered cap=delegated rights=attenuated forged=denied revoked=denied"
}
