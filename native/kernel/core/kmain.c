/* kmain.c -- C kernel core bring-up after the UEFI stub.
 *
 * ck_kernel_entry runs at the firmware EL on the firmware's translation:
 * vectors, PSCI conduit, own address space, then EL2 -> EL1h (ADR 0009) with
 * the MMU on our tables. ck_el1_main then reports the MMU switch from live
 * registers, proves the guard pages, brings up GICv3 and the EL1 physical
 * timer, starts and parks the secondary cores (core/smp.c), runs the M3
 * isolation checks (core/m3.c) and the linked boot stages,
 * and ends with the final report and a PSCI reset. QEMU runs of this path
 * qualify nothing physical. */
#include "arch.h"
#include "ck_internal.h"
#include "entropy.h"
#include "handoff_check.h"

#define TTBR_BADDR_MASK 0x0000fffffffffffeull

static struct ck_handoff *hand;

const void *ck_acpi_find(const char sig[4])
{
    return hand && hand->rsdp ? ck_acpi_lookup(hand->rsdp, sig) : 0;
}

static void run_stage(const char *name, int (*fn)(void))
{
    if (!fn) {
        ck_printf("stage %s: not linked\n", name);
        return;
    }
    ck_set_stage(name);
    int rc = fn();
    ck_irq_cpu_enable(0);
    if (rc == 0)
        ck_printf("stage %s: ok\n", name);
    else
        ck_printf("stage %s: FAIL rc=%d\n", name, rc);
}

static __attribute__((noreturn)) void ck_el1_main(void *arg)
{
    struct ck_handoff *h = arg;
    ck_set_stage("kernel_el1");
    ck_mm_el1_ready();
    const struct ck_mm_report *mm = ck_mm_report();

    ck_puts("\n");
    ck_report_header("kernel");
    unsigned el = ck_current_el();
    uint64_t sctlr = ck_rd(sctlr_el1);
    int mmu_on = (sctlr & 1) != 0;
    ck_printf("mmu: %s\n", mmu_on ? "enabled" : "disabled");
    ck_printf("pt_frames_used: %llu\n", (unsigned long long)mm->pt_tables);
    uint64_t el1_base = ck_rd(ttbr0_el1) & TTBR_BADDR_MASK;
    uint64_t fw_base = h->firmware_ttbr0 & TTBR_BADDR_MASK;
    int switched = el == 1 && mmu_on && el1_base == mm->root && el1_base != fw_base;
    ck_printf("mmu_switch: firmware=EL%u firmware_mmu=%s firmware_ttbr0=0x%llx aienos_root=0x%llx "
              "ttbr0_el1=0x%llx switched=%s\n",
              h->firmware_el, (h->firmware_sctlr & 1) ? "on" : "off", (unsigned long long)fw_base,
              (unsigned long long)mm->root, (unsigned long long)el1_base, switched ? "yes" : "no");
    ck_printf("mmu_regs: mair=0x%llx tcr=0x%llx sctlr=0x%llx\n", (unsigned long long)ck_rd(mair_el1),
              (unsigned long long)ck_rd(tcr_el1), (unsigned long long)sctlr);
    ck_printf("memory: ram_ranges=%llu free_bytes=%llu stack=0x%llx-0x%llx heap=0x%llx-0x%llx "
              "dma=0x%llx-0x%llx exit_attempts=%u\n",
              (unsigned long long)mm->ram_ranges, (unsigned long long)mm->free_bytes,
              (unsigned long long)mm->stack_lo, (unsigned long long)mm->stack_hi,
              (unsigned long long)mm->heap_lo, (unsigned long long)mm->heap_hi,
              (unsigned long long)mm->dma_lo, (unsigned long long)mm->dma_hi, h->exit_attempts);

    /* Heap smoke test. */
    void *a = ck_alloc(100), *b = ck_alloc(5000);
    if (!a || !b)
        ck_panic("heap: allocation failed");
    ck_free(a);
    ck_free(b);

    /* Addition over the Rust kernel: the guard pages really fault, and the
     * fault is contained (handled and resumed, no reset). */
    char detail[160];
    ck_set_stage("guard_page");
    if (ck_mm_guard_selftest(detail, sizeof detail) == 0)
        ck_printf("guard_page: ok fault=contained (%s) [C kernel addition, not in the Rust kernel]\n",
                  detail);
    else
        ck_printf("guard_page: FAIL %s\n", detail);

    /* GICv3 from the MADT, then the EL1 physical timer window. */
    ck_set_stage("gic");
    const void *madt = ck_acpi_find("APIC");
    struct ck_madt_gic mg;
    if (!madt || ck_madt_parse(madt, &mg))
        ck_panic("gic: no usable ACPI MADT");
    struct ck_gic_report gr;
    int rc = ck_gic_init(&mg, &gr);
    if (rc)
        ck_panic("gic: init failed rc=%d (madt gicd=0x%llx gicr=0x%llx)", rc,
                 (unsigned long long)mg.gicd, (unsigned long long)mg.gicr);
    ck_set_stage("timer");
    struct ck_timer_window tw;
    if (ck_timer_window(200, &tw))
        ck_panic("timer: counter frequency is zero");
    uint64_t f = tw.freq_hz;
    ck_printf("gic: v%u\n", gr.arch_rev);
    ck_printf("timer_irq: %llu ticks in %llu ms\n", (unsigned long long)tw.ticks,
              (unsigned long long)tw.ms);
    ck_printf("gic_madt: gicd=0x%llx gicr=0x%llx arch_rev=%u icc_sre=%llu\n",
              (unsigned long long)gr.gicd, (unsigned long long)gr.gicr, gr.arch_rev,
              (unsigned long long)gr.icc_sre);
    ck_printf("gic_redistributor: frame=0x%llx\n", (unsigned long long)gr.rd_frame);
    ck_printf("timer_stats: intid=30 freq_hz=%llu period_us=%llu min_us=%llu avg_us=%llu max_us=%llu\n",
              (unsigned long long)f, (unsigned long long)ck_counter_to_us(f / 100, f),
              (unsigned long long)ck_counter_to_us(tw.min_interval, f),
              (unsigned long long)(tw.ticks ? ck_counter_to_us(tw.span / tw.ticks, f) : 0),
              (unsigned long long)ck_counter_to_us(tw.max_interval, f));

    uint64_t spsel = ck_rd(spsel);
    ck_printf("exception_level: EL%u\n", el);
    ck_puts("kernel: alive\n");
    ck_printf("kernel_el: EL%u%s\n", el, (spsel & 1) ? "h" : "t");

    /* Kernel entropy (arch/rndr.c): RNDR or a latched refusal, no fallback.
     * Probed once here, before the artifact loader and the stages. */
    ck_set_stage("entropy");
    int ent = ck_entropy_init();
    if (ent == CK_RNG_OK)
        ck_printf("entropy: rndr feat_rng=yes probe_words=2 retries=%llu stuck_test=ok\n",
                  (unsigned long long)ck_entropy_retries());
    else
        ck_printf("entropy: unavailable reason=%s (%s); security consumers refuse, fail closed\n",
                  ck_entropy_reason(),
                  ent == CK_RNG_ABSENT ? "ID_AA64ISAR0_EL1.RNDR=0, no FEAT_RNG"
                  : ent == CK_RNG_FAILED ? "RNDR returned no number within the retry bound"
                  : ent == CK_RNG_STUCK ? "RNDR repeated a 64-bit word"
                                        : "probe error");

    /* Secondary cores (core/smp.c): PSCI CPU_ON, check in, park in WFE with
     * interrupts masked; the boot core goes on alone. Lines judged by
     * scripts/qemu_ck_smp_test.sh (CK gate SMP). */
    ck_smp_run();

    /* One FP/SIMD-enabled Rust unit (core/fpu.c), probe build only. */
    ck_fpu_run();

    /* Ingest the GGUF over fw_cfg and call the Rust inference unit (core/infer.c), probe build only. */
    ck_infer_run();

    /* M3 isolation checks (core/m3.c), before any stage registers an IRQ. */
    ck_m3_run();

    run_stage("devices", ck_stage_devices);
    run_stage("security", ck_stage_security);
    run_stage("store", ck_stage_store);

    /* P2 sealed-artifact loader (core/artifact_loader.c). Runs after the store
     * stage: its default candidate source is the boot disk Store, read by that
     * stage before the NVMe DMA revoke. No stage registers an IRQ. */
    ck_artifact_run();
    struct ck_mm_usage mu;
    ck_mm_usage(&mu);
    ck_printf("mm_usage: stack_bytes=%llu stack_used=%llu heap_bytes=%llu heap_free=%llu heap_min_free=%llu\n",
              (unsigned long long)mu.stack_bytes, (unsigned long long)mu.stack_used,
              (unsigned long long)mu.heap_bytes, (unsigned long long)mu.heap_free,
              (unsigned long long)mu.heap_min_free);

    ck_set_stage("final");
    ck_puts("\n");
    ck_report_header("final");
    ck_artifact_final();
    ck_puts("note: QEMU qualifies nothing physical\n");
    ck_reset();
}

void ck_kernel_entry(struct ck_handoff *h)
{
    hand = h;
    unsigned el = ck_current_el();
    if (el == 2)
        ck_wr(vbar_el2, (uint64_t)(uintptr_t)ck_vectors_el2);
    else
        ck_wr(vbar_el1, (uint64_t)(uintptr_t)ck_vectors);
    ck_isb();
#ifdef CK_SELFTEST_EL2_FAULT
    /* One-off check of the EL2 fatal path (never in a normal build). */
    if (el == 2)
        __asm__ volatile("brk #0x2");
#endif
    const char *why;
    if (ck_handoff_check(h, &why) != 0)
        ck_panic("handoff: %s", why);
    ck_psci_configure(ck_acpi_find("FACP"));
    ck_set_stage("mm_build");
    uint64_t sp = ck_mm_build(h);
    ck_set_stage("el1_switch");
    if (el == 2)
        ck_enter_el1(ck_mm_report()->root, ck_mm_mair(), ck_mm_tcr(), ck_mm_sctlr(), sp,
                     ck_el1_main, h);
    if (el == 1)
        ck_switch_el1(ck_mm_report()->root, ck_mm_mair(), ck_mm_tcr(), ck_mm_sctlr(), sp,
                      ck_el1_main, h);
    ck_panic("kernel entry at unsupported EL%u", el);
}
