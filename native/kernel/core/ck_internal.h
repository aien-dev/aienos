/* ck_internal.h -- declarations shared inside the C kernel core (boot stub,
 * arch, mm, core). Not part of the stage contract (that is ck.h). */
#ifndef AIENOS_CK_INTERNAL_H
#define AIENOS_CK_INTERNAL_H

#include "ck.h"
#include "handoff.h"
#include "acpi.h"
#include "fmt.h"

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

/* ---- console (core/console.c) ---- */
/* While UEFI boot services live: writer for ConOut (NULL to detach). */
void ck_console_set_efi(void (*write)(const char *s, size_t n));
/* SPCR UART: returns 0 if the interface type is supported. */
int ck_console_set_uart(const struct ck_spcr *spcr);
/* Name of the active UART driver for the report, e.g. "pl011". */
const char *ck_console_uart_name(void);
uint64_t ck_console_uart_base(void);

/* ---- report (core/report.c) ---- */
void ck_set_stage(const char *name);
const char *ck_stage_name(void);
void ck_report_header(const char *kind);
__attribute__((noreturn)) void ck_reset(void);
/* PSCI conduit from the FADT; default SMC. */
void ck_psci_configure(const void *fadt);
/* One PSCI call (SMC32/SMC64 calling convention, x0-x3 in, x0 out) on the
 * configured conduit: HVC only at EL1 when the FADT says HVC, else SMC. */
int64_t ck_psci_call(uint64_t fn, uint64_t a1, uint64_t a2, uint64_t a3);
/* "hvc" or "smc": the conduit ck_psci_call uses at the current EL. */
const char *ck_psci_conduit(void);
__attribute__((noreturn)) void ck_fault_report(const char *what, uint64_t esr, uint64_t far,
                                               uint64_t elr, unsigned el);

/* ---- memory (mm/mmu.c) ---- */
struct ck_mm_report {
    uint64_t root;
    uint64_t pt_tables;
    uint64_t stack_lo, stack_hi, stack_guard;
    uint64_t heap_lo, heap_hi, heap_guard_lo, heap_guard_hi;
    uint64_t dma_lo, dma_hi;
    uint64_t ram_ranges, free_bytes;
};
/* EL2/firmware phase: frames from the map, our tables, stack, heap, DMA pool.
 * Returns the stack top for the EL1 entry. */
uint64_t ck_mm_build(const struct ck_handoff *h);
const struct ck_handoff *ck_handoff_get(void); /* the record the stub passed (kmain.c) */
/* EL1 phase: heap ready after the MMU is on. */
void ck_mm_el1_ready(void);
const struct ck_mm_report *ck_mm_report(void);
/* High-water marks: stack words ever written (painted at build), heap free
 * bytes now and at the lowest point since the heap came up. */
struct ck_mm_usage {
    uint64_t stack_bytes, stack_used, heap_bytes, heap_free, heap_min_free;
};
void ck_mm_usage(struct ck_mm_usage *u);
uint64_t ck_mm_mair(void);
uint64_t ck_mm_tcr(void);
uint64_t ck_mm_sctlr(void);
/* Guard-page self test (EL1). 0 if every guard faulted and was contained. */
int ck_mm_guard_selftest(char *detail, size_t n);

/* ---- artifact loader support (mm/mmu.c) ---- */
/* Contiguous 4 KiB frames from the free list; 0 on success. */
int ck_mm_frames_alloc(uint64_t npages, uint64_t *pa);
/* Returns the frames; nonzero if the free list refused them. */
int ck_mm_frames_free(uint64_t pa, uint64_t npages);
uint64_t ck_mm_free_frames(void);
/* 1 if [pa, pa+len) is identity mapped in the kernel tables. */
int ck_mm_mapped(uint64_t pa, uint64_t len);
/* ck_mmio_map without the panic: 0 on RAM overlap or map failure. */
volatile void *ck_mm_mmio_try_map(uint64_t phys, size_t len);

/* ---- P2 artifact loader (core/artifact_loader.c) ---- */
void ck_artifact_run(void);
void ck_artifact_final(void);

/* ---- GIC and timer (arch/gic.c, arch/timer.c) ---- */
struct ck_gic_report {
    uint64_t gicd, gicr;
    uint32_t arch_rev;
    uint64_t icc_sre;
    uint64_t rd_frame; /* this CPU's redistributor frame */
};
int ck_gic_init(const struct ck_madt_gic *madt, struct ck_gic_report *out);
struct ck_timer_window {
    uint64_t ticks, ms, freq_hz, min_interval, max_interval, span;
};
int ck_timer_window(uint32_t ms, struct ck_timer_window *out);
uint64_t ck_counter_to_us(uint64_t counter, uint64_t freq);
void ck_timer_tick(void); /* IRQ dispatcher: INTID 30 */
/* M3 isolation checks: threads, el0, preempt, placement, ipc (core/m3.c). */
void ck_m3_run(void);
/* arch/rndr.c: probe FEAT_RNG + two RNDR words once, before any consumer.
 * Returns CK_RNG_OK or the refusal (see core/entropy.h). */
int ck_entropy_init(void);
uint64_t ck_entropy_retries(void);
/* core/smp.c: secondary cores through PSCI CPU_ON, each on its own stack with
 * the MMU on the boot core's tables, checked in and parked in WFE. Prints
 * the smp: lines scripts/qemu_ck_smp_test.sh judges; never panics. */
void ck_smp_run(void);
void ck_fpu_run(void); /* core/fpu.c: probe build only (CK_RUST_LIBS), else a no-op */
void ck_infer_run(void); /* core/infer.c: probe build only (CK_INFER_LIB), else a no-op */

#endif
