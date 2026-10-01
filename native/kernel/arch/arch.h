/* arch.h -- AArch64 system register access for the C kernel core. GICv3 CPU
 * interface registers use their S3_* encodings so any assembler accepts them. */
#ifndef AIENOS_CK_ARCH_H
#define AIENOS_CK_ARCH_H

#include <stdint.h>

#define ck_rd(reg) ({ uint64_t _v; __asm__ volatile("mrs %0, " #reg : "=r"(_v)); _v; })
#define ck_wr(reg, v) __asm__ volatile("msr " #reg ", %0" ::"r"((uint64_t)(v)) : "memory")
#define ck_isb() __asm__ volatile("isb" ::: "memory")
#define ck_dsb_sy() __asm__ volatile("dsb sy" ::: "memory")
#define ck_dsb_ish() __asm__ volatile("dsb ish" ::: "memory")
#define ck_irq_off() __asm__ volatile("msr daifset, #2" ::: "memory")
#define ck_irq_on() __asm__ volatile("msr daifclr, #2" ::: "memory")

#define ICC_PMR_EL1 S3_0_C4_C6_0
#define ICC_IAR1_EL1 S3_0_C12_C12_0
#define ICC_EOIR1_EL1 S3_0_C12_C12_1
#define ICC_BPR1_EL1 S3_0_C12_C12_3
#define ICC_CTLR_EL1 S3_0_C12_C12_4
#define ICC_SRE_EL1 S3_0_C12_C12_5
#define ICC_IGRPEN1_EL1 S3_0_C12_C12_7
#define ck_rd_s(reg) ck_rd(reg)
#define ck_wr_s(reg, v) ck_wr(reg, v)

static inline unsigned ck_current_el(void)
{
    return (unsigned)(ck_rd(CurrentEL) >> 2) & 3;
}

/* Exception frame pushed by vectors.S (layout shared with the assembly). */
struct ck_frame {
    uint64_t x[31];
    uint64_t elr;
    uint64_t spsr;
    uint64_t vector; /* 0..15: entry index in the vector table */
};
_Static_assert(sizeof(struct ck_frame) == 272, "frame layout");

extern char ck_vectors[], ck_vectors_el2[];
/* Lowest valid address of the active kernel stack; the vector entry switches
 * to an emergency stack when an exception arrives with SP below it. */
extern uint64_t ck_stack_floor;

/* Recoverable probe: 0 if the 8-byte read at addr completed, 1 if it took a
 * synchronous data abort (the handler resumes at the fixup). EL1 only. */
int ck_probe_read(const volatile void *addr);
struct ck_probe {
    uint64_t fixup; /* nonzero while a probe is armed */
    uint64_t insn;  /* address of the probing load */
    uint64_t esr, far;
};
extern struct ck_probe ck_probe_state;

/* EL2 -> EL1h per ADR 0009, MMU on at EL1 with the given tables, then calls
 * entry(arg) on `sp`. Never returns. */
__attribute__((noreturn)) void ck_enter_el1(uint64_t root, uint64_t mair, uint64_t tcr,
                                            uint64_t sctlr, uint64_t sp,
                                            void (*entry)(void *), void *arg);
/* Same, when firmware already runs at EL1: switch tables in place. */
__attribute__((noreturn)) void ck_switch_el1(uint64_t root, uint64_t mair, uint64_t tcr,
                                             uint64_t sctlr, uint64_t sp,
                                             void (*entry)(void *), void *arg);

#endif
