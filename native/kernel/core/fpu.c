/* fpu.c -- run ONE floating-point/SIMD-enabled unit (a Rust no_std staticlib,
 * crates/aienos-fpu-probe) from the general-regs-only C kernel (aienos#34
 * lane 0). Only compiled into the probe build: Makefile CK_RUST_LIBS=<.a>
 * adds -DCK_FPU_PROBE=1; the default image carries none of this.
 *
 * The kernel runs at EL1h (EL2 -> EL1 drop in arch/vectors.S). FP/SIMD
 * access at EL1 is governed by CPACR_EL1.FPEN (0b11 = no trap) and, from
 * EL2, by CPTR_EL2 (vectors.S sets it to no-trap before the drop). The
 * kernel never saves FP state: no exception handler touches v0-v31 and the
 * kernel is built -mgeneral-regs-only. So the unit runs with every exception
 * masked (DAIF.DAIF) from the first FP instruction to the last, and FP
 * registers are left dirty (nothing else in the kernel reads them; EL0 runs
 * with FPEN=01 and traps, never sees them). A future FP-using scheduler must
 * save/restore v0-v31/FPSR/FPCR before dropping that restriction. */
#include <stdint.h>

#include "arch.h"
#include "ck_internal.h"

#ifdef CK_FPU_PROBE
extern int aienos_fpu_probe(uint32_t *out);

#define CPACR_FPEN_SHIFT 20

/* Set CPACR_EL1.FPEN = 0b11 and synchronise. Idempotent: vectors.S already
 * does this at the EL2 -> EL1 drop; doing it here makes the unit not depend
 * on that. */
void ck_fpu_enable(void)
{
    uint64_t v = ck_rd(cpacr_el1);
    v |= 3ull << CPACR_FPEN_SHIFT;
    ck_wr(cpacr_el1, v);
    ck_isb();
}

void ck_fpu_run(void)
{
    uint32_t out[6] = {0, 0, 0, 0, 0, 0};
    uint64_t daif;
    int rc;

    ck_fpu_enable();
    daif = ck_rd(daif);
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    rc = aienos_fpu_probe(out);
    ck_wr(daif, daif);

    int ok = rc == 0 && out[0] == 0x42880000u /* 68.0f */ && out[2] == 0x41300000u /* 11.0f */ &&
             out[3] == 0x41b00000u /* 22.0f */ && out[4] == 0x42040000u /* 33.0f */ &&
             out[5] == 0x42300000u /* 44.0f */;
    ck_printf("fpu: el1_cpacr=0x%llx rc=%d dot_bits=0x%x exp1_bits=0x%x neon_bits=0x%x,0x%x,0x%x,0x%x\n",
              (unsigned long long)ck_rd(cpacr_el1), rc, out[0], out[1], out[2], out[3], out[4], out[5]);
    ck_printf("AIENOS_CK_FPU: %s\n", ok ? "PASS" : "FAIL");
}
#else
void ck_fpu_run(void) {}
#endif
