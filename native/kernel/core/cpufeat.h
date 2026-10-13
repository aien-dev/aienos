/* cpufeat.h -- CPU feature decode from the Arm ID registers (pure function).
 *
 * Field positions (quoted from Linux arch/arm64/tools/sysreg, which
 * transcribes the Arm ARM DDI0487 register pages; the Arm ARM PDF itself was
 * not available offline here):
 *   ID_AA64ISAR0_EL1: RNDR [63:60], FHM [51:48], DP [47:44]
 *   ID_AA64ISAR1_EL1: I8MM [55:52], BF16 [47:44]
 *   ID_AA64PFR0_EL1:  SVE [35:32] (unsigned), AdvSIMD [23:20] and FP [19:16]
 *                     (signed; 0b1111 = not implemented, 0b0001 = with FP16)
 * dotprod = DP >= 1. i8mm = I8MM >= 1. fp16 = FP >= 1 && AdvSIMD >= 1 (signed
 * compare, so 0xf is "absent"). sve = SVE >= 1. rndr = RNDR >= 1.
 * Reads only the boot core's registers; per-core comparison is not done. */
#ifndef AIENOS_CK_CPUFEAT_H
#define AIENOS_CK_CPUFEAT_H

#include <stddef.h>
#include <stdint.h>

struct ck_cpu_features {
    unsigned dotprod, i8mm, bf16, fhm, fp16, sve, rndr;
};

void ck_cpufeat_decode(uint64_t isar0, uint64_t isar1, uint64_t pfr0, struct ck_cpu_features *out);
/* "cpu_features: dotprod=1 i8mm=0 bf16=0 fhm=1 fp16=1 sve=0 rndr=0" (no newline). */
int ck_cpufeat_format(const struct ck_cpu_features *f, char *buf, size_t n);

#endif
