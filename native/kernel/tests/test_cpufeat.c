/* test_cpufeat.c -- host tests of core/cpufeat.c: every field at its Arm
 * position, neighbours do not leak, signed FP/AdvSIMD (0xf = absent), line. */
#include <string.h>
#include "ck_test.h"
#include "cpufeat.h"

static struct ck_cpu_features dec(uint64_t a, uint64_t b, uint64_t p)
{
    struct ck_cpu_features f;
    memset(&f, 0xAA, sizeof f);
    ck_cpufeat_decode(a, b, p, &f);
    return f;
}

int main(void)
{
    /* Boot record: all zero until kmain records the decode; nothing assumed. */
    CHECK(!ck_cpufeat_boot()->dotprod && !ck_cpufeat_boot()->i8mm);
    struct ck_cpu_features f = dec(0, 0, 0);
    CHECK(!f.dotprod && !f.i8mm && !f.bf16 && !f.fhm && !f.sve && !f.rndr);
    CHECK(!f.fp16); /* FP=0 AdvSIMD=0: implemented, no half precision */

    f = dec(1ull << 44, 0, 0); CHECK(f.dotprod && !f.fhm && !f.rndr && !f.i8mm);
    f = dec(1ull << 48, 0, 0); CHECK(f.fhm && !f.dotprod);
    f = dec(1ull << 60, 0, 0); CHECK(f.rndr && !f.dotprod);
    f = dec(0, 1ull << 52, 0); CHECK(f.i8mm && !f.bf16);
    f = dec(0, 1ull << 44, 0); CHECK(f.bf16 && !f.i8mm);
    f = dec(0, 0, 1ull << 32); CHECK(f.sve);
    f = dec(0, 0, (1ull << 16) | (1ull << 20)); CHECK(f.fp16);
    f = dec(0, 0, 1ull << 16); CHECK(!f.fp16); /* FP16 FP without AdvSIMD fp16 */
    f = dec(0, 0, 0xfull << 16 | 1ull << 20); CHECK(!f.fp16); /* FP=-1: absent */
    f = dec(0, 0, 0xfull << 20 | 1ull << 16); CHECK(!f.fp16);
    /* Cortex-A76-like: DP=1 (bit 44), no I8MM, FP16 */
    f = dec(0x0000100011111110ull, 0x0000000000100001ull, 0x0000000011212222ull | (1ull << 16 | 1ull << 20));
    CHECK(f.dotprod && !f.i8mm && f.fp16 && !f.sve);
    /* higher field values still count */
    f = dec(2ull << 44, 2ull << 52, 0); CHECK(f.dotprod && f.i8mm);
    /* adjacent fields do not leak: bits just outside each field */
    f = dec(1ull << 43, (1ull << 51) | (1ull << 56), 1ull << 31 | 1ull << 36);
    CHECK(!f.dotprod && !f.i8mm && !f.sve);
    f = dec(1ull << 59 | 1ull << 43 | 1ull << 55, 1ull << 43 | 1ull << 56, 0); CHECK(!f.rndr && !f.fhm && !f.bf16 && !f.dotprod);

    char buf[128];
    f = dec(1ull << 44, 0, 1ull << 16 | 1ull << 20);
    int n = ck_cpufeat_format(&f, buf, sizeof buf);
    CHECK(n > 0 && strcmp(buf, "cpu_features: dotprod=1 i8mm=0 bf16=0 fhm=0 fp16=1 sve=0 rndr=0") == 0);
    char small[8];
    ck_cpufeat_format(&f, small, sizeof small);
    CHECK(strlen(small) == 7);
    /* The recorded boot decode is what core/infer.c hands the Rust unit. */
    f = dec(1ull << 44, 0, 0);
    ck_cpufeat_set_boot(&f);
    CHECK(ck_cpufeat_boot()->dotprod == 1 && ck_cpufeat_boot()->i8mm == 0);
    f = dec(0, 0, 0);
    ck_cpufeat_set_boot(&f);
    CHECK(ck_cpufeat_boot()->dotprod == 0);
    return ck_t_verdict("test_cpufeat");
}
