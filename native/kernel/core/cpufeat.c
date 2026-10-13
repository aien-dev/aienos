/* cpufeat.c -- see cpufeat.h for the register field positions. */
#include "cpufeat.h"
#include "fmt.h"

static unsigned ufield(uint64_t v, unsigned hi, unsigned lo)
{
    return (unsigned)((v >> lo) & ((1u << (hi - lo + 1u)) - 1u));
}

/* Signed 4-bit field: 0b1000..0b1111 are negative (0xf = -1 = not implemented). */
static int sfield(uint64_t v, unsigned hi, unsigned lo)
{
    int x = (int)ufield(v, hi, lo);
    return x >= 8 ? x - 16 : x;
}

void ck_cpufeat_decode(uint64_t isar0, uint64_t isar1, uint64_t pfr0, struct ck_cpu_features *out)
{
    out->dotprod = ufield(isar0, 47, 44) >= 1u;
    out->fhm = ufield(isar0, 51, 48) >= 1u;
    out->rndr = ufield(isar0, 63, 60) >= 1u;
    out->i8mm = ufield(isar1, 55, 52) >= 1u;
    out->bf16 = ufield(isar1, 47, 44) >= 1u;
    out->sve = ufield(pfr0, 35, 32) >= 1u;
    out->fp16 = sfield(pfr0, 19, 16) >= 1 && sfield(pfr0, 23, 20) >= 1;
}

int ck_cpufeat_format(const struct ck_cpu_features *f, char *buf, size_t n)
{
    return ck_snprintf(buf, n, "cpu_features: dotprod=%u i8mm=%u bf16=%u fhm=%u fp16=%u sve=%u rndr=%u", f->dotprod,
                       f->i8mm, f->bf16, f->fhm, f->fp16, f->sve, f->rndr);
}
