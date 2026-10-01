/* rndr.c -- kernel glue for core/entropy.c: the real FEAT_RNG check
 * (ID_AA64ISAR0_EL1.RNDR, bits [63:60]) and the RNDR read (NZCV.Z set means
 * no random number was returned). Implements the ck.h entropy services.
 * There is no other source: without RNDR every request is refused and the
 * consumer fails closed. Not covered here: firmware that traps RNDR to EL3
 * (FEAT_RNG_TRAP) and answers with an UNDEFINED exception would fault the
 * read; that shows as a kernel fault, never as weak bytes.
 * QEMU is not hardware: GB10 RNDR availability is UNVERIFIED. */
#include "arch.h"
#include "ck_internal.h"
#include "entropy.h"

static int hw_present(void *ctx)
{
    (void)ctx;
    return ((ck_rd(id_aa64isar0_el1) >> 60) & 0xfu) >= 1u;
}

static int hw_read(void *ctx, uint64_t *out)
{
    (void)ctx;
    uint64_t v, nzcv;
    /* s3_3_c2_c4_0 = RNDR; read NZCV straight after it. */
    __asm__ volatile("mrs %0, s3_3_c2_c4_0\n\tmrs %1, nzcv" : "=r"(v), "=r"(nzcv)::"cc");
    *out = v;
    return (nzcv & (1ull << 30)) == 0;
}

static const struct ck_rng_ops hw_ops = { hw_present, hw_read, 0 };
static struct ck_rng rng = { 0, CK_RNG_UNPROBED, 0, 0, 0 };

int ck_entropy_init(void)
{
    return ck_rng_probe(&rng, &hw_ops);
}

int ck_entropy_fill(void *buf, size_t len)
{
    return ck_rng_fill(&rng, buf, len);
}

int ck_entropy_status(void)
{
    return rng.state;
}

const char *ck_entropy_reason(void)
{
    return ck_rng_reason(rng.state);
}

uint64_t ck_entropy_retries(void)
{
    return rng.retries;
}
