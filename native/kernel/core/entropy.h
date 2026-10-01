/* entropy.h -- kernel entropy: the Arm RNDR instruction or a refusal.
 *
 * Pure selection logic over two callbacks (is FEAT_RNG present, read one
 * RNDR word), so host tests drive it with a mocked RNDR. The kernel glue
 * (arch/rndr.c) supplies the real ID_AA64ISAR0_EL1 / RNDR accessors.
 *
 * There is no fallback source. Rules:
 *  - FEAT_RNG is checked first (ID_AA64ISAR0_EL1.RNDR >= 1); absent means
 *    every request is refused.
 *  - RNDR reports failure by setting NZCV.Z; each 64-bit word is retried at
 *    most CK_RNG_RETRIES times, then the source is refused.
 *  - Stuck-output test: a word equal to the previous word refuses the source
 *    (FIPS-style continuous test; false-positive odds 2^-64 per word).
 *  - A refusal is latched for the rest of the boot and the caller's buffer
 *    is zeroed, so no partial or stale bytes ever leave as "random".
 * QEMU is not hardware: nothing built on this is physically qualified. */
#ifndef AIENOS_CK_ENTROPY_H
#define AIENOS_CK_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

#define CK_RNG_RETRIES 64u

enum {
    CK_RNG_OK = 0,
    CK_RNG_UNPROBED = -1, /* ck_rng_probe not called yet */
    CK_RNG_ABSENT = -2,   /* ID_AA64ISAR0_EL1.RNDR == 0 */
    CK_RNG_FAILED = -3,   /* RNDR failed CK_RNG_RETRIES times in a row */
    CK_RNG_STUCK = -4,    /* two consecutive words were equal */
    CK_RNG_EARG = -5,     /* bad arguments (state unchanged) */
};

struct ck_rng_ops {
    int (*present)(void *ctx);              /* 1 if FEAT_RNG is implemented */
    int (*read)(void *ctx, uint64_t *out);  /* 1 = valid word; 0 = RNDR failed (Z set) */
    void *ctx;
};

struct ck_rng {
    const struct ck_rng_ops *ops;
    int state;           /* CK_RNG_OK or the latched refusal */
    uint64_t last;       /* previous word, for the stuck-output test */
    uint64_t words;      /* words delivered (probe included) */
    uint64_t retries;    /* failed RNDR reads that a retry recovered */
};

/* Check FEAT_RNG, then draw two words (retry + stuck test). Returns the new
 * state: CK_RNG_OK or a refusal. */
int ck_rng_probe(struct ck_rng *r, const struct ck_rng_ops *ops);
/* Fill buf with RNDR output. 0 on success; otherwise the (latched) refusal
 * and buf is zeroed. */
int ck_rng_fill(struct ck_rng *r, void *buf, size_t len);
/* Short reason word for a state: "rndr", "absent", "failed", "stuck", ... */
const char *ck_rng_reason(int state);

#endif
