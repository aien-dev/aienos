/* pi5_rng.h -- Raspberry Pi 5 (BCM2712) RNG200 hardware random source, polled.
 * Plugs into core/entropy.c as a struct ck_rng_ops. No fallback: when the
 * block does not answer, is locked out, or stays empty, read() returns 0 and
 * the strict rules in entropy.c refuse the source.
 *
 * Register map and sequences: Linux drivers/char/hw_random/iproc-rng200.c
 * (raspberrypi/linux rpi-6.12.y): offsets lines 21-48, bcm2711_rng200_init
 * lines 206-225, bcm2711_rng200_read lines 169-204 (warm-up wait on the total
 * bit count, FIFO count in the low 8 bits), fail check and one restart per
 * read lines 105-122, restart sequence lines 70-97.
 * Address: Pi firmware ACPI DSDT \_SB.RNG0 (HID RPI1014) 0x107d208000 len 0x28.
 * The block's design is not public: output quality is trust-the-vendor, the
 * same standing as Arm RNDR. */
#ifndef AIENOS_CK_PI5_RNG_H
#define AIENOS_CK_PI5_RNG_H
#include <stdint.h>
#include "entropy.h"

#define CK_PI5_RNG_PHYS 0x107d208000ull
#define CK_PI5_RNG_BYTES 0x28u

#define CK_RNG200_CTRL 0x00u
#define CK_RNG200_SOFT_RESET 0x04u
#define CK_RNG200_RBG_SOFT_RESET 0x08u
#define CK_RNG200_BITCOUNT 0x0cu
#define CK_RNG200_BITCOUNT_THRESH 0x10u
#define CK_RNG200_INT_STATUS 0x18u
#define CK_RNG200_FIFO_DATA 0x20u
#define CK_RNG200_FIFO_COUNT 0x24u

#define CK_RNG200_CTRL_ENABLE_MASK 0x00001fffu
#define CK_RNG200_CTRL_ENABLE 0x1u
#define CK_RNG200_CTRL_DIV_SHIFT 13
#define CK_RNG200_INT_LOCKOUT 0x80000000u
#define CK_RNG200_INT_NIST_FAIL 0x00000020u
#define CK_RNG200_FIFO_COUNT_MASK 0xffu
#define CK_RNG200_FIFO_THRESH_SHIFT 8
#define CK_RNG200_BITCOUNT_WARM 16u /* Linux waits for count > 16 */
#define CK_RNG200_THRESHOLD_INIT 0x40000u

/* Upper bound on register polls for one wait (warm-up or FIFO fill). */
#ifndef CK_RNG200_SPINS
#define CK_RNG200_SPINS 2000000u
#endif

/* Register access, so a host test can stand a mock block behind it. */
struct ck_rng200_io {
    uint32_t (*rd)(void *ctx, uint32_t off);
    void (*wr)(void *ctx, uint32_t off, uint32_t v);
    void *ctx;
};

struct ck_rng200 {
    struct ck_rng200_io io;
    int up;      /* init found the block enabled */
    int refused; /* latched: lockout/NIST fail twice, or no data */
    int resets;  /* soft resets done (at most one per read) */
};

/* Linux init: leave an already-enabled block alone, else threshold, FIFO
 * threshold, enable at 1 MHz. up = block enabled afterwards. */
void ck_rng200_init(struct ck_rng200 *r, const struct ck_rng200_io *io);
int ck_rng200_present(void *ctx);
/* One 64-bit word from two FIFO words. 1 = valid; 0 = failure (never fabricated). */
int ck_rng200_read(void *ctx, uint64_t *out);

#ifdef CK_PI5
/* Maps the block, runs init; returns the ops for ck_rng_probe (present()
 * reports 0 when the map failed). */
const struct ck_rng_ops *ck_pi5_rng_ops(void);
#endif
#endif
