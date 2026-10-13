/* pi5_rng.c -- see pi5_rng.h. The logic is hosted-testable; the MMIO glue at
 * the bottom is Pi 5 only (CK_PI5). */
#include "pi5_rng.h"

static uint32_t fifo_words(struct ck_rng200 *r)
{
    return r->io.rd(r->io.ctx, CK_RNG200_FIFO_COUNT) & CK_RNG200_FIFO_COUNT_MASK;
}

void ck_rng200_init(struct ck_rng200 *r, const struct ck_rng200_io *io)
{
    r->io = *io;
    r->refused = 0;
    r->resets = 0;
    r->up = 0;
    if (!(r->io.rd(r->io.ctx, CK_RNG200_CTRL) & CK_RNG200_CTRL_ENABLE_MASK)) {
        r->io.wr(r->io.ctx, CK_RNG200_BITCOUNT_THRESH, CK_RNG200_THRESHOLD_INIT);
        r->io.wr(r->io.ctx, CK_RNG200_FIFO_COUNT, 2u << CK_RNG200_FIFO_THRESH_SHIFT);
        r->io.wr(r->io.ctx, CK_RNG200_CTRL, (3u << CK_RNG200_CTRL_DIV_SHIFT) | CK_RNG200_CTRL_ENABLE);
    }
    r->up = (r->io.rd(r->io.ctx, CK_RNG200_CTRL) & CK_RNG200_CTRL_ENABLE_MASK) != 0;
}

int ck_rng200_present(void *ctx)
{
    struct ck_rng200 *r = ctx;
    return r->up && !r->refused;
}

/* Linux iproc_rng200_restart: disable, clear status, pulse RBG and RNG reset, enable. */
static void restart(struct ck_rng200 *r)
{
    void *c = r->io.ctx;
    uint32_t v = r->io.rd(c, CK_RNG200_CTRL) & ~CK_RNG200_CTRL_ENABLE_MASK;
    r->io.wr(c, CK_RNG200_CTRL, v);
    r->io.wr(c, CK_RNG200_INT_STATUS, 0xffffffffu);
    r->io.wr(c, CK_RNG200_RBG_SOFT_RESET, r->io.rd(c, CK_RNG200_RBG_SOFT_RESET) | 1u);
    r->io.wr(c, CK_RNG200_SOFT_RESET, r->io.rd(c, CK_RNG200_SOFT_RESET) | 1u);
    r->io.wr(c, CK_RNG200_SOFT_RESET, r->io.rd(c, CK_RNG200_SOFT_RESET) & ~1u);
    r->io.wr(c, CK_RNG200_RBG_SOFT_RESET, r->io.rd(c, CK_RNG200_RBG_SOFT_RESET) & ~1u);
    r->io.wr(c, CK_RNG200_CTRL, (r->io.rd(c, CK_RNG200_CTRL) & ~CK_RNG200_CTRL_ENABLE_MASK) | CK_RNG200_CTRL_ENABLE);
    r->resets++;
}

/* 1 = healthy; 0 = failed even after the one allowed restart (latch refusal). */
static int healthy(struct ck_rng200 *r)
{
    uint32_t bad = CK_RNG200_INT_LOCKOUT | CK_RNG200_INT_NIST_FAIL;
    if (r->io.rd(r->io.ctx, CK_RNG200_INT_STATUS) & bad) {
        restart(r);
        if (r->io.rd(r->io.ctx, CK_RNG200_INT_STATUS) & bad) {
            r->refused = 1;
            return 0;
        }
    }
    return 1;
}

static int word32(struct ck_rng200 *r, uint32_t *out)
{
    uint32_t i;
    if (!healthy(r))
        return 0;
    for (i = 0; i < CK_RNG200_SPINS; i++)
        if (r->io.rd(r->io.ctx, CK_RNG200_BITCOUNT) > CK_RNG200_BITCOUNT_WARM)
            break;
    if (i == CK_RNG200_SPINS)
        return 0;
    for (i = 0; i < CK_RNG200_SPINS; i++)
        if (fifo_words(r))
            break;
    if (i == CK_RNG200_SPINS)
        return 0;
    *out = r->io.rd(r->io.ctx, CK_RNG200_FIFO_DATA);
    return 1;
}

int ck_rng200_read(void *ctx, uint64_t *out)
{
    struct ck_rng200 *r = ctx;
    uint32_t a, b;
    if (!r->up || r->refused)
        return 0;
    if (!word32(r, &a) || !word32(r, &b))
        return 0;
    *out = ((uint64_t)a << 32) | b;
    return 1;
}

#ifdef CK_PI5
#include "ck.h"

static volatile uint8_t *regs;
static struct ck_rng200 dev;

static uint32_t mm_rd(void *c, uint32_t off) { (void)c; return *(volatile uint32_t *)(regs + off); }
static void mm_wr(void *c, uint32_t off, uint32_t v) { (void)c; *(volatile uint32_t *)(regs + off) = v; }

static int mm_present(void *c)
{
    return regs && ck_rng200_present(c);
}

static const struct ck_rng_ops pi_ops = {mm_present, ck_rng200_read, &dev};

const struct ck_rng_ops *ck_pi5_rng_ops(void)
{
    static const struct ck_rng200_io io = {mm_rd, mm_wr, 0};
    if (!regs) {
        regs = ck_mmio_map(CK_PI5_RNG_PHYS, 0x1000);
        if (regs)
            ck_rng200_init(&dev, &io);
    }
    return &pi_ops;
}
#endif
