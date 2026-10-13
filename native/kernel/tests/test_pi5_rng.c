/* test_pi5_rng.c -- Pi 5 RNG200 driver (dev/pi5_rng.c) against a mocked
 * register block, driving the real core/entropy.c rules: init sequence,
 * empty FIFO, lockout (one soft reset, then refuse, latched), warm-up that
 * never finishes, stuck output, block that will not enable. Hosted: this is
 * NOT the hardware; the block itself is proved on the hub Pi (pi5-run.sh). */
#include <stdio.h>
#include <string.h>
#include "ck_test.h"
#include "pi5_rng.h"

struct mock {
    uint32_t ctrl, thresh, fifo_thr, status, bitcount;
    uint64_t seq;       /* next generated word source */
    int fifo_n;         /* words available */
    int same;           /* every word is this value when same_on */
    int same_on;
    int fifo_empty;     /* count register always 0 */
    int ignore_enable;  /* control writes do not stick */
    int lockout_sticks; /* reset does not clear the lockout */
    int resets, writes, fifo_reads;
    uint32_t last_w_off[16], last_w_val[16];
};

static uint32_t m_rd(void *c, uint32_t off)
{
    struct mock *m = c;
    switch (off) {
    case CK_RNG200_CTRL: return m->ctrl;
    case CK_RNG200_BITCOUNT: return m->bitcount;
    case CK_RNG200_INT_STATUS: return m->status;
    case CK_RNG200_FIFO_COUNT: return m->fifo_empty ? 0 : (m->fifo_thr << 8) | (uint32_t)(m->fifo_n > 255 ? 255 : m->fifo_n);
    case CK_RNG200_FIFO_DATA:
        m->fifo_reads++;
        if (m->same_on) return (uint32_t)m->same;
        return (uint32_t)(m->seq++ * 0x9e3779b97f4a7c15ull >> 17) | 1u;
    default: return 0;
    }
}

static void m_wr(void *c, uint32_t off, uint32_t v)
{
    struct mock *m = c;
    if (m->writes < 16) { m->last_w_off[m->writes] = off; m->last_w_val[m->writes] = v; }
    m->writes++;
    switch (off) {
    case CK_RNG200_CTRL: if (!m->ignore_enable) m->ctrl = v; break;
    case CK_RNG200_BITCOUNT_THRESH: m->thresh = v; break;
    case CK_RNG200_FIFO_COUNT: m->fifo_thr = v >> 8; break;
    case CK_RNG200_INT_STATUS:
        if (v == 0xffffffffu && !m->lockout_sticks) m->status = 0;
        break;
    case CK_RNG200_SOFT_RESET: if (v & 1u) m->resets++; break;
    default: break;
    }
}

static void fresh(struct mock *m)
{
    memset(m, 0, sizeof *m);
    m->bitcount = 100;
    m->fifo_n = 200;
    m->seq = 1;
}

static void bring_up(struct mock *m, struct ck_rng200 *r)
{
    struct ck_rng200_io io = {m_rd, m_wr, m};
    ck_rng200_init(r, &io);
}

static void ops_of(struct ck_rng200 *r, struct ck_rng_ops *o)
{
    o->present = ck_rng200_present;
    o->read = ck_rng200_read;
    o->ctx = r;
}

int main(void)
{
    struct mock m;
    struct ck_rng200 r;
    struct ck_rng_ops ops;
    struct ck_rng rng;
    uint8_t buf[64];
    uint64_t w;

    printf("  [init from cold: threshold, FIFO threshold, enable at 1 MHz]\n");
    fresh(&m);
    bring_up(&m, &r);
    CHECK(m.thresh == 0x40000u);
    CHECK(m.fifo_thr == 2u);
    CHECK(m.ctrl == ((3u << 13) | 1u));
    CHECK(r.up == 1);
    CHECK(ck_rng200_present(&r) == 1);

    printf("  [init when firmware already enabled it: no writes]\n");
    fresh(&m);
    m.ctrl = (3u << 13) | 1u;
    bring_up(&m, &r);
    CHECK(m.writes == 0);
    CHECK(r.up == 1);

    printf("  [block that will not enable: absent, probe refuses]\n");
    fresh(&m);
    m.ignore_enable = 1;
    bring_up(&m, &r);
    ops_of(&r, &ops);
    CHECK(r.up == 0);
    CHECK(ck_rng_probe(&rng, &ops) == CK_RNG_ABSENT);

    printf("  [healthy: probe OK, fill delivers, words come from two FIFO reads]\n");
    fresh(&m);
    bring_up(&m, &r);
    ops_of(&r, &ops);
    CHECK(ck_rng_probe(&rng, &ops) == CK_RNG_OK);
    CHECK(m.fifo_reads == 4);
    memset(buf, 0, sizeof buf);
    CHECK(ck_rng_fill(&rng, buf, sizeof buf) == 0);
    {
        int nz = 0;
        for (unsigned i = 0; i < sizeof buf; i++) nz |= buf[i];
        CHECK(nz != 0);
    }
    CHECK(m.resets == 0);

    printf("  [FIFO stays empty: read fails, probe FAILED, buffer zeroed]\n");
    fresh(&m);
    bring_up(&m, &r);
    m.fifo_empty = 1;
    ops_of(&r, &ops);
    CHECK(ck_rng200_read(&r, &w) == 0);
    CHECK(ck_rng_probe(&rng, &ops) == CK_RNG_FAILED);
    memset(buf, 0xaa, sizeof buf);
    CHECK(ck_rng_fill(&rng, buf, sizeof buf) == CK_RNG_FAILED);
    CHECK(buf[0] == 0 && buf[63] == 0);

    printf("  [warm-up never completes: no data fabricated]\n");
    fresh(&m);
    bring_up(&m, &r);
    m.bitcount = 16;
    CHECK(ck_rng200_read(&r, &w) == 0);
    CHECK(m.fifo_reads == 0);

    printf("  [lockout that a soft reset clears: exactly one reset, then data]\n");
    fresh(&m);
    bring_up(&m, &r);
    m.status = CK_RNG200_INT_LOCKOUT;
    CHECK(ck_rng200_read(&r, &w) == 1);
    CHECK(m.resets == 1);
    CHECK(r.refused == 0);

    printf("  [NIST fail that a reset clears]\n");
    fresh(&m);
    bring_up(&m, &r);
    m.status = CK_RNG200_INT_NIST_FAIL;
    CHECK(ck_rng200_read(&r, &w) == 1);
    CHECK(m.resets == 1);

    printf("  [lockout that persists: one reset, refuse, latched, no more resets]\n");
    fresh(&m);
    bring_up(&m, &r);
    m.status = CK_RNG200_INT_LOCKOUT;
    m.lockout_sticks = 1;
    ops_of(&r, &ops);
    CHECK(ck_rng_probe(&rng, &ops) == CK_RNG_FAILED);
    CHECK(m.resets == 1);
    CHECK(r.refused == 1);
    CHECK(ck_rng200_present(&r) == 0);
    m.status = 0; /* even if the flag clears, the refusal stays */
    CHECK(ck_rng200_read(&r, &w) == 0);
    CHECK(m.resets == 1);
    CHECK(m.fifo_reads == 0);

    printf("  [stuck output (same word forever): existing entropy rule refuses]\n");
    fresh(&m);
    bring_up(&m, &r);
    m.same_on = 1;
    m.same = 0x12345678;
    ops_of(&r, &ops);
    CHECK(ck_rng_probe(&rng, &ops) == CK_RNG_STUCK);

    return ck_t_verdict("test_pi5_rng");
}
