/* test_entropy.c -- host tests of core/entropy.c (RNDR-or-refuse) against a
 * mocked RNDR: FEAT_RNG absent, RNDR always failing, failing then
 * succeeding (inside and at the retry bound), failing mid-fill, a stuck
 * (repeating) source, and the latched refusal. */
#include <string.h>
#include "ck_test.h"
#include "entropy.h"

struct mock {
    int present;
    int fail_next;      /* fail this many reads, then succeed */
    long ok_left;       /* successes before failing forever (-1 = never) */
    int constant;       /* return the same word every time */
    uint64_t ctr;
    unsigned reads, present_calls;
};

static int m_present(void *c)
{
    struct mock *m = c;
    m->present_calls++;
    return m->present;
}

static int m_read(void *c, uint64_t *out)
{
    struct mock *m = c;
    m->reads++;
    *out = 0x1111111111111111ull; /* what a failed RNDR leaves (Arm: 0) */
    if (m->fail_next > 0) {
        m->fail_next--;
        *out = 0;
        return 0;
    }
    if (m->ok_left == 0) {
        *out = 0;
        return 0;
    }
    if (m->ok_left > 0) m->ok_left--;
    *out = m->constant ? 0x0123456789abcdefull : (0x9e3779b97f4a7c15ull * ++m->ctr);
    return 1;
}

static int all(const uint8_t *p, size_t n, uint8_t v)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}

static void setup(struct mock *m, struct ck_rng_ops *ops)
{
    memset(m, 0, sizeof *m);
    m->present = 1;
    m->ok_left = -1;
    ops->present = m_present;
    ops->read = m_read;
    ops->ctx = m;
}

int main(void)
{
    struct mock m;
    struct ck_rng_ops ops;
    struct ck_rng r;
    uint8_t buf[40];

    /* Never probed (zeroed state): refuse, zero the buffer. */
    memset(&r, 0, sizeof r);
    memset(buf, 0xaa, sizeof buf);
    CHECK(ck_rng_fill(&r, buf, sizeof buf) == CK_RNG_UNPROBED);
    CHECK(all(buf, sizeof buf, 0));
    CHECK(ck_rng_probe(&r, NULL) == CK_RNG_EARG);

    /* 1. FEAT_RNG absent: refused without a single RNDR read. */
    setup(&m, &ops);
    m.present = 0;
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_ABSENT);
    CHECK(m.reads == 0);
    memset(buf, 0xaa, sizeof buf);
    CHECK(ck_rng_fill(&r, buf, sizeof buf) == CK_RNG_ABSENT);
    CHECK(all(buf, sizeof buf, 0));
    CHECK(m.reads == 0);
    CHECK(strcmp(ck_rng_reason(r.state), "absent") == 0);

    /* 2. RNDR always fails: exactly CK_RNG_RETRIES reads, then refused and
     * latched (no further reads). */
    setup(&m, &ops);
    m.ok_left = 0;
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_FAILED);
    CHECK(m.reads == CK_RNG_RETRIES);
    memset(buf, 0xaa, sizeof buf);
    CHECK(ck_rng_fill(&r, buf, sizeof buf) == CK_RNG_FAILED);
    CHECK(all(buf, sizeof buf, 0));
    CHECK(m.reads == CK_RNG_RETRIES);
    CHECK(strcmp(ck_rng_reason(r.state), "failed") == 0);

    /* 3a. Fails CK_RNG_RETRIES - 1 times, then succeeds: usable. */
    setup(&m, &ops);
    m.fail_next = (int)CK_RNG_RETRIES - 1;
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_OK);
    CHECK(r.retries == CK_RNG_RETRIES - 1);
    CHECK(strcmp(ck_rng_reason(r.state), "rndr") == 0);
    /* 3b. Fails exactly CK_RNG_RETRIES times: refused (bound is inclusive). */
    setup(&m, &ops);
    m.fail_next = (int)CK_RNG_RETRIES;
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_FAILED);

    /* 4. Normal fill, length not a multiple of 8: little-endian words, in order. */
    setup(&m, &ops);
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_OK);
    CHECK(r.words == 2 && m.reads == 2);
    memset(buf, 0, sizeof buf);
    CHECK(ck_rng_fill(&r, buf, 13) == CK_RNG_OK);
    uint64_t w3 = 0x9e3779b97f4a7c15ull * 3, w4 = 0x9e3779b97f4a7c15ull * 4;
    int match = 1;
    for (int k = 0; k < 8; k++) match &= buf[k] == (uint8_t)(w3 >> (8 * k));
    for (int k = 0; k < 5; k++) match &= buf[8 + k] == (uint8_t)(w4 >> (8 * k));
    CHECK(match);
    CHECK(all(buf + 13, sizeof buf - 13, 0));
    CHECK(ck_rng_fill(&r, buf, 0) == CK_RNG_OK);

    /* 5. Transient failure during a fill is retried and recovered. */
    m.fail_next = 5;
    uint64_t before = r.retries;
    CHECK(ck_rng_fill(&r, buf, 16) == CK_RNG_OK);
    CHECK(r.retries == before + 5);

    /* 6. Source dies mid-fill: whole buffer zeroed (no partial bytes),
     * refusal latched even after RNDR would recover. */
    setup(&m, &ops);
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_OK);
    m.ok_left = 2; /* two more words, then dead */
    memset(buf, 0xaa, sizeof buf);
    CHECK(ck_rng_fill(&r, buf, sizeof buf) == CK_RNG_FAILED);
    CHECK(all(buf, sizeof buf, 0));
    m.ok_left = -1;
    unsigned reads = m.reads;
    memset(buf, 0xaa, sizeof buf);
    CHECK(ck_rng_fill(&r, buf, 8) == CK_RNG_FAILED);
    CHECK(all(buf, 8, 0));
    CHECK(m.reads == reads);

    /* 7. Stuck source: two equal words refuse at probe. */
    setup(&m, &ops);
    m.constant = 1;
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_STUCK);
    CHECK(strcmp(ck_rng_reason(r.state), "stuck") == 0);
    memset(buf, 0xaa, sizeof buf);
    CHECK(ck_rng_fill(&r, buf, sizeof buf) == CK_RNG_STUCK);
    CHECK(all(buf, sizeof buf, 0));
    /* 7b. Source sticks mid-fill: refused, buffer zeroed. */
    setup(&m, &ops);
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_OK);
    m.constant = 1; /* next word 0x0123.. differs from the last; the one after repeats */
    memset(buf, 0xaa, sizeof buf);
    CHECK(ck_rng_fill(&r, buf, 24) == CK_RNG_STUCK);
    CHECK(all(buf, 24, 0));

    /* 8. Re-probe after a refusal starts fresh (a new boot). */
    setup(&m, &ops);
    CHECK(ck_rng_probe(&r, &ops) == CK_RNG_OK);
    CHECK(ck_rng_fill(NULL, buf, 1) == CK_RNG_EARG);
    CHECK(ck_rng_fill(&r, NULL, 1) == CK_RNG_EARG);

    return ck_t_verdict("test_entropy");
}
