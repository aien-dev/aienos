/* entropy.c -- RNDR-or-refuse selection logic (see entropy.h). Pure C, no
 * ck.h services, so the host tests (tests/test_entropy.c) run it against a
 * mocked RNDR. */
#include "entropy.h"

static void wipe(uint8_t *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

/* One word with the architected bounded retry. 0 ok, else refusal. */
static int draw(struct ck_rng *r, uint64_t *out)
{
    for (uint32_t t = 0; t < CK_RNG_RETRIES; t++) {
        uint64_t v = 0;
        if (r->ops->read(r->ops->ctx, &v)) {
            r->retries += t;
            if (r->words && v == r->last) return CK_RNG_STUCK;
            r->last = v;
            r->words++;
            *out = v;
            return CK_RNG_OK;
        }
    }
    return CK_RNG_FAILED;
}

int ck_rng_probe(struct ck_rng *r, const struct ck_rng_ops *ops)
{
    if (!r || !ops || !ops->present || !ops->read) return CK_RNG_EARG;
    r->ops = ops;
    r->last = 0;
    r->words = 0;
    r->retries = 0;
    if (!ops->present(ops->ctx)) return r->state = CK_RNG_ABSENT;
    uint64_t a, b;
    int rc = draw(r, &a);
    if (rc == CK_RNG_OK) rc = draw(r, &b);
    return r->state = rc;
}

int ck_rng_fill(struct ck_rng *r, void *buf, size_t len)
{
    if (!r || (!buf && len)) return CK_RNG_EARG;
    uint8_t *p = buf;
    if (r->state != CK_RNG_OK || !r->ops) {
        if (r->state == CK_RNG_OK) r->state = CK_RNG_UNPROBED;
        wipe(p, len);
        return r->state;
    }
    size_t i = 0;
    while (i < len) {
        uint64_t v;
        int rc = draw(r, &v);
        if (rc != CK_RNG_OK) {
            r->state = rc;
            wipe(p, len);
            return rc;
        }
        for (unsigned k = 0; k < 8 && i < len; k++) p[i++] = (uint8_t)(v >> (8 * k));
        v = 0;
    }
    return CK_RNG_OK;
}

const char *ck_rng_reason(int state)
{
    switch (state) {
    case CK_RNG_OK: return "rndr";
    case CK_RNG_UNPROBED: return "unprobed";
    case CK_RNG_ABSENT: return "absent";
    case CK_RNG_FAILED: return "failed";
    case CK_RNG_STUCK: return "stuck";
    default: return "bad-argument";
    }
}
