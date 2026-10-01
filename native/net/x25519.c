/* AIENOS X25519 (RFC 7748). See x25519.h.
 *
 * Field GF(2^255 - 19) in 16 signed 64-bit limbs of 16 bits each (the
 * TweetNaCl representation), rewritten here with every shift of a possibly
 * negative value replaced by a multiply so the code has no undefined
 * behaviour. Lines tagged GUARD:<name> are removed one at a time by
 * `make mutants`; the tests must catch each removal.
 */
#include "x25519.h"

#include <string.h>

typedef int64_t fe[16];

static const fe K121665 = {0xDB41, 1};

static void carry(fe o)
{
    for (int i = 0; i < 16; i++) {
        o[i] += (int64_t)1 << 16;
        int64_t c = o[i] >> 16; /* arithmetic shift (gcc/clang); value-preserving floor */
        if (i < 15) o[i + 1] += c - 1;
        else o[0] += 38 * (c - 1); /* GUARD:x-fold */
        o[i] -= c * 65536;
    }
}

/* Swap p and q when b = 1, keep them when b = 0, without a branch. */
static void cswap(fe p, fe q, int64_t b)
{
    int64_t m = -b; /* 0 or all ones */
    for (int i = 0; i < 16; i++) {
        int64_t t = m & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void add(fe o, const fe a, const fe b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void sub(fe o, const fe a, const fe b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void mul(fe o, const fe a, const fe b)
{
    int64_t t[31];
    for (int i = 0; i < 31; i++) t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    carry(o);
    carry(o);
}

static void sqr(fe o, const fe a) { mul(o, a, a); }

/* o = i^(p-2) = 1/i. The exponent is public, so its branches are too. */
static void invert(fe o, const fe in)
{
    fe c;
    memcpy(c, in, sizeof c);
    for (int a = 253; a >= 0; a--) {
        sqr(c, c);
        if (a != 2 && a != 4) mul(c, c, in);
    }
    memcpy(o, c, sizeof c);
}

static void unpack(fe o, const uint8_t n[32])
{
    for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff; /* GUARD:u-mask */
}

/* Fully reduce mod p (two conditional subtractions) and encode. */
static void pack(uint8_t o[32], const fe n)
{
    fe m, t;
    memcpy(t, n, sizeof t);
    carry(t);
    carry(t);
    carry(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        cswap(t, m, 1 - b); /* GUARD:x-reduce */
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xff);
    }
}

static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int aienos_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32])
{
    uint8_t z[32];
    fe x, a, b, c, d, e, f;
    memcpy(z, scalar, 32);
    z[31] &= 127; /* bit 255 is never read by the ladder; kept for clarity */
    z[31] |= 64;  /* GUARD:clamp-254 */
    z[0] &= 248;  /* GUARD:clamp-low */
    unpack(x, u);
    for (int i = 0; i < 16; i++) { b[i] = x[i]; a[i] = c[i] = d[i] = 0; }
    a[0] = d[0] = 1;
    /* Montgomery ladder over bits 254..0 (RFC 7748 Section 5). */
    for (int i = 254; i >= 0; i--) {
        int64_t r = (z[i >> 3] >> (i & 7)) & 1;
        cswap(a, b, r);
        cswap(c, d, r);
        add(e, a, c);
        sub(a, a, c);
        add(c, b, d);
        sub(b, b, d);
        sqr(d, e);
        sqr(f, a);
        mul(a, c, a);
        mul(c, b, e);
        add(e, a, c);
        sub(a, a, c);
        sqr(b, a);
        sub(c, d, f);
        mul(a, c, K121665);
        add(a, a, d);
        mul(c, c, a);
        mul(a, d, f);
        mul(d, b, x);
        sqr(b, e);
        cswap(a, b, r);
        cswap(c, d, r);
    }
    invert(c, c);
    mul(a, a, c);
    pack(out, a);
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= out[i];
    wipe(z, sizeof z);
    wipe(a, sizeof a); wipe(b, sizeof b); wipe(c, sizeof c);
    wipe(d, sizeof d); wipe(e, sizeof e); wipe(f, sizeof f); wipe(x, sizeof x);
    /* all-zero output <=> small-order input (RFC 7748 Section 6.1) */
    return ((acc | (uint8_t)-acc) >> 7) ? 0 : -1;
}

void aienos_x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
    static const uint8_t nine[32] = {9};
    (void)aienos_x25519(out, scalar, nine);
}
