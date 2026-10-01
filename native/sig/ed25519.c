/* Ed25519 (RFC 8032 Section 5.1), pure Ed25519 only.
 *
 * Field GF(2^255 - 19): five 51-bit limbs, 128-bit products.
 * Points: extended twisted Edwards coordinates (X:Y:Z:T), a = -1, with the
 * RFC 8032 Section 5.1.4 addition and doubling formulas (complete).
 * Scalars mod L: bit-serial reduction with a masked conditional subtract.
 *
 * Constant time (signing, key derivation): the scalar ladder always doubles
 * and adds and keeps the sum with a masked select; there is no branch and
 * no memory index that depends on a secret. Exponents used in inversion and
 * square roots are public constants. Verification and point decoding take
 * only public input and use ordinary branches.
 *
 * Lines tagged GUARD:<name> are removed one at a time by `make mutants`.
 */
#include <string.h>

#include "aienos_sig.h"
#include "sig_internal.h"

typedef unsigned __int128 u128;
typedef uint64_t fe[5];
typedef struct {
    fe X, Y, Z, T;
} ge;
typedef struct {
    fe d, d2, sqrtm1;
    ge B;
} consts;

#define MASK51 ((uint64_t)0x7ffffffffffff)

/* ---------------------------------------------------------------- field */

static void fe_0(fe h) { h[0] = h[1] = h[2] = h[3] = h[4] = 0; }
static void fe_1(fe h) { fe_0(h); h[0] = 1; }
static void fe_copy(fe h, const fe f) { for (int i = 0; i < 5; i++) h[i] = f[i]; }

/* Weak reduction: afterwards h1..h4 < 2^51 and h0 < 2^51 + 2^18. */
static void fe_carry(fe h)
{
    uint64_t c;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
    c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
    c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
    c = h[4] >> 51; h[4] &= MASK51; h[0] += 19 * c;
}

static void fe_add(fe h, const fe f, const fe g)
{
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
    fe_carry(h);
}

/* h = f - g computed as f + 4p - g (g limbs are below 2^53 - 76). */
static void fe_sub(fe h, const fe f, const fe g)
{
    h[0] = f[0] + 0x1fffffffffffb4 - g[0];
    h[1] = f[1] + 0x1ffffffffffffc - g[1];
    h[2] = f[2] + 0x1ffffffffffffc - g[2];
    h[3] = f[3] + 0x1ffffffffffffc - g[3];
    h[4] = f[4] + 0x1ffffffffffffc - g[4];
    fe_carry(h);
}

static void fe_neg(fe h, const fe f)
{
    fe z;
    fe_0(z);
    fe_sub(h, z, f);
}

static void fe_mul(fe h, const fe f, const fe g)
{
    uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    uint64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    uint64_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4;
    u128 r0 = (u128)f0 * g0 + (u128)f1 * g4_19 + (u128)f2 * g3_19 + (u128)f3 * g2_19 + (u128)f4 * g1_19;
    u128 r1 = (u128)f0 * g1 + (u128)f1 * g0 + (u128)f2 * g4_19 + (u128)f3 * g3_19 + (u128)f4 * g2_19;
    u128 r2 = (u128)f0 * g2 + (u128)f1 * g1 + (u128)f2 * g0 + (u128)f3 * g4_19 + (u128)f4 * g3_19;
    u128 r3 = (u128)f0 * g3 + (u128)f1 * g2 + (u128)f2 * g1 + (u128)f3 * g0 + (u128)f4 * g4_19;
    u128 r4 = (u128)f0 * g4 + (u128)f1 * g3 + (u128)f2 * g2 + (u128)f3 * g1 + (u128)f4 * g0;
    r1 += r0 >> 51;
    r2 += r1 >> 51;
    r3 += r2 >> 51;
    r4 += r3 >> 51;
    u128 c = r4 >> 51;
    uint64_t h0 = (uint64_t)r0 & MASK51, h1 = (uint64_t)r1 & MASK51, h2 = (uint64_t)r2 & MASK51;
    uint64_t h3 = (uint64_t)r3 & MASK51, h4 = (uint64_t)r4 & MASK51;
    u128 t = (u128)h0 + c * 19;
    h0 = (uint64_t)t & MASK51;
    h1 += (uint64_t)(t >> 51);
    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static uint64_t load_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

static void store_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

/* Reads 255 bits (bit 255 ignored); the value may be >= p. */
static void fe_frombytes(fe h, const uint8_t s[32])
{
    h[0] = load_le64(s) & MASK51;
    h[1] = (load_le64(s + 6) >> 3) & MASK51;
    h[2] = (load_le64(s + 12) >> 6) & MASK51;
    h[3] = (load_le64(s + 19) >> 1) & MASK51;
    h[4] = (load_le64(s + 24) >> 12) & MASK51;
}

/* Canonical encoding (fully reduced mod p), branch free. */
static void fe_tobytes(uint8_t s[32], const fe f)
{
    fe t;
    fe_copy(t, f);
    fe_carry(t);
    fe_carry(t); /* now t < 2^255 + 19 < 2p */
    uint64_t q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51; /* q = 1 iff t >= p */
    t[0] += 19 * q;
    t[1] += t[0] >> 51; t[0] &= MASK51;
    t[2] += t[1] >> 51; t[1] &= MASK51;
    t[3] += t[2] >> 51; t[2] &= MASK51;
    t[4] += t[3] >> 51; t[3] &= MASK51;
    t[4] &= MASK51; /* drop q * 2^255 */
    store_le64(s, t[0] | (t[1] << 51));
    store_le64(s + 8, (t[1] >> 13) | (t[2] << 38));
    store_le64(s + 16, (t[2] >> 26) | (t[3] << 25));
    store_le64(s + 24, (t[3] >> 39) | (t[4] << 12));
}

/* f = g if b == 1, unchanged if b == 0; b must be 0 or 1. */
static void fe_cmov(fe f, const fe g, uint64_t b)
{
    uint64_t m = 0 - b;
    AIENOS_SIG_BARRIER(m);
    for (int i = 0; i < 5; i++)
        f[i] ^= m & (f[i] ^ g[i]);
}

/* Low bit of the canonical value (the RFC 8032 "sign" of x). */
static uint64_t fe_isneg(const fe f)
{
    uint8_t s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

/* Public data only. */
static int fe_iszero(const fe f)
{
    uint8_t s[32], d = 0;
    fe_tobytes(s, f);
    for (int i = 0; i < 32; i++) d |= s[i];
    return d == 0;
}

static int fe_eq(const fe f, const fe g)
{
    uint8_t a[32], b[32];
    fe_tobytes(a, f);
    fe_tobytes(b, g);
    return aienos_sig_ct_equal(a, b, 32);
}

/* out = z^e, e a PUBLIC little-endian 256-bit exponent. */
static void fe_pow(fe out, const fe z, const uint8_t e[32])
{
    fe r, b;
    fe_1(r);
    fe_copy(b, z);
    for (int i = 255; i >= 0; i--) {
        fe_sq(r, r);
        if ((e[i >> 3] >> (i & 7)) & 1)
            fe_mul(r, r, b);
    }
    fe_copy(out, r);
}

/* p - 2 = 2^255 - 21, (p - 5) / 8 = 2^252 - 3, (p - 1) / 4 = 2^253 - 5 */
static const uint8_t EXP_INV[32] = {
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
static const uint8_t EXP_P58[32] = {
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f};
static const uint8_t EXP_SQRTM1[32] = {
    0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f};

static void fe_invert(fe out, const fe z) { fe_pow(out, z, EXP_INV); }

/* ---------------------------------------------------------------- points */

static void ge_identity(ge *p)
{
    fe_0(p->X); fe_1(p->Y); fe_1(p->Z); fe_0(p->T);
}

static void ge_add(ge *r, const ge *p, const ge *q, const consts *k)
{
    fe a, b, c, d, e, f, g, h, t;
    fe_sub(a, p->Y, p->X); fe_sub(t, q->Y, q->X); fe_mul(a, a, t);
    fe_add(b, p->Y, p->X); fe_add(t, q->Y, q->X); fe_mul(b, b, t);
    fe_mul(c, p->T, q->T); fe_mul(c, c, k->d2);
    fe_mul(d, p->Z, q->Z); fe_add(d, d, d);
    fe_sub(e, b, a); fe_sub(f, d, c); fe_add(g, d, c); fe_add(h, b, a);
    fe_mul(r->X, e, f); fe_mul(r->Y, g, h); fe_mul(r->T, e, h); fe_mul(r->Z, f, g);
}

static void ge_dbl(ge *r, const ge *p)
{
    fe a, b, c, e, f, g, h, t;
    fe_sq(a, p->X); fe_sq(b, p->Y); fe_sq(c, p->Z); fe_add(c, c, c);
    fe_add(h, a, b); fe_add(t, p->X, p->Y); fe_sq(t, t); fe_sub(e, h, t);
    fe_sub(g, a, b); fe_add(f, c, g);
    fe_mul(r->X, e, f); fe_mul(r->Y, g, h); fe_mul(r->T, e, h); fe_mul(r->Z, f, g);
}

static void ge_cmov(ge *r, const ge *p, uint64_t b)
{
    fe_cmov(r->X, p->X, b); fe_cmov(r->Y, p->Y, b);
    fe_cmov(r->Z, p->Z, b); fe_cmov(r->T, p->T, b);
}

static void ge_neg(ge *r, const ge *p)
{
    fe_neg(r->X, p->X); fe_copy(r->Y, p->Y); fe_copy(r->Z, p->Z); fe_neg(r->T, p->T);
}

/* r = [s]p, constant time in s: 256 doublings and 256 additions always,
 * the sum kept by a masked select. */
static void ge_scalarmult(ge *r, const ge *p, const uint8_t s[32], const consts *k)
{
    ge q, t;
    ge_identity(&q);
    for (int i = 255; i >= 0; i--) {
        uint64_t bit = (uint64_t)((s[i >> 3] >> (i & 7)) & 1);
        ge_dbl(&q, &q);
        ge_add(&t, &q, p, k);
        ge_cmov(&q, &t, bit);
    }
    *r = q;
    aienos_sig_wipe(&q, sizeof q);
    aienos_sig_wipe(&t, sizeof t);
}

static void ge_tobytes(uint8_t s[32], const ge *p)
{
    fe zi, x, y;
    fe_invert(zi, p->Z);
    fe_mul(x, p->X, zi);
    fe_mul(y, p->Y, zi);
    fe_tobytes(s, y);
    s[31] ^= (uint8_t)(fe_isneg(x) << 7);
    aienos_sig_wipe(zi, sizeof zi);
    aienos_sig_wipe(x, sizeof x);
    aienos_sig_wipe(y, sizeof y);
}

/* 1 iff the 255-bit value y (bit 255 already cleared) is >= p. */
static int y_noncanonical(const uint8_t y[32])
{
    if (y[31] != 0x7f) return 0;
    for (int i = 30; i >= 1; i--)
        if (y[i] != 0xff) return 0;
    return y[0] >= 0xed;
}

/* RFC 8032 Section 5.1.3 decoding. Public input; returns 0 or -1. */
static int ge_frombytes(ge *p, const uint8_t s[32], const consts *k)
{
    uint8_t yb[32];
    memcpy(yb, s, 32);
    uint64_t sign = yb[31] >> 7;
    yb[31] &= 0x7f;
    if (y_noncanonical(yb)) return -1; /* GUARD:y-canonical */
    fe y, y2, u, v, v3, x, vx2, nu, one;
    fe_frombytes(y, yb);
    fe_1(one);
    fe_sq(y2, y);
    fe_sub(u, y2, one);       /* u = y^2 - 1 */
    fe_mul(v, y2, k->d);
    fe_add(v, v, one);        /* v = d y^2 + 1 */
    fe_sq(v3, v);
    fe_mul(v3, v3, v);        /* v^3 */
    fe_sq(x, v3);
    fe_mul(x, x, v);
    fe_mul(x, x, u);          /* u v^7 */
    fe_pow(x, x, EXP_P58);
    fe_mul(x, x, v3);
    fe_mul(x, x, u);          /* candidate root u v^3 (u v^7)^((p-5)/8) */
    fe_sq(vx2, x);
    fe_mul(vx2, vx2, v);
    fe_neg(nu, u);
    int root_ok = fe_eq(vx2, u);
    if (!root_ok && fe_eq(vx2, nu)) {
        fe_mul(x, x, k->sqrtm1);
        root_ok = 1;
    }
    if (!root_ok) return -1; /* GUARD:on-curve */
    if (fe_iszero(x) && sign) return -1; /* GUARD:x-zero-sign */
    if (fe_isneg(x) != sign) fe_neg(x, x); /* GUARD:x-sign */
    fe_copy(p->X, x);
    fe_copy(p->Y, y);
    fe_1(p->Z);
    fe_mul(p->T, x, y);
    return 0;
}

/* Public input. 1 iff [8]p is the identity (order of p divides 8). */
static int ge_small_order(const ge *p)
{
    ge q;
    ge_dbl(&q, p);
    ge_dbl(&q, &q);
    ge_dbl(&q, &q);
    return fe_iszero(q.X) && fe_eq(q.Y, q.Z);
}

/* Public input: -x^2 + y^2 == 1 + d x^2 y^2 for the affine point. */
static int ge_on_curve(const ge *p, const consts *k)
{
    fe zi, x, y, x2, y2, l, r, one;
    fe_invert(zi, p->Z);
    fe_mul(x, p->X, zi); fe_mul(y, p->Y, zi);
    fe_sq(x2, x); fe_sq(y2, y);
    fe_sub(l, y2, x2);
    fe_1(one);
    fe_mul(r, x2, y2); fe_mul(r, r, k->d); fe_add(r, r, one);
    return fe_eq(l, r);
}

static void consts_init(consts *k)
{
    /* d = -121665 / 121666, sqrt(-1) = 2^((p-1)/4), B = encoding 0x58 0x66.. */
    fe a, b, two;
    fe_0(a); a[0] = 121665;
    fe_0(b); b[0] = 121666;
    fe_invert(b, b);
    fe_mul(a, a, b);
    fe_neg(k->d, a);
    fe_add(k->d2, k->d, k->d);
    fe_0(two); two[0] = 2;
    fe_pow(k->sqrtm1, two, EXP_SQRTM1);
    uint8_t enc[32];
    memset(enc, 0x66, 32);
    enc[0] = 0x58;
    (void)ge_frombytes(&k->B, enc, k);
}

/* ---------------------------------------------------------------- scalars */

/* L = 2^252 + 27742317777372353535851937790883648493, little endian words. */
static const uint32_t LW[8] = {0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
                               0x00000000, 0x00000000, 0x00000000, 0x10000000};

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* r = x mod L for a 512-bit x given as 16 words. Constant time: one shift
 * and one masked subtract per input bit. */
static void sc_reduce_words(uint8_t out[32], const uint32_t x[16])
{
    uint32_t r[8] = {0}, t[8];
    for (int i = 511; i >= 0; i--) {
        uint32_t carry = (x[i >> 5] >> (i & 31)) & 1;
        for (int j = 0; j < 8; j++) {
            uint32_t nc = r[j] >> 31;
            r[j] = (r[j] << 1) | carry;
            carry = nc;
        }
        uint64_t borrow = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t d = (uint64_t)r[j] - LW[j] - borrow;
            t[j] = (uint32_t)d;
            borrow = (d >> 63) & 1;
        }
        uint32_t m = (uint32_t)borrow - 1; /* all ones iff r >= L */
        AIENOS_SIG_BARRIER(m);
        for (int j = 0; j < 8; j++) r[j] = (t[j] & m) | (r[j] & ~m); /* GUARD:sc-sub */
    }
    for (int j = 0; j < 8; j++) st32(out + 4 * j, r[j]);
    aienos_sig_wipe(r, sizeof r);
    aienos_sig_wipe(t, sizeof t);
}

void aienos_sig_sc_reduce(uint8_t out[32], const uint8_t in[64])
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = ld32(in + 4 * i);
    sc_reduce_words(out, x);
    aienos_sig_wipe(x, sizeof x);
}

void aienos_sig_sc_muladd(uint8_t out[32], const uint8_t a[32], const uint8_t b[32],
                          const uint8_t c[32])
{
    uint32_t aw[8], bw[8], p[16] = {0};
    for (int i = 0; i < 8; i++) { aw[i] = ld32(a + 4 * i); bw[i] = ld32(b + 4 * i); }
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = (uint64_t)aw[i] * bw[j] + p[i + j] + carry;
            p[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        p[i + 8] = (uint32_t)carry;
    }
    uint64_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint64_t t = (uint64_t)p[i] + (i < 8 ? ld32(c + 4 * i) : 0) + carry;
        p[i] = (uint32_t)t;
        carry = t >> 32;
    }
    /* a, b, c < 2^256 with a*b + c < 2^512 for every caller here (a < L,
     * b < 2^255); carry is 0. */
    sc_reduce_words(out, p);
    aienos_sig_wipe(aw, sizeof aw);
    aienos_sig_wipe(bw, sizeof bw);
    aienos_sig_wipe(p, sizeof p);
}

/* Public input: 1 iff s < L. */
static int sc_canonical(const uint8_t s[32])
{
    for (int j = 7; j >= 0; j--) {
        uint32_t w = ld32(s + 4 * j);
        if (w < LW[j]) return 1;
        if (w > LW[j]) return 0;
    }
    return 0; /* s == L */
}

/* ---------------------------------------------------------------- Ed25519 */

/* h = SHA-512(sk); a = clamp(h[0..32]); A = encode([a]B). */
static void expand_key(uint8_t h[64], uint8_t pk[32], const uint8_t sk[32], const consts *k)
{
    ge A;
    aienos_sha512(sk, 32, h);
    h[0] &= 248; /* GUARD:clamp-low */
    h[31] &= 127; /* GUARD:clamp-high */
    h[31] |= 64; /* GUARD:clamp-254 */
    ge_scalarmult(&A, &k->B, h, k);
    ge_tobytes(pk, &A);
    aienos_sig_wipe(&A, sizeof A);
}

int aienos_ed25519_public_key(uint8_t pk[32], const uint8_t sk[32])
{
    if (!pk || !sk) return AIENOS_SIG_ERR_ARG;
    consts k;
    uint8_t h[64];
    consts_init(&k);
    expand_key(h, pk, sk, &k);
    aienos_sig_wipe(h, sizeof h);
    return AIENOS_SIG_OK;
}

int aienos_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                        const uint8_t sk[32])
{
    if (!sig || !sk || (!msg && msg_len)) return AIENOS_SIG_ERR_ARG;
    consts k;
    uint8_t h[64], pk[32], rh[64], r[32], Rb[32], kh[64], ks[32], S[32];
    ge R;
    aienos_sha512_ctx c;
    consts_init(&k);
    expand_key(h, pk, sk, &k);

    aienos_sha512_init(&c); /* r = SHA-512(prefix || M) mod L */
    aienos_sha512_update(&c, h + 32, 32);
    aienos_sha512_update(&c, msg, msg_len);
    aienos_sha512_final(&c, rh);
    aienos_sig_sc_reduce(r, rh);
    ge_scalarmult(&R, &k.B, r, &k);
    ge_tobytes(Rb, &R);

    aienos_sha512_init(&c); /* k = SHA-512(R || A || M) mod L */
    aienos_sha512_update(&c, Rb, 32);
    aienos_sha512_update(&c, pk, 32);
    aienos_sha512_update(&c, msg, msg_len);
    aienos_sha512_final(&c, kh);
    aienos_sig_sc_reduce(ks, kh);

    aienos_sig_sc_muladd(S, ks, h, r); /* S = (r + k a) mod L */
    memcpy(sig, Rb, 32);
    memcpy(sig + 32, S, 32);

    aienos_sig_wipe(h, sizeof h);
    aienos_sig_wipe(rh, sizeof rh);
    aienos_sig_wipe(r, sizeof r);
    aienos_sig_wipe(&R, sizeof R);
    aienos_sig_wipe(S, sizeof S);
    return AIENOS_SIG_OK;
}

int aienos_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                          const uint8_t pk[32])
{
    if (!sig || !pk || (!msg && msg_len)) return AIENOS_SIG_ERR_ARG;
    consts k;
    ge A, R, sB, kA, chk;
    uint8_t kh[64], ks[32], enc[32];
    aienos_sha512_ctx c;
    consts_init(&k);
    if (!sc_canonical(sig + 32)) return AIENOS_SIG_ERR_INVALID; /* GUARD:s-range */
    if (ge_frombytes(&A, pk, &k)) return AIENOS_SIG_ERR_INVALID;
    if (ge_small_order(&A)) return AIENOS_SIG_ERR_INVALID; /* GUARD:a-small-order */
    if (ge_frombytes(&R, sig, &k)) return AIENOS_SIG_ERR_INVALID;
    if (ge_small_order(&R)) return AIENOS_SIG_ERR_INVALID; /* GUARD:r-small-order */

    aienos_sha512_init(&c);
    aienos_sha512_update(&c, sig, 32);
    aienos_sha512_update(&c, pk, 32);
    aienos_sha512_update(&c, msg, msg_len);
    aienos_sha512_final(&c, kh);
    aienos_sig_sc_reduce(ks, kh);

    ge_scalarmult(&sB, &k.B, sig + 32, &k);
    ge_scalarmult(&kA, &A, ks, &k);
    ge_neg(&kA, &kA);
    ge_add(&chk, &sB, &kA, &k); /* [S]B - [k]A, must equal R */
    ge_tobytes(enc, &chk);
    if (!aienos_sig_ct_equal(enc, sig, 32)) return AIENOS_SIG_ERR_INVALID; /* GUARD:r-check */
    return AIENOS_SIG_OK;
}

/* ---------------------------------------------------------------- test hooks */

void aienos_sig_basemult(uint8_t out[32], const uint8_t s[32])
{
    consts k;
    ge P;
    consts_init(&k);
    ge_scalarmult(&P, &k.B, s, &k);
    ge_tobytes(out, &P);
}

int aienos_sig_decode_check(uint8_t out[32], int *small, const uint8_t in[32])
{
    consts k;
    ge P;
    consts_init(&k);
    if (ge_frombytes(&P, in, &k)) return -1;
    if (!ge_on_curve(&P, &k)) return -2;
    *small = ge_small_order(&P);
    ge_tobytes(out, &P);
    return 0;
}
