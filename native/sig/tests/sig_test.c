/* Known-answer, negative and round-trip tests for native/sig.
 *
 * Vector sources (all hard-coded, none generated at build time):
 *   - RFC 8032 Section 7.1: TEST 1, 2, 3, 1024 and SHA(abc), verbatim
 *     (tests/rfc8032_vectors.h).
 *   - SHA-512: FIPS 180-4 examples ("abc", the 896-bit message, one million
 *     'a'), the empty string, and padding-boundary lengths; digests checked
 *     against GNU coreutils sha512sum at authoring time.
 *   - Ed25519 small-order points: the eight points of order dividing 8.
 * Round trips use a fixed-seed splitmix64 generator (reproducible).
 * Last line is exactly AIENOS_SIG_NATIVE: PASS (exit 0) or ... FAIL (exit 1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aienos_sig.h"
#include "../sig_internal.h"
#include "rfc8032_vectors.h"

static int g_fail, g_checks;

#define CHECK(cond, ...)                                         \
    do {                                                         \
        g_checks++;                                              \
        if (!(cond)) {                                           \
            g_fail++;                                            \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                        \
            fprintf(stderr, "\n");                               \
        }                                                        \
    } while (0)

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex into a freshly allocated buffer (at least 1 byte). */
static uint8_t *unhex(const char *h, size_t *len)
{
    size_t n = strlen(h);
    if (n % 2 != 0) { fprintf(stderr, "odd hex\n"); exit(1); }
    uint8_t *b = malloc(n / 2 + 1);
    if (!b) exit(1);
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(h[2 * i]), lo = hexval(h[2 * i + 1]);
        if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex\n"); exit(1); }
        b[i] = (uint8_t)(hi << 4 | lo);
    }
    *len = n / 2;
    return b;
}

static void unhex_fixed(const char *h, uint8_t *out, size_t want)
{
    size_t n;
    uint8_t *b = unhex(h, &n);
    if (n != want) { fprintf(stderr, "hex length %zu != %zu\n", n, want); exit(1); }
    memcpy(out, b, n);
    free(b);
}

static uint64_t g_rng = 0x41494e4f53534947ull; /* fixed seed */
static uint64_t rnd(void)
{
    uint64_t z = (g_rng += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}
static void rnd_bytes(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)rnd();
}

/* L, little endian. */
static const uint8_t L_BYTES[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

/* a = b + c (256-bit little endian), returns carry. */
static int add256(uint8_t a[32], const uint8_t b[32], const uint8_t c[32])
{
    unsigned carry = 0;
    for (int i = 0; i < 32; i++) {
        unsigned t = (unsigned)b[i] + c[i] + carry;
        a[i] = (uint8_t)t;
        carry = t >> 8;
    }
    return (int)carry;
}

/* ------------------------------------------------------------ SHA-512 */

static void test_sha512(void)
{
    static const struct { const char *msg; size_t reps; const char *hex; } kat[] = {
        {"", 1, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {"abc", 1, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
         "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
        {"a", 1000000, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"},
        {"a", 111, "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2"},
        {"a", 112, "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca"},
        {"a", 127, "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502"},
        {"a", 128, "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321"},
        {"a", 239, "52c853cb8d907f3d4d6b889beb027985d7c273486d75f8baf26f80d24e90c74c6c3de3e22131582380a7d14d43f2941a31385439cd6ddc469f628015e50bf286"},
        {"a", 240, "4c296d90c61052a62ffb1dd196f1b7b09373b1f93e71836baebf89690546b7595684dbe9467a8e484fa0d1094272b4344a7c24f5fee8daedeb0bf549c985ab5f"},
    };
    for (size_t v = 0; v < sizeof kat / sizeof kat[0]; v++) {
        uint8_t want[64], got[64];
        unhex_fixed(kat[v].hex, want, 64);
        size_t ml = strlen(kat[v].msg);
        aienos_sha512_ctx c;
        aienos_sha512_init(&c);
        for (size_t r = 0; r < kat[v].reps; r++)
            aienos_sha512_update(&c, (const uint8_t *)kat[v].msg, ml);
        aienos_sha512_final(&c, got);
        CHECK(memcmp(got, want, 64) == 0, "sha512 kat %zu", v);
        if (kat[v].reps == 1) {
            aienos_sha512((const uint8_t *)kat[v].msg, ml, got);
            CHECK(memcmp(got, want, 64) == 0, "sha512 one-shot kat %zu", v);
        }
    }
    /* Every split point of a 300-byte message gives the one-shot digest. */
    uint8_t m[300], one[64], got[64];
    rnd_bytes(m, sizeof m);
    aienos_sha512(m, sizeof m, one);
    for (size_t s = 0; s <= sizeof m; s++) {
        aienos_sha512_ctx c;
        aienos_sha512_init(&c);
        aienos_sha512_update(&c, m, s);
        aienos_sha512_update(&c, NULL, 0);
        aienos_sha512_update(&c, m + s, sizeof m - s);
        aienos_sha512_final(&c, got);
        CHECK(memcmp(got, one, 64) == 0, "sha512 split %zu", s);
    }
}

/* ------------------------------------------------------------ RFC 8032 */

static void test_rfc_vectors(void)
{
    for (size_t v = 0; v < sizeof RFC8032_71 / sizeof RFC8032_71[0]; v++) {
        const struct rfc_vec *t = &RFC8032_71[v];
        uint8_t sk[32], pk[32], sig[64], got_pk[32], got_sig[64], bad[64], badpk[32];
        size_t ml;
        unhex_fixed(t->sk, sk, 32);
        unhex_fixed(t->pk, pk, 32);
        unhex_fixed(t->sig, sig, 64);
        uint8_t *msg = unhex(t->msg, &ml);

        CHECK(aienos_ed25519_public_key(got_pk, sk) == AIENOS_SIG_OK, "TEST %s pk rc", t->name);
        CHECK(memcmp(got_pk, pk, 32) == 0, "TEST %s public key", t->name);
        CHECK(aienos_ed25519_sign(got_sig, msg, ml, sk) == AIENOS_SIG_OK, "TEST %s sign rc", t->name);
        CHECK(memcmp(got_sig, sig, 64) == 0, "TEST %s signature", t->name);
        CHECK(aienos_ed25519_verify(sig, msg, ml, pk) == AIENOS_SIG_OK, "TEST %s verify", t->name);

        /* Byte flips in the signature (two different flips per byte). */
        for (int i = 0; i < 64; i++)
            for (int f = 0; f < 2; f++) {
                memcpy(bad, sig, 64);
                bad[i] ^= f ? 0x80 : 0x01;
                CHECK(aienos_ed25519_verify(bad, msg, ml, pk) == AIENOS_SIG_ERR_INVALID,
                      "TEST %s sig flip byte %d", t->name, i);
            }
        /* Byte flips in the public key. */
        for (int i = 0; i < 32; i++)
            for (int f = 0; f < 2; f++) {
                memcpy(badpk, pk, 32);
                badpk[i] ^= f ? 0x80 : 0x01;
                CHECK(aienos_ed25519_verify(sig, msg, ml, badpk) == AIENOS_SIG_ERR_INVALID,
                      "TEST %s pk flip byte %d", t->name, i);
            }
        /* Byte flips in the message (every byte; stride 7 on the long one). */
        size_t stride = ml > 64 ? 7 : 1;
        for (size_t i = 0; i < ml; i += stride) {
            msg[i] ^= 0x01;
            CHECK(aienos_ed25519_verify(sig, msg, ml, pk) == AIENOS_SIG_ERR_INVALID,
                  "TEST %s msg flip byte %zu", t->name, i);
            msg[i] ^= 0x01;
        }
        if (ml > 0) {
            CHECK(aienos_ed25519_verify(sig, msg, ml - 1, pk) == AIENOS_SIG_ERR_INVALID,
                  "TEST %s truncated msg", t->name);
            msg[ml - 1] ^= 0x01;
            CHECK(aienos_ed25519_verify(sig, msg, ml, pk) == AIENOS_SIG_ERR_INVALID,
                  "TEST %s last msg byte", t->name);
            msg[ml - 1] ^= 0x01;
        }
        uint8_t *longer = malloc(ml + 1);
        if (!longer) exit(1);
        memcpy(longer, msg, ml);
        longer[ml] = 0;
        CHECK(aienos_ed25519_verify(sig, longer, ml + 1, pk) == AIENOS_SIG_ERR_INVALID,
              "TEST %s extended msg", t->name);
        free(longer);

        /* Non-canonical S: S + L names the same scalar but must be refused. */
        memcpy(bad, sig, 64);
        CHECK(add256(bad + 32, sig + 32, L_BYTES) == 0, "S+L fits");
        CHECK(aienos_ed25519_verify(bad, msg, ml, pk) == AIENOS_SIG_ERR_INVALID,
              "TEST %s S + L accepted", t->name);
        /* S = L exactly, and S with the top bit set. */
        memcpy(bad, sig, 32);
        memcpy(bad + 32, L_BYTES, 32);
        CHECK(aienos_ed25519_verify(bad, msg, ml, pk) == AIENOS_SIG_ERR_INVALID, "S = L");
        memcpy(bad, sig, 64);
        bad[63] |= 0xe0;
        CHECK(aienos_ed25519_verify(bad, msg, ml, pk) == AIENOS_SIG_ERR_INVALID, "S high bits");
        free(msg);
    }
}

/* ------------------------------------------------------------ scalars and base point */

static void test_scalars(void)
{
    uint8_t out[32], in64[64], one[32] = {1}, zero[32] = {0}, enc[32];
    /* [L]B is the identity, [1]B is the base point, [L+1]B is B. */
    uint8_t ident[32] = {1};
    uint8_t B[32];
    memset(B, 0x66, 32);
    B[0] = 0x58;
    aienos_sig_basemult(enc, L_BYTES);
    CHECK(memcmp(enc, ident, 32) == 0, "[L]B != identity");
    aienos_sig_basemult(enc, one);
    CHECK(memcmp(enc, B, 32) == 0, "[1]B != B");
    uint8_t l1[32];
    add256(l1, L_BYTES, one);
    aienos_sig_basemult(enc, l1);
    CHECK(memcmp(enc, B, 32) == 0, "[L+1]B != B");
    aienos_sig_basemult(enc, zero);
    CHECK(memcmp(enc, ident, 32) == 0, "[0]B != identity");

    /* Reduction: L -> 0, L + 5 -> 5, L - 1 -> L - 1, 2^512 - 1 consistent with
     * muladd, (L-1)^2 -> 1. */
    memset(in64, 0, 64);
    memcpy(in64, L_BYTES, 32);
    aienos_sig_sc_reduce(out, in64);
    CHECK(memcmp(out, zero, 32) == 0, "L mod L");
    uint8_t five[32] = {5};
    add256(in64, L_BYTES, five);
    aienos_sig_sc_reduce(out, in64);
    CHECK(memcmp(out, five, 32) == 0, "L+5 mod L");
    uint8_t lm1[32];
    memcpy(lm1, L_BYTES, 32);
    lm1[0] -= 1;
    memset(in64, 0, 64);
    memcpy(in64, lm1, 32);
    aienos_sig_sc_reduce(out, in64);
    CHECK(memcmp(out, lm1, 32) == 0, "L-1 mod L");
    aienos_sig_sc_muladd(out, lm1, lm1, zero);
    CHECK(memcmp(out, one, 32) == 0, "(L-1)^2 mod L");
    /* 2^512 - 1 mod L: check direct reduction against muladd construction. */
    uint8_t all_ones[64], max256[32], m1[32], m2[32];
    memset(all_ones, 0xff, 64);
    memset(max256, 0xff, 32);
    aienos_sig_sc_reduce(out, all_ones);
    /* 2^512 - 1 = (2^256 - 1)^2 + 2 * (2^256 - 1) = max256 * max256 + max256 + max256 */
    aienos_sig_sc_muladd(m1, max256, max256, max256);
    aienos_sig_sc_muladd(m2, one, max256, m1);
    CHECK(memcmp(out, m2, 32) == 0, "2^512 - 1 consistent with muladd");
    uint8_t two[32] = {2}, three[32] = {3}, four[32] = {4}, ten[32] = {10};
    aienos_sig_sc_muladd(out, two, three, four);
    CHECK(memcmp(out, ten, 32) == 0, "2*3+4");
    aienos_sig_sc_muladd(out, lm1, one, two);
    CHECK(memcmp(out, one, 32) == 0, "(L-1)+2 mod L");
    /* Random: [x mod L]B == [x]B for random 256-bit x (x < 2^256). */
    for (int i = 0; i < 16; i++) {
        uint8_t x[32], e1[32], e2[32];
        rnd_bytes(x, 32);
        memset(in64, 0, 64);
        memcpy(in64, x, 32);
        aienos_sig_sc_reduce(out, in64);
        aienos_sig_basemult(e1, x);
        aienos_sig_basemult(e2, out);
        CHECK(memcmp(e1, e2, 32) == 0, "reduce consistent with group order %d", i);
    }
}

/* ------------------------------------------------------------ point decoding */

static const char *SMALL_ORDER[] = {
    "0100000000000000000000000000000000000000000000000000000000000000", /* identity */
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* order 2 */
    "0000000000000000000000000000000000000000000000000000000000000000", /* order 4 */
    "0000000000000000000000000000000000000000000000000000000000000080", /* order 4 */
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", /* order 8 */
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", /* order 8 */
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", /* order 8 */
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", /* order 8 */
};

static void test_decoding(void)
{
    uint8_t in[32], out[32];
    int small = -1;
    /* Every non-canonical y (p <= y < 2^255), with both sign bits. */
    for (int k = 0; k < 19; k++)
        for (int s = 0; s < 2; s++) {
            memset(in, 0xff, 32);
            in[0] = (uint8_t)(0xed + k);
            in[31] = (uint8_t)(0x7f | (s << 7));
            CHECK(aienos_sig_decode_check(out, &small, in) == -1, "non-canonical y=p+%d sign %d", k, s);
        }
    /* x = 0 with the sign bit set (y = 1 and y = -1). */
    memset(in, 0, 32);
    in[0] = 1;
    in[31] = 0x80;
    CHECK(aienos_sig_decode_check(out, &small, in) == -1, "x=0 sign=1 (y=1)");
    memset(in, 0xff, 32);
    in[0] = 0xec;
    in[31] = 0xff;
    CHECK(aienos_sig_decode_check(out, &small, in) == -1, "x=0 sign=1 (y=-1)");
    /* Small y values: each either refused or a valid, re-encodable point. */
    int refused = 0, accepted = 0;
    for (int y = 2; y < 64; y++)
        for (int s = 0; s < 2; s++) {
            memset(in, 0, 32);
            in[0] = (uint8_t)y;
            in[31] = (uint8_t)(s << 7);
            int rc = aienos_sig_decode_check(out, &small, in);
            CHECK(rc != -2, "y=%d decoded off the curve", y);
            if (rc == -1) refused++;
            if (rc == 0) {
                accepted++;
                CHECK(memcmp(in, out, 32) == 0, "y=%d sign %d re-encoding", y, s);
            }
        }
    CHECK(refused > 0 && accepted > 0, "on-curve split refused=%d accepted=%d", refused, accepted);
    /* The eight small-order points decode and are flagged small. */
    for (size_t i = 0; i < sizeof SMALL_ORDER / sizeof SMALL_ORDER[0]; i++) {
        unhex_fixed(SMALL_ORDER[i], in, 32);
        small = 0;
        CHECK(aienos_sig_decode_check(out, &small, in) == 0, "small-order %zu decodes", i);
        CHECK(small == 1, "small-order %zu flagged", i);
        CHECK(memcmp(in, out, 32) == 0, "small-order %zu re-encodes", i);
    }
    /* The base point decodes and is not small. */
    memset(in, 0x66, 32);
    in[0] = 0x58;
    CHECK(aienos_sig_decode_check(out, &small, in) == 0 && small == 0, "B decodes, not small");
}

/* ------------------------------------------------------------ verification policy */

/* Builds S = r + k a for a chosen R encoding, as a signer would. */
static void forge_with_r(uint8_t sig[64], const uint8_t Renc[32], const uint8_t r[32],
                         const uint8_t a[32], const uint8_t A[32], const uint8_t *m, size_t ml)
{
    uint8_t kh[64], ks[32];
    aienos_sha512_ctx c;
    aienos_sha512_init(&c);
    aienos_sha512_update(&c, Renc, 32);
    aienos_sha512_update(&c, A, 32);
    aienos_sha512_update(&c, m, ml);
    aienos_sha512_final(&c, kh);
    aienos_sig_sc_reduce(ks, kh);
    memcpy(sig, Renc, 32);
    aienos_sig_sc_muladd(sig + 32, ks, a, r);
}

static void test_policy(void)
{
    static const uint8_t m[] = "owner key signed migration record";
    size_t ml = sizeof m - 1;
    uint8_t sk[32], pk[32], h[64], a[32], sig[64], Renc[32], zero[32] = {0};
    uint8_t r[32] = {5};
    rnd_bytes(sk, 32);
    aienos_ed25519_public_key(pk, sk);
    aienos_sha512(sk, 32, h);
    memcpy(a, h, 32);
    a[0] &= 248; a[31] &= 127; a[31] |= 64;

    /* Positive control: R = [5]B, S = 5 + k a is an ordinary valid signature. */
    aienos_sig_basemult(Renc, r);
    forge_with_r(sig, Renc, r, a, pk, m, ml);
    CHECK(aienos_ed25519_verify(sig, m, ml, pk) == AIENOS_SIG_OK, "control signature");

    /* R = identity with S = k a satisfies [S]B = R + [k]A; must be refused. */
    uint8_t ident[32] = {1};
    forge_with_r(sig, ident, zero, a, pk, m, ml);
    CHECK(aienos_ed25519_verify(sig, m, ml, pk) == AIENOS_SIG_ERR_INVALID, "small-order R accepted");
    /* With an honest public key in the prime-order subgroup, [S]B - [k]A is always
     * in the prime-order subgroup and can only equal small-order R if R is the
     * identity point. For R != identity, [S]B - [k]A != R holds regardless of
     * the small-order guard. We verify all 8 small-order R values are rejected. */
    for (size_t i = 0; i < sizeof SMALL_ORDER / sizeof SMALL_ORDER[0]; i++) {
        uint8_t Rs[32];
        unhex_fixed(SMALL_ORDER[i], Rs, 32);
        forge_with_r(sig, Rs, zero, a, pk, m, ml);
        CHECK(aienos_ed25519_verify(sig, m, ml, pk) == AIENOS_SIG_ERR_INVALID, "small R %zu", i);
    }

    /* A small order: R = [r]B, S = r satisfies [S]B = R + [k]A when [k]A is
     * the identity. We find a message nonce for each small-order A such that
     * k mod 8 == 0, guaranteeing [k]A is the identity. Then the signature is
     * mathematically valid under [S]B - [k]A == R, so it is refused ONLY
     * by the small-order public-key check. */
    uint8_t s8[64];
    memcpy(s8, Renc, 32);
    memcpy(s8 + 32, r, 32);
    CHECK(aienos_ed25519_verify(s8, m, ml, ident) == AIENOS_SIG_ERR_INVALID, "identity A accepted");
    for (size_t i = 0; i < sizeof SMALL_ORDER / sizeof SMALL_ORDER[0]; i++) {
        uint8_t As[32];
        unhex_fixed(SMALL_ORDER[i], As, 32);
        uint8_t mi[sizeof m + 4];
        memcpy(mi, m, ml);
        int found = 0;
        for (uint32_t ctr = 0; ctr < 1000; ctr++) {
            mi[ml] = (uint8_t)ctr;
            mi[ml + 1] = (uint8_t)(ctr >> 8);
            mi[ml + 2] = (uint8_t)(ctr >> 16);
            mi[ml + 3] = (uint8_t)(ctr >> 24);
            uint8_t kh[64], ks[32];
            aienos_sha512_ctx c;
            aienos_sha512_init(&c);
            aienos_sha512_update(&c, Renc, 32);
            aienos_sha512_update(&c, As, 32);
            aienos_sha512_update(&c, mi, ml + 4);
            aienos_sha512_final(&c, kh);
            aienos_sig_sc_reduce(ks, kh);
            if ((ks[0] & 7) == 0) {
                CHECK(aienos_ed25519_verify(s8, mi, ml + 4, As) == AIENOS_SIG_ERR_INVALID, "small A %zu", i);
                found = 1;
                break;
            }
        }
        CHECK(found, "found k mod 8 == 0 for small A %zu", i);
    }

    /* Non-canonical R and A encodings (y >= p) are refused. */
    aienos_ed25519_sign(sig, m, ml, sk);
    for (int k = 0; k < 19; k++) {
        uint8_t bad[64], nc[32];
        memset(nc, 0xff, 32);
        nc[0] = (uint8_t)(0xed + k);
        nc[31] = 0x7f;
        memcpy(bad, sig, 64);
        memcpy(bad, nc, 32);
        CHECK(aienos_ed25519_verify(bad, m, ml, pk) == AIENOS_SIG_ERR_INVALID, "non-canonical R %d", k);
        CHECK(aienos_ed25519_verify(sig, m, ml, nc) == AIENOS_SIG_ERR_INVALID, "non-canonical A %d", k);
    }

    /* Argument checks. */
    CHECK(aienos_ed25519_sign(NULL, m, ml, sk) == AIENOS_SIG_ERR_ARG, "sign NULL sig");
    CHECK(aienos_ed25519_sign(sig, NULL, 1, sk) == AIENOS_SIG_ERR_ARG, "sign NULL msg");
    CHECK(aienos_ed25519_sign(sig, m, ml, NULL) == AIENOS_SIG_ERR_ARG, "sign NULL sk");
    CHECK(aienos_ed25519_verify(NULL, m, ml, pk) == AIENOS_SIG_ERR_ARG, "verify NULL sig");
    CHECK(aienos_ed25519_verify(sig, NULL, 1, pk) == AIENOS_SIG_ERR_ARG, "verify NULL msg");
    CHECK(aienos_ed25519_verify(sig, m, ml, NULL) == AIENOS_SIG_ERR_ARG, "verify NULL pk");
    CHECK(aienos_ed25519_public_key(NULL, sk) == AIENOS_SIG_ERR_ARG, "pk NULL");
    CHECK(aienos_ed25519_sign(sig, NULL, 0, sk) == AIENOS_SIG_OK, "sign empty NULL msg");
    CHECK(aienos_ed25519_verify(sig, NULL, 0, pk) == AIENOS_SIG_OK, "verify empty NULL msg");
}

/* ------------------------------------------------------------ round trips */

static void test_round_trips(int n)
{
    uint8_t sk[32], pk[32], sig[64], sig2[64], bad[64], m[300];
    int ok = 0;
    for (int i = 0; i < n; i++) {
        rnd_bytes(sk, 32);
        size_t ml = (size_t)(rnd() % sizeof m);
        rnd_bytes(m, ml);
        aienos_ed25519_public_key(pk, sk);
        aienos_ed25519_sign(sig, m, ml, sk);
        int good = aienos_ed25519_verify(sig, m, ml, pk) == AIENOS_SIG_OK;
        CHECK(good, "round trip %d", i);
        aienos_ed25519_sign(sig2, m, ml, sk);
        CHECK(memcmp(sig, sig2, 64) == 0, "deterministic %d", i);
        memcpy(bad, sig, 64);
        bad[rnd() % 64] ^= (uint8_t)(1u << (rnd() % 8));
        CHECK(aienos_ed25519_verify(bad, m, ml, pk) == AIENOS_SIG_ERR_INVALID, "random sig flip %d", i);
        if (ml > 0) {
            size_t j = (size_t)(rnd() % ml);
            m[j] ^= 0x10;
            CHECK(aienos_ed25519_verify(sig, m, ml, pk) == AIENOS_SIG_ERR_INVALID, "random msg flip %d", i);
            m[j] ^= 0x10;
        }
        ok += good;
    }
    /* Signing in place: the signature buffer overlaps the message. */
    uint8_t buf[100];
    rnd_bytes(buf, sizeof buf);
    rnd_bytes(sk, 32);
    uint8_t copy[100];
    memcpy(copy, buf, sizeof buf);
    aienos_ed25519_public_key(pk, sk);
    aienos_ed25519_sign(sig, copy, sizeof copy, sk);
    aienos_ed25519_sign(buf, buf, sizeof buf, sk);
    CHECK(memcmp(buf, sig, 64) == 0, "in-place sign");
    printf("round trips: %d/%d verified\n", ok, n);
}

int main(void)
{
    test_sha512();
    test_rfc_vectors();
    test_scalars();
    test_decoding();
    test_policy();
    test_round_trips(1000);
    printf("checks: %d, failures: %d\n", g_checks, g_fail);
    if (g_fail) {
        printf("AIENOS_SIG_NATIVE: FAIL\n");
        return 1;
    }
    printf("AIENOS_SIG_NATIVE: PASS\n");
    return 0;
}
