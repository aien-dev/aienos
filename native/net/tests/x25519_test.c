/* X25519 tests: RFC 7748 Section 5.2 vectors (both single vectors, the
 * 1-iteration and 1,000-iteration checks; 1,000,000 with X25519_LONG=1) and
 * the Section 6.1 Diffie-Hellman vector, copied verbatim from the RFC text
 * (https://www.rfc-editor.org/rfc/rfc7748.txt, file sha256
 * 279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3), plus
 * small-order refusal, u top-bit masking, non-canonical u and DH symmetry.
 * Prints X25519_RFC7748: PASS or FAIL. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../x25519.h"

static unsigned long checks, failures;
#define CHECK(c, ...) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

static void hex(uint8_t *o, const char *h)
{
    for (size_t i = 0; i < 32; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); o[i] = (uint8_t)v; }
}

static int eqhex(const uint8_t *b, const char *h)
{
    uint8_t t[32];
    hex(t, h);
    return memcmp(b, t, 32) == 0;
}

/* RFC 7748 Section 5.2 */
static const char *V[2][3] = {
    {"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
    {"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"},
};
static const char *ITER1 = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";
static const char *ITER1000 = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51";
static const char *ITER1M = "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424";
/* RFC 7748 Section 6.1 */
static const char *ALICE_SK = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char *ALICE_PK = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
static const char *BOB_SK = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
static const char *BOB_PK = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static const char *SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

int main(void)
{
    uint8_t k[32], u[32], o[32], t[32];
    for (int i = 0; i < 2; i++) {
        hex(k, V[i][0]); hex(u, V[i][1]);
        CHECK(aienos_x25519(o, k, u) == 0, "vector %d status", i);
        CHECK(eqhex(o, V[i][2]), "RFC 7748 5.2 vector %d", i);
        /* aliasing out == u */
        memcpy(t, u, 32);
        aienos_x25519(t, k, t);
        CHECK(memcmp(t, o, 32) == 0, "aliased vector %d", i);
    }
    /* iterated: k = X25519(k, u), u = old k */
    memset(k, 0, 32); k[0] = 9;
    memcpy(u, k, 32);
    long n = getenv("X25519_LONG") ? 1000000 : 1000;
    for (long it = 1; it <= n; it++) {
        aienos_x25519(o, k, u);
        memcpy(u, k, 32);
        memcpy(k, o, 32);
        if (it == 1) CHECK(eqhex(k, ITER1), "after 1 iteration");
        if (it == 1000) CHECK(eqhex(k, ITER1000), "after 1000 iterations");
        if (it == 1000000) CHECK(eqhex(k, ITER1M), "after 1000000 iterations");
    }
    /* Diffie-Hellman */
    uint8_t ask[32], bsk[32], apk[32], bpk[32], s1[32], s2[32];
    hex(ask, ALICE_SK); hex(bsk, BOB_SK);
    aienos_x25519_base(apk, ask);
    aienos_x25519_base(bpk, bsk);
    CHECK(eqhex(apk, ALICE_PK), "alice pk");
    CHECK(eqhex(bpk, BOB_PK), "bob pk");
    CHECK(aienos_x25519(s1, ask, bpk) == 0 && eqhex(s1, SHARED), "alice shared");
    CHECK(aienos_x25519(s2, bsk, apk) == 0 && eqhex(s2, SHARED), "bob shared");
    /* small-order inputs give all-zero output and status -1: u = 0, 1,
     * p-1 (order 2/4 points of the curve and twist), p, p+1 (non-canonical
     * encodings of 0 and 1) and the two order-8 points. */
    static const char *SMALL[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    };
    for (size_t i = 0; i < sizeof SMALL / sizeof SMALL[0]; i++) {
        hex(u, SMALL[i]);
        int r = aienos_x25519(o, ask, u);
        uint8_t acc = 0;
        for (int j = 0; j < 32; j++) acc |= o[j];
        CHECK(r == -1 && acc == 0, "small-order input %zu refused (r=%d)", i, r);
    }
    /* top bit of u is ignored (RFC 7748 Section 5) */
    hex(u, V[0][1]); hex(k, V[0][0]);
    aienos_x25519(t, k, u);
    u[31] ^= 0x80;
    aienos_x25519(o, k, u);
    CHECK(memcmp(o, t, 32) == 0, "u top bit masked");
    /* non-canonical u = p + 9 must act as u = 9 */
    static const char *P9 = "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
    hex(u, P9);
    aienos_x25519(o, ask, u);
    CHECK(eqhex(o, ALICE_PK), "u = p + 9 equals u = 9");
    /* DH symmetry on a deterministic family */
    uint8_t x[32], y[32];
    uint64_t s = 0x7748;
    for (int it = 0; it < 64; it++) {
        for (int j = 0; j < 32; j++) { s = s * 6364136223846793005ULL + 1442695040888963407ULL; x[j] = (uint8_t)(s >> 56); }
        for (int j = 0; j < 32; j++) { s = s * 6364136223846793005ULL + 1442695040888963407ULL; y[j] = (uint8_t)(s >> 56); }
        aienos_x25519_base(apk, x);
        aienos_x25519_base(bpk, y);
        aienos_x25519(s1, x, bpk);
        aienos_x25519(s2, y, apk);
        CHECK(memcmp(s1, s2, 32) == 0, "DH symmetry %d", it);
        /* clamping: low 3 bits and bit 255 of the scalar do not matter */
        memcpy(t, x, 32); t[0] ^= 7; t[31] ^= 0x80;
        aienos_x25519_base(o, t);
        CHECK(memcmp(o, apk, 32) == 0, "clamp-equivalent scalar %d", it);
    }
    printf("X25519_RFC7748: %s (%lu checks, %lu failures, %ld iterations)\n",
           failures ? "FAIL" : "PASS", checks, failures, n);
    return failures ? 1 : 0;
}
