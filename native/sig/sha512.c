/* SHA-512 (FIPS 180-4). Round constants K are the FIPS 180-4 Section 4.2.3
 * values. Lines tagged GUARD:<name> are removed one at a time by
 * `make mutants`; the tests must fail for each. */
#include <string.h>

#include "aienos_sig.h"
#include "sig_internal.h"

static const uint64_t K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint64_t load_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

static void store_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static void compress(uint64_t h[8], const uint8_t blk[128])
{
    uint64_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = load_be64(blk + 8 * i);
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROR(w[i - 15], 1) ^ ROR(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR(w[i - 2], 19) ^ ROR(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ROR(e, 14) ^ ROR(e, 18) ^ ROR(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = hh + S1 + ch + K[i] + w[i];
        uint64_t S0 = ROR(a, 28) ^ ROR(a, 34) ^ ROR(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    aienos_sig_wipe(w, sizeof w);
}

void aienos_sha512_init(aienos_sha512_ctx *c)
{
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    };
    for (int i = 0; i < 8; i++)
        c->h[i] = iv[i];
    c->bytes = 0;
    c->n = 0;
}

void aienos_sha512_update(aienos_sha512_ctx *c, const uint8_t *p, size_t len)
{
    if (len == 0)
        return;
    c->bytes += (uint64_t)len;
    if (c->n > 0) {
        size_t take = 128 - c->n;
        if (take > len)
            take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take;
        p += take;
        len -= take;
        if (c->n < 128)
            return;
        compress(c->h, c->buf);
        c->n = 0;
    }
    while (len >= 128) {
        compress(c->h, p);
        p += 128;
        len -= 128;
    }
    if (len > 0) {
        memcpy(c->buf, p, len);
        c->n = len;
    }
}

void aienos_sha512_final(aienos_sha512_ctx *c, uint8_t out[64])
{
    uint64_t bits_hi = c->bytes >> 61, bits_lo = c->bytes << 3;
    size_t n = c->n;
    c->buf[n++] = 0x80; /* GUARD:sha-pad */
    if (n > 112) {
        memset(c->buf + n, 0, 128 - n);
        compress(c->h, c->buf);
        n = 0;
    }
    memset(c->buf + n, 0, 112 - n);
    store_be64(c->buf + 112, bits_hi);
    store_be64(c->buf + 120, bits_lo); /* GUARD:sha-len */
    compress(c->h, c->buf);
    for (int i = 0; i < 8; i++)
        store_be64(out + 8 * i, c->h[i]);
    aienos_sig_wipe(c, sizeof *c);
}

void aienos_sha512(const uint8_t *p, size_t len, uint8_t out[64])
{
    aienos_sha512_ctx c;
    aienos_sha512_init(&c);
    aienos_sha512_update(&c, p, len);
    aienos_sha512_final(&c, out);
}
