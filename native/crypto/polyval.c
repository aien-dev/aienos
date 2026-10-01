/* POLYVAL per RFC 8452 Section 3, port of crates/aienos-crypto/src/polyval.rs.
 *
 * Field GF(2^128) modulo x^128 + x^127 + x^126 + x^121 + 1, little-endian
 * bit order. Constant-time: dot() always runs 128 steps; each bit of a
 * selects b through a mask (behind an optimization barrier), never a branch
 * or a secret-dependent address.
 */
#include "aienos_crypto.h"
#include "crypto_internal.h"

static inline uint64_t load_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

static inline void store_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

void aienos_polyval_dot(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
    uint64_t a0 = load_le64(a), a1 = load_le64(a + 8);
    uint64_t b0 = load_le64(b), b1 = load_le64(b + 8);
    uint64_t v0 = 0, v1 = 0;

    for (int i = 0; i < 128; i++) {
        uint64_t bit = ((i < 64 ? a0 >> i : a1 >> (i - 64))) & 1u;
        AIENOS_CT_BARRIER(bit);
        uint64_t m = 0u - bit;
        v0 ^= b0 & m;
        v1 ^= b1 & m;

        /* v = v * x^-1: shift right one bit, fold x^-1 = 0xe1 << 120 if the
         * bit shifted out was set. */
        uint64_t lsb = v0 & 1u;
        AIENOS_CT_BARRIER(lsb);
        v0 = (v0 >> 1) | (v1 << 63);
        v1 = (v1 >> 1) ^ ((UINT64_C(0xe1) << 56) & (0u - lsb));
    }
    store_le64(out, v0);
    store_le64(out + 8, v1);
    /* a0..b1 are secret register copies; nothing to wipe in memory. */
}

void aienos_polyval_init(aienos_polyval *p, const uint8_t h[16])
{
    for (int i = 0; i < 16; i++) {
        p->h[i] = h[i];
        p->s[i] = 0;
    }
}

void aienos_polyval_update_block(aienos_polyval *p, const uint8_t x[16])
{
    for (int i = 0; i < 16; i++)
        p->s[i] ^= x[i];
    aienos_polyval_dot(p->s, p->s, p->h);
}

int aienos_polyval_update(aienos_polyval *p, const uint8_t *data, size_t len)
{
    if (len % 16 != 0 || (data == NULL && len != 0))
        return AIENOS_CRYPTO_ERR_LENGTH;
    for (size_t off = 0; off < len; off += 16)
        aienos_polyval_update_block(p, data + off);
    return AIENOS_CRYPTO_OK;
}

void aienos_polyval_final(aienos_polyval *p, uint8_t out[16])
{
    for (int i = 0; i < 16; i++)
        out[i] = p->s[i];
    aienos_polyval_wipe(p);
}

void aienos_polyval_wipe(aienos_polyval *p)
{
    aienos_wipe(p, sizeof *p);
}
