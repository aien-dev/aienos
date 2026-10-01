/* AES-256 block encryption per FIPS 197, port of crates/aienos-crypto/src/aes.rs.
 *
 * Constant-time design: the S-box is computed, not looked up. Each byte is
 * inverted in GF(2^8) as x^254 (0 maps to 0) and passed through the FIPS 197
 * affine transform. All arithmetic is shifts, masks and XORs with a fixed
 * number of steps, 8 bytes packed per uint64_t ("SIMD within a register"),
 * so no memory address and no branch depends on key or data bytes.
 * Slower than table AES; ARMv8 AESE/AESMC are a possible future speedup.
 */
#include "aienos_crypto.h"
#include "crypto_internal.h"

static const uint32_t RCON[10] = {
    0x01000000u, 0x02000000u, 0x04000000u, 0x08000000u, 0x10000000u,
    0x20000000u, 0x40000000u, 0x80000000u, 0x1b000000u, 0x36000000u,
};

#define LANES(m) ((uint64_t)(m) * UINT64_C(0x0101010101010101))
#define LSB LANES(0x01)
#define LOW7 LANES(0x7f)

/* 0/1 per lane -> 0x00/0xff per lane. (b << 8) - b == b * 0xff lane by lane:
 * no carry or borrow crosses lanes, and it holds mod 2^64 for the top lane. */
static inline uint64_t lane_mask(uint64_t bits)
{
    return (bits << 8) - bits;
}

/* Multiply every lane by x in GF(2^8), branch-free. */
static inline uint64_t xtime_lanes(uint64_t a)
{
    uint64_t hi = (a >> 7) & LSB;
    uint64_t reduce = hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4); /* hi * 0x1b */
    return ((a & LOW7) << 1) ^ reduce;
}

/* Lane-wise GF(2^8) multiply modulo x^8 + x^4 + x^3 + x + 1; always 8 steps. */
static inline uint64_t gf_mul_lanes(uint64_t a, uint64_t b)
{
    uint64_t acc = 0;
    for (int i = 0; i < 8; i++) {
        acc ^= a & lane_mask((b >> i) & LSB);
        a = xtime_lanes(a);
    }
    return acc;
}

/* Rotate each byte lane left by k (1..7). */
static inline uint64_t rotl_lanes(uint64_t x, unsigned k)
{
    uint64_t hi = LANES((uint8_t)(0xffu << k));
    uint64_t lo = LANES(0xffu >> (8 - k));
    return ((x << k) & hi) | ((x >> (8 - k)) & lo);
}

/* S(b) = Affine(b^254) on 8 lanes; fixed addition chain of 11 multiplies. */
static uint64_t sub_lanes(uint64_t x)
{
    uint64_t x2 = gf_mul_lanes(x, x);
    uint64_t x3 = gf_mul_lanes(x2, x);
    uint64_t x6 = gf_mul_lanes(x3, x3);
    uint64_t x12 = gf_mul_lanes(x6, x6);
    uint64_t x15 = gf_mul_lanes(x12, x3);
    uint64_t x30 = gf_mul_lanes(x15, x15);
    uint64_t x60 = gf_mul_lanes(x30, x30);
    uint64_t x120 = gf_mul_lanes(x60, x60);
    uint64_t x240 = gf_mul_lanes(x120, x120);
    uint64_t x252 = gf_mul_lanes(x240, x12);
    uint64_t inv = gf_mul_lanes(x252, x2);
    return inv ^ rotl_lanes(inv, 1) ^ rotl_lanes(inv, 2) ^ rotl_lanes(inv, 3) ^
           rotl_lanes(inv, 4) ^ LANES(0x63);
}

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

void aienos_aes_sub_bytes16(uint8_t s[16])
{
    store_le64(s, sub_lanes(load_le64(s)));
    store_le64(s + 8, sub_lanes(load_le64(s + 8)));
}

static uint32_t sub_word(uint32_t w)
{
    return (uint32_t)sub_lanes(w);
}

static inline uint32_t rot_word(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

static inline uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (0x1bu & (0u - (unsigned)(x >> 7))));
}

void aienos_aes256_init(aienos_aes256_key *k, const uint8_t key[32])
{
    uint32_t *rk = k->rk;
    for (int i = 0; i < 8; i++)
        rk[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
                ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];
    /* i % 8 depends only on the public loop index. */
    for (int i = 8; i < 60; i++) {
        uint32_t t = rk[i - 1];
        if (i % 8 == 0)
            t = sub_word(rot_word(t)) ^ RCON[i / 8 - 1];
        else if (i % 8 == 4)
            t = sub_word(t);
        rk[i] = rk[i - 8] ^ t;
    }
}

void aienos_aes256_wipe(aienos_aes256_key *k)
{
    aienos_wipe(k->rk, sizeof k->rk);
}

static inline void add_round_key(uint8_t s[16], const uint32_t *rk)
{
    for (int c = 0; c < 4; c++) {
        s[4 * c] ^= (uint8_t)(rk[c] >> 24);
        s[4 * c + 1] ^= (uint8_t)(rk[c] >> 16);
        s[4 * c + 2] ^= (uint8_t)(rk[c] >> 8);
        s[4 * c + 3] ^= (uint8_t)rk[c];
    }
}

/* State is column-major: s[r + 4c]. Row r rotates left by r. */
static inline void shift_rows(uint8_t s[16])
{
    uint8_t t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static inline void mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t *p = s + 4 * c;
        uint8_t s0 = p[0], s1 = p[1], s2 = p[2], s3 = p[3];
        uint8_t h0 = xtime(s0), h1 = xtime(s1), h2 = xtime(s2), h3 = xtime(s3);
        p[0] = h0 ^ s1 ^ h1 ^ s2 ^ s3;
        p[1] = s0 ^ h1 ^ s2 ^ h2 ^ s3;
        p[2] = s0 ^ s1 ^ h2 ^ s3 ^ h3;
        p[3] = s0 ^ h0 ^ s1 ^ s2 ^ h3;
    }
}

/* Works directly on the caller's block: no state copy left on the stack. */
void aienos_aes256_encrypt_block(const aienos_aes256_key *k, uint8_t block[16])
{
    add_round_key(block, &k->rk[0]);
    for (int round = 1; round < 14; round++) {
        aienos_aes_sub_bytes16(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &k->rk[4 * round]);
    }
    aienos_aes_sub_bytes16(block);
    shift_rows(block);
    add_round_key(block, &k->rk[56]);
}
