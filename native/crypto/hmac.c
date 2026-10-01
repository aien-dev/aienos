/* HMAC-SHA-256 with a 32-byte key, port of sha256.rs hmac_sha256.
 * SHA-256 itself is the in-house native/argus/sha256.c. */
#include "aienos_crypto.h"

void aienos_hmac_sha256_init(aienos_hmac_sha256_ctx *c, const uint8_t key[32])
{
    uint8_t ipad[64];
    for (int i = 0; i < 64; i++) {
        uint8_t k = i < 32 ? key[i] : 0;
        ipad[i] = (uint8_t)(0x36 ^ k);
        c->opad[i] = (uint8_t)(0x5c ^ k);
    }
    sha256_init(&c->inner);
    sha256_update(&c->inner, ipad, sizeof ipad);
    aienos_wipe(ipad, sizeof ipad);
}

void aienos_hmac_sha256_update(aienos_hmac_sha256_ctx *c, const uint8_t *data, size_t len)
{
    if (len != 0)
        sha256_update(&c->inner, data, len);
}

void aienos_hmac_sha256_final(aienos_hmac_sha256_ctx *c, uint8_t out[32])
{
    uint8_t inner_digest[32];
    sha256_ctx outer;
    sha256_final(&c->inner, inner_digest);
    sha256_init(&outer);
    sha256_update(&outer, c->opad, sizeof c->opad);
    sha256_update(&outer, inner_digest, sizeof inner_digest);
    sha256_final(&outer, out);
    aienos_wipe(inner_digest, sizeof inner_digest);
    aienos_wipe(&outer, sizeof outer);
    aienos_wipe(c, sizeof *c);
}

void aienos_hmac_sha256(const uint8_t key[32], const uint8_t *data, size_t len, uint8_t out[32])
{
    aienos_hmac_sha256_ctx c;
    aienos_hmac_sha256_init(&c, key);
    aienos_hmac_sha256_update(&c, data, len);
    aienos_hmac_sha256_final(&c, out);
}
