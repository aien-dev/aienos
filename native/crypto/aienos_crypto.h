/* AIENOS in-house crypto primitives, C port of crates/aienos-crypto.
 *
 * AES-256 (FIPS 197), POLYVAL and AEAD_AES_256_GCM_SIV (RFC 8452), and
 * HMAC-SHA-256 over the in-house SHA-256 in native/argus/sha256.c.
 * No heap, no clock, no I/O. Secret scratch is wiped before returning.
 */
#ifndef AIENOS_CRYPTO_H
#define AIENOS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "../argus/sha256.h"

#define AIENOS_AES256_KEY_LEN 32
#define AIENOS_AES_BLOCK_LEN 16
#define AIENOS_POLYVAL_BLOCK_LEN 16
#define AIENOS_GCMSIV_KEY_LEN 32
#define AIENOS_GCMSIV_NONCE_LEN 12
#define AIENOS_GCMSIV_TAG_LEN 16

/* RFC 8452 Section 6: P_MAX = A_MAX = 2^36 bytes, C_MAX = 2^36 + 16. */
#define AIENOS_GCMSIV_MAX_PT_LEN (UINT64_C(1) << 36)
#define AIENOS_GCMSIV_MAX_AAD_LEN (UINT64_C(1) << 36)
#define AIENOS_GCMSIV_MAX_CT_LEN (AIENOS_GCMSIV_MAX_PT_LEN + AIENOS_GCMSIV_TAG_LEN)

/* Return codes. */
#define AIENOS_CRYPTO_OK 0
#define AIENOS_CRYPTO_ERR_LENGTH (-1) /* bad/oversize length, size mismatch or NULL buffer */
#define AIENOS_CRYPTO_ERR_AUTH (-2)   /* tag did not verify */

/* ---- AES-256 (encrypt direction only; GCM-SIV never decrypts a block) ---- */

typedef struct {
    uint32_t rk[60]; /* 15 round keys, big-endian words as in FIPS 197 */
} aienos_aes256_key;

void aienos_aes256_init(aienos_aes256_key *k, const uint8_t key[AIENOS_AES256_KEY_LEN]);
/* Encrypt one block in place. Constant-time: computed S-box, no tables. */
void aienos_aes256_encrypt_block(const aienos_aes256_key *k, uint8_t block[AIENOS_AES_BLOCK_LEN]);
/* Zero the key schedule (volatile writes). Call when done with the key. */
void aienos_aes256_wipe(aienos_aes256_key *k);

/* ---- POLYVAL (RFC 8452 Section 3) ---- */

typedef struct {
    uint8_t h[16]; /* hash key H */
    uint8_t s[16]; /* accumulator S_j */
} aienos_polyval;

/* out = dot(a, b) = a * b * x^-128 mod x^128 + x^127 + x^126 + x^121 + 1.
 * out may alias a or b. */
void aienos_polyval_dot(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);
void aienos_polyval_init(aienos_polyval *p, const uint8_t h[16]);
/* S = dot(S ^ X, H). */
void aienos_polyval_update_block(aienos_polyval *p, const uint8_t x[16]);
/* Whole 16-byte blocks only: returns AIENOS_CRYPTO_ERR_LENGTH (and absorbs
 * nothing) if len is not a multiple of 16. */
int aienos_polyval_update(aienos_polyval *p, const uint8_t *data, size_t len);
/* Write S to out and wipe the state. */
void aienos_polyval_final(aienos_polyval *p, uint8_t out[16]);
void aienos_polyval_wipe(aienos_polyval *p);

/* ---- AEAD_AES_256_GCM_SIV (RFC 8452) ---- */

/* Per-nonce key derivation (RFC 8452 Section 4). Exposed for tests and
 * callers that need it; the outputs are secret, wipe them after use. */
void aienos_gcmsiv_derive_keys(const uint8_t key[AIENOS_GCMSIV_KEY_LEN],
                               const uint8_t nonce[AIENOS_GCMSIV_NONCE_LEN],
                               uint8_t auth_key[16], uint8_t enc_key[32]);

/* Seal: out = ciphertext || tag, out_len must equal pt_len + 16.
 * Limits: pt_len <= 2^36, aad_len <= 2^36. A NULL pointer is allowed only
 * with a zero length. out may be exactly pt (in place); any other overlap is
 * undefined. Length errors return AIENOS_CRYPTO_ERR_LENGTH before
 * anything is read or written. */
int aienos_gcmsiv_seal(const uint8_t key[AIENOS_GCMSIV_KEY_LEN],
                       const uint8_t nonce[AIENOS_GCMSIV_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *out, size_t out_len);

/* Open: in = ciphertext || tag (in_len >= 16, in_len <= 2^36 + 16),
 * out_len must equal in_len - 16, aad_len <= 2^36.
 *
 * RFC 8452 computes the tag over the plaintext, so the plaintext must exist
 * before the tag can be checked. This function decrypts into out, computes
 * the expected tag over out, compares tags in constant time, and on a
 * mismatch zeroes all of out[0..out_len) with volatile writes before
 * returning AIENOS_CRYPTO_ERR_AUTH. Length errors return
 * AIENOS_CRYPTO_ERR_LENGTH before anything is read or written, so out then
 * holds whatever the caller put there (never plaintext). out may be
 * exactly in (in place); then a failed open zeroes the ciphertext too.
 * Any other overlap is undefined. */
int aienos_gcmsiv_open(const uint8_t key[AIENOS_GCMSIV_KEY_LEN],
                       const uint8_t nonce[AIENOS_GCMSIV_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_len);

/* ---- HMAC-SHA-256 with a 32-byte key (port of sha256.rs hmac_sha256) ---- */

typedef struct {
    sha256_ctx inner;
    uint8_t opad[64];
} aienos_hmac_sha256_ctx;

void aienos_hmac_sha256_init(aienos_hmac_sha256_ctx *c, const uint8_t key[32]);
void aienos_hmac_sha256_update(aienos_hmac_sha256_ctx *c, const uint8_t *data, size_t len);
/* Writes the MAC and wipes the context. */
void aienos_hmac_sha256_final(aienos_hmac_sha256_ctx *c, uint8_t out[32]);
void aienos_hmac_sha256(const uint8_t key[32], const uint8_t *data, size_t len, uint8_t out[32]);

/* Constant-time equality of two n-byte buffers: 1 if equal, 0 if not.
 * Run time depends only on n. */
int aienos_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

/* Zero n bytes with volatile writes the optimizer cannot drop. */
void aienos_wipe(void *p, size_t n);

#endif /* AIENOS_CRYPTO_H */
