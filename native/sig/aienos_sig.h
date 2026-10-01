/* AIENOS in-house signatures in C: Ed25519 (RFC 8032 Section 5.1, pure
 * Ed25519 only: no Ed25519ph, no Ed25519ctx) and SHA-512 (FIPS 180-4).
 *
 * No heap, no clock, no I/O. Signing and public-key derivation are written
 * to run in constant time with respect to the secret key and the nonce.
 * Verification handles only public data and is NOT constant time.
 */
#ifndef AIENOS_SIG_H
#define AIENOS_SIG_H

#include <stddef.h>
#include <stdint.h>

#define AIENOS_SIG_OK 0
#define AIENOS_SIG_ERR_INVALID (-1) /* signature or public key rejected */
#define AIENOS_SIG_ERR_ARG (-2)     /* NULL buffer */

#define AIENOS_ED25519_SECRET_KEY_LEN 32
#define AIENOS_ED25519_PUBLIC_KEY_LEN 32
#define AIENOS_ED25519_SIGNATURE_LEN 64

/* SHA-512 */
#define AIENOS_SHA512_DIGEST_LEN 64
typedef struct {
    uint64_t h[8];
    uint64_t bytes;   /* total bytes absorbed (messages up to 2^64 - 1 bytes) */
    uint8_t buf[128];
    size_t n;         /* bytes waiting in buf */
} aienos_sha512_ctx;

void aienos_sha512_init(aienos_sha512_ctx *c);
void aienos_sha512_update(aienos_sha512_ctx *c, const uint8_t *p, size_t len);
/* Writes the digest and wipes the context. */
void aienos_sha512_final(aienos_sha512_ctx *c, uint8_t out[AIENOS_SHA512_DIGEST_LEN]);
void aienos_sha512(const uint8_t *p, size_t len, uint8_t out[AIENOS_SHA512_DIGEST_LEN]);

/* Ed25519. sk is the 32-byte RFC 8032 secret key (seed). */
int aienos_ed25519_public_key(uint8_t pk[32], const uint8_t sk[32]);

/* Derives the public key from sk itself (no caller-supplied public key, so
 * a mismatched pair cannot leak the key). msg may be NULL when msg_len is 0.
 * sig may overlap msg. */
int aienos_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                        const uint8_t sk[32]);

/* Returns AIENOS_SIG_OK only if sig is a valid signature of msg under pk.
 * Rejects (AIENOS_SIG_ERR_INVALID): S >= L, a non-canonical or off-curve
 * encoding of A or R, x = 0 with the sign bit set, and A or R of small order
 * (order dividing 8). Equation checked: encode([S]B - [k]A) == R bytes
 * (cofactorless, RFC 8032 Section 5.1.7 without the optional factor 8). */
int aienos_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                          const uint8_t pk[32]);

#endif
