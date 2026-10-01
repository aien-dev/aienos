/* AIENOS X25519 (RFC 7748 Section 5), in C. No heap, clock or I/O.
 *
 * Why native/net and not native/sig: X25519 is only used here, for the M6-B
 * handshake's ephemeral key agreement. native/sig is signatures (Ed25519 +
 * SHA-512) owned by another lane; keeping X25519 next to its one caller
 * avoids touching that tree. The field code is separate from ed25519.c on
 * purpose (no shared internal header across lanes); if a second caller
 * appears, move it to its own native/ecdh directory.
 *
 * Constant time with respect to the scalar: a fixed 255-step Montgomery
 * ladder with masked conditional swaps, no secret-dependent branches or
 * table indexes. Spot-checked by reading the AArch64 -O2 code, not measured.
 */
#ifndef AIENOS_X25519_H
#define AIENOS_X25519_H

#include <stdint.h>

#define AIENOS_X25519_LEN 32

/* out = X25519(scalar, u) per RFC 7748: the scalar is clamped and the top
 * bit of u is masked, exactly as the RFC says. Always writes out. Returns 0
 * normally, or -1 if out is the all-zero value (u was a small-order point);
 * callers doing key agreement must refuse that case. out may alias u. */
int aienos_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]);

/* out = X25519(scalar, 9): the public key for a secret scalar. */
void aienos_x25519_base(uint8_t out[32], const uint8_t scalar[32]);

#endif
