/* Internal hooks for the test. Not public API. */
#ifndef AIENOS_SIG_INTERNAL_H
#define AIENOS_SIG_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/* Optimization barrier: the compiler must treat v as unknown, so a mask
 * cannot be turned back into a branch. */
#define AIENOS_SIG_BARRIER(v) __asm__ volatile("" : "+r"(v))

void aienos_sig_wipe(void *p, size_t n);
int aienos_sig_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

/* out = in mod L (in: 64 bytes little endian). */
void aienos_sig_sc_reduce(uint8_t out[32], const uint8_t in[64]);
/* out = (a * b + c) mod L (all little endian, a, b, c < 2^256). */
void aienos_sig_sc_muladd(uint8_t out[32], const uint8_t a[32], const uint8_t b[32],
                          const uint8_t c[32]);
/* out = encode([s]B), s any 32-byte little-endian scalar. */
void aienos_sig_basemult(uint8_t out[32], const uint8_t s[32]);
/* Decode a point. Returns -1 if decoding is refused, -2 if it decoded to a
 * point that is not on the curve (must never happen), else 0 and writes
 * the re-encoding to out and whether the point has small order to *small. */
int aienos_sig_decode_check(uint8_t out[32], int *small, const uint8_t in[32]);

#endif
