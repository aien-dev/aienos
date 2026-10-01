/* Internal hooks shared by the library objects and the test. Not public API. */
#ifndef AIENOS_CRYPTO_INTERNAL_H
#define AIENOS_CRYPTO_INTERNAL_H

#include <stdint.h>

/* Constant-time AES S-box on all 16 bytes of s, in place. */
void aienos_aes_sub_bytes16(uint8_t s[16]);

/* Optimization barrier: the compiler must treat v as unknown, so a 0/1
 * value cannot be turned back into a branch. */
#define AIENOS_CT_BARRIER(v) __asm__ volatile("" : "+r"(v))

#endif
