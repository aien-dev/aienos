/* Constant-time helpers: volatile wipe and equality. */
#include "aienos_crypto.h"
#include "crypto_internal.h"

void aienos_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++)
        v[i] = 0;
    __asm__ volatile("" : : "r"(p) : "memory");
}

int aienos_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint32_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint32_t)(a[i] ^ b[i]);
    AIENOS_CT_BARRIER(diff);
    /* (diff - 1) >> 31 is 1 iff diff == 0 (diff <= 0xff). */
    return (int)((diff - 1u) >> 31);
}
