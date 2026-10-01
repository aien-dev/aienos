/* Internal helpers for native/m5. Not part of the API. */
#ifndef AIENOS_M5_INTERNAL_H
#define AIENOS_M5_INTERNAL_H

#include <stdint.h>
#include <string.h>

#include "../crypto/aienos_crypto.h"
#include "m5.h"

static inline void m5_put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void m5_put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static inline void m5_put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static inline uint16_t m5_get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t m5_get32(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)p[i] << (8 * i);
    return v;
}
static inline uint64_t m5_get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static inline int m5_all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}
static inline int m5_valid_class(uint8_t c) { return c == M5_ID_PRODUCTION || c == M5_ID_TEST; }

/* HMAC(key, domain || body) */
void m5_mac(const uint8_t key[32], const char *domain, size_t domain_len,
            const uint8_t *body, size_t body_len, uint8_t out[32]);

#endif
