/* Shared helpers for the native Store tests (hosted: libc allowed here). */
#ifndef STORE_TEST_UTIL_H
#define STORE_TEST_UTIL_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "store_engine.h"

static int g_checks __attribute__((unused)), g_failed __attribute__((unused));
#define CHECK(cond, ...)                                                              \
    do {                                                                              \
        g_checks++;                                                                   \
        if (!(cond)) {                                                                \
            g_failed++;                                                               \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                      \
            fprintf(stderr, __VA_ARGS__);                                             \
            fprintf(stderr, "\n");                                                    \
        }                                                                             \
    } while (0)
#define CHECK_EQ(got, want, what)                                                     \
    do {                                                                              \
        long long g_ = (long long)(got), w_ = (long long)(want);                      \
        CHECK(g_ == w_, "%s: got %lld (%s), want %lld (%s)", what, g_, st_strerror((int)g_), \
              w_, st_strerror((int)w_));                                              \
    } while (0)

static inline void to_hex(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

/* RAM-backed st_dev that records reads, writes and flushes and can be told
 * to fail one unit's read or write, or every flush (the Rust MemoryDevice). */
#define MEM_LOG 4096
typedef struct {
    uint8_t (*units)[SV1_UNIT];
    uint64_t n;
    uint64_t reads[MEM_LOG], writes[MEM_LOG];
    size_t nreads, nwrites;
    unsigned flushes;
    int64_t fail_read, fail_write;
    int fail_flush;
} memdev;

static int mem_read(void *ctx, uint64_t u, uint8_t out[SV1_UNIT])
{
    memdev *m = ctx;
    if (m->nreads < MEM_LOG)
        m->reads[m->nreads++] = u;
    if ((int64_t)u == m->fail_read || u >= m->n)
        return -1;
    memcpy(out, m->units[u], SV1_UNIT);
    return 0;
}
static int mem_write(void *ctx, uint64_t u, const uint8_t in[SV1_UNIT])
{
    memdev *m = ctx;
    if (m->nwrites < MEM_LOG)
        m->writes[m->nwrites++] = u;
    if ((int64_t)u == m->fail_write || u >= m->n)
        return -1;
    memcpy(m->units[u], in, SV1_UNIT);
    return 0;
}
static int mem_flush(void *ctx)
{
    memdev *m = ctx;
    m->flushes++;
    return m->fail_flush ? -1 : 0;
}
static inline void mem_init(memdev *m, uint64_t n)
{
    memset(m, 0, sizeof *m);
    m->units = calloc((size_t)n, SV1_UNIT);
    if (!m->units) {
        perror("calloc");
        exit(2);
    }
    m->n = n;
    m->fail_read = m->fail_write = -1;
}
static inline void mem_free(memdev *m)
{
    free(m->units);
    m->units = NULL;
}
static inline void mem_clear_log(memdev *m)
{
    m->nreads = m->nwrites = 0;
    m->flushes = 0;
}
static inline void mem_clone(memdev *dst, const memdev *src)
{
    mem_init(dst, src->n);
    memcpy(dst->units, src->units, (size_t)src->n * SV1_UNIT);
}
static inline st_dev mem_dev(memdev *m)
{
    st_dev d = {m, m->n, mem_read, mem_write, mem_flush};
    return d;
}
static inline void rechecksum(uint8_t *u)
{
    memset(u + SV1_SB_CRC_OFFSET, 0, 4);
    sv1_put32(u + SV1_SB_CRC_OFFSET, sv1_crc32c(u, SV1_UNIT));
}

#endif
