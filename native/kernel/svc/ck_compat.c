/* ck_compat.c -- kernel-build implementations behind the svc/compat headers and the
 * four memory routines GCC may emit calls to. Freestanding; ck.h only.
 * Not linked into the host tests (they use libc). */
#include <stddef.h>
#include <stdint.h>
#include "ck.h"
#include "ck_compat.h"
#include "compat/pthread.h"
#include "compat/stdio.h"
#include "compat/time.h"
#include "sha256.h"

/* ---- memory routines: weak, so a core copy wins at link time ---------- */
__attribute__((weak)) void *memcpy(void *restrict d, const void *restrict s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    while (n--) *a++ = *b++;
    return d;
}
__attribute__((weak)) void *memmove(void *d, const void *s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    if (a < b) {
        while (n--) *a++ = *b++;
    } else {
        while (n--) a[n] = b[n];
    }
    return d;
}
__attribute__((weak)) void *memset(void *d, int c, size_t n)
{
    unsigned char *a = d;
    while (n--) *a++ = (unsigned char)c;
    return d;
}
__attribute__((weak)) int memcmp(const void *x, const void *y, size_t n)
{
    const unsigned char *a = x, *b = y;
    for (; n; n--, a++, b++)
        if (*a != *b) return *a < *b ? -1 : 1;
    return 0;
}

/* ---- heap, clock, lock ------------------------------------------------- */
void *ck_compat_malloc(size_t n) { return ck_alloc(n ? n : 1); }
void *ck_compat_calloc(size_t n, size_t sz)
{
    if (sz && n > (size_t)-1 / sz) return 0;
    size_t total = n * sz;
    return ck_alloc(total ? total : 1); /* ck_alloc memory is zeroed (ck.h) */
}
void ck_compat_free(void *p)
{
    if (p) ck_free(p);
}
int ck_compat_clock_gettime(clockid_t id, struct timespec *ts)
{
    (void)id;
    if (!ts) return -1;
    uint64_t us = ck_time_us();
    ts->tv_sec = (time_t)(us / 1000000u);
    ts->tv_nsec = (long)((us % 1000000u) * 1000u);
    return 0;
}
void ck_compat_mutex_lock(pthread_mutex_t *m)
{
    if (m->locked) ck_panic("ck_compat: mutex re-entered (single-core stage code)");
    m->locked = 1;
}

/* ---- entropy for "/dev/urandom" --------------------------------------- */
static int g_entropy = CK_ENTROPY_NONE;
int ck_compat_entropy_source(void) { return g_entropy; }

#if defined(__aarch64__)
static int have_rndr(void)
{
    uint64_t isar0;
    __asm__ volatile("mrs %0, id_aa64isar0_el1" : "=r"(isar0));
    return ((isar0 >> 60) & 0xfu) >= 1u;
}
static int rndr(uint64_t *out)
{
    uint64_t v, nzcv;
    __asm__ volatile("mrs %0, s3_3_c2_c4_0\n\tmrs %1, nzcv" : "=r"(v), "=r"(nzcv)::"cc");
    *out = v;
    return (nzcv & (1ull << 30)) == 0; /* Z set = failure */
}
static uint64_t cntvct(void)
{
    uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v));
    return v;
}
#else
static int have_rndr(void) { return 0; }
static int rndr(uint64_t *out) { *out = 0; return 0; }
static uint64_t cntvct(void) { return ck_time_us(); }
#endif

static void fill_entropy(uint8_t *buf, size_t len)
{
    size_t i = 0;
    if (have_rndr()) {
        while (i < len) {
            uint64_t v;
            int tries = 0;
            while (!rndr(&v)) {
                if (++tries > 64) goto fallback;
            }
            for (int k = 0; k < 8 && i < len; k++) buf[i++] = (uint8_t)(v >> (8 * k));
        }
        g_entropy = CK_ENTROPY_RNDR;
        return;
    }
fallback:
    /* Timer jitter: hash 256 counter samples taken around short delays.
     * WEAK: an observer of boot timing could narrow it down. */
    {
        uint64_t s[256];
        for (int k = 0; k < 256; k++) {
            s[k] = cntvct() ^ (ck_time_us() << 17);
            ck_udelay((uint32_t)(s[k] & 3u) + 1u);
        }
        uint8_t d[32];
        sha256_hash((const uint8_t *)s, sizeof s, d);
        for (i = 0; i < len; i++) buf[i] = d[i % 32] ^ (uint8_t)(i * 151u);
        g_entropy = CK_ENTROPY_TIMER_WEAK;
    }
}

struct ck_compat_file { int open; };
static struct ck_compat_file urandom_file;

FILE *ck_compat_fopen(const char *path, const char *mode)
{
    (void)mode;
    const char *want = "/dev/urandom";
    for (int i = 0;; i++) {
        if (path[i] != want[i]) return 0;
        if (!want[i]) break;
    }
    urandom_file.open = 1;
    return &urandom_file;
}
size_t ck_compat_fread(void *buf, size_t sz, size_t n, FILE *f)
{
    if (!f || !f->open || sz == 0 || n == 0 || n > (size_t)-1 / sz) return 0;
    fill_entropy(buf, sz * n);
    return n;
}
int ck_compat_fclose(FILE *f)
{
    if (f) f->open = 0;
    return 0;
}
