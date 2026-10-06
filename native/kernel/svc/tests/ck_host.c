/* ck_host.c -- host implementation of the ck.h services for the stage host
 * tests (malloc + stdio). Hosted test code only; never in the image.
 * Identity "mapping": ck_mmio_map returns the address it is given, so a
 * test hands MCFG an aligned heap buffer as the fake ECAM. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "ck.h"
#include "ck_compat.h"
#include "ck_host.h"

const void *ck_host_mcfg;
int ck_host_quiet;

void ck_puts(const char *s)
{
    if (!ck_host_quiet) fputs(s, stdout);
}
void ck_vprintf(const char *fmt, va_list ap)
{
    if (!ck_host_quiet) vprintf(fmt, ap);
}
void ck_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ck_vprintf(fmt, ap);
    va_end(ap);
}
void ck_panic(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("ck_panic: ", stdout);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
    abort();
}
void *ck_alloc(size_t bytes) { return calloc(1, bytes ? bytes : 1); }
void ck_free(void *p) { free(p); }
void *ck_dma_alloc(size_t bytes, size_t align, uint64_t *phys)
{
    if (align < 16) align = 16;
    size_t n = (bytes + align - 1) / align * align;
    void *p = aligned_alloc(align, n);
    if (!p) return NULL;
    memset(p, 0, n);
    if (phys) *phys = (uint64_t)(uintptr_t)p;
    return p;
}
volatile void *ck_mmio_map(uint64_t phys, size_t len)
{
    (void)len;
    return (volatile void *)(uintptr_t)phys;
}
void ck_mb(void) { __sync_synchronize(); }
const void *ck_acpi_find(const char sig[4])
{
    if (memcmp(sig, "MCFG", 4) == 0) return ck_host_mcfg;
    return NULL;
}
uint64_t ck_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}
void ck_udelay(uint32_t us) { (void)us; }
const char *ck_commit(void) { return "host-test-commit"; }
unsigned ck_exception_level(void) { return 1; }
uint64_t ck_conventional_memory_kb(void) { return 42; }
uint32_t ck_boot_count_hint(void) { return 0; }

/* Host: the capability library reads the real /dev/urandom. */
int ck_compat_entropy_source(void) { return CK_ENTROPY_HOST; }
/* Host: the kernel RNDR service is not in play (libc /dev/urandom above). */
int ck_entropy_status(void) { return 0; }
const char *ck_entropy_reason(void) { return "host-urandom"; }

/* Host: no IORT, so no SMMU (the NVMe gate stays fail-closed). */
int ck_dma_confine(uint32_t segment, uint32_t rid, uint64_t phys, uint64_t len, struct ck_dma_confinement *out)
{
    (void)segment; (void)rid; (void)phys; (void)len; (void)out;
    return CK_SMMU_ABSENT;
}
int ck_dma_unconfine(uint32_t stream_id) { (void)stream_id; return CK_SMMU_EARG; }
int ck_dma_faults(uint32_t stream_id, struct ck_dma_fault *first)
{
    (void)stream_id; (void)first;
    return -1;
}
