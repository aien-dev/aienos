/* ck_host.c -- host implementation of the ck.h services for the stage host
 * tests (malloc + stdio). Hosted test code only; never in the image.
 * Identity "mapping": ck_mmio_map returns the address it is given, so a
 * test hands MCFG an aligned heap buffer as the fake ECAM. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>
#include "ck.h"
#include "ck_compat.h"
#include "ck_host.h"

const void *ck_host_mcfg;
int ck_host_quiet;
int ck_host_try_map_ok;
uint64_t ck_host_try_map_fail;

/* Optional text capture so a test can check what a stage printed. */
static char cap_buf[32768];
static size_t cap_len;
static int cap_on;
void ck_host_capture_start(void) { cap_len = 0; cap_buf[0] = 0; cap_on = 1; }
const char *ck_host_capture_text(void) { return cap_buf; }
void ck_host_capture_stop(void) { cap_on = 0; }
static void cap_add(const char *s, size_t n)
{
    if (!cap_on) return;
    if (n > sizeof cap_buf - 1 - cap_len) n = sizeof cap_buf - 1 - cap_len;
    memcpy(cap_buf + cap_len, s, n);
    cap_len += n;
    cap_buf[cap_len] = 0;
}

void ck_puts(const char *s)
{
    cap_add(s, strlen(s));
    if (!ck_host_quiet) fputs(s, stdout);
}
void ck_vprintf(const char *fmt, va_list ap)
{
    if (cap_on) {
        char tmp[512];
        va_list c;
        va_copy(c, ap);
        int n = vsnprintf(tmp, sizeof tmp, fmt, c);
        va_end(c);
        if (n > 0) cap_add(tmp, (size_t)n < sizeof tmp ? (size_t)n : sizeof tmp - 1);
    }
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
/* Host: the kernel never frees DMA regions; the shim remembers them and frees at exit so leak checks stay useful. */
static void *host_dma[32];
static unsigned host_dma_n;
static void host_dma_free_all(void)
{
    while (host_dma_n) free(host_dma[--host_dma_n]);
}
void *ck_dma_alloc(size_t bytes, size_t align, uint64_t *phys)
{
    if (align < 16) align = 16;
    size_t n = (bytes + align - 1) / align * align;
    void *p = aligned_alloc(align, n);
    if (!p) return NULL;
    memset(p, 0, n);
    if (host_dma_n < 32) {
        if (host_dma_n == 0) atexit(host_dma_free_all);
        host_dma[host_dma_n++] = p;
    }
    if (phys) *phys = (uint64_t)(uintptr_t)p;
    return p;
}
/* Host: no platform MMIO by default (the ACPI platform xHCI list is always
 * empty). A test may turn on identity mapping (ck_host_try_map_ok) and make
 * one exact address fail (ck_host_try_map_fail).
 *
 * The fake also keeps a tiny page map so exclusive ownership and unmap can be
 * tested: try_map (shared, like the kernel's) and map_exclusive record the
 * page range as mapped; map_exclusive refuses when any page is recorded;
 * unmap_exclusive turns the range into PROT_NONE so a raw access really
 * faults, and a later map_exclusive restores PROT_READ|PROT_WRITE. */
#define HOST_PAGE 4096ull
#define HOST_MAPS 16
static struct { uint64_t lo, hi; int unmapped, excl; } hmap[HOST_MAPS];
static unsigned hmap_n;
int ck_host_unmap_calls;

static void host_range(uint64_t phys, size_t len, uint64_t *lo, uint64_t *hi)
{
    *lo = phys & ~(HOST_PAGE - 1);
    *hi = (phys + len + HOST_PAGE - 1) & ~(HOST_PAGE - 1);
}
static int host_find(uint64_t lo, uint64_t hi, int unmapped)
{
    for (unsigned i = 0; i < hmap_n; i++)
        if (hmap[i].unmapped == unmapped && lo < hmap[i].hi && hmap[i].lo < hi) return (int)i;
    return -1;
}
static void host_drop(int i) { hmap[i] = hmap[--hmap_n]; }
static void host_add(uint64_t lo, uint64_t hi, int excl)
{
    if (hmap_n < HOST_MAPS) hmap[hmap_n++] = (typeof(hmap[0])){ lo, hi, 0, excl };
}
/* Same rule as the kernel: a live exclusive range is never shared. */
static int host_excl_live(uint64_t lo, uint64_t hi)
{
    for (unsigned i = 0; i < hmap_n; i++)
        if (hmap[i].excl && !hmap[i].unmapped && lo < hmap[i].hi && hmap[i].lo < hi) return 1;
    return 0;
}
void ck_host_mmio_reset(void) { hmap_n = 0; ck_host_unmap_calls = 0; }

volatile void *ck_mmio_try_map(uint64_t phys, size_t len)
{
    if (!ck_host_try_map_ok || (ck_host_try_map_fail && phys == ck_host_try_map_fail)) return NULL;
    uint64_t lo, hi;
    host_range(phys, len, &lo, &hi);
    if (host_excl_live(lo, hi)) return NULL;
    for (int i; (i = host_find(lo, hi, 1)) >= 0;) { /* pages given back earlier: usable again */
        mprotect((void *)(uintptr_t)hmap[i].lo, hmap[i].hi - hmap[i].lo, PROT_READ | PROT_WRITE);
        host_drop(i);
    }
    if (host_find(lo, hi, 0) < 0) host_add(lo, hi, 0);
    return (volatile void *)(uintptr_t)phys;
}
volatile void *ck_mmio_map_exclusive(uint64_t phys, size_t len)
{
    if (!len || !ck_host_try_map_ok || (ck_host_try_map_fail && phys == ck_host_try_map_fail)) return NULL;
    uint64_t lo, hi;
    host_range(phys, len, &lo, &hi);
    if (hmap_n >= HOST_MAPS || host_find(lo, hi, 0) >= 0) return NULL;
    for (int i; (i = host_find(lo, hi, 1)) >= 0;) { /* pages given back earlier: usable again */
        mprotect((void *)(uintptr_t)hmap[i].lo, hmap[i].hi - hmap[i].lo, PROT_READ | PROT_WRITE);
        host_drop(i);
    }
    host_add(lo, hi, 1);
    return (volatile void *)(uintptr_t)phys;
}
int ck_mmio_is_mapped(uint64_t phys, size_t len)
{
    uint64_t lo, hi;
    host_range(phys, len, &lo, &hi);
    return len && host_find(lo, hi, 0) >= 0;
}
volatile void *ck_mmio_map(uint64_t phys, size_t len)
{
    if (len && host_excl_live(phys & ~(HOST_PAGE - 1), (phys + len + HOST_PAGE - 1) & ~(HOST_PAGE - 1)))
        ck_panic("ck_mmio_map: 0x%llx overlaps an exclusive MMIO window", (unsigned long long)phys);
    return (volatile void *)(uintptr_t)phys;
}
int ck_mmio_unmap_exclusive(uint64_t phys, size_t len)
{
    uint64_t lo, hi;
    host_range(phys, len, &lo, &hi);
    int i = len ? host_find(lo, hi, 0) : -1;
    if (i < 0 || !hmap[i].excl || hmap[i].lo != lo || hmap[i].hi != hi) return -1;
    ck_host_unmap_calls++;
    hmap[i].unmapped = 1;
    return mprotect((void *)(uintptr_t)lo, hi - lo, PROT_NONE) == 0 ? 0 : -1;
}
/* Host: no DSDT reachable (no FADT in ck_acpi_find). */
int ck_acpi_platform_devices(const char *const *ids, unsigned nids, struct ck_platform_dev *out, unsigned max,
                             struct ck_acpi_scan_info *info)
{
    (void)ids; (void)nids; (void)out; (void)max;
    if (info) info->tables = info->refused = info->devices = 0, info->first_refusal = 0;
    return -1;
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

/* Host: no IORT by default, so no SMMU (the NVMe gate stays fail-closed). A test may set
 * ck_host_confine_rc = 0 to model an SMMU that confines; every call is recorded. */
int ck_host_confine_rc = CK_SMMU_ABSENT;
unsigned ck_host_confine_calls, ck_host_unconfine_calls;
uint32_t ck_host_confine_segment, ck_host_confine_rid;
uint64_t ck_host_confine_phys, ck_host_confine_len;
int ck_dma_confine(uint32_t segment, uint32_t rid, uint64_t phys, uint64_t len, struct ck_dma_confinement *out)
{
    ck_host_confine_calls++;
    ck_host_confine_segment = segment;
    ck_host_confine_rid = rid;
    ck_host_confine_phys = phys;
    ck_host_confine_len = len;
    if (ck_host_confine_rc == 0 && out) {
        out->smmu_base = 0x2b400000ull;
        out->stream_id = 0x40u | rid;
        out->iova = phys;
        out->len = len;
    }
    return ck_host_confine_rc;
}
int ck_dma_confine_named(const char *acpi_name, uint64_t phys, uint64_t len, struct ck_dma_confinement *out)
{
    (void)acpi_name; (void)phys; (void)len; (void)out;
    return CK_SMMU_ABSENT;
}
int ck_dma_unconfine(uint32_t stream_id)
{
    (void)stream_id;
    ck_host_unconfine_calls++;
    return ck_host_confine_rc == 0 ? 0 : CK_SMMU_EARG;
}
int ck_dma_faults(uint32_t stream_id, struct ck_dma_fault *first)
{
    (void)stream_id; (void)first;
    return -1;
}
