/* ck_probe.c -- PROBE, not a gate. A throwaway ck.h implementation for
 * QEMU virt (highmem=off) so the Lane 18 stages can run before the real
 * core exists: PL011 UART, bump heap, identity MMIO (MMU off), generic
 * timer, a hand-built MCFG for the low ECAM. QEMU is an emulator; nothing
 * here qualifies any physical machine. The real core replaces this file. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include "ck.h"

#define UART 0x09000000ul
#define QEMU_ECAM_LOW 0x3f000000ull

extern uint8_t __heap_start[], __heap_end[];
static uintptr_t heap_next;

static void putc_(char c)
{
    volatile uint32_t *dr = (volatile uint32_t *)UART;
    volatile uint32_t *fr = (volatile uint32_t *)(UART + 0x18);
    if (c == '\n') {
        while (*fr & (1u << 5))
            ;
        *dr = '\r';
    }
    while (*fr & (1u << 5))
        ;
    *dr = (uint32_t)(uint8_t)c;
}
void ck_puts(const char *s)
{
    while (*s) putc_(*s++);
}

static void put_num(unsigned long long v, unsigned base, int width, char pad, int neg)
{
    char b[24];
    int n = 0;
    do {
        b[n++] = "0123456789abcdef"[v % base];
        v /= base;
    } while (v);
    if (neg) b[n++] = '-';
    while (width-- > n) putc_(pad);
    while (n) putc_(b[--n]);
}

void ck_vprintf(const char *f, va_list ap)
{
    for (; *f; f++) {
        if (*f != '%') {
            putc_(*f);
            continue;
        }
        f++;
        char pad = ' ';
        int width = 0, lng = 0, sz = 0;
        if (*f == '0') pad = '0', f++;
        while (*f >= '0' && *f <= '9') width = width * 10 + (*f++ - '0');
        while (*f == 'l') lng++, f++;
        if (*f == 'z') sz = 1, f++;
        switch (*f) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            ck_puts(s ? s : "(null)");
            break;
        }
        case 'c': putc_((char)va_arg(ap, int)); break;
        case 'd': {
            long long v = lng >= 2 ? va_arg(ap, long long) : lng ? va_arg(ap, long) : va_arg(ap, int);
            put_num(v < 0 ? (unsigned long long)(-v) : (unsigned long long)v, 10, width, pad, v < 0);
            break;
        }
        case 'u':
        case 'x': {
            unsigned long long v = sz ? va_arg(ap, size_t) : lng >= 2 ? va_arg(ap, unsigned long long) :
                                   lng ? va_arg(ap, unsigned long) : va_arg(ap, unsigned);
            put_num(v, *f == 'x' ? 16 : 10, width, pad, 0);
            break;
        }
        case 'p': ck_puts("0x"); put_num((uintptr_t)va_arg(ap, void *), 16, 0, ' ', 0); break;
        case '%': putc_('%'); break;
        default: putc_('?'); break;
        }
    }
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
    ck_puts("report_kind: panic ");
    va_start(ap, fmt);
    ck_vprintf(fmt, ap);
    va_end(ap);
    ck_puts("\n");
    register uint64_t x0 __asm__("x0") = 0x84000008u;
    __asm__ volatile("hvc #0" : "+r"(x0));
    for (;;) __asm__ volatile("wfi");
}

static void *bump(size_t bytes, size_t align)
{
    if (!heap_next) heap_next = (uintptr_t)__heap_start;
    uintptr_t a = (heap_next + align - 1) & ~(uintptr_t)(align - 1);
    if (a + bytes > (uintptr_t)__heap_end || a + bytes < a) return 0;
    heap_next = a + bytes;
    volatile uint8_t *p = (volatile uint8_t *)a; /* QEMU RAM starts zeroed; zero anyway */
    for (size_t i = 0; i < bytes; i++) p[i] = 0;
    return (void *)a;
}
void *ck_alloc(size_t bytes) { return bump(bytes ? bytes : 1, 16); }
void ck_free(void *p) { (void)p; } /* bump heap: probe only */
void *ck_dma_alloc(size_t bytes, size_t align, uint64_t *phys)
{
    void *p = bump(bytes, align < 4096 ? 4096 : align);
    if (p && phys) *phys = (uint64_t)(uintptr_t)p;
    return p;
}
volatile void *ck_mmio_map(uint64_t phys, size_t len)
{
    (void)len;
    return (volatile void *)(uintptr_t)phys;
}
void ck_mb(void) { __asm__ volatile("dsb sy" ::: "memory"); }

static uint8_t mcfg[60];
const void *ck_acpi_find(const char sig[4])
{
    if (sig[0] != 'M' || sig[1] != 'C' || sig[2] != 'F' || sig[3] != 'G') return 0;
    /* QEMU virt highmem=off: ECAM 0x3f000000, 16 buses. Built here because
     * -kernel boots have no ACPI; the real core finds the firmware table. */
    const char *s = "MCFG";
    for (int i = 0; i < 4; i++) mcfg[i] = (uint8_t)s[i];
    mcfg[4] = sizeof mcfg;
    mcfg[8] = 1;
    for (int i = 0; i < 8; i++) mcfg[44 + i] = (uint8_t)(QEMU_ECAM_LOW >> (8 * i));
    mcfg[54] = 0;
    mcfg[55] = 15;
    uint8_t sum = 0;
    mcfg[9] = 0;
    for (unsigned i = 0; i < sizeof mcfg; i++) sum = (uint8_t)(sum + mcfg[i]);
    mcfg[9] = (uint8_t)(0u - sum);
    return mcfg;
}
static uint64_t cntfrq(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
}
static uint64_t cntvct(void)
{
    uint64_t v;
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(v));
    return v;
}
uint64_t ck_time_us(void) { return cntvct() * 1000000u / cntfrq(); }
void ck_udelay(uint32_t us)
{
    uint64_t t0 = cntvct(), ticks = cntfrq() * us / 1000000u + 1;
    while (cntvct() - t0 < ticks)
        ;
}
#ifndef PROBE_COMMIT
#define PROBE_COMMIT "unknown"
#endif
const char *ck_commit(void) { return PROBE_COMMIT; }
uint32_t ck_boot_count_hint(void) { return 0; }

void probe_main(void)
{
    ck_printf("probe: lane18 stage PROBE on QEMU virt (emulator; not a gate, qualifies nothing physical)\n");
    int d = ck_stage_devices ? ck_stage_devices() : -999;
    int s = ck_stage_security ? ck_stage_security() : -999;
    int t = ck_stage_store ? ck_stage_store() : -999;
    ck_printf("probe: stages devices=%d security=%d store=%d\n", d, s, t);
}
