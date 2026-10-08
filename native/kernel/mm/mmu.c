/* mmu.c -- the kernel's own address space. Built while the firmware's
 * translation is still live (identity), switched on at EL1 by ck_enter_el1.
 *
 *   RAM (every WB-capable UEFI RAM type)  Normal WB, RW, XN
 *   kernel image                           text RX, rodata/relocs RO+XN, data/bss RW+XN
  *   kernel stack (256 KiB)                 RW, unmapped guard page below
  *   heap (64 MiB)                           RW, unmapped guard page on each side
 *   DMA pool (8 MiB)                       Normal Non-cacheable (ck_dma_alloc)
 *   MMIO                                   Device-nGnRE, XN (ck_mmio_map)
 *   GOP framebuffer (CHANDOF3)             Device-nGnRE, XN (ck_mmio_map), visible
 *                                          pitch x height x 4 bytes, only outside RAM
 *   ACPI tables outside WB RAM             Normal RO, XN
 *
 * Frames for tables, stack, heap and the pool come from the allocator, which
 * only ever holds EfiConventionalMemory minus the image and the handoff. */
#include "arch.h"
#include "ck_internal.h"
#include "frames.h"
#include "heap.h"
#include "pt.h"

/* Stack: stage code needs >= 128 KiB (m5_envelope_open alone has a ~64 KiB
 * frame); 256 KiB gives 2x margin. Heap: the Store workspace and state are
 * each over 1 MiB and the stage probe ran in a 64 MiB bump heap; 64 MiB with
 * free() is the same budget. Both report their high-water marks. */
#define STACK_BYTES (256ull << 10)
#define HEAP_BYTES (64ull << 20)
#define STACK_PAINT 0x5354414b5354414bull /* "KATSKATS": never-used stack words */
#define DMA_BYTES (8ull << 20)
#define RAM_MAX 256

extern char __image_base[], __text_start[], __text_end[], __ro_start[], __ro_end[],
    __rw_start[], __image_end[];

uint64_t ck_stack_floor; /* read by vectors.S; 0 until the EL1 stack is live */

static struct ck_frames frames;
static struct ck_pt pt;
static struct ck_heap heap;
static int heap_ready;
static size_t heap_min_free;
static struct ck_mm_report rep;
static uint64_t dma_cur;
static struct {
    uint64_t base, end;
} ram[RAM_MAX];
static unsigned ram_n;

/* Live exclusive MMIO ranges (ck_mmio_map_exclusive). Fixed table: when full, a
 * new exclusive map is refused (fail closed). ck_mm_mmio_try_map and
 * ck_mmio_map refuse to share these pages, so an unmap can never pull a
 * mapping out from under another driver. */
#define EXCL_MAX 8
static struct {
    uint64_t lo, hi;
} excl[EXCL_MAX];
static unsigned excl_n;

static int pt_alloc(void *ctx, uint64_t *phys)
{
    (void)ctx;
    if (ck_frames_alloc(&frames, 1, CK_PAGE, phys))
        return -1;
    memset((void *)(uintptr_t)*phys, 0, CK_PAGE);
    return 0;
}

static int ram_type(uint32_t t)
{
    return (t >= 1 && t <= 7) || t == 9 || t == 10 || t == 14;
}

static int overlaps_ram(uint64_t lo, uint64_t hi)
{
    for (unsigned i = 0; i < ram_n; i++)
        if (lo < ram[i].end && ram[i].base < hi)
            return 1;
    return 0;
}

static int overlaps_excl(uint64_t lo, uint64_t hi)
{
    for (unsigned i = 0; i < excl_n; i++)
        if (lo < excl[i].hi && excl[i].lo < hi)
            return 1;
    return 0;
}

static void must(int rc, const char *what)
{
    if (rc)
        ck_panic("mm: %s failed rc=%d", what, rc);
}

static uint64_t take(uint64_t bytes, uint64_t align, const char *what)
{
    uint64_t pa;
    if (ck_frames_alloc(&frames, bytes / CK_PAGE, align, &pa))
        ck_panic("mm: out of frames for %s (%llu bytes)", what, (unsigned long long)bytes);
    return pa;
}

static void tlb_sync(void)
{
    __asm__ volatile("dsb ishst\n tlbi vmalle1is\n dsb ish\n isb" ::: "memory");
}


static void map_acpi_page(uint64_t pa, uint64_t len)
{
    uint64_t lo = pa & ~(CK_PAGE - 1), hi = (pa + len + CK_PAGE - 1) & ~(CK_PAGE - 1);
    for (uint64_t p = lo; p < hi; p += CK_PAGE) {
        uint64_t a;
        if (ck_pt_lookup(&pt, p, &a, 0, 0) != 0)
            must(ck_pt_map(&pt, p, p, CK_PAGE, CK_PT_NORMAL_RO), "acpi map");
    }
}

static void acpi_reserve_cb(uint64_t lo, uint64_t hi, void *ctx)
{
    ck_frames_reserve(ctx, lo, hi);
}

static void acpi_cb(uint64_t table, uint32_t len, void *ctx)
{
    (void)ctx;
    map_acpi_page(table, len);
}

uint64_t ck_mm_build(const struct ck_handoff *h)
{
    ck_frames_init(&frames);
    if (ck_frames_from_efi(&frames, (const void *)(uintptr_t)h->memory_map, h->map_size,
                           h->desc_size) <= 0)
        ck_panic("mm: no usable memory in the UEFI map");
    /* The image (with the handoff and the map copy in its BSS) is LoaderCode
     * on UEFI already; reserve it explicitly anyway. */
    ck_frames_reserve(&frames, h->image_base, h->image_end);
    ck_frames_reserve(&frames, (uint64_t)(uintptr_t)h, (uint64_t)(uintptr_t)h + sizeof *h);
    ck_frames_reserve(&frames, h->memory_map, h->memory_map + h->map_size);
    /* CHANDOF2: the model the stub read from the boot disk (EfiLoaderData,
     * never handed out anyway); whole pages, explicit like the image. */
    if (h->model_flags & CK_HANDOFF_MODEL_PRESENT)
        ck_frames_reserve(&frames, h->model_base,
                          (h->model_base + h->model_len + CK_PAGE - 1) & ~(uint64_t)(CK_PAGE - 1));
    /* ACPI: the RSDP, the XSDT/RSDT and every table the root lists, whole
     * pages, before the first allocation. UEFI keeps them out of
     * EfiConventionalMemory already; this holds even if a firmware does not. */
    if (h->rsdp)
        ck_acpi_spans(h->rsdp, acpi_reserve_cb, &frames);

    must(ck_pt_init(&pt, pt_alloc, 0), "pt init");

    /* RAM, identity, Normal WB, non-executable. */
    for (uint64_t off = 0; off + h->desc_size <= h->map_size; off += h->desc_size) {
        const struct ck_efi_desc *d = (const void *)(uintptr_t)(h->memory_map + off);
        if (!ram_type(d->type) || !(d->attr & 0x8 /* EFI_MEMORY_WB */) || !d->pages)
            continue;
        uint64_t len = d->pages * CK_PAGE;
        must(ck_pt_map(&pt, d->phys, d->phys, len, CK_PT_NORMAL_RW), "ram map");
        if (ram_n < RAM_MAX) {
            ram[ram_n].base = d->phys;
            ram[ram_n].end = d->phys + len;
            ram_n++;
        } else {
            ck_panic("mm: more than %d RAM ranges", RAM_MAX);
        }
    }

    /* Kernel image permissions. */
    uint64_t ib = (uint64_t)(uintptr_t)__image_base;
    must(ck_pt_map(&pt, ib, ib, (uint64_t)(uintptr_t)__text_start - ib, CK_PT_NORMAL_RO), "image header");
    must(ck_pt_map(&pt, (uint64_t)(uintptr_t)__text_start, (uint64_t)(uintptr_t)__text_start,
                   (uint64_t)(__text_end - __text_start), CK_PT_NORMAL_RX), "image text");
    must(ck_pt_map(&pt, (uint64_t)(uintptr_t)__ro_start, (uint64_t)(uintptr_t)__ro_start,
                   (uint64_t)(__ro_end - __ro_start), CK_PT_NORMAL_RO), "image rodata");
    must(ck_pt_map(&pt, (uint64_t)(uintptr_t)__rw_start, (uint64_t)(uintptr_t)__rw_start,
                   (uint64_t)(__image_end - __rw_start), CK_PT_NORMAL_RW), "image data");

    /* Stack with a guard page below. */
    uint64_t s = take(STACK_BYTES + CK_PAGE, CK_PAGE, "stack");
    must(ck_pt_unmap(&pt, s, CK_PAGE), "stack guard");
    rep.stack_guard = s;
    rep.stack_lo = s + CK_PAGE;
    rep.stack_hi = rep.stack_lo + STACK_BYTES;
    for (uint64_t *w = (uint64_t *)(uintptr_t)rep.stack_lo; w < (uint64_t *)(uintptr_t)rep.stack_hi; w++)
        *w = STACK_PAINT;

    /* Heap with guard pages on both sides. */
    uint64_t hp = take(HEAP_BYTES + 2 * CK_PAGE, CK_PAGE, "heap");
    must(ck_pt_unmap(&pt, hp, CK_PAGE), "heap guard low");
    must(ck_pt_unmap(&pt, hp + CK_PAGE + HEAP_BYTES, CK_PAGE), "heap guard high");
    rep.heap_guard_lo = hp;
    rep.heap_lo = hp + CK_PAGE;
    rep.heap_hi = rep.heap_lo + HEAP_BYTES;
    rep.heap_guard_hi = rep.heap_hi;

    /* DMA pool: Normal Non-cacheable. Zero it through the firmware's cached
     * mapping, then clean+invalidate so no dirty or stale line survives the
     * attribute change. */
    uint64_t dp = take(DMA_BYTES, 2ull << 20, "dma pool");
    memset((void *)(uintptr_t)dp, 0, DMA_BYTES);
    uint64_t ctr = ck_rd(ctr_el0);
    uint64_t line = 4ull << ((ctr >> 16) & 0xf);
    for (uint64_t a = dp; a < dp + DMA_BYTES; a += line)
        __asm__ volatile("dc civac, %0" ::"r"(a) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
    must(ck_pt_map(&pt, dp, dp, DMA_BYTES, CK_PT_NORMAL_NC), "dma pool");
    rep.dma_lo = dp;
    rep.dma_hi = dp + DMA_BYTES;
    dma_cur = dp;

    /* ACPI tables (and the RSDP) wherever the firmware put them. */
    if (h->rsdp) {
        map_acpi_page(h->rsdp, 36);
        int is_x = 0;
        uint64_t root = ck_acpi_root(h->rsdp, &is_x);
        if (root)
            map_acpi_page(root, *(const uint32_t *)(uintptr_t)(root + 4));
        ck_acpi_each(h->rsdp, acpi_cb, 0);
    }

    /* Console UART, so output keeps working after the switch. */
    uint64_t ub = ck_console_uart_base();
    if (ub)
        ck_mmio_map(ub, CK_PAGE);

    /* GOP framebuffer (CHANDOF3, validated by handoff_check.c): Device-nGnRE
     * like any MMIO, the bytes the console touches (pitch x height x 4).
     * UEFI 2.10 12.9 says nothing about the memory attributes of the frame
     * buffer after ExitBootServices (DOCS SILENT); on QEMU ramfb and, per
     * Linux /proc/iomem, on the Spark it lies in a firmware-reserved range
     * this kernel does not map as RAM. If it overlaps a RAM range mapped
     * write-back the kernel refuses it (no second, mismatched mapping) and
     * reports on the UART only. */
    if (h->fb_status == CK_HANDOFF_FB_PRESENT) {
        uint64_t fb_len = (uint64_t)h->fb_pitch * h->fb_height * 4u;
        uint64_t lo = h->fb_base & ~(CK_PAGE - 1);
        uint64_t hi = (h->fb_base + fb_len + CK_PAGE - 1) & ~(CK_PAGE - 1);
        rep.fb_map_bytes = fb_len;
        if (overlaps_ram(lo, hi)) {
            rep.fb_map = CK_MM_FB_OVERLAPS_RAM;
        } else {
            ck_mmio_map(h->fb_base, fb_len);
            rep.fb_map = CK_MM_FB_MAPPED;
        }
    }

    /* Tables were written through the firmware's cacheable mapping and our
     * walks are cacheable too; make them visible before the switch. */
    __asm__ volatile("dsb ish" ::: "memory");
    rep.root = pt.root;
    rep.pt_tables = pt.tables;
    rep.ram_ranges = ram_n;
    rep.free_bytes = ck_frames_free_bytes(&frames);
    return rep.stack_hi;
}

void ck_mm_el1_ready(void)
{
    pt.live = 1;
    ck_stack_floor = rep.stack_lo;
    if (ck_heap_init(&heap, (void *)(uintptr_t)rep.heap_lo, HEAP_BYTES))
        ck_panic("mm: heap init failed");
    heap_ready = 1;
    heap_min_free = ck_heap_free_bytes(&heap);
}

void ck_mm_usage(struct ck_mm_usage *u)
{
    u->stack_bytes = STACK_BYTES;
    const uint64_t *w = (const uint64_t *)(uintptr_t)rep.stack_lo;
    while ((uint64_t)(uintptr_t)w < rep.stack_hi && *w == STACK_PAINT)
        w++;
    u->stack_used = rep.stack_hi - (uint64_t)(uintptr_t)w;
    u->heap_bytes = HEAP_BYTES;
    u->heap_free = heap_ready ? ck_heap_free_bytes(&heap) : 0;
    u->heap_min_free = heap_min_free;
}

const struct ck_mm_report *ck_mm_report(void) { return &rep; }
uint64_t ck_mm_mair(void) { return CK_MAIR_VALUE; }

uint64_t ck_mm_tcr(void)
{
    uint64_t ips = ck_rd(id_aa64mmfr0_el1) & 7;
    if (ips > 5)
        ips = 5; /* 48-bit output is all a 4-level, 48-bit VA walk needs */
    return 16ull | (1ull << 8) | (1ull << 10) | (3ull << 12) | (16ull << 16) | (1ull << 23) |
           (2ull << 30) | (ips << 32);
}

uint64_t ck_mm_sctlr(void)
{
    return 0x30d00800ull | (1ull << 0) | (1ull << 2) | (1ull << 12);
}

void *ck_alloc(size_t bytes)
{
    if (!heap_ready)
        return 0;
    void *p = ck_heap_alloc(&heap, bytes);
    if (p) {
        size_t fb = ck_heap_free_bytes(&heap);
        if (fb < heap_min_free)
            heap_min_free = fb;
    }
    return p;
}

void ck_free(void *p)
{
    if (!p)
        return;
    if (!heap_ready || ck_heap_free(&heap, p))
        ck_panic("ck_free: bad pointer %p", p);
}

void *ck_dma_alloc(size_t bytes, size_t align, uint64_t *phys)
{
    if (!bytes || align < CK_PAGE || (align & (align - 1)))
        return 0;
    uint64_t a = (dma_cur + align - 1) & ~((uint64_t)align - 1);
    uint64_t len = ((uint64_t)bytes + CK_PAGE - 1) & ~(CK_PAGE - 1);
    if (!dma_cur || a < dma_cur || a + len > rep.dma_hi)
        return 0;
    dma_cur = a + len;
    memset((void *)(uintptr_t)a, 0, len);
    if (phys)
        *phys = a;
    return (void *)(uintptr_t)a;
}

volatile void *ck_mmio_map(uint64_t phys, size_t len)
{
    if (!len)
        ck_panic("ck_mmio_map: zero length at 0x%llx", (unsigned long long)phys);
    uint64_t lo = phys & ~(CK_PAGE - 1);
    uint64_t hi = (phys + len + CK_PAGE - 1) & ~(CK_PAGE - 1);
    if (hi < lo || overlaps_ram(lo, hi))
        ck_panic("ck_mmio_map: 0x%llx+0x%llx overlaps RAM", (unsigned long long)phys,
                 (unsigned long long)len);
    if (overlaps_excl(lo, hi))
        ck_panic("ck_mmio_map: 0x%llx+0x%llx overlaps an exclusive MMIO window", (unsigned long long)phys,
                 (unsigned long long)len);
    int rc = ck_pt_map(&pt, lo, lo, hi - lo, CK_PT_DEVICE);
    if (rc)
        ck_panic("ck_mmio_map: 0x%llx+0x%llx rc=%d", (unsigned long long)phys,
                 (unsigned long long)len, rc);
    if (pt.live)
        tlb_sync();
    return (volatile void *)(uintptr_t)phys;
}

int ck_mm_guard_selftest(char *detail, size_t n)
{
    const struct {
        const char *name;
        uint64_t addr;
    } g[] = {
        {"stack", rep.stack_guard},
        {"heap_lo", rep.heap_guard_lo},
        {"heap_hi", rep.heap_guard_hi},
    };
    /* Control: a mapped heap word must read without a fault. */
    if (ck_probe_read((const volatile void *)(uintptr_t)rep.heap_lo) != 0) {
        ck_snprintf(detail, n, "control read of heap faulted");
        return -1;
    }
    for (unsigned i = 0; i < sizeof g / sizeof g[0]; i++) {
        uint64_t a = g[i].addr + 8;
        ck_probe_state.esr = ck_probe_state.far = 0;
        if (ck_probe_read((const volatile void *)(uintptr_t)a) != 1) {
            ck_snprintf(detail, n, "%s guard 0x%llx did not fault", g[i].name, (unsigned long long)a);
            return -1;
        }
        uint64_t ec = (ck_probe_state.esr >> 26) & 0x3f;
        uint64_t dfsc = ck_probe_state.esr & 0x3f;
        if (ec != 0x25 || ck_probe_state.far != a || (dfsc & 0x3c) != 0x04) {
            ck_snprintf(detail, n, "%s guard: unexpected esr=0x%llx far=0x%llx", g[i].name,
                        (unsigned long long)ck_probe_state.esr,
                        (unsigned long long)ck_probe_state.far);
            return -1;
        }
    }
    ck_snprintf(detail, n, "stack=0x%llx heap_lo=0x%llx heap_hi=0x%llx",
                (unsigned long long)rep.stack_guard, (unsigned long long)rep.heap_guard_lo,
                (unsigned long long)rep.heap_guard_hi);
    return 0;
}

/* ---- artifact loader support (core/artifact_loader.c) ---- */

int ck_mm_frames_alloc(uint64_t npages, uint64_t *pa)
{
    return npages ? ck_frames_alloc(&frames, npages, CK_PAGE, pa) : -1;
}

int ck_mm_frames_free(uint64_t pa, uint64_t npages)
{
    return ck_frames_add(&frames, pa, pa + npages * CK_PAGE);
}

uint64_t ck_mm_free_frames(void) { return ck_frames_free_bytes(&frames) / CK_PAGE; }

int ck_mm_mapped(uint64_t pa, uint64_t len)
{
    uint64_t lo = pa & ~(CK_PAGE - 1), hi = pa + len;
    if (hi < pa)
        return 0;
    for (uint64_t p = lo; p < hi; p += CK_PAGE) {
        uint64_t a;
        if (ck_pt_lookup(&pt, p, &a, 0, 0) != 0 || a != p)
            return 0;
    }
    return 1;
}

volatile void *ck_mm_mmio_try_map(uint64_t phys, size_t len)
{
    uint64_t lo = phys & ~(CK_PAGE - 1);
    uint64_t hi = (phys + len + CK_PAGE - 1) & ~(CK_PAGE - 1);
    if (!len || hi <= lo || overlaps_ram(lo, hi) || overlaps_excl(lo, hi))
        return 0;
    for (uint64_t p = lo; p < hi; p += CK_PAGE) {
        uint64_t a;
        if (ck_pt_lookup(&pt, p, &a, 0, 0) == 0) {
            if (a != p)
                return 0;
            continue;
        }
        if (ck_pt_map(&pt, p, p, CK_PAGE, CK_PT_DEVICE))
            return 0;
    }
    if (pt.live)
        tlb_sync();
    return (volatile void *)(uintptr_t)phys;
}

volatile void *ck_mmio_try_map(uint64_t phys, size_t len)
{
    return len ? ck_mm_mmio_try_map(phys, len) : 0;
}

/* Exclusive map for a caller that unmaps again (mmio_window.c). All or
 * nothing: if any page is already mapped, by anyone, nothing is mapped. Pages
 * are mapped one at a time at level 3 so the unmap never needs to split a
 * block (a split is refused on live tables). */
volatile void *ck_mmio_map_exclusive(uint64_t phys, size_t len)
{
    uint64_t lo = phys & ~(CK_PAGE - 1);
    uint64_t hi = (phys + len + CK_PAGE - 1) & ~(CK_PAGE - 1);
    if (!len || hi <= lo || overlaps_ram(lo, hi) || overlaps_excl(lo, hi) ||
        excl_n >= EXCL_MAX)
        return 0;
    for (uint64_t p = lo; p < hi; p += CK_PAGE)
        if (ck_pt_lookup(&pt, p, 0, 0, 0) == 0)
            return 0;
    for (uint64_t p = lo; p < hi; p += CK_PAGE)
        if (ck_pt_map(&pt, p, p, CK_PAGE, CK_PT_DEVICE)) {
            (void)ck_pt_unmap(&pt, lo, p - lo); /* undo: these pages were ours a moment ago */
            if (pt.live)
                tlb_sync();
            return 0;
        }
    excl[excl_n].lo = lo;
    excl[excl_n++].hi = hi;
    if (pt.live)
        tlb_sync();
    return (volatile void *)(uintptr_t)phys;
}

/* Break before make: the entries are made invalid first, then the TLB is
 * invalidated and synchronised (tlb_sync) before this returns, so no stale
 * translation outlives the call and a later map of the same pages starts from
 * invalid entries. */
int ck_mmio_unmap_exclusive(uint64_t phys, size_t len)
{
    uint64_t lo = phys & ~(CK_PAGE - 1);
    uint64_t hi = (phys + len + CK_PAGE - 1) & ~(CK_PAGE - 1);
    if (!len || hi <= lo || overlaps_ram(lo, hi))
        return -1;
    unsigned e = 0;
    while (e < excl_n && !(excl[e].lo == lo && excl[e].hi == hi))
        e++;
    if (e == excl_n) /* only a range handed out by ck_mmio_map_exclusive can be taken back */
        return -1;
    for (uint64_t p = lo; p < hi; p += CK_PAGE) {
        uint64_t a, at;
        int lv;
        /* Only a Device identity page of its own: never RAM, a block, or a page with other attributes. */
        if (ck_pt_lookup(&pt, p, &a, &at, &lv) != 0 || a != p || lv != 3 || at != CK_PT_DEVICE)
            return -1;
    }
    if (ck_pt_unmap(&pt, lo, hi - lo))
        return -1;
    excl[e] = excl[--excl_n]; /* the range is free for ordinary maps again */
    if (pt.live)
        tlb_sync();
    return 0;
}

int ck_mmio_is_mapped(uint64_t phys, size_t len)
{
    uint64_t lo = phys & ~(CK_PAGE - 1);
    uint64_t hi = (phys + len + CK_PAGE - 1) & ~(CK_PAGE - 1);
    for (uint64_t p = lo; len && p < hi; p += CK_PAGE)
        if (ck_pt_lookup(&pt, p, 0, 0, 0) == 0)
            return 1;
    return 0;
}
