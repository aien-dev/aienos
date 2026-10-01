/* pci.c -- PCIe ECAM discovery from ACPI MCFG (see pci.h). Freestanding. */
#include "pci.h"
#include "ck.h"

#define CFG_VENDOR 0x00u
#define CFG_COMMAND 0x04u
#define CFG_CLASSREV 0x08u
#define CFG_HEADER 0x0eu
#define CFG_BAR0 0x10u
#define CFG_SUBSYS 0x2cu
#define CFG_SECONDARY_BUS 0x19u
#define CMD_IO 0x1u
#define CMD_MEM 0x2u
#define CMD_BM 0x4u

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }

int pci_mcfg_parse(const uint8_t *t, size_t len, pci_ecam *out)
{
    if (!t || !out) return PCI_E_ARG;
    if (len < 44u + 16u) return PCI_E_MCFG;
    if (t[0] != 'M' || t[1] != 'C' || t[2] != 'F' || t[3] != 'G') return PCI_E_MCFG;
    uint32_t tl = le32(t + 4);
    if (tl != len) return PCI_E_MCFG;
    if ((len - 44u) % 16u != 0) return PCI_E_MCFG;
    for (size_t off = 44; off + 16 <= len; off += 16) {
        const uint8_t *e = t + off;
        uint16_t seg = (uint16_t)(e[8] | e[9] << 8);
        if (seg != 0) continue;
        pci_ecam c;
        c.base = le64(e);
        c.segment = seg;
        c.start_bus = e[10];
        c.end_bus = e[11];
        if (c.base == 0 || (c.base & 0xfffffu) != 0 || c.start_bus > c.end_bus) return PCI_E_MCFG;
        *out = c;
        return PCI_OK;
    }
    return PCI_E_MCFG;
}

volatile uint8_t *pci_cfg(const pci_bus_access *a, uint8_t bus, uint8_t dev, uint8_t fn)
{
    if (bus < a->start_bus || bus > a->end_bus || dev > 31 || fn > 7) return 0;
    uint64_t off = ((uint64_t)(bus - a->start_bus) << 20) | ((uint64_t)dev << 15) | ((uint64_t)fn << 12);
    return a->ecam + off;
}
uint32_t pci_r32(volatile uint8_t *c, uint32_t off) { return *(volatile uint32_t *)(c + (off & ~3u)); }
void pci_w32(volatile uint8_t *c, uint32_t off, uint32_t v) { *(volatile uint32_t *)(c + (off & ~3u)) = v; }
uint16_t pci_r16(volatile uint8_t *c, uint32_t off)
{
    return (uint16_t)(pci_r32(c, off) >> ((off & 2u) * 8u));
}
void pci_w16(volatile uint8_t *c, uint32_t off, uint16_t v)
{
    /* 32-bit read-modify-write keeps every access dword sized; only used on
     * COMMAND (whose STATUS half is write-1-to-clear: write zeros there). */
    uint32_t sh = (off & 2u) * 8u;
    uint32_t keep = (off & 2u) ? 0x0000ffffu : 0u;
    uint32_t old = pci_r32(c, off) & keep;
    pci_w32(c, off, old | ((uint32_t)v << sh));
}

uint64_t pci_bar_size(uint32_t lo, uint32_t hi, int is64)
{
    if (is64) {
        uint64_t mask = ((uint64_t)hi << 32) | (uint64_t)(lo & ~0xfu);
        return mask ? ~mask + 1u : 0;
    }
    uint32_t mask = lo & ~0xfu;
    return mask ? (uint64_t)(uint32_t)(~mask + 1u) : 0;
}
uint64_t pci_window_alloc(pci_window *w, uint64_t size)
{
    if (size == 0 || (size & (size - 1u)) != 0) return 0;
    uint64_t a = (w->next + size - 1u) & ~(size - 1u);
    if (a < w->next || a + size < a || a + size > w->limit) return 0;
    w->next = a + size;
    return a;
}

static void size_bars(pci_func *f)
{
    volatile uint8_t *c = f->cfg;
    uint32_t nbars = (f->header_type & 0x7fu) == 0 ? 6u : ((f->header_type & 0x7fu) == 1 ? 2u : 0u);
    uint16_t cmd = pci_r16(c, CFG_COMMAND);
    pci_w16(c, CFG_COMMAND, (uint16_t)(cmd & ~(CMD_IO | CMD_MEM | CMD_BM)));
    for (uint32_t i = 0; i < nbars; i++) {
        pci_bar *b = &f->bar[i];
        uint32_t off = CFG_BAR0 + 4u * i;
        uint32_t orig = pci_r32(c, off);
        if (orig & 1u) { /* I/O BAR: report, never assign (no I/O space on AArch64 here) */
            pci_w32(c, off, 0xffffffffu);
            uint32_t rb = pci_r32(c, off);
            pci_w32(c, off, orig);
            b->io = 1;
            b->addr = orig & ~3u;
            b->size = (rb & ~3u) ? (uint64_t)((~(rb & ~3u) + 1u) & 0xffffu) : 0;
            continue;
        }
        int is64 = ((orig >> 1) & 3u) == 2u && i + 1 < nbars;
        uint32_t orig_hi = is64 ? pci_r32(c, off + 4) : 0;
        pci_w32(c, off, 0xffffffffu);
        if (is64) pci_w32(c, off + 4, 0xffffffffu);
        uint32_t lo = pci_r32(c, off);
        uint32_t hi = is64 ? pci_r32(c, off + 4) : 0;
        pci_w32(c, off, orig);
        if (is64) pci_w32(c, off + 4, orig_hi);
        b->is64 = (uint8_t)is64;
        b->prefetch = (uint8_t)((orig >> 3) & 1u);
        b->size = pci_bar_size(lo, hi, is64);
        b->addr = ((uint64_t)orig_hi << 32) | (orig & ~0xfu);
        if (is64) {
            i++; /* upper half is part of this BAR */
        }
    }
    pci_w16(c, CFG_COMMAND, cmd);
}

static int add_func(pci_system *s, uint8_t bus, uint8_t dev, uint8_t fn, volatile uint8_t *c)
{
    if (s->n >= PCI_MAX_FUNCS) return PCI_E_FULL;
    pci_func *f = &s->f[s->n++];
    uint32_t id = pci_r32(c, CFG_VENDOR);
    f->bus = bus;
    f->dev = dev;
    f->fn = fn;
    f->vendor = (uint16_t)id;
    f->device = (uint16_t)(id >> 16);
    f->class_code = pci_r32(c, CFG_CLASSREV) >> 8;
    f->header_type = (uint8_t)(pci_r32(c, 0x0c) >> 16);
    uint32_t ss = (f->header_type & 0x7fu) == 0 ? pci_r32(c, CFG_SUBSYS) : 0;
    f->subsys_vendor = (uint16_t)ss;
    f->subsys_id = (uint16_t)(ss >> 16);
    f->cfg = c;
    for (uint32_t i = 0; i < PCI_MAX_BARS; i++) {
        f->bar[i].addr = f->bar[i].size = 0;
        f->bar[i].is64 = f->bar[i].prefetch = f->bar[i].io = f->bar[i].assigned_here = 0;
    }
    size_bars(f);
    return PCI_OK;
}

static int scan_bus(pci_system *s, uint8_t bus, uint32_t depth)
{
    for (uint8_t dev = 0; dev < 32; dev++) {
        for (uint8_t fn = 0; fn < 8; fn++) {
            volatile uint8_t *c = pci_cfg(&s->acc, bus, dev, fn);
            if (!c) return PCI_OK;
            uint16_t vendor = (uint16_t)pci_r32(c, CFG_VENDOR);
            if (vendor == 0xffffu || vendor == 0) {
                if (fn == 0) break;
                continue;
            }
            int rc = add_func(s, bus, dev, fn, c);
            if (rc) return rc;
            const pci_func *f = &s->f[s->n - 1];
            if ((f->header_type & 0x7fu) == 1 && depth < 8) {
                uint8_t sec = (uint8_t)(pci_r32(c, 0x18) >> 8);
                if (sec > bus && sec <= s->acc.end_bus) {
                    s->bridges_followed++;
                    rc = scan_bus(s, sec, depth + 1);
                    if (rc) return rc;
                }
            }
            if (fn == 0 && !(f->header_type & 0x80u)) break;
        }
    }
    return PCI_OK;
}

static void assign_bars(pci_system *s, pci_window *win)
{
    if (win) { /* never hand out space below a firmware assignment in the window */
        for (uint32_t k = 0; k < s->n; k++)
            for (uint32_t i = 0; i < PCI_MAX_BARS; i++) {
                const pci_bar *b = &s->f[k].bar[i];
                if (b->io || b->size == 0 || b->addr == 0) continue;
                if (b->addr >= win->base && b->addr < win->limit && b->addr + b->size > win->next)
                    win->next = b->addr + b->size;
            }
    }
    for (uint32_t k = 0; k < s->n; k++) {
        pci_func *f = &s->f[k];
        f->bars_ok = 1;
        for (uint32_t i = 0; i < PCI_MAX_BARS; i++) {
            pci_bar *b = &f->bar[i];
            if (b->io || b->size == 0 || b->addr != 0) continue;
            uint64_t a = win ? pci_window_alloc(win, b->size) : 0;
            if (a == 0 || (!b->is64 && (a >> 32) != 0)) {
                f->bars_ok = 0;
                continue;
            }
            uint32_t off = CFG_BAR0 + 4u * i;
            uint32_t low_flags = pci_r32(f->cfg, off) & 0xfu;
            pci_w32(f->cfg, off, (uint32_t)a | low_flags);
            if (b->is64) pci_w32(f->cfg, off + 4, (uint32_t)(a >> 32));
            b->addr = a;
            b->assigned_here = 1;
        }
    }
}

int pci_enumerate(pci_system *s, pci_window *win)
{
    if (!s || !s->acc.ecam) return PCI_E_ARG;
    s->n = 0;
    s->bridges_followed = 0;
    int rc = scan_bus(s, s->acc.start_bus, 0);
    if (rc) return rc;
    assign_bars(s, win);
    return PCI_OK;
}

void pci_enable(const pci_func *f, int bm)
{
    uint16_t cmd = pci_r16(f->cfg, CFG_COMMAND);
    cmd |= CMD_MEM;
    if (bm) cmd |= CMD_BM;
    pci_w16(f->cfg, CFG_COMMAND, cmd);
}

const pci_func *pci_find_class(const pci_system *s, uint32_t cc, uint32_t mask)
{
    for (uint32_t i = 0; i < s->n; i++)
        if ((s->f[i].class_code & mask) == (cc & mask)) return &s->f[i];
    return 0;
}

const pci_func *pci_find_id(const pci_system *s, uint16_t vendor, uint16_t device)
{
    for (uint32_t i = 0; i < s->n; i++)
        if (s->f[i].vendor == vendor && s->f[i].device == device) return &s->f[i];
    return 0;
}

const char *pci_class_name(uint32_t cc)
{
    switch (cc >> 8) {
    case 0x0108: return "nvme";
    case 0x0200: return "ethernet";
    case 0x0600: return "host-bridge";
    case 0x0604: return "pci-bridge";
    case 0x0c03: return "usb";
    case 0x0300: return "display";
    case 0x0100: return "scsi";
    case 0x0106: return "sata";
    case 0x0180: return "storage";
    case 0x0700: return "serial";
    default: break;
    }
    if ((cc >> 16) == 0x01) return "storage";
    if ((cc >> 16) == 0x02) return "network";
    return "other";
}

/* ---- stage glue --------------------------------------------------------- */

#define QEMU_VIRT_ECAM_HIGH 0x4010000000ull
#define QEMU_VIRT_ECAM_LOW 0x3f000000ull
#define QEMU_VIRT_MMIO32_BASE 0x10000000ull
#define QEMU_VIRT_MMIO32_LIMIT 0x3eff0000ull

int pci_stage_probe(pci_system *s)
{
    const uint8_t *mcfg = (const uint8_t *)ck_acpi_find("MCFG");
    if (!mcfg) {
        ck_printf("pci: no ACPI MCFG table\n");
        return PCI_E_NO_MCFG;
    }
    uint32_t len = le32(mcfg + 4);
    int rc = pci_mcfg_parse(mcfg, len, &s->ecam);
    if (rc) {
        ck_printf("pci: MCFG malformed (len=%u)\n", len);
        return rc;
    }
    uint64_t first = s->ecam.base + ((uint64_t)s->ecam.start_bus << 20);
    uint64_t bytes = (uint64_t)(s->ecam.end_bus - s->ecam.start_bus + 1u) << 20;
    s->acc.ecam = (volatile uint8_t *)ck_mmio_map(first, (size_t)bytes);
    s->acc.start_bus = s->ecam.start_bus;
    s->acc.end_bus = s->ecam.end_bus;
    ck_printf("pci: ecam base=0x%llx seg=%u bus=%u-%u\n", (unsigned long long)s->ecam.base,
              s->ecam.segment, s->ecam.start_bus, s->ecam.end_bus);
    pci_window win, *wp = 0;
    if (s->ecam.base == QEMU_VIRT_ECAM_HIGH || s->ecam.base == QEMU_VIRT_ECAM_LOW) {
        win.base = win.next = QEMU_VIRT_MMIO32_BASE;
        win.limit = QEMU_VIRT_MMIO32_LIMIT;
        wp = &win;
    }
    rc = pci_enumerate(s, wp);
    if (rc) {
        ck_printf("pci: enumerate failed rc=%d\n", rc);
        return rc;
    }
    uint32_t assigned = 0, unassigned = 0;
    for (uint32_t i = 0; i < s->n; i++) {
        const pci_func *f = &s->f[i];
        ck_printf("pci: %02x:%02x.%u %04x:%04x class=%06x %s\n", f->bus, f->dev, f->fn, f->vendor,
                  f->device, f->class_code, pci_class_name(f->class_code));
        for (uint32_t b = 0; b < PCI_MAX_BARS; b++) {
            if (f->bar[b].assigned_here) assigned++;
            if (!f->bar[b].io && f->bar[b].size && !f->bar[b].addr) unassigned++;
        }
    }
    ck_printf("pci: %u functions, %u bridges followed, bars assigned_here=%u unassigned=%u%s\n", s->n,
              s->bridges_followed, assigned, unassigned,
              wp ? " (window: QEMU virt mmio32, QEMU-only assumption)" : " (no window: firmware assignment only)");
    return PCI_OK;
}
