/*
 * sdhci_payload.c -- bare-metal AArch64 test of native/disk/disk_sdhci.c
 * against QEMU's emulated PCI SD Host Controller (sdhci-pci) and SD card on
 * the "virt" machine (highmem=off: PCIe ECAM at 0x3f000000, 32-bit MMIO
 * window at 0x10000000). MMU off, so every access is Device-nGnRnE. The
 * driver is PIO only: no DMA, no bus mastering.
 *
 * QEMU is an emulator. A PASS here says the C driver works against QEMU's
 * SDHCI and SD card models; it says nothing about the Pi 5's controller.
 */
#include <stdint.h>
#include "../disk.h"
#include "../disk_sdhci.h"

#define UART 0x09000000ul
#define ECAM 0x3f000000ul
#define MMIO_BASE 0x10000000ul

static void putc_(char c)
{
    volatile uint32_t *dr = (volatile uint32_t *)UART;
    volatile uint32_t *fr = (volatile uint32_t *)(UART + 0x18);
    while (*fr & (1u << 5))
        ;
    *dr = (uint32_t)(uint8_t)c;
}
static void puts_(const char *s) { while (*s) { if (*s == '\n') putc_('\r'); putc_(*s++); } }
static void putdec(int64_t v)
{
    char b[24];
    int n = 0;
    uint64_t u = v < 0 ? (uint64_t)(-v) : (uint64_t)v;
    if (v < 0) putc_('-');
    do { b[n++] = (char)('0' + u % 10); u /= 10; } while (u);
    while (n) putc_(b[--n]);
}
static void puthex(uint64_t v)
{
    puts_("0x");
    for (int i = 60; i >= 0; i -= 4) putc_("0123456789abcdef"[(v >> i) & 15]);
}

static int fails, checks;
static void check(int ok, const char *what, int64_t got)
{
    checks++;
    if (!ok) {
        fails++;
        puts_("FAIL: ");
        puts_(what);
        puts_(" (got ");
        putdec(got);
        puts_(")\n");
    }
}

/* ---- platform ops ---- */
static volatile uint8_t *bar0;
static uint32_t r32(void *c, uint32_t o) { (void)c; return *(volatile uint32_t *)(bar0 + o); }
static void w32(void *c, uint32_t o, uint32_t v) { (void)c; *(volatile uint32_t *)(bar0 + o) = v; }
static uint64_t cntfrq(void) { uint64_t v; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v)); return v; }
static uint64_t cntvct(void) { uint64_t v; __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(v)); return v; }
static void delay(void *c, uint32_t us)
{
    (void)c;
    uint64_t f = cntfrq(), t0 = cntvct(), ticks = (f * us) / 1000000u + 1;
    while (cntvct() - t0 < ticks)
        ;
}

/* ---- PCIe: find the SD host controller (class 08 05), assign BAR0, enable MEM ---- */
static volatile uint32_t *cfg(uint32_t bus, uint32_t dev, uint32_t fn, uint32_t off)
{
    return (volatile uint32_t *)(ECAM + (bus << 20) + (dev << 15) + (fn << 12) + off);
}
static int pci_find_sdhci(void)
{
    for (uint32_t d = 0; d < 32; d++) {
        uint32_t id = *cfg(0, d, 0, 0);
        if ((id & 0xffff) == 0xffff) continue;
        uint32_t cls = *cfg(0, d, 0, 8) >> 8; /* class/subclass/progif */
        if ((cls >> 8) != 0x0805) continue;
        puts_("pci: SDHCI at 00:");
        putdec(d);
        puts_(".0 id ");
        puthex(id);
        puts_("\n");
        *cfg(0, d, 0, 4) = 0; /* disable decode while sizing */
        *cfg(0, d, 0, 0x10) = 0xffffffffu;
        uint32_t lo = *cfg(0, d, 0, 0x10);
        int is64 = ((lo >> 1) & 3) == 2;
        uint32_t size = ~(lo & ~0xfu) + 1;
        if (size < 0x100 || size > 0x1000000) { puts_("pci: bad BAR0 size\n"); return -1; }
        *cfg(0, d, 0, 0x10) = (uint32_t)MMIO_BASE;
        if (is64) *cfg(0, d, 0, 0x14) = 0;
        *cfg(0, d, 0, 4) = 1u << 1; /* memory space only: PIO driver, no bus master */
        bar0 = (volatile uint8_t *)MMIO_BASE;
        puts_("pci: BAR0 size ");
        puthex(size);
        puts_("\n");
        return 0;
    }
    return -1;
}

static uint8_t wbuf[256u * 512u], rbuf[256u * 512u];

static void fill(uint8_t *b, uint32_t n, uint32_t seed)
{
    for (uint32_t i = 0; i < n; i++) b[i] = (uint8_t)(seed * 37u + i * 13u + (i >> 8));
}
static void zero(uint8_t *b, uint32_t n) { for (uint32_t i = 0; i < n; i++) ((volatile uint8_t *)b)[i] = 0; }
static int same(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

/* The host script reads this block back out of the card image file. */
static const char MARK[] = "AIENOS-SDHCI-QEMU block 5 written by disk_sdhci.c";

static sdhci_card C;
static const sdhci_ops OPS = {0, r32, w32, delay};

void payload_main(void)
{
    puts_("AIENOS native SDHCI payload (C driver, QEMU virt)\n");
    if (pci_find_sdhci()) {
        puts_("no SD host controller found\nSDHCI_QEMU_PAYLOAD: FAIL\n");
        return;
    }
    sdhci_cfg scfg = {0, 0, 1, 64}; /* 4-bit bus, at most 64 blocks per command */
    int rc = sdhci_init(&C, &OPS, &scfg);
    check(rc == SDHCI_OK, "sdhci_init", rc);
    if (rc) {
        puts_("last_cmd ");
        putdec(C.last_cmd);
        puts_(" last_int ");
        puthex(C.last_int);
        puts_("\nSDHCI_QEMU_PAYLOAD: FAIL\n");
        return;
    }
    puts_("card: spec ");
    putdec(C.spec);
    puts_(" base_hz ");
    putdec(C.base_hz);
    puts_(" card_hz ");
    putdec(C.card_hz);
    puts_(" high_capacity ");
    putdec(C.high_capacity);
    puts_(" blocks ");
    putdec((int64_t)C.blocks);
    puts_(" rca ");
    puthex(C.rca);
    puts_("\n");
    check(C.card_hz <= 25000000u && C.card_hz > 0, "card clock at or below 25 MHz", C.card_hz);
    disk_dev *d = &C.dev;
    check(d->block_size == 512, "block size", d->block_size);

    /* 1, 8, 64 (one command), 200 (split into 64-block commands) blocks */
    uint32_t sizes[] = {1, 8, 64, 200};
    uint64_t lba = 16;
    for (uint32_t i = 0; i < 4; i++) {
        uint32_t n = sizes[i], bytes = n * 512u;
        fill(wbuf, bytes, i + 1);
        check(disk_write(d, lba, n, wbuf) == DISK_OK, "disk_write", n);
        zero(rbuf, bytes);
        check(disk_read(d, lba, n, rbuf) == DISK_OK, "disk_read", n);
        check(same(wbuf, rbuf, bytes), "read-back matches write", n);
        lba += n + 1;
    }
    zero(wbuf, 512);
    for (uint32_t i = 0; MARK[i]; i++) wbuf[i] = (uint8_t)MARK[i];
    check(disk_write(d, 5, 1, wbuf) == DISK_OK, "write marker block", 0);
    check(disk_flush(d) == DISK_OK, "flush", 0);
    /* out of range: refused by the driver, never sent */
    check(sdhci_read(&C, C.blocks, 1, rbuf) == DISK_ERANGE, "range refusal", 0);
    check(disk_read(d, d->block_count - 1, 2, rbuf) == DISK_ERANGE, "disk range refusal", 0);
    check(C.ready, "still ready after refusals", 0);
    /* last block */
    fill(wbuf, 512, 99);
    check(disk_write(d, d->block_count - 1, 1, wbuf) == DISK_OK, "write last block", 0);
    /* full re-init (controller reset, card re-identified), data still there */
    rc = sdhci_init(&C, &OPS, &scfg);
    check(rc == SDHCI_OK, "re-init", rc);
    zero(rbuf, 512);
    check(disk_read(d, d->block_count - 1, 1, rbuf) == DISK_OK && same(wbuf, rbuf, 512),
          "last block survives re-init", 0);
    fill(wbuf, 200u * 512u, 4);
    zero(rbuf, 200u * 512u);
    check(disk_read(d, lba - 201, 200, rbuf) == DISK_OK && same(wbuf, rbuf, 200u * 512u),
          "200-block extent survives re-init", 0);
    puts_("payload checks ");
    putdec(checks);
    puts_(", failures ");
    putdec(fails);
    puts_("\n");
    puts_(fails == 0 && checks > 0 ? "SDHCI_QEMU_PAYLOAD: PASS\n" : "SDHCI_QEMU_PAYLOAD: FAIL\n");
}
