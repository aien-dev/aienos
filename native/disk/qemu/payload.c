/*
 * payload.c -- bare-metal AArch64 test of native/disk/disk_nvme.c against
 * QEMU's emulated NVMe controller on the "virt" machine (highmem=off, so the
 * PCIe ECAM sits at 0x3f000000 and the 32-bit MMIO window at 0x10000000).
 * MMU off: every access is Device-nGnRnE and nothing is cached, so the DMA
 * region needs no cache maintenance; the barrier op is DSB SY.
 *
 * QEMU is an emulator. A PASS here says the C driver works against QEMU's
 * NVMe model; it says nothing about any physical controller.
 */
#include <stdint.h>
#include "../disk.h"
#include "../disk_nvme.h"

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
static void bar(void *c) { (void)c; __asm__ volatile("dsb sy" ::: "memory"); }
static uint64_t cntfrq(void) { uint64_t v; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v)); return v; }
static uint64_t cntvct(void) { uint64_t v; __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(v)); return v; }
static void delay(void *c, uint32_t us)
{
    (void)c;
    uint64_t f = cntfrq(), t0 = cntvct(), ticks = (f * us) / 1000000u + 1;
    while (cntvct() - t0 < ticks)
        ;
}

/* ---- PCIe: find the NVMe function, assign BAR0, enable MEM + bus master ---- */
static volatile uint32_t *cfg(uint32_t bus, uint32_t dev, uint32_t fn, uint32_t off)
{
    return (volatile uint32_t *)(ECAM + (bus << 20) + (dev << 15) + (fn << 12) + off);
}
static int pci_find_nvme(void)
{
    for (uint32_t d = 0; d < 32; d++) {
        uint32_t id = *cfg(0, d, 0, 0);
        if ((id & 0xffff) == 0xffff) continue;
        uint32_t cls = *cfg(0, d, 0, 8) >> 8; /* class/subclass/progif */
        if (cls != 0x010802) continue;
        puts_("pci: NVMe at 00:");
        putdec(d);
        puts_(".0 id ");
        puthex(id);
        puts_("\n");
        *cfg(0, d, 0, 4) = 0; /* disable decode while sizing */
        *cfg(0, d, 0, 0x10) = 0xffffffffu;
        uint32_t lo = *cfg(0, d, 0, 0x10);
        int is64 = ((lo >> 1) & 3) == 2;
        uint32_t size = ~(lo & ~0xfu) + 1;
        if (size == 0 || size > 0x1000000) { puts_("pci: bad BAR0 size\n"); return -1; }
        *cfg(0, d, 0, 0x10) = (uint32_t)MMIO_BASE;
        if (is64) *cfg(0, d, 0, 0x14) = 0;
        *cfg(0, d, 0, 4) = (1u << 1) | (1u << 2); /* memory space + bus master */
        bar0 = (volatile uint8_t *)MMIO_BASE;
        puts_("pci: BAR0 size ");
        puthex(size);
        puts_(is64 ? " 64-bit\n" : " 32-bit\n");
        return 0;
    }
    return -1;
}

/* ---- DMA region (identity mapped: phys == virt with the MMU off) ---- */
#define DMA_BYTES (6u * 4096u + 128u * 1024u)
static uint8_t dma_mem[DMA_BYTES] __attribute__((aligned(4096)));
static uint8_t wbuf[300u * 1024u], rbuf[300u * 1024u];

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

static nvme_ctrl C;
static const nvme_ops OPS = {0, r32, w32, 0, 0, bar, delay};

static void run_namespace(uint32_t nsid, uint32_t want_bs)
{
    nvme_dma dma = {dma_mem, (uint64_t)(uintptr_t)dma_mem, DMA_BYTES};
    nvme_config cfg = {nsid, 0};
    int rc = nvme_init(&C, &OPS, &dma, &cfg);
    check(rc == NVME_OK, "nvme_init", rc);
    if (rc) return;
    puts_("ns ");
    putdec(C.nsid);
    puts_(": block_size ");
    putdec(C.block_size);
    puts_(" blocks ");
    putdec((int64_t)C.block_count);
    puts_(" max_xfer ");
    putdec(C.max_xfer_bytes);
    puts_(" vwc ");
    putdec(C.vwc);
    puts_(" vs ");
    puthex(C.vs);
    puts_("\n");
    check(C.block_size == want_bs, "block size", C.block_size);
    disk_dev d;
    rc = nvme_disk(&C, &d);
    check(rc == DISK_OK, "nvme_disk", rc);
    if (rc) return;
    uint32_t bs = d.block_size;
    uint32_t sizes[] = {1, 8, (128u * 1024u) / bs, (300u * 1024u) / bs};
    uint64_t lba = 3;
    for (uint32_t i = 0; i < 4; i++) {
        uint32_t n = sizes[i], bytes = n * bs;
        fill(wbuf, bytes, nsid * 10 + i);
        rc = disk_write(&d, lba, n, wbuf);
        check(rc == DISK_OK, "disk_write", rc);
        zero(rbuf, bytes);
        rc = disk_read(&d, lba, n, rbuf);
        check(rc == DISK_OK, "disk_read", rc);
        check(same(wbuf, rbuf, bytes), "read-back matches write", n);
        lba += n + 1;
    }
    check(disk_flush(&d) == DISK_OK, "flush", 0);
    /* out of range: refused by the driver, never sent */
    check(nvme_read(&C, d.block_count, 1, rbuf) == NVME_ERANGE, "range refusal", 0);
    check(disk_read(&d, d.block_count - 1, 2, rbuf) == DISK_ERANGE, "disk range refusal", 0);
    /* last block works */
    fill(wbuf, bs, 99);
    check(disk_write(&d, d.block_count - 1, 1, wbuf) == DISK_OK, "write last block", 0);
    check(disk_flush(&d) == DISK_OK, "flush 2", 0);
    /* controller reset (disable + full re-init), data still there */
    check(nvme_disable(&C) == NVME_OK, "disable", 0);
    check(nvme_read(&C, 0, 1, rbuf) == NVME_ESTATE, "I/O refused while disabled", 0);
    rc = nvme_init(&C, &OPS, &dma, &cfg);
    check(rc == NVME_OK, "re-init", rc);
    zero(rbuf, bs);
    check(nvme_read(&C, d.block_count - 1, 1, rbuf) == NVME_OK && same(wbuf, rbuf, bs),
          "last block survives controller reset", 0);
    uint32_t n = (300u * 1024u) / bs;
    fill(wbuf, n * bs, nsid * 10 + 3);
    zero(rbuf, n * bs);
    check(disk_read(&d, lba - n - 1, n, rbuf) == DISK_OK && same(wbuf, rbuf, n * bs),
          "300 KiB extent survives controller reset", 0);
    check(nvme_disable(&C) == NVME_OK, "final disable", 0);
}

void payload_main(void)
{
    puts_("AIENOS native NVMe payload (C driver, QEMU virt)\n");
    if (pci_find_nvme()) {
        puts_("no NVMe function found\nNVME_QEMU_PAYLOAD: FAIL\n");
        return;
    }
    run_namespace(0, 512);  /* first active namespace: 512 B LBAs */
    run_namespace(2, 4096); /* second namespace: 4 KiB LBAs */
    puts_("payload checks ");
    putdec(checks);
    puts_(", failures ");
    putdec(fails);
    puts_("\n");
    puts_(fails == 0 && checks > 0 ? "NVME_QEMU_PAYLOAD: PASS\n" : "NVME_QEMU_PAYLOAD: FAIL\n");
}
