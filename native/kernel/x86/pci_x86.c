/* pci_x86.c -- AIENOS-IMAC-KERNEL-1: the PCI walk and the devices it hands
 * out, for the 2017 iMac and QEMU q35.
 *
 * The walk reads the config space of every function in the ECAM window the
 * ACPI MCFG names, buses start..end, honoring the multi-function bit. It
 * remembers each function, then drives, in this order: every AHCI controller
 * (ahci_x86.c), every NVMe controller (native/disk/disk_nvme.c through the
 * glue below) and a READ-ONLY look at a Broadcom Ethernet controller.
 * The only config writes are memory decode and bus mastering for the AHCI and
 * NVMe functions the kernel drives.
 *
 * Disks are read-only here. The NVMe driver resets and enables the controller
 * and creates its queues (no media is touched by that); the kernel then reads
 * through a disk_dev whose write and flush hooks always refuse, and this file
 * never calls nvme_write or nvme_flush (the build checks). Each disk's GPT is
 * checked by dev/disk_part.c. Serial numbers and MAC addresses are never
 * printed. QEMU runs of this path qualify nothing physical. */
#include "../core/ck_internal.h"
#include "../mm/frames.h"
#include "disk.h"
#include "disk_nvme.h"
#include "disk_part.h"
#include "x86.h"

#define PCI_MAX 64u
#define NVME_MAX 2u
#define NVME_DMA_PAGES (NVME_FIXED_PAGES + 32u) /* 128 KiB bounce */

struct pfn {
    volatile uint8_t *cfg;
    uint8_t bus, dev, fn, ht;
    uint16_t vendor, device;
    uint32_t cls;
};

static struct pfn found[PCI_MAX];
static unsigned nfound;
static uint64_t g_tsc_hz;
static struct ck_x86_storage_result res;

static uint32_t cr32(volatile uint8_t *cfg, unsigned off) { return *(volatile uint32_t *)(cfg + off); }
static uint16_t cr16(volatile uint8_t *cfg, unsigned off) { return *(volatile uint16_t *)(cfg + off); }
static void cw16(volatile uint8_t *cfg, unsigned off, uint16_t v) { *(volatile uint16_t *)(cfg + off) = v; }

void ck_x86_disk_report(const char *tag, unsigned ctrl, unsigned index, const disk_dev *dev)
{
    static uint8_t blk[4096];
    if (disk_read(dev, 0, 1, blk) != DISK_OK) {
        ck_printf("%s_read: ctrl=%u disk=%u lba0 read FAILED\n", tag, ctrl, index);
        return;
    }
    ck_printf("%s_read: ctrl=%u disk=%u lba=0 bytes=%u boot_sig=%02x%02x first=%02x%02x%02x%02x\n", tag, ctrl,
              index, dev->block_size, blk[510], blk[511], blk[0], blk[1], blk[2], blk[3]);
    ck_part part;
    ck_gpt_info info;
    int rc = ck_gpt_find_aienos(dev, &part, &info);
    if (rc == CK_GPT_OK) {
        res.gpt_valid++;
        ck_printf("%s_gpt: ctrl=%u disk=%u gpt=valid used=%u aienos first_lba=%llu last_lba=%llu\n", tag, ctrl,
                  index, info.used, (unsigned long long)part.first_lba,
                  (unsigned long long)(part.first_lba + part.blocks - 1));
    } else if (rc == CK_GPT_ENOPART) {
        res.gpt_valid++;
        ck_printf("%s_gpt: ctrl=%u disk=%u gpt=valid used=%u last_lba=%llu, no AIENOS partition, nothing "
                  "written\n", tag, ctrl, index, info.used, (unsigned long long)info.last_lba);
    } else {
        ck_printf("%s_gpt: ctrl=%u disk=%u refused: %s\n", tag, ctrl, index, ck_gpt_strerror(rc));
    }
}

/* ---- NVMe glue ---- */
struct nvme_slot {
    volatile uint8_t *bar;
    nvme_ctrl c;
    disk_dev dev;
};
static struct nvme_slot nvmes[NVME_MAX];

static uint32_t nv_rd32(void *ctx, uint32_t off) { return *(volatile uint32_t *)((volatile uint8_t *)ctx + off); }
static void nv_wr32(void *ctx, uint32_t off, uint32_t v) { *(volatile uint32_t *)((volatile uint8_t *)ctx + off) = v; }
static void nv_barrier(void *ctx)
{
    (void)ctx;
    __asm__ volatile("mfence" ::: "memory");
}
static void nv_delay_us(void *ctx, uint32_t us)
{
    (void)ctx;
    uint64_t t0 = ck_rdtsc(), n = g_tsc_hz / 1000000 * us;
    while (ck_rdtsc() - t0 < n)
        ck_pause();
}
static int ro_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    (void)ctx, (void)lba, (void)count, (void)buf;
    return DISK_ESTATE; /* read-only */
}
static int ro_flush(void *ctx)
{
    (void)ctx;
    return DISK_ESTATE;
}

static void nvme_start(const struct pfn *f, struct ck_frames *fr)
{
    unsigned idx = res.nvme_ctrls++;
    uint32_t lo = cr32(f->cfg, 0x10), hi = (lo & 6) == 4 ? cr32(f->cfg, 0x14) : 0;
    uint64_t bar = ((uint64_t)hi << 32 | lo) & ~0xfull;
    ck_printf("pci: nvme %02x:%02x.%u id=%04x:%04x bar0=0x%llx\n", f->bus, f->dev, f->fn, f->vendor, f->device,
              (unsigned long long)bar);
    if (idx >= NVME_MAX || (lo & 1) || !bar || ck_x86_map_mmio(bar, 0x4000)) {
        ck_printf("nvme: ctrl=%u skipped (BAR0 not a usable memory BAR, or more than %u controllers)\n", idx,
                  NVME_MAX);
        return;
    }
    uint64_t pa;
    if (ck_frames_alloc(fr, NVME_DMA_PAGES, CK_PAGE, &pa)) {
        ck_printf("nvme: ctrl=%u no DMA frames\n", idx);
        return;
    }
    memset((void *)(uintptr_t)pa, 0, NVME_DMA_PAGES * CK_PAGE);
    cw16(f->cfg, 4, (uint16_t)(cr16(f->cfg, 4) | 0x6)); /* memory decode + bus master */
    struct nvme_slot *s = &nvmes[idx];
    s->bar = (volatile uint8_t *)(uintptr_t)bar;
    nvme_ops ops = {(void *)(uintptr_t)bar, nv_rd32, nv_wr32, 0, 0, nv_barrier, nv_delay_us};
    nvme_dma dma = {(uint8_t *)(uintptr_t)pa, pa, NVME_DMA_PAGES * CK_PAGE};
    nvme_config cfg = {0, 0};
    int rc = nvme_init(&s->c, &ops, &dma, &cfg);
    if (rc != NVME_OK) {
        ck_printf("nvme: ctrl=%u init refused rc=%d (no data was read or written)\n", idx, rc);
        return;
    }
    if (nvme_disk(&s->c, &s->dev) != DISK_OK) {
        ck_printf("nvme: ctrl=%u no disk view\n", idx);
        return;
    }
    s->dev.write = ro_write;
    s->dev.flush = ro_flush;
    res.nvme_disks++;
    ck_printf("nvme_disk: ctrl=%u disk=0 version=%u.%u nsid=%u blocks=%llu block=%u mib=%llu access=read-only\n",
              idx, s->c.vs >> 16, (s->c.vs >> 8) & 0xff, s->c.nsid, (unsigned long long)s->c.block_count,
              s->c.block_size, (unsigned long long)(s->c.block_count * s->c.block_size >> 20));
    ck_x86_disk_report("nvme", idx, 0, &s->dev);
}

/* ---- Broadcom Ethernet: a look, nothing driven ----
 * Config reads only, plus, when the chip is awake (D0) with memory decode on,
 * MII reads of the PHY's status and ID through the MAC's MI_COM register. */
#define TG3_MI_COM 0x44c
#define TG3_MI_MODE 0x454
#define MI_START_BUSY 0x20000000u
#define MI_READ 0x08000000u

static int mii_read(volatile uint8_t *bar, unsigned reg, uint16_t *out)
{
    volatile uint32_t *com = (volatile uint32_t *)(bar + TG3_MI_COM);
    *com = MI_READ | MI_START_BUSY | 1u << 21 | (reg & 0x1f) << 16; /* PHY address 1 */
    uint64_t t0 = ck_rdtsc();
    uint32_t v;
    while ((v = *com) & MI_START_BUSY)
        if (ck_rdtsc() - t0 > g_tsc_hz / 100) /* 10 ms */
            return -1;
    *out = (uint16_t)v;
    return 0;
}

static void net_look(const struct pfn *f)
{
    res.net_found++;
    uint32_t lo = cr32(f->cfg, 0x10), hi = (lo & 6) == 4 ? cr32(f->cfg, 0x14) : 0;
    uint64_t bar = ((uint64_t)hi << 32 | lo) & ~0xfull;
    uint16_t cmd = cr16(f->cfg, 4);
    unsigned dstate = 9;
    if (cr16(f->cfg, 6) & 0x10)
        for (unsigned p = cr32(f->cfg, 0x34) & 0xfc, n = 0; p && n < 48; n++) {
            uint32_t h = cr32(f->cfg, p);
            if ((h & 0xff) == 1) {
                dstate = cr16(f->cfg, p + 4) & 3;
                break;
            }
            p = (h >> 8) & 0xfc;
        }
    ck_printf("net: %02x:%02x.%u id=%04x:%04x bar0=0x%llx mem_decode=%u bus_master=%u power=D%u\n", f->bus, f->dev,
              f->fn, f->vendor, f->device, (unsigned long long)bar, cmd & 2 ? 1u : 0u, cmd & 4 ? 1u : 0u, dstate);
    if (f->vendor != 0x14e4 || dstate != 0 || !(cmd & 2) || !bar || ck_x86_map_mmio(bar, 0x10000)) {
        ck_puts("net: PHY not read (not a Broadcom chip, chip asleep, or BAR off)\n");
        return;
    }
    volatile uint8_t *b = (volatile uint8_t *)(uintptr_t)bar;
    uint32_t mode = *(volatile uint32_t *)(b + TG3_MI_MODE);
    if (mode & 0x10) { /* hardware auto-poll owns the MII bus: leave it */
        ck_printf("net: PHY not read (MI auto-poll on, mi_mode=0x%x)\n", mode);
        return;
    }
    uint16_t bmsr = 0, id1 = 0, id2 = 0;
    if (mii_read(b, 1, &bmsr) || mii_read(b, 1, &bmsr) || mii_read(b, 2, &id1) || mii_read(b, 3, &id2)) {
        ck_puts("net: PHY did not answer on the MII bus\n");
        return;
    }
    res.net_link = (bmsr & 4) ? 1 : 2;
    ck_printf("net: phy_id=%04x:%04x bmsr=0x%04x link=%s autoneg_done=%u\n", id1, id2, bmsr, bmsr & 4 ? "up" : "down",
              bmsr & 0x20 ? 1u : 0u);
}

const struct ck_x86_storage_result *ck_x86_storage(uint64_t rsdp, struct ck_frames *fr, uint64_t tsc_hz,
                                                   uint64_t map_top)
{
    g_tsc_hz = tsc_hz;
    (void)map_top; /* device registers above it are mapped on demand (ck_x86_map_mmio) */
    const uint8_t *m = rsdp ? ck_acpi_lookup(rsdp, "MCFG") : 0;
    if (!m) {
        ck_puts("pci: no ACPI MCFG, no devices\n");
        return &res;
    }
    uint32_t len;
    memcpy(&len, m + 4, 4);
    for (uint32_t off = 44; off + 16 <= len; off += 16) {
        uint64_t base;
        uint16_t seg;
        memcpy(&base, m + off, 8);
        memcpy(&seg, m + off + 8, 2);
        uint8_t sb = m[off + 10], eb = m[off + 11];
        if (!base || sb > eb || ck_x86_map_mmio(base + ((uint64_t)sb << 20), (uint64_t)(eb - sb + 1) << 20)) {
            ck_printf("pci: ecam seg=%u at 0x%llx not mappable, skipped\n", seg,
                      (unsigned long long)base);
            continue;
        }
        for (unsigned bus = sb; bus <= eb; bus++)
            for (unsigned dev = 0; dev < 32; dev++)
                for (unsigned fn = 0; fn < 8; fn++) {
                    volatile uint8_t *cfg = (volatile uint8_t *)(uintptr_t)(base + ((uint64_t)bus << 20) +
                                                                            ((uint64_t)dev << 15) +
                                                                            ((uint64_t)fn << 12));
                    uint32_t idr = cr32(cfg, 0);
                    if ((idr & 0xffff) == 0xffff || (idr & 0xffff) == 0) {
                        if (fn == 0)
                            break;
                        continue;
                    }
                    res.pci_functions++;
                    uint8_t ht = (uint8_t)(cr32(cfg, 0x0c) >> 16);
                    if (nfound < PCI_MAX)
                        found[nfound++] = (struct pfn){cfg, (uint8_t)bus, (uint8_t)dev, (uint8_t)fn, ht,
                                                       (uint16_t)idr, (uint16_t)(idr >> 16), cr32(cfg, 8) >> 8};
                    if (fn == 0 && !(ht & 0x80))
                        break;
                }
    }

    for (unsigned i = 0; i < nfound; i++) {
        const struct pfn *f = &found[i];
        if (f->cls != 0x010601 || (f->ht & 0x7f) != 0)
            continue;
        uint32_t bar = cr32(f->cfg, 0x24);
        uint64_t abar = bar & ~0xfu;
        ck_printf("pci: ahci %02x:%02x.%u id=%04x:%04x bar5=0x%x\n", f->bus, f->dev, f->fn, f->vendor, f->device, bar);
        if ((bar & 1) || (bar & 6) || !abar || ck_x86_map_mmio(abar, 0x1100)) {
            ck_puts("ahci: BAR5 is not a usable 32-bit memory BAR, controller skipped\n");
        } else {
            cw16(f->cfg, 4, (uint16_t)(cr16(f->cfg, 4) | 0x6)); /* memory decode + bus master */
            ck_x86_ahci_start(res.ahci_ctrls, abar, fr, tsc_hz);
        }
        res.ahci_ctrls++;
    }
    res.ahci_disks = ck_x86_ahci_disks();
    for (unsigned i = 0; i < nfound; i++)
        if (found[i].cls == 0x010802 && (found[i].ht & 0x7f) == 0)
            nvme_start(&found[i], fr);
    for (unsigned i = 0; i < nfound; i++)
        if ((found[i].cls >> 8) == 0x0200 && (found[i].ht & 0x7f) == 0)
            net_look(&found[i]);
    if (!res.net_found)
        ck_puts("net: no Ethernet controller\n");
    ck_printf("storage: pci_functions=%u ahci_controllers=%u disks=%u nvme_controllers=%u nvme_disks=%u "
              "gpt_valid=%u writes=none\n", res.pci_functions, res.ahci_ctrls, res.ahci_disks, res.nvme_ctrls,
              res.nvme_disks, res.gpt_valid);
    return &res;
}
