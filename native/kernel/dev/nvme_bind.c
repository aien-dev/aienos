/* nvme_bind.c -- NVMe binding through ck.h (see nvme_bind.h). Freestanding. */
#include "nvme_bind.h"
#include "ck.h"
#include "disk_layout.h"

#ifndef CK_NVME_DMA_BYPASS
#define CK_NVME_DMA_BYPASS 0
#endif

static uint32_t m_r32(void *ctx, uint32_t off)
{
    ck_nvme *n = ctx;
    return *(volatile uint32_t *)(n->bar0 + off);
}
static void m_w32(void *ctx, uint32_t off, uint32_t v)
{
    ck_nvme *n = ctx;
    *(volatile uint32_t *)(n->bar0 + off) = v;
}
static void m_barrier(void *ctx)
{
    (void)ctx;
    ck_mb();
}
static void m_delay(void *ctx, uint32_t us)
{
    (void)ctx;
    ck_udelay(us);
}

static uint8_t probe_buf[CK_LAYOUT_UNIT];
static uint8_t probe_rd[CK_LAYOUT_UNIT];

int ck_disk_rw_probe(const disk_dev *d, uint32_t seed, uint64_t *lba_out)
{
    uint32_t bpu = CK_LAYOUT_UNIT / d->block_size;
    uint64_t units = d->block_count / bpu;
    if (units < 1) return DISK_EGEOMETRY;
    uint64_t lba = (units - 1u) * bpu;
    if (lba_out) *lba_out = lba;
    uint32_t x = seed ? seed : 0x9e3779b9u;
    for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        probe_buf[i] = (uint8_t)x;
        probe_rd[i] = 0;
    }
    int rc = disk_write(d, lba, bpu, probe_buf);
    if (rc) return rc;
    rc = disk_flush(d);
    if (rc) return rc;
    rc = disk_read(d, lba, bpu, probe_rd);
    if (rc) return rc;
    for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++)
        if (probe_rd[i] != probe_buf[i]) return DISK_EIO;
    return DISK_OK;
}

int ck_nvme_bind(ck_nvme *n, const pci_system *pci)
{
    n->bound = 0;
    const pci_func *f = pci_find_class(pci, 0x010802u, 0xffffffu);
    if (!f) {
        ck_printf("nvme: no class 0x010802 function\n");
        return -1;
    }
    n->pf = f;
    const pci_bar *b = &f->bar[0];
    ck_printf("nvme: discovery %02x:%02x.%u vid=0x%04x did=0x%04x bar0=0x%llx size=0x%llx%s\n", f->bus, f->dev,
              f->fn, f->vendor, f->device, (unsigned long long)b->addr, (unsigned long long)b->size,
              b->assigned_here ? " (assigned by stage)" : " (firmware)");
    if (b->io || b->addr == 0 || b->size < 0x2000u) {
        ck_printf("nvme: unavailable (BAR0 unusable)\n");
        return NVME_EARG;
    }
    /* DMA gate. The ck core has no SMMU service, so DMA cannot be confined
     * to a window. The Rust kernel denies NVMe DMA without an SMMU unless
     * built with its unsafe bypass; this stage mirrors that choice at build
     * time (CK_NVME_DMA_BYPASS). */
#if CK_NVME_DMA_BYPASS
    ck_printf("WARNING: UNSAFE NVME DMA BYPASS ACTIVE (ck core has no SMMU service; device can DMA anywhere)\n");
    ck_printf("dma_gate: nvme granted (UnsafeBypass), bus master on\n");
#else
    ck_printf("dma_gate: nvme denied (NoSmmu), bus master stays off\n");
    ck_printf("nvme: unavailable (SMMU DMA isolation not active)\n");
    return NVME_ESTATE;
#endif
    n->bar0 = (volatile uint8_t *)ck_mmio_map(b->addr, (size_t)b->size);
    pci_enable(f, 1);
    uint64_t phys = 0;
    uint8_t *dma = ck_dma_alloc(CK_NVME_DMA_BYTES, NVME_PAGE, &phys);
    if (!dma) {
        ck_printf("nvme: unavailable (DMA allocation of %u bytes failed)\n", (unsigned)CK_NVME_DMA_BYTES);
        return NVME_EARG;
    }
    nvme_ops ops = {n, m_r32, m_w32, 0, 0, m_barrier, m_delay};
    nvme_dma region = {dma, phys, CK_NVME_DMA_BYTES};
    nvme_config cfg = {0, 0};
    int rc = nvme_init(&n->ctrl, &ops, &region, &cfg);
    if (rc) {
        ck_printf("nvme: identify FAIL (init rc=%d last_err=%d)\n", rc, n->ctrl.last_err);
        return rc;
    }
    nvme_ctrl *c = &n->ctrl;
    ck_printf("nvme: identify ok vs=0x%08x nn=%u nsid=%u mdts=%u vwc=%u max_xfer=%u\n", c->vs, c->nn, c->nsid,
              c->mdts, c->vwc, c->max_xfer_bytes);
    ck_printf("nvme: geometry nsid=%u block_count=%llu block_size=%u\n", c->nsid,
              (unsigned long long)c->block_count, c->block_size);
    ck_printf("nvme: atomicity block_size=%u awupf_raw=%u nawupf_raw=%u nabspf_raw=%u nabo_blocks=%u\n",
              c->block_size, c->awupf_raw, c->nawupf_raw, c->nabspf_raw, c->nabo_blocks);
    rc = nvme_disk(c, &n->disk);
    if (rc) {
        ck_printf("nvme: disk_dev refused rc=%d\n", rc);
        return rc;
    }
    /* Bounds: a read past the namespace end is refused before any command. */
    uint8_t *one = probe_rd;
    rc = disk_read(&n->disk, c->block_count, 1, one);
    ck_printf("nvme: bounds read lba=%llu -> %s (rc=%d)\n", (unsigned long long)c->block_count,
              rc == DISK_ERANGE ? "refused" : "NOT REFUSED", rc);
    if (rc != DISK_ERANGE) return DISK_EIO;
    rc = disk_read(&n->disk, 0, 1, one);
    ck_printf("nvme: read lba=0 blocks=1 %s (rc=%d)\n", rc ? "FAIL" : "ok", rc);
    if (rc) return rc;
    uint64_t lba = 0;
    rc = ck_disk_rw_probe(&n->disk, (uint32_t)ck_time_us() ^ 0xa5a5a5a5u, &lba);
    ck_printf("nvme: rw probe lba=%llu bytes=%u write+flush+readback %s (rc=%d)\n", (unsigned long long)lba,
              CK_LAYOUT_UNIT, rc ? "FAIL" : "match", rc);
    if (rc) return rc;
    n->bound = 1;
    return 0;
}
