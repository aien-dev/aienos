/* nvme_bind.c -- NVMe binding through ck.h (see nvme_bind.h). Freestanding. */
#include "nvme_bind.h"
#include "nvme_shutdown.h"
#include "ck.h"
#include "disk_layout.h"

/* NVMe DMA rule: no SMMU confinement means no DMA. The default build asks
 * the core for SMMU confinement (ck_dma_confine) and refuses NVMe DMA when
 * there is no SMMU or it did not come up (fail-closed). The unconfined
 * bypass is TEST-ONLY: it exists only for QEMU without an SMMU, only when a
 * QEMU gate script asks for it with CK_QEMU_UNSAFE_DMA=1, and is never used
 * when an SMMU is present; it can never be combined with a hardware-staging
 * build (same rule as the compile_error! in crates/aienos-boot/src/lib.rs). */
#if defined(CK_NVME_DMA_BYPASS)
#error "CK_NVME_DMA_BYPASS is retired: the unconfined NVMe DMA bypass is CK_QEMU_UNSAFE_DMA=1 (QEMU only)"
#endif
#if defined(CK_QEMU_UNSAFE_DMA) && defined(CK_HARDWARE_STAGING)
#error "CK_QEMU_UNSAFE_DMA (unconfined DMA, QEMU debug only) cannot be combined with CK_HARDWARE_STAGING: no SMMU confinement means no DMA"
#endif
#if defined(CK_QEMU_UNSAFE_DMA) && CK_QEMU_UNSAFE_DMA == 1
#define CK_NVME_UNSAFE_BYPASS 1
#elif defined(CK_QEMU_UNSAFE_DMA) && CK_QEMU_UNSAFE_DMA != 0
#error "CK_QEMU_UNSAFE_DMA must be 0 or 1"
#else
#define CK_NVME_UNSAFE_BYPASS 0
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
static uint8_t probe_orig[CK_LAYOUT_UNIT];

/* SMMU negative test (confined mode only). The driver's bounce-buffer bus
 * address is pointed at a pattern-filled page that is NOT in the stream's
 * window and a one-block read of LBA 0 is issued, so the controller tries
 * to DMA into that page. Pass: the SMMU records a translation fault for this
 * stream at that page, the page keeps its pattern (the write never landed),
 * and after restoring the bounce address a normal read works again. The
 * read's own status is reported but not judged (QEMU may complete it). */
static int smmu_negative_test(ck_nvme *n)
{
    uint64_t cphys = 0;
    volatile uint8_t *canary = ck_dma_alloc(NVME_PAGE, NVME_PAGE, &cphys);
    if (!canary) {
        ck_printf("smmu_negative: FAIL (no canary page)\n");
        return -1;
    }
    for (uint32_t i = 0; i < NVME_PAGE; i++)
        canary[i] = 0x5a;
    (void)ck_dma_faults(n->stream_id, 0); /* drain anything older */
    nvme_ctrl *c = &n->ctrl;
    uint64_t saved = c->bounce_phys;
    c->bounce_phys = cphys;
    ck_mb();
    int rc = disk_read(&n->disk, 0, 1, probe_rd);
    c->bounce_phys = saved;
    ck_mb();
    struct ck_dma_fault fl = { 0, 0, 0, 0 };
    int faults = ck_dma_faults(n->stream_id, &fl);
    int intact = 1;
    for (uint32_t i = 0; i < NVME_PAGE; i++)
        if (canary[i] != 0x5a) intact = 0;
    int rc2 = disk_read(&n->disk, 0, 1, probe_rd);
    int ok = faults >= 1 && fl.type == CK_DMA_FAULT_TRANSLATION && fl.stream_id == n->stream_id &&
             (fl.addr & ~(uint64_t)(NVME_PAGE - 1u)) == cphys && intact && rc2 == 0;
    ck_printf("smmu_negative: %s dma outside window iova=0x%llx faults=%d type=0x%x sid=0x%x addr=0x%llx "
              "page=%s cmd_rc=%d recovery_read=%s\n",
              ok ? "refused" : "FAIL", (unsigned long long)cphys, faults, fl.type, fl.stream_id,
              (unsigned long long)fl.addr, intact ? "intact" : "MODIFIED", rc, rc2 ? "FAIL" : "ok");
    return ok ? 0 : -1;
}

int ck_disk_rw_probe(const disk_dev *d, uint32_t seed, uint64_t *lba_out)
{
    uint32_t bpu = CK_LAYOUT_UNIT / d->block_size;
    uint64_t units = d->block_count / bpu;
    if (units < 1) return DISK_EGEOMETRY;
    uint64_t lba = (units - 1u) * bpu;
    if (lba_out) *lba_out = lba;
    int rc = disk_read(d, lba, bpu, probe_orig);
    if (rc) return rc;
    uint32_t x = seed ? seed : 0x9e3779b9u;
    for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        probe_buf[i] = (uint8_t)x;
        probe_rd[i] = 0;
    }
    rc = disk_write(d, lba, bpu, probe_buf);
    if (rc) return rc;
    rc = disk_flush(d);
    if (rc) return rc;
    rc = disk_read(d, lba, bpu, probe_rd);
    if (rc) return rc;
    int match = 1;
    for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++)
        if (probe_rd[i] != probe_buf[i]) match = 0;
    /* Put the original bytes back, durably, and verify them. */
    rc = disk_write(d, lba, bpu, probe_orig);
    if (rc) return rc;
    rc = disk_flush(d);
    if (rc) return rc;
    rc = disk_read(d, lba, bpu, probe_rd);
    if (rc) return rc;
    for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++)
        if (probe_rd[i] != probe_orig[i]) return DISK_EIO;
    return match ? DISK_OK : DISK_EIO;
}

int ck_nvme_bind(ck_nvme *n, const pci_found *found, uint32_t nfound, const pci_system *probe)
{
    /* Ownership first: one owner at a time. A refused call changes nothing. */
    if (n->claimed) {
        ck_printf("nvme: bind refused, already owned by seg %04x %02x:%02x.%u (bound=%d bm_on=%d confined=%d)\n",
                  n->fn.segment, n->fn.bus, n->fn.dev, n->fn.fn, n->bound, n->bm_on, n->confined);
        return NVME_ESTATE;
    }
    n->bound = 0;
    n->bm_on = 0;
    n->confined = 0;
    n->shut = 0;
    n->stream_id = 0;
    n->pf = 0;
#if CK_NVME_UNSAFE_BYPASS
    ck_printf("WARNING: UNSAFE NVME DMA BYPASS BUILD (CK_QEMU_UNSAFE_DMA=1, QEMU debug only, TEST-ONLY)\n");
#endif
#if defined(CK_TEST_DISK_XLATE_BYPASS)
    ck_printf("WARNING: TEST-ONLY DISK TRANSLATION BYPASS BUILD (CK_TEST_DISK_XLATE_BYPASS=1, DISK_LAYOUT "
              "mutation; never counts toward a PASS)\n");
#endif
    uint32_t cands = 0;
    const pci_found *cand = pci_disc_find_class(found, nfound, 0x010802u, 0xffffffu, &cands);
    if (!cand) {
        ck_printf("nvme: no class 0x010802 function\n");
        return -1;
    }
    pci_bus_access acc;
    if (pci_stage_disc_access(cand->segment, cand->bus, &acc)) {
        ck_printf("nvme: unavailable (no mapped ECAM for seg %04x bus %02x)\n", cand->segment, cand->bus);
        return NVME_EARG;
    }
    n->claimed = 1; /* recorded once, before the device is touched */
    if (pci_func_from_found(&n->fn, cand, &acc)) {
        /* Refused before any write to the device: as if the bind was never attempted. */
        n->claimed = 0;
        ck_printf("nvme: unavailable (seg %04x %02x:%02x.%u cannot be read as an endpoint; nothing written, not owned)\n",
                  cand->segment, cand->bus, cand->dev, cand->fn);
        return NVME_EARG;
    }
    if (probe) /* keep the log wording for a function the segment-0 stage assigned */
        for (uint32_t i = 0; i < probe->n; i++) {
            const pci_func *p = &probe->f[i];
            if (p->segment == n->fn.segment && p->bus == n->fn.bus && p->dev == n->fn.dev && p->fn == n->fn.fn)
                for (uint32_t b = 0; b < PCI_MAX_BARS; b++) n->fn.bar[b].assigned_here = p->bar[b].assigned_here;
        }
    const pci_func *f = n->pf = &n->fn;
    if (cands > 1)
        ck_printf("nvme: %u class 0x010802 functions in discovery, binding the lowest segment/bus/dev/fn only\n", cands);
    /* A function firmware left with bus mastering on must not be live before the DMA gate. */
    if (cand->command & 0x4u) {
        int brc = pci_bus_master_off(f);
        ck_printf("nvme: firmware left bus master on, cleared before the DMA gate (%s)\n", brc ? "STUCK" : "ok");
        if (brc) {
            ck_printf("nvme: unavailable (bus master would not clear; the device was written, so it stays owned, fail closed)\n");
            return NVME_ESTATE;
        }
    }
    const pci_bar *b = &f->bar[0];
    ck_printf("nvme: discovery %02x:%02x.%u vid=0x%04x did=0x%04x bar0=0x%llx size=0x%llx%s\n", f->bus, f->dev,
              f->fn, f->vendor, f->device, (unsigned long long)b->addr, (unsigned long long)b->size,
              b->assigned_here ? " (assigned by stage)" : " (firmware)");
    if (b->io || b->addr == 0 || b->size < 0x2000u) {
        ck_printf("nvme: unavailable (BAR0 unusable)\n");
        return NVME_EARG;
    }
    /* DMA gate (same policy as the Rust dma_gate::dma_grant): SMMU
     * confinement first; with no SMMU at all, only the QEMU-only unsafe
     * bypass build may enable DMA; an SMMU that is present but did not come
     * up never falls back to the bypass. The DMA region is allocated first
     * so the confinement window is exactly the region the driver uses. */
    uint64_t phys = 0;
    uint8_t *dma = ck_dma_alloc(CK_NVME_DMA_BYTES, NVME_PAGE, &phys);
    if (!dma) {
        ck_printf("nvme: unavailable (DMA allocation of %u bytes failed)\n", (unsigned)CK_NVME_DMA_BYTES);
        return NVME_EARG;
    }
    uint32_t rid = ((uint32_t)f->bus << 8) | ((uint32_t)f->dev << 3) | (uint32_t)f->fn;
    uint64_t win = ((uint64_t)CK_NVME_DMA_BYTES + NVME_PAGE - 1u) & ~(uint64_t)(NVME_PAGE - 1u);
    struct ck_dma_confinement cf;
    int src = ck_dma_confine(f->segment, rid, phys, win, &cf);
    if (src == 0) {
        n->confined = 1;
        n->stream_id = cf.stream_id;
        ck_printf("smmu: enabled base=0x%llx stream_id=0x%x\n", (unsigned long long)cf.smmu_base, cf.stream_id);
        ck_printf("smmu_dma_window: nvme only, translation active iova=0x%llx len=0x%llx rid=0x%x\n",
                  (unsigned long long)cf.iova, (unsigned long long)cf.len, rid);
        ck_printf("dma_gate: nvme granted (Confined), bus master on\n");
    } else if (src == CK_SMMU_ABSENT) {
#if CK_NVME_UNSAFE_BYPASS
        ck_printf("WARNING: UNSAFE NVME DMA BYPASS ACTIVE (no SMMU on this machine; device can DMA anywhere; TEST-ONLY build)\n");
        ck_printf("dma_gate: nvme granted (UnsafeBypass), bus master on\n");
#else
        ck_printf("dma_gate: nvme denied (NoSmmu), bus master stays off\n");
        ck_printf("nvme: unavailable (SMMU DMA isolation not active)\n");
        return NVME_ESTATE;
#endif
    } else {
        ck_printf("dma_gate: nvme denied (SmmuNotReady rc=%d), bus master stays off\n", src);
        ck_printf("nvme: unavailable (SMMU DMA isolation not active)\n");
        return NVME_ESTATE;
    }
    n->bar0 = (volatile uint8_t *)ck_mmio_map(b->addr, (size_t)b->size);
    pci_enable(f, 1);
    n->bm_on = 1;
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
    /* Partition-aware footprint (dev/disk_part.h, audit R2): the GPT is
     * parsed read-only; without exactly one valid AIENOS partition nothing is
     * ever written to this disk and there is no whole-disk fallback. */
    ck_gpt_info gi;
    rc = ck_gpt_find_aienos(&n->disk, &n->part, &gi);
    if (rc) {
        ck_printf("disk: no AIENOS partition, refusing writes (gpt: %s, rc=%d)\n", ck_gpt_strerror(rc), rc);
        return rc;
    }
    ck_printf("disk: gpt ok primary+backup crc32 entries=%u used=%u aienos_index=%u first_lba=%llu "
              "last_lba=%llu blocks=%llu\n",
              gi.entries, gi.used, gi.part_index, (unsigned long long)n->part.first_lba,
              (unsigned long long)(n->part.first_lba + n->part.blocks - 1u), (unsigned long long)n->part.blocks);
    /* The translation layer itself (no I/O): partition LBA 0 maps to the
     * partition start; past the end, straddling the end and an overflowing
     * LBA are refused. Any of these not refused: stop before any write. */
    uint64_t a0 = 0, ax = 0;
    int x0 = ck_part_xlate(&n->part, 0, 1, &a0);
    int x1 = ck_part_xlate(&n->part, n->part.blocks, 1, &ax);
    int x2 = ck_part_xlate(&n->part, n->part.blocks - 1u, 2, &ax);
    int x3 = ck_part_xlate(&n->part, ~(uint64_t)0, 1, &ax);
    int xok = x0 == DISK_OK && x1 == DISK_ERANGE && x2 == DISK_ERANGE && x3 == DISK_ERANGE;
    ck_printf("disk: xlate part_lba=0 -> disk_lba=%llu (rc=%d)\n", (unsigned long long)a0, x0);
    ck_printf("disk: write past partition end part_lba=%llu -> %s (xlate rc=%d,%d,%d)\n", (unsigned long long)n->part.blocks,
              xok ? "refused" : "NOT REFUSED", x1, x2, x3);
    if (!xok) return DISK_ERANGE; /* not -1: devices.c reads -1 as "no NVMe present" */
    uint64_t lba = 0, dlba = 0;
    rc = ck_disk_rw_probe(&n->part.dev, (uint32_t)ck_time_us() ^ 0xa5a5a5a5u, &lba);
    int xr = ck_part_xlate(&n->part, lba, CK_LAYOUT_UNIT / n->part.dev.block_size, &dlba);
    ck_printf("nvme: rw probe part_lba=%llu disk_lba=%llu bytes=%u write+flush+readback %s (rc=%d)\n",
              (unsigned long long)lba, (unsigned long long)dlba, CK_LAYOUT_UNIT, rc ? "FAIL" : "match", rc);
    if (rc) return rc;
    if (xr) return DISK_ERANGE;
    if (n->confined) {
        rc = smmu_negative_test(n);
        if (rc) return DISK_EIO;
    }
    n->bound = 1;
    return 0;
}

int ck_nvme_shutdown_bound(ck_nvme *n)
{
    if (!n || !n->bar0 || !n->bm_on || n->shut)
        return CK_NVME_SHUT_EARG;
    n->shut = 1;
    struct ck_nvme_shut_ops o = {n, m_r32, m_w32, m_barrier, m_delay};
    struct ck_nvme_shut_result r = {0, 0, 0, 0};
    int rc = ck_nvme_shutdown(&o, CK_NVME_SHUT_TIMEOUT_US, &r);
    ck_printf("nvme: shutdown normal cc=0x%08x->0x%08x csts=0x%08x shst=%s waited_us=%u\n", r.cc_before,
              r.cc_after, r.csts, ck_nvme_shutdown_str(rc), r.waited_us);
    if (ck_nvme_shutdown_needs_disable(rc)) {
        /* The controller may still be live: stop it (CC.EN = 0, wait for
         * CSTS.RDY = 0) before the caller cuts bus mastering. */
        struct ck_nvme_shut_result d = {0, 0, 0, 0};
        int drc = ck_nvme_disable(&o, CK_NVME_DISABLE_TIMEOUT_US, &d);
        ck_printf("nvme: shutdown fallback disable cc=0x%08x->0x%08x csts=0x%08x rdy0=%s waited_us=%u\n",
                  d.cc_before, d.cc_after, d.csts, ck_nvme_shutdown_str(drc), d.waited_us);
    }
    return rc;
}
