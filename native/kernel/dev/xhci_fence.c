/* xhci_fence.c -- xHCI DMA fence (see xhci_fence.h). Freestanding. */
#include "xhci_fence.h"
#include "ck.h"
#include "usb_kbd.h"
#include "xhci_acpi_fmt.h"

#if defined(CK_TEST_XHCI_MUTATION) && defined(CK_HARDWARE_STAGING)
#error "CK_TEST_XHCI_MUTATION (TEST-ONLY xHCI DMA fence mutation) cannot be combined with CK_HARDWARE_STAGING"
#endif
#if defined(CK_TEST_XHCI_MUTATION) && defined(CK_QEMU_UNSAFE_DMA)
#error "CK_TEST_XHCI_MUTATION cannot be combined with CK_QEMU_UNSAFE_DMA"
#endif
#if defined(CK_TEST_XHCI_MUTATION)
#if CK_TEST_XHCI_MUTATION < 1 || CK_TEST_XHCI_MUTATION > 4
#error "CK_TEST_XHCI_MUTATION must be 1..4 (bm-left-on, no-revoke, grant-no-smmu, no-sweep)"
#endif
#define CK_XHCI_MUT CK_TEST_XHCI_MUTATION
#else
#define CK_XHCI_MUT 0
#endif

#define CMD_MEM 0x2u
#define CMD_BM 0x4u
/* xHCI capability / operational registers (xHCI 1.2 sections 5.3, 5.4). */
#define XHCI_CAPLENGTH 0x00u /* bits 7:0 CAPLENGTH, 31:16 HCIVERSION */
#define XHCI_USBCMD 0x00u    /* operational */
#define XHCI_USBSTS 0x04u
#define USBCMD_RS 0x1u
#define USBCMD_HCRST 0x2u
#define USBSTS_HCH 0x1u
#define USBSTS_CNR 0x800u

typedef struct {
    const pci_func *pf;
    int plat;      /* ACPI platform controller (no PCI function, no bus-master bit) */
    char name[48]; /* its ACPI name (platform only) */
    volatile uint8_t *bar0;
    uint32_t op; /* operational register offset (CAPLENGTH) */
    int bm_on, confined, mapped;
    uint32_t stream_id;
    const char *state;
} ck_xhci;

static ck_xhci g_x;
static uint8_t *g_dma_mem;
static uint64_t g_dma_phys;

static uint32_t x_r32(uint32_t off) { return *(volatile uint32_t *)(g_x.bar0 + off); }
static void x_w32(uint32_t off, uint32_t v) { *(volatile uint32_t *)(g_x.bar0 + off) = v; }

int ck_xhci_live(void) { return (g_x.pf || g_x.plat) && (g_x.bm_on || g_x.confined); }
const char *ck_xhci_state(void) { return g_x.state ? g_x.state : "absent"; }

#if CK_XHCI_MUT
static const char *mut_name(void)
{
    switch (CK_XHCI_MUT) {
    case CK_XHCI_MUT_BM_LEFT_ON: return "bm-left-on";
    case CK_XHCI_MUT_NO_REVOKE: return "no-revoke";
    case CK_XHCI_MUT_GRANT_NO_SMMU: return "grant-no-smmu";
    default: return "no-sweep";
    }
}
#endif

int ck_xhci_sweep_enabled(void)
{
#if CK_XHCI_MUT
    ck_printf("WARNING: TEST-ONLY xHCI MUTATION BUILD (CK_TEST_XHCI_MUTATION=%s, QEMU gate self-test only, "
              "never a PASS)\n", mut_name());
#endif
    return CK_XHCI_MUT != CK_XHCI_MUT_NO_SWEEP;
}

void ck_xhci_after_sweep(const pci_system *pci)
{
#if CK_XHCI_MUT == CK_XHCI_MUT_BM_LEFT_ON
    const pci_func *f = pci_find_class(pci, CK_XHCI_CLASS, 0xffffffu);
    if (f) pci_w16(f->cfg, 0x04, (uint16_t)(pci_r16(f->cfg, 0x04) | CMD_BM));
#else
    (void)pci;
#endif
}

/* Make sure the controller is halted (R/S = 0, wait for HCH) while it may
 * still DMA. Returns 0 when USBSTS.HCH reads 1. */
static int halt(const char *when)
{
    if (!g_x.mapped) return 0;
    uint32_t cmd = x_r32(g_x.op + XHCI_USBCMD);
    if (cmd & USBCMD_RS) x_w32(g_x.op + XHCI_USBCMD, cmd & ~USBCMD_RS);
    uint64_t t0 = ck_time_us();
    uint32_t sts;
    while (!((sts = x_r32(g_x.op + XHCI_USBSTS)) & USBSTS_HCH) && ck_time_us() - t0 < CK_XHCI_HALT_WAIT_US)
        ck_udelay(10);
    int ok = (sts & USBSTS_HCH) != 0;
    ck_printf("xhci: %s usbcmd=0x%08x usbsts=0x%08x halted=%s\n", when, cmd, sts, ok ? "yes" : "NO (TIMEOUT)");
    return ok ? 0 : -1;
}

void ck_xhci_release(void)
{
    ck_xhci *x = &g_x;
    if (!x->pf && !x->plat) return;
    if (x->plat && x->bm_on) {
        /* No bus-master bit on a platform controller: halt it, reset it (drops
         * every ring pointer it holds), then the stream goes back to abort
         * below, which is the gate that actually stops its DMA. */
        int h = halt("halt before revoke");
        int reset_ok = 0;
        if (h == 0) {
            x_w32(x->op + XHCI_USBCMD, USBCMD_HCRST);
            uint64_t t0 = ck_time_us();
            while (((x_r32(x->op + XHCI_USBCMD) & USBCMD_HCRST) || (x_r32(x->op + XHCI_USBSTS) & USBSTS_CNR)) &&
                   ck_time_us() - t0 < 100000u)
                ck_udelay(20);
            reset_ok = !(x_r32(x->op + XHCI_USBCMD) & USBCMD_HCRST);
        }
        x->bm_on = 0;
        ck_printf("dma_gate: xhci %s quiesced (halted=%s reset=%s)\n", x->name, h == 0 ? "yes" : "NO",
                  reset_ok ? "yes" : "NO");
    }
    if (x->pf && x->bm_on) {
        (void)halt("halt before revoke");
#if CK_XHCI_MUT == CK_XHCI_MUT_NO_REVOKE
        /* TEST-ONLY mutation: bus mastering is left on. */
        int off = (pci_r16(x->pf->cfg, 0x04) & CMD_BM) ? -1 : 0;
#else
        int off = pci_bus_master_off(x->pf);
#endif
        if (off == 0) {
            x->bm_on = 0;
            ck_printf("dma_gate: xhci bus master revoked\n");
        } else /* bm_on stays set: the reset quiesce hook retries the revoke */
            ck_printf("dma_gate: xhci bus master revoke FAILED (command register still has BME)\n");
        uint16_t c = pci_r16(x->pf->cfg, 0x04);
        ck_printf("xhci_pci: after phase command=0x%04x bus_master=%s\n", c, (c & CMD_BM) ? "on" : "off");
    }
    if (x->confined) {
        int urc = ck_dma_unconfine(x->stream_id);
        x->confined = 0;
        ck_printf("smmu: xhci stream 0x%x %s (rc=%d)\n", x->stream_id, urc == 0 ? "returned to abort" : "abort FAILED",
                  urc);
    }
}


/* ---- ACPI platform controllers (NEXT-PHASE-3 cut 2) ----
 * Discovery runs once per boot, read-only, before any controller is
 * touched; the lines it prints are the ones tools/ck_acpi_scan.c predicts
 * from firmware tables. */
static struct ck_platform_dev g_plat[CK_XHCI_PLAT_MAX];
static int g_nplat = -2; /* -2 not scanned yet, -1 no DSDT */

static void acpi_discover(void)
{
    if (g_nplat != -2) return;
    static const char *const ids[] = CK_XHCI_ACPI_IDS;
    static const char *const ctl[] = { CK_ACPI_CONTROL_ID };
    struct ck_acpi_scan_info info;
    struct ck_platform_dev c;
    int nc = ck_acpi_platform_devices(ctl, 1, &c, 1, &info);
    if (nc < 0) {
        ck_printf(CK_ACPI_SCAN_NONE);
        g_nplat = -1;
        return;
    }
    ck_printf(CK_ACPI_SCAN_FMT, info.tables, info.refused, info.first_refusal, info.devices);
    if (nc > 0)
        ck_printf(CK_ACPI_CONTROL_FMT, c.hid, c.name, (unsigned long long)c.mmio_base, (unsigned long long)c.mmio_len);
    else
        ck_printf(CK_ACPI_CONTROL_NONE);
    int n = ck_acpi_platform_devices(ids, CK_XHCI_ACPI_NIDS, g_plat, CK_XHCI_PLAT_MAX, &info);
    if (n > (int)CK_XHCI_PLAT_MAX) n = (int)CK_XHCI_PLAT_MAX;
    g_nplat = n < 0 ? -1 : n;
    for (int i = 0; i < g_nplat; i++)
        ck_printf(CK_XHCI_ACPI_FMT, g_plat[i].name, g_plat[i].hid[0] ? g_plat[i].hid : "-",
                  g_plat[i].cid[0] ? g_plat[i].cid : "-", g_plat[i].table, (unsigned long long)g_plat[i].mmio_base,
                  (unsigned long long)g_plat[i].mmio_len);
    ck_printf(CK_XHCI_ACPI_COUNT_FMT, g_nplat < 0 ? 0 : g_nplat);
}

static int same_last_seg(const char *a, const char *b)
{
    const char *la = a, *lb = b;
    for (const char *p = a; *p; p++)
        if (*p == '.' || *p == '\\' || *p == '^') la = p + 1;
    for (const char *p = b; *p; p++)
        if (*p == '.' || *p == '\\' || *p == '^') lb = p + 1;
    while (*la && *la == *lb) la++, lb++;
    return *la == *lb;
}

/* One platform controller: map, halt whatever the firmware left running,
 * SMMU-confined grant by its ACPI name or fail-closed deny, keyboard phase,
 * then release (halt, reset, stream back to abort). *kbd_rc gets the phase
 * result, or 1 when the phase did not run. */
static int plat_fence_one(int idx, int *kbd_rc)
{
    const struct ck_platform_dev *p = &g_plat[idx];
    ck_xhci *x = &g_x;
    *kbd_rc = 1;
    x->pf = 0;
    x->plat = 0;
    x->bar0 = 0;
    x->op = 0;
    x->bm_on = x->confined = x->mapped = 0;
    x->stream_id = 0;
    unsigned k = 0;
    for (; k + 1 < sizeof x->name && p->name[k]; k++) x->name[k] = p->name[k];
    x->name[k] = 0;
    ck_printf(CK_XHCI_PLAT_TRY_FMT, x->name, (unsigned long long)p->mmio_base, (unsigned long long)p->mmio_len);
    for (int j = 0; j < g_nplat; j++)
        if (j != idx && same_last_seg(g_plat[j].name, p->name)) {
            ck_printf(CK_XHCI_PLAT_SKIP_FMT, x->name, "name not unique in DSDT/SSDT");
            x->state = "ambiguous";
            return CK_XHCI_E_ARG;
        }
    if (!p->mmio_base || p->mmio_len < 0x1000u || (p->mmio_base & 0xfffu)) {
        ck_printf(CK_XHCI_PLAT_SKIP_FMT, x->name, "no usable _CRS memory range");
        x->state = "bar-unusable";
        return CK_XHCI_E_ARG;
    }
    volatile uint8_t *bar = (volatile uint8_t *)ck_mmio_try_map(p->mmio_base, (size_t)p->mmio_len);
    if (!bar) {
        ck_printf(CK_XHCI_PLAT_SKIP_FMT, x->name, "memory range not mappable as MMIO");
        x->state = "bar-unusable";
        return CK_XHCI_E_ARG;
    }
    x->bar0 = bar;
    x->mapped = 1;
    uint32_t cap = x_r32(XHCI_CAPLENGTH);
    x->op = cap & 0xffu;
    ck_printf("xhci: %s caplength=0x%02x hciversion=0x%04x (platform)\n", x->name, cap & 0xffu, cap >> 16);
    /* Stop any DMA the firmware left running before the SMMU decision; a
     * denied controller stays halted. */
    if (halt("halted before gate")) {
        ck_printf("keyboard: unavailable (platform xHCI %s would not halt)\n", x->name);
        x->state = "halt-failed";
        return CK_XHCI_E_HALT;
    }
    if (!g_dma_mem) g_dma_mem = ck_dma_alloc(CK_XHCI_DMA_BYTES, 4096, &g_dma_phys);
    if (!g_dma_mem) {
        ck_printf("keyboard: unavailable (DMA allocation of %u bytes failed)\n", (unsigned)CK_XHCI_DMA_BYTES);
        x->state = "dma-alloc-failed";
        return CK_XHCI_E_DMA;
    }
    struct ck_dma_confinement cf = { 0, 0, 0, 0 };
    int src = ck_dma_confine_named(x->name, g_dma_phys, CK_XHCI_DMA_BYTES, &cf);
    if (src) {
        if (src == CK_SMMU_OTHER)
            ck_printf(CK_XHCI_PLAT_OTHER_FMT, x->name, (unsigned long long)cf.smmu_base, cf.stream_id);
        else
            ck_printf(CK_XHCI_PLAT_DENY_FMT, x->name,
                      src == CK_SMMU_ABSENT     ? "NoSmmu"
                      : src == CK_SMMU_NOSTREAM ? "NoStream"
                      : src == CK_SMMU_EARG     ? "Ambiguous"
                                                : "SmmuNotReady");
        x->state = "denied";
        return CK_XHCI_E_DENIED;
    }
    x->plat = 1;
    x->confined = 1;
    x->bm_on = 1; /* may DMA from here until the release */
    x->stream_id = cf.stream_id;
    ck_printf(CK_XHCI_PLAT_GRANT_FMT, x->name, (unsigned long long)cf.smmu_base, cf.stream_id);
    ck_printf("smmu_dma_window: xhci %s only, translation active iova=0x%llx len=0x%llx\n", x->name,
              (unsigned long long)cf.iova, (unsigned long long)cf.len);
    *kbd_rc = ck_kbd_phase(x->bar0, g_dma_mem, g_dma_phys, CK_XHCI_DMA_BYTES);
    x->state = "fenced";
    ck_xhci_release();
    return CK_XHCI_OK;
}

/* Every platform controller in table order until one carries a keyboard. */
static int plat_fence_all(void)
{
    if (g_nplat <= 0) {
        ck_printf("keyboard: unavailable (no xHCI controller)\n");
        g_x.state = "absent";
        return CK_XHCI_ABSENT;
    }
    int rc = CK_XHCI_ABSENT, any_fenced = 0;
    for (int i = 0; i < g_nplat; i++) {
        int krc;
        rc = plat_fence_one(i, &krc);
        if (rc == CK_XHCI_OK) any_fenced = 1;
        if (rc == CK_XHCI_OK && krc == 0) return CK_XHCI_OK; /* keyboard found and its phase ran */
        if (ck_kbd_recovery_requested()) return rc;
    }
    if (any_fenced) g_x.state = "fenced";
    ck_printf("keyboard: unavailable (no keyboard on any platform xHCI)\n");
    return any_fenced ? CK_XHCI_OK : rc;
}

int ck_xhci_fence(const pci_system *pci)
{
    ck_xhci *x = &g_x;
    if (ck_xhci_live()) {
        ck_printf("keyboard: unavailable (previous xHCI fence still live; release it first)\n");
        return CK_XHCI_E_ARG;
    }
    acpi_discover();
    x->pf = 0;
    x->plat = 0;
    x->name[0] = 0;
    x->bar0 = 0;
    x->op = 0;
    x->bm_on = x->confined = x->mapped = 0;
    x->stream_id = 0;
    x->state = "absent";
    const pci_func *f = pci ? pci_find_class(pci, CK_XHCI_CLASS, 0xffffffu) : 0;
    if (!f) {
        /* No PCI xHCI (the DGX Spark has none): the ACPI platform
         * controllers found by acpi_discover, each behind its own fence. */
        ck_printf("keyboard: no PCI xHCI controller; trying %d ACPI platform controller(s)\n", g_nplat < 0 ? 0 : g_nplat);
        return plat_fence_all();
    }
    x->pf = f;
    const pci_bar *b = &f->bar[0];
    /* Rust: "keyboard: xhci {seg:04x}:{bus:02x}:{dev:02x}.{fn} mmio {:#x}". */
    ck_printf("keyboard: xhci %04x:%02x:%02x.%u mmio 0x%llx (found post-exit on the ECAM walk)\n",
              pci->ecam.segment, f->bus, f->dev, f->fn, (unsigned long long)b->addr);
    uint16_t command = pci_r16(f->cfg, 0x04);
    ck_printf("xhci_pci: command=0x%04x bus_master=%s\n", command, (command & CMD_BM) ? "on" : "off");
    if (command & CMD_BM) {
        /* The sweep could not clear it (or it came back): no gate, no DMA. The
         * bus-master bit is left as found; the reset quiesce hook does not
         * touch an unbound controller. */
        x->state = "bme-stuck";
        ck_printf("keyboard: unavailable (xHCI bus master would not clear)\n");
        return CK_XHCI_E_BME;
    }
    if (b->io || b->addr == 0 || b->size < 0x1000u) {
        x->state = "bar-unusable";
        ck_printf("keyboard: unavailable (xHCI BAR0 unusable)\n");
        return CK_XHCI_E_ARG;
    }
    /* DMA gate: the window is exactly the region a driver would use. */
    if (!g_dma_mem) g_dma_mem = ck_dma_alloc(CK_XHCI_DMA_BYTES, 4096, &g_dma_phys);
    if (!g_dma_mem) {
        x->state = "dma-alloc-failed";
        ck_printf("keyboard: unavailable (DMA allocation of %u bytes failed)\n", (unsigned)CK_XHCI_DMA_BYTES);
        return CK_XHCI_E_DMA;
    }
    uint32_t rid = ((uint32_t)f->bus << 8) | ((uint32_t)f->dev << 3) | (uint32_t)f->fn;
    struct ck_dma_confinement cf;
    int src = ck_dma_confine(rid, g_dma_phys, CK_XHCI_DMA_BYTES, &cf);
    if (src == 0) {
        x->confined = 1;
        x->stream_id = cf.stream_id;
        ck_printf("smmu: enabled base=0x%llx stream_id=0x%x\n", (unsigned long long)cf.smmu_base, cf.stream_id);
        ck_printf("smmu_dma_window: xhci only, translation active iova=0x%llx len=0x%llx rid=0x%x\n",
                  (unsigned long long)cf.iova, (unsigned long long)cf.len, rid);
        ck_printf("dma_gate: xhci granted (Confined), bus master on\n");
    } else {
#if CK_XHCI_MUT == CK_XHCI_MUT_GRANT_NO_SMMU
        /* TEST-ONLY mutation: DMA granted without confinement. */
        ck_printf("dma_gate: xhci granted (TestMutationNoSmmu rc=%d), bus master on\n", src);
#else
        if (src == CK_SMMU_ABSENT)
            ck_printf("dma_gate: xhci denied (NoSmmu), bus master stays off\n");
        else
            ck_printf("dma_gate: xhci denied (SmmuNotReady rc=%d), bus master stays off\n", src);
        ck_printf("keyboard: unavailable (SMMU DMA isolation not active)\n");
        uint16_t c = pci_r16(f->cfg, 0x04);
        ck_printf("xhci_pci: after deny command=0x%04x bus_master=%s\n", c, (c & CMD_BM) ? "on" : "off");
        x->state = "denied";
        return CK_XHCI_E_DENIED;
#endif
    }
    x->bar0 = (volatile uint8_t *)ck_mmio_map(b->addr, (size_t)b->size);
    pci_enable(f, 1);
    x->bm_on = 1;
    x->mapped = 1;
    uint32_t cap = x_r32(XHCI_CAPLENGTH);
    x->op = cap & 0xffu;
    ck_printf("xhci: caplength=0x%02x hciversion=0x%04x dma_window=0x%llx+0x%x\n", cap & 0xffu, cap >> 16,
              (unsigned long long)g_dma_phys, (unsigned)CK_XHCI_DMA_BYTES);
    int hrc = halt("halted after grant");
    /* Rows 29-30 and the recovery-access hook (usb_kbd.c): the polled HID
     * boot-keyboard driver runs only here, inside the confined grant, on the
     * fence's DMA region; the release below halts and revokes whatever it
     * returns. A controller that would not halt is never driven. */
    int krc = hrc == 0 ? ck_kbd_phase(x->bar0, g_dma_mem, g_dma_phys, CK_XHCI_DMA_BYTES) : 1;
    x->state = hrc ? "halt-failed" : "fenced";
    ck_xhci_release();
    /* A PCI controller without a keyboard: try the platform ones next. */
    if (krc == CK_KBD_E_NOKBD && g_nplat > 0 && !ck_kbd_recovery_requested()) {
        ck_printf("keyboard: none on the PCI xHCI; trying %d ACPI platform controller(s)\n", g_nplat);
        x->pf = 0;
        int prc = plat_fence_all();
        if (prc == CK_XHCI_OK) return CK_XHCI_OK;
        x->state = "fenced";
    }
    return hrc ? CK_XHCI_E_HALT : CK_XHCI_OK;
}
