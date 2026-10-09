/* devices.c -- ck_stage_devices: PCI (with the post-exit bus-master sweep),
 * NVMe, virtio-net, xHCI DMA fence. Freestanding. */
#include "devices.h"
#include "ck.h"
#include "nvme_bind.h"
#include "pci.h"
#include "mmio_window.h"
#include "virtio_net.h"
#include "net_bind.h"
#include "xhci_fence.h"
#include "usb_kbd.h"

static pci_system g_pci;
static ck_nvme g_nvme;

/* Later stages get only the AIENOS partition view (dev/disk_part.h), never the
 * whole namespace: every access they make goes through ck_part_xlate. */
const disk_dev *ck_dev_boot_disk(void) { return g_nvme.bound && g_nvme.part.valid ? &g_nvme.part.dev : 0; }

void ck_dev_nvme_release(void)
{
    if (!g_nvme.pf) { /* bind stopped before any device access: nothing to quiesce */
        g_nvme.claimed = 0;
        return;
    }
    g_nvme.bound = 0;
    if (g_nvme.bm_on) {
        /* Halt order: NVMe normal shutdown (CC.SHN, wait CSTS.SHST) while the
         * controller can still DMA, then bus master off, then the SMMU
         * stream back to abort. */
        ck_nvme_shutdown_bound(&g_nvme);
        if (pci_bus_master_off(g_nvme.pf) == 0) {
            g_nvme.bm_on = 0;
            ck_printf("dma_gate: nvme bus master revoked\n");
        } else /* bm_on stays set: the reset quiesce hook retries the revoke */
            ck_printf("dma_gate: nvme bus master revoke FAILED (command register still has BME)\n");
    }
    if (g_nvme.confined) {
        /* Bus mastering is off (or never came on); return the stream to
         * abort as well, independently of the bus master state. */
        int urc = ck_dma_unconfine(g_nvme.stream_id);
        g_nvme.confined = 0;
        ck_printf("smmu: nvme stream 0x%x %s (rc=%d)\n", g_nvme.stream_id,
                  urc == 0 ? "returned to abort" : "abort FAILED", urc);
    }
    /* Ownership is given back only once DMA is fully off (bus master and stream). */
    if (!g_nvme.bm_on && !g_nvme.confined) g_nvme.claimed = 0;
}

int ck_stage_devices(void)
{
    int rc = pci_stage_probe(&g_pci);
    if (rc) return rc;
    /* Report-only multi-segment discovery for the boot log (aienos#286); the
     * result is ignored, nothing below depends on it. */
    (void)pci_stage_discover_report();
    /* Report-only read-only MMIO window on a discovered NVMe BAR0 (aienos#286, cut B3); result ignored. */
    (void)ck_mmio_stage_report();
    /* Post-exit bus-master sweep (Rust dma_gate::sweep_bus_master): before any
     * device is given DMA, clear BME on every endpoint firmware left with it
     * set, so each device starts with DMA off. */
    if (ck_xhci_sweep_enabled()) {
        pci_sweep sw;
        pci_sweep_bus_master(&g_pci.acc, &sw);
        pci_sweep_report(&g_pci.ecam, &sw);
    }
    ck_xhci_after_sweep(&g_pci); /* TEST-ONLY bm-left-on mutation hook; no-op otherwise */
    /* NVMe is bound from the multi-segment discovery result (aienos#31), any segment; the segment-0
     * enumeration above is only used for the other devices and for log wording. */
    uint32_t dn = 0;
    const pci_found *df = pci_stage_disc_found(&dn);
    int nrc = ck_nvme_bind(&g_nvme, df, dn, &g_pci);
    if (nrc) ck_dev_nvme_release(); /* a failed bind never keeps DMA */
    (void)pci_nvme_disc_report(df, dn, g_nvme.claimed ? g_nvme.pf : 0);
    virtio_pci_caps caps;
    const pci_func *vf = 0;
    int vrc = ck_virtio_net_probe(&g_pci, &caps, &vf);
    /* virtio-net: SMMU-confined attach plus one bounded UDP round trip; the
     * device is always released again before this returns (net_bind.h). A
     * net failure is reported, never a devices-stage failure. */
    int netrc = (vrc == 0 && vf) ? ck_net_bind_selftest(vf, &caps) : 1;
    ck_printf("devices: pci=ok nvme=%s virtio_net=%s\n", g_nvme.bound ? "bound" : "unbound",
              vrc != 0 ? "caps-refused" : !vf ? "absent" : netrc == 0 ? "selftest-ok" : "selftest-failed");
    /* xHCI: DMA fence (bus master off before the gate, SMMU-confined grant or
     * fail-closed deny, halt, revoke, stream back to abort) with the operator
     * keyboard phase inside the grant (usb_kbd.c). Reported, never a
     * devices-stage failure. */
    int xrc = ck_xhci_fence(&g_pci);
    ck_printf("devices: xhci=%s (rc=%d)\n", ck_xhci_state(), xrc);
    ck_kbd_recovery_report(ck_xhci_state());
    if (ck_kbd_recovery_requested()) {
        /* Recovery access chosen: the xHCI is already revoked; release every
         * other device's DMA before the stub halts (no Store stage runs). */
        if (ck_net_live()) ck_net_release();
        ck_dev_nvme_release();
        ck_printf("devices: recovery halt nvme=%s virtio_net=%s xhci=%s\n", g_nvme.bm_on || g_nvme.confined ? "LIVE" : "released",
                  ck_net_live() ? "LIVE" : "released", ck_xhci_live() ? "LIVE" : "released");
        if (!g_nvme.bm_on && !g_nvme.confined && !ck_net_live() && !ck_xhci_live()) ck_recovery_console_stub();
        ck_panic("recovery access: device DMA still live, refusing to halt with it");
    }
    if (nrc == -1) return 0;  /* no NVMe present: not a devices failure; Store reports it */
    return nrc;
}

/* Called by the core's ck_reset (PSCI reset/off after the final report, a
 * panic or a fault report): no device may keep DMA across a reset. A normal
 * boot has already released the NVMe controller in the Store stage, so this
 * only reports that; after a panic mid-stage it does the full halt order. */
void ck_stage_quiesce(void)
{
    int net_live = ck_net_live();
    if (net_live) ck_net_release();
    int xhci_live = ck_xhci_live();
    if (xhci_live) ck_xhci_release();
    int was_live = g_nvme.pf && (g_nvme.bm_on || g_nvme.confined);
    if (was_live)
        ck_dev_nvme_release();
    ck_printf("devices: quiesce before reset nvme=%s\n",
              !g_nvme.pf ? "none" : was_live ? "released-now" : "already-released");
    if (net_live) ck_printf("devices: quiesce before reset virtio_net=released-now\n");
    if (xhci_live) ck_printf("devices: quiesce before reset xhci=released-now\n");
}

#if defined(CK_CONSOLE_SESSION) && CK_CONSOLE_SESSION
/* Final boot stage "console" (C3-1a, TEST-ONLY QEMU image built with
 * CK_CONSOLE_SESSION=1): runs after every other boot step. Serial (PL011) and
 * the USB keyboard feed one line editor and the existing shell until "exit".
 * The USB keyboard runs inside the same xHCI DMA fence as the boot shell
 * (SMMU window first, no SMMU means no DMA); the fence is re-entered here and
 * revoked exactly as in the devices stage. Nothing here grants capabilities. */
int ck_stage_console_session(void)
{
#if defined(CK_TEST_CONSOLE_MUTATION)
    ck_printf("WARNING: TEST-ONLY console session MUTATION BUILD (CK_TEST_CONSOLE_MUTATION=bm-left-on-after-exit, "
              "QEMU gate self-test only, never a PASS)\n");
#endif
    ck_printf("console_session: begin (TEST-ONLY QEMU image, CK_CONSOLE_SESSION=1; QEMU only, hardware NOT_RUN)\n");
    int xrc = ck_xhci_session(&g_pci);
    ck_printf("console_session: xhci fence returned rc=%d state=%s\n", xrc, ck_xhci_state());
    ck_console_session_serial_only(); /* no-op once the exit came inside the fence */
    ck_printf("console_session: end (exit) xhci=%s\n", ck_xhci_live() ? "LIVE" : "released");
    return 0;
}
#endif
