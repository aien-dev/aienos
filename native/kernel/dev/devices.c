/* devices.c -- ck_stage_devices: PCI (with the post-exit bus-master sweep),
 * NVMe, virtio-net, xHCI DMA fence. Freestanding. */
#include "devices.h"
#include "ck.h"
#include "nvme_bind.h"
#include "pci.h"
#include "virtio_net.h"
#include "net_bind.h"
#include "xhci_fence.h"

static pci_system g_pci;
static ck_nvme g_nvme;

/* Later stages get only the AIENOS partition view (dev/disk_part.h), never the
 * whole namespace: every access they make goes through ck_part_xlate. */
const disk_dev *ck_dev_boot_disk(void) { return g_nvme.bound && g_nvme.part.valid ? &g_nvme.part.dev : 0; }

void ck_dev_nvme_release(void)
{
    if (!g_nvme.pf) return;
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
}

int ck_stage_devices(void)
{
    int rc = pci_stage_probe(&g_pci);
    if (rc) return rc;
    /* Post-exit bus-master sweep (Rust dma_gate::sweep_bus_master): before any
     * device is given DMA, clear BME on every endpoint firmware left with it
     * set, so each device starts with DMA off. */
    if (ck_xhci_sweep_enabled()) {
        pci_sweep sw;
        pci_sweep_bus_master(&g_pci.acc, &sw);
        pci_sweep_report(&g_pci.ecam, &sw);
    }
    ck_xhci_after_sweep(&g_pci); /* TEST-ONLY bm-left-on mutation hook; no-op otherwise */
    int nrc = ck_nvme_bind(&g_nvme, &g_pci);
    if (nrc) ck_dev_nvme_release(); /* a failed bind never keeps DMA */
    virtio_pci_caps caps;
    const pci_func *vf = 0;
    int vrc = ck_virtio_net_probe(&g_pci, &caps, &vf);
    /* virtio-net: SMMU-confined attach plus one bounded UDP round trip; the
     * device is always released again before this returns (net_bind.h). A
     * net failure is reported, never a devices-stage failure. */
    int netrc = (vrc == 0 && vf) ? ck_net_bind_selftest(vf, &caps) : 1;
    ck_printf("devices: pci=ok nvme=%s virtio_net=%s\n", g_nvme.bound ? "bound" : "unbound",
              vrc != 0 ? "caps-refused" : !vf ? "absent" : netrc == 0 ? "selftest-ok" : "selftest-failed");
    /* xHCI: DMA fence only (bus master off before the gate, SMMU-confined grant
     * or fail-closed deny, halt, revoke, stream back to abort); no USB HID
     * driver yet. Reported, never a devices-stage failure. */
    int xrc = ck_xhci_fence(&g_pci);
    ck_printf("devices: xhci=%s (rc=%d)\n", ck_xhci_state(), xrc);
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
