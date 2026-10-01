/* devices.c -- ck_stage_devices: PCI, NVMe, virtio-net. Freestanding. */
#include "devices.h"
#include "ck.h"
#include "nvme_bind.h"
#include "pci.h"
#include "virtio_net.h"

static pci_system g_pci;
static ck_nvme g_nvme;

const disk_dev *ck_dev_boot_disk(void) { return g_nvme.bound ? &g_nvme.disk : 0; }

void ck_dev_nvme_release(void)
{
    if (!g_nvme.pf) return;
    g_nvme.bound = 0;
    if (g_nvme.bm_on) {
        g_nvme.bm_on = 0;
        if (pci_bus_master_off(g_nvme.pf) == 0)
            ck_printf("dma_gate: nvme bus master revoked\n");
        else
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
    int nrc = ck_nvme_bind(&g_nvme, &g_pci);
    if (nrc) ck_dev_nvme_release(); /* a failed bind never keeps DMA */
    virtio_pci_caps caps;
    int vrc = ck_virtio_net_probe(&g_pci, &caps);
    ck_printf("devices: pci=ok nvme=%s virtio_net=%s\n", g_nvme.bound ? "bound" : "unbound",
              vrc == 0 ? "probed" : "caps-refused");
    if (nrc == -1) return 0;  /* no NVMe present: not a devices failure; Store reports it */
    return nrc;
}
