/* devices.c -- ck_stage_devices: PCI, NVMe, virtio-net. Freestanding. */
#include "devices.h"
#include "ck.h"
#include "nvme_bind.h"
#include "pci.h"
#include "virtio_net.h"

static pci_system g_pci;
static ck_nvme g_nvme;

const disk_dev *ck_dev_boot_disk(void) { return g_nvme.bound ? &g_nvme.disk : 0; }

int ck_stage_devices(void)
{
    int rc = pci_stage_probe(&g_pci);
    if (rc) return rc;
    int nrc = ck_nvme_bind(&g_nvme, &g_pci);
    virtio_pci_caps caps;
    int vrc = ck_virtio_net_probe(&g_pci, &caps);
    ck_printf("devices: pci=ok nvme=%s virtio_net=%s\n", g_nvme.bound ? "bound" : "unbound",
              vrc == 0 ? "probed" : "caps-refused");
    if (nrc == -1) return 0;  /* no NVMe present: not a devices failure; Store reports it */
    return nrc;
}
