/* virtio_net.h -- virtio-net discovery stage. native/net provides only the
 * virtio 1.x PCI capability parser (no queues, no driver), so this stage
 * finds the device, parses its capabilities and reports "not bound". */
#ifndef AIENOS_CK_VIRTIO_NET_H
#define AIENOS_CK_VIRTIO_NET_H
#include "aienos_virtio_pci.h"
#include "pci.h"
/* Returns 0 when no virtio-net exists or its capabilities parsed; the
 * parse error code (> 0) otherwise. Never binds, never enables DMA. */
int ck_virtio_net_probe(const pci_system *pci, virtio_pci_caps *caps_out);
#endif
