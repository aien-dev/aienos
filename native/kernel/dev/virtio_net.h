/* virtio_net.h -- virtio-net discovery stage: finds the virtio-net PCI
 * function and parses its virtio 1.x capabilities (native/net
 * aienos_virtio_pci.c). Binding and the data path are dev/net_bind.c. */
#ifndef AIENOS_CK_VIRTIO_NET_H
#define AIENOS_CK_VIRTIO_NET_H
#include "aienos_virtio_pci.h"
#include "pci.h"
/* Returns 0 when no virtio-net exists (*func_out = NULL) or its capabilities
 * parsed (*func_out = the function); the parse error code (> 0) otherwise.
 * Never enables the device. func_out may be NULL. */
int ck_virtio_net_probe(const pci_system *pci, virtio_pci_caps *caps_out, const pci_func **func_out);
#endif
