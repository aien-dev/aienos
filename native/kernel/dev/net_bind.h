/* net_bind.h -- bind native/net's polled virtio-net driver
 * (aienos_virtio_net.c) to the virtio-net PCI function through ck.h services
 * and run one bounded UDP round trip (QEMU user networking).
 *
 * DMA rule (same as NVMe, dev/nvme_bind.c): no SMMU confinement means no DMA.
 * The driver's one shared region (rings + packet buffers) is allocated first
 * and becomes the stream's only SMMU window (ck_dma_confine); only then are
 * memory decoding and bus mastering enabled. Without an SMMU, or when the
 * SMMU did not come up, the device stays off. There is no unconfined bypass
 * for virtio-net, not even in the TEST-ONLY CK_QEMU_UNSAFE_DMA=1 build.
 *
 * Limit (QEMU): the driver does not negotiate VIRTIO_F_ACCESS_PLATFORM, and
 * QEMU's virtio-pci then performs device DMA without the vIOMMU, so the SMMU
 * window is programmed but QEMU does not enforce it for this device. The
 * kernel prints access_platform=no; the gate does not claim confinement. */
#ifndef AIENOS_CK_NET_BIND_H
#define AIENOS_CK_NET_BIND_H
#include "aienos_virtio_net.h"
#include "pci.h"

#define CK_NET_QSIZE 64u

enum {
    CK_NET_OK = 0,
    CK_NET_E_ARG = -501,     /* bad function, BAR or capability window */
    CK_NET_E_DMA = -502,     /* DMA region allocation failed */
    CK_NET_E_DENIED = -503,  /* no SMMU confinement: device left off */
    CK_NET_E_INIT = -504,    /* vnet_init failed */
    CK_NET_E_ARP = -505,     /* no ARP reply from the gateway in time */
    CK_NET_E_TX = -506,      /* frame build, post or completion failed */
    CK_NET_E_RX = -507,      /* no matching UDP reply in time, or device broken */
};

/* Attach (DMA gate, BAR map, bus master, vnet_init), then ARP for the
 * gateway and one UDP datagram to CK_NET_ECHO_PORT and back, every wait
 * bounded by ck_time_us. Always leaves the device released (reset, bus
 * master off, stream back to abort) before returning. */
int ck_net_bind_selftest(const pci_func *f, const virtio_pci_caps *caps);

/* Reset the device, revoke bus mastering and return the SMMU stream to
 * abort if still live; prints the dma_gate/smmu lines. Idempotent. */
void ck_net_release(void);
/* 1 while the device may still DMA (bus master on or stream confined). */
int ck_net_live(void);
#endif
