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
 * ACCESS_PLATFORM: vnet_init_flags(..., VNET_INIT_REQUIRE_ACCESS_PLATFORM)
 * negotiates VIRTIO_F_ACCESS_PLATFORM (bit 33) and refuses a device that does
 * not offer it (fail closed: QEMU virtio-pci without iommu_platform=on DMAs
 * around the vIOMMU). With it, every ring and buffer access of the device
 * goes through the SMMU window; the kernel prints access_platform=yes.
 *
 * Fence proof (after the good round trip, net_bind.c smmu_negative_test):
 * the RX descriptors the device holds are pointed at a pattern page outside
 * the window and a datagram draws a reply; the SMMU must log F_TRANSLATION
 * for this stream at that page, the page must stay intact. Measured on QEMU
 * 8.2.2: no NEEDS_RESET; QEMU completes the RX through its internal bounce
 * buffer (rx_completed=1) while the refused write never reaches the page.
 * The binding discards the redirected descriptors, resets and re-inits the
 * device and runs a second round trip inside the window. */
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
    CK_NET_E_SMMU = -508,    /* SMMU negative test or its recovery failed */
};

/* Attach (DMA gate, BAR map, bus master, vnet_init_flags with
 * ACCESS_PLATFORM required), then ARP for the gateway and one UDP datagram to
 * CK_NET_ECHO_PORT and back, then the SMMU fence test and its recovery round
 * trip (CK_NET_E_SMMU if either fails), every wait bounded by ck_time_us.
 * Always leaves the device released (reset, bus master off, stream back to
 * abort) before returning. */
int ck_net_bind_selftest(const pci_func *f, const virtio_pci_caps *caps);

/* Reset the device, revoke bus mastering and return the SMMU stream to
 * abort if still live; prints the dma_gate/smmu lines. Idempotent. */
void ck_net_release(void);
/* 1 while the device may still DMA (bus master on or stream confined). */
int ck_net_live(void);
#endif
