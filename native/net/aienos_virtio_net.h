/* virtio-net (virtio 1.x, split virtqueues) driver core, polled, hosted-testable.
 *
 * The Rust reference crates/aienos-kernel/src/virtio_net.rs only parses PCI
 * capabilities; it has no queue code. This data path is written from the
 * virtio 1.x specification (sections 2.6 split virtqueues, 4.1.4 PCI
 * capabilities, 5.1 network device) and is new C, not a port.
 *
 * Device access goes through vnet_ops only: register reads/writes inside the
 * four mapped capability windows and the queue notify. No heap, no clock, no
 * I/O of its own. All rings and packet buffers live in ONE caller-provided
 * region (mem, len) that the device sees at bus address `dma`. The driver
 * builds every descriptor itself from the descriptor id (never reads a
 * descriptor back from shared memory) and checks it lies inside the region.
 * Anything a device writes is untrusted: a used-ring entry with an id out of
 * range, an id not outstanding, a length larger than the buffer, a used index
 * that runs ahead of what was posted, or a short RX completion marks the
 * device broken (sticky); the caller must reset and re-init.
 *
 * Features: VIRTIO_F_VERSION_1 is required; VIRTIO_NET_F_MAC and
 * VIRTIO_F_ACCESS_PLATFORM are accepted when offered (virtio 1.x 6.1: a driver
 * SHOULD accept ACCESS_PLATFORM; with it the device DMAs through the
 * platform IOMMU, so `dma` below is an IOMMU bus address). With
 * VNET_INIT_REQUIRE_ACCESS_PLATFORM the driver refuses (fail closed, before
 * FEATURES_OK) a device that does not offer it: an IOMMU-confined caller
 * must never run a device that would bypass the IOMMU. Every other feature
 * is declined (no packed ring, no indirect descriptors, no event index, no
 * offloads, no mergeable RX buffers, no control queue). One descriptor per packet; the 12-byte
 * virtio 1.x net header precedes each frame. Interrupts are not used. */
#ifndef AIENOS_VIRTIO_NET_H
#define AIENOS_VIRTIO_NET_H

#include <stddef.h>
#include <stdint.h>

#include "aienos_virtio_pci.h"

#define VNET_QUEUE_MAX 256u         /* largest queue size the driver uses */
#define VNET_QUEUE_MIN 2u
#define VNET_HDR_LEN 12u            /* struct virtio_net_hdr incl. num_buffers */
#define VNET_FRAME_MAX 1514u        /* Ethernet II without FCS, no VLAN tag */
#define VNET_BUF_LEN (VNET_HDR_LEN + VNET_FRAME_MAX)
#define VNET_BUF_STRIDE 1536u

#define VNET_F_MAC 5u
#define VNET_F_VERSION_1 32u
#define VNET_F_ACCESS_PLATFORM 33u  /* VIRTIO_F_ACCESS_PLATFORM (was IOMMU_PLATFORM) */

/* vnet_init_flags flags */
#define VNET_INIT_REQUIRE_ACCESS_PLATFORM 1u

/* virtio common configuration (virtio 1.x 4.1.4.3), byte offsets */
#define VNET_CC_DFSELECT 0x00u
#define VNET_CC_DF 0x04u
#define VNET_CC_GFSELECT 0x08u
#define VNET_CC_GF 0x0cu
#define VNET_CC_MSIX 0x10u
#define VNET_CC_NUMQ 0x12u
#define VNET_CC_STATUS 0x14u
#define VNET_CC_CFGGEN 0x15u
#define VNET_CC_Q_SELECT 0x16u
#define VNET_CC_Q_SIZE 0x18u
#define VNET_CC_Q_MSIX 0x1au
#define VNET_CC_Q_ENABLE 0x1cu
#define VNET_CC_Q_NOFF 0x1eu
#define VNET_CC_Q_DESCLO 0x20u
#define VNET_CC_Q_DESCHI 0x24u
#define VNET_CC_Q_AVAILLO 0x28u
#define VNET_CC_Q_AVAILHI 0x2cu
#define VNET_CC_Q_USEDLO 0x30u
#define VNET_CC_Q_USEDHI 0x34u
#define VNET_CC_LEN 0x38u

#define VNET_S_ACK 1u
#define VNET_S_DRIVER 2u
#define VNET_S_DRIVER_OK 4u
#define VNET_S_FEATURES_OK 8u
#define VNET_S_NEEDS_RESET 64u
#define VNET_S_FAILED 128u

#define VNET_DESC_F_WRITE 2u
#define VNET_AVAIL_F_NO_INTERRUPT 1u

enum { VNET_RX_QUEUE = 0, VNET_TX_QUEUE = 1 };
typedef enum { VNET_WIN_COMMON = 0, VNET_WIN_NOTIFY = 1, VNET_WIN_ISR = 2, VNET_WIN_DEVICE = 3 } vnet_window;

typedef struct {
    void *ctx;
    /* width is 1, 2 or 4; off + width is already checked against the window */
    uint32_t (*read)(void *ctx, vnet_window win, uint32_t off, unsigned width);
    void (*write)(void *ctx, vnet_window win, uint32_t off, unsigned width, uint32_t val);
    /* write `queue` (16 bit) at byte `off` of the notify window (checked) */
    void (*notify)(void *ctx, uint32_t off, uint16_t queue);
} vnet_ops;

typedef enum {
    VNET_OK = 0,
    VNET_E_ARG = 1,            /* NULL, bad queue size, frame too long, buffer too small */
    VNET_E_CAPS = 2,           /* a required capability missing or too short */
    VNET_E_MEM = 3,            /* region too small, misaligned, or bus range wraps */
    VNET_E_RESET_TIMEOUT = 4,  /* device never read back status 0 */
    VNET_E_NO_VERSION_1 = 5,   /* device does not offer VIRTIO_F_VERSION_1 */
    VNET_E_FEATURES = 6,       /* device refused FEATURES_OK */
    VNET_E_QUEUES = 7,         /* fewer than 2 queues, size 0, or queue already enabled */
    VNET_E_NOTIFY = 8,         /* notify offset outside the notify window */
    VNET_E_CONFIG = 9,         /* device config generation never settled */
    VNET_E_FULL = 10,          /* no free TX descriptor (reclaim first) */
    VNET_E_DEVICE = 11,        /* hostile or broken device completion; device is now broken */
    VNET_E_BROKEN = 12,        /* sticky: an earlier VNET_E_DEVICE; reset and re-init */
    VNET_E_NO_ACCESS_PLATFORM = 13, /* required (flag) but not offered by the device */
} vnet_err;

typedef struct {
    uint16_t size;          /* negotiated, power of two, <= VNET_QUEUE_MAX */
    uint16_t avail_idx;     /* driver shadow of avail->idx */
    uint16_t last_used;     /* next used-ring slot to consume */
    uint16_t in_flight;     /* descriptors posted and not yet completed */
    uint32_t notify_off;    /* byte offset in the notify window */
    size_t desc_off, avail_off, used_off, buf_off; /* offsets into mem */
    uint8_t posted[VNET_QUEUE_MAX];
} vnet_queue;

typedef struct {
    vnet_ops ops;
    virtio_pci_caps caps;
    uint8_t *mem;
    uint64_t dma;
    size_t mem_len;
    uint64_t features;      /* accepted feature bits */
    uint8_t has_mac;
    uint8_t mac[6];
    uint8_t broken;
    vnet_queue q[2];        /* VNET_RX_QUEUE, VNET_TX_QUEUE */
} vnet_dev;

/* Bytes of shared region needed for two queues of `qsize` (power of two in
 * [VNET_QUEUE_MIN, VNET_QUEUE_MAX]); 0 if qsize is invalid. */
size_t vnet_mem_size(uint16_t qsize);

/* Reset and bring up the device: feature negotiation, both queues, all RX
 * buffers posted, DRIVER_OK. mem and dma must be 16-byte aligned; mem_len >=
 * vnet_mem_size(qsize). The device may offer a smaller queue: the driver then
 * uses the largest power of two it offers (>= VNET_QUEUE_MIN). On failure the
 * driver writes FAILED to the device status when it got that far. */
vnet_err vnet_init(vnet_dev *d, const vnet_ops *ops, const virtio_pci_caps *caps,
                   void *mem, uint64_t dma, size_t mem_len, uint16_t qsize);
/* vnet_init with flags (VNET_INIT_REQUIRE_ACCESS_PLATFORM); vnet_init is flags 0. */
vnet_err vnet_init_flags(vnet_dev *d, const vnet_ops *ops, const virtio_pci_caps *caps, void *mem, uint64_t dma,
                         size_t mem_len, uint16_t qsize, uint32_t flags);

/* Copy one Ethernet frame (14..VNET_FRAME_MAX bytes, no FCS) into a free TX
 * buffer behind a zero virtio-net header, post it and notify. */
vnet_err vnet_tx(vnet_dev *d, const uint8_t *frame, size_t len);

/* Consume TX completions; *reclaimed (optional) gets the count. */
vnet_err vnet_tx_reclaim(vnet_dev *d, unsigned *reclaimed);

/* Take at most one received frame: copies it (header stripped) to out (cap >=
 * VNET_FRAME_MAX), sets *len, sets *got to 1, and re-posts the buffer. *got 0:
 * nothing pending. */
vnet_err vnet_rx(vnet_dev *d, uint8_t *out, size_t cap, size_t *len, int *got);

const char *vnet_err_name(vnet_err e);

#endif
