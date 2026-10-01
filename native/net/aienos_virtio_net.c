/* See aienos_virtio_net.h. */
#include "aienos_virtio_net.h"

#include <string.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "virtio 1.x rings are little-endian; this driver assumes a little-endian CPU"
#endif

#define VNET_RESET_POLLS 100000u
#define VNET_CFGGEN_TRIES 8u
#define ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~(size_t)((a) - 1))

const char *vnet_err_name(vnet_err e)
{
    switch (e) {
    case VNET_OK: return "Ok";
    case VNET_E_ARG: return "Arg";
    case VNET_E_CAPS: return "Caps";
    case VNET_E_MEM: return "Mem";
    case VNET_E_RESET_TIMEOUT: return "ResetTimeout";
    case VNET_E_NO_VERSION_1: return "NoVersion1";
    case VNET_E_FEATURES: return "FeaturesRefused";
    case VNET_E_QUEUES: return "Queues";
    case VNET_E_NOTIFY: return "NotifyOffset";
    case VNET_E_CONFIG: return "ConfigGeneration";
    case VNET_E_FULL: return "Full";
    case VNET_E_DEVICE: return "HostileDevice";
    case VNET_E_BROKEN: return "Broken";
    case VNET_E_NO_ACCESS_PLATFORM: return "NoAccessPlatform";
    }
    return "Unknown";
}

static int pow2_ok(uint32_t n) { return n >= VNET_QUEUE_MIN && n <= VNET_QUEUE_MAX && (n & (n - 1)) == 0; }

/* Layout of one queue sized for qsize, starting at base; returns the end. */
static size_t queue_layout(vnet_queue *q, size_t base, uint32_t qsize)
{
    size_t at = ALIGN_UP(base, 64);
    q->desc_off = at;  at += 16u * qsize;
    at = ALIGN_UP(at, 64);
    q->avail_off = at; at += 6u + 2u * qsize;
    at = ALIGN_UP(at, 64);
    q->used_off = at;  at += 6u + 8u * qsize;
    at = ALIGN_UP(at, 64);
    q->buf_off = at;   at += (size_t)VNET_BUF_STRIDE * qsize;
    return at;
}

size_t vnet_mem_size(uint16_t qsize)
{
    if (!pow2_ok(qsize)) return 0;
    vnet_queue q;
    return queue_layout(&q, queue_layout(&q, 0, qsize), qsize);
}

/* ---- register access, bounded by the parsed capability windows ---- */
static const virtio_pci_region *win_region(const vnet_dev *d, vnet_window w)
{
    switch (w) {
    case VNET_WIN_COMMON: return &d->caps.common_cfg;
    case VNET_WIN_NOTIFY: return &d->caps.notify_cfg;
    case VNET_WIN_ISR: return &d->caps.isr_cfg;
    case VNET_WIN_DEVICE: return &d->caps.device_cfg;
    }
    return NULL;
}
static int win_ok(const vnet_dev *d, vnet_window w, uint32_t off, unsigned width)
{
    const virtio_pci_region *r = win_region(d, w);
    return r && r->present && (uint64_t)off + width <= r->length;
}
/* Callers only pass constant offsets that vnet_init checked against the
 * window lengths up front; the check here is a second line. */
static uint32_t rd(vnet_dev *d, vnet_window w, uint32_t off, unsigned width)
{
    if (!win_ok(d, w, off, width)) return 0;
    return d->ops.read(d->ops.ctx, w, off, width);
}
static void wr(vnet_dev *d, vnet_window w, uint32_t off, unsigned width, uint32_t v)
{
    if (win_ok(d, w, off, width)) d->ops.write(d->ops.ctx, w, off, width, v);
}
static void wr64(vnet_dev *d, uint32_t lo_off, uint64_t v)
{
    wr(d, VNET_WIN_COMMON, lo_off, 4, (uint32_t)v);
    wr(d, VNET_WIN_COMMON, lo_off + 4, 4, (uint32_t)(v >> 32));
}

/* ---- shared ring memory ---- */
static int in_region(const vnet_dev *d, size_t off, size_t len)
{
    return off <= d->mem_len && len <= d->mem_len - off;
}
static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

/* Write descriptor `id` of queue q for its own buffer. Refuses (returns 0)
 * when the buffer would leave the region (cannot happen for a correctly
 * sized region; kept as a guard). */
static int set_desc(vnet_dev *d, vnet_queue *q, uint16_t id, uint32_t len, uint16_t flags)
{
    size_t boff = q->buf_off + (size_t)id * VNET_BUF_STRIDE;
    if (id >= q->size || len > VNET_BUF_LEN || !in_region(d, boff, len)) return 0;
    uint8_t *e = d->mem + q->desc_off + 16u * id;
    put64(e, d->dma + boff);
    put32(e + 8, len);
    put16(e + 12, flags);
    put16(e + 14, 0);
    return 1;
}

static void avail_push(vnet_dev *d, vnet_queue *q, uint16_t id)
{
    uint8_t *a = d->mem + q->avail_off;
    put16(a + 4 + 2u * (q->avail_idx & (q->size - 1)), id);
    q->avail_idx++;
    q->posted[id] = 1;
    q->in_flight++;
    __atomic_thread_fence(__ATOMIC_RELEASE); /* ring entry before idx */
    __atomic_store_n((uint16_t *)(void *)(a + 2), q->avail_idx, __ATOMIC_RELEASE);
}

static void kick(vnet_dev *d, vnet_queue *q, uint16_t index)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST); /* idx visible before the notify */
    d->ops.notify(d->ops.ctx, q->notify_off, index);
}

static vnet_err mark_broken(vnet_dev *d)
{
    d->broken = 1;
    return VNET_E_DEVICE;
}

/* Take the next used entry, validating everything the device wrote. *got 0
 * when nothing is pending. limit = most bytes the device may report written. */
static vnet_err used_next(vnet_dev *d, vnet_queue *q, uint32_t limit, uint16_t *id_out,
                          uint32_t *len_out, int *got)
{
    *got = 0;
    uint8_t *u = d->mem + q->used_off;
    uint16_t idx = __atomic_load_n((uint16_t *)(void *)(u + 2), __ATOMIC_ACQUIRE);
    uint16_t pending = (uint16_t)(idx - q->last_used);
    if (pending == 0) return VNET_OK;
    /* more completions than posted. Defense in depth: the posted[] check
     * below also catches every case the tests construct. */
    if (pending > q->in_flight) return mark_broken(d);
    const volatile uint8_t *e = u + 4 + 8u * (q->last_used & (q->size - 1));
    uint32_t id = 0, len = 0;
    for (int i = 0; i < 4; i++) { id |= (uint32_t)e[i] << (8 * i); len |= (uint32_t)e[4 + i] << (8 * i); }
    if (id >= q->size || !q->posted[id] || len > limit) return mark_broken(d);
    q->posted[id] = 0;
    q->in_flight--;
    q->last_used++;
    *id_out = (uint16_t)id;
    *len_out = len;
    *got = 1;
    return VNET_OK;
}

static vnet_err fail(vnet_dev *d, vnet_err e)
{
    uint32_t s = rd(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1);
    wr(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1, (s | VNET_S_FAILED) & 0xffu);
    return e;
}

static vnet_err setup_queue(vnet_dev *d, uint16_t index, uint32_t want)
{
    vnet_queue *q = &d->q[index];
    wr(d, VNET_WIN_COMMON, VNET_CC_Q_SELECT, 2, index);
    uint32_t max = rd(d, VNET_WIN_COMMON, VNET_CC_Q_SIZE, 2);
    if (max == 0 || rd(d, VNET_WIN_COMMON, VNET_CC_Q_ENABLE, 2) != 0) return VNET_E_QUEUES;
    uint32_t n = want;
    while (n > max) n >>= 1;
    if (n < VNET_QUEUE_MIN) return VNET_E_QUEUES;
    q->size = (uint16_t)n;
    wr(d, VNET_WIN_COMMON, VNET_CC_Q_SIZE, 2, n);
    wr(d, VNET_WIN_COMMON, VNET_CC_Q_MSIX, 2, 0xffffu); /* polled: no vector */
    uint64_t noff = (uint64_t)rd(d, VNET_WIN_COMMON, VNET_CC_Q_NOFF, 2) * d->caps.notify_off_multiplier;
    if (noff + 2 > d->caps.notify_cfg.length) return VNET_E_NOTIFY;
    q->notify_off = (uint32_t)noff;
    wr64(d, VNET_CC_Q_DESCLO, d->dma + q->desc_off);
    wr64(d, VNET_CC_Q_AVAILLO, d->dma + q->avail_off);
    wr64(d, VNET_CC_Q_USEDLO, d->dma + q->used_off);
    put16(d->mem + q->avail_off, VNET_AVAIL_F_NO_INTERRUPT);
    wr(d, VNET_WIN_COMMON, VNET_CC_Q_ENABLE, 2, 1);
    return VNET_OK;
}

vnet_err vnet_init(vnet_dev *d, const vnet_ops *ops, const virtio_pci_caps *caps,
                   void *mem, uint64_t dma, size_t mem_len, uint16_t qsize)
{
    return vnet_init_flags(d, ops, caps, mem, dma, mem_len, qsize, 0);
}

vnet_err vnet_init_flags(vnet_dev *d, const vnet_ops *ops, const virtio_pci_caps *caps, void *mem, uint64_t dma,
                         size_t mem_len, uint16_t qsize, uint32_t flags)
{
    if (!d) return VNET_E_ARG;
    memset(d, 0, sizeof *d);
    d->broken = 1; /* until init succeeds */
    if ((flags & ~VNET_INIT_REQUIRE_ACCESS_PLATFORM) || !ops || !ops->read || !ops->write || !ops->notify || !caps ||
        !mem || !pow2_ok(qsize))
        return VNET_E_ARG;
    /* required windows: common (whole structure), notify (+ multiplier), isr, device */
    if (!caps->common_cfg.present || caps->common_cfg.length < VNET_CC_LEN || !caps->notify_cfg.present ||
        !caps->has_notify_off_multiplier || caps->notify_cfg.length < 2 || !caps->isr_cfg.present ||
        !caps->device_cfg.present)
        return VNET_E_CAPS;
    size_t need = vnet_mem_size(qsize);
    if (mem_len < need || ((uintptr_t)mem & 15u) || (dma & 15u) || dma > UINT64_MAX - mem_len)
        return VNET_E_MEM;
    d->ops = *ops;
    d->caps = *caps;
    d->mem = mem;
    d->dma = dma;
    d->mem_len = mem_len;
    memset(mem, 0, need);
    size_t end = queue_layout(&d->q[VNET_RX_QUEUE], 0, qsize);
    queue_layout(&d->q[VNET_TX_QUEUE], end, qsize);

    /* 3.1.1: reset, ACKNOWLEDGE, DRIVER */
    wr(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1, 0);
    unsigned polls = 0;
    while (rd(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1) != 0)
        if (++polls >= VNET_RESET_POLLS) return VNET_E_RESET_TIMEOUT;
    wr(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1, VNET_S_ACK);
    wr(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1, VNET_S_ACK | VNET_S_DRIVER);

    /* features */
    wr(d, VNET_WIN_COMMON, VNET_CC_DFSELECT, 4, 0);
    uint64_t offered = rd(d, VNET_WIN_COMMON, VNET_CC_DF, 4);
    wr(d, VNET_WIN_COMMON, VNET_CC_DFSELECT, 4, 1);
    offered |= (uint64_t)rd(d, VNET_WIN_COMMON, VNET_CC_DF, 4) << 32;
    if (!(offered >> VNET_F_VERSION_1 & 1)) return fail(d, VNET_E_NO_VERSION_1);
    /* Fail closed: a caller that confines DMA with an IOMMU must not run a
     * device that would DMA around it. */
    if ((flags & VNET_INIT_REQUIRE_ACCESS_PLATFORM) && !(offered >> VNET_F_ACCESS_PLATFORM & 1))
        return fail(d, VNET_E_NO_ACCESS_PLATFORM);
    uint64_t accept =
        (1ull << VNET_F_VERSION_1) | (offered & ((1ull << VNET_F_MAC) | (1ull << VNET_F_ACCESS_PLATFORM)));
    if (accept >> VNET_F_MAC & 1) {
        if (caps->device_cfg.length < 6) return fail(d, VNET_E_CAPS);
    }
    wr(d, VNET_WIN_COMMON, VNET_CC_GFSELECT, 4, 0);
    wr(d, VNET_WIN_COMMON, VNET_CC_GF, 4, (uint32_t)accept);
    wr(d, VNET_WIN_COMMON, VNET_CC_GFSELECT, 4, 1);
    wr(d, VNET_WIN_COMMON, VNET_CC_GF, 4, (uint32_t)(accept >> 32));
    wr(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1, VNET_S_ACK | VNET_S_DRIVER | VNET_S_FEATURES_OK);
    if (!(rd(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1) & VNET_S_FEATURES_OK)) return fail(d, VNET_E_FEATURES);
    d->features = accept;

    /* queues: 0 = receiveq1, 1 = transmitq1 */
    wr(d, VNET_WIN_COMMON, VNET_CC_MSIX, 2, 0xffffu);
    if (rd(d, VNET_WIN_COMMON, VNET_CC_NUMQ, 2) < 2) return fail(d, VNET_E_QUEUES);
    for (uint16_t i = 0; i < 2; i++) {
        vnet_err e = setup_queue(d, i, qsize);
        if (e) return fail(d, e);
    }

    /* MAC, read under a stable config generation */
    if (accept >> VNET_F_MAC & 1) {
        unsigned t = 0;
        for (;; t++) {
            if (t >= VNET_CFGGEN_TRIES) return fail(d, VNET_E_CONFIG);
            uint32_t g0 = rd(d, VNET_WIN_COMMON, VNET_CC_CFGGEN, 1);
            for (uint32_t i = 0; i < 6; i++) d->mac[i] = (uint8_t)rd(d, VNET_WIN_DEVICE, i, 1);
            if (rd(d, VNET_WIN_COMMON, VNET_CC_CFGGEN, 1) == g0) break;
        }
        d->has_mac = 1;
    }

    /* post every RX buffer, then DRIVER_OK, then the first notify */
    vnet_queue *rx = &d->q[VNET_RX_QUEUE];
    for (uint16_t id = 0; id < rx->size; id++) {
        if (!set_desc(d, rx, id, VNET_BUF_LEN, VNET_DESC_F_WRITE)) return fail(d, VNET_E_MEM);
        avail_push(d, rx, id);
    }
    wr(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1,
       VNET_S_ACK | VNET_S_DRIVER | VNET_S_FEATURES_OK | VNET_S_DRIVER_OK);
    uint32_t s = rd(d, VNET_WIN_COMMON, VNET_CC_STATUS, 1);
    if ((s & (VNET_S_NEEDS_RESET | VNET_S_FAILED)) || !(s & VNET_S_DRIVER_OK)) return fail(d, VNET_E_DEVICE);
    d->broken = 0;
    kick(d, rx, VNET_RX_QUEUE);
    return VNET_OK;
}

vnet_err vnet_tx_reclaim(vnet_dev *d, unsigned *reclaimed)
{
    if (reclaimed) *reclaimed = 0;
    if (!d) return VNET_E_ARG;
    if (d->broken) return VNET_E_BROKEN;
    vnet_queue *q = &d->q[VNET_TX_QUEUE];
    for (;;) {
        uint16_t id; uint32_t len; int got;
        /* TX buffers are device-readable only (QEMU reports 0 written); a
         * report above one buffer length is hostile. */
        vnet_err e = used_next(d, q, VNET_BUF_LEN, &id, &len, &got);
        if (e || !got) return e;
        if (reclaimed) (*reclaimed)++;
    }
}

vnet_err vnet_tx(vnet_dev *d, const uint8_t *frame, size_t len)
{
    if (!d || !frame || len < 14 || len > VNET_FRAME_MAX) return VNET_E_ARG;
    if (d->broken) return VNET_E_BROKEN;
    vnet_queue *q = &d->q[VNET_TX_QUEUE];
    if (q->in_flight >= q->size) return VNET_E_FULL;
    uint16_t id = 0;
    while (id < q->size && q->posted[id]) id++;
    if (id >= q->size) return VNET_E_FULL;
    if (!set_desc(d, q, id, (uint32_t)(VNET_HDR_LEN + len), 0)) return VNET_E_MEM;
    uint8_t *b = d->mem + q->buf_off + (size_t)id * VNET_BUF_STRIDE;
    memset(b, 0, VNET_HDR_LEN); /* flags 0, GSO_NONE: no offloads negotiated */
    memcpy(b + VNET_HDR_LEN, frame, len);
    avail_push(d, q, id);
    kick(d, q, VNET_TX_QUEUE);
    return VNET_OK;
}

vnet_err vnet_rx(vnet_dev *d, uint8_t *out, size_t cap, size_t *len, int *got)
{
    if (got) *got = 0;
    if (len) *len = 0;
    if (!d || !out || !len || !got || cap < VNET_FRAME_MAX) return VNET_E_ARG;
    if (d->broken) return VNET_E_BROKEN;
    vnet_queue *q = &d->q[VNET_RX_QUEUE];
    uint16_t id; uint32_t n; int have;
    vnet_err e = used_next(d, q, VNET_BUF_LEN, &id, &n, &have);
    if (e || !have) return e;
    if (n < VNET_HDR_LEN) return mark_broken(d); /* every RX completion carries the header */
    size_t flen = n - VNET_HDR_LEN;              /* <= VNET_FRAME_MAX by the limit above */
    memcpy(out, d->mem + q->buf_off + (size_t)id * VNET_BUF_STRIDE + VNET_HDR_LEN, flen);
    if (!set_desc(d, q, id, VNET_BUF_LEN, VNET_DESC_F_WRITE)) return mark_broken(d);
    avail_push(d, q, id);
    kick(d, q, VNET_RX_QUEUE);
    *len = flen;
    *got = 1;
    return VNET_OK;
}
