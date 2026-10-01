/* net_bind.c -- virtio-net binding and UDP round trip (see net_bind.h).
 * Freestanding. */
#include "net_bind.h"
#include "ck.h"
#include "net_udp.h"
#include <string.h>

#define WIN_N 4
#define ARP_TRIES 4u
#define ARP_WAIT_US 500000u
#define UDP_TRIES 5u
#define UDP_WAIT_US 1000000u
#define RESET_WAIT_US 100000u
#define PROBE_WAIT_US 3000000u
#define CANARY_BYTE 0x5au

typedef struct {
    const pci_func *pf;
    volatile uint8_t *bar_va[PCI_MAX_BARS];
    volatile uint8_t *win[WIN_N];
    vnet_dev dev;
    int bm_on, confined;
    uint32_t stream_id;
} ck_vnet;

static ck_vnet g_net;
/* ck_dma_alloc memory is never freed: allocate the shared region once and
 * reuse it on a later bind. */
static uint8_t *g_dma_mem;
static uint64_t g_dma_phys;
static uint8_t frame[VNET_FRAME_MAX];
static uint8_t rxbuf[VNET_FRAME_MAX];

static uint32_t o_read(void *ctx, vnet_window w, uint32_t off, unsigned width)
{
    volatile uint8_t *p = ((ck_vnet *)ctx)->win[w] + off;
    if (width == 1) return *p;
    if (width == 2) return *(volatile uint16_t *)p;
    return *(volatile uint32_t *)p;
}
static void o_write(void *ctx, vnet_window w, uint32_t off, unsigned width, uint32_t v)
{
    volatile uint8_t *p = ((ck_vnet *)ctx)->win[w] + off;
    if (width == 1) *p = (uint8_t)v;
    else if (width == 2) *(volatile uint16_t *)p = (uint16_t)v;
    else *(volatile uint32_t *)p = v;
    ck_mb();
}
static void o_notify(void *ctx, uint32_t off, uint16_t q)
{
    ck_mb(); /* ring writes visible before the doorbell */
    *(volatile uint16_t *)(((ck_vnet *)ctx)->win[VNET_WIN_NOTIFY] + off) = q;
}

/* Map the BAR behind one capability window; 0 on a bad BAR or a window
 * outside it. */
static volatile uint8_t *map_window(ck_vnet *n, const virtio_pci_region *r)
{
    if (!r->present || r->bar >= PCI_MAX_BARS) return 0;
    const pci_bar *b = &n->pf->bar[r->bar];
    if (b->io || b->addr == 0 || b->size == 0) return 0;
    if ((uint64_t)r->offset + r->length > b->size) return 0;
    if (!n->bar_va[r->bar]) n->bar_va[r->bar] = (volatile uint8_t *)ck_mmio_map(b->addr, (size_t)b->size);
    return n->bar_va[r->bar] + r->offset;
}

static void hex8(uint32_t v, char *o)
{
    static const char h[] = "0123456789abcdef";
    for (int i = 7; i >= 0; i--, v >>= 4) o[i] = h[v & 15u];
}

static int has_prefix(const uint8_t *b, size_t n, const char *s, size_t sn)
{
    return n >= sn && memcmp(b, s, sn) == 0;
}
static int contains(const uint8_t *b, size_t n, const char *s, size_t sn)
{
    for (size_t i = 0; i + sn <= n; i++)
        if (memcmp(b + i, s, sn) == 0) return 1;
    return 0;
}

int ck_net_live(void) { return g_net.pf && (g_net.bm_on || g_net.confined); }

void ck_net_release(void)
{
    ck_vnet *n = &g_net;
    if (!n->pf) return;
    if (n->bm_on) {
        /* Device reset (status 0) stops the queues; then cut bus mastering. */
        uint32_t st = 0xffu;
        if (n->win[VNET_WIN_COMMON]) {
            o_write(n, VNET_WIN_COMMON, VNET_CC_STATUS, 1, 0);
            uint64_t t0 = ck_time_us();
            while ((st = o_read(n, VNET_WIN_COMMON, VNET_CC_STATUS, 1)) != 0 && ck_time_us() - t0 < RESET_WAIT_US)
                ck_udelay(10);
        }
        ck_printf("virtio_net: device reset status=0x%02x (%s)\n", st, st == 0 ? "stopped" : "TIMEOUT");
        if (pci_bus_master_off(n->pf) == 0) {
            n->bm_on = 0;
            ck_printf("dma_gate: virtio_net bus master revoked\n");
        } else
            ck_printf("dma_gate: virtio_net bus master revoke FAILED (command register still has BME)\n");
    }
    if (n->confined) {
        int urc = ck_dma_unconfine(n->stream_id);
        n->confined = 0;
        ck_printf("smmu: virtio_net stream 0x%x %s (rc=%d)\n", n->stream_id,
                  urc == 0 ? "returned to abort" : "abort FAILED", urc);
    }
}

/* Poll RX until `want` arrives or `us` passes. Answers ARP requests for our
 * address on the way. Returns the kind seen (CK_NET_IGNORED on timeout), or
 * -1 when the device is broken. */
static int wait_for(ck_vnet *n, ck_net_peer *p, ck_net_kind want, uint32_t us, size_t *len_out, int *csum,
                    unsigned *frames)
{
    uint64_t t0 = ck_time_us();
    do {
        size_t len = 0;
        int got = 0;
        vnet_err e = vnet_rx(&n->dev, rxbuf, sizeof rxbuf, &len, &got);
        if (e != VNET_OK) {
            ck_printf("net: rx error %s\n", vnet_err_name(e));
            return -1;
        }
        (void)vnet_tx_reclaim(&n->dev, 0);
        if (!got) continue;
        (*frames)++;
        net_mac mac;
        net_arp_packet req;
        const uint8_t *pl = 0;
        size_t pn = 0;
        ck_net_kind k = ck_net_classify(p, rxbuf, len, &mac, &req, &pl, &pn, csum);
        if (k == CK_NET_ARP_ASK) {
            size_t w = ck_net_arp_reply(p, &req, frame, sizeof frame);
            if (w && vnet_tx(&n->dev, frame, w) == VNET_OK)
                ck_printf("net: arp answered who-has %u.%u.%u.%u\n", p->ip.b[0], p->ip.b[1], p->ip.b[2], p->ip.b[3]);
            continue;
        }
        if (k != (ck_net_kind)want) continue;
        if (k == CK_NET_ARP_GW) p->gw_mac = mac;
        if (k == CK_NET_UDP_REPLY) {
            /* Keep the reply: move the payload to the front of rxbuf. */
            memmove(rxbuf, pl, pn);
            *len_out = pn;
        }
        return (int)k;
    } while (ck_time_us() - t0 < us);
    return CK_NET_IGNORED;
}

static int roundtrip(ck_vnet *n, ck_net_peer *pp)
{
    ck_net_peer p;
    memset(&p, 0, sizeof p);
    memset(pp, 0, sizeof *pp);
    memcpy(p.mac.b, n->dev.mac, 6);
    static const net_ipv4 me = {{10, 0, 2, 15}}, gw = {{10, 0, 2, 2}};
    p.ip = me;
    p.gw_ip = gw;
    p.lport = CK_NET_LOCAL_PORT;
    p.rport = CK_NET_ECHO_PORT;
    unsigned frames = 0, tries = 0;
    size_t dummy = 0;
    int csum = 0, k = CK_NET_IGNORED;

    for (tries = 1; tries <= ARP_TRIES && k != CK_NET_ARP_GW; tries++) {
        size_t w = ck_net_arp_request(&p, frame, sizeof frame);
        if (!w || vnet_tx(&n->dev, frame, w) != VNET_OK) return CK_NET_E_TX;
        k = wait_for(n, &p, CK_NET_ARP_GW, ARP_WAIT_US, &dummy, &csum, &frames);
        if (k < 0) return CK_NET_E_RX;
    }
    if (k != CK_NET_ARP_GW) {
        ck_printf("net: arp who-has 10.0.2.2 FAIL (no reply after %u tries, frames_seen=%u)\n", ARP_TRIES, frames);
        return CK_NET_E_ARP;
    }
    ck_printf("net: arp who-has 10.0.2.2 tell 10.0.2.15 -> %02x:%02x:%02x:%02x:%02x:%02x tries=%u\n", p.gw_mac.b[0],
              p.gw_mac.b[1], p.gw_mac.b[2], p.gw_mac.b[3], p.gw_mac.b[4], p.gw_mac.b[5], tries - 1);

    static char msg[] = "AIENOS-CK-NET ping nonce=00000000";
    hex8((uint32_t)ck_time_us() ^ 0x5eedc0deu, msg + sizeof msg - 9);
    const size_t mlen = sizeof msg - 1;
    unsigned reclaimed = 0;
    k = CK_NET_IGNORED;
    for (tries = 1; tries <= UDP_TRIES && k != CK_NET_UDP_REPLY; tries++) {
        size_t w = ck_net_udp_frame(&p, (uint16_t)(0x4e00u + tries), (const uint8_t *)msg, mlen, frame, sizeof frame);
        vnet_err e = w ? vnet_tx(&n->dev, frame, w) : VNET_E_ARG;
        if (e != VNET_OK) {
            ck_printf("net: udp tx FAIL (%s)\n", vnet_err_name(e));
            return CK_NET_E_TX;
        }
        /* The device must hand the TX descriptor back (bounded). */
        uint64_t t0 = ck_time_us();
        unsigned r = 0;
        while (ck_time_us() - t0 < UDP_WAIT_US) {
            r = 0;
            if (vnet_tx_reclaim(&n->dev, &r) != VNET_OK) return CK_NET_E_TX;
            reclaimed += r;
            if (n->dev.q[VNET_TX_QUEUE].in_flight == 0) break;
        }
        ck_printf("net: udp tx 10.0.2.15:%u -> 10.0.2.2:%u frame=%u bytes payload=\"%s\" try=%u completed=%s\n",
                  CK_NET_LOCAL_PORT, CK_NET_ECHO_PORT, (unsigned)w, msg, tries,
                  n->dev.q[VNET_TX_QUEUE].in_flight == 0 ? "yes" : "NO");
        size_t pn = 0;
        k = wait_for(n, &p, CK_NET_UDP_REPLY, UDP_WAIT_US, &pn, &csum, &frames);
        if (k < 0) return CK_NET_E_RX;
        if (k != CK_NET_UDP_REPLY) continue;
        static const char pong[] = "AIENOS-CK-NET pong token=";
        char shown[160];
        ck_net_printable(rxbuf, pn, shown, sizeof shown);
        int mine = has_prefix(rxbuf, pn, pong, sizeof pong - 1) && contains(rxbuf, pn, msg, mlen);
        ck_printf("net: udp rx 10.0.2.2:%u -> 10.0.2.15:%u payload_len=%u udp_csum=%s parsed=m6a echo_of_ours=%s "
                  "payload=\"%s\"\n",
                  CK_NET_ECHO_PORT, CK_NET_LOCAL_PORT, (unsigned)pn, csum ? "verified" : "absent", mine ? "yes" : "NO",
                  shown);
        if (!mine) k = CK_NET_IGNORED; /* not the reply to our datagram: the next try sends again */
    }
    if (k != CK_NET_UDP_REPLY) {
        ck_printf("net: udp round trip FAIL (no reply after %u tries, frames_seen=%u)\n", UDP_TRIES, frames);
        return CK_NET_E_RX;
    }
    ck_printf("net: udp round trip ok tx_reclaimed=%u rx_frames=%u\n", reclaimed, frames);
    *pp = p;
    return CK_NET_OK;
}

/* SMMU negative test (net_bind.h). After a good round trip, every RX
 * descriptor the device still holds is pointed at a pattern-filled page
 * that is NOT in the stream's window (and mapped by no other entry of this
 * stream's stage-1 table), then one datagram is sent (TX buffer inside the
 * window) so the helper's reply makes the device write an RX frame. Pass:
 * the SMMU event queue holds an F_TRANSLATION record for this stream at
 * that page, the page keeps its pattern, and the positive round trip before
 * it raised no fault at all. How the device model reacts is reported, not
 * judged: QEMU 8.2 either refuses the descriptor (virtio "bogus descriptor",
 * NEEDS_RESET) or maps it through its internal bounce buffer and completes
 * the RX, the write-back of which the SMMU refuses as well (rx_completed,
 * device_status). recovery() below resets and re-inits the device either way. */
static int smmu_negative_test(ck_vnet *n, const ck_net_peer *p, uint64_t win_lo, uint64_t win_len)
{
    static volatile uint8_t *canary; /* ck_dma_alloc is never freed: once */
    static uint64_t cphys;
    if (!canary) canary = ck_dma_alloc(4096, 4096, &cphys);
    if (!canary) {
        ck_printf("net_smmu_negative: FAIL (no canary page)\n");
        return -1;
    }
    if (!(cphys + 4096u <= win_lo || cphys >= win_lo + win_len)) {
        ck_printf("net_smmu_negative: FAIL (canary page 0x%llx inside the window)\n", (unsigned long long)cphys);
        return -1;
    }
    for (uint32_t i = 0; i < 4096u; i++) canary[i] = CANARY_BYTE;
    struct ck_dma_fault fl = {0, 0, 0, 0};
    int before = ck_dma_faults(n->stream_id, 0); /* faults raised by the positive round trip (want 0) */

    vnet_queue *q = &n->dev.q[VNET_RX_QUEUE];
    unsigned redirected = 0;
    for (uint16_t id = 0; id < q->size; id++) {
        if (!q->posted[id]) continue;
        memcpy(n->dev.mem + q->desc_off + 16u * id, &cphys, 8); /* descriptor addr, little-endian */
        redirected++;
    }
    ck_mb(); /* descriptors rewritten before the datagram that draws the reply */
    uint16_t used0 = *(volatile uint16_t *)(n->dev.mem + q->used_off + 2);

    static char probe[] = "AIENOS-CK-NET ping smmu-probe nonce=00000000";
    hex8((uint32_t)ck_time_us() ^ 0x0badd0e5u, probe + sizeof probe - 9);
    size_t w = ck_net_udp_frame(p, 0x4f00u, (const uint8_t *)probe, sizeof probe - 1, frame, sizeof frame);
    vnet_err e = w ? vnet_tx(&n->dev, frame, w) : VNET_E_ARG;
    ck_printf("net_smmu_negative: rx descriptors redirected=%u to iova=0x%llx (outside window 0x%llx+0x%llx); "
              "probe datagram \"%s\" tx=%s\n",
              redirected, (unsigned long long)cphys, (unsigned long long)win_lo, (unsigned long long)win_len, probe,
              vnet_err_name(e));
    uint32_t st = 0;
    uint64_t t0 = ck_time_us();
    while (e == VNET_OK && ck_time_us() - t0 < PROBE_WAIT_US) {
        st = o_read(n, VNET_WIN_COMMON, VNET_CC_STATUS, 1);
        if (st & VNET_S_NEEDS_RESET) break;
        ck_udelay(1000);
    }
    ck_udelay(20000); /* let any further event records land */
    st = o_read(n, VNET_WIN_COMMON, VNET_CC_STATUS, 1);
    n->dev.broken = 1; /* descriptors no longer point into the region: never use them again */
    int faults = ck_dma_faults(n->stream_id, &fl);
    int intact = 1;
    for (uint32_t i = 0; i < 4096u; i++)
        if (canary[i] != CANARY_BYTE) intact = 0;
    uint16_t rx_done = (uint16_t)(*(volatile uint16_t *)(n->dev.mem + q->used_off + 2) - used0);
    int ok = e == VNET_OK && before == 0 && faults >= 1 && fl.type == CK_DMA_FAULT_TRANSLATION &&
             fl.stream_id == n->stream_id && (fl.addr & ~(uint64_t)4095u) == cphys && intact;
    ck_printf("net_smmu_negative: %s rx dma outside window iova=0x%llx faults=%d type=0x%x sid=0x%x addr=0x%llx "
              "page=%s rx_completed=%u device_status=0x%02x needs_reset=%s faults_during_roundtrip=%d overflow=%d\n",
              ok ? "refused" : "FAIL", (unsigned long long)cphys, faults, fl.type, fl.stream_id,
              (unsigned long long)fl.addr, intact ? "intact" : "MODIFIED", rx_done, st,
              (st & VNET_S_NEEDS_RESET) ? "yes" : "no", before, fl.overflow);
    return ok ? 0 : -1;
}

/* After the negative test: reset + re-init (vnet_init writes status 0 and
 * rebuilds every descriptor inside the window) and a second full round
 * trip, still confined, with no new SMMU fault. */
static int recovery(ck_vnet *n, const vnet_ops *ops, const virtio_pci_caps *caps, uint8_t *mem, uint64_t phys,
                    size_t need)
{
    vnet_err e =
        vnet_init_flags(&n->dev, ops, caps, mem, phys, need, CK_NET_QSIZE, VNET_INIT_REQUIRE_ACCESS_PLATFORM);
    ck_printf("net_smmu_recovery: device reset + reinit %s (%s) access_platform=%s\n", e == VNET_OK ? "ok" : "FAIL",
              vnet_err_name(e), (n->dev.features >> VNET_F_ACCESS_PLATFORM & 1) ? "yes" : "no");
    if (e != VNET_OK) return -1;
    ck_net_peer p;
    int rc = roundtrip(n, &p);
    int faults = ck_dma_faults(n->stream_id, 0);
    int ok = rc == CK_NET_OK && faults == 0;
    ck_printf("net_smmu_recovery: round trip after the fault %s (rc=%d new_faults=%d)\n", ok ? "ok" : "FAIL", rc,
              faults);
    return ok ? 0 : -1;
}

int ck_net_bind_selftest(const pci_func *f, const virtio_pci_caps *caps)
{
    ck_vnet *n = &g_net;
    /* Never forget a device that may still do DMA: a live earlier bind
     * (bus master on or stream confined) must be released first. */
    if (ck_net_live()) {
        ck_printf("virtio_net: not bound (previous bind still live; release it first)\n");
        return CK_NET_E_ARG;
    }
    memset(n, 0, sizeof *n);
    if (!f || !caps) return CK_NET_E_ARG;
    n->pf = f;
    size_t need = vnet_mem_size(CK_NET_QSIZE);
    uint64_t win = ((uint64_t)need + 4095u) & ~(uint64_t)4095u;
    if (need && !g_dma_mem) g_dma_mem = ck_dma_alloc((size_t)win, 4096, &g_dma_phys);
    uint8_t *mem = need ? g_dma_mem : 0;
    uint64_t phys = g_dma_phys;
    if (!mem) {
        ck_printf("virtio_net: unavailable (DMA allocation of %u bytes failed)\n", (unsigned)win);
        return CK_NET_E_DMA;
    }
    uint32_t rid = ((uint32_t)f->bus << 8) | ((uint32_t)f->dev << 3) | (uint32_t)f->fn;
    struct ck_dma_confinement cf;
    int src = ck_dma_confine(rid, phys, win, &cf);
    if (src != 0) {
        ck_printf("dma_gate: virtio_net denied (%s rc=%d), bus master stays off\n",
                  src == CK_SMMU_ABSENT ? "NoSmmu" : "SmmuNotReady", src);
        ck_printf("virtio_net: not bound (SMMU DMA isolation not active)\n");
        return CK_NET_E_DENIED;
    }
    n->confined = 1;
    n->stream_id = cf.stream_id;
    ck_printf("smmu_dma_window: virtio_net only iova=0x%llx len=0x%llx rid=0x%x stream_id=0x%x\n",
              (unsigned long long)cf.iova, (unsigned long long)cf.len, rid, cf.stream_id);
    const virtio_pci_region *r[WIN_N] = {&caps->common_cfg, &caps->notify_cfg, &caps->isr_cfg, &caps->device_cfg};
    for (int i = 0; i < WIN_N; i++) {
        n->win[i] = map_window(n, r[i]);
        if (!n->win[i] && i != VNET_WIN_ISR) { /* ISR is unused (polled driver) */
            ck_printf("virtio_net: not bound (capability window %d outside its BAR)\n", i);
            ck_net_release();
            return CK_NET_E_ARG;
        }
    }
    pci_enable(f, 1);
    n->bm_on = 1;
    ck_printf("dma_gate: virtio_net granted (Confined), bus master on\n");
    vnet_ops ops = {n, o_read, o_write, o_notify};
    /* Fail closed: without VIRTIO_F_ACCESS_PLATFORM QEMU (and a real device
     * behind a bypassing transport) would DMA around the SMMU window. */
    vnet_err e =
        vnet_init_flags(&n->dev, &ops, caps, mem, phys, need, CK_NET_QSIZE, VNET_INIT_REQUIRE_ACCESS_PLATFORM);
    if (e != VNET_OK) {
        ck_printf("virtio_net: init FAIL (%s)\n", vnet_err_name(e));
        ck_net_release();
        return CK_NET_E_INIT;
    }
    const uint8_t *m = n->dev.mac;
    ck_printf("virtio_net: attached %02x:%02x.%u rid=0x%x qsize=rx%u/tx%u mac=%02x:%02x:%02x:%02x:%02x:%02x "
              "features=0x%llx access_platform=%s\n",
              f->bus, f->dev, f->fn, rid, n->dev.q[VNET_RX_QUEUE].size, n->dev.q[VNET_TX_QUEUE].size, m[0], m[1], m[2],
              m[3], m[4], m[5], (unsigned long long)n->dev.features,
              (n->dev.features >> VNET_F_ACCESS_PLATFORM & 1) ? "yes" : "no");
    ck_net_peer peer;
    memset(&peer, 0, sizeof peer);
    int rc = n->dev.has_mac ? roundtrip(n, &peer) : CK_NET_E_INIT;
    /* Prove the fence: device DMA outside the window is refused by the SMMU,
     * then the device recovers inside it (net_bind.h). */
    if (rc == CK_NET_OK &&
        (smmu_negative_test(n, &peer, phys, win) != 0 || recovery(n, &ops, caps, mem, phys, need) != 0))
        rc = CK_NET_E_SMMU;
    if (!n->dev.has_mac) ck_printf("net: no MAC offered by the device; round trip not attempted\n");
    ck_printf("net: selftest %s (rc=%d)\n", rc == CK_NET_OK ? "PASS" : "FAIL", rc);
    ck_net_release();
    return rc;
}
