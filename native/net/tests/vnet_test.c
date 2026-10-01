/* Lane 26 hosted tests: virtio PCI caps against real QEMU 8.2.2 config-space
 * dumps (tests/fixtures/), malformed caps, and the virtio-net split-virtqueue
 * driver against a simulated device in C that also plays hostile. Ends with
 * an M6-A UDP round trip through the TX and RX queues.
 * Not proven here: a real device, real DMA, interrupts, QEMU slirp. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aienos_net.h"
#include "../aienos_virtio_net.h"
#include "../aienos_virtio_pci.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define EQ(a, b) CHECK((long long)(a) == (long long)(b))

static uint64_t rng = 0x26;
static uint32_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (uint32_t)(rng >> 11); }

/* ---------------- capability parsing ---------------- */
static int load(const char *path, uint8_t *b, size_t n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t got = fread(b, 1, n, f);
    int extra = fgetc(f) != EOF;
    fclose(f);
    return got == n && !extra;
}
static void put32(uint8_t *c, size_t at, uint32_t v) { for (int i = 0; i < 4; i++) c[at + i] = (uint8_t)(v >> (8 * i)); }

static uint8_t qemu_trans[256], qemu_modern[256];

static void test_qemu_caps(void)
{
    virtio_pci_caps r;
    CHECK(load("tests/fixtures/qemu822_virtio_net_pci_transitional.cfg", qemu_trans, 256));
    CHECK(load("tests/fixtures/qemu822_virtio_net_pci_modern.cfg", qemu_modern, 256));
    EQ(qemu_trans[2] | qemu_trans[3] << 8, 0x1000);
    EQ(qemu_modern[2] | qemu_modern[3] << 8, 0x1041);
    const uint8_t *imgs[2] = {qemu_trans, qemu_modern};
    for (int k = 0; k < 2; k++) {
        const uint8_t *c = imgs[k];
        /* the dump contains a PCI_CFG cap (type 5) with bar 0, offset 0, length 0 at 0x84 */
        EQ(c[0x84], 9); EQ(c[0x87], 5); EQ(c[0x86], 20); EQ(c[0x90] | c[0x91] | c[0x92] | c[0x93], 0);
        EQ(virtio_pci_parse_caps(c, 256, &r), VIRTIO_PCI_OK);
        CHECK(r.common_cfg.present && r.common_cfg.bar == 4 && r.common_cfg.offset == 0 && r.common_cfg.length == 0x1000);
        CHECK(r.isr_cfg.present && r.isr_cfg.bar == 4 && r.isr_cfg.offset == 0x1000);
        CHECK(r.device_cfg.present && r.device_cfg.bar == 4 && r.device_cfg.offset == 0x2000);
        CHECK(r.notify_cfg.present && r.notify_cfg.bar == 4 && r.notify_cfg.offset == 0x3000 && r.notify_cfg.length == 0x1000);
        CHECK(r.has_notify_off_multiplier && r.notify_off_multiplier == 4);
        uint8_t big[4096] = {0};
        memcpy(big, c, 256);
        EQ(virtio_pci_parse_caps(big, 4096, &r), VIRTIO_PCI_OK);
    }
    /* malformed variants of the real image stay refused */
    uint8_t x[256];
    memcpy(x, qemu_modern, 256); put32(x, 0x4c, 0);           /* zero-length COMMON_CFG */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, qemu_modern, 256); put32(x, 0x7c, 0);           /* zero-length NOTIFY_CFG */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, qemu_modern, 256); put32(x, 0x5c, 0);           /* zero-length ISR_CFG */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, qemu_modern, 256); put32(x, 0x6c, 0);           /* zero-length DEVICE_CFG */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, qemu_modern, 256); x[0x44] = 6;                 /* COMMON_CFG bad BAR */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, qemu_modern, 256); put32(x, 0x78, 0xfffff800);  /* NOTIFY offset+length overflows */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, qemu_modern, 256); x[0x86] = 12;                /* PCI_CFG cap shorter than 16 */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_SHORT_CAPABILITY);
    memcpy(x, qemu_modern, 256); x[0x34] = 0xfc; x[0xfc] = 9; x[0xfd] = 0; /* cap past config space */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_SHORT_CAPABILITY);
    memcpy(x, qemu_modern, 256); x[0x41] = 0x98;              /* loop back to MSI-X */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_CAPABILITY_LOOP);
    memcpy(x, qemu_modern, 256); x[0x85] = 0x84;              /* PCI_CFG self loop */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_CAPABILITY_LOOP);
    memcpy(x, qemu_modern, 256); x[0x63] = 1;                 /* DEVICE_CFG retyped as a 2nd COMMON */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_DUPLICATE_CAPABILITY);
    memcpy(x, qemu_modern, 256); x[0x99] = 0x30;              /* pointer into the header */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_POINTER);
    /* PCI_CFG (and any other unmapped type) is ignored even with a junk region */
    memcpy(x, qemu_modern, 256); x[0x88] = 7; put32(x, 0x8c, 0xffffffff); put32(x, 0x90, 5);
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_OK);
    memcpy(x, qemu_modern, 256); x[0x87] = 9;                 /* VENDOR_CFG-type, length 0 */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_OK);
    /* required caps missing: the parser reports them absent, vnet_init refuses */
    memcpy(x, qemu_modern, 256); x[0x73] = 0;                 /* NOTIFY retyped to 0 */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_OK);
    CHECK(!r.notify_cfg.present); /* vnet_init then refuses: test_init, VNET_E_CAPS */
}

/* ---------------- simulated device ---------------- */
typedef struct {
    uint16_t max, size, enable, noff;
    uint64_t desc, avail, used;
    uint16_t last_avail, used_idx;
} simq;

typedef struct {
    uint8_t *mem; uint64_t dma; size_t mem_len;
    uint64_t dev_features, drv_features;
    uint32_t dfsel, gfsel;
    uint8_t status, cfggen;
    uint16_t numq, qsel;
    simq q[2];
    uint8_t mac[6];
    uint32_t mult;
    /* knobs */
    int refuse_features, reset_stuck, cfggen_unstable, preenabled;
    uint32_t noff_override;
    /* observations */
    unsigned notifies[2], faults, status_writes;
    uint8_t wire[8][2048]; size_t wire_len[8]; unsigned nwire;
} sim;

static uint8_t *bus(sim *s, uint64_t a, size_t n)
{
    if (a < s->dma || a - s->dma > s->mem_len || n > s->mem_len - (a - s->dma)) { s->faults++; return NULL; }
    return s->mem + (a - s->dma);
}
static uint16_t g16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t g32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t g64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static void s16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void s32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static uint32_t sim_read(void *ctx, vnet_window w, uint32_t off, unsigned width)
{
    sim *s = ctx;
    if (w == VNET_WIN_DEVICE) return off < 6 && width == 1 ? s->mac[off] : 0;
    if (w != VNET_WIN_COMMON) return 0;
    simq *q = &s->q[s->qsel < 2 ? s->qsel : 0];
    switch (off) {
    case VNET_CC_DF: return (uint32_t)(s->dev_features >> (s->dfsel ? 32 : 0));
    case VNET_CC_NUMQ: return s->numq;
    case VNET_CC_STATUS: return s->reset_stuck ? 1 : s->status;
    case VNET_CC_CFGGEN: return s->cfggen_unstable ? s->cfggen++ : s->cfggen;
    case VNET_CC_Q_SIZE: return s->qsel < 2 ? q->size : 0;
    case VNET_CC_Q_ENABLE: return s->qsel < 2 ? q->enable : 0;
    case VNET_CC_Q_NOFF: return s->noff_override ? s->noff_override : q->noff;
    }
    return 0;
}
static void sim_write(void *ctx, vnet_window w, uint32_t off, unsigned width, uint32_t v)
{
    sim *s = ctx;
    (void)width;
    if (w != VNET_WIN_COMMON) { s->faults++; return; }
    simq *q = &s->q[s->qsel < 2 ? s->qsel : 0];
    switch (off) {
    case VNET_CC_DFSELECT: s->dfsel = v; break;
    case VNET_CC_GFSELECT: s->gfsel = v; break;
    case VNET_CC_GF:
        if (s->gfsel) s->drv_features = (s->drv_features & 0xffffffffull) | (uint64_t)v << 32;
        else s->drv_features = (s->drv_features & ~0xffffffffull) | v;
        break;
    case VNET_CC_STATUS:
        s->status_writes++;
        if (v == 0) { s->status = 0; for (int i = 0; i < 2; i++) { s->q[i].enable = s->preenabled; s->q[i].size = s->q[i].max; s->q[i].last_avail = s->q[i].used_idx = 0; } break; }
        if ((v & VNET_S_FEATURES_OK) && !(s->status & VNET_S_FEATURES_OK)) {
            if (s->refuse_features || (s->drv_features & ~s->dev_features)) v &= ~VNET_S_FEATURES_OK;
        }
        s->status = (uint8_t)v;
        break;
    case VNET_CC_Q_SELECT: s->qsel = (uint16_t)v; break;
    case VNET_CC_Q_SIZE: if (v > q->max) s->faults++; q->size = (uint16_t)v; break;
    case VNET_CC_Q_ENABLE: q->enable = (uint16_t)v; break;
    case VNET_CC_Q_DESCLO: q->desc = (q->desc & ~0xffffffffull) | v; break;
    case VNET_CC_Q_DESCHI: q->desc = (q->desc & 0xffffffffull) | (uint64_t)v << 32; break;
    case VNET_CC_Q_AVAILLO: q->avail = (q->avail & ~0xffffffffull) | v; break;
    case VNET_CC_Q_AVAILHI: q->avail = (q->avail & 0xffffffffull) | (uint64_t)v << 32; break;
    case VNET_CC_Q_USEDLO: q->used = (q->used & ~0xffffffffull) | v; break;
    case VNET_CC_Q_USEDHI: q->used = (q->used & 0xffffffffull) | (uint64_t)v << 32; break;
    default: break;
    }
}
static void sim_notify(void *ctx, uint32_t off, uint16_t queue)
{
    sim *s = ctx;
    if (!(s->status & VNET_S_DRIVER_OK) || queue > 1 || off != (uint32_t)s->q[queue].noff * s->mult) s->faults++;
    else s->notifies[queue]++;
}
static const vnet_ops sim_ops = {0, sim_read, sim_write, sim_notify};

static void sim_reset(sim *s, uint8_t *mem, uint64_t dma, size_t len)
{
    memset(s, 0, sizeof *s);
    s->mem = mem; s->dma = dma; s->mem_len = len;
    s->dev_features = (1ull << VNET_F_VERSION_1) | (1ull << VNET_F_MAC);
    s->numq = 3; s->mult = 4;
    s->q[0].max = s->q[1].max = 256;
    s->q[0].noff = 0; s->q[1].noff = 1;
    for (int i = 0; i < 6; i++) s->mac[i] = (uint8_t)(0x52 + i);
}

static void push_used(sim *s, int qi, uint32_t id, uint32_t len)
{
    simq *q = &s->q[qi];
    uint8_t *u = bus(s, q->used, 6 + 8u * q->size);
    if (!u) return;
    uint8_t *e = u + 4 + 8u * (q->used_idx % q->size);
    s32(e, id); s32(e + 4, len);
    q->used_idx++;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    s16(u + 2, q->used_idx);
}

/* Read the next available descriptor of queue qi; checks every field. */
static int pop_avail(sim *s, int qi, uint16_t *id, uint8_t **buf, uint32_t *len, uint16_t *flags)
{
    simq *q = &s->q[qi];
    uint8_t *a = bus(s, q->avail, 6 + 2u * q->size);
    if (!a || !q->enable) return 0;
    if (g16(a + 2) == q->last_avail) return 0;
    if ((uint16_t)(g16(a + 2) - q->last_avail) > q->size) { s->faults++; return 0; }
    *id = g16(a + 4 + 2u * (q->last_avail % q->size));
    q->last_avail++;
    if (*id >= q->size) { s->faults++; return 0; }
    uint8_t *d = bus(s, q->desc + 16u * *id, 16);
    if (!d) return 0;
    *len = g32(d + 8); *flags = g16(d + 12);
    if (*flags & 1u) s->faults++; /* NEXT: the driver never chains */
    *buf = bus(s, g64(d), *len);
    return *buf != NULL;
}

/* Device transmits everything pending on TX (completes with len 0). */
static unsigned sim_tx(sim *s)
{
    unsigned n = 0; uint16_t id, fl; uint8_t *b; uint32_t len;
    while (pop_avail(s, 1, &id, &b, &len, &fl)) {
        if ((fl & VNET_DESC_F_WRITE) || len < VNET_HDR_LEN || len > VNET_BUF_LEN) s->faults++;
        for (unsigned i = 0; i < VNET_HDR_LEN; i++) if (b[i]) s->faults++;
        unsigned slot = s->nwire++ % 8;
        s->wire_len[slot] = len - VNET_HDR_LEN;
        memcpy(s->wire[slot], b + VNET_HDR_LEN, len - VNET_HDR_LEN);
        push_used(s, 1, id, 0);
        n++;
    }
    return n;
}
/* Device receives one frame into the next RX buffer. */
static int sim_rx(sim *s, const uint8_t *f, size_t n)
{
    uint16_t id, fl; uint8_t *b; uint32_t len;
    if (!pop_avail(s, 0, &id, &b, &len, &fl)) return 0;
    if (!(fl & VNET_DESC_F_WRITE) || len < VNET_HDR_LEN + n) { s->faults++; return 0; }
    memset(b, 0, VNET_HDR_LEN); s16(b + 10, 1);
    memcpy(b + VNET_HDR_LEN, f, n);
    push_used(s, 0, id, (uint32_t)(VNET_HDR_LEN + n));
    return 1;
}

/* every descriptor in both tables lies inside the shared region */
static void check_descs(const vnet_dev *d)
{
    for (int qi = 0; qi < 2; qi++) {
        const vnet_queue *q = &d->q[qi];
        for (unsigned i = 0; i < q->size; i++) {
            const uint8_t *e = d->mem + q->desc_off + 16u * i;
            uint64_t a = g64(e); uint32_t l = g32(e + 8);
            if (l == 0) continue;
            CHECK(a >= d->dma && a - d->dma <= d->mem_len && l <= d->mem_len - (a - d->dma));
            CHECK(l <= VNET_BUF_LEN);
        }
    }
}

static uint8_t region[1 << 20] __attribute__((aligned(4096)));
#define DMA 0x80000000ull

static int bring_up(vnet_dev *d, sim *s, uint16_t qsize)
{
    vnet_ops o = sim_ops; o.ctx = s;
    virtio_pci_caps c;
    if (virtio_pci_parse_caps(qemu_modern, 256, &c) != VIRTIO_PCI_OK) return -1;
    return vnet_init(d, &o, &c, region, DMA, sizeof region, qsize);
}

static void test_init(void)
{
    sim s; vnet_dev d;
    EQ(vnet_mem_size(3), 0); EQ(vnet_mem_size(1), 0); EQ(vnet_mem_size(512), 0);
    CHECK(vnet_mem_size(256) <= sizeof region);

    sim_reset(&s, region, DMA, sizeof region);
    s.dev_features = ~0ull; /* offers everything, incl. packed, indirect, ACCESS_PLATFORM */
    EQ(bring_up(&d, &s, 256), VNET_OK);
    /* ACCESS_PLATFORM is accepted when offered (virtio 1.x 6.1 SHOULD) */
    EQ(s.drv_features, (1ull << VNET_F_VERSION_1) | (1ull << VNET_F_MAC) | (1ull << VNET_F_ACCESS_PLATFORM));
    EQ(d.features, s.drv_features);
    EQ(s.status, VNET_S_ACK | VNET_S_DRIVER | VNET_S_FEATURES_OK | VNET_S_DRIVER_OK);
    CHECK(d.has_mac && d.mac[0] == 0x52 && d.mac[5] == 0x57);
    EQ(d.q[0].size, 256); EQ(d.q[1].size, 256);
    EQ(s.q[0].enable, 1); EQ(s.q[1].enable, 1);
    EQ(s.notifies[0], 1); EQ(s.faults, 0);
    check_descs(&d);

    /* without MAC */
    sim_reset(&s, region, DMA, sizeof region);
    s.dev_features = 1ull << VNET_F_VERSION_1;
    EQ(bring_up(&d, &s, 8), VNET_OK);
    CHECK(!d.has_mac); EQ(s.drv_features, 1ull << VNET_F_VERSION_1);

    /* the device offers less: largest power of two at or below */
    sim_reset(&s, region, DMA, sizeof region);
    s.q[0].max = 100; s.q[1].max = 64;
    EQ(bring_up(&d, &s, 256), VNET_OK);
    EQ(d.q[0].size, 64); EQ(d.q[1].size, 64); EQ(s.faults, 0);

    struct { const char *what; int knob; vnet_err want; } cases[] = {
        {"no VERSION_1 (legacy-only device)", 1, VNET_E_NO_VERSION_1},
        {"FEATURES_OK refused", 2, VNET_E_FEATURES},
        {"reset never completes", 3, VNET_E_RESET_TIMEOUT},
        {"one queue only", 4, VNET_E_QUEUES},
        {"queue size 0", 5, VNET_E_QUEUES},
        {"queue size 1", 6, VNET_E_QUEUES},
        {"queue already enabled", 7, VNET_E_QUEUES},
        {"notify offset outside window", 8, VNET_E_NOTIFY},
        {"config generation never settles", 9, VNET_E_CONFIG},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        sim_reset(&s, region, DMA, sizeof region);
        switch (cases[i].knob) {
        case 1: s.dev_features = 1ull << VNET_F_MAC; break;
        case 2: s.refuse_features = 1; break;
        case 3: s.reset_stuck = 1; break;
        case 4: s.numq = 1; break;
        case 5: s.q[1].max = 0; break;
        case 6: s.q[0].max = 1; break;
        case 7: s.preenabled = 1; break;
        case 8: s.noff_override = 0x400; break; /* 0x400 * 4 + 2 > 0x1000 */
        case 9: s.cfggen_unstable = 1; break;
        }
        vnet_err e = bring_up(&d, &s, 16);
        if (e != cases[i].want) fprintf(stderr, "init case '%s': got %s\n", cases[i].what, vnet_err_name(e));
        EQ(e, cases[i].want);
        CHECK(d.broken);
        if (cases[i].knob != 3) CHECK(s.status & VNET_S_FAILED);
        CHECK(!(s.status & VNET_S_DRIVER_OK));
        EQ(s.notifies[0] + s.notifies[1], 0);
        uint8_t f[64] = {0};
        EQ(vnet_tx(&d, f, 60), VNET_E_BROKEN);
    }

    /* argument and memory refusals */
    vnet_ops o = sim_ops; o.ctx = &s;
    virtio_pci_caps c, bad;
    EQ(virtio_pci_parse_caps(qemu_modern, 256, &c), VIRTIO_PCI_OK);
    sim_reset(&s, region, DMA, sizeof region);
    EQ(vnet_init(&d, &o, &c, region, DMA, sizeof region, 6), VNET_E_ARG);
    EQ(vnet_init(&d, &o, &c, region, DMA, vnet_mem_size(16) - 1, 16), VNET_E_MEM);
    EQ(vnet_init(&d, &o, &c, region + 8, DMA, sizeof region - 8, 16), VNET_E_MEM);
    EQ(vnet_init(&d, &o, &c, region, DMA + 4, sizeof region, 16), VNET_E_MEM);
    EQ(vnet_init(&d, &o, &c, region, UINT64_MAX - 0xfff, sizeof region, 16), VNET_E_MEM);
    bad = c; bad.notify_cfg.present = 0;      EQ(vnet_init(&d, &o, &bad, region, DMA, sizeof region, 16), VNET_E_CAPS);
    bad = c; bad.has_notify_off_multiplier = 0; EQ(vnet_init(&d, &o, &bad, region, DMA, sizeof region, 16), VNET_E_CAPS);
    bad = c; bad.common_cfg.length = 0x37;    EQ(vnet_init(&d, &o, &bad, region, DMA, sizeof region, 16), VNET_E_CAPS);
    bad = c; bad.isr_cfg.present = 0;         EQ(vnet_init(&d, &o, &bad, region, DMA, sizeof region, 16), VNET_E_CAPS);
    bad = c; bad.device_cfg.present = 0;      EQ(vnet_init(&d, &o, &bad, region, DMA, sizeof region, 16), VNET_E_CAPS);
    bad = c; bad.device_cfg.length = 4;       EQ(vnet_init(&d, &o, &bad, region, DMA, sizeof region, 16), VNET_E_CAPS);
    EQ(s.notifies[0] + s.notifies[1], 0);
    EQ(vnet_init_flags(&d, &o, &c, region, DMA, sizeof region, 16, 2), VNET_E_ARG); /* unknown flag */
    EQ(s.notifies[0] + s.notifies[1], 0);
}

/* VIRTIO_F_ACCESS_PLATFORM (bit 33): accepted when offered; with
 * VNET_INIT_REQUIRE_ACCESS_PLATFORM a device that does not offer it is refused
 * before FEATURES_OK (fail closed: it would DMA around the IOMMU). */
static void test_access_platform(void)
{
    sim s; vnet_dev d;
    vnet_ops o = sim_ops; o.ctx = &s;
    virtio_pci_caps c;
    EQ(virtio_pci_parse_caps(qemu_modern, 256, &c), VIRTIO_PCI_OK);
    const uint64_t ap = 1ull << VNET_F_ACCESS_PLATFORM, v1 = 1ull << VNET_F_VERSION_1, mac = 1ull << VNET_F_MAC;

    /* not offered, not required: works as before, bit not written */
    sim_reset(&s, region, DMA, sizeof region);
    EQ(vnet_init_flags(&d, &o, &c, region, DMA, sizeof region, 16, 0), VNET_OK);
    EQ(s.drv_features, v1 | mac); CHECK(!(d.features & ap));

    /* offered, not required: accepted */
    sim_reset(&s, region, DMA, sizeof region);
    s.dev_features = v1 | mac | ap;
    EQ(vnet_init(&d, &o, &c, region, DMA, sizeof region, 16), VNET_OK);
    EQ(s.drv_features, v1 | mac | ap); CHECK(d.features & ap);

    /* offered and required: accepted, device runs */
    sim_reset(&s, region, DMA, sizeof region);
    s.dev_features = v1 | mac | ap;
    EQ(vnet_init_flags(&d, &o, &c, region, DMA, sizeof region, 16, VNET_INIT_REQUIRE_ACCESS_PLATFORM), VNET_OK);
    EQ(s.drv_features, v1 | mac | ap); EQ(d.features, v1 | mac | ap); CHECK(!d.broken);
    EQ(s.status, VNET_S_ACK | VNET_S_DRIVER | VNET_S_FEATURES_OK | VNET_S_DRIVER_OK);
    uint8_t f[60] = {0};
    EQ(vnet_tx(&d, f, sizeof f), VNET_OK);
    EQ(sim_tx(&s), 1);

    /* required but not offered (QEMU without iommu_platform=on): refused before
     * FEATURES_OK, FAILED set, no feature bits written, no queue, no notify */
    const uint64_t offers[] = {v1 | mac, v1, ~0ull & ~ap};
    for (size_t i = 0; i < sizeof offers / sizeof offers[0]; i++) {
        sim_reset(&s, region, DMA, sizeof region);
        s.dev_features = offers[i];
        EQ(vnet_init_flags(&d, &o, &c, region, DMA, sizeof region, 16, VNET_INIT_REQUIRE_ACCESS_PLATFORM),
           VNET_E_NO_ACCESS_PLATFORM);
        CHECK(d.broken);
        CHECK(s.status & VNET_S_FAILED);
        CHECK(!(s.status & (VNET_S_FEATURES_OK | VNET_S_DRIVER_OK)));
        EQ(s.drv_features, 0);
        EQ(s.q[0].enable + s.q[1].enable, 0);
        EQ(s.notifies[0] + s.notifies[1], 0);
        EQ(vnet_tx(&d, f, sizeof f), VNET_E_BROKEN);
    }
    /* a legacy-only device is still refused as NoVersion1 first */
    sim_reset(&s, region, DMA, sizeof region);
    s.dev_features = mac | ap;
    EQ(vnet_init_flags(&d, &o, &c, region, DMA, sizeof region, 16, VNET_INIT_REQUIRE_ACCESS_PLATFORM),
       VNET_E_NO_VERSION_1);
    CHECK(strcmp(vnet_err_name(VNET_E_NO_ACCESS_PLATFORM), "NoAccessPlatform") == 0);
}

static void test_datapath)(void)
{
    sim s; vnet_dev d;
    sim_reset(&s, region, DMA, sizeof region);
    EQ(bring_up(&d, &s, 4), VNET_OK);
    uint8_t f[VNET_FRAME_MAX], out[VNET_FRAME_MAX];
    size_t n; int got; unsigned rc;
    for (size_t i = 0; i < sizeof f; i++) f[i] = (uint8_t)(i * 7 + 1);
    EQ(vnet_tx(&d, f, 13), VNET_E_ARG);
    EQ(vnet_tx(&d, f, VNET_FRAME_MAX + 1), VNET_E_ARG);
    EQ(vnet_rx(&d, out, VNET_FRAME_MAX - 1, &n, &got), VNET_E_ARG);
    EQ(vnet_rx(&d, out, sizeof out, &n, &got), VNET_OK); EQ(got, 0);
    /* fill TX, then full, then reclaim */
    for (int i = 0; i < 4; i++) EQ(vnet_tx(&d, f, 60 + (size_t)i), VNET_OK);
    EQ(vnet_tx(&d, f, 60), VNET_E_FULL);
    EQ(s.notifies[1], 4);
    EQ(sim_tx(&s), 4);
    EQ(s.wire_len[3], 63); CHECK(memcmp(s.wire[3], f, 63) == 0);
    EQ(vnet_tx_reclaim(&d, &rc), VNET_OK); EQ(rc, 4);
    EQ(vnet_tx(&d, f, VNET_FRAME_MAX), VNET_OK);
    EQ(sim_tx(&s), 1);
    EQ(s.wire_len[4], VNET_FRAME_MAX); CHECK(memcmp(s.wire[4], f, VNET_FRAME_MAX) == 0);
    /* 70,000 frames each way: 16-bit ring indices wrap */
    unsigned bad = 0;
    for (unsigned i = 0; i < 70000; i++) {
        size_t len = 14 + (i * 131u) % (VNET_FRAME_MAX - 13);
        f[0] = (uint8_t)i; f[len - 1] = (uint8_t)(i >> 8);
        if (!sim_rx(&s, f, len)) bad++;
        if (vnet_rx(&d, out, sizeof out, &n, &got) != VNET_OK || !got || n != len || memcmp(out, f, len)) bad++;
        if (vnet_tx_reclaim(&d, NULL) != VNET_OK || vnet_tx(&d, f, len) != VNET_OK || sim_tx(&s) != 1) bad++;
        if (s.wire_len[(s.nwire - 1) % 8] != len || memcmp(s.wire[(s.nwire - 1) % 8], f, len)) bad++;
    }
    EQ(bad, 0);
    CHECK(s.q[0].used_idx < 70000u); /* wrapped */
    EQ(s.faults, 0);
    check_descs(&d);
}

/* hostile completions: each must be refused and leave the device broken */
static void test_hostile(void)
{
    sim s; vnet_dev d;
    uint8_t f[128] = {0}, out[VNET_FRAME_MAX];
    size_t n; int got;
    for (int k = 0; k < 9; k++) {
        sim_reset(&s, region, DMA, sizeof region);
        EQ(bring_up(&d, &s, 8), VNET_OK);
        vnet_err e = VNET_OK;
        switch (k) {
        case 0: push_used(&s, 0, 8, 60); e = vnet_rx(&d, out, sizeof out, &n, &got); break;      /* id == size */
        case 1: push_used(&s, 0, 0xffffffffu, 60); e = vnet_rx(&d, out, sizeof out, &n, &got); break;
        case 2: push_used(&s, 0, 3, VNET_BUF_LEN + 1); e = vnet_rx(&d, out, sizeof out, &n, &got); break; /* oversized */
        case 3: push_used(&s, 0, 3, VNET_HDR_LEN - 1); e = vnet_rx(&d, out, sizeof out, &n, &got); break; /* short */
        case 4: { /* used idx runs ahead of everything posted */
            uint8_t *u = region + d.q[0].used_off; s16(u + 2, 9);
            e = vnet_rx(&d, out, sizeof out, &n, &got); break; }
        case 5: e = vnet_tx(&d, f, 60); push_used(&s, 1, 1, 0); if (!e) e = vnet_tx_reclaim(&d, NULL); break; /* never posted */
        case 6: vnet_tx(&d, f, 60); vnet_tx(&d, f, 60); push_used(&s, 1, 0, 0); push_used(&s, 1, 0, 0);
                e = vnet_tx_reclaim(&d, NULL); break;                                          /* double completion */
        case 7: push_used(&s, 1, 0, 0); e = vnet_tx_reclaim(&d, NULL); break;                 /* completion with nothing posted */
        case 8: vnet_tx(&d, f, 60); push_used(&s, 1, 0, 0x10000); e = vnet_tx_reclaim(&d, NULL); break; /* TX len oversized */
        }
        if (e != VNET_E_DEVICE) fprintf(stderr, "hostile case %d: got %s\n", k, vnet_err_name(e));
        EQ(e, VNET_E_DEVICE);
        EQ(vnet_rx(&d, out, sizeof out, &n, &got), VNET_E_BROKEN);
        EQ(vnet_tx(&d, f, 60), VNET_E_BROKEN);
        EQ(vnet_tx_reclaim(&d, NULL), VNET_E_BROKEN);
    }
    /* a hostile device rewriting the descriptor table cannot steer the driver:
       re-posted descriptors are rebuilt from the id */
    sim_reset(&s, region, DMA, sizeof region);
    EQ(bring_up(&d, &s, 8), VNET_OK);
    memset(region + d.q[0].desc_off, 0xa5, 16u * 8);
    for (int i = 0; i < 8; i++) { push_used(&s, 0, (uint32_t)i, 60); EQ(vnet_rx(&d, out, sizeof out, &n, &got), VNET_OK); EQ(got, 1); EQ(n, 48); }
    check_descs(&d);

    /* seeded random hostile used-ring traffic: never crashes, never delivers
       more than a frame, never writes a descriptor outside the region */
    unsigned delivered = 0, refused = 0;
    for (unsigned round = 0; round < 2000; round++) {
        sim_reset(&s, region, DMA, sizeof region);
        if (bring_up(&d, &s, (uint16_t)(2u << (rnd() % 7))) != VNET_OK) { CHECK(0); continue; }
        for (unsigned step = 0; step < 40 && !d.broken; step++) {
            uint32_t r = rnd();
            switch (r % 6) {
            case 0: sim_rx(&s, f, 14 + rnd() % 100); break;
            case 1: vnet_tx(&d, f, 14 + rnd() % 100); break;
            case 2: sim_tx(&s); break;
            case 3: push_used(&s, (int)(rnd() % 2), rnd() % (d.q[0].size + 2), rnd() % 2 ? rnd() % (VNET_BUF_LEN + 4) : 60); break;
            case 4: { uint8_t *u = region + d.q[rnd() % 2].used_off; s16(u + 2, (uint16_t)(g16(u + 2) + rnd() % 3)); break; }
            default: break;
            }
            vnet_err e = vnet_rx(&d, out, sizeof out, &n, &got);
            if (e == VNET_OK && got) { delivered++; CHECK(n <= VNET_FRAME_MAX); }
            if (e == VNET_OK) e = vnet_tx_reclaim(&d, NULL);
            if (e != VNET_OK) { CHECK(e == VNET_E_DEVICE && d.broken); refused++; }
            check_descs(&d);
            CHECK(d.q[0].in_flight <= d.q[0].size && d.q[1].in_flight <= d.q[1].size);
        }
    }
    CHECK(delivered > 1000 && refused > 500);
    printf("vnet_test: hostile fuzz delivered=%u refused=%u\n", delivered, refused);
}

/* M6-A UDP frame out through TX, reply in through RX, parsed by M6-A */
static void test_m6a_udp(void)
{
    sim s; vnet_dev d;
    sim_reset(&s, region, DMA, sizeof region);
    EQ(bring_up(&d, &s, 16), VNET_OK);
    net_mac me, peer = {{0x02, 0, 0, 0, 0, 2}};
    memcpy(me.b, d.mac, 6);
    net_ipv4 ip_me = {{10, 0, 2, 15}}, ip_peer = {{10, 0, 2, 2}};
    const char *msg = "aienos lane26 ping";
    uint8_t udp[256], ip[512], frame[VNET_FRAME_MAX];
    size_t ul, il, fl;
    net_udp_header uh = {40000, 7};
    EQ(net_udp_build(&uh, (const uint8_t *)msg, strlen(msg), ip_me, ip_peer, udp, sizeof udp, &ul), NET_OK);
    net_ipv4_header ih = {0, 1, 64, NET_IPPROTO_UDP, ip_me, ip_peer};
    EQ(net_ipv4_build(&ih, udp, ul, ip, sizeof ip, &il), NET_OK);
    net_eth_frame ef = {peer, me, NET_ETHERTYPE_IPV4, ip, il};
    EQ(net_eth_build(&ef, frame, sizeof frame, &fl), NET_OK);
    EQ(vnet_tx(&d, frame, fl), VNET_OK);
    EQ(sim_tx(&s), 1);
    EQ(s.wire_len[0], fl); CHECK(memcmp(s.wire[0], frame, fl) == 0);

    /* the device side parses what went out with M6-A and answers */
    net_eth_frame pe; net_ipv4_header pih; net_udp_header puh;
    const uint8_t *pl, *data; size_t pll, dl;
    EQ(net_eth_parse(s.wire[0], s.wire_len[0], &pe), NET_OK);
    EQ(net_ipv4_parse(pe.payload, pe.payload_len, &pih, &pl, &pll), NET_OK);
    EQ(net_udp_parse(pl, pll, pih.source, pih.destination, &puh, &data, &dl), NET_OK);
    CHECK(dl == strlen(msg) && memcmp(data, msg, dl) == 0);
    const char *rep = "pong from simulated device";
    net_udp_header rh = {puh.destination_port, puh.source_port};
    EQ(net_udp_build(&rh, (const uint8_t *)rep, strlen(rep), ip_peer, ip_me, udp, sizeof udp, &ul), NET_OK);
    net_ipv4_header rih = {0, 9, 64, NET_IPPROTO_UDP, ip_peer, ip_me};
    EQ(net_ipv4_build(&rih, udp, ul, ip, sizeof ip, &il), NET_OK);
    net_eth_frame ref = {me, peer, NET_ETHERTYPE_IPV4, ip, il};
    EQ(net_eth_build(&ref, frame, sizeof frame, &fl), NET_OK);
    EQ(sim_rx(&s, frame, fl), 1);

    uint8_t out[VNET_FRAME_MAX]; size_t n; int got;
    EQ(vnet_rx(&d, out, sizeof out, &n, &got), VNET_OK); EQ(got, 1); EQ(n, fl);
    EQ(net_eth_parse(out, n, &pe), NET_OK);
    CHECK(memcmp(pe.destination.b, d.mac, 6) == 0);
    EQ(net_ipv4_parse(pe.payload, pe.payload_len, &pih, &pl, &pll), NET_OK);
    CHECK(memcmp(pih.destination.b, ip_me.b, 4) == 0);
    EQ(net_udp_parse(pl, pll, pih.source, pih.destination, &puh, &data, &dl), NET_OK);
    EQ(puh.destination_port, 40000); EQ(puh.source_port, 7);
    CHECK(dl == strlen(rep) && memcmp(data, rep, dl) == 0);
    EQ(vnet_tx_reclaim(&d, NULL), VNET_OK);
    EQ(s.faults, 0);
    int ok = failures == 0;
    printf("VNET_M6A_UDP_ROUNDTRIP_SIM: %s\n", ok ? "PASS" : "FAIL");
}

int main(void)
{
    test_qemu_caps();
    int caps_ok = failures == 0;
    printf("VIRTIO_PCI_QEMU822_CAPS: %s (real QEMU 8.2.2 virtio-net-pci config dumps, 0x1000 + 0x1041)\n",
           caps_ok ? "PASS" : "FAIL");
    test_init();
    int ap_before = failures;
    test_access_platform();
    printf("VNET_ACCESS_PLATFORM_SIM: %s (bit 33 accepted when offered; required + not offered refused before FEATURES_OK)\n",
           failures == ap_before ? "PASS" : "FAIL");
    test_datapath();
    test_hostile();
    test_m6a_udp();
    printf("vnet_test: %d checks, %d failures\n", checks, failures);
    printf("VNET_SIM_DATAPATH: %s (simulated device only; no real device, DMA, IRQ or QEMU round trip)\n",
           failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
