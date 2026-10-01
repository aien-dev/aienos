/* Host tests for the M6-A protocol layer: the Rust reference's own vectors,
 * malformed-packet negatives, build/parse round trips, and a seeded
 * randomized hostile-input sweep. Usage: net_test [seed] [iterations] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aienos_net.h"
#include "../aienos_virtio_pci.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define EQ(a, b) CHECK((long long)(a) == (long long)(b))

static uint64_t rng;
static uint64_t next(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

static void fix_ip_csum(uint8_t *h, size_t hl)
{
    h[10] = h[11] = 0;
    uint16_t c = net_checksum(h, hl);
    h[10] = (uint8_t)(c >> 8); h[11] = (uint8_t)c;
}

/* ---------------- vectors ported from net.rs #[cfg(test)] ---------------- */
static void test_rust_vectors(void)
{
    const uint8_t v[] = {0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7};
    EQ(net_checksum(v, sizeof v), 0x220d);
    const uint8_t one[] = {1};
    EQ(net_checksum(one, 1), 0xfeff);

    const uint8_t req[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x54, 0, 0x12, 0x34, 0x56,
                           0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56,
                           192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1};
    net_eth_frame f;
    EQ(net_eth_parse(req, sizeof req, &f), NET_OK);
    EQ(f.ethertype, NET_ETHERTYPE_ARP);
    net_arp_packet a;
    EQ(net_arp_parse(f.payload, f.payload_len, &a), NET_OK);
    EQ(a.operation, NET_ARP_REQUEST);
    uint8_t out[64]; size_t w = 0;
    EQ(net_arp_build(&a, out, 28, &w), NET_OK);
    EQ(w, 28);
    CHECK(memcmp(out, req + 14, 28) == 0);
    EQ(net_eth_build(&f, out, sizeof out, &w), NET_OK);
    EQ(w, sizeof req);
    CHECK(memcmp(out, req, sizeof req) == 0);

    const uint8_t p[] = {0x45, 0, 0, 0x1c, 0, 1, 0, 0, 64, 1, 0x8e, 0xa9, 192, 0, 2, 1,
                         198, 51, 100, 2, 8, 0, 0xe5, 0xca, 0x12, 0x34, 0, 1};
    net_ipv4_header h; const uint8_t *body; size_t blen;
    EQ(net_ipv4_parse(p, sizeof p, &h, &body, &blen), NET_OK);
    EQ(h.protocol, 1);
    net_icmp_echo e;
    EQ(net_icmp_echo_parse(body, blen, &e), NET_OK);
    EQ(e.identifier, 0x1234);
    EQ(e.reply, 0);
    EQ(net_ipv4_build(&h, body, blen, out, 28, &w), NET_OK);
    EQ(w, 28);
    CHECK(memcmp(out, p, 28) == 0);
    uint8_t ic[8];
    EQ(net_icmp_echo_build(&e, NULL, 0, ic, sizeof ic, &w), NET_OK);
    CHECK(memcmp(ic, p + 20, 8) == 0);

    net_ipv4 src = {{192, 0, 2, 1}}, dst = {{198, 51, 100, 2}};
    net_udp_header u = {1234, 53};
    uint8_t ub[11];
    EQ(net_udp_build(&u, (const uint8_t *)"abc", 3, src, dst, ub, sizeof ub, &w), NET_OK);
    EQ(ub[6], 0x4a); EQ(ub[7], 0x37);
    net_udp_header u2; const uint8_t *up; size_t ul;
    EQ(net_udp_parse(ub, sizeof ub, src, dst, &u2, &up, &ul), NET_OK);
    EQ(ul, 3); CHECK(memcmp(up, "abc", 3) == 0);
    EQ(u2.source_port, 1234); EQ(u2.destination_port, 53);

    EQ(net_eth_parse(NULL, 0, &f), NET_ERR_TRUNCATED);
    uint8_t z[27] = {0};
    EQ(net_arp_parse(z, 27, &a), NET_ERR_TRUNCATED);
    uint8_t z20[20] = {0};
    EQ(net_ipv4_parse(z20, 20, &h, &body, &blen), NET_ERR_INVALID);
    uint8_t fr[20] = {0x45, 0, 0, 20, 0, 0, 0x20, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    fix_ip_csum(fr, 20);
    EQ(net_ipv4_parse(fr, 20, &h, &body, &blen), NET_ERR_UNSUPPORTED);

    uint8_t rs[20] = {0x45, 0, 0, 20, 0x12, 0x34, 0x80, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2};
    fix_ip_csum(rs, 20);
    EQ(net_ipv4_parse(rs, 20, &h, &body, &blen), NET_ERR_INVALID);
    rs[6] = 0x40; /* don't-fragment alone stays valid */
    fix_ip_csum(rs, 20);
    EQ(net_ipv4_parse(rs, 20, &h, &body, &blen), NET_OK);
}

static void test_arp_cache(void)
{
    net_arp_cache c;
    EQ(net_arp_cache_init(&c, 0), NET_ERR_CAPACITY);
    EQ(net_arp_cache_init(&c, NET_ARP_CACHE_MAX + 1), NET_ERR_CAPACITY);
    EQ(net_arp_cache_init(&c, 1), NET_OK);
    net_arp_packet p = {2, {{1, 1, 1, 1, 1, 1}}, {{1, 1, 1, 1}}, {{0}}, {{2, 2, 2, 2}}};
    net_mac m;
    EQ(net_arp_cache_learn(&c, &p, 0, 0, 0, 5), NET_ERR_INVALID); /* unsolicited refused */
    EQ(net_arp_cache_learn(&c, &p, 1, 0, 0, 5), NET_OK);
    EQ(net_arp_cache_lookup(&c, p.sender_ip, 4, &m), 1);
    CHECK(memcmp(m.b, p.sender_mac.b, 6) == 0);
    EQ(net_arp_cache_lookup(&c, p.sender_ip, 5, &m), 0); /* expired at exactly ttl */
    /* full cache: a different sender is refused until expiry frees the slot */
    EQ(net_arp_cache_learn(&c, &p, 1, 0, 10, 5), NET_OK);
    net_arp_packet q = p; q.sender_ip.b[3] = 9;
    EQ(net_arp_cache_learn(&c, &q, 1, 0, 11, 5), NET_ERR_CAPACITY);
    EQ(net_arp_cache_learn(&c, &q, 1, 0, 15, 5), NET_OK);      /* expired slot is reclaimed by learn */
    EQ(net_arp_cache_lookup(&c, q.sender_ip, 16, &m), 1);
    EQ(net_arp_cache_lookup(&c, p.sender_ip, 16, &m), 0);
    EQ(net_arp_cache_learn(&c, &p, 1, 0, 20, 5), NET_OK);      /* q expired at 20 */
    /* same IP re-learn replaces in place (spoofed reply would overwrite: caller must gate) */
    p.sender_mac.b[0] = 7;
    EQ(net_arp_cache_learn(&c, &p, 1, 0, 12, 5), NET_OK);
    EQ(net_arp_cache_lookup(&c, p.sender_ip, 13, &m), 1);
    EQ(m.b[0], 7);
    /* ttl saturates instead of wrapping */
    EQ(net_arp_cache_learn(&c, &p, 0, 1, UINT64_MAX - 1, 100), NET_OK);
    EQ(net_arp_cache_lookup(&c, p.sender_ip, UINT64_MAX - 1, &m), 1);
}

/* ---------------- malformed-packet negatives ---------------- */
static void test_malformed(void)
{
    net_eth_frame f; net_arp_packet a; net_ipv4_header h; const uint8_t *pl; size_t pll;
    net_icmp_echo e; net_udp_header u;
    uint8_t b[128];
    for (size_t n = 0; n < 14; n++) EQ(net_eth_parse(b, n, &f), NET_ERR_TRUNCATED);
    /* ARP: every truncation, bad htype/ptype/hlen/plen, bad op */
    uint8_t arp[28] = {0, 1, 8, 0, 6, 4, 0, 2};
    for (size_t n = 0; n < 28; n++) EQ(net_arp_parse(arp, n, &a), NET_ERR_TRUNCATED);
    EQ(net_arp_parse(arp, 28, &a), NET_OK);
    for (int i = 0; i < 6; i++) {
        uint8_t x[28]; memcpy(x, arp, 28); x[i] ^= 0x10;
        EQ(net_arp_parse(x, 28, &a), NET_ERR_INVALID);
    }
    uint8_t ops[] = {0, 3, 0xff};
    for (size_t i = 0; i < sizeof ops; i++) {
        uint8_t x[28]; memcpy(x, arp, 28); x[7] = ops[i];
        EQ(net_arp_parse(x, 28, &a), NET_ERR_UNSUPPORTED);
    }
    /* IPv4 */
    uint8_t ip[40] = {0x45, 0, 0, 28, 0, 7, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2};
    fix_ip_csum(ip, 20);
    EQ(net_ipv4_parse(ip, 28, &h, &pl, &pll), NET_OK);
    EQ(pll, 8);
    for (size_t n = 0; n < 20; n++) EQ(net_ipv4_parse(ip, n, &h, &pl, &pll), NET_ERR_TRUNCATED);
    EQ(net_ipv4_parse(ip, 27, &h, &pl, &pll), NET_ERR_TRUNCATED);  /* total > buffer */
    memcpy(b, ip, 40); b[3] = 19; fix_ip_csum(b, 20);               /* total < ihl */
    EQ(net_ipv4_parse(b, 40, &h, &pl, &pll), NET_ERR_TRUNCATED);
    memcpy(b, ip, 40); b[0] = 0x65; fix_ip_csum(b, 20);              /* version 6 */
    EQ(net_ipv4_parse(b, 40, &h, &pl, &pll), NET_ERR_INVALID);
    for (uint8_t ihl = 0; ihl < 5; ihl++) {                          /* ihl < 5 */
        memcpy(b, ip, 40); b[0] = (uint8_t)(0x40 | ihl);
        EQ(net_ipv4_parse(b, 40, &h, &pl, &pll), NET_ERR_INVALID);
    }
    memcpy(b, ip, 40); b[0] = 0x4f;                                  /* ihl 60 > buffer */
    EQ(net_ipv4_parse(b, 40, &h, &pl, &pll), NET_ERR_INVALID);
    memcpy(b, ip, 40); b[8] = 0; fix_ip_csum(b, 20);                 /* ttl 0 */
    EQ(net_ipv4_parse(b, 40, &h, &pl, &pll), NET_ERR_INVALID);
    memcpy(b, ip, 40); b[11] ^= 1;                                   /* bad checksum */
    EQ(net_ipv4_parse(b, 40, &h, &pl, &pll), NET_ERR_INVALID);
    memcpy(b, ip, 40); b[7] = 1; fix_ip_csum(b, 20);                 /* fragment offset */
    EQ(net_ipv4_parse(b, 40, &h, &pl, &pll), NET_ERR_UNSUPPORTED);
    /* options (ihl 6) are accepted and skipped; payload stops at total length */
    uint8_t o[32] = {0x46, 0, 0, 30, 0, 0, 0x40, 0, 1, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 1, 0};
    fix_ip_csum(o, 24);
    EQ(net_ipv4_parse(o, 32, &h, &pl, &pll), NET_OK);
    CHECK(pl == o + 24 && pll == 6);
    /* oversize builds */
    static uint8_t big[70000];
    size_t w;
    net_ipv4_header hh = {0, 0, 64, 17, {{0}}, {{0}}};
    EQ(net_ipv4_build(&hh, big, 65535 - 19, big, sizeof big, &w), NET_ERR_TRUNCATED);
    EQ(net_ipv4_build(&hh, NULL, 0, b, 19, &w), NET_ERR_TRUNCATED);
    net_udp_header uh = {1, 2};
    net_ipv4 s = {{1, 2, 3, 4}}, d = {{5, 6, 7, 8}};
    EQ(net_udp_build(&uh, big, 65535 - 7, s, d, big, sizeof big, &w), NET_ERR_TRUNCATED);
    EQ(net_udp_build(&uh, big + 100, 65535 - 8, s, d, big, sizeof big, &w), NET_OK);
    EQ(w, 65535);
    /* ICMP */
    uint8_t ic[16];
    net_icmp_echo ee = {1, 9, 9, 0};
    EQ(net_icmp_echo_build(&ee, (const uint8_t *)"12345678", 8, ic, sizeof ic, &w), NET_OK);
    EQ(net_icmp_echo_parse(ic, 16, &e), NET_OK);
    for (size_t n = 0; n < 8; n++) EQ(net_icmp_echo_parse(ic, n, &e), NET_ERR_TRUNCATED);
    EQ(net_icmp_echo_parse(ic, 15, &e), NET_ERR_INVALID); /* length lie breaks checksum */
    memcpy(b, ic, 16); b[1] = 1;
    EQ(net_icmp_echo_parse(b, 16, &e), NET_ERR_UNSUPPORTED);
    memcpy(b, ic, 16); b[0] = 3;
    EQ(net_icmp_echo_parse(b, 16, &e), NET_ERR_UNSUPPORTED);
    memcpy(b, ic, 16); b[12] ^= 0x80;
    EQ(net_icmp_echo_parse(b, 16, &e), NET_ERR_INVALID);
    /* UDP */
    uint8_t ud[16];
    EQ(net_udp_build(&uh, (const uint8_t *)"hostile", 7, s, d, ud, sizeof ud, &w), NET_OK);
    EQ(w, 15);
    for (size_t n = 0; n < 8; n++) EQ(net_udp_parse(ud, n, s, d, &u, &pl, &pll), NET_ERR_TRUNCATED);
    EQ(net_udp_parse(ud, 14, s, d, &u, &pl, &pll), NET_ERR_INVALID); /* length field > buffer */
    memcpy(b, ud, 15); b[5] = 7;                                       /* length < 8 */
    EQ(net_udp_parse(b, 15, s, d, &u, &pl, &pll), NET_ERR_INVALID);
    memcpy(b, ud, 15); b[14] ^= 1;                                     /* payload corrupted */
    EQ(net_udp_parse(b, 15, s, d, &u, &pl, &pll), NET_ERR_INVALID);
    net_ipv4 s2 = {{1, 2, 3, 5}};                                      /* wrong pseudo-header */
    EQ(net_udp_parse(ud, 15, s2, d, &u, &pl, &pll), NET_ERR_INVALID);
    memcpy(b, ud, 15); b[6] = b[7] = 0;                                /* checksum 0 = absent */
    EQ(net_udp_parse(b, 15, s2, d, &u, &pl, &pll), NET_OK);
    memcpy(b, ud, 15); memcpy(b + 15, "XYZ", 3);                      /* trailing bytes ignored */
    EQ(net_udp_parse(b, 18, s, d, &u, &pl, &pll), NET_OK);
    EQ(pll, 7);
    /* null/argument misuse never dereferences */
    EQ(net_eth_parse(NULL, 5, &f), NET_ERR_INVALID);
    EQ(net_ipv4_parse(ip, 28, NULL, &pl, &pll), NET_ERR_INVALID);
    EQ(net_eth_build(NULL, b, 10, &w), NET_ERR_INVALID);
    EQ(net_checksum(NULL, 99), 0xffff);
}

/* ---------------- virtio PCI capability walk ---------------- */
static void put32(uint8_t *c, size_t o, uint32_t v) { c[o] = (uint8_t)v; c[o + 1] = (uint8_t)(v >> 8); c[o + 2] = (uint8_t)(v >> 16); c[o + 3] = (uint8_t)(v >> 24); }
static void put_cap(uint8_t *c, size_t at, uint8_t nx, uint8_t kind, uint8_t bar, uint32_t off, uint32_t len)
{
    size_t cl = kind == 2 ? 20 : 16;
    memset(c + at, 0, cl);
    c[at] = 9; c[at + 1] = nx; c[at + 2] = (uint8_t)cl; c[at + 3] = kind; c[at + 4] = bar;
    put32(c, at + 8, off); put32(c, at + 12, len);
    if (kind == 2) put32(c, at + 16, 4);
}
static void test_virtio(void)
{
    uint8_t c[256] = {0};
    virtio_pci_caps r;
    c[6] = 1 << 4; c[0x34] = 0x40;
    put_cap(c, 0x40, 0x50, 1, 0, 0x1000, 0x100);
    put_cap(c, 0x50, 0x64, 2, 2, 0x2000, 0x100);
    put_cap(c, 0x64, 0x74, 3, 0, 0x3000, 1);
    put_cap(c, 0x74, 0, 4, 0, 0x4000, 0x80);
    EQ(virtio_pci_parse_caps(c, 256, &r), VIRTIO_PCI_OK);
    CHECK(r.common_cfg.present && r.common_cfg.bar == 0 && r.common_cfg.offset == 0x1000 && r.common_cfg.length == 0x100);
    CHECK(r.notify_cfg.present && r.notify_cfg.bar == 2 && r.notify_cfg.offset == 0x2000);
    CHECK(r.has_notify_off_multiplier && r.notify_off_multiplier == 4);
    CHECK(r.isr_cfg.present && r.isr_cfg.length == 1);
    CHECK(r.device_cfg.present && r.device_cfg.offset == 0x4000 && r.device_cfg.length == 0x80);
    uint8_t big[4096] = {0};
    memcpy(big, c, 256);
    EQ(virtio_pci_parse_caps(big, 4096, &r), VIRTIO_PCI_OK);
    EQ(virtio_pci_parse_caps(c, 255, &r), VIRTIO_PCI_INVALID_CONFIG_LENGTH);
    EQ(virtio_pci_parse_caps(NULL, 256, &r), VIRTIO_PCI_INVALID_CONFIG_LENGTH);

    uint8_t x[256];
    memcpy(x, c, 256); x[6] = 0;
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_CAPABILITIES_NOT_PRESENT);
    memcpy(x, c, 256); x[0x34] = 0x3c;               /* pointer into header */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_POINTER);
    memcpy(x, c, 256); x[0x41] = 0x40;               /* self loop */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_CAPABILITY_LOOP);
    memcpy(x, c, 256); x[0x75] = 0x50;               /* long loop back to 0x50 */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_CAPABILITY_LOOP);
    memcpy(x, c, 256); x[0x41] = 0; x[0x42] = 8;     /* short cap (Rust vector) */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_SHORT_CAPABILITY);
    memcpy(x, c, 256); x[0x52] = 16;                 /* notify cap shorter than 20 */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_SHORT_CAPABILITY);
    memset(x, 0, 256); x[6] = 16; x[0x34] = 0xf8; x[0xf8] = 9; /* cap runs off the end */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_SHORT_CAPABILITY);
    memset(x, 0, 256); x[6] = 16; x[0x34] = 0xfc; x[0xfc] = 1;  /* non-vendor cap at end is fine */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_OK);
    memcpy(x, c, 256); x[0x44] = 6;                  /* bar > 5 */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, c, 256); put32(x, 0x4c, 0);            /* zero length */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, c, 256); put32(x, 0x48, 0xffffff00);   /* offset + length overflows */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_INVALID_REGION);
    memcpy(x, c, 256); x[0x77] = 1;                  /* second common cfg */
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_DUPLICATE_CAPABILITY);
    /* the longest loop-free chain: all 48 aligned slots 0x40..0xfc. The 48-step
       bound in the reference is therefore unreachable without a revisit. */
    memset(x, 0, 256); x[6] = 16; x[0x34] = 0x40;
    for (int i = 0; i < 48; i++) { size_t at = 0x40 + 4 * (size_t)i; x[at] = 1; x[at + 1] = (uint8_t)(i == 47 ? 0 : at + 4); }
    EQ(virtio_pci_parse_caps(x, 256, &r), VIRTIO_PCI_OK);
}

/* ---------------- round trips ---------------- */
static void test_roundtrips(unsigned iters)
{
    static uint8_t data[2000], pkt[2100], frame[2200];
    for (unsigned it = 0; it < iters; it++) {
        size_t dl = next() % 1400;
        for (size_t i = 0; i < dl; i++) data[i] = (uint8_t)next();
        net_ipv4 s = {{(uint8_t)next(), (uint8_t)next(), (uint8_t)next(), (uint8_t)next()}};
        net_ipv4 d = {{(uint8_t)next(), (uint8_t)next(), (uint8_t)next(), (uint8_t)next()}};
        net_udp_header u = {(uint16_t)next(), (uint16_t)next()};
        size_t ul, il, fl;
        EQ(net_udp_build(&u, data, dl, s, d, pkt + 20, sizeof pkt - 20, &ul), NET_OK);
        net_ipv4_header h = {(uint8_t)next(), (uint16_t)next(), (uint8_t)(1 + next() % 255), NET_IPPROTO_UDP, s, d};
        EQ(net_ipv4_build(&h, pkt + 20, ul, pkt, sizeof pkt, &il), NET_OK);
        net_eth_frame f = {{{1, 2, 3, 4, 5, 6}}, {{6, 5, 4, 3, 2, 1}}, NET_ETHERTYPE_IPV4, pkt, il};
        EQ(net_eth_build(&f, frame, sizeof frame, &fl), NET_OK);
        net_eth_frame f2; net_ipv4_header h2; net_udp_header u2;
        const uint8_t *ip, *up; size_t ipl, upl;
        EQ(net_eth_parse(frame, fl, &f2), NET_OK);
        EQ(net_ipv4_parse(f2.payload, f2.payload_len, &h2, &ip, &ipl), NET_OK);
        CHECK(memcmp(&h, &h2, sizeof h) == 0);
        EQ(net_udp_parse(ip, ipl, h2.source, h2.destination, &u2, &up, &upl), NET_OK);
        CHECK(upl == dl && (dl == 0 || memcmp(up, data, dl) == 0));
        CHECK(u2.source_port == u.source_port && u2.destination_port == u.destination_port);
        /* every single-bit flip in the IP header or UDP datagram is caught or changes nothing visible */
        size_t bit = next() % ((fl - 14) * 8);
        frame[14 + bit / 8] ^= (uint8_t)(1u << (bit % 8));
        net_err e = net_ipv4_parse(frame + 14, fl - 14, &h2, &ip, &ipl);
        if (e == NET_OK) e = net_udp_parse(ip, ipl, h2.source, h2.destination, &u2, &up, &upl);
        CHECK(e != NET_OK || (ip[6] == 0 && ip[7] == 0)); /* only a flip to "no checksum" passes */
    }
}

/* ---------------- randomized hostile inputs: no crash, views stay in bounds ---------------- */
static void test_hostile(unsigned iters)
{
    static uint8_t b[4096];
    for (unsigned it = 0; it < iters; it++) {
        size_t n = next() % 1600;
        for (size_t i = 0; i < n; i++) b[i] = (uint8_t)next();
        if (n > 20 && (it & 1)) { /* make it look like IPv4 more often */
            b[0] = (uint8_t)(0x45 + (next() % 3 == 0 ? next() % 11 : 0));
            if (next() & 1) { b[2] = (uint8_t)(n >> 8); b[3] = (uint8_t)n; }
            b[6] &= 0x40; if (!b[8]) b[8] = 1;
            if (next() & 1) fix_ip_csum(b, (size_t)(b[0] & 15) * 4 <= n ? (size_t)(b[0] & 15) * 4 : 20);
        }
        net_eth_frame f; net_arp_packet a; net_ipv4_header h; net_icmp_echo e; net_udp_header u;
        memset(&h, 0, sizeof h);
        const uint8_t *p; size_t pl;
        if (net_eth_parse(b, n, &f) == NET_OK) CHECK(f.payload == b + 14 && f.payload_len == n - 14);
        (void)net_arp_parse(b, n, &a);
        if (net_ipv4_parse(b, n, &h, &p, &pl) == NET_OK) {
            CHECK(p >= b + 20 && p + pl <= b + n);
            net_ipv4 s = h.source, d = h.destination;
            if (net_udp_parse(p, pl, s, d, &u, &p, &pl) == NET_OK) CHECK(p + pl <= b + n);
        }
        if (net_icmp_echo_parse(b, n, &e) == NET_OK) CHECK(e.data_len == n - 8);
        if (net_udp_parse(b, n, h.source, h.destination, &u, &p, &pl) == NET_OK) CHECK(p == b + 8 && p + pl <= b + n);
        virtio_pci_caps r;
        b[6] |= 16;
        (void)virtio_pci_parse_caps(b, 256, &r);
    }
}

int main(int argc, char **argv)
{
    unsigned long long seed = argc > 1 ? strtoull(argv[1], NULL, 0) : 0x6a5e11ULL;
    unsigned iters = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 0) : 200000;
    rng = seed ? seed : 1;
    test_rust_vectors();
    test_arp_cache();
    test_malformed();
    test_virtio();
    test_roundtrips(iters / 10);
    test_hostile(iters);
    printf("net_test seed=0x%llx iters=%u checks=%d failures=%d\n", seed, iters, checks, failures);
    printf("NET_PROTOCOL_HOST: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
