/* Differential corpus tool for the M6-A protocol layer.
 *
 *   net_diff gen SEED COUNT > corpus.bin   structure-aware hostile corpus
 *   net_diff run < corpus.bin              one canonical result line per record
 *
 * The same corpus is fed to the unmodified Rust reference (net.rs and
 * virtio_net.rs) by a driver kept OUTSIDE this repository (no Rust in AIENOS
 * code). Both outputs must be byte-identical; the agreed output digest is
 * pinned in the Makefile (`make diff-check`) so C regressions are caught
 * without Rust. Record: kind u8, length u16 big-endian, bytes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aienos_net.h"
#include "../aienos_virtio_pci.h"

enum { K_ETH = 1, K_ARP, K_IPV4, K_ICMP, K_UDP, K_CSUM, K_VIRTIO, K_UDP_BUILD, K_IPV4_BUILD, K_ICMP_BUILD, K_MAX };

static uint64_t rng;
static uint32_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (uint32_t)(rng >> 11); }

static void emit(int kind, const uint8_t *b, size_t n)
{
    uint8_t h[3] = {(uint8_t)kind, (uint8_t)(n >> 8), (uint8_t)n};
    fwrite(h, 1, 3, stdout);
    fwrite(b, 1, n, stdout);
}

static void fix_csum(uint8_t *b, size_t at, size_t from, size_t to)
{
    b[at] = b[at + 1] = 0;
    uint16_t c = net_checksum(b + from, to - from);
    b[at] = (uint8_t)(c >> 8); b[at + 1] = (uint8_t)c;
}

/* Mutate: flips, boundary length fields, truncation, extension. */
static size_t mutate(uint8_t *b, size_t n, size_t cap)
{
    unsigned m = rnd() % 8;
    for (unsigned i = 0; i < m && n; i++) {
        switch (rnd() % 6) {
        case 0: b[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); break;
        case 1: b[rnd() % n] = (uint8_t)rnd(); break;
        case 2: n = rnd() % (n + 1); break;
        case 3: { size_t add = rnd() % 16; while (add-- && n < cap) b[n++] = (uint8_t)rnd(); } break;
        case 4: { static const uint8_t v[] = {0, 1, 7, 8, 19, 20, 0x45, 0x7f, 0x80, 0xff}; b[rnd() % n] = v[rnd() % sizeof v]; } break;
        default: break;
        }
    }
    return n;
}

static void gen_one(void)
{
    uint8_t b[4096];
    size_t n = 0;
    int kind = 1 + (int)(rnd() % (K_MAX - 1));
    for (size_t i = 0; i < sizeof b; i++) b[i] = (uint8_t)rnd();
    int structured = rnd() % 4 != 0;
    switch (kind) {
    case K_ETH: n = rnd() % 40; break;
    case K_ARP:
        n = 28 + rnd() % 4;
        if (structured) { const uint8_t h[8] = {0, 1, 8, 0, 6, 4, 0, (uint8_t)(1 + rnd() % 2)}; memcpy(b, h, 8); }
        break;
    case K_IPV4: case K_ICMP: case K_UDP: {
        /* IPv4 header (+opts) | payload, built valid, then maybe mutated */
        size_t ihl = 5 + (rnd() % 4 == 0 ? rnd() % 3 : 0);
        size_t pl = rnd() % 64;
        n = ihl * 4 + pl;
        b[0] = (uint8_t)(0x40 | ihl); b[2] = (uint8_t)(n >> 8); b[3] = (uint8_t)n;
        b[6] &= 0x40; b[7] = 0; if (!b[8]) b[8] = 1;
        if (kind == K_IPV4) { fix_csum(b, 10, 0, ihl * 4); break; }
        if (kind == K_ICMP) {
            /* the ICMP record is the IPv4 payload only */
            memmove(b, b + ihl * 4, pl); n = pl < 8 ? 8 : pl;
            b[0] = rnd() % 2 ? 0 : 8; b[1] = 0; fix_csum(b, 2, 0, n);
            break;
        }
        /* UDP record: src(4) dst(4) datagram */
        n = 8 + 8 + pl;
        b[12] = (uint8_t)((8 + pl) >> 8); b[13] = (uint8_t)(8 + pl);
        if (rnd() % 5 == 0) { b[14] = b[15] = 0; }
        else {
            uint8_t tmp[4096]; net_udp_header u = {(uint16_t)(b[8] << 8 | b[9]), (uint16_t)(b[10] << 8 | b[11])};
            net_ipv4 s, d; memcpy(s.b, b, 4); memcpy(d.b, b + 4, 4); size_t w;
            if (net_udp_build(&u, b + 16, pl, s, d, tmp, sizeof tmp, &w) == NET_OK) memcpy(b + 8, tmp, w);
        }
        break;
    }
    case K_CSUM: n = rnd() % 300; break;
    case K_VIRTIO: {
        n = rnd() % 16 == 0 ? (rnd() % 2 ? 4096 : 255) : 256;
        memset(b, 0, 256);
        b[6] = 16; b[0x34] = (uint8_t)(0x40 + 4 * (rnd() % 4));
        size_t at = b[0x34];
        unsigned caps = rnd() % 7;
        for (unsigned i = 0; i < caps && at + 20 <= 256; i++) {
            uint8_t kd = (uint8_t)(rnd() % 6), cl = kd == 2 ? 20 : 16;
            size_t nx = at + cl + 4 * (rnd() % 3);
            b[at] = rnd() % 5 ? 9 : 1; b[at + 1] = (uint8_t)(i + 1 == caps || nx + 20 > 256 ? 0 : nx);
            b[at + 2] = cl; b[at + 3] = kd; b[at + 4] = (uint8_t)(rnd() % 7);
            uint32_t off = rnd() % 3 ? rnd() % 0x10000 : rnd() * 3u, len = rnd() % 4 ? rnd() % 0x400 : rnd() * 5u;
            for (int k = 0; k < 4; k++) { b[at + 8 + k] = (uint8_t)(off >> (8 * k)); b[at + 12 + k] = (uint8_t)(len >> (8 * k)); }
            if (rnd() % 8 == 0) b[at + 1] = b[0x34]; /* loop */
            at = nx;
        }
        if (structured) n = n == 256 ? 256 : n; /* mutations below may still break it */
        if (rnd() % 2) { size_t m = n; mutate(b, 256, 256); n = m; }
        emit(kind, b, n);
        return;
    }
    case K_UDP_BUILD: n = 12 + rnd() % 40; break;
    case K_IPV4_BUILD: n = 13 + rnd() % 40; break;
    case K_ICMP_BUILD: n = 5 + rnd() % 40; break;
    }
    if (rnd() % 2 || !structured) n = mutate(b, n, sizeof b);
    emit(kind, b, n);
}

static void mac(const net_mac *m) { printf(" %02x%02x%02x%02x%02x%02x", m->b[0], m->b[1], m->b[2], m->b[3], m->b[4], m->b[5]); }
static void ip(const net_ipv4 *a) { printf(" %u.%u.%u.%u", a->b[0], a->b[1], a->b[2], a->b[3]); }
static void hexs(const uint8_t *b, size_t n) { putchar(' '); for (size_t i = 0; i < n; i++) printf("%02x", b[i]); }
static void region(const virtio_pci_region *r) { if (r->present) printf(" %u:%x:%x", r->bar, r->offset, r->length); else printf(" -"); }

static void run_one(int kind, const uint8_t *b, size_t n)
{
    net_err e = NET_OK;
    switch (kind) {
    case K_ETH: { net_eth_frame f; printf("E"); if ((e = net_eth_parse(b, n, &f)) == NET_OK) { printf(" Ok"); mac(&f.destination); mac(&f.source); printf(" %04x %zu", f.ethertype, f.payload_len); } break; }
    case K_ARP: { net_arp_packet a; printf("A"); if ((e = net_arp_parse(b, n, &a)) == NET_OK) { printf(" Ok %u", a.operation); mac(&a.sender_mac); ip(&a.sender_ip); mac(&a.target_mac); ip(&a.target_ip); } break; }
    case K_IPV4: { net_ipv4_header h; const uint8_t *p; size_t pl; printf("I"); if ((e = net_ipv4_parse(b, n, &h, &p, &pl)) == NET_OK) { printf(" Ok %u %u %u %u", h.dscp_ecn, h.identification, h.ttl, h.protocol); ip(&h.source); ip(&h.destination); printf(" %zu %zu", (size_t)(p - b), pl); } break; }
    case K_ICMP: { net_icmp_echo c; printf("C"); if ((e = net_icmp_echo_parse(b, n, &c)) == NET_OK) printf(" Ok %d %u %u %zu", c.reply, c.identifier, c.sequence, c.data_len); break; }
    case K_UDP: {
        printf("U");
        if (n < 8) { printf(" Short\n"); return; }
        net_ipv4 s, d; memcpy(s.b, b, 4); memcpy(d.b, b + 4, 4);
        net_udp_header u; const uint8_t *p; size_t pl;
        if ((e = net_udp_parse(b + 8, n - 8, s, d, &u, &p, &pl)) == NET_OK) printf(" Ok %u %u %zu %zu", u.source_port, u.destination_port, (size_t)(p - (b + 8)), pl);
        break;
    }
    case K_CSUM: printf("K %04x\n", net_checksum(b, n)); return;
    case K_VIRTIO: {
        virtio_pci_caps c; virtio_pci_err ve = virtio_pci_parse_caps(b, n, &c);
        printf("V");
        if (ve) { printf(" Err %s\n", virtio_pci_err_name(ve)); return; }
        printf(" Ok"); region(&c.common_cfg); region(&c.notify_cfg);
        if (c.has_notify_off_multiplier) printf(" %x", c.notify_off_multiplier); else printf(" -");
        region(&c.isr_cfg); region(&c.device_cfg); putchar('\n');
        return;
    }
    case K_UDP_BUILD: case K_IPV4_BUILD: case K_ICMP_BUILD: {
        uint8_t out[4096]; size_t w = 0;
        size_t hdr = kind == K_UDP_BUILD ? 12 : kind == K_IPV4_BUILD ? 13 : 5;
        printf(kind == K_UDP_BUILD ? "BU" : kind == K_IPV4_BUILD ? "BI" : "BC");
        if (n < hdr) { printf(" Short\n"); return; }
        if (kind == K_UDP_BUILD) {
            net_ipv4 s, d; memcpy(s.b, b, 4); memcpy(d.b, b + 4, 4);
            net_udp_header u = {(uint16_t)(b[8] << 8 | b[9]), (uint16_t)(b[10] << 8 | b[11])};
            e = net_udp_build(&u, b + hdr, n - hdr, s, d, out, sizeof out, &w);
        } else if (kind == K_IPV4_BUILD) {
            net_ipv4_header h = {b[0], (uint16_t)(b[1] << 8 | b[2]), b[3], b[4], {{b[5], b[6], b[7], b[8]}}, {{b[9], b[10], b[11], b[12]}}};
            e = net_ipv4_build(&h, b + hdr, n - hdr, out, sizeof out, &w);
        } else {
            net_icmp_echo c = {b[0] & 1, (uint16_t)(b[1] << 8 | b[2]), (uint16_t)(b[3] << 8 | b[4]), 0};
            e = net_icmp_echo_build(&c, b + hdr, n - hdr, out, sizeof out, &w);
        }
        if (e == NET_OK) { printf(" Ok"); hexs(out, w); }
        break;
    }
    default: printf("?\n"); return;
    }
    if (e != NET_OK) printf(" Err %s", net_err_name(e));
    putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "gen") == 0) {
        rng = strtoull(argv[2], NULL, 0); if (!rng) rng = 1;
        unsigned long count = strtoul(argv[3], NULL, 0);
        for (unsigned long i = 0; i < count; i++) gen_one();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "run") == 0) {
        static uint8_t b[65536];
        int k;
        while ((k = getchar()) != EOF) {
            int h1 = getchar(), h2 = getchar();
            if (h1 == EOF || h2 == EOF) return 2;
            size_t n = (size_t)h1 << 8 | (size_t)h2;
            if (fread(b, 1, n, stdin) != n) return 2;
            run_one(k, b, n);
        }
        return 0;
    }
    fprintf(stderr, "usage: net_diff gen SEED COUNT | net_diff run\n");
    return 2;
}
