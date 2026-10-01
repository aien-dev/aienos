/* net_udp.c -- UDP round-trip frames (see net_udp.h). Freestanding. */
#include "net_udp.h"
#include <string.h>

static const net_mac k_bcast = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

static int mac_eq(const net_mac *a, const net_mac *b) { return memcmp(a->b, b->b, 6) == 0; }
static int ip_eq(net_ipv4 a, net_ipv4 b) { return memcmp(a.b, b.b, 4) == 0; }
static int mac_unicast(const net_mac *m)
{
    static const net_mac zero = {{0, 0, 0, 0, 0, 0}};
    return !(m->b[0] & 1u) && !mac_eq(m, &zero);
}

static size_t eth_wrap(const net_mac *dst, const net_mac *src, uint16_t type, const uint8_t *pl, size_t n,
                       uint8_t *out, size_t cap)
{
    net_eth_frame f;
    f.destination = *dst;
    f.source = *src;
    f.ethertype = type;
    f.payload = pl;
    f.payload_len = n;
    size_t w = 0;
    return net_eth_build(&f, out, cap, &w) == NET_OK ? w : 0;
}

static size_t arp_frame(const ck_net_peer *p, uint16_t op, const net_mac *tmac, net_ipv4 tip,
                        const net_mac *eth_dst, uint8_t *out, size_t cap)
{
    net_arp_packet a;
    uint8_t body[64];
    size_t w = 0;
    a.operation = op;
    a.sender_mac = p->mac;
    a.sender_ip = p->ip;
    a.target_mac = *tmac;
    a.target_ip = tip;
    if (net_arp_build(&a, body, sizeof body, &w) != NET_OK) return 0;
    return eth_wrap(eth_dst, &p->mac, NET_ETHERTYPE_ARP, body, w, out, cap);
}

size_t ck_net_arp_request(const ck_net_peer *p, uint8_t *out, size_t cap)
{
    static const net_mac zero = {{0, 0, 0, 0, 0, 0}};
    if (!p || !out) return 0;
    return arp_frame(p, NET_ARP_REQUEST, &zero, p->gw_ip, &k_bcast, out, cap);
}

size_t ck_net_arp_reply(const ck_net_peer *p, const net_arp_packet *req, uint8_t *out, size_t cap)
{
    if (!p || !req || !out || !mac_unicast(&req->sender_mac)) return 0;
    return arp_frame(p, NET_ARP_REPLY, &req->sender_mac, req->sender_ip, &req->sender_mac, out, cap);
}

size_t ck_net_udp_frame(const ck_net_peer *p, uint16_t ip_id, const uint8_t *data, size_t n, uint8_t *out,
                        size_t cap)
{
    static uint8_t udp[1500], ip[1500];
    if (!p || !out || (n && !data) || !mac_unicast(&p->gw_mac)) return 0;
    net_udp_header uh = {p->lport, p->rport};
    size_t uw = 0, iw = 0;
    if (net_udp_build(&uh, data, n, p->ip, p->gw_ip, udp, sizeof udp, &uw) != NET_OK) return 0;
    net_ipv4_header ih;
    ih.dscp_ecn = 0;
    ih.identification = ip_id;
    ih.ttl = 64;
    ih.protocol = NET_IPPROTO_UDP;
    ih.source = p->ip;
    ih.destination = p->gw_ip;
    if (net_ipv4_build(&ih, udp, uw, ip, sizeof ip, &iw) != NET_OK) return 0;
    return eth_wrap(&p->gw_mac, &p->mac, NET_ETHERTYPE_IPV4, ip, iw, out, cap);
}

ck_net_kind ck_net_classify(const ck_net_peer *p, const uint8_t *frame, size_t len, net_mac *mac,
                            net_arp_packet *arp, const uint8_t **payload, size_t *payload_len, int *csum)
{
    net_eth_frame e;
    if (!p || !frame || net_eth_parse(frame, len, &e) != NET_OK) return CK_NET_IGNORED;
    if (!mac_eq(&e.destination, &p->mac) && !mac_eq(&e.destination, &k_bcast)) return CK_NET_IGNORED;
    if (e.ethertype == NET_ETHERTYPE_ARP) {
        net_arp_packet a;
        if (net_arp_parse(e.payload, e.payload_len, &a) != NET_OK) return CK_NET_IGNORED;
        if (!ip_eq(a.target_ip, p->ip) || !mac_unicast(&a.sender_mac)) return CK_NET_IGNORED;
        if (a.operation == NET_ARP_REPLY && ip_eq(a.sender_ip, p->gw_ip) && mac_eq(&a.target_mac, &p->mac) &&
            mac_eq(&e.destination, &p->mac)) {
            if (mac) *mac = a.sender_mac;
            return CK_NET_ARP_GW;
        }
        if (a.operation == NET_ARP_REQUEST) {
            if (arp) *arp = a;
            return CK_NET_ARP_ASK;
        }
        return CK_NET_IGNORED;
    }
    if (e.ethertype != NET_ETHERTYPE_IPV4 || !mac_eq(&e.destination, &p->mac)) return CK_NET_IGNORED;
    net_ipv4_header ih;
    const uint8_t *ipl = 0;
    size_t ipn = 0;
    if (net_ipv4_parse(e.payload, e.payload_len, &ih, &ipl, &ipn) != NET_OK) return CK_NET_IGNORED;
    if (ih.protocol != NET_IPPROTO_UDP || !ip_eq(ih.source, p->gw_ip) || !ip_eq(ih.destination, p->ip))
        return CK_NET_IGNORED;
    net_udp_header uh;
    const uint8_t *pl = 0;
    size_t pn = 0;
    if (net_udp_parse(ipl, ipn, ih.source, ih.destination, &uh, &pl, &pn) != NET_OK) return CK_NET_IGNORED;
    if (uh.source_port != p->rport || uh.destination_port != p->lport) return CK_NET_IGNORED;
    if (payload) *payload = pl;
    if (payload_len) *payload_len = pn;
    if (csum) *csum = (ipl[6] | ipl[7]) != 0;
    return CK_NET_UDP_REPLY;
}

void ck_net_printable(const uint8_t *b, size_t n, char *out, size_t cap)
{
    if (!out || !cap) return;
    size_t i = 0;
    for (; b && i < n && i + 1 < cap; i++) {
        uint8_t c = b[i];
        out[i] = (c == '"' || c == '\\') ? '\'' : (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    out[i] = 0;
}
