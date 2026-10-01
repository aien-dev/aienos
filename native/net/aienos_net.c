/* AIENOS M6-A network protocol layer. See aienos_net.h. No heap, no clock, no I/O. */
#include "aienos_net.h"

#include <string.h>

static uint16_t rd16(const uint8_t *b) { return (uint16_t)((uint16_t)b[0] << 8 | b[1]); }
static void wr16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v; }

/* Sum of big-endian 16-bit words; odd final byte is the high octet. */
static uint64_t sum16(const uint8_t *d, size_t n)
{
    uint64_t s = 0;
    size_t i = 0;
    for (; i + 1 < n; i += 2) s += rd16(d + i);
    if (i < n) s += (uint64_t)d[i] << 8;
    return s;
}

static uint16_t fold(uint64_t s)
{
    while (s >> 16) s = (s & 0xffffu) + (s >> 16);
    return (uint16_t)s;
}

uint16_t net_checksum(const uint8_t *data, size_t len)
{
    if (!data) len = 0;
    return (uint16_t)~fold(len ? sum16(data, len) : 0);
}

const char *net_err_name(net_err e)
{
    switch (e) {
    case NET_OK: return "Ok";
    case NET_ERR_TRUNCATED: return "Truncated";
    case NET_ERR_INVALID: return "Invalid";
    case NET_ERR_UNSUPPORTED: return "Unsupported";
    case NET_ERR_CAPACITY: return "Capacity";
    }
    return "Unknown";
}

/* ---- Ethernet ---- */
net_err net_eth_parse(const uint8_t *b, size_t len, net_eth_frame *out)
{
    if (!out || (!b && len)) return NET_ERR_INVALID;
    if (len < 14) return NET_ERR_TRUNCATED;
    memcpy(out->destination.b, b, 6);
    memcpy(out->source.b, b + 6, 6);
    out->ethertype = rd16(b + 12);
    out->payload = b + 14;
    out->payload_len = len - 14;
    return NET_OK;
}

net_err net_eth_build(const net_eth_frame *f, uint8_t *out, size_t cap, size_t *written)
{
    if (!f || !written || (!f->payload && f->payload_len) || (!out && cap)) return NET_ERR_INVALID;
    if (f->payload_len > SIZE_MAX - 14) return NET_ERR_CAPACITY;
    size_t n = 14 + f->payload_len;
    if (cap < n) return NET_ERR_TRUNCATED;
    if (f->payload_len) memmove(out + 14, f->payload, f->payload_len);
    memcpy(out, f->destination.b, 6);
    memcpy(out + 6, f->source.b, 6);
    wr16(out + 12, f->ethertype);
    *written = n;
    return NET_OK;
}

/* ---- ARP ---- */
net_err net_arp_parse(const uint8_t *b, size_t len, net_arp_packet *out)
{
    if (!out || (!b && len)) return NET_ERR_INVALID;
    if (len < 28) return NET_ERR_TRUNCATED;
    if (rd16(b) != 1 || rd16(b + 2) != NET_ETHERTYPE_IPV4 || b[4] != 6 || b[5] != 4)
        return NET_ERR_INVALID;
    uint16_t op = rd16(b + 6);
    if (op != NET_ARP_REQUEST && op != NET_ARP_REPLY) return NET_ERR_UNSUPPORTED;
    out->operation = op;
    memcpy(out->sender_mac.b, b + 8, 6);
    memcpy(out->sender_ip.b, b + 14, 4);
    memcpy(out->target_mac.b, b + 18, 6);
    memcpy(out->target_ip.b, b + 24, 4);
    return NET_OK;
}

net_err net_arp_build(const net_arp_packet *p, uint8_t *out, size_t cap, size_t *written)
{
    if (!p || !written || (!out && cap)) return NET_ERR_INVALID;
    if (cap < 28) return NET_ERR_TRUNCATED;
    const uint8_t hdr[6] = {0, 1, 8, 0, 6, 4};
    memcpy(out, hdr, 6);
    wr16(out + 6, p->operation);
    memcpy(out + 8, p->sender_mac.b, 6);
    memcpy(out + 14, p->sender_ip.b, 4);
    memcpy(out + 18, p->target_mac.b, 6);
    memcpy(out + 24, p->target_ip.b, 4);
    *written = 28;
    return NET_OK;
}

/* ---- ARP cache ---- */
net_err net_arp_cache_init(net_arp_cache *c, size_t capacity)
{
    if (!c) return NET_ERR_INVALID;
    if (capacity == 0 || capacity > NET_ARP_CACHE_MAX) return NET_ERR_CAPACITY;
    memset(c, 0, sizeof *c);
    c->capacity = capacity;
    return NET_OK;
}

int net_arp_cache_lookup(net_arp_cache *c, net_ipv4 ip, uint64_t now, net_mac *mac)
{
    if (!c || c->capacity > NET_ARP_CACHE_MAX) return 0;
    for (size_t i = 0; i < c->capacity; i++) {
        net_arp_entry *e = &c->entries[i];
        if (e->used && e->expires <= now) memset(e, 0, sizeof *e);
        if (e->used && memcmp(e->ip.b, ip.b, 4) == 0) {
            if (mac) *mac = e->mac;
            return 1;
        }
    }
    return 0;
}

net_err net_arp_cache_learn(net_arp_cache *c, const net_arp_packet *p, int solicited,
                            int allow_unsolicited, uint64_t now, uint64_t ttl)
{
    if (!c || !p || c->capacity == 0 || c->capacity > NET_ARP_CACHE_MAX) return NET_ERR_INVALID;
    if (!solicited && !allow_unsolicited) return NET_ERR_INVALID;
    uint64_t expires = (ttl > UINT64_MAX - now) ? UINT64_MAX : now + ttl;
    size_t slot = SIZE_MAX;
    for (size_t i = 0; i < c->capacity; i++) {
        const net_arp_entry *e = &c->entries[i];
        if (e->used && memcmp(e->ip.b, p->sender_ip.b, 4) == 0) { slot = i; break; }
        /* An expired entry is free (deliberate difference: the reference only
         * reclaims it during a lookup, so learning depended on lookup order). */
        if ((!e->used || e->expires <= now) && slot == SIZE_MAX) slot = i;
    }
    if (slot == SIZE_MAX) return NET_ERR_CAPACITY;
    c->entries[slot].used = 1;
    c->entries[slot].ip = p->sender_ip;
    c->entries[slot].mac = p->sender_mac;
    c->entries[slot].expires = expires;
    return NET_OK;
}

/* ---- IPv4 ---- */
net_err net_ipv4_parse(const uint8_t *b, size_t len, net_ipv4_header *out,
                       const uint8_t **payload, size_t *payload_len)
{
    if (!out || !payload || !payload_len || (!b && len)) return NET_ERR_INVALID;
    if (len < 20) return NET_ERR_TRUNCATED;
    if (b[0] >> 4 != 4) return NET_ERR_INVALID;
    size_t h = (size_t)(b[0] & 15) * 4;
    if (h < 20 || len < h) return NET_ERR_INVALID;
    size_t total = rd16(b + 2);
    if (total < h || total > len) return NET_ERR_TRUNCATED;
    uint16_t ff = rd16(b + 6);
    if (ff & 0x8000u) return NET_ERR_INVALID;      /* RFC 791 reserved bit */
    if (ff & 0x3fffu) return NET_ERR_UNSUPPORTED;  /* MF or offset: no reassembly */
    if (b[8] == 0) return NET_ERR_INVALID;
    if (net_checksum(b, h) != 0) return NET_ERR_INVALID;
    out->dscp_ecn = b[1];
    out->identification = rd16(b + 4);
    out->ttl = b[8];
    out->protocol = b[9];
    memcpy(out->source.b, b + 12, 4);
    memcpy(out->destination.b, b + 16, 4);
    *payload = b + h;
    *payload_len = total - h;
    return NET_OK;
}

net_err net_ipv4_build(const net_ipv4_header *h, const uint8_t *payload, size_t payload_len,
                       uint8_t *out, size_t cap, size_t *written)
{
    if (!h || !written || (!payload && payload_len) || (!out && cap)) return NET_ERR_INVALID;
    if (payload_len > SIZE_MAX - 20) return NET_ERR_CAPACITY;
    size_t total = 20 + payload_len;
    if (total > 0xffffu || cap < total) return NET_ERR_TRUNCATED;
    if (payload_len) memmove(out + 20, payload, payload_len);
    memset(out, 0, 20);
    out[0] = 0x45;
    out[1] = h->dscp_ecn;
    wr16(out + 2, (uint16_t)total);
    wr16(out + 4, h->identification);
    out[8] = h->ttl;
    out[9] = h->protocol;
    memcpy(out + 12, h->source.b, 4);
    memcpy(out + 16, h->destination.b, 4);
    wr16(out + 10, net_checksum(out, 20));
    *written = total;
    return NET_OK;
}

/* ---- ICMP echo ---- */
net_err net_icmp_echo_parse(const uint8_t *b, size_t len, net_icmp_echo *out)
{
    if (!out || (!b && len)) return NET_ERR_INVALID;
    if (len < 8) return NET_ERR_TRUNCATED;
    if ((b[0] != 0 && b[0] != 8) || b[1] != 0) return NET_ERR_UNSUPPORTED;
    if (net_checksum(b, len) != 0) return NET_ERR_INVALID;
    out->reply = b[0] == 0;
    out->identifier = rd16(b + 4);
    out->sequence = rd16(b + 6);
    out->data_len = len - 8;
    return NET_OK;
}

net_err net_icmp_echo_build(const net_icmp_echo *e, const uint8_t *data, size_t data_len,
                            uint8_t *out, size_t cap, size_t *written)
{
    if (!e || !written || (!data && data_len) || (!out && cap)) return NET_ERR_INVALID;
    if (data_len > SIZE_MAX - 8) return NET_ERR_CAPACITY;
    size_t n = 8 + data_len;
    if (cap < n) return NET_ERR_TRUNCATED;
    if (data_len) memmove(out + 8, data, data_len);
    memset(out, 0, 8);
    out[0] = e->reply ? 0 : 8;
    wr16(out + 4, e->identifier);
    wr16(out + 6, e->sequence);
    wr16(out + 2, net_checksum(out, n));
    *written = n;
    return NET_OK;
}

/* ---- UDP ---- */
static uint64_t pseudo(net_ipv4 src, net_ipv4 dst, uint16_t len)
{
    return (uint64_t)rd16(src.b) + rd16(src.b + 2) + rd16(dst.b) + rd16(dst.b + 2) +
           NET_IPPROTO_UDP + len;
}

net_err net_udp_parse(const uint8_t *b, size_t len, net_ipv4 src, net_ipv4 dst,
                      net_udp_header *out, const uint8_t **payload, size_t *payload_len)
{
    if (!out || !payload || !payload_len || (!b && len)) return NET_ERR_INVALID;
    if (len < 8) return NET_ERR_TRUNCATED;
    size_t n = rd16(b + 4);
    if (n < 8 || n > len) return NET_ERR_INVALID;
    if (rd16(b + 6) != 0) {
        if (fold(pseudo(src, dst, (uint16_t)n) + sum16(b, n)) != 0xffffu) return NET_ERR_INVALID;
    }
    out->source_port = rd16(b);
    out->destination_port = rd16(b + 2);
    *payload = b + 8;
    *payload_len = n - 8;
    return NET_OK;
}

net_err net_udp_build(const net_udp_header *h, const uint8_t *data, size_t data_len,
                      net_ipv4 src, net_ipv4 dst, uint8_t *out, size_t cap, size_t *written)
{
    if (!h || !written || (!data && data_len) || (!out && cap)) return NET_ERR_INVALID;
    if (data_len > 0xffffu - 8) return NET_ERR_TRUNCATED;
    size_t n = 8 + data_len;
    if (cap < n) return NET_ERR_TRUNCATED;
    if (data_len) memmove(out + 8, data, data_len);
    memset(out, 0, 8);
    wr16(out, h->source_port);
    wr16(out + 2, h->destination_port);
    wr16(out + 4, (uint16_t)n);
    uint16_t c = (uint16_t)~fold(pseudo(src, dst, (uint16_t)n) + sum16(out, n));
    wr16(out + 6, c == 0 ? 0xffffu : c);
    *written = n;
    return NET_OK;
}
