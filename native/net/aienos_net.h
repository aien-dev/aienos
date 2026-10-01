/* AIENOS M6-A hosted network protocol layer, in C. No Rust, no heap.
 *
 * Port of the Rust reference crates/aienos-kernel/src/net.rs (read as the
 * spec, not extended). Every parser takes (pointer, length), checks every
 * offset before reading, and returns views into the caller's buffer only.
 * Error order matches the Rust reference exactly so the two can be compared
 * byte for byte (see tests/net_diff.c).
 *
 * Deliberate difference: checksums accumulate in 64 bits, so inputs larger
 * than 128 KiB cannot overflow the sum (the Rust u32 sum would overflow there).
 *
 * Hosted only: no native binding (needs a C kernel) and no production keys
 * (needs M5). See README.md.
 */
#ifndef AIENOS_NET_H
#define AIENOS_NET_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    NET_OK = 0,
    NET_ERR_TRUNCATED = 1,
    NET_ERR_INVALID = 2,
    NET_ERR_UNSUPPORTED = 3,
    NET_ERR_CAPACITY = 4,
} net_err;

typedef struct { uint8_t b[6]; } net_mac;
typedef struct { uint8_t b[4]; } net_ipv4;

#define NET_ETHERTYPE_IPV4 0x0800u
#define NET_ETHERTYPE_ARP 0x0806u
#define NET_ARP_REQUEST 1u
#define NET_ARP_REPLY 2u
#define NET_IPPROTO_ICMP 1u
#define NET_IPPROTO_UDP 17u

/* RFC 1071 one's-complement checksum; a final odd byte is the high octet. */
uint16_t net_checksum(const uint8_t *data, size_t len);

/* ---- Ethernet II ---- */
typedef struct {
    net_mac destination;
    net_mac source;
    uint16_t ethertype;
    const uint8_t *payload; /* view into the parsed buffer */
    size_t payload_len;
} net_eth_frame;

net_err net_eth_parse(const uint8_t *b, size_t len, net_eth_frame *out);
net_err net_eth_build(const net_eth_frame *f, uint8_t *out, size_t cap, size_t *written);

/* ---- ARP (Ethernet/IPv4 only) ---- */
typedef struct {
    uint16_t operation;
    net_mac sender_mac;
    net_ipv4 sender_ip;
    net_mac target_mac;
    net_ipv4 target_ip;
} net_arp_packet;

net_err net_arp_parse(const uint8_t *b, size_t len, net_arp_packet *out);
net_err net_arp_build(const net_arp_packet *p, uint8_t *out, size_t cap, size_t *written);

/* Fixed-capacity ARP cache. The caller owns the clock and the expiry policy.
 * Capacity is chosen at init (1..NET_ARP_CACHE_MAX); no allocation. */
#define NET_ARP_CACHE_MAX 64
typedef struct {
    uint8_t used;
    net_ipv4 ip;
    net_mac mac;
    uint64_t expires;
} net_arp_entry;
typedef struct {
    size_t capacity;
    net_arp_entry entries[NET_ARP_CACHE_MAX];
} net_arp_cache;

net_err net_arp_cache_init(net_arp_cache *c, size_t capacity);
/* Returns 1 and fills *mac on a live hit, 0 otherwise. Expired entries seen
 * before the hit are evicted (same sweep as the Rust reference). */
int net_arp_cache_lookup(net_arp_cache *c, net_ipv4 ip, uint64_t now, net_mac *mac);
/* Learn only solicited senders unless allow_unsolicited is non-zero. */
net_err net_arp_cache_learn(net_arp_cache *c, const net_arp_packet *p, int solicited,
                            int allow_unsolicited, uint64_t now, uint64_t ttl);

/* ---- IPv4 (no options emitted, no fragment reassembly) ---- */
typedef struct {
    uint8_t dscp_ecn;
    uint16_t identification;
    uint8_t ttl;
    uint8_t protocol;
    net_ipv4 source;
    net_ipv4 destination;
} net_ipv4_header;

net_err net_ipv4_parse(const uint8_t *b, size_t len, net_ipv4_header *out,
                       const uint8_t **payload, size_t *payload_len);
net_err net_ipv4_build(const net_ipv4_header *h, const uint8_t *payload, size_t payload_len,
                       uint8_t *out, size_t cap, size_t *written);

/* ---- ICMP echo ---- */
typedef struct {
    int reply; /* 1 = echo reply (type 0), 0 = echo request (type 8) */
    uint16_t identifier;
    uint16_t sequence;
    size_t data_len;
} net_icmp_echo;

net_err net_icmp_echo_parse(const uint8_t *b, size_t len, net_icmp_echo *out);
net_err net_icmp_echo_build(const net_icmp_echo *e, const uint8_t *data, size_t data_len,
                            uint8_t *out, size_t cap, size_t *written);

/* ---- UDP over IPv4 ---- */
typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
} net_udp_header;

net_err net_udp_parse(const uint8_t *b, size_t len, net_ipv4 src, net_ipv4 dst,
                      net_udp_header *out, const uint8_t **payload, size_t *payload_len);
net_err net_udp_build(const net_udp_header *h, const uint8_t *data, size_t data_len,
                      net_ipv4 src, net_ipv4 dst, uint8_t *out, size_t cap, size_t *written);

const char *net_err_name(net_err e);

#endif /* AIENOS_NET_H */
