/* net_udp.h -- the C kernel's UDP round-trip frames over the M6-A protocol
 * layer (native/net/aienos_net.h): ARP for the gateway, one UDP datagram
 * out, one UDP datagram back. Pure functions over caller buffers (no device,
 * no clock), so they are host-tested in svc/tests/stage_test.c.
 *
 * Addresses are QEMU user networking (slirp) defaults: guest 10.0.2.15,
 * gateway/host 10.0.2.2. Slirp forwards a datagram for 10.0.2.2:PORT to the
 * host's 127.0.0.1:PORT (scripts/qemu_ck_net_test.sh runs the echo helper
 * native/kernel/tools/ck_udp_echo.c there). QEMU is not hardware. */
#ifndef AIENOS_CK_NET_UDP_H
#define AIENOS_CK_NET_UDP_H
#include <stddef.h>
#include <stdint.h>
#include "aienos_net.h"

#define CK_NET_ECHO_PORT 47029u  /* host helper port (scripts read this line) */
#define CK_NET_LOCAL_PORT 47030u /* guest source port */

typedef struct {
    net_mac mac;      /* ours (virtio-net config) */
    net_ipv4 ip;      /* ours */
    net_mac gw_mac;   /* learned from the ARP reply */
    net_ipv4 gw_ip;
    uint16_t lport, rport;
} ck_net_peer;

/* Frame builders: bytes written, 0 when the buffer is too small or an
 * argument is bad. */
size_t ck_net_arp_request(const ck_net_peer *p, uint8_t *out, size_t cap);
/* ARP reply to `req` (a request for p->ip), sent to its sender. */
size_t ck_net_arp_reply(const ck_net_peer *p, const net_arp_packet *req, uint8_t *out, size_t cap);
/* Ethernet + IPv4 + UDP from p->ip:lport to p->gw_ip:rport via p->gw_mac. */
size_t ck_net_udp_frame(const ck_net_peer *p, uint16_t ip_id, const uint8_t *data, size_t n, uint8_t *out,
                        size_t cap);

typedef enum {
    CK_NET_IGNORED = 0,   /* not for us, malformed, or not what we wait for */
    CK_NET_ARP_GW = 1,    /* ARP reply from gw_ip to us: *mac = gateway MAC */
    CK_NET_ARP_ASK = 2,   /* ARP request for our ip: *arp = the request */
    CK_NET_UDP_REPLY = 3, /* UDP gw_ip:rport -> ip:lport, checksum ok: payload view */
} ck_net_kind;

/* Classify one received frame (Ethernet, no FCS). Every field is checked by
 * the M6-A parsers; anything else is CK_NET_IGNORED. A gateway MAC that is
 * zero, broadcast or multicast is ignored. For CK_NET_UDP_REPLY, *csum = 1
 * when the datagram carried a UDP checksum (verified by net_udp_parse), 0
 * when it carried none (allowed for UDP over IPv4). */
ck_net_kind ck_net_classify(const ck_net_peer *p, const uint8_t *frame, size_t len, net_mac *mac,
                            net_arp_packet *arp, const uint8_t **payload, size_t *payload_len, int *csum);

/* Copy at most cap-1 bytes of `b` as printable ASCII ('.' for anything
 * else, '\'' for '"' and '\\'), NUL-terminated. */
void ck_net_printable(const uint8_t *b, size_t n, char *out, size_t cap);
#endif
