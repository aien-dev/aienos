/* report_x86.c -- sends the iMac kernel's report over Ethernet, so the
 * owner no longer has to photograph the screen.
 *
 * The report is the console's RAM copy (console_x86.c: everything printed,
 * the first 16 KiB). It is cut into parts of CK_X86_REPORT_CHUNK bytes; each
 * part is one UDP datagram from 0.0.0.0:PORT to 255.255.255.255:PORT in an
 * Ethernet broadcast frame (no address to configure, no ARP, nothing to
 * answer), with a one-line header the receiver checks:
 *   "AIENOS-IMAC-REPORT v=1 run=<16 hex> part=<i>/<n> bytes=<total>\n"
 * The host side is native/kernel/tools/ck_imac_report_listen.c. During the
 * screen hold the whole report is sent again every 2 s while the link is up,
 * so a receiver that missed a datagram gets it on the next round.
 *
 * ck_x86_report_frame is a pure function of its arguments (no device, no
 * clock) and is host-tested by scripts/ck_imac_report_test.sh. */
#ifdef CK_X86_REPORT_HOST
#include <string.h>
#else
#include "../core/ck_internal.h"
#include "x86.h"
#endif
#include "aienos_net.h"
#include "report_x86.h"

#define REPORT_HDR "AIENOS-IMAC-REPORT v=1 "

static void hex16(char *out, uint64_t v)
{
    for (int i = 15; i >= 0; i--, v >>= 4)
        out[i] = "0123456789abcdef"[v & 15];
}

static size_t dec(char *out, unsigned v)
{
    char t[10];
    size_t n = 0, k = 0;
    do
        t[n++] = (char)('0' + v % 10);
    while ((v /= 10) && n < sizeof t);
    while (n)
        out[k++] = t[--n];
    return k;
}

unsigned ck_x86_report_parts(size_t len)
{
    if (!len || len > CK_X86_REPORT_MAX)
        return 0;
    return (unsigned)((len + CK_X86_REPORT_CHUNK - 1) / CK_X86_REPORT_CHUNK);
}

size_t ck_x86_report_frame(const uint8_t mac[6], uint64_t run, const char *log, size_t len, unsigned part,
                           uint8_t *out, size_t cap)
{
    static uint8_t data[160 + CK_X86_REPORT_CHUNK], udp[8 + sizeof data], ip[20 + sizeof udp];
    unsigned parts = ck_x86_report_parts(len);
    if (!mac || !log || !out || part >= parts)
        return 0;
    size_t off = (size_t)part * CK_X86_REPORT_CHUNK;
    size_t n = len - off < CK_X86_REPORT_CHUNK ? len - off : CK_X86_REPORT_CHUNK;
    size_t h = sizeof REPORT_HDR - 1;
    memcpy(data, REPORT_HDR "run=", h + 4);
    h += 4;
    hex16((char *)data + h, run);
    h += 16;
    memcpy(data + h, " part=", 6);
    h += 6;
    h += dec((char *)data + h, part);
    data[h++] = '/';
    h += dec((char *)data + h, parts);
    memcpy(data + h, " bytes=", 7);
    h += 7;
    h += dec((char *)data + h, (unsigned)len);
    data[h++] = '\n';
    memcpy(data + h, log + off, n);

    const net_ipv4 any = {{0, 0, 0, 0}}, bcast_ip = {{255, 255, 255, 255}};
    net_udp_header uh = {CK_X86_REPORT_PORT, CK_X86_REPORT_PORT};
    size_t uw = 0, iw = 0, ew = 0;
    if (net_udp_build(&uh, data, h + n, any, bcast_ip, udp, sizeof udp, &uw) != NET_OK)
        return 0;
    net_ipv4_header ih;
    ih.dscp_ecn = 0;
    ih.identification = (uint16_t)part;
    ih.ttl = 1; /* this network only */
    ih.protocol = NET_IPPROTO_UDP;
    ih.source = any;
    ih.destination = bcast_ip;
    if (net_ipv4_build(&ih, udp, uw, ip, sizeof ip, &iw) != NET_OK)
        return 0;
    net_eth_frame e;
    memset(e.destination.b, 0xff, 6);
    memcpy(e.source.b, mac, 6);
    e.ethertype = NET_ETHERTYPE_IPV4;
    e.payload = ip;
    e.payload_len = iw;
    if (net_eth_build(&e, out, cap, &ew) != NET_OK)
        return 0;
    return ew;
}

#ifndef CK_X86_REPORT_HOST
/* Holds for `seconds`, sending the report every 2 s while the link is up.
 * Without a working network it only waits. Returns the rounds sent. */
unsigned ck_x86_report_hold(uint64_t tsc_hz, unsigned seconds)
{
    static uint8_t frame[1600];
    static int busy; /* a fault while sending ends up here again: only wait */
    uint64_t t0 = ck_rdtsc(), end = t0 + (uint64_t)seconds * tsc_hz, next = t0;
    if (busy++ || !ck_x86_tg3_ready()) {
        while (ck_rdtsc() < end)
            ck_pause();
        return 0;
    }
    ck_printf("report: sending this screen to UDP port %u (broadcast) every 2 s during the hold\n",
              (unsigned)CK_X86_REPORT_PORT);
    size_t len;
    const char *log = ck_x86_console_log(&len);
    unsigned parts = ck_x86_report_parts(len), rounds = 0, failed = 0;
    uint8_t mac[6];
    ck_x86_tg3_mac(mac);
    uint64_t run = t0 ^ (uint64_t)len << 48;
    while (ck_rdtsc() < end) {
        if (ck_rdtsc() < next) {
            ck_pause();
            continue;
        }
        next += 2 * tsc_hz;
        if (!ck_x86_tg3_link())
            continue;
        for (unsigned p = 0; p < parts; p++) {
            size_t n = ck_x86_report_frame(mac, run, log, len, p, frame, sizeof frame);
            if (!n || ck_x86_tg3_send(frame, n))
                failed++;
        }
        if (ck_x86_tg3_drain(100))
            failed++;
        rounds++;
    }
    /* Printed after the snapshot, so only the screen shows it. */
    ck_printf("report: rounds=%u parts=%u bytes=%u send_failures=%u\n", rounds, parts, (unsigned)len, failed);
    return rounds;
}
#endif
