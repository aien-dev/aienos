/* report_x86.h -- the iMac kernel's network report (report_x86.c): the
 * console's RAM copy cut into UDP broadcast datagrams. No machine access in
 * here, so the frame builder is also compiled and tested on the host. */
#ifndef AIENOS_CK_X86_REPORT_H
#define AIENOS_CK_X86_REPORT_H
#include <stddef.h>
#include <stdint.h>

#define CK_X86_REPORT_PORT 47031u  /* UDP, source and destination */
#define CK_X86_REPORT_CHUNK 1024u  /* report bytes per datagram */
#define CK_X86_REPORT_MAX 16384u   /* the console's RAM copy */

/* Datagrams needed for a report of len bytes; 0 when len is 0 or too big. */
unsigned ck_x86_report_parts(size_t len);
/* The Ethernet frame (no FCS) carrying part `part` of the report: broadcast
 * from `mac`, IPv4 0.0.0.0 -> 255.255.255.255, UDP PORT -> PORT, TTL 1.
 * Bytes written, 0 on a bad argument or a buffer too small. */
size_t ck_x86_report_frame(const uint8_t mac[6], uint64_t run, const char *log, size_t len, unsigned part,
                           uint8_t *out, size_t cap);
#endif
