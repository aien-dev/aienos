/* AIENOS M6-A framed control-transport STUB, TEST identity only.
 *
 * There is no Rust reference for this layer; this file is its spec. It is a
 * reliable, ordered, authenticated message channel carried in UDP payloads,
 * driven entirely by the caller: the caller supplies the clock (ticks), puts
 * frames on the wire and hands received frames back. No heap, clock or I/O.
 *
 * Identity: ONLY the published TEST identity exists here. Its key is derived
 * from a public label, so it authenticates nothing against a real attacker; it
 * exercises framing, loss recovery and refusal paths. Production identity and
 * keys wait for M5 (key hierarchy), and native binding waits for a C kernel.
 *
 * Frame (big-endian), total = 24 + payload_len + 16:
 *   0  magic "ACT1"      4  version (1)      5  type (1 DATA, 2 ACK)
 *   6  sender role (0/1) 7  identity kind (0x54 TEST)
 *   8  session u32       12 seq u32          16 ack u32 (next seq expected)
 *   20 payload_len u16   22 reserved u16 (0)
 *   24 payload           .. tag: HMAC-SHA256(key, frame[0..24+len])[0..16]
 * ACK frames carry seq 0 and no payload. DATA frames piggyback ack.
 * Sender: up to CT_WINDOW unacknowledged messages, per-message retransmit
 * after rto ticks, link declared down after max_retries retransmissions.
 * Receiver: delivers only the next expected seq (in order, exactly once);
 * duplicates and gaps are not delivered and trigger a cumulative ACK.
 */
#ifndef AIENOS_CTL_H
#define AIENOS_CTL_H

#include <stddef.h>
#include <stdint.h>

#define CT_HEADER_LEN 24u
#define CT_TAG_LEN 16u
#define CT_MAX_PAYLOAD 1024u
#define CT_MAX_FRAME (CT_HEADER_LEN + CT_MAX_PAYLOAD + CT_TAG_LEN)
#define CT_WINDOW 4u
#define CT_VERSION 1u
#define CT_TYPE_DATA 1u
#define CT_TYPE_ACK 2u
#define CT_IDENTITY_TEST 0x54u

typedef enum {
    CT_OK = 0,           /* frame accepted (ack, duplicate or gap) / frame produced */
    CT_DELIVERED = 1,    /* receive: one in-order message copied out */
    CT_IDLE = 2,         /* poll: nothing to send now */
    CT_ERR_ARG = -1,
    CT_ERR_MALFORMED = -2,  /* bad magic/version/type/lengths/reserved fields */
    CT_ERR_BAD_TAG = -3,    /* authentication tag mismatch */
    CT_ERR_REFUSED = -4,    /* wrong identity kind, session or sender role */
    CT_ERR_BAD_ACK = -5,    /* ack outside the sent range */
    CT_ERR_CAPACITY = -6,   /* output buffer too small */
    CT_ERR_TOO_LARGE = -7,  /* message longer than CT_MAX_PAYLOAD */
    CT_ERR_WINDOW_FULL = -8,
    CT_ERR_LINK_DOWN = -9,  /* max retries exhausted; endpoint is dead */
    CT_ERR_SEQ_EXHAUSTED = -10, /* sequence space used up; needs a new session */
} ct_status;

typedef struct {
    uint8_t kind; /* always CT_IDENTITY_TEST */
    uint8_t key[32];
} ct_identity;

typedef struct {
    uint8_t used, sent;
    uint16_t len;
    uint32_t seq;
    uint32_t tries;
    uint64_t last_tx;
    uint8_t data[CT_MAX_PAYLOAD];
} ct_slot;

typedef struct {
    uint64_t tx_frames, tx_retransmits, tx_acks;
    uint64_t rx_delivered, rx_duplicate, rx_gap, rx_ack;
    uint64_t rx_malformed, rx_bad_tag, rx_refused, rx_bad_ack;
} ct_counters;

typedef struct {
    uint8_t key[32];
    uint8_t role;
    uint8_t link_down;
    uint8_t ack_pending;
    uint32_t session;
    uint32_t rto;
    uint32_t max_retries;
    uint32_t next_seq; /* sender: next seq to assign */
    uint32_t base;     /* sender: oldest unacknowledged seq */
    uint32_t expected; /* receiver: next seq to deliver */
    ct_slot slots[CT_WINDOW];
    ct_counters c;
} ct_endpoint;

/* Derive the public TEST identity for a label. Never use for production. */
ct_status ct_test_identity(ct_identity *id, const char *label);

ct_status ct_init(ct_endpoint *ep, const ct_identity *id, uint8_t role, uint32_t session,
                  uint32_t rto, uint32_t max_retries);
/* Queue one message for reliable, ordered delivery. */
ct_status ct_send(ct_endpoint *ep, const uint8_t *msg, size_t len);
/* Produce the next frame to put on the wire (CT_OK, *written > 0) or CT_IDLE. */
ct_status ct_poll_tx(ct_endpoint *ep, uint64_t now, uint8_t *out, size_t cap, size_t *written);
/* Process one received frame. CT_DELIVERED copies one message into msg. */
ct_status ct_receive(ct_endpoint *ep, const uint8_t *frame, size_t len, uint8_t *msg, size_t cap,
                     size_t *msg_len);
/* Number of queued, unacknowledged messages. */
uint32_t ct_in_flight(const ct_endpoint *ep);
const char *ct_status_name(ct_status s);

#endif
