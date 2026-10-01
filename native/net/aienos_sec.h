/* AIENOS M6-B secure control transport (hosted), in C. No heap, clock or I/O.
 *
 * A mutually authenticated, encrypted datagram channel between two machines,
 * carried in M6-A UDP payloads. This header is the wire spec. The caller
 * supplies the clock (ticks), the randomness and the identity keys, puts
 * datagrams on the wire and hands received ones back.
 *
 * Identity: each machine has an Ed25519 identity key (native/sig) and is
 * told the one peer public key it will accept (a pinned roster of one).
 * In this lane only TEST keys exist (sec_test_identity, public labels,
 * NOT-FOR-PRODUCTION). Real keys wait for the TRUST-1 owner-key chain.
 *
 * Handshake (SIGMA style, 3 messages, identities in clear). All integers
 * big-endian. Every handshake message starts with
 *   0 magic "ASC1"  4 version 1  5 type  6 reserved u16 (0)
 *   HS1 (type 1, 72 bytes, initiator -> responder)
 *     8 random_i[32]  40 eph_i[32]                    X25519 public key
 *   HS2 (type 2, 200 bytes, responder -> initiator)
 *     8 random_r[32]  40 eph_r[32]  72 id_r[32]  104 sig_r[64]  168 fin_r[32]
 *   HS3 (type 3, 136 bytes, initiator -> responder)
 *     8 id_i[32]  40 sig_i[64]  104 fin_i[32]
 * Transcript hashes (SHA-256, C = "AIENOS-M6B-v1 transcript"):
 *   TH_a = H(C | HS1 | HS2[0..104))      sig_r = Ed25519(sk_r, "AIENOS-M6B-v1 sig r" | 0 | TH_a)
 *   TH_b = H(C | HS1 | HS2[0..168))      fin_r = HMAC(fin_key_r, TH_b)
 *   TH_c = H(C | HS1 | HS2 | HS3[0..40)) sig_i = Ed25519(sk_i, "AIENOS-M6B-v1 sig i" | 0 | TH_c)
 *   TH_d = H(C | HS1 | HS2 | HS3[0..104)) fin_i = HMAC(fin_key_i, TH_d)
 *   TH_f = H(C | HS1 | HS2 | HS3)
 * Each signature covers both ephemeral keys, both randoms and the signer's
 * identity, so a message from one handshake cannot be spliced into another.
 * Key schedule (HKDF-SHA256, RFC 5869, one 32-byte output block each):
 *   dh = X25519(eph_sk, peer_eph) (all-zero result refused)
 *   PRK = HKDF-Extract(salt = SHA-256("AIENOS-M6B-v1 hkdf salt"), dh)
 *   fin_key_r = Expand(PRK, "fin r" | TH_a), fin_key_i = Expand(PRK, "fin i" | TH_a)
 *   master = Expand(PRK, "master" | TH_f)
 *   key_i2r[0] = Expand(master, "i2r"), key_r2i[0] = Expand(master, "r2i")
 *   session_id = Expand(master, "session")[0..8)
 *   key_dir[e + 1] = Expand(key_dir[e], "rekey")  (old key wiped)
 *
 * Record (type 0x10), total = 24 + 1 + payload_len + 16:
 *   0 magic "ASC1"  4 version 1  5 type 0x10  6 dir (0 i2r, 1 r2i)
 *   7 reserved (0)  8 session_id[8]  16 seq u64
 *   24 AES-256-GCM-SIV(key_dir[seq / rekey_interval],
 *        nonce = dir | 0 0 0 | seq, aad = bytes 0..24,
 *        plaintext = inner_type | payload) || tag[16]
 *   inner_type: 1 DATA, 2 CLOSE, 3 CONFIRM (responder's "keys installed")
 * The sender's seq starts at 0 and rises by one per record. The receiver
 * keeps a SEC_WINDOW-record sliding replay window (accepts reordering inside
 * it, refuses duplicates and anything older) and the keys of the current
 * and previous epoch only. After max_records the channel refuses to send:
 * run a new handshake.
 *
 * Loss: HS1 is resent every rto ticks until HS2 arrives; HS3 every rto until
 * an authenticated record from the responder arrives (the responder answers
 * every valid HS3 with a CONFIRM record); the responder answers a repeat of
 * the exact HS1 with its stored HS2. More than max_retries resends of one
 * flight -> SEC_ERR_LINK_DOWN. Data records are not resent here: carry the
 * M6-A reliable channel (aienos_ctl) inside them for ordered, exactly-once
 * delivery.
 */
#ifndef AIENOS_SEC_H
#define AIENOS_SEC_H

#include <stddef.h>
#include <stdint.h>

#define SEC_VERSION 1u
#define SEC_TYPE_HS1 1u
#define SEC_TYPE_HS2 2u
#define SEC_TYPE_HS3 3u
#define SEC_TYPE_RECORD 0x10u
#define SEC_INNER_DATA 1u
#define SEC_INNER_CLOSE 2u
#define SEC_INNER_CONFIRM 3u

#define SEC_HS1_LEN 72u
#define SEC_HS2_LEN 200u
#define SEC_HS3_LEN 136u
#define SEC_REC_HEADER_LEN 24u
#define SEC_TAG_LEN 16u
#define SEC_MAX_PAYLOAD 1100u /* holds one full M6-A control frame (1064) */
#define SEC_REC_OVERHEAD (SEC_REC_HEADER_LEN + 1u + SEC_TAG_LEN)
#define SEC_MAX_DATAGRAM (SEC_REC_OVERHEAD + SEC_MAX_PAYLOAD)
#define SEC_WINDOW 64u
#define SEC_MAX_EPOCH_SKIP 4u
#define SEC_MIN_REKEY_INTERVAL (2u * SEC_WINDOW)

typedef enum {
    SEC_OK = 0,          /* accepted (handshake progress, confirm, duplicate HS) */
    SEC_DATA = 1,        /* receive: one authenticated payload copied out */
    SEC_IDLE = 2,        /* poll: nothing to send now */
    SEC_PEER_CLOSED = 3, /* receive: authenticated CLOSE; keys wiped */
    SEC_ERR_ARG = -1,
    SEC_ERR_MALFORMED = -2, /* magic/version/type/length/reserved/direction */
    SEC_ERR_BAD_TAG = -3,   /* record or finished MAC did not verify */
    SEC_ERR_REFUSED = -4,   /* wrong session, unexpected or different handshake message */
    SEC_ERR_IDENTITY = -5,  /* peer presented an identity key we were not told to accept */
    SEC_ERR_BAD_SIG = -6,   /* handshake signature did not verify over our transcript */
    SEC_ERR_REPLAY = -7,    /* duplicate, older than the window, or unknown epoch */
    SEC_ERR_CAPACITY = -8,
    SEC_ERR_TOO_LARGE = -9,
    SEC_ERR_STATE = -10,    /* not established (or wrong role for this message) */
    SEC_ERR_LINK_DOWN = -11,
    SEC_ERR_EXHAUSTED = -12, /* max_records used; new handshake needed */
    SEC_ERR_CLOSED = -13,
    SEC_ERR_WEAK_KEY = -14,  /* small-order X25519 share (all-zero secret) */
} sec_status;

typedef enum {
    SEC_ST_START = 0,      /* initiator: HS1 not sent yet; responder: waiting for HS1 */
    SEC_ST_WAIT_HS2 = 1,   /* initiator */
    SEC_ST_WAIT_HS3 = 2,   /* responder */
    SEC_ST_ESTABLISHED = 3,
    SEC_ST_CLOSED = 4,
    SEC_ST_DOWN = 5,
} sec_state;

typedef struct {
    uint8_t role;            /* 0 initiator, 1 responder */
    uint8_t id_sk[32];       /* our Ed25519 identity secret key (TEST only here) */
    uint8_t peer_pk[32];     /* the one peer identity key we accept */
    uint8_t entropy[64];     /* caller's fresh randomness: ephemeral scalar | random */
    uint32_t rto;            /* resend interval, ticks (>= 1) */
    uint32_t max_retries;    /* resends of one flight before LINK_DOWN */
    uint64_t rekey_interval; /* records per key epoch, >= SEC_MIN_REKEY_INTERVAL */
    uint64_t max_records;    /* records per direction before EXHAUSTED, >= 1 */
} sec_config;

typedef struct {
    uint64_t tx_hs, tx_hs_resend, tx_records, rekeys_tx, rekeys_rx;
    uint64_t rx_hs, rx_hs_dup, rx_records, rx_malformed, rx_bad_tag, rx_refused;
    uint64_t rx_identity, rx_bad_sig, rx_replay, rx_state, rx_weak;
} sec_counters;

typedef struct {
    uint8_t role, state, confirmed, flight_pending, confirm_pending, close_sent;
    uint8_t id_sk[32], id_pk[32], peer_pk[32];
    uint8_t eph_sk[32], eph_pk[32], random[32];
    uint8_t fin_key_i[32], prk[32];        /* responder keeps them until HS3 */
    uint8_t hs1[SEC_HS1_LEN], hs2[SEC_HS2_LEN], hs3[SEC_HS3_LEN];
    uint8_t flight[SEC_MAX_DATAGRAM];      /* current resendable datagram */
    uint16_t flight_len;
    uint32_t rto, max_retries, tries;
    uint64_t last_tx;
    uint64_t rekey_interval, max_records;
    uint8_t session_id[8];
    /* send direction */
    uint8_t tx_key[32];
    uint64_t tx_epoch, tx_seq;
    /* receive direction */
    uint8_t rx_key[32], rx_prev_key[32];
    uint8_t rx_has_prev, rx_any;
    uint64_t rx_epoch, rx_top; /* rx_top = highest accepted seq + 1 */
    uint64_t rx_bitmap;        /* bit i set: seq rx_top - 1 - i accepted */
    sec_counters c;
} sec_endpoint;

/* Public TEST identity from a label (sk = SHA-256(public prefix | label)).
 * NOT-FOR-PRODUCTION: anyone can recompute it. */
sec_status sec_test_identity(uint8_t sk[32], uint8_t pk[32], const char *label);

sec_status sec_init(sec_endpoint *ep, const sec_config *cfg);
/* Next handshake/control datagram to put on the wire, or SEC_IDLE. */
sec_status sec_poll_tx(sec_endpoint *ep, uint64_t now, uint8_t *out, size_t cap, size_t *written);
/* Seal one payload into a record datagram (established only). */
sec_status sec_seal(sec_endpoint *ep, const uint8_t *msg, size_t len, uint8_t *out, size_t cap,
                    size_t *written);
/* Process one received datagram. SEC_DATA copies the payload into msg. */
sec_status sec_receive(sec_endpoint *ep, uint64_t now, const uint8_t *in, size_t len, uint8_t *msg,
                       size_t cap, size_t *msg_len);
/* Send CLOSE (written to out), wipe every key, enter SEC_ST_CLOSED. The
 * same datagram is resent by sec_poll_tx every rto, max_retries times. */
sec_status sec_close(sec_endpoint *ep, uint64_t now, uint8_t *out, size_t cap, size_t *written);
const char *sec_status_name(sec_status s);

/* HKDF-SHA256 single-block expand / extract, exposed for the RFC 5869 test. */
void sec_hkdf_extract(uint8_t prk[32], const uint8_t salt[32], const uint8_t *ikm, size_t len);
void sec_hkdf_expand1(uint8_t out[32], const uint8_t prk[32], const uint8_t *info, size_t len);

#endif
