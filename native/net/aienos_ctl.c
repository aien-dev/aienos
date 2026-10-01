/* AIENOS M6-A control-transport stub. See aienos_ctl.h. No heap, clock or I/O. */
#include "aienos_ctl.h"

#include <string.h>

#include "../argus/sha256.h"

static const uint8_t CT_MAGIC[4] = {'A', 'C', 'T', '1'};
/* Public derivation label: anyone can compute a TEST key. */
static const char CT_TEST_LABEL[] = "AIENOS-M6A-TEST-IDENTITY/NOT-FOR-PRODUCTION/";

static void wr16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v; }
static void wr32(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v;
}
static uint16_t rd16(const uint8_t *b) { return (uint16_t)((uint16_t)b[0] << 8 | b[1]); }
static uint32_t rd32(const uint8_t *b)
{
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

static void hmac_sha256(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint8_t ipad[SHA256_BLOCK_SIZE], opad[SHA256_BLOCK_SIZE], inner[SHA256_DIGEST_SIZE];
    memset(ipad, 0x36, sizeof ipad);
    memset(opad, 0x5c, sizeof opad);
    for (size_t i = 0; i < 32; i++) { ipad[i] ^= key[i]; opad[i] ^= key[i]; }
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, ipad, sizeof ipad);
    sha256_update(&c, msg, len);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, sizeof opad);
    sha256_update(&c, inner, sizeof inner);
    sha256_final(&c, out);
}

static int tag_equal(const uint8_t *a, const uint8_t *b)
{
    uint8_t d = 0;
    for (size_t i = 0; i < CT_TAG_LEN; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

const char *ct_status_name(ct_status s)
{
    switch (s) {
    case CT_OK: return "Ok";
    case CT_DELIVERED: return "Delivered";
    case CT_IDLE: return "Idle";
    case CT_ERR_ARG: return "Arg";
    case CT_ERR_MALFORMED: return "Malformed";
    case CT_ERR_BAD_TAG: return "BadTag";
    case CT_ERR_REFUSED: return "Refused";
    case CT_ERR_BAD_ACK: return "BadAck";
    case CT_ERR_CAPACITY: return "Capacity";
    case CT_ERR_TOO_LARGE: return "TooLarge";
    case CT_ERR_WINDOW_FULL: return "WindowFull";
    case CT_ERR_LINK_DOWN: return "LinkDown";
    case CT_ERR_SEQ_EXHAUSTED: return "SeqExhausted";
    }
    return "Unknown";
}

ct_status ct_test_identity(ct_identity *id, const char *label)
{
    if (!id || !label) return CT_ERR_ARG;
    size_t n = strnlen(label, 65);
    if (n == 0 || n > 64) return CT_ERR_ARG;
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)CT_TEST_LABEL, sizeof CT_TEST_LABEL - 1);
    sha256_update(&c, (const uint8_t *)label, n);
    sha256_final(&c, id->key);
    id->kind = CT_IDENTITY_TEST;
    return CT_OK;
}

ct_status ct_init(ct_endpoint *ep, const ct_identity *id, uint8_t role, uint32_t session,
                  uint32_t rto, uint32_t max_retries)
{
    if (!ep || !id || role > 1 || rto == 0) return CT_ERR_ARG;
    if (id->kind != CT_IDENTITY_TEST) return CT_ERR_REFUSED; /* production identity: M5 */
    memset(ep, 0, sizeof *ep);
    memcpy(ep->key, id->key, 32);
    ep->role = role;
    ep->session = session;
    ep->rto = rto;
    ep->max_retries = max_retries;
    return CT_OK;
}

uint32_t ct_in_flight(const ct_endpoint *ep) { return ep ? ep->next_seq - ep->base : 0; }

ct_status ct_send(ct_endpoint *ep, const uint8_t *msg, size_t len)
{
    if (!ep || (!msg && len)) return CT_ERR_ARG;
    if (ep->link_down) return CT_ERR_LINK_DOWN;
    if (len > CT_MAX_PAYLOAD) return CT_ERR_TOO_LARGE;
    if (ep->next_seq == UINT32_MAX) return CT_ERR_SEQ_EXHAUSTED;
    if (ep->next_seq - ep->base >= CT_WINDOW) return CT_ERR_WINDOW_FULL;
    ct_slot *s = &ep->slots[ep->next_seq % CT_WINDOW];
    memset(s, 0, sizeof *s);
    s->used = 1;
    s->seq = ep->next_seq++;
    s->len = (uint16_t)len;
    if (len) memcpy(s->data, msg, len);
    return CT_OK;
}

static size_t build_frame(const ct_endpoint *ep, uint8_t type, uint32_t seq, const uint8_t *p,
                          uint16_t len, uint8_t *out)
{
    memcpy(out, CT_MAGIC, 4);
    out[4] = CT_VERSION;
    out[5] = type;
    out[6] = ep->role;
    out[7] = CT_IDENTITY_TEST;
    wr32(out + 8, ep->session);
    wr32(out + 12, seq);
    wr32(out + 16, ep->expected);
    wr16(out + 20, len);
    wr16(out + 22, 0);
    if (len) memcpy(out + CT_HEADER_LEN, p, len);
    uint8_t mac[32];
    hmac_sha256(ep->key, out, CT_HEADER_LEN + (size_t)len, mac);
    memcpy(out + CT_HEADER_LEN + len, mac, CT_TAG_LEN);
    return CT_HEADER_LEN + (size_t)len + CT_TAG_LEN;
}

ct_status ct_poll_tx(ct_endpoint *ep, uint64_t now, uint8_t *out, size_t cap, size_t *written)
{
    if (!ep || !out || !written) return CT_ERR_ARG;
    *written = 0;
    if (ep->link_down) return CT_ERR_LINK_DOWN;
    for (uint32_t q = ep->base; q != ep->next_seq; q++) {
        ct_slot *s = &ep->slots[q % CT_WINDOW];
        if (!s->used || s->seq != q) continue;
        int due = !s->sent || (now >= s->last_tx && now - s->last_tx >= ep->rto);
        if (!due) continue;
        if (s->sent && s->tries > ep->max_retries) { ep->link_down = 1; return CT_ERR_LINK_DOWN; }
        if (cap < CT_HEADER_LEN + (size_t)s->len + CT_TAG_LEN) return CT_ERR_CAPACITY;
        if (s->sent) ep->c.tx_retransmits++;
        s->sent = 1;
        s->tries++;
        s->last_tx = now;
        *written = build_frame(ep, CT_TYPE_DATA, s->seq, s->data, s->len, out);
        ep->ack_pending = 0; /* piggybacked */
        ep->c.tx_frames++;
        return CT_OK;
    }
    if (ep->ack_pending) {
        if (cap < CT_HEADER_LEN + CT_TAG_LEN) return CT_ERR_CAPACITY;
        *written = build_frame(ep, CT_TYPE_ACK, 0, NULL, 0, out);
        ep->ack_pending = 0;
        ep->c.tx_acks++;
        ep->c.tx_frames++;
        return CT_OK;
    }
    return CT_IDLE;
}

ct_status ct_receive(ct_endpoint *ep, const uint8_t *f, size_t len, uint8_t *msg, size_t cap,
                     size_t *msg_len)
{
    if (!ep || (!f && len) || !msg_len || (!msg && cap)) return CT_ERR_ARG;
    *msg_len = 0;
    if (ep->link_down) return CT_ERR_LINK_DOWN;
    /* 1. structure, before any field is trusted */
    if (len < CT_HEADER_LEN + CT_TAG_LEN || memcmp(f, CT_MAGIC, 4) != 0 || f[4] != CT_VERSION ||
        (f[5] != CT_TYPE_DATA && f[5] != CT_TYPE_ACK) || f[6] > 1 || rd16(f + 22) != 0) {
        ep->c.rx_malformed++;
        return CT_ERR_MALFORMED;
    }
    size_t plen = rd16(f + 20);
    if (plen > CT_MAX_PAYLOAD || len != CT_HEADER_LEN + plen + CT_TAG_LEN) {
        ep->c.rx_malformed++;
        return CT_ERR_MALFORMED;
    }
    if (f[7] != CT_IDENTITY_TEST) { ep->c.rx_refused++; return CT_ERR_REFUSED; }
    /* 2. authentication */
    uint8_t mac[32];
    hmac_sha256(ep->key, f, CT_HEADER_LEN + plen, mac);
    if (!tag_equal(mac, f + CT_HEADER_LEN + plen)) { ep->c.rx_bad_tag++; return CT_ERR_BAD_TAG; }
    /* 3. binding: our session, frames from the peer role only (no reflection) */
    if (rd32(f + 8) != ep->session || f[6] == ep->role) { ep->c.rx_refused++; return CT_ERR_REFUSED; }
    uint8_t type = f[5];
    uint32_t seq = rd32(f + 12), ack = rd32(f + 16);
    if (type == CT_TYPE_ACK && (seq != 0 || plen != 0)) { ep->c.rx_malformed++; return CT_ERR_MALFORMED; }
    if (ack > ep->next_seq) { ep->c.rx_bad_ack++; return CT_ERR_BAD_ACK; }
    if (type == CT_TYPE_DATA && seq == ep->expected && cap < plen) return CT_ERR_CAPACITY;
    /* 4. cumulative ack (a stale ack below base is ignored: reordering) */
    while (ep->base < ack) {
        ct_slot *s = &ep->slots[ep->base % CT_WINDOW];
        if (s->used && s->seq == ep->base) memset(s, 0, sizeof *s);
        ep->base++;
    }
    if (type == CT_TYPE_ACK) { ep->c.rx_ack++; return CT_OK; }
    /* 5. data: deliver exactly the next expected seq */
    ep->ack_pending = 1;
    if (seq == ep->expected) {
        if (ep->expected == UINT32_MAX) { ep->c.rx_refused++; return CT_ERR_SEQ_EXHAUSTED; }
        if (plen) memcpy(msg, f + CT_HEADER_LEN, plen);
        *msg_len = plen;
        ep->expected++;
        ep->c.rx_delivered++;
        return CT_DELIVERED;
    }
    if (seq < ep->expected) ep->c.rx_duplicate++;
    else ep->c.rx_gap++;
    return CT_OK;
}
