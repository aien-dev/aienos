/* AIENOS M6-B secure control transport. See aienos_sec.h for the wire spec.
 * No heap, clock or I/O. Lines tagged GUARD:<name> are removed one at a time
 * by `make mutants`; the tests must catch every removal.
 */
#include "aienos_sec.h"

#include <string.h>

#include "../argus/sha256.h"
#include "../crypto/aienos_crypto.h"
#include "../sig/aienos_sig.h"
#include "x25519.h"

static const uint8_t SEC_MAGIC[4] = {'A', 'S', 'C', '1'};
static const char TH_LABEL[] = "AIENOS-M6B-v1 transcript";
static const char SALT_LABEL[] = "AIENOS-M6B-v1 hkdf salt";
static const char SIG_R_LABEL[] = "AIENOS-M6B-v1 sig r"; /* signed with its NUL */
static const char SIG_I_LABEL[] = "AIENOS-M6B-v1 sig i";
static const char TEST_ID_LABEL[] = "AIENOS-M6B-TEST-IDENTITY/NOT-FOR-PRODUCTION/";

static void wr64(uint8_t *b, uint64_t v) { for (int i = 7; i >= 0; i--) { b[i] = (uint8_t)v; v >>= 8; } }
static uint64_t rd64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = v << 8 | b[i];
    return v;
}

const char *sec_status_name(sec_status s)
{
    switch (s) {
    case SEC_OK: return "Ok";
    case SEC_DATA: return "Data";
    case SEC_IDLE: return "Idle";
    case SEC_PEER_CLOSED: return "PeerClosed";
    case SEC_ERR_ARG: return "Arg";
    case SEC_ERR_MALFORMED: return "Malformed";
    case SEC_ERR_BAD_TAG: return "BadTag";
    case SEC_ERR_REFUSED: return "Refused";
    case SEC_ERR_IDENTITY: return "Identity";
    case SEC_ERR_BAD_SIG: return "BadSig";
    case SEC_ERR_REPLAY: return "Replay";
    case SEC_ERR_CAPACITY: return "Capacity";
    case SEC_ERR_TOO_LARGE: return "TooLarge";
    case SEC_ERR_STATE: return "State";
    case SEC_ERR_LINK_DOWN: return "LinkDown";
    case SEC_ERR_EXHAUSTED: return "Exhausted";
    case SEC_ERR_CLOSED: return "Closed";
    case SEC_ERR_WEAK_KEY: return "WeakKey";
    }
    return "Unknown";
}

/* ---- HKDF-SHA256 (RFC 5869) with 32-byte keys, one output block ---- */

void sec_hkdf_extract(uint8_t prk[32], const uint8_t salt[32], const uint8_t *ikm, size_t len)
{
    aienos_hmac_sha256(salt, ikm, len, prk);
}

void sec_hkdf_expand1(uint8_t out[32], const uint8_t prk[32], const uint8_t *info, size_t len)
{
    static const uint8_t one = 1;
    aienos_hmac_sha256_ctx c;
    aienos_hmac_sha256_init(&c, prk);
    aienos_hmac_sha256_update(&c, info, len);
    aienos_hmac_sha256_update(&c, &one, 1);
    aienos_hmac_sha256_final(&c, out);
}

/* Expand(key, label | th), label without its NUL. */
static void expand_label(uint8_t out[32], const uint8_t key[32], const char *label,
                         const uint8_t *th, size_t th_len)
{
    static const uint8_t one = 1;
    aienos_hmac_sha256_ctx c;
    aienos_hmac_sha256_init(&c, key);
    aienos_hmac_sha256_update(&c, (const uint8_t *)label, strlen(label));
    if (th_len) aienos_hmac_sha256_update(&c, th, th_len);
    aienos_hmac_sha256_update(&c, &one, 1);
    aienos_hmac_sha256_final(&c, out);
}

/* TH = SHA-256(label | a | b | c) */
static void transcript(uint8_t th[32], const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                       const uint8_t *c, size_t cl)
{
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)TH_LABEL, sizeof TH_LABEL - 1);
    sha256_update(&h, a, al);
    if (bl) sha256_update(&h, b, bl);
    if (cl) sha256_update(&h, c, cl);
    sha256_final(&h, th);
}

/* Signed message: label | NUL | th (fixed 52 bytes). */
static void sig_msg(uint8_t m[52], const char *label, const uint8_t th[32])
{
    memcpy(m, label, 20); /* both labels are 19 chars + NUL */
    memcpy(m + 20, th, 32);
}

static void hs_header(uint8_t *b, uint8_t type)
{
    memcpy(b, SEC_MAGIC, 4);
    b[4] = SEC_VERSION;
    b[5] = type;
    b[6] = 0;
    b[7] = 0;
}

static void wipe_secrets(sec_endpoint *ep)
{
    aienos_wipe(ep->eph_sk, sizeof ep->eph_sk);
    aienos_wipe(ep->fin_key_i, sizeof ep->fin_key_i);
    aienos_wipe(ep->prk, sizeof ep->prk);
    aienos_wipe(ep->tx_key, sizeof ep->tx_key);
    aienos_wipe(ep->rx_key, sizeof ep->rx_key);
    aienos_wipe(ep->rx_prev_key, sizeof ep->rx_prev_key);
}

static void go_down(sec_endpoint *ep)
{
    wipe_secrets(ep);
    aienos_wipe(ep->id_sk, sizeof ep->id_sk);
    ep->state = SEC_ST_DOWN;
}

sec_status sec_test_identity(uint8_t sk[32], uint8_t pk[32], const char *label)
{
    if (!sk || !pk || !label) return SEC_ERR_ARG;
    size_t n = strnlen(label, 65);
    if (n == 0 || n > 64) return SEC_ERR_ARG;
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)TEST_ID_LABEL, sizeof TEST_ID_LABEL - 1);
    sha256_update(&c, (const uint8_t *)label, n);
    sha256_final(&c, sk);
    return aienos_ed25519_public_key(pk, sk) == AIENOS_SIG_OK ? SEC_OK : SEC_ERR_ARG;
}

sec_status sec_init(sec_endpoint *ep, const sec_config *cfg)
{
    if (!ep || !cfg || cfg->role > 1 || cfg->rto == 0 || cfg->max_records == 0 ||
        cfg->rekey_interval < SEC_MIN_REKEY_INTERVAL)
        return SEC_ERR_ARG;
    memset(ep, 0, sizeof *ep);
    ep->role = cfg->role;
    memcpy(ep->id_sk, cfg->id_sk, 32);
    if (aienos_ed25519_public_key(ep->id_pk, ep->id_sk) != AIENOS_SIG_OK) {
        aienos_wipe(ep, sizeof *ep);
        return SEC_ERR_ARG;
    }
    memcpy(ep->peer_pk, cfg->peer_pk, 32);
    memcpy(ep->eph_sk, cfg->entropy, 32);
    memcpy(ep->random, cfg->entropy + 32, 32);
    aienos_x25519_base(ep->eph_pk, ep->eph_sk);
    ep->rto = cfg->rto;
    ep->max_retries = cfg->max_retries;
    ep->rekey_interval = cfg->rekey_interval;
    ep->max_records = cfg->max_records;
    ep->state = SEC_ST_START;
    return SEC_OK;
}

/* Derive record keys and session id from PRK and TH_f; wipe PRK. */
static void install_keys(sec_endpoint *ep, const uint8_t th_f[32])
{
    uint8_t master[32], sid[32];
    expand_label(master, ep->prk, "master", th_f, 32);
    if (ep->role == 0) {
        expand_label(ep->tx_key, master, "i2r", NULL, 0);
        expand_label(ep->rx_key, master, "r2i", NULL, 0);
    } else {
        expand_label(ep->tx_key, master, "r2i", NULL, 0);
        expand_label(ep->rx_key, master, "i2r", NULL, 0);
    }
    expand_label(sid, master, "session", NULL, 0);
    memcpy(ep->session_id, sid, 8);
    aienos_wipe(master, sizeof master);
    aienos_wipe(ep->prk, sizeof ep->prk);
    aienos_wipe(ep->fin_key_i, sizeof ep->fin_key_i);
    aienos_wipe(ep->eph_sk, sizeof ep->eph_sk);
    ep->tx_epoch = ep->tx_seq = 0;
    ep->rx_epoch = ep->rx_top = ep->rx_bitmap = 0;
    ep->rx_has_prev = 0;
    ep->state = SEC_ST_ESTABLISHED;
}

/* dh -> PRK. Returns 0, or -1 for a small-order peer share. */
static int derive_prk(sec_endpoint *ep, const uint8_t peer_eph[32])
{
    uint8_t dh[32], salt[32];
    int r = aienos_x25519(dh, ep->eph_sk, peer_eph);
    if (r != 0) {
        aienos_wipe(dh, sizeof dh);
        return -1; /* GUARD:weak-dh */
    }
    sha256_hash((const uint8_t *)SALT_LABEL, sizeof SALT_LABEL - 1, salt);
    sec_hkdf_extract(ep->prk, salt, dh, sizeof dh);
    aienos_wipe(dh, sizeof dh);
    return 0;
}

static sec_status build_record(sec_endpoint *ep, uint8_t inner, const uint8_t *msg, size_t len,
                               uint8_t *out, size_t cap, size_t *written)
{
    if (len > SEC_MAX_PAYLOAD) return SEC_ERR_TOO_LARGE;
    size_t total = SEC_REC_OVERHEAD + len;
    if (cap < total) return SEC_ERR_CAPACITY;
    if (ep->tx_seq >= ep->max_records) return SEC_ERR_EXHAUSTED; /* GUARD:max-records */
    uint64_t epoch = ep->tx_seq / ep->rekey_interval;
    while (ep->tx_epoch < epoch) { /* one step per epoch; old key wiped */
        uint8_t next[32];
        expand_label(next, ep->tx_key, "rekey", NULL, 0);
        memcpy(ep->tx_key, next, 32); /* GUARD:rekey-tx */
        aienos_wipe(next, sizeof next);
        ep->tx_epoch++;
        ep->c.rekeys_tx++;
    }
    uint8_t dir = ep->role;
    memcpy(out, SEC_MAGIC, 4);
    out[4] = SEC_VERSION;
    out[5] = SEC_TYPE_RECORD;
    out[6] = dir;
    out[7] = 0;
    memcpy(out + 8, ep->session_id, 8);
    wr64(out + 16, ep->tx_seq);
    uint8_t nonce[12] = {dir, 0, 0, 0};
    wr64(nonce + 4, ep->tx_seq);
    out[SEC_REC_HEADER_LEN] = inner;
    if (len) memmove(out + SEC_REC_HEADER_LEN + 1, msg, len);
    if (aienos_gcmsiv_seal(ep->tx_key, nonce, out, SEC_REC_HEADER_LEN, out + SEC_REC_HEADER_LEN,
                           1 + len, out + SEC_REC_HEADER_LEN, 1 + len + SEC_TAG_LEN) != AIENOS_CRYPTO_OK)
        return SEC_ERR_ARG;
    ep->tx_seq++;
    ep->c.tx_records++;
    *written = total;
    return SEC_OK;
}

sec_status sec_seal(sec_endpoint *ep, const uint8_t *msg, size_t len, uint8_t *out, size_t cap,
                    size_t *written)
{
    if (!ep || (!msg && len) || !out || !written) return SEC_ERR_ARG;
    *written = 0;
    if (ep->state == SEC_ST_CLOSED) return SEC_ERR_CLOSED;
    if (ep->state == SEC_ST_DOWN) return SEC_ERR_LINK_DOWN;
    if (ep->state != SEC_ST_ESTABLISHED) return SEC_ERR_STATE;
    return build_record(ep, SEC_INNER_DATA, msg, len, out, cap, written);
}

static sec_status emit_flight(sec_endpoint *ep, uint64_t now, uint8_t *out, size_t cap,
                              size_t *written)
{
    if (cap < ep->flight_len) return SEC_ERR_CAPACITY;
    memcpy(out, ep->flight, ep->flight_len);
    *written = ep->flight_len;
    ep->last_tx = now;
    ep->c.tx_hs++;
    return SEC_OK;
}

sec_status sec_poll_tx(sec_endpoint *ep, uint64_t now, uint8_t *out, size_t cap, size_t *written)
{
    if (!ep || !out || !written) return SEC_ERR_ARG;
    *written = 0;
    if (ep->state == SEC_ST_DOWN) return SEC_ERR_LINK_DOWN;
    if (ep->role == 0 && ep->state == SEC_ST_START) {
        if (cap < SEC_HS1_LEN) return SEC_ERR_CAPACITY;
        hs_header(ep->hs1, SEC_TYPE_HS1);
        memcpy(ep->hs1 + 8, ep->random, 32);
        memcpy(ep->hs1 + 40, ep->eph_pk, 32);
        memcpy(ep->flight, ep->hs1, SEC_HS1_LEN);
        ep->flight_len = SEC_HS1_LEN;
        ep->state = SEC_ST_WAIT_HS2;
        ep->tries = 0;
        return emit_flight(ep, now, out, cap, written);
    }
    if (ep->flight_pending) {
        sec_status s = emit_flight(ep, now, out, cap, written);
        if (s == SEC_OK) ep->flight_pending = 0;
        return s;
    }
    if (ep->confirm_pending && ep->state == SEC_ST_ESTABLISHED) {
        sec_status s = build_record(ep, SEC_INNER_CONFIRM, NULL, 0, out, cap, written);
        if (s == SEC_OK) ep->confirm_pending = 0;
        return s;
    }
    int resend = (ep->role == 0 && ep->state == SEC_ST_WAIT_HS2) ||
                 (ep->role == 0 && ep->state == SEC_ST_ESTABLISHED && !ep->confirmed) ||
                 (ep->state == SEC_ST_CLOSED && ep->close_sent);
    if (resend && now >= ep->last_tx && now - ep->last_tx >= ep->rto) {
        if (ep->tries >= ep->max_retries) {
            if (ep->state == SEC_ST_CLOSED) { ep->close_sent = 0; return SEC_IDLE; }
            go_down(ep);
            return SEC_ERR_LINK_DOWN;
        }
        sec_status s = emit_flight(ep, now, out, cap, written);
        if (s == SEC_OK) { ep->tries++; ep->c.tx_hs_resend++; }
        return s;
    }
    return SEC_IDLE;
}

sec_status sec_close(sec_endpoint *ep, uint64_t now, uint8_t *out, size_t cap, size_t *written)
{
    if (!ep || !out || !written) return SEC_ERR_ARG;
    *written = 0;
    if (ep->state != SEC_ST_ESTABLISHED) return SEC_ERR_STATE;
    size_t n = 0;
    sec_status s = build_record(ep, SEC_INNER_CLOSE, NULL, 0, ep->flight, sizeof ep->flight, &n);
    if (s != SEC_OK) return s;
    if (cap < n) return SEC_ERR_CAPACITY;
    ep->flight_len = (uint16_t)n;
    wipe_secrets(ep); /* GUARD:close-wipe */
    ep->state = SEC_ST_CLOSED;
    ep->close_sent = 1;
    ep->flight_pending = ep->confirm_pending = 0;
    ep->tries = 0;
    return emit_flight(ep, now, out, cap, written);
}

/* ---- handshake receive ---- */

static sec_status on_hs1(sec_endpoint *ep, const uint8_t *m)
{
    if (ep->role != 1) { ep->c.rx_state++; return SEC_ERR_STATE; }
    if (ep->state != SEC_ST_START) {
        if (memcmp(m, ep->hs1, SEC_HS1_LEN) != 0) {
            ep->c.rx_refused++;
            return SEC_ERR_REFUSED; /* GUARD:hs1-dup */
        }
        ep->c.rx_hs_dup++;
        if (ep->state == SEC_ST_WAIT_HS3) ep->flight_pending = 1; /* HS2 was lost */
        return SEC_OK;
    }
    if (derive_prk(ep, m + 40) != 0) { ep->c.rx_weak++; return SEC_ERR_WEAK_KEY; }
    memcpy(ep->hs1, m, SEC_HS1_LEN);
    uint8_t *h2 = ep->hs2, th[32], sm[52], fin_key_r[32];
    hs_header(h2, SEC_TYPE_HS2);
    memcpy(h2 + 8, ep->random, 32);
    memcpy(h2 + 40, ep->eph_pk, 32);
    memcpy(h2 + 72, ep->id_pk, 32);
    transcript(th, ep->hs1, SEC_HS1_LEN, h2, 104, NULL, 0);           /* TH_a */
    expand_label(fin_key_r, ep->prk, "fin r", th, 32);
    expand_label(ep->fin_key_i, ep->prk, "fin i", th, 32);
    sig_msg(sm, SIG_R_LABEL, th);
    aienos_ed25519_sign(h2 + 104, sm, sizeof sm, ep->id_sk);
    transcript(th, ep->hs1, SEC_HS1_LEN, h2, 168, NULL, 0);           /* TH_b */
    aienos_hmac_sha256(fin_key_r, th, 32, h2 + 168);
    aienos_wipe(fin_key_r, sizeof fin_key_r);
    memcpy(ep->flight, h2, SEC_HS2_LEN);
    ep->flight_len = SEC_HS2_LEN;
    ep->flight_pending = 1;
    ep->state = SEC_ST_WAIT_HS3;
    ep->c.rx_hs++;
    return SEC_OK;
}

static sec_status on_hs2(sec_endpoint *ep, const uint8_t *m)
{
    if (ep->role != 0) { ep->c.rx_state++; return SEC_ERR_STATE; }
    if (ep->state == SEC_ST_ESTABLISHED && memcmp(m, ep->hs2, SEC_HS2_LEN) == 0) {
        ep->c.rx_hs_dup++;
        if (!ep->confirmed) ep->flight_pending = 1; /* HS3 was lost */
        return SEC_OK;
    }
    if (ep->state != SEC_ST_WAIT_HS2) { ep->c.rx_refused++; return SEC_ERR_REFUSED; }
    if (memcmp(m + 72, ep->peer_pk, 32) != 0) {
        ep->c.rx_identity++;
        return SEC_ERR_IDENTITY; /* GUARD:hs-identity-r */
    }
    uint8_t th[32], sm[52], fin_key_r[32], fin_key_i[32], fin[32];
    transcript(th, ep->hs1, SEC_HS1_LEN, m, 104, NULL, 0);            /* TH_a */
    sig_msg(sm, SIG_R_LABEL, th);
    if (aienos_ed25519_verify(m + 104, sm, sizeof sm, ep->peer_pk) != AIENOS_SIG_OK) {
        ep->c.rx_bad_sig++;
        return SEC_ERR_BAD_SIG; /* GUARD:hs-sig-r */
    }
    if (derive_prk(ep, m + 40) != 0) { ep->c.rx_weak++; return SEC_ERR_WEAK_KEY; }
    expand_label(fin_key_r, ep->prk, "fin r", th, 32);
    expand_label(fin_key_i, ep->prk, "fin i", th, 32);
    transcript(th, ep->hs1, SEC_HS1_LEN, m, 168, NULL, 0);            /* TH_b */
    aienos_hmac_sha256(fin_key_r, th, 32, fin);
    aienos_wipe(fin_key_r, sizeof fin_key_r);
    if (!aienos_ct_equal(fin, m + 168, 32)) {
        aienos_wipe(fin_key_i, sizeof fin_key_i);
        aienos_wipe(ep->prk, sizeof ep->prk);
        ep->c.rx_bad_tag++;
        return SEC_ERR_BAD_TAG; /* GUARD:hs-fin-r */
    }
    memcpy(ep->hs2, m, SEC_HS2_LEN);
    uint8_t *h3 = ep->hs3;
    hs_header(h3, SEC_TYPE_HS3);
    memcpy(h3 + 8, ep->id_pk, 32);
    transcript(th, ep->hs1, SEC_HS1_LEN, ep->hs2, SEC_HS2_LEN, h3, 40); /* TH_c */
    sig_msg(sm, SIG_I_LABEL, th);
    aienos_ed25519_sign(h3 + 40, sm, sizeof sm, ep->id_sk);
    transcript(th, ep->hs1, SEC_HS1_LEN, ep->hs2, SEC_HS2_LEN, h3, 104); /* TH_d */
    aienos_hmac_sha256(fin_key_i, th, 32, h3 + 104);
    aienos_wipe(fin_key_i, sizeof fin_key_i);
    transcript(th, ep->hs1, SEC_HS1_LEN, ep->hs2, SEC_HS2_LEN, h3, SEC_HS3_LEN); /* TH_f */
    install_keys(ep, th);
    memcpy(ep->flight, h3, SEC_HS3_LEN);
    ep->flight_len = SEC_HS3_LEN;
    ep->flight_pending = 1;
    ep->confirmed = 0;
    ep->tries = 0;
    ep->c.rx_hs++;
    return SEC_OK;
}

static sec_status on_hs3(sec_endpoint *ep, const uint8_t *m)
{
    if (ep->role != 1) { ep->c.rx_state++; return SEC_ERR_STATE; }
    if (ep->state == SEC_ST_ESTABLISHED && memcmp(m, ep->hs3, SEC_HS3_LEN) == 0) {
        ep->c.rx_hs_dup++;
        ep->confirm_pending = 1; /* our CONFIRM was lost */
        return SEC_OK;
    }
    if (ep->state != SEC_ST_WAIT_HS3) { ep->c.rx_refused++; return SEC_ERR_REFUSED; }
    if (memcmp(m + 8, ep->peer_pk, 32) != 0) {
        ep->c.rx_identity++;
        return SEC_ERR_IDENTITY; /* GUARD:hs-identity-i */
    }
    uint8_t th[32], sm[52], fin[32];
    transcript(th, ep->hs1, SEC_HS1_LEN, ep->hs2, SEC_HS2_LEN, m, 40); /* TH_c */
    sig_msg(sm, SIG_I_LABEL, th);
    if (aienos_ed25519_verify(m + 40, sm, sizeof sm, ep->peer_pk) != AIENOS_SIG_OK) {
        ep->c.rx_bad_sig++;
        return SEC_ERR_BAD_SIG; /* GUARD:hs-sig-i */
    }
    transcript(th, ep->hs1, SEC_HS1_LEN, ep->hs2, SEC_HS2_LEN, m, 104); /* TH_d */
    aienos_hmac_sha256(ep->fin_key_i, th, 32, fin);
    if (!aienos_ct_equal(fin, m + 104, 32)) {
        ep->c.rx_bad_tag++;
        return SEC_ERR_BAD_TAG; /* GUARD:hs-fin-i */
    }
    memcpy(ep->hs3, m, SEC_HS3_LEN);
    transcript(th, ep->hs1, SEC_HS1_LEN, ep->hs2, SEC_HS2_LEN, ep->hs3, SEC_HS3_LEN); /* TH_f */
    install_keys(ep, th);
    ep->confirmed = 1;
    ep->confirm_pending = 1;
    ep->c.rx_hs++;
    return SEC_OK;
}

/* ---- record receive ---- */

static sec_status on_record(sec_endpoint *ep, const uint8_t *in, size_t len, uint8_t *msg,
                            size_t cap, size_t *msg_len)
{
    if (len < SEC_REC_OVERHEAD || len > SEC_MAX_DATAGRAM) {
        ep->c.rx_malformed++;
        return SEC_ERR_MALFORMED; /* GUARD:rec-len */
    }
    if (in[6] != (uint8_t)(1 - ep->role) || in[7] != 0) {
        ep->c.rx_malformed++;
        return SEC_ERR_MALFORMED; /* GUARD:rec-dir */
    }
    if (ep->state == SEC_ST_CLOSED) return SEC_ERR_CLOSED;
    if (ep->state != SEC_ST_ESTABLISHED) { ep->c.rx_state++; return SEC_ERR_STATE; }
    if (memcmp(in + 8, ep->session_id, 8) != 0) {
        ep->c.rx_refused++;
        return SEC_ERR_REFUSED; /* GUARD:rec-session */
    }
    uint64_t seq = rd64(in + 16);
    if (seq >= ep->max_records) { ep->c.rx_replay++; return SEC_ERR_EXHAUSTED; }
    /* replay window check, nothing changes yet */
    if (seq < ep->rx_top) {
        uint64_t back = ep->rx_top - seq;
        if (back > SEC_WINDOW) { ep->c.rx_replay++; return SEC_ERR_REPLAY; } /* GUARD:replay-old */
        if ((ep->rx_bitmap >> (back - 1)) & 1) { ep->c.rx_replay++; return SEC_ERR_REPLAY; } /* GUARD:replay-dup */
    }
    size_t ct_len = len - SEC_REC_HEADER_LEN, pt_len = ct_len - SEC_TAG_LEN;
    if (pt_len - 1 > cap) return SEC_ERR_CAPACITY;
    /* key for this record's epoch */
    uint64_t e = seq / ep->rekey_interval;
    uint8_t fwd[32], fwd_prev[32];
    const uint8_t *key;
    int advance = 0;
    if (e == ep->rx_epoch) key = ep->rx_key;
    else if (ep->rx_has_prev && e + 1 == ep->rx_epoch) key = ep->rx_prev_key;
    else if (e > ep->rx_epoch && e - ep->rx_epoch <= SEC_MAX_EPOCH_SKIP) {
        memcpy(fwd, ep->rx_key, 32);
        for (uint64_t k = ep->rx_epoch; k < e; k++) {
            memcpy(fwd_prev, fwd, 32);
            expand_label(fwd, fwd_prev, "rekey", NULL, 0);
        }
        key = fwd;
        advance = 1;
    } else {
        ep->c.rx_replay++;
        return SEC_ERR_REPLAY;
    }
    uint8_t nonce[12] = {in[6], 0, 0, 0};
    memcpy(nonce + 4, in + 16, 8);
    uint8_t pt[SEC_MAX_PAYLOAD + 1];
    int r = aienos_gcmsiv_open(key, nonce, in, SEC_REC_HEADER_LEN, in + SEC_REC_HEADER_LEN, ct_len,
                               pt, pt_len);
    if (r != AIENOS_CRYPTO_OK) {
        if (advance) { aienos_wipe(fwd, 32); aienos_wipe(fwd_prev, 32); }
        aienos_wipe(pt, sizeof pt);
        ep->c.rx_bad_tag++;
        return SEC_ERR_BAD_TAG; /* GUARD:rec-tag */
    }
    /* authenticated: commit window and epoch */
    if (seq >= ep->rx_top) {
        uint64_t shift = seq + 1 - ep->rx_top;
        ep->rx_bitmap = shift >= 64 ? 0 : ep->rx_bitmap << shift;
        ep->rx_bitmap |= 1;
        ep->rx_top = seq + 1;
    } else {
        ep->rx_bitmap |= (uint64_t)1 << (ep->rx_top - 1 - seq);
    }
    if (advance) {
        memcpy(ep->rx_prev_key, fwd_prev, 32); /* GUARD:rekey-rx */
        memcpy(ep->rx_key, fwd, 32);
        aienos_wipe(fwd, 32);
        aienos_wipe(fwd_prev, 32);
        ep->c.rekeys_rx += e - ep->rx_epoch;
        ep->rx_epoch = e;
        ep->rx_has_prev = 1;
    }
    ep->c.rx_records++;
    if (ep->role == 0) ep->confirmed = 1; /* any record from the responder confirms HS3 */
    uint8_t inner = pt[0];
    sec_status out;
    if (inner == SEC_INNER_DATA) {
        if (pt_len > 1) memcpy(msg, pt + 1, pt_len - 1);
        *msg_len = pt_len - 1;
        out = SEC_DATA;
    } else if (inner == SEC_INNER_CLOSE && pt_len == 1) {
        wipe_secrets(ep);
        ep->state = SEC_ST_CLOSED;
        ep->close_sent = 0;
        ep->flight_pending = ep->confirm_pending = 0;
        out = SEC_PEER_CLOSED;
    } else if (inner == SEC_INNER_CONFIRM && pt_len == 1 && ep->role == 0) {
        out = SEC_OK;
    } else {
        ep->c.rx_malformed++;
        out = SEC_ERR_MALFORMED;
    }
    aienos_wipe(pt, sizeof pt);
    return out;
}

sec_status sec_receive(sec_endpoint *ep, uint64_t now, const uint8_t *in, size_t len, uint8_t *msg,
                       size_t cap, size_t *msg_len)
{
    (void)now;
    if (!ep || (!in && len) || !msg_len || (!msg && cap)) return SEC_ERR_ARG;
    *msg_len = 0;
    if (ep->state == SEC_ST_DOWN) return SEC_ERR_LINK_DOWN;
    /* structure first, before any field is trusted */
    if (len < 8 || memcmp(in, SEC_MAGIC, 4) != 0 || in[4] != SEC_VERSION) {
        ep->c.rx_malformed++;
        return SEC_ERR_MALFORMED;
    }
    uint8_t type = in[5];
    if (type == SEC_TYPE_RECORD) return on_record(ep, in, len, msg, cap, msg_len);
    size_t want = type == SEC_TYPE_HS1 ? SEC_HS1_LEN : type == SEC_TYPE_HS2 ? SEC_HS2_LEN
                : type == SEC_TYPE_HS3 ? SEC_HS3_LEN : 0;
    if (want == 0 || len != want || in[6] != 0 || in[7] != 0) {
        ep->c.rx_malformed++;
        return SEC_ERR_MALFORMED; /* GUARD:hs-len */
    }
    if (ep->state == SEC_ST_CLOSED) return SEC_ERR_CLOSED;
    if (type == SEC_TYPE_HS1) return on_hs1(ep, in);
    if (type == SEC_TYPE_HS2) return on_hs2(ep, in);
    return on_hs3(ep, in);
}
