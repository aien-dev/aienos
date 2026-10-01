/* M6-B secure control transport tests (hosted, TEST identities only).
 *
 * Two in-process machines exchange datagrams over the M6-A stack: every
 * datagram is built into a real Ethernet/IPv4/UDP frame with aienos_net,
 * queued on a simulated wire, parsed back and handed to the receiver.
 * Scenarios: handshake, wrong identity, transcript tamper (every byte of
 * every handshake message), splice and impersonation attempts, replay,
 * reordering inside and outside the window, truncation/extension/bit flips,
 * rekey across epochs, close, deterministic loss (drop every Nth datagram)
 * with the M6-A reliable channel carried inside the secure records, and a
 * malformed-input sweep. Prints AIENOS_NET_SECURE_TESTS: PASS or FAIL.
 *
 * Every key here is a public TEST key (sec_test_identity); the "entropy"
 * is a seeded generator, NOT-FOR-PRODUCTION.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aienos_ctl.h"
#include "../aienos_net.h"
#include "../aienos_sec.h"
#include "../x25519.h"
#include "../../argus/sha256.h"
#include "../../crypto/aienos_crypto.h"
#include "../../sig/aienos_sig.h"

static unsigned long checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define EQ(a, b) do { long long _a = (long long)(a), _b = (long long)(b); checks++; if (_a != _b) { failures++; fprintf(stderr, "FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, _a, _b); } } while (0)

static uint64_t prng_s = 0x5ec0de;
static uint8_t rnd8(void)
{
    prng_s ^= prng_s << 13; prng_s ^= prng_s >> 7; prng_s ^= prng_s << 17;
    return (uint8_t)(prng_s >> 24);
}
static void fill(uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) b[i] = rnd8(); }

static int all_zero(const uint8_t *b, size_t n)
{
    uint8_t a = 0;
    for (size_t i = 0; i < n; i++) a |= b[i];
    return a == 0;
}

static int contains(const void *hay, size_t hn, const uint8_t *needle, size_t nn)
{
    const uint8_t *h = hay;
    for (size_t i = 0; i + nn <= hn; i++) if (memcmp(h + i, needle, nn) == 0) return 1;
    return 0;
}

/* ---- identities and endpoints ---- */

static uint8_t SK_A[32], PK_A[32], SK_B[32], PK_B[32], SK_M[32], PK_M[32];

static void cfg_for(sec_config *c, int role, const uint8_t *sk, const uint8_t *peer_pk)
{
    memset(c, 0, sizeof *c);
    c->role = (uint8_t)role;
    memcpy(c->id_sk, sk, 32);
    memcpy(c->peer_pk, peer_pk, 32);
    fill(c->entropy, 64);
    c->rto = 4;
    c->max_retries = 6;
    c->rekey_interval = 1u << 16;
    c->max_records = (uint64_t)1 << 40;
}

static void make_pair(sec_endpoint *a, sec_endpoint *b, uint64_t rekey, uint32_t retries)
{
    sec_config ca, cb;
    cfg_for(&ca, 0, SK_A, PK_B);
    cfg_for(&cb, 1, SK_B, PK_A);
    ca.rekey_interval = cb.rekey_interval = rekey;
    ca.max_retries = cb.max_retries = retries;
    EQ(sec_init(a, &ca), SEC_OK);
    EQ(sec_init(b, &cb), SEC_OK);
}

/* ---- M6-A wire: datagram -> Ethernet/IPv4/UDP frame -> queue -> parse ---- */

#define PORT 7016
#define QMAX 512
#define FRAME_MAX 1600
typedef struct { int to; size_t n; uint8_t f[FRAME_MAX]; } wframe;
typedef struct {
    wframe q[QMAX];
    size_t head, nq;
    uint64_t sent, dropped, drop_every, count[2]; /* drop pattern counted per direction */
    int tamper_type, tamper_pos;   /* flip byte tamper_pos of every datagram of this type */
    int blackout;                  /* drop everything */
} wire;

static const net_mac MAC[2] = {{{0x02, 0, 0, 0, 0, 0xa1}}, {{0x02, 0, 0, 0, 0, 0xb2}}};
static const net_ipv4 IP[2] = {{{10, 6, 0, 1}}, {{10, 6, 0, 2}}};

static void wire_put(wire *w, int from, const uint8_t *d, size_t n)
{
    w->sent++;
    w->count[from]++;
    if (w->blackout || (w->drop_every && w->count[from] % w->drop_every == 0)) { w->dropped++; return; }
    uint8_t dg[SEC_MAX_DATAGRAM];
    if (n > sizeof dg) { CHECK(0); return; }
    memcpy(dg, d, n);
    if (w->tamper_type && n >= 6 && dg[5] == w->tamper_type && (size_t)w->tamper_pos < n)
        dg[w->tamper_pos] ^= 0x01;
    uint8_t udp[FRAME_MAX], ip[FRAME_MAX];
    size_t un = 0, in = 0, fn = 0;
    net_udp_header uh = {PORT, PORT};
    int to = 1 - from;
    CHECK(net_udp_build(&uh, dg, n, IP[from], IP[to], udp, sizeof udp, &un) == NET_OK);
    net_ipv4_header ih = {0, (uint16_t)w->sent, 64, NET_IPPROTO_UDP, IP[from], IP[to]};
    CHECK(net_ipv4_build(&ih, udp, un, ip, sizeof ip, &in) == NET_OK);
    net_eth_frame ef = {MAC[to], MAC[from], NET_ETHERTYPE_IPV4, ip, in};
    if (w->nq >= QMAX) { w->dropped++; return; }
    wframe *x = &w->q[(w->head + w->nq++) % QMAX];
    x->to = to;
    CHECK(net_eth_build(&ef, x->f, sizeof x->f, &fn) == NET_OK);
    x->n = fn;
}

/* Pop the next frame and unwrap it to the secure-transport datagram. */
static int wire_get(wire *w, int *to, const uint8_t **dg, size_t *dn, uint8_t *keep)
{
    if (!w->nq) return 0;
    wframe *x = &w->q[w->head];
    w->head = (w->head + 1) % QMAX;
    w->nq--;
    memcpy(keep, x->f, x->n);
    *to = x->to;
    net_eth_frame ef;
    net_ipv4_header ih;
    net_udp_header uh;
    const uint8_t *ipp, *udpp;
    size_t ipn, udpn;
    if (net_eth_parse(keep, x->n, &ef) != NET_OK || ef.ethertype != NET_ETHERTYPE_IPV4) return -1;
    if (memcmp(ef.destination.b, MAC[x->to].b, 6) != 0) return -1;
    if (net_ipv4_parse(ef.payload, ef.payload_len, &ih, &ipp, &ipn) != NET_OK) return -1;
    if (ih.protocol != NET_IPPROTO_UDP || memcmp(ih.destination.b, IP[x->to].b, 4) != 0) return -1;
    if (net_udp_parse(ipp, ipn, ih.source, ih.destination, &uh, &udpp, &udpn) != NET_OK) return -1;
    if (uh.destination_port != PORT) return -1;
    *dg = udpp;
    *dn = udpn;
    return 1;
}

/* ---- two machines ---- */

#define NMSG 150
typedef struct {
    sec_endpoint s;
    ct_endpoint ct;
    int use_ct;
    uint32_t next_send, next_expect;
    uint64_t delivered, misordered, data_records;
    int last_status, saw_status[32]; /* index -status for errors */
    int peer_closed;
} machine;

typedef struct {
    machine m[2];
    wire w;
    uint64_t now;
} sys_t;

static void ct_msg(int from, uint32_t i, uint8_t *m, size_t *n)
{
    *n = (i * 29u + (unsigned)from * 13u) % 300u + 4u;
    for (size_t k = 0; k < *n; k++) m[k] = (uint8_t)(i * 151u + k * 3u + (unsigned)from);
    m[0] = (uint8_t)(i >> 8); m[1] = (uint8_t)i; m[2] = (uint8_t)from; m[3] = 0x5a;
}

static void note(machine *x, sec_status s)
{
    x->last_status = s;
    if (s < 0 && -s < 32) x->saw_status[-s] = 1;
}

static void sys_init(sys_t *S, uint64_t rekey, uint32_t retries, int use_ct, uint32_t ct_rto)
{
    memset(S, 0, sizeof *S);
    make_pair(&S->m[0].s, &S->m[1].s, rekey, retries);
    for (int i = 0; i < 2; i++) {
        S->m[i].use_ct = use_ct;
        if (use_ct) {
            ct_identity id;
            CHECK(ct_test_identity(&id, "lane16-inner") == CT_OK);
            CHECK(ct_init(&S->m[i].ct, &id, (uint8_t)i, 0x16, ct_rto, 40) == CT_OK);
        }
    }
}

/* One tick: each side emits handshake/control datagrams, then (if
 * established) its M6-A control frames sealed in records; then the wire is
 * drained into the receivers. */
static void sys_tick(sys_t *S)
{
    uint8_t out[FRAME_MAX], frame[CT_MAX_FRAME], msg[SEC_MAX_PAYLOAD];
    size_t n;
    for (int i = 0; i < 2; i++) {
        machine *x = &S->m[i];
        for (int k = 0; k < 8; k++) {
            sec_status s = sec_poll_tx(&x->s, S->now, out, sizeof out, &n);
            if (s != SEC_OK) { if (s != SEC_IDLE) note(x, s); break; }
            wire_put(&S->w, i, out, n);
        }
        if (!x->use_ct || x->s.state != SEC_ST_ESTABLISHED) continue;
        int cap_frames = 16;
        while (x->next_send < NMSG && ct_in_flight(&x->ct) < CT_WINDOW) {
            size_t ml;
            ct_msg(i, x->next_send, msg, &ml);
            if (ct_send(&x->ct, msg, ml) != CT_OK) break;
            x->next_send++;
        }
        for (int k = 0; k < cap_frames; k++) {
            ct_status c = ct_poll_tx(&x->ct, S->now, frame, sizeof frame, &n);
            if (c != CT_OK) break;
            size_t rn;
            sec_status s = sec_seal(&x->s, frame, n, out, sizeof out, &rn);
            if (s != SEC_OK) { note(x, s); break; }
            wire_put(&S->w, i, out, rn);
        }
    }
    uint8_t keep[FRAME_MAX], got[CT_MAX_PAYLOAD], exp[CT_MAX_PAYLOAD];
    size_t budget = S->w.nq;
    while (budget--) {
        int to;
        const uint8_t *dg;
        size_t dn;
        int r = wire_get(&S->w, &to, &dg, &dn, keep);
        if (r <= 0) { CHECK(r == 0); continue; }
        machine *x = &S->m[to];
        size_t ml;
        sec_status s = sec_receive(&x->s, S->now, dg, dn, msg, sizeof msg, &ml);
        note(x, s);
        if (s == SEC_PEER_CLOSED) x->peer_closed = 1;
        if (s != SEC_DATA) continue;
        x->data_records++;
        if (!x->use_ct) continue;
        size_t gl;
        ct_status c = ct_receive(&x->ct, msg, ml, got, sizeof got, &gl);
        if (c == CT_DELIVERED) {
            size_t el;
            ct_msg(1 - to, x->next_expect, exp, &el);
            if (el != gl || memcmp(exp, got, gl) != 0) x->misordered++;
            x->next_expect++;
            x->delivered++;
        }
    }
    S->now++;
}

static int established(const sys_t *S)
{
    return S->m[0].s.state == SEC_ST_ESTABLISHED && S->m[1].s.state == SEC_ST_ESTABLISHED;
}

static void run_handshake(sys_t *S, int ticks)
{
    for (int t = 0; t < ticks && !(established(S) && S->m[0].s.confirmed); t++) sys_tick(S);
}

/* ---- tests ---- */

static void test_hkdf(void)
{
    /* RFC 5869 A.1 (rfc-editor.org/rfc/rfc5869.txt, sha256
     * 7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c).
     * The 13-byte salt zero-padded to 32 bytes is the same HMAC key. */
    static const uint8_t prk_exp[32] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    static const uint8_t okm_exp[32] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf};
    uint8_t ikm[22], salt[32] = {0}, info[10], prk[32], okm[32];
    memset(ikm, 0x0b, sizeof ikm);
    for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
    for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
    sec_hkdf_extract(prk, salt, ikm, sizeof ikm);
    sec_hkdf_expand1(okm, prk, info, sizeof info);
    CHECK(memcmp(prk, prk_exp, 32) == 0);
    CHECK(memcmp(okm, okm_exp, 32) == 0);
}

static void test_handshake_and_data(void)
{
    sys_t S;
    sys_init(&S, 1u << 16, 6, 0, 4);
    run_handshake(&S, 20);
    CHECK(established(&S));
    CHECK(S.m[0].s.confirmed);
    sec_endpoint *a = &S.m[0].s, *b = &S.m[1].s;
    CHECK(memcmp(a->session_id, b->session_id, 8) == 0);
    CHECK(memcmp(a->tx_key, b->rx_key, 32) == 0 && memcmp(b->tx_key, a->rx_key, 32) == 0);
    CHECK(memcmp(a->tx_key, a->rx_key, 32) != 0);
    CHECK(all_zero(a->eph_sk, 32) && all_zero(b->eph_sk, 32) && all_zero(a->prk, 32) &&
          all_zero(b->prk, 32) && all_zero(b->fin_key_i, 32));
    /* data both ways, every payload size 0..SEC_MAX_PAYLOAD step 37, plus the max */
    uint8_t m[SEC_MAX_PAYLOAD], d[SEC_MAX_DATAGRAM], got[SEC_MAX_PAYLOAD];
    size_t n, gl;
    int ok = 1;
    for (size_t len = 0; len <= SEC_MAX_PAYLOAD; len = len == SEC_MAX_PAYLOAD ? len + 1 : (len + 37 > SEC_MAX_PAYLOAD ? SEC_MAX_PAYLOAD : len + 37)) {
        for (int dir = 0; dir < 2; dir++) {
            sec_endpoint *tx = dir ? b : a, *rx = dir ? a : b;
            fill(m, len);
            if (sec_seal(tx, m, len, d, sizeof d, &n) != SEC_OK || n != SEC_REC_OVERHEAD + len) ok = 0;
            if (sec_receive(rx, 0, d, n, got, sizeof got, &gl) != SEC_DATA || gl != len || memcmp(got, m, len)) ok = 0;
        }
    }
    CHECK(ok);
    EQ(sec_seal(a, m, SEC_MAX_PAYLOAD + 1, d, sizeof d, &n), SEC_ERR_TOO_LARGE);
    EQ(sec_seal(a, m, 10, d, SEC_REC_OVERHEAD + 9, &n), SEC_ERR_CAPACITY);
    /* receiver capacity: refused before anything changes, then accepted */
    CHECK(sec_seal(a, m, 100, d, sizeof d, &n) == SEC_OK);
    EQ(sec_receive(b, 0, d, n, got, 99, &gl), SEC_ERR_CAPACITY);
    EQ(sec_receive(b, 0, d, n, got, 100, &gl), SEC_DATA);
    /* the ciphertext differs from the plaintext and between records */
    uint8_t d2[SEC_MAX_DATAGRAM];
    size_t n2;
    memset(m, 0x41, 64);
    CHECK(sec_seal(a, m, 64, d, sizeof d, &n) == SEC_OK && sec_seal(a, m, 64, d2, sizeof d2, &n2) == SEC_OK);
    CHECK(!contains(d, n, m, 16) && memcmp(d + 24, d2 + 24, n - 24) != 0);
    /* reflection: our own record sent back to us */
    EQ(sec_receive(a, 0, d, n, got, sizeof got, &gl), SEC_ERR_MALFORMED);
    /* state machine: messages for the wrong role or stage */
    EQ(sec_receive(a, 0, a->hs1, SEC_HS1_LEN, got, sizeof got, &gl), SEC_ERR_STATE);
    EQ(sec_receive(b, 0, b->hs2, SEC_HS2_LEN, got, sizeof got, &gl), SEC_ERR_STATE);
    EQ(sec_receive(a, 0, a->hs3, SEC_HS3_LEN, got, sizeof got, &gl), SEC_ERR_STATE);
}

/* ct over sec, with a loss pattern. Returns 1 when both sides got all messages. */
static int run_ct(uint64_t drop_every, uint64_t rekey, uint64_t *digest_out)
{
    sys_t S;
    prng_s = 0x10ad + drop_every;
    sys_init(&S, rekey, 40, 1, 3);
    S.w.drop_every = drop_every;
    for (int t = 0; t < 20000 && !(S.m[0].delivered == NMSG && S.m[1].delivered == NMSG); t++) sys_tick(&S);
    int ok = S.m[0].delivered == NMSG && S.m[1].delivered == NMSG && !S.m[0].misordered &&
             !S.m[1].misordered && S.m[0].ct.c.rx_bad_tag == 0 && S.m[1].ct.c.rx_bad_tag == 0;
    if (!ok)
        fprintf(stderr, "loss N=%llu: delivered %llu/%llu misordered %llu/%llu state %d/%d\n",
                (unsigned long long)drop_every, (unsigned long long)S.m[0].delivered,
                (unsigned long long)S.m[1].delivered, (unsigned long long)S.m[0].misordered,
                (unsigned long long)S.m[1].misordered, S.m[0].s.state, S.m[1].s.state);
    if (!ok) for (int i = 0; i < 2; i++) fprintf(stderr, "  m%d ct down %d inflight %u base %u next %u exp %u retx %llu; sec rx %llu replay %llu badtag %llu state %llu malformed %llu; ticks %llu\n", i, S.m[i].ct.link_down, ct_in_flight(&S.m[i].ct), S.m[i].ct.base, S.m[i].ct.next_seq, S.m[i].ct.expected, (unsigned long long)S.m[i].ct.c.tx_retransmits, (unsigned long long)S.m[i].s.c.rx_records, (unsigned long long)S.m[i].s.c.rx_replay, (unsigned long long)S.m[i].s.c.rx_bad_tag, (unsigned long long)S.m[i].s.c.rx_state, (unsigned long long)S.m[i].s.c.rx_malformed, (unsigned long long)S.now);
    /* no record ever failed authentication on an honest (lossy) link */
    CHECK(S.m[0].s.c.rx_bad_tag == 0 && S.m[1].s.c.rx_bad_tag == 0);
    if (digest_out)
        *digest_out = S.now * 1000003u + S.w.sent * 31u + S.w.dropped + S.m[0].s.c.tx_records * 7u +
                      S.m[1].s.c.tx_hs_resend * 11u;
    if (drop_every && S.w.dropped == 0) ok = 0; /* loss really happened */
    return ok;
}

static void test_loss(void)
{
    static const uint64_t N[] = {0, 2, 3, 4, 5, 7, 11, 16};
    for (size_t i = 0; i < sizeof N / sizeof N[0]; i++) {
        uint64_t d1 = 0, d2 = 0;
        CHECK(run_ct(N[i], 1u << 16, &d1));
        CHECK(run_ct(N[i], 1u << 16, &d2));
        EQ(d1, d2); /* deterministic: bit-identical rerun */
    }
    /* loss plus frequent rekeys: records cross many epochs and get reordered by resends */
    CHECK(run_ct(3, SEC_MIN_REKEY_INTERVAL, NULL));
    CHECK(run_ct(5, SEC_MIN_REKEY_INTERVAL, NULL));
    /* total blackout: the initiator gives up after max_retries */
    sys_t S;
    sys_init(&S, 1u << 16, 3, 0, 4);
    S.w.blackout = 1;
    for (int t = 0; t < 200; t++) sys_tick(&S);
    EQ(S.m[0].s.state, SEC_ST_DOWN);
    CHECK(S.m[0].saw_status[-SEC_ERR_LINK_DOWN]);
    CHECK(all_zero(S.m[0].s.id_sk, 32));
    EQ(S.m[0].s.c.tx_hs, 1 + 3);
    /* HS3 lost forever (responder never established): initiator goes down */
    sys_init(&S, 1u << 16, 3, 0, 4);
    S.w.tamper_type = SEC_TYPE_HS3;
    S.w.tamper_pos = 0; /* bad magic: always malformed */
    for (int t = 0; t < 200; t++) sys_tick(&S);
    EQ(S.m[0].s.state, SEC_ST_DOWN);
    EQ(S.m[1].s.state, SEC_ST_WAIT_HS3);
}

static void test_wrong_identity(void)
{
    sys_t S;
    /* initiator expects B, responder is Mallory with a valid key of its own */
    memset(&S, 0, sizeof S);
    sec_config ca, cb;
    cfg_for(&ca, 0, SK_A, PK_B);
    cfg_for(&cb, 1, SK_M, PK_A);
    ca.max_retries = cb.max_retries = 3;
    CHECK(sec_init(&S.m[0].s, &ca) == SEC_OK && sec_init(&S.m[1].s, &cb) == SEC_OK);
    for (int t = 0; t < 200; t++) sys_tick(&S);
    CHECK(S.m[0].saw_status[-SEC_ERR_IDENTITY]);
    CHECK(S.m[0].s.c.rx_identity >= 1);
    EQ(S.m[0].s.state, SEC_ST_DOWN);
    CHECK(all_zero(S.m[0].s.tx_key, 32));
    /* responder expects A, initiator is Mallory */
    memset(&S, 0, sizeof S);
    cfg_for(&ca, 0, SK_M, PK_B);
    cfg_for(&cb, 1, SK_B, PK_A);
    ca.max_retries = cb.max_retries = 3;
    CHECK(sec_init(&S.m[0].s, &ca) == SEC_OK && sec_init(&S.m[1].s, &cb) == SEC_OK);
    for (int t = 0; t < 200; t++) sys_tick(&S);
    CHECK(S.m[1].saw_status[-SEC_ERR_IDENTITY]);
    CHECK(S.m[1].s.state != SEC_ST_ESTABLISHED);
    EQ(S.m[0].s.state, SEC_ST_DOWN); /* never confirmed */
    /* records Mallory sends are refused: B has no keys */
    CHECK(S.m[1].s.c.rx_records == 0);
}

/* Impersonation: Mallory claims the expected identity but can only sign
 * with her own key; she knows every ephemeral secret she uses, so the
 * finished MAC is valid and only the signature check can refuse. */
static void test_impersonation(void)
{
    sys_t S;
    sec_config ca, cb;
    /* Mallory as responder claiming to be B */
    memset(&S, 0, sizeof S);
    cfg_for(&ca, 0, SK_A, PK_B);
    cfg_for(&cb, 1, SK_M, PK_A);
    ca.max_retries = cb.max_retries = 3;
    CHECK(sec_init(&S.m[0].s, &ca) == SEC_OK && sec_init(&S.m[1].s, &cb) == SEC_OK);
    memcpy(S.m[1].s.id_pk, PK_B, 32);
    for (int t = 0; t < 200; t++) sys_tick(&S);
    CHECK(S.m[0].saw_status[-SEC_ERR_BAD_SIG]);
    CHECK(S.m[0].s.state != SEC_ST_ESTABLISHED);
    /* Mallory as initiator claiming to be A */
    memset(&S, 0, sizeof S);
    cfg_for(&ca, 0, SK_M, PK_B);
    cfg_for(&cb, 1, SK_B, PK_A);
    ca.max_retries = cb.max_retries = 3;
    CHECK(sec_init(&S.m[0].s, &ca) == SEC_OK && sec_init(&S.m[1].s, &cb) == SEC_OK);
    memcpy(S.m[0].s.id_pk, PK_A, 32);
    for (int t = 0; t < 200; t++) sys_tick(&S);
    CHECK(S.m[1].saw_status[-SEC_ERR_BAD_SIG]);
    CHECK(S.m[1].s.state != SEC_ST_ESTABLISHED);
}

/* Flip one byte of every copy of one handshake message type in transit. */
static void test_transcript_tamper(void)
{
    static const struct { int type; size_t len; } T[] = {
        {SEC_TYPE_HS1, SEC_HS1_LEN}, {SEC_TYPE_HS2, SEC_HS2_LEN}, {SEC_TYPE_HS3, SEC_HS3_LEN}};
    unsigned long refused = 0, positions = 0, split = 0, est = 0;
    for (size_t t = 0; t < 3; t++) {
        for (size_t pos = 0; pos < T[t].len; pos++) {
            if (pos == 5) continue; /* the type byte itself: the message becomes another type */
            sys_t S;
            sys_init(&S, 1u << 16, 2, 0, 3);
            S.w.tamper_type = T[t].type;
            S.w.tamper_pos = (int)pos;
            for (int k = 0; k < 60; k++) sys_tick(&S);
            positions++;
            (void)0; /* an HS1 random byte is only caught by the initiator (signature) */
            int saw = 0;
            for (int e = 1; e < 32; e++) saw |= S.m[0].saw_status[e] | S.m[1].saw_status[e];
            if (saw) refused++;
            if (S.m[1].s.state == SEC_ST_ESTABLISHED) est++;
            if (established(&S) && memcmp(S.m[0].s.tx_key, S.m[1].s.rx_key, 32) != 0) split++;
            if (S.m[0].s.state == SEC_ST_ESTABLISHED && S.m[0].s.confirmed) est++;
        }
    }
    EQ(refused, positions); /* every tampered message was refused by a machine */
    EQ(est, 0);             /* and no handshake completed */
    EQ(split, 0);
    /* the type byte: HS1 relabelled as HS2/HS3 etc. is refused too */
    for (size_t t = 0; t < 3; t++) {
        sys_t S;
        sys_init(&S, 1u << 16, 2, 0, 3);
        S.w.tamper_type = T[t].type;
        S.w.tamper_pos = 5;
        for (int k = 0; k < 60; k++) sys_tick(&S);
        CHECK(!(S.m[1].s.state == SEC_ST_ESTABLISHED) && !(S.m[0].s.confirmed));
    }
}

static void test_splice(void)
{
    /* two concurrent handshakes between the same two identities */
    sec_endpoint a1, b1, a2, b2;
    uint8_t h1a[SEC_HS1_LEN], h1b[SEC_HS1_LEN], h2a[SEC_HS2_LEN], h2b[SEC_HS2_LEN], h3a[SEC_HS3_LEN], h3b[SEC_HS3_LEN];
    uint8_t msg[64];
    size_t n, ml;
    make_pair(&a1, &b1, 1u << 16, 3);
    make_pair(&a2, &b2, 1u << 16, 3);
    CHECK(sec_poll_tx(&a1, 0, h1a, sizeof h1a, &n) == SEC_OK && n == SEC_HS1_LEN);
    CHECK(sec_poll_tx(&a2, 0, h1b, sizeof h1b, &n) == SEC_OK);
    EQ(sec_receive(&b1, 0, h1a, SEC_HS1_LEN, msg, sizeof msg, &ml), SEC_OK);
    EQ(sec_receive(&b2, 0, h1b, SEC_HS1_LEN, msg, sizeof msg, &ml), SEC_OK);
    CHECK(sec_poll_tx(&b1, 0, h2a, sizeof h2a, &n) == SEC_OK && n == SEC_HS2_LEN);
    CHECK(sec_poll_tx(&b2, 0, h2b, sizeof h2b, &n) == SEC_OK);
    /* session 2's HS2 spliced into session 1 */
    EQ(sec_receive(&a1, 0, h2b, SEC_HS2_LEN, msg, sizeof msg, &ml), SEC_ERR_BAD_SIG);
    /* a mixed HS2: session 1's signature with session 2's ephemeral */
    uint8_t mix[SEC_HS2_LEN];
    memcpy(mix, h2a, SEC_HS2_LEN);
    memcpy(mix + 40, h2b + 40, 32);
    EQ(sec_receive(&a1, 0, mix, SEC_HS2_LEN, msg, sizeof msg, &ml), SEC_ERR_BAD_SIG);
    EQ(a1.state, SEC_ST_WAIT_HS2); /* refusals change nothing */
    EQ(sec_receive(&a1, 0, h2a, SEC_HS2_LEN, msg, sizeof msg, &ml), SEC_OK);
    EQ(sec_receive(&a2, 0, h2b, SEC_HS2_LEN, msg, sizeof msg, &ml), SEC_OK);
    CHECK(sec_poll_tx(&a1, 0, h3a, sizeof h3a, &n) == SEC_OK && n == SEC_HS3_LEN);
    CHECK(sec_poll_tx(&a2, 0, h3b, sizeof h3b, &n) == SEC_OK);
    /* session 2's HS3 spliced into session 1 */
    EQ(sec_receive(&b1, 0, h3b, SEC_HS3_LEN, msg, sizeof msg, &ml), SEC_ERR_BAD_SIG);
    /* a different HS1 to a responder already in a handshake */
    EQ(sec_receive(&b1, 0, h1b, SEC_HS1_LEN, msg, sizeof msg, &ml), SEC_ERR_REFUSED);
    /* the exact HS1 again: answered with the stored HS2 */
    EQ(sec_receive(&b1, 0, h1a, SEC_HS1_LEN, msg, sizeof msg, &ml), SEC_OK);
    uint8_t again[SEC_HS2_LEN];
    CHECK(sec_poll_tx(&b1, 1, again, sizeof again, &n) == SEC_OK && n == SEC_HS2_LEN &&
          memcmp(again, h2a, SEC_HS2_LEN) == 0);
    EQ(sec_receive(&b1, 0, h3a, SEC_HS3_LEN, msg, sizeof msg, &ml), SEC_OK);
    EQ(sec_receive(&b2, 0, h3b, SEC_HS3_LEN, msg, sizeof msg, &ml), SEC_OK);
    CHECK(b1.state == SEC_ST_ESTABLISHED && b2.state == SEC_ST_ESTABLISHED);
    CHECK(memcmp(a1.session_id, b1.session_id, 8) == 0 && memcmp(a1.session_id, a2.session_id, 8) != 0);
    /* a record of session 2 delivered into session 1 */
    uint8_t rec[SEC_MAX_DATAGRAM], got[SEC_MAX_PAYLOAD];
    CHECK(sec_seal(&a2, (const uint8_t *)"x", 1, rec, sizeof rec, &n) == SEC_OK);
    EQ(sec_receive(&b1, 0, rec, n, got, sizeof got, &ml), SEC_ERR_REFUSED);
    /* session 2's record with session 1's id patched in: header is authenticated */
    memcpy(rec + 8, a1.session_id, 8);
    EQ(sec_receive(&b1, 0, rec, n, got, sizeof got, &ml), SEC_ERR_BAD_TAG);
    /* an old HS2 replayed to a fresh initiator */
    sec_endpoint a3, b3;
    make_pair(&a3, &b3, 1u << 16, 3);
    CHECK(sec_poll_tx(&a3, 0, h1b, sizeof h1b, &n) == SEC_OK);
    EQ(sec_receive(&a3, 0, h2a, SEC_HS2_LEN, msg, sizeof msg, &ml), SEC_ERR_BAD_SIG);
    /* a duplicate HS3 after establishment gets a fresh CONFIRM; a different one is refused */
    EQ(sec_receive(&b1, 0, h3a, SEC_HS3_LEN, msg, sizeof msg, &ml), SEC_OK);
    CHECK(sec_poll_tx(&b1, 2, rec, sizeof rec, &n) == SEC_OK && n == SEC_REC_OVERHEAD);
    EQ(sec_receive(&b1, 0, h3b, SEC_HS3_LEN, msg, sizeof msg, &ml), SEC_ERR_REFUSED);
}

/* Build an HS2 from a chosen ephemeral share, signed with B's TEST key the
 * way an honest-but-malicious responder would. */
static void forge_hs2(uint8_t h2[SEC_HS2_LEN], const uint8_t hs1[SEC_HS1_LEN], const uint8_t eph[32])
{
    memset(h2, 0, SEC_HS2_LEN);
    memcpy(h2, "ASC1", 4);
    h2[4] = 1; h2[5] = SEC_TYPE_HS2;
    fill(h2 + 8, 32);
    memcpy(h2 + 40, eph, 32);
    memcpy(h2 + 72, PK_B, 32);
    sha256_ctx c;
    uint8_t th[32], sm[52];
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)"AIENOS-M6B-v1 transcript", 24);
    sha256_update(&c, hs1, SEC_HS1_LEN);
    sha256_update(&c, h2, 104);
    sha256_final(&c, th);
    memcpy(sm, "AIENOS-M6B-v1 sig r", 20);
    memcpy(sm + 20, th, 32);
    aienos_ed25519_sign(h2 + 104, sm, sizeof sm, SK_B);
}

static void test_weak_keys(void)
{
    static const uint8_t ZERO[32] = {0};
    static const uint8_t ONE[32] = {1};
    sec_endpoint a, b;
    uint8_t h1[SEC_HS1_LEN], h2[SEC_HS2_LEN], msg[8];
    size_t n, ml;
    /* small-order initiator share */
    make_pair(&a, &b, 1u << 16, 3);
    CHECK(sec_poll_tx(&a, 0, h1, sizeof h1, &n) == SEC_OK);
    memcpy(h1 + 40, ONE, 32);
    EQ(sec_receive(&b, 0, h1, SEC_HS1_LEN, msg, sizeof msg, &ml), SEC_ERR_WEAK_KEY);
    EQ(b.state, SEC_ST_START);
    /* small-order responder share with a valid signature (forged by B's own key) */
    make_pair(&a, &b, 1u << 16, 3);
    CHECK(sec_poll_tx(&a, 0, h1, sizeof h1, &n) == SEC_OK);
    forge_hs2(h2, h1, ZERO);
    EQ(sec_receive(&a, 0, h2, SEC_HS2_LEN, msg, sizeof msg, &ml), SEC_ERR_WEAK_KEY);
    EQ(a.state, SEC_ST_WAIT_HS2);
    /* control: same forging path with an honest share reaches the MAC check */
    uint8_t s[32], p[32];
    fill(s, 32);
    aienos_x25519_base(p, s);
    forge_hs2(h2, h1, p);
    EQ(sec_receive(&a, 0, h2, SEC_HS2_LEN, msg, sizeof msg, &ml), SEC_ERR_BAD_TAG);
}

/* Two established endpoints, direct (no wire). */
static void pair_up(sec_endpoint *a, sec_endpoint *b, uint64_t rekey, uint64_t max_records)
{
    sec_config ca, cb;
    cfg_for(&ca, 0, SK_A, PK_B);
    cfg_for(&cb, 1, SK_B, PK_A);
    ca.rekey_interval = cb.rekey_interval = rekey;
    ca.max_records = cb.max_records = max_records;
    CHECK(sec_init(a, &ca) == SEC_OK && sec_init(b, &cb) == SEC_OK);
    uint8_t d[SEC_MAX_DATAGRAM], msg[SEC_MAX_PAYLOAD];
    size_t n, ml;
    CHECK(sec_poll_tx(a, 0, d, sizeof d, &n) == SEC_OK);
    CHECK(sec_receive(b, 0, d, n, msg, sizeof msg, &ml) == SEC_OK);
    CHECK(sec_poll_tx(b, 0, d, sizeof d, &n) == SEC_OK);
    CHECK(sec_receive(a, 0, d, n, msg, sizeof msg, &ml) == SEC_OK);
    CHECK(sec_poll_tx(a, 0, d, sizeof d, &n) == SEC_OK);
    CHECK(sec_receive(b, 0, d, n, msg, sizeof msg, &ml) == SEC_OK);
    CHECK(sec_poll_tx(b, 0, d, sizeof d, &n) == SEC_OK); /* CONFIRM */
    CHECK(sec_receive(a, 0, d, n, msg, sizeof msg, &ml) == SEC_OK);
    CHECK(a->state == SEC_ST_ESTABLISHED && a->confirmed && b->state == SEC_ST_ESTABLISHED);
}

#define RMAX 200
static uint8_t recs[RMAX][SEC_MAX_DATAGRAM];
static size_t rlen[RMAX];

static void seal_n(sec_endpoint *tx, int count)
{
    for (int i = 0; i < count; i++) {
        uint8_t m[8];
        for (int k = 0; k < 8; k++) m[k] = (uint8_t)(i + k);
        CHECK(sec_seal(tx, m, sizeof m, recs[i], sizeof recs[i], &rlen[i]) == SEC_OK);
    }
}

static int deliver(sec_endpoint *rx, int i)
{
    uint8_t got[SEC_MAX_PAYLOAD];
    size_t gl;
    return sec_receive(rx, 0, recs[i], rlen[i], got, sizeof got, &gl);
}

static void test_replay_reorder(void)
{
    sec_endpoint a, b;
    pair_up(&a, &b, 1u << 16, (uint64_t)1 << 40);
    /* a has sent no records yet: seq 0..199 */
    seal_n(&a, 200);
    /* in order 0..9, then duplicates */
    for (int i = 0; i < 10; i++) EQ(deliver(&b, i), SEC_DATA);
    for (int i = 0; i < 10; i++) EQ(deliver(&b, i), SEC_ERR_REPLAY);
    /* 74 first, then 73..11 in reverse (inside the window); 10 is outside */
    EQ(deliver(&b, 74), SEC_DATA);
    for (int i = 73; i >= 11; i--) EQ(deliver(&b, i), SEC_DATA);
    EQ(deliver(&b, 10), SEC_ERR_REPLAY);  /* 75 - 10 = 65 > 64: too old */
    EQ(deliver(&b, 74), SEC_ERR_REPLAY);
    EQ(deliver(&b, 11), SEC_ERR_REPLAY);  /* exactly at the window edge, already seen */
    /* jump ahead, then a record just inside and just outside the window */
    EQ(deliver(&b, 199), SEC_DATA);       /* top = 200 */
    EQ(deliver(&b, 136), SEC_DATA);       /* 200 - 136 = 64: inside, never seen */
    EQ(deliver(&b, 135), SEC_ERR_REPLAY); /* 65 back: outside */
    EQ(deliver(&b, 134), SEC_ERR_REPLAY); /* 66 back, never seen; the bit a wrapped shift would hit (198) is unset */
    EQ(deliver(&b, 70), SEC_ERR_REPLAY);  /* 130 back */
    EQ(deliver(&b, 136), SEC_ERR_REPLAY);
    /* shuffled order inside the window: every record accepted exactly once */
    sec_endpoint c, d;
    pair_up(&c, &d, 1u << 16, (uint64_t)1 << 40);
    seal_n(&c, 64);
    int order[64];
    for (int i = 0; i < 64; i++) order[i] = i;
    for (int i = 63; i > 0; i--) { int j = rnd8() % (i + 1); int t = order[i]; order[i] = order[j]; order[j] = t; }
    int ok = 1;
    for (int i = 0; i < 64; i++) ok &= deliver(&d, order[i]) == SEC_DATA;
    for (int i = 0; i < 64; i++) ok &= deliver(&d, i) == SEC_ERR_REPLAY;
    CHECK(ok);
    EQ(d.c.rx_records, 64);
}

static void test_mutilation(void)
{
    sec_endpoint a, b;
    pair_up(&a, &b, 1u << 16, (uint64_t)1 << 40);
    seal_n(&a, 2);
    uint8_t buf[SEC_MAX_DATAGRAM + 64], got[SEC_MAX_PAYLOAD];
    size_t gl, n = rlen[0];
    unsigned long bad = 0, tries = 0, data = 0;
    /* every truncation */
    for (size_t l = 0; l < n; l++) {
        memcpy(buf, recs[0], l);
        int s = sec_receive(&b, 0, buf, l, got, sizeof got, &gl);
        tries++; bad += s < 0; data += s == SEC_DATA;
        if (l >= 8 && l < SEC_REC_OVERHEAD) EQ(s, SEC_ERR_MALFORMED);
    }
    /* extensions by 1..64 bytes */
    for (size_t e = 1; e <= 64; e++) {
        memcpy(buf, recs[0], n);
        fill(buf + n, e);
        int s = sec_receive(&b, 0, buf, n + e, got, sizeof got, &gl);
        tries++; bad += s < 0; data += s == SEC_DATA;
    }
    /* every single-bit flip */
    for (size_t bit = 0; bit < n * 8; bit++) {
        memcpy(buf, recs[0], n);
        buf[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        int s = sec_receive(&b, 0, buf, n, got, sizeof got, &gl);
        tries++; bad += s < 0; data += s == SEC_DATA;
        if (bit / 8 < 8) EQ(s, SEC_ERR_MALFORMED);
        if (bit / 8 >= SEC_REC_HEADER_LEN) EQ(s, SEC_ERR_BAD_TAG);
        if (bit / 8 >= 8 && bit / 8 < 16) EQ(s, SEC_ERR_REFUSED);
    }
    EQ(bad, tries);
    EQ(data, 0);
    /* an oversize datagram is refused on length alone */
    memset(buf, 0, sizeof buf);
    memcpy(buf, recs[0], 24);
    EQ(sec_receive(&b, 0, buf, SEC_MAX_DATAGRAM + 1, got, sizeof got, &gl), SEC_ERR_MALFORMED);
    /* nothing above changed the receiver: the genuine records are still accepted once */
    EQ(deliver(&b, 0), SEC_DATA);
    EQ(deliver(&b, 1), SEC_DATA);
    EQ(deliver(&b, 0), SEC_ERR_REPLAY);
    /* handshake messages: every truncation and extension is malformed */
    sec_endpoint x, y;
    make_pair(&x, &y, 1u << 16, 3);
    uint8_t h1[SEC_HS1_LEN + 8] = {0};
    size_t hn;
    CHECK(sec_poll_tx(&x, 0, h1, sizeof h1, &hn) == SEC_OK);
    int ok = 1;
    for (size_t l = 0; l < SEC_HS1_LEN + 8; l++) {
        if (l == SEC_HS1_LEN) continue;
        ok &= sec_receive(&y, 0, h1, l, got, sizeof got, &gl) == SEC_ERR_MALFORMED;
    }
    CHECK(ok);
    EQ(y.state, SEC_ST_START);
    /* non-zero reserved bytes */
    h1[6] = 1;
    EQ(sec_receive(&y, 0, h1, SEC_HS1_LEN, got, sizeof got, &gl), SEC_ERR_MALFORMED);
    /* records before the handshake: state error, never data */
    EQ(sec_receive(&y, 0, recs[0], rlen[0], got, sizeof got, &gl), SEC_ERR_STATE);
}

static void test_rekey(void)
{
    const uint64_t R = SEC_MIN_REKEY_INTERVAL;
    sec_endpoint a, b;
    pair_up(&a, &b, R, (uint64_t)1 << 40);
    uint8_t key0_tx[32];
    memcpy(key0_tx, a.tx_key, 32);
    sec_endpoint snap = a; /* epoch-0 sender snapshot */
    uint8_t m[16], d[SEC_MAX_DATAGRAM], got[SEC_MAX_PAYLOAD];
    size_t n, gl;
    int ok = 1;
    /* 10 epochs and a bit; hold back the last two records of each epoch and
     * deliver them after the first two of the next one (reorder across the
     * boundary, needs the previous epoch's key) */
    uint8_t held[2][SEC_MAX_DATAGRAM];
    size_t heldn[2] = {0, 0};
    uint64_t total = 10 * R + 5;
    for (uint64_t i = 0; i < total; i++) {
        for (int k = 0; k < 16; k++) m[k] = (uint8_t)(i * 7 + k);
        if (sec_seal(&a, m, sizeof m, d, sizeof d, &n) != SEC_OK) { ok = 0; break; }
        uint64_t pos = i % R;
        if (pos >= R - 2) { memcpy(held[pos - (R - 2)], d, n); heldn[pos - (R - 2)] = n; continue; }
        int s = sec_receive(&b, 0, d, n, got, sizeof got, &gl);
        ok &= s == SEC_DATA && gl == 16 && memcmp(got, m, 16) == 0;
        if (pos == 1 && i > R) {
            for (int h = 0; h < 2; h++)
                ok &= sec_receive(&b, 0, held[h], heldn[h], got, sizeof got, &gl) == SEC_DATA;
        }
    }
    CHECK(ok);
    EQ(a.tx_epoch, 10);
    EQ(a.c.rekeys_tx, 10);
    EQ(b.rx_epoch, 10);
    EQ(b.c.rekeys_rx, 10);
    EQ(b.c.rx_records, total); /* every held pair delivered after the next epoch began */
    CHECK(memcmp(a.tx_key, b.rx_key, 32) == 0);
    /* forward secrecy of old epochs: the epoch-0 key is gone from both sides */
    CHECK(!contains(&a, sizeof a, key0_tx, 32));
    CHECK(!contains(&b, sizeof b, key0_tx, 32));
    /* the ratchet is what the spec says: key[e+1] = Expand(key[e], "rekey") */
    uint8_t k[32];
    memcpy(k, key0_tx, 32);
    for (int e = 0; e < 10; e++) sec_hkdf_expand1(k, k, (const uint8_t *)"rekey", 5);
    CHECK(memcmp(k, a.tx_key, 32) == 0);
    /* a record for the current epoch sealed with an old key is refused */
    snap.tx_seq = 10 * R + 50;
    snap.tx_epoch = 10 * R; /* stop the snapshot from ratcheting: it keeps key 0 */
    CHECK(sec_seal(&snap, m, sizeof m, d, sizeof d, &n) == SEC_OK);
    EQ(sec_receive(&b, 0, d, n, got, sizeof got, &gl), SEC_ERR_BAD_TAG);
    /* jumping ahead up to SEC_MAX_EPOCH_SKIP epochs is accepted, further is refused */
    sec_endpoint ahead = a;
    ahead.tx_seq = (10 + SEC_MAX_EPOCH_SKIP + 1) * R;
    CHECK(sec_seal(&ahead, m, sizeof m, d, sizeof d, &n) == SEC_OK);
    EQ(sec_receive(&b, 0, d, n, got, sizeof got, &gl), SEC_ERR_REPLAY);
    ahead = a;
    ahead.tx_seq = (10 + SEC_MAX_EPOCH_SKIP) * R + 3;
    CHECK(sec_seal(&ahead, m, sizeof m, d, sizeof d, &n) == SEC_OK);
    EQ(sec_receive(&b, 0, d, n, got, sizeof got, &gl), SEC_DATA);
    EQ(b.rx_epoch, 10 + SEC_MAX_EPOCH_SKIP);
    /* max_records: the sender stops, the receiver refuses beyond it */
    sec_endpoint c, e;
    pair_up(&c, &e, R, 5);
    ok = 1;
    for (int i = 0; i < 4; i++) ok &= sec_seal(&c, m, 4, d, sizeof d, &n) == SEC_OK; /* CONFIRM used seq 0 of e's side only */
    CHECK(ok);
    CHECK(sec_seal(&c, m, 4, d, sizeof d, &n) == SEC_OK);
    EQ(sec_seal(&c, m, 4, d, sizeof d, &n), SEC_ERR_EXHAUSTED);
    sec_endpoint over = c;
    over.max_records = 100;
    CHECK(sec_seal(&over, m, 4, d, sizeof d, &n) == SEC_OK);
    EQ(sec_receive(&e, 0, d, n, got, sizeof got, &gl), SEC_ERR_EXHAUSTED);
    /* config limits */
    sec_config bad;
    cfg_for(&bad, 0, SK_A, PK_B);
    bad.rekey_interval = SEC_MIN_REKEY_INTERVAL - 1;
    EQ(sec_init(&c, &bad), SEC_ERR_ARG);
}

static void test_close(void)
{
    sec_endpoint a, b;
    pair_up(&a, &b, 1u << 16, (uint64_t)1 << 40);
    uint8_t d[SEC_MAX_DATAGRAM], d2[SEC_MAX_DATAGRAM], got[SEC_MAX_PAYLOAD];
    size_t n, n2, gl;
    seal_n(&a, 1);
    /* too small an output buffer: refused before anything changes (Gemini review finding) */
    uint64_t seq0 = a.tx_seq;
    EQ(sec_close(&a, 10, d, SEC_REC_OVERHEAD - 1, &n), SEC_ERR_CAPACITY);
    CHECK(a.tx_seq == seq0 && a.state == SEC_ST_ESTABLISHED && !all_zero(a.tx_key, 32));
    {   /* unconfirmed initiator: its stored HS3 resend must survive a refused close */
        sec_endpoint u, v;
        uint8_t h[SEC_MAX_DATAGRAM], h3[SEC_HS3_LEN];
        size_t hn, ml;
        make_pair(&u, &v, 1u << 16, 3);
        CHECK(sec_poll_tx(&u, 0, h, sizeof h, &hn) == SEC_OK);
        CHECK(sec_receive(&v, 0, h, hn, got, sizeof got, &ml) == SEC_OK);
        CHECK(sec_poll_tx(&v, 0, h, sizeof h, &hn) == SEC_OK);
        CHECK(sec_receive(&u, 0, h, hn, got, sizeof got, &ml) == SEC_OK);
        memcpy(h3, u.hs3, SEC_HS3_LEN);
        EQ(sec_close(&u, 0, h, 20, &hn), SEC_ERR_CAPACITY);
        CHECK(sec_poll_tx(&u, 0, h, sizeof h, &hn) == SEC_OK && hn == SEC_HS3_LEN && memcmp(h, h3, SEC_HS3_LEN) == 0);
        EQ(u.tx_seq, 0);
    }
    CHECK(sec_close(&a, 10, d, sizeof d, &n) == SEC_OK && n == SEC_REC_OVERHEAD);
    EQ(a.state, SEC_ST_CLOSED);
    CHECK(all_zero(a.tx_key, 32) && all_zero(a.rx_key, 32) && all_zero(a.rx_prev_key, 32));
    EQ(sec_seal(&a, got, 1, d2, sizeof d2, &n2), SEC_ERR_CLOSED);
    /* the close datagram is resent max_retries times, then never again */
    int resends = 0;
    for (uint64_t t = 11; t < 200; t++) {
        sec_status s = sec_poll_tx(&a, t, d2, sizeof d2, &n2);
        if (s == SEC_OK) { resends++; CHECK(n2 == n && memcmp(d, d2, n) == 0); }
    }
    EQ(resends, 6);
    /* data before close is still delivered; close is authenticated */
    EQ(deliver(&b, 0), SEC_DATA);
    uint8_t forged[SEC_MAX_DATAGRAM];
    memcpy(forged, d, n);
    forged[n - 1] ^= 1;
    EQ(sec_receive(&b, 0, forged, n, got, sizeof got, &gl), SEC_ERR_BAD_TAG);
    EQ(b.state, SEC_ST_ESTABLISHED);
    EQ(sec_receive(&b, 0, d, n, got, sizeof got, &gl), SEC_PEER_CLOSED);
    EQ(b.state, SEC_ST_CLOSED);
    CHECK(all_zero(b.tx_key, 32) && all_zero(b.rx_key, 32));
    EQ(sec_receive(&b, 0, d, n, got, sizeof got, &gl), SEC_ERR_CLOSED);
    EQ(sec_seal(&b, got, 1, d2, sizeof d2, &n2), SEC_ERR_CLOSED);
    EQ(sec_close(&b, 0, d2, sizeof d2, &n2), SEC_ERR_STATE);
}

static void test_fuzz(void)
{
    sec_endpoint a, b, x, y;
    pair_up(&a, &b, SEC_MIN_REKEY_INTERVAL, (uint64_t)1 << 40);
    make_pair(&x, &y, 1u << 16, 3);
    uint8_t buf[SEC_MAX_DATAGRAM + 16], got[SEC_MAX_PAYLOAD];
    size_t gl;
    unsigned long data = 0;
    prng_s = 0xf022;
    for (int i = 0; i < 100000; i++) {
        size_t n = rnd8() % 4 == 0 ? (size_t)(rnd8() % 48) : (size_t)((rnd8() << 3 | rnd8()) % sizeof buf);
        fill(buf, n);
        if (n >= 8 && rnd8() % 2) { memcpy(buf, "ASC1", 4); buf[4] = 1; buf[5] = (uint8_t)(rnd8() % 2 ? 0x10 : rnd8() % 4); }
        if (n >= 16 && buf[5] == 0x10 && rnd8() % 2) { memcpy(buf + 8, b.session_id, 8); buf[6] = 0; buf[7] = 0; }
        data += sec_receive(&b, 0, buf, n, got, sizeof got, &gl) == SEC_DATA;
        data += sec_receive(&y, 0, buf, n, got, sizeof got, &gl) == SEC_DATA;
    }
    EQ(data, 0);
    EQ(y.state, SEC_ST_START);
    EQ(b.c.rx_records, 0);
    /* the endpoints still work */
    seal_n(&a, 1);
    EQ(deliver(&b, 0), SEC_DATA);
}

static void test_args(void)
{
    sec_endpoint a;
    sec_config c;
    uint8_t d[8];
    size_t n;
    cfg_for(&c, 0, SK_A, PK_B);
    EQ(sec_init(NULL, &c), SEC_ERR_ARG);
    c.role = 2;
    EQ(sec_init(&a, &c), SEC_ERR_ARG);
    c.role = 0; c.rto = 0;
    EQ(sec_init(&a, &c), SEC_ERR_ARG);
    c.rto = 1; c.max_records = 0;
    EQ(sec_init(&a, &c), SEC_ERR_ARG);
    c.max_records = 10;
    EQ(sec_init(&a, &c), SEC_OK);
    EQ(sec_poll_tx(&a, 0, d, sizeof d, &n), SEC_ERR_CAPACITY);
    EQ(sec_seal(&a, d, 1, d, sizeof d, &n), SEC_ERR_STATE);
    EQ(sec_close(&a, 0, d, sizeof d, &n), SEC_ERR_STATE);
    EQ(sec_receive(&a, 0, NULL, 4, d, sizeof d, &n), SEC_ERR_ARG);
    uint8_t sk[32], pk[32];
    EQ(sec_test_identity(sk, pk, ""), SEC_ERR_ARG);
    CHECK(strcmp(sec_status_name(SEC_ERR_WEAK_KEY), "WeakKey") == 0);
}

int main(void)
{
    CHECK(sec_test_identity(SK_A, PK_A, "lane16-machine-a") == SEC_OK);
    CHECK(sec_test_identity(SK_B, PK_B, "lane16-machine-b") == SEC_OK);
    CHECK(sec_test_identity(SK_M, PK_M, "lane16-mallory") == SEC_OK);
    struct { const char *name; void (*fn)(void); } T[] = {
        {"hkdf_rfc5869", test_hkdf},
        {"handshake_and_data", test_handshake_and_data},
        {"wrong_identity", test_wrong_identity},
        {"impersonation", test_impersonation},
        {"transcript_tamper", test_transcript_tamper},
        {"splice", test_splice},
        {"weak_keys", test_weak_keys},
        {"replay_reorder", test_replay_reorder},
        {"mutilation", test_mutilation},
        {"rekey", test_rekey},
        {"close", test_close},
        {"loss_recovery", test_loss},
        {"fuzz", test_fuzz},
        {"args", test_args},
    };
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) {
        unsigned long f0 = failures, c0 = checks;
        T[i].fn();
        printf("  %-20s %s (%lu checks)\n", T[i].name, failures == f0 ? "PASS" : "FAIL", checks - c0);
    }
    printf("AIENOS_NET_SECURE_TESTS: %s (%lu checks, %lu failures)\n", failures ? "FAIL" : "PASS",
           checks, failures);
    return failures ? 1 : 0;
}
