/* Deterministic loss/recovery and refusal tests for the M6-A control-transport
 * stub (TEST identity only). A seeded simulated link drops, duplicates,
 * corrupts and reorders frames; every scenario must deliver every message in
 * order exactly once, or fail the link deterministically. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aienos_ctl.h"
#include "../../argus/sha256.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define EQ(a, b) CHECK((long long)(a) == (long long)(b))

typedef struct { uint64_t s; } prng;
static uint32_t rnd(prng *p) { p->s ^= p->s << 13; p->s ^= p->s >> 7; p->s ^= p->s << 17; return (uint32_t)(p->s >> 11); }
static int chance(prng *p, unsigned pct) { return rnd(p) % 100 < pct; }

typedef struct {
    unsigned drop, dup, corrupt, max_delay; /* percent, percent, percent, ticks */
    uint64_t blackout_from, blackout_to;    /* everything dropped in [from, to) */
} link_cfg;
static uint64_t drop_every; /* Lane 19: drop every Nth frame per direction (0 = off) */

#define QMAX 256
typedef struct { uint64_t at; int to; size_t n; uint8_t f[CT_MAX_FRAME]; } wire_frame;
typedef struct {
    wire_frame q[QMAX];
    size_t nq;
    sha256_ctx transcript;
    uint64_t sent, dropped, count[2];
} wire;

typedef struct {
    int done, link_down_a, link_down_b;
    uint64_t ticks;
    uint32_t delivered[2];
    ct_counters ca, cb;
    uint8_t digest[32];
} result;

#define MSGS 64
static void msg_for(int from, uint32_t i, uint8_t *m, size_t *n)
{
    *n = (i * 37u + (unsigned)from * 11u) % 200u + (i % 5 == 0 ? 0 : 1);
    for (size_t k = 0; k < *n; k++) m[k] = (uint8_t)(i * 131u + k * 7u + (unsigned)from);
}

static void put_on_wire(wire *w, prng *p, const link_cfg *L, uint64_t now, int to, const uint8_t *f, size_t n)
{
    w->sent++;
    sha256_update(&w->transcript, f, n);
    w->count[to]++;
    if ((now >= L->blackout_from && now < L->blackout_to) || chance(p, L->drop) ||
        (drop_every && w->count[to] % drop_every == 0)) { w->dropped++; return; }
    int copies = chance(p, L->dup) ? 2 : 1;
    for (int c = 0; c < copies && w->nq < QMAX; c++) {
        wire_frame *x = &w->q[w->nq++];
        x->at = now + 1 + (L->max_delay ? rnd(p) % L->max_delay : 0);
        x->to = to;
        x->n = n;
        memcpy(x->f, f, n);
        if (chance(p, L->corrupt)) x->f[rnd(p) % n] ^= (uint8_t)(1u << (rnd(p) % 8));
    }
}

static result run(uint64_t seed, const link_cfg *L, uint32_t nmsg, uint32_t rto, uint32_t retries, uint64_t limit)
{
    static ct_endpoint ep[2];
    static wire w;
    ct_identity id;
    result r;
    memset(&r, 0, sizeof r);
    memset(&w, 0, sizeof w);
    sha256_init(&w.transcript);
    prng p = {seed ? seed : 1};
    CHECK(ct_test_identity(&id, "lane5-test-link") == CT_OK);
    CHECK(ct_init(&ep[0], &id, 0, 0xA1E5u, rto, retries) == CT_OK);
    CHECK(ct_init(&ep[1], &id, 1, 0xA1E5u, rto, retries) == CT_OK);
    uint32_t queued[2] = {0, 0};
    uint8_t buf[CT_MAX_FRAME], m[CT_MAX_PAYLOAD], want[CT_MAX_PAYLOAD];
    size_t n, wl;
    for (uint64_t now = 0; now < limit; now++) {
        for (int e = 0; e < 2; e++) {
            while (queued[e] < nmsg) {
                msg_for(e, queued[e], m, &n);
                ct_status s = ct_send(&ep[e], m, n);
                if (s == CT_ERR_WINDOW_FULL || s == CT_ERR_LINK_DOWN) break;
                EQ(s, CT_OK);
                queued[e]++;
            }
            for (;;) {
                ct_status s = ct_poll_tx(&ep[e], now, buf, sizeof buf, &n);
                if (s != CT_OK) break;
                put_on_wire(&w, &p, L, now, 1 - e, buf, n);
            }
        }
        /* deliver everything due in FIFO order; only the random delay reorders */
        size_t keep = 0;
        for (size_t k = 0; k < w.nq; k++) {
            if (w.q[k].at > now) { if (keep != k) w.q[keep] = w.q[k]; keep++; continue; }
            const wire_frame *xp = &w.q[k];
            wire_frame x; x.to = xp->to; x.n = xp->n; memcpy(x.f, xp->f, xp->n);
            ct_status s = ct_receive(&ep[x.to], x.f, x.n, m, sizeof m, &n);
            CHECK(s == CT_OK || s == CT_DELIVERED || s == CT_ERR_BAD_TAG || s == CT_ERR_MALFORMED ||
                  s == CT_ERR_REFUSED || s == CT_ERR_LINK_DOWN);
            if (s == CT_DELIVERED) {
                uint32_t i = r.delivered[x.to]++;
                msg_for(1 - x.to, i, want, &wl); /* in order, exactly once, intact */
                CHECK(n == wl && memcmp(m, want, n) == 0);
            }
        }
        w.nq = keep;
        r.link_down_a = ep[0].link_down;
        r.link_down_b = ep[1].link_down;
        if (r.delivered[0] == nmsg && r.delivered[1] == nmsg && ct_in_flight(&ep[0]) == 0 &&
            ct_in_flight(&ep[1]) == 0) { r.done = 1; r.ticks = now; break; }
        if (r.link_down_a || r.link_down_b) { r.ticks = now; break; }
    }
    r.ca = ep[0].c;
    r.cb = ep[1].c;
    sha256_final(&w.transcript, r.digest);
    return r;
}

static void hex(const uint8_t *d, char *o) { for (int i = 0; i < 32; i++) sprintf(o + 2 * i, "%02x", d[i]); }

static void scenario(const char *name, uint64_t seed, link_cfg L, uint32_t rto, uint32_t retries, int expect_done)
{
    result a = run(seed, &L, MSGS, rto, retries, 200000);
    result b = run(seed, &L, MSGS, rto, retries, 200000);
    CHECK(memcmp(&a, &b, sizeof a) == 0); /* bit-identical rerun */
    EQ(a.done, expect_done);
    if (expect_done) { EQ(a.delivered[0], MSGS); EQ(a.delivered[1], MSGS); }
    char h[65]; hex(a.digest, h);
    printf("  %-22s done=%d ticks=%llu retx=%llu/%llu dup=%llu/%llu gap=%llu/%llu badtag=%llu/%llu malformed=%llu/%llu transcript=%.16s\n",
           name, a.done, (unsigned long long)a.ticks,
           (unsigned long long)a.ca.tx_retransmits, (unsigned long long)a.cb.tx_retransmits,
           (unsigned long long)a.ca.rx_duplicate, (unsigned long long)a.cb.rx_duplicate,
           (unsigned long long)a.ca.rx_gap, (unsigned long long)a.cb.rx_gap,
           (unsigned long long)a.ca.rx_bad_tag, (unsigned long long)a.cb.rx_bad_tag,
           (unsigned long long)a.ca.rx_malformed, (unsigned long long)a.cb.rx_malformed, h);
}

static void test_loss_recovery(void)
{
    scenario("clean", 1, (link_cfg){0, 0, 0, 0, 0, 0}, 4, 5, 1);
    {   /* a clean FIFO link needs no retransmission and sees no gap */
        link_cfg L = {0, 0, 0, 0, 0, 0};
        result c = run(1, &L, MSGS, 4, 5, 100000);
        EQ(c.ca.tx_retransmits + c.cb.tx_retransmits, 0);
        EQ(c.ca.rx_gap + c.cb.rx_gap + c.ca.rx_duplicate + c.cb.rx_duplicate, 0);
    }
    scenario("loss30", 2, (link_cfg){30, 0, 0, 0, 0, 0}, 4, 40, 1);
    scenario("loss+dup+reorder", 3, (link_cfg){20, 15, 0, 6, 0, 0}, 8, 40, 1);
    scenario("corrupt20", 4, (link_cfg){0, 0, 20, 2, 0, 0}, 4, 40, 1);
    scenario("everything", 5, (link_cfg){25, 10, 10, 5, 0, 0}, 8, 60, 1);
    scenario("blackout-recover", 6, (link_cfg){5, 0, 0, 2, 20, 120}, 10, 20, 1);

    /* total blackout: the link fails deterministically after max_retries */
    link_cfg dead = {100, 0, 0, 0, 0, 0};
    result d = run(7, &dead, 1, 5, 3, 10000);
    EQ(d.done, 0);
    /* Lane 19: resend waits are jittered, so the two sides no longer give up on
     * the same tick. The first side down has sent 1 + 3 frames: at 0, then 5
     * (first retransmit waits exactly rto), then two waits in [5, 10], and is
     * declared down after a third wait in [5, 10]: tick 20..35. */
    CHECK(d.link_down_a || d.link_down_b);
    EQ(d.link_down_a ? d.ca.tx_retransmits : d.cb.tx_retransmits, 3);
    CHECK(d.ticks >= 20 && d.ticks <= 35);
    result d2 = run(7, &dead, 1, 5, 3, 10000);
    CHECK(memcmp(&d, &d2, sizeof d) == 0); /* deterministic */
    printf("  %-22s link_down at tick %llu after %llu retransmissions\n", "blackout-dead",
           (unsigned long long)d.ticks, (unsigned long long)d.ca.tx_retransmits);
}

/* ---------------- refusal and malformed-frame negatives ---------------- */
static void pair(ct_endpoint *a, ct_endpoint *b, uint32_t session)
{
    ct_identity id;
    ct_test_identity(&id, "lane5-test-link");
    ct_init(a, &id, 0, session, 4, 3);
    ct_init(b, &id, 1, session, 4, 3);
}

static void test_refusals(void)
{
    static ct_endpoint a, b, c;
    uint8_t f[CT_MAX_FRAME + 8], x[CT_MAX_FRAME + 8], m[CT_MAX_PAYLOAD];
    size_t n, ml;
    ct_identity id, other;
    EQ(ct_test_identity(&id, ""), CT_ERR_ARG);
    EQ(ct_test_identity(&id, "lane5-test-link"), CT_OK);
    EQ(id.kind, CT_IDENTITY_TEST);
    id.kind = 0x50; /* anything but TEST is refused: production identity needs M5 */
    EQ(ct_init(&a, &id, 0, 1, 4, 3), CT_ERR_REFUSED);
    EQ(ct_test_identity(&id, "lane5-test-link"), CT_OK);
    EQ(ct_init(&a, &id, 2, 1, 4, 3), CT_ERR_ARG);
    EQ(ct_init(&a, &id, 0, 1, 0, 3), CT_ERR_ARG);

    pair(&a, &b, 77);
    EQ(ct_send(&a, (const uint8_t *)"hello", 5), CT_OK);
    EQ(ct_poll_tx(&a, 0, f, sizeof f, &n), CT_OK);
    EQ(n, CT_HEADER_LEN + 5 + CT_TAG_LEN);
    /* every truncation and a trailing byte */
    for (size_t k = 0; k < n; k++) CHECK(ct_receive(&b, f, k, m, sizeof m, &ml) < 0);
    memcpy(x, f, n); x[n] = 0;
    EQ(ct_receive(&b, x, n + 1, m, sizeof m, &ml), CT_ERR_MALFORMED);
    /* header field corruption */
    const size_t malformed_at[] = {0, 3, 4, 5, 22, 23};
    for (size_t i = 0; i < sizeof malformed_at / sizeof *malformed_at; i++) {
        memcpy(x, f, n); x[malformed_at[i]] ^= 0x40;
        EQ(ct_receive(&b, x, n, m, sizeof m, &ml), CT_ERR_MALFORMED);
    }
    memcpy(x, f, n); x[6] = 2;
    EQ(ct_receive(&b, x, n, m, sizeof m, &ml), CT_ERR_MALFORMED);
    memcpy(x, f, n); x[20] = 0x04; x[21] = 0x01; /* payload_len 1025 > max */
    EQ(ct_receive(&b, x, n, m, sizeof m, &ml), CT_ERR_MALFORMED);
    memcpy(x, f, n); x[21] = 4;                  /* length lie */
    EQ(ct_receive(&b, x, n, m, sizeof m, &ml), CT_ERR_MALFORMED);
    memcpy(x, f, n); x[7] = 0x50;                /* non-TEST identity kind */
    EQ(ct_receive(&b, x, n, m, sizeof m, &ml), CT_ERR_REFUSED);
    /* every authenticated byte is covered by the tag */
    const size_t tagged_at[] = {8, 11, 12, 15, 16, 19, 24, 28, CT_HEADER_LEN + 5, CT_HEADER_LEN + 5 + 15};
    for (size_t i = 0; i < sizeof tagged_at / sizeof *tagged_at; i++) {
        memcpy(x, f, n); x[tagged_at[i]] ^= 1;
        EQ(ct_receive(&b, x, n, m, sizeof m, &ml), CT_ERR_BAD_TAG);
    }
    /* wrong key */
    ct_test_identity(&other, "someone-else");
    ct_init(&c, &other, 1, 77, 4, 3);
    EQ(ct_receive(&c, f, n, m, sizeof m, &ml), CT_ERR_BAD_TAG);
    /* reflection: A's own frame back to A */
    EQ(ct_receive(&a, f, n, m, sizeof m, &ml), CT_ERR_REFUSED);
    /* another session with the same key */
    ct_init(&c, &id, 1, 78, 4, 3);
    EQ(ct_receive(&c, f, n, m, sizeof m, &ml), CT_ERR_REFUSED);
    /* output buffer too small leaves state unchanged; then delivers */
    EQ(ct_receive(&b, f, n, m, 4, &ml), CT_ERR_CAPACITY);
    EQ(b.expected, 0);
    EQ(ct_receive(&b, f, n, m, sizeof m, &ml), CT_DELIVERED);
    CHECK(ml == 5 && memcmp(m, "hello", 5) == 0);
    /* replay is never redelivered */
    for (int i = 0; i < 5; i++) EQ(ct_receive(&b, f, n, m, sizeof m, &ml), CT_OK);
    EQ(b.c.rx_delivered, 1);
    EQ(b.c.rx_duplicate, 5);
    /* B acks; A frees the slot; a replayed old ack is harmless */
    uint8_t ackf[64]; size_t an;
    EQ(ct_poll_tx(&b, 0, ackf, sizeof ackf, &an), CT_OK);
    EQ(an, CT_HEADER_LEN + CT_TAG_LEN);
    EQ(ct_poll_tx(&b, 0, ackf + 40, 24, &n), CT_IDLE);
    EQ(ct_receive(&a, ackf, an, m, sizeof m, &ml), CT_OK);
    EQ(ct_in_flight(&a), 0);
    EQ(ct_receive(&a, ackf, an, m, sizeof m, &ml), CT_OK);
    /* an ACK for data never sent */
    b.expected = 9; b.ack_pending = 1;
    EQ(ct_poll_tx(&b, 0, ackf, sizeof ackf, &an), CT_OK);
    EQ(ct_receive(&a, ackf, an, m, sizeof m, &ml), CT_ERR_BAD_ACK);
    EQ(ct_in_flight(&a), 0);
    /* turning DATA into ACK in flight breaks the tag */
    b.expected = 1;
    EQ(ct_send(&b, (const uint8_t *)"z", 1), CT_OK);
    EQ(ct_poll_tx(&b, 0, x, sizeof x, &n), CT_OK);
    x[5] = CT_TYPE_ACK;
    EQ(ct_receive(&a, x, n, m, sizeof m, &ml), CT_ERR_BAD_TAG);

    /* sender limits */
    pair(&a, &b, 5);
    static uint8_t big[CT_MAX_PAYLOAD + 1];
    EQ(ct_send(&a, big, CT_MAX_PAYLOAD + 1), CT_ERR_TOO_LARGE);
    EQ(ct_send(&a, big, CT_MAX_PAYLOAD), CT_OK);
    for (uint32_t i = 1; i < CT_WINDOW; i++) EQ(ct_send(&a, big, 1), CT_OK);
    EQ(ct_send(&a, big, 1), CT_ERR_WINDOW_FULL);
    EQ(ct_poll_tx(&a, 0, f, CT_HEADER_LEN + CT_MAX_PAYLOAD + CT_TAG_LEN - 1, &n), CT_ERR_CAPACITY);
    EQ(ct_poll_tx(&a, 0, f, sizeof f, &n), CT_OK);
    EQ(n, CT_MAX_FRAME);
    EQ(ct_receive(&b, f, n, m, sizeof m, &ml), CT_DELIVERED);
    EQ(ml, CT_MAX_PAYLOAD);
    pair(&a, &b, 6);
    a.next_seq = a.base = UINT32_MAX;
    EQ(ct_send(&a, big, 1), CT_ERR_SEQ_EXHAUSTED);
    /* gap: seq 1 before seq 0 is not delivered; seq 0 then is, then 1 on retransmit */
    pair(&a, &b, 8);
    uint8_t f0[64], f1[64]; size_t n0, n1;
    ct_send(&a, (const uint8_t *)"0", 1);
    ct_send(&a, (const uint8_t *)"1", 1);
    EQ(ct_poll_tx(&a, 0, f0, sizeof f0, &n0), CT_OK);
    EQ(ct_poll_tx(&a, 0, f1, sizeof f1, &n1), CT_OK);
    EQ(ct_receive(&b, f1, n1, m, sizeof m, &ml), CT_OK);
    EQ(b.c.rx_gap, 1);
    EQ(ct_receive(&b, f0, n0, m, sizeof m, &ml), CT_DELIVERED);
    EQ(m[0], '0');
    EQ(ct_poll_tx(&a, 3, f1, sizeof f1, &n1), CT_IDLE); /* rto 4 not reached */
    EQ(ct_poll_tx(&a, 4, f0, sizeof f0, &n0), CT_OK);    /* retransmit seq 0 */
    EQ(ct_poll_tx(&a, 4, f1, sizeof f1, &n1), CT_OK);    /* retransmit seq 1 */
    EQ(ct_receive(&b, f1, n1, m, sizeof m, &ml), CT_DELIVERED);
    EQ(m[0], '1');
    /* a clock that goes backwards never triggers a retransmit storm */
    EQ(ct_poll_tx(&a, 1, f1, sizeof f1, &n1), CT_IDLE);
    /* link down is sticky */
    pair(&a, &b, 9);
    ct_send(&a, (const uint8_t *)"q", 1);
    uint64_t t = 0;
    while (ct_poll_tx(&a, t, f, sizeof f, &n) != CT_ERR_LINK_DOWN) t++;
    EQ(ct_send(&a, (const uint8_t *)"q", 1), CT_ERR_LINK_DOWN);
    EQ(ct_receive(&a, ackf, an, m, sizeof m, &ml), CT_ERR_LINK_DOWN);
}

/* ---------------- resend jitter (Lane 19) ---------------- */
/* Strictly periodic loss, both senders in lockstep, no sender-side timing
 * tricks: with a fixed resend interval this starved one frame until the link
 * went down. The jittered resend schedule must recover for every N. */
static void test_periodic_loss(void)
{
    int recovered = 0, total = 0;
    static const uint64_t N[] = {2, 3, 4, 5, 6, 7, 8, 11, 16};
    for (size_t i = 0; i < sizeof N / sizeof N[0]; i++) {
        link_cfg L = {0, 0, 0, 0, 0, 0};
        drop_every = N[i];
        result a = run(9, &L, MSGS, 3, 40, 200000);
        result b = run(9, &L, MSGS, 3, 40, 200000);
        CHECK(memcmp(&a, &b, sizeof a) == 0); /* bit-identical rerun */
        EQ(a.done, 1);
        total++; recovered += a.done;
        EQ(a.delivered[0], MSGS);
        EQ(a.delivered[1], MSGS);
        CHECK(a.ca.tx_retransmits + a.cb.tx_retransmits > 0); /* loss really happened */
        if (!a.done)
            fprintf(stderr, "periodic loss N=%llu: delivered %u/%u down %d/%d\n",
                    (unsigned long long)N[i], a.delivered[0], a.delivered[1], a.link_down_a, a.link_down_b);
    }
    drop_every = 0;
    printf("  %-22s %d/%d drop-every-N patterns (N=2..16) recovered, bit-identical reruns\n", "periodic-loss",
           recovered, total);
}

/* Transmit ticks of one message on a dead link, until link down. */
static int tx_schedule(uint32_t session, uint8_t role, uint32_t seq, uint32_t rto, uint32_t retries,
                       uint64_t *at, int max)
{
    ct_endpoint e;
    ct_identity id;
    uint8_t f[CT_MAX_FRAME];
    size_t n;
    ct_test_identity(&id, "lane19-jitter");
    ct_init(&e, &id, role, session, rto, retries);
    e.next_seq = e.base = seq;
    EQ(ct_send(&e, (const uint8_t *)"j", 1), CT_OK);
    int k = 0;
    for (uint64_t t = 0; t < 100000; t++) {
        ct_status s = ct_poll_tx(&e, t, f, sizeof f, &n);
        if (s == CT_ERR_LINK_DOWN) break;
        if (s == CT_OK && k < max) at[k++] = t;
    }
    return k;
}

static void test_resend_schedule(void)
{
    uint64_t at[64], at2[64];
    int first_exact = 1, bounded = 1, by_seq = 0, by_session = 0, by_role = 0, by_tries = 0;
    for (uint32_t q = 0; q < 64; q++) {
        int k = tx_schedule(0xA1E5u, 0, q * 7919u, 5, 6, at, 64);
        EQ(k, 1 + 6); /* first send + max_retries retransmissions */
        EQ(tx_schedule(0xA1E5u, 0, q * 7919u, 5, 6, at2, 64), k);
        CHECK(memcmp(at, at2, sizeof at[0] * (size_t)k) == 0); /* deterministic */
        if (at[1] - at[0] != 5) first_exact = 0;
        for (int i = 1; i < k; i++)
            if (at[i] - at[i - 1] < 5 || at[i] - at[i - 1] > 10) bounded = 0;
        for (int i = 3; i < k; i++)
            if (at[i] - at[i - 1] != at[2] - at[1]) by_tries = 1;
        uint64_t g_seq = at[2] - at[1];
        tx_schedule(0xA1E5u, 0, q * 7919u + 1, 5, 6, at2, 64);
        if (at2[2] - at2[1] != g_seq) by_seq = 1;
        tx_schedule(0xA1E5u + 1 + q, 0, q * 7919u, 5, 6, at2, 64);
        if (at2[2] - at2[1] != g_seq) by_session = 1;
        tx_schedule(0xA1E5u, 1, q * 7919u, 5, 6, at2, 64);
        if (at2[2] - at2[1] != g_seq) by_role = 1;
    }
    CHECK(first_exact); /* the first retransmit waits exactly rto */
    CHECK(bounded);     /* every wait is in [rto, 2*rto] */
    CHECK(by_tries && by_seq && by_session && by_role);
    /* rto 1: waits are 1 or 2, and both occur */
    int saw1 = 0, saw2 = 0;
    for (uint32_t q = 0; q < 16; q++) {
        int k = tx_schedule(3, 0, q, 1, 8, at, 64);
        for (int i = 2; i < k; i++) {
            uint64_t g = at[i] - at[i - 1];
            CHECK(g == 1 || g == 2);
            saw1 |= g == 1; saw2 |= g == 2;
        }
    }
    CHECK(saw1 && saw2);
    /* largest rto: the wait is computed without 32-bit overflow */
    ct_endpoint e;
    ct_identity id;
    uint8_t f[CT_MAX_FRAME];
    size_t n;
    ct_test_identity(&id, "lane19-jitter");
    ct_init(&e, &id, 0, 1, UINT32_MAX, 3);
    ct_send(&e, (const uint8_t *)"j", 1);
    EQ(ct_poll_tx(&e, 0, f, sizeof f, &n), CT_OK);
    EQ(ct_poll_tx(&e, UINT32_MAX - 1ull, f, sizeof f, &n), CT_IDLE);
    EQ(ct_poll_tx(&e, UINT32_MAX, f, sizeof f, &n), CT_OK);
    EQ(ct_poll_tx(&e, 2ull * UINT32_MAX - 1, f, sizeof f, &n), CT_IDLE);
    EQ(ct_poll_tx(&e, 3ull * UINT32_MAX, f, sizeof f, &n), CT_OK);
    printf("  %-22s first wait = rto, later waits in [rto, 2*rto], vary by seq/session/role/try\n",
           "resend-schedule");
}

int main(void)
{
    test_refusals();
    test_loss_recovery();
    test_periodic_loss();
    test_resend_schedule();
    printf("ctl_test checks=%d failures=%d\n", checks, failures);
    printf("CTL_TRANSPORT_LOSS_RECOVERY: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
