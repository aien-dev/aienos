/*
 * test_argus_event.c -- ARGUS lane B: event ABI tests.
 *   layout (static), round trip for every kind, known-answer digests,
 *   malformed-field rejection, forward compatibility, secret-negative scan.
 * Run from native/argus (the secret scan reads . and tests/).
 */
#include "argus_abi.h"
#include "sha256.h"
#include "../capability/aienos_capability.h"

#include <dirent.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

/* ---- ABI layout: the header's documented offsets are the contract ---- */
_Static_assert(sizeof(ArgusEvent) == ARGUS_EVENT_SIZE, "event is 128 bytes");
_Static_assert(offsetof(ArgusEvent, version) == 0, "off");
_Static_assert(offsetof(ArgusEvent, class_) == 1, "off");
_Static_assert(offsetof(ArgusEvent, kind) == 2, "off");
_Static_assert(offsetof(ArgusEvent, effect_class) == 4, "off");
_Static_assert(offsetof(ArgusEvent, outcome) == 5, "off");
_Static_assert(offsetof(ArgusEvent, flags) == 6, "off");
_Static_assert(offsetof(ArgusEvent, sequence) == 8, "off");
_Static_assert(offsetof(ArgusEvent, tick) == 16, "off");
_Static_assert(offsetof(ArgusEvent, principal) == 24, "off");
_Static_assert(offsetof(ArgusEvent, code) == 28, "off");
_Static_assert(offsetof(ArgusEvent, cap_id) == 32, "off");
_Static_assert(offsetof(ArgusEvent, object_id) == 36, "off");
_Static_assert(offsetof(ArgusEvent, cap_generation) == 40, "off");
_Static_assert(offsetof(ArgusEvent, world_generation) == 48, "off");
_Static_assert(offsetof(ArgusEvent, resource) == 56, "off");
_Static_assert(offsetof(ArgusEvent, machine_id) == 64, "off");
_Static_assert(offsetof(ArgusEvent, evidence_digest) == 96, "off");

/* ArgusCapRef must stay layout-identical to the authority's AienosCapRef. */
_Static_assert(sizeof(ArgusCapRef) == sizeof(AienosCapRef), "capref size");
_Static_assert(offsetof(ArgusCapRef, cap_id) == offsetof(AienosCapRef, cap_id), "capref cap_id");
_Static_assert(offsetof(ArgusCapRef, generation) == offsetof(AienosCapRef, generation), "capref generation");
_Static_assert(sizeof(((ArgusCapRef *)0)->cap_id) == sizeof(((AienosCapRef *)0)->cap_id), "capref cap_id size");
_Static_assert(sizeof(((ArgusCapRef *)0)->generation) == sizeof(((AienosCapRef *)0)->generation), "capref gen size");

/* Secret-negative (layout half): no event field is 32 bytes except the two digest slots. */
#define NOT32(f) _Static_assert(sizeof(((ArgusEvent *)0)->f) != 32, "32-byte field: " #f)
NOT32(version); NOT32(class_); NOT32(kind); NOT32(effect_class); NOT32(outcome); NOT32(flags);
NOT32(sequence); NOT32(tick); NOT32(principal); NOT32(code); NOT32(cap_id); NOT32(object_id);
NOT32(cap_generation); NOT32(world_generation); NOT32(resource);
_Static_assert(sizeof(((ArgusEvent *)0)->machine_id) == 32, "machine_id");
_Static_assert(sizeof(((ArgusEvent *)0)->evidence_digest) == 32, "evidence_digest");
/* 17 fields; if a field is added, the sum below stops matching and this file must be updated. */
_Static_assert(1 + 1 + 2 + 1 + 1 + 2 + 8 + 8 + 4 + 4 + 4 + 4 + 8 + 8 + 8 + 32 + 32 == ARGUS_EVENT_SIZE,
               "field list complete");

static int failures;
#define CHECK(cond) do { if (!(cond)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static const uint16_t all_kinds[] = {
    ARGUS_EV_CAPABILITY_GRANTED, ARGUS_EV_CAPABILITY_USED, ARGUS_EV_CAPABILITY_DENIED, ARGUS_EV_CAPABILITY_REVOKED,
    ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_EV_CREDENTIAL_LEASE_REVOKED,
    ARGUS_EV_ARTIFACT_ADMITTED, ARGUS_EV_ARTIFACT_REJECTED, ARGUS_EV_ARTIFACT_ACTIVATED,
    ARGUS_EV_MACHINE_JOINED, ARGUS_EV_MACHINE_TRUST_CHANGED, ARGUS_EV_MACHINE_REMOVED,
    ARGUS_EV_PROVIDER_DISCOVERED, ARGUS_EV_PROVIDER_CHANGED, ARGUS_EV_PROVIDER_QUARANTINED, ARGUS_EV_PROVIDER_USED,
    ARGUS_EV_EXTERNAL_EFFECT_REQUESTED, ARGUS_EV_EXTERNAL_EFFECT_DENIED, ARGUS_EV_EXTERNAL_EFFECT_COMMITTED,
    ARGUS_EV_INTEGRITY_VIOLATION, ARGUS_EV_SIGNATURE_FAILURE, ARGUS_EV_STALE_GENERATION, ARGUS_EV_FORGED_CAPABILITY,
    ARGUS_EV_WORLD_COMMITTED, ARGUS_EV_POLICY_CHANGED, ARGUS_EV_RUNTIME_BUILD_CHANGED,
    ARGUS_EV_TELEMETRY_DROPPED, ARGUS_EV_CAPABILITY_USE_SUMMARY,
};
#define N_KINDS (sizeof all_kinds / sizeof all_kinds[0])

static int is_known_kind(unsigned k)
{
    for (size_t i = 0; i < N_KINDS; i++) if (all_kinds[i] == k) return 1;
    return 0;
}

/* Independent restatement of the per-kind class floor (argus_abi.h hostile-review rules). */
static unsigned floor_of(unsigned k)
{
    static const uint16_t crit[] = { 60, 61, 62, 63, 80, 42, 31, 32, 71, 72, 4, 12, 21, 52 };
    static const uint16_t sec[]  = { 1, 3, 10, 20, 22, 30, 40, 41, 50, 51, 70 };
    static const uint16_t aud[]  = { 2, 11, 43, 81 };
    for (size_t i = 0; i < sizeof crit / sizeof crit[0]; i++) if (crit[i] == k) return 1;
    for (size_t i = 0; i < sizeof sec / sizeof sec[0]; i++) if (sec[i] == k) return 2;
    for (size_t i = 0; i < sizeof aud / sizeof aud[0]; i++) if (aud[i] == k) return 3;
    return 0;
}

/* Reference oracle: the result argus_event_validate must give. */
static int oracle(const ArgusEvent *e)
{
    if (e->version != 1) return ARGUS_ERR_VERSION;
    if (e->class_ < 1 || e->class_ > 4) return ARGUS_ERR_MALFORMED;
    if (!is_known_kind(e->kind)) return ARGUS_ERR_MALFORMED;
    if (e->class_ > floor_of(e->kind)) return ARGUS_ERR_MALFORMED;
    if (e->effect_class > 3) return ARGUS_ERR_MALFORMED;
    if (e->outcome < 1 || e->outcome > 3) return ARGUS_ERR_MALFORMED;
    if (((e->flags & 2u) != 0) != (e->kind == 80)) return ARGUS_ERR_MALFORMED;
    if (e->cap_id >= 256 && e->cap_id != 0xFFFFFFFFu) return ARGUS_ERR_MALFORMED;   /* v1.1: CAP_NONE allowed */
    if (e->kind == 81 && e->outcome != 1) return ARGUS_ERR_MALFORMED;               /* summary: outcome OK only */
    if (e->sequence == 0 || e->sequence == UINT64_MAX) return ARGUS_ERR_MALFORMED;
    if (e->kind >= 50 && e->kind <= 52 && e->effect_class != 3) return ARGUS_ERR_MALFORMED;
    return ARGUS_OK;
}

static ArgusEvent fixed_event(void)
{
    ArgusEvent e;
    memset(&e, 0, sizeof e);
    e.version = ARGUS_ABI_VERSION;
    e.class_ = ARGUS_CLASS_SECURITY;
    e.kind = ARGUS_EV_CAPABILITY_USED;
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    e.outcome = ARGUS_OUTCOME_OK;
    e.flags = ARGUS_FLAG_SYNTHETIC;
    e.sequence = 0x0102030405060708ull;
    e.tick = 0x1112131415161718ull;
    e.principal = 0x21222324u;
    e.code = -7;
    e.cap_id = 0x31323334u;
    e.object_id = 0x41424344u;
    e.cap_generation = 0x5152535455565758ull;
    e.world_generation = 0x6162636465666768ull;
    e.resource = 0x8182838485868788ull;
    for (unsigned i = 0; i < 32; i++) {
        e.machine_id[i] = (uint8_t)(0xA0 + i);
        e.evidence_digest[i] = (uint8_t)(0xC0 + i);
    }
    return e;
}

/* fixed_event is the known-answer sample (its bytes and digests are pinned; encode
 * never validates). Its cap_id is out of range, so the validity tests start from
 * this valid variant instead. */
static ArgusEvent valid_event(void)
{
    ArgusEvent e = fixed_event();
    e.cap_id = 0x34;
    return e;
}

/* Make e valid for its kind: class at the floor, CONSUMER iff TELEMETRY_DROPPED, EXTERNAL for effects,
 * outcome OK for CAPABILITY_USE_SUMMARY. Stream bits (2-15) are kept. */
static void fit_kind(ArgusEvent *e)
{
    e->class_ = (uint8_t)floor_of(e->kind);
    e->flags = (uint16_t)((e->flags & (uint16_t)~ARGUS_FLAG_CONSUMER) | (e->kind == ARGUS_EV_TELEMETRY_DROPPED ? ARGUS_FLAG_CONSUMER : 0));
    if (e->kind >= 50 && e->kind <= 52) e->effect_class = ARGUS_EFFECT_EXTERNAL;
    if (e->kind == ARGUS_EV_CAPABILITY_USE_SUMMARY) e->outcome = ARGUS_OUTCOME_OK;
}

static ArgusFinding fixed_finding(void)
{
    ArgusFinding f;
    memset(&f, 0, sizeof f);
    f.code = ARGUS_F_REVOKED_CAPABILITY_USED;
    f.severity = ARGUS_SEV_HIGH;
    f.confidence = ARGUS_CONF_DETERMINISTIC;
    f.sync_allowed = 1;
    f.containment = ARGUS_CONTAIN_REVOKE_CAPABILITY;
    f.detector = ARGUS_F_REVOKED_CAPABILITY_USED;
    f.sequence = 42;
    f.prior_sequence = 17;
    f.principal = 7;
    f.cap_id = 9;
    f.cap_generation = 3;
    for (unsigned i = 0; i < 32; i++) { f.machine_id[i] = (uint8_t)i; f.event_digest[i] = (uint8_t)(0xFF - i); }
    return f;
}

static void hex(char *out, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
    out[2 * n] = 0;
}

static void check_digest(const char *name, const uint8_t d[32], const char *expect)
{
    char h[65];
    hex(h, d, 32);
    printf("  %-22s %s\n", name, h);
    if (strcmp(h, expect) != 0) { failures++; fprintf(stderr, "FAIL %s: expected %s\n", name, expect); }
}

/* ---- known-answer vectors ---- */
static void test_known_answers(void)
{
    uint8_t d[32], b[ARGUS_EVENT_SIZE];
    char h[2 * ARGUS_EVENT_SIZE + 1];
    printf("known-answer vectors:\n");
    sha256_hash((const uint8_t *)"abc", 3, d);
    check_digest("sha256(\"abc\")", d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    ArgusEvent e = fixed_event();
    CHECK(argus_event_encode(&e, b) == ARGUS_OK);
    hex(h, b, sizeof b);
    printf("  fixed event bytes      %s\n", h);
    /* Spot-check little-endian placement independently of the digest. */
    CHECK(b[0] == 1 && b[1] == 2 && b[2] == 2 && b[3] == 0 && b[4] == 3 && b[5] == 1 && b[6] == 1 && b[7] == 0);
    CHECK(b[8] == 0x08 && b[15] == 0x01 && b[16] == 0x18 && b[24] == 0x24 && b[27] == 0x21);
    CHECK(b[28] == 0xF9 && b[29] == 0xFF && b[30] == 0xFF && b[31] == 0xFF);   /* -7 */
    CHECK(b[32] == 0x34 && b[36] == 0x44 && b[40] == 0x58 && b[47] == 0x51 && b[48] == 0x68 && b[55] == 0x61);
    CHECK(b[56] == 0x88 && b[63] == 0x81 && b[64] == 0xA0 && b[95] == 0xBF && b[96] == 0xC0 && b[127] == 0xDF);

    argus_event_digest(&e, d);
    check_digest("event digest", d, "1be29450b792d28426444fceb5e44174e69bb631d5ef6063a870c21929574303");
    uint8_t chain[32] = {0};
    argus_chain_extend(chain, &e);
    check_digest("chain(0, event)", chain, "09ea598e432197cc2d6ff341ec57ab403c06312bad2992480b72c6ce87a6d747");
    ArgusEvent e2 = e;
    e2.sequence++;
    argus_chain_extend(chain, &e2);
    check_digest("chain(chain, event+1)", chain, "21b19c9ba36f86074263f49952b64ee8dea9b5ff02ed215555cb1a03bfda78e0");
    ArgusFinding f = fixed_finding();
    argus_finding_digest(&f, d);
    check_digest("finding digest", d, "b56e133cc6f6cfefe642ce0f1ec74e67c3fee57db2f114257ba04d3d3ee7680a");

    /* Chain definition check: H(chain || bytes) computed by hand. */
    uint8_t buf[32 + ARGUS_EVENT_SIZE], manual[32], c2[32] = {0};
    memset(buf, 0, 32);
    argus_event_encode(&e, buf + 32);
    sha256_hash(buf, sizeof buf, manual);
    argus_chain_extend(c2, &e);
    CHECK(memcmp(manual, c2, 32) == 0);
    /* encode/digest/chain never validate: a sequence-0 record still has canonical bytes. */
    {
        ArgusEvent z; memset(&z, 0, sizeof z);
        uint8_t zb[ARGUS_EVENT_SIZE], zc[32] = {0}, zd[32];
        CHECK(argus_event_validate(&z) != ARGUS_OK);
        CHECK(argus_event_encode(&z, zb) == ARGUS_OK);
        for (unsigned i = 0; i < ARGUS_EVENT_SIZE; i++) CHECK(zb[i] == 0);
        argus_chain_extend(zc, &z);
        argus_event_digest(&z, zd);
        CHECK(memcmp(zc, zd, 32) != 0);
    }
    /* Event digest definition check: H(bytes). */
    sha256_hash(buf + 32, ARGUS_EVENT_SIZE, manual);
    argus_event_digest(&e, d);
    CHECK(memcmp(manual, d, 32) == 0);
    /* Every finding field affects its digest. */
    uint8_t base[32];
    argus_finding_digest(&f, base);
    for (int field = 0; field < 13; field++) {
        ArgusFinding g = f;
        switch (field) {
        case 0: g.code ^= 1; break;          case 1: g.severity ^= 1; break;
        case 2: g.confidence ^= 1; break;    case 3: g.sync_allowed ^= 1; break;
        case 4: g.containment ^= 1; break;   case 5: g.detector ^= 0x100; break;
        case 6: g.sequence ^= 1ull << 63; break;  case 7: g.prior_sequence ^= 1; break;
        case 8: g.principal ^= 1u << 31; break;   case 9: g.cap_id ^= 1; break;
        case 10: g.cap_generation ^= 1ull << 40; break;
        case 11: g.machine_id[31] ^= 1; break;    case 12: g.event_digest[0] ^= 0x80; break;
        }
        argus_finding_digest(&g, d);
        CHECK(memcmp(d, base, 32) != 0);
    }
}

/* ---- round trip, every kind, every class it allows ---- */
static void test_round_trip(void)
{
    uint8_t b[ARGUS_EVENT_SIZE], b2[ARGUS_EVENT_SIZE];
    size_t n = 0;
    for (size_t i = 0; i < N_KINDS; i++) {
        unsigned fl = floor_of(all_kinds[i]);
        CHECK(fl >= 1 && fl <= 3);
        CHECK(argus_event_min_class(all_kinds[i]) == fl);
        for (uint8_t cls = 1; cls <= fl; cls++) {
            ArgusEvent e = valid_event(), d;
            e.kind = all_kinds[i];
            e.effect_class = (uint8_t)(i % 4);
            e.outcome = (uint8_t)(1 + i % 3);
            e.flags = (uint16_t)((i % 2) | ((i * 613u) << ARGUS_FLAG_STREAM_SHIFT));   /* v1.1 stream bits */
            fit_kind(&e);
            e.class_ = cls;
            e.sequence = 1 + i * 7 + cls;
            e.code = (int32_t)(0 - (int32_t)i);
            e.cap_id = i % 5 == 4 ? ARGUS_CAP_NONE : (uint32_t)(i * 9 % ARGUS_CAP_MAX);
            CHECK(argus_event_validate(&e) == ARGUS_OK);
            CHECK(argus_event_encode(&e, b) == ARGUS_OK);
            memset(&d, 0x5A, sizeof d);
            CHECK(argus_event_decode(b, &d) == ARGUS_OK);
            CHECK(argus_event_encode(&d, b2) == ARGUS_OK);
            CHECK(memcmp(b, b2, sizeof b) == 0);
            CHECK(memcmp(&e, &d, sizeof e) == 0);   /* no padding in ArgusEvent (asserted above) */
            n++;
        }
    }
    CHECK(N_KINDS == 29);
    CHECK(n == 14 * 1 + 11 * 2 + 4 * 3);
    printf("round trip: %zu kinds x every class at or above the kind's floor = %zu events OK\n", N_KINDS, n);
}

/* ---- malformed fields ---- */
static int decode_mut(size_t off, uint8_t v)
{
    ArgusEvent e = valid_event(), out, sentinel;
    uint8_t b[ARGUS_EVENT_SIZE];
    argus_event_encode(&e, b);
    b[off] = v;
    memset(&out, 0x77, sizeof out);
    sentinel = out;
    int rc = argus_event_decode(b, &out);
    if (rc != ARGUS_OK && memcmp(&out, &sentinel, sizeof out) != 0) { failures++; fprintf(stderr, "FAIL decode wrote output on error\n"); }
    return rc;
}

/* validate rejects; encode never validates but its bytes must then fail decode the same way. */
static void expect_struct(ArgusEvent e, int want)
{
    uint8_t b[ARGUS_EVENT_SIZE];
    ArgusEvent out;
    CHECK(argus_event_validate(&e) == want);
    CHECK(argus_event_encode(&e, b) == ARGUS_OK);
    CHECK(argus_event_decode(b, &out) == want);
}

/* Byte-level check: e encoded, decode must agree with the oracle. */
static void expect_oracle(ArgusEvent e)
{
    expect_struct(e, oracle(&e));
}

static void test_malformed(void)
{
    size_t n = 0;
    CHECK(oracle(&(ArgusEvent){0}) == ARGUS_ERR_VERSION);
    { ArgusEvent v = valid_event(); CHECK(oracle(&v) == ARGUS_OK); expect_struct(v, ARGUS_OK); }
    /* version: anything but 1 -> VERSION (checked first) */
    for (unsigned v = 0; v < 256; v++) {
        if (v == 1) continue;
        CHECK(decode_mut(0, (uint8_t)v) == ARGUS_ERR_VERSION);
        ArgusEvent e = valid_event(); e.version = (uint8_t)v; expect_struct(e, ARGUS_ERR_VERSION);
        n++;
    }
    /* class: only 1..4, and no weaker than the kind floor (CAPABILITY_USED: AUDIT) */
    for (unsigned v = 0; v < 256; v++) {
        int want = (v >= 1 && v <= 3) ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        CHECK(decode_mut(1, (uint8_t)v) == want);
        ArgusEvent e = valid_event(); e.class_ = (uint8_t)v; expect_struct(e, want);
        n++;
    }
    /* class x kind: every class byte against every known kind (fitted otherwise valid) */
    for (size_t i = 0; i < N_KINDS; i++) {
        for (unsigned v = 0; v < 256; v++) {
            ArgusEvent e = valid_event(); e.kind = all_kinds[i]; fit_kind(&e); e.class_ = (uint8_t)v;
            int want = (v >= 1 && v <= floor_of(all_kinds[i])) ? ARGUS_OK : ARGUS_ERR_MALFORMED;
            CHECK(oracle(&e) == want);
            expect_struct(e, want);
            n++;
        }
    }
    /* kind: every 16-bit value. min_class is 0 exactly for unknown kinds.
     * (a) the valid base as is (AUDIT, no CONSUMER, EXTERNAL) -> oracle decides;
     * (b) fitted to the kind -> OK iff the kind is known. */
    size_t known = 0;
    for (unsigned v = 0; v < 65536; v++) {
        CHECK((argus_event_min_class((uint16_t)v) != 0) == is_known_kind(v));
        CHECK(argus_event_min_class((uint16_t)v) == floor_of(v));
        ArgusEvent e = valid_event(); e.kind = (uint16_t)v; expect_oracle(e);
        ArgusEvent f = valid_event(); f.kind = (uint16_t)v; if (is_known_kind(v)) fit_kind(&f);
        int want = is_known_kind(v) ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        CHECK(oracle(&f) == want);
        expect_struct(f, want);
        uint8_t b[ARGUS_EVENT_SIZE]; ArgusEvent out;
        argus_event_encode(&f, b);
        b[2] = (uint8_t)v; b[3] = (uint8_t)(v >> 8);
        CHECK(argus_event_decode(b, &out) == want);
        known += is_known_kind(v);
        n++;
    }
    CHECK(known == N_KINDS);
    CHECK(decode_mut(3, 1) == ARGUS_ERR_MALFORMED);   /* high byte of kind */
    /* effect_class 0..3 (CAPABILITY_USED: any); EXTERNAL_EFFECT_*: only EXTERNAL */
    for (unsigned v = 0; v < 256; v++) {
        int want = v <= 3 ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        CHECK(decode_mut(4, (uint8_t)v) == want);
        ArgusEvent e = valid_event(); e.effect_class = (uint8_t)v; expect_struct(e, want);
        for (uint16_t k = 50; k <= 52; k++) {
            ArgusEvent x = valid_event(); x.kind = k; fit_kind(&x); x.effect_class = (uint8_t)v;
            expect_struct(x, v == ARGUS_EFFECT_EXTERNAL ? ARGUS_OK : ARGUS_ERR_MALFORMED);
            n++;
        }
        n++;
    }
    /* outcome 1..3 */
    for (unsigned v = 0; v < 256; v++) {
        int want = (v >= 1 && v <= 3) ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        CHECK(decode_mut(5, (uint8_t)v) == want);
        ArgusEvent e = valid_event(); e.outcome = (uint8_t)v; expect_struct(e, want);
        n++;
    }
    /* flags: every 16-bit value, on a producer kind and on TELEMETRY_DROPPED.
     * v1.1: bits 2-15 are the stream id, so no bit is reserved. Producer kind: OK iff
     * CONSUMER is clear. TELEMETRY_DROPPED: OK iff CONSUMER is set. */
    for (unsigned v = 0; v < 65536; v++) {
        int want_p = (v & ARGUS_FLAG_CONSUMER) == 0 ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        int want_t = (v & ARGUS_FLAG_CONSUMER) != 0 ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        CHECK(ARGUS_STREAM_OF(v) == (v >> 2));
        ArgusEvent e = valid_event(); e.flags = (uint16_t)v;
        CHECK(oracle(&e) == want_p);
        expect_struct(e, want_p);
        ArgusEvent t = valid_event(); t.kind = ARGUS_EV_TELEMETRY_DROPPED; fit_kind(&t); t.flags = (uint16_t)v;
        CHECK(oracle(&t) == want_t);
        expect_struct(t, want_t);
        n += 2;
    }
    CHECK(decode_mut(6, 0x04) == ARGUS_OK);              /* stream 1 (v1.1; was reserved in v1) */
    CHECK(decode_mut(6, 0x03) == ARGUS_ERR_MALFORMED);   /* CONSUMER on a producer kind */
    CHECK(decode_mut(7, 0x80) == ARGUS_OK);              /* stream 0x2000 */
    CHECK(decode_mut(6, 0xFD) == ARGUS_OK && decode_mut(7, 0xFF) == ARGUS_OK);   /* stream 0x3FFF, the maximum */
    /* cap_id: < ARGUS_CAP_MAX or == ARGUS_CAP_NONE (v1.1; 0 is the OFFICE slot, a real cap) */
    {
        static const uint32_t ok_ids[] = { 0, 1, 255, ARGUS_CAP_NONE };
        static const uint32_t bad_ids[] = { 256, 257, 300, 0x10000, 0x7FFFFFFFu, 0xFFFFFFFEu };
        for (size_t i = 0; i < 4; i++) { ArgusEvent e = valid_event(); e.cap_id = ok_ids[i]; expect_struct(e, ARGUS_OK); n++; }
        for (size_t i = 0; i < 6; i++) { ArgusEvent e = valid_event(); e.cap_id = bad_ids[i]; expect_struct(e, ARGUS_ERR_MALFORMED); n++; }
        /* byte 33 of cap_id 0x34: 0x0000VV34 is never CAP_NONE, so only VV == 0 is valid */
        for (unsigned v = 0; v < 256; v++) {
            CHECK(decode_mut(33, (uint8_t)v) == (v == 0 ? ARGUS_OK : ARGUS_ERR_MALFORMED));
            n++;
        }
    }
    /* sequence: 0 and UINT64_MAX rejected, UINT64_MAX-1 accepted */
    {
        ArgusEvent e = valid_event(); e.sequence = 0; expect_struct(e, ARGUS_ERR_MALFORMED);
        e.sequence = UINT64_MAX; expect_struct(e, ARGUS_ERR_MALFORMED);
        e.sequence = UINT64_MAX - 1; expect_struct(e, ARGUS_OK);
        uint8_t b[ARGUS_EVENT_SIZE]; ArgusEvent out;
        e.sequence = 1; argus_event_encode(&e, b); b[8] = 0;
        CHECK(argus_event_decode(b, &out) == ARGUS_ERR_MALFORMED);
        memset(b + 8, 0xFF, 8);
        CHECK(argus_event_decode(b, &out) == ARGUS_ERR_MALFORMED);
        n += 5;
    }
    /* v1.1 CAPABILITY_USE_SUMMARY: floor AUDIT, outcome OK only, any tick accepted,
     * CONSUMER rejected, stream bits and CAP_NONE accepted. */
    {
        ArgusEvent s = valid_event(); s.kind = ARGUS_EV_CAPABILITY_USE_SUMMARY; fit_kind(&s);
        s.tick = 0; s.resource = 4096; s.cap_generation = 9; s.object_id = 7; s.effect_class = ARGUS_EFFECT_NONE;
        CHECK(argus_event_min_class(ARGUS_EV_CAPABILITY_USE_SUMMARY) == ARGUS_CLASS_AUDIT);
        expect_struct(s, ARGUS_OK);
        ArgusEvent t = s; t.tick = 12345; expect_struct(t, ARGUS_OK);          /* producer rule says 0; not enforced */
        t = s; t.outcome = ARGUS_OUTCOME_DENIED; expect_struct(t, ARGUS_ERR_MALFORMED);
        t = s; t.outcome = ARGUS_OUTCOME_ERROR; expect_struct(t, ARGUS_ERR_MALFORMED);
        t = s; t.class_ = ARGUS_CLASS_INFORMATIONAL; expect_struct(t, ARGUS_ERR_MALFORMED);
        t = s; t.class_ = ARGUS_CLASS_CRITICAL; expect_struct(t, ARGUS_OK);
        t = s; t.flags |= ARGUS_FLAG_CONSUMER; expect_struct(t, ARGUS_ERR_MALFORMED);
        t = s; t.flags = (uint16_t)(ARGUS_FLAG_SYNTHETIC | (0x3FFFu << ARGUS_FLAG_STREAM_SHIFT)); expect_struct(t, ARGUS_OK);
        CHECK(ARGUS_STREAM_OF(t.flags) == 0x3FFFu);
        t = s; t.cap_id = ARGUS_CAP_NONE; expect_struct(t, ARGUS_OK);
        t = s; t.cap_id = 0; expect_struct(t, ARGUS_OK);
        for (unsigned v = 0; v < 256; v++) {             /* outcome byte of an encoded summary */
            uint8_t b[ARGUS_EVENT_SIZE]; ArgusEvent out;
            argus_event_encode(&s, b); b[5] = (uint8_t)v;
            CHECK(argus_event_decode(b, &out) == (v == ARGUS_OUTCOME_OK ? ARGUS_OK : ARGUS_ERR_MALFORMED));
            n++;
        }
        n += 11;
    }
    /* The ring's own drop report must be a valid event (CRITICAL, CONSUMER, CAP_NONE). */
    {
        ArgusEvent t = { .version = 1, .class_ = ARGUS_CLASS_CRITICAL, .kind = ARGUS_EV_TELEMETRY_DROPPED,
                         .outcome = ARGUS_OUTCOME_ERROR, .flags = ARGUS_FLAG_CONSUMER, .sequence = 1,
                         .code = ARGUS_ERR_FULL, .object_id = ARGUS_CLASS_AUDIT, .resource = 3 };
        expect_struct(t, ARGUS_OK);
        t.class_ = ARGUS_CLASS_SECURITY; expect_struct(t, ARGUS_ERR_MALFORMED);
        n += 2;
    }
    /* NULL arguments */
    {
        uint8_t b[ARGUS_EVENT_SIZE]; ArgusEvent e = valid_event();
        CHECK(argus_event_validate(NULL) == ARGUS_ERR_ARG);
        CHECK(argus_event_encode(NULL, b) == ARGUS_ERR_ARG);
        CHECK(argus_event_encode(&e, NULL) == ARGUS_ERR_ARG);
        CHECK(argus_event_decode(NULL, &e) == ARGUS_ERR_ARG);
        CHECK(argus_event_decode(b, NULL) == ARGUS_ERR_ARG);
    }
    printf("malformed: %zu field values checked (version, class, class x kind floor, every kind, effect incl. "
           "EXTERNAL_EFFECT_*, outcome, every flags x {producer, TELEMETRY_DROPPED}, cap_id bound, sequence 0/max)\n", n);
}

/* ---- forward compatibility ---- */
static void test_forward_compat(void)
{
    ArgusEvent e = fixed_event(), out;
    uint8_t b[ARGUS_EVENT_SIZE];
    argus_event_encode(&e, b);
    b[0] = 2;
    CHECK(argus_event_decode(b, &out) == ARGUS_ERR_VERSION);
    /* A v2 event with otherwise-unknown fields must still report VERSION, not MALFORMED. */
    memset(b, 0xFF, sizeof b);
    b[0] = 2;
    CHECK(argus_event_decode(b, &out) == ARGUS_ERR_VERSION);
    printf("forward compat: version 2 bytes rejected with ARGUS_ERR_VERSION\n");
}

/* ---- secret-negative: tree scan ----
 * Every regular file under native/argus (sources, headers, README, makefiles,
 * tests, docs), recursively, except the build output directory `out/`.
 * The forbidden word is matched case-insensitively; the authority's length
 * macro case-sensitively. Both patterns are assembled at run time so this
 * file never contains them literally. */
static int contains_ci(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (; *hay; hay++) if (strncasecmp(hay, needle, n) == 0) return 1;
    return 0;
}

static void scan_tree(const char *dir, const char *word, const char *cap_len, int *files, int *hits)
{
    DIR *d = opendir(dir);
    if (!d) { failures++; fprintf(stderr, "FAIL cannot open %s (run from native/argus)\n", dir); return; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (strcmp(dir, ".") == 0 && strcmp(de->d_name, "out") == 0) continue;   /* build output */
        char path[1024];
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) { failures++; fprintf(stderr, "FAIL cannot stat %s\n", path); continue; }
        if (S_ISDIR(st.st_mode)) { scan_tree(path, word, cap_len, files, hits); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        FILE *fp = fopen(path, "r");
        if (!fp) { failures++; fprintf(stderr, "FAIL cannot read %s\n", path); continue; }
        (*files)++;
        char line[4096];
        int lineno = 0;
        while (fgets(line, sizeof line, fp)) {
            lineno++;
            if (contains_ci(line, word) || strstr(line, cap_len)) {
                (*hits)++;
                fprintf(stderr, "FAIL %s:%d contains a forbidden word\n", path, lineno);
            }
        }
        fclose(fp);
    }
    closedir(d);
}

static void test_secret_negative(void)
{
    char word[8], cap_len[32];
    snprintf(word, sizeof word, "%s%s", "to", "ken");
    snprintf(cap_len, sizeof cap_len, "%s%s%s", "AIENOS_CAP_", "TO", "KEN_LEN");
    int files = 0, hits = 0;
    scan_tree(".", word, cap_len, &files, &hits);
    CHECK(files >= 10);
    CHECK(hits == 0);
    printf("secret-negative: %d files under native/argus scanned (recursive, out/ excluded), %d hits; "
           "no 32-byte event field except machine_id/evidence_digest (static)\n", files, hits);
}

int main(void)
{
    test_known_answers();
    test_round_trip();
    test_malformed();
    test_forward_compat();
    test_secret_negative();
    if (failures) { printf("test_argus_event: FAIL (%d)\n", failures); return 1; }
    printf("test_argus_event: PASS\n");
    return 0;
}
