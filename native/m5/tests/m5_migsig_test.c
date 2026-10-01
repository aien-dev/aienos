/* native/m5 owner-signed migration record tests (Ed25519 from native/sig).
 * Host-only (hosted libc), not QEMU. Every key here is a TEST key derived
 * from a public label; no real owner key is used or needed.
 * Last line: "AIENOS_M5_MIGRATION_SIG: PASS" (exit 0) or "... FAIL" (exit 1). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../m5.h"
#include "../../argus/sha256.h"
#include "../../sig/aienos_sig.h"

static int g_fail;
#define CHECK(c) do { if (!(c)) { printf("  check failed: %s (line %d)\n", #c, __LINE__); g_fail = 1; } } while (0)

static int all_zero(const void *p, size_t n) { const uint8_t *b = p; for (size_t i = 0; i < n; i++) if (b[i]) return 0; return 1; }
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }

#define DOMAIN "AIENOS-M5-OWNER-MIGRATION-V1"
#define L M5_OWNER_MIG_LEN

/* ---------- TEST keys (public labels, never an owner key) ---------- */
static uint8_t TEST_SK[32], TEST_PK[32], TEST_SK2[32], TEST_PK2[32];
static uint8_t K_VOL[32];
static m5_subkeys SK;
static uint8_t IDS[3][32];
static uint8_t MIG[M5_MIGRATION_LEN];

static void test_key(const char *label, uint8_t sk[32], uint8_t pk[32])
{
    uint8_t h[64];
    aienos_sha512((const uint8_t *)label, strlen(label), h);
    memcpy(sk, h, 32);
    aienos_ed25519_public_key(pk, sk);
}

static m5_migration mig_fixture(void)
{
    m5_migration m;
    memset(&m, 0, sizeof m);
    m.identity_class = M5_ID_PRODUCTION;
    memset(m.agent_root_id, 0x32, 32);
    memset(m.genesis_store_uuid, 0xA0, 16);
    memset(m.source_store_uuid, 0xA0, 16);
    memset(m.dest_store_uuid, 0xD0, 16);
    m.source_store_generation = 9;
    m.source_anchor_counter = 5;
    m.migration_counter = 2;
    m.owner_hierarchy_generation = 1;
    memset(m.source_commit_digest, 0x5C, 32);
    return m;
}

static m5_owner_migration own_fixture(void)
{
    m5_owner_migration o;
    memset(&o, 0, sizeof o);
    o.identity_class = M5_ID_PRODUCTION;
    memset(o.agent_root_id, 0x32, 32);
    memset(o.source_store_uuid, 0xA0, 16);
    memset(o.dest_store_uuid, 0xD0, 16);
    o.source_store_generation = 9;
    o.store_format_version = 1;
    o.envelope_count = 3;
    m5_envelope_set_digest((const uint8_t (*)[32])IDS, 3, o.envelope_set_digest);
    sha256_hash(MIG, sizeof MIG, o.migration_manifest_digest);
    o.migration_counter = 2;
    o.owner_hierarchy_generation = 1;
    return o;
}

static void fixtures(void)
{
    test_key("AIENOS TEST-ONLY owner key 1 (not an owner key)", TEST_SK, TEST_PK);
    test_key("AIENOS TEST-ONLY owner key 2 (not an owner key)", TEST_SK2, TEST_PK2);
    for (int i = 0; i < 32; i++) K_VOL[i] = (uint8_t)(0x11 + i);
    m5_derive_subkeys(K_VOL, M5_ID_PRODUCTION, 1, &SK);
    for (int i = 0; i < 3; i++) memset(IDS[i], 0x10 * (i + 1), 32); /* ascending */
    m5_migration m = mig_fixture();
    m5_migration_seal(&m, SK.k_root_auth, MIG);
}

#define VERIFY(buf, len, pk, e, last, o) m5_owner_migration_verify(buf, len, pk, M5_ID_PRODUCTION, e, last, o)

/* Sign an arbitrary 208-byte body directly (bypasses sign_body's format check). */
static void raw_sign(uint8_t rec[L], const uint8_t sk[32])
{
    uint8_t msg[sizeof(DOMAIN) + M5_OWNER_MIG_BODY_LEN];
    memcpy(msg, DOMAIN, sizeof(DOMAIN));
    memcpy(msg + sizeof(DOMAIN), rec, M5_OWNER_MIG_BODY_LEN);
    aienos_ed25519_sign(rec + M5_OWNER_MIG_BODY_LEN, msg, sizeof msg, sk);
}

/* ---------- tests ---------- */
static void t_roundtrip(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t r[L];
    CHECK(m5_owner_migration_sign(&m, TEST_SK, r) == M5_OK);
    CHECK(VERIFY(r, L, TEST_PK, &m, 1, &o) == M5_OK);
    CHECK(o.migration_counter == 2 && o.store_format_version == 1 && o.envelope_count == 3);
    uint8_t kid[32];
    sha256_hash(TEST_PK, 32, kid);
    CHECK(memcmp(o.owner_key_id, kid, 32) == 0);
    CHECK(memcmp(o.envelope_set_digest, m.envelope_set_digest, 32) == 0);
    /* deterministic (Ed25519 has no random nonce) */
    uint8_t r2[L];
    m5_owner_migration_sign(&m, TEST_SK, r2);
    CHECK(memcmp(r, r2, L) == 0);
}

static void t_layout_pinned(void)
{
    m5_owner_migration m = own_fixture();
    uint8_t r[L], kid[32];
    m5_owner_migration_sign(&m, TEST_SK, r);
    sha256_hash(TEST_PK, 32, kid);
    CHECK(memcmp(r, "AIENOMG1", 8) == 0 && r[8] == 1 && r[9] == 0 && r[10] == 0 && r[11] == 0);
    CHECK(r[12] == M5_ID_PRODUCTION && all_zero(r + 13, 3));
    CHECK(memcmp(r + 16, kid, 32) == 0);
    CHECK(memcmp(r + 48, m.agent_root_id, 32) == 0);
    CHECK(memcmp(r + 80, m.source_store_uuid, 16) == 0 && memcmp(r + 96, m.dest_store_uuid, 16) == 0);
    CHECK(r[112] == 9 && all_zero(r + 113, 7));
    CHECK(r[120] == 1 && all_zero(r + 121, 3) && r[124] == 3 && all_zero(r + 125, 3));
    CHECK(memcmp(r + 128, m.envelope_set_digest, 32) == 0);
    CHECK(memcmp(r + 160, m.migration_manifest_digest, 32) == 0);
    CHECK(r[192] == 2 && all_zero(r + 193, 7) && r[200] == 1 && all_zero(r + 201, 7));
    /* the signature is plain Ed25519 over domain || body: checked with native/sig directly */
    uint8_t msg[sizeof(DOMAIN) + M5_OWNER_MIG_BODY_LEN];
    memcpy(msg, DOMAIN, sizeof(DOMAIN));
    memcpy(msg + sizeof(DOMAIN), r, M5_OWNER_MIG_BODY_LEN);
    CHECK(aienos_ed25519_verify(r + 208, msg, sizeof msg, TEST_PK) == AIENOS_SIG_OK);
    CHECK(aienos_ed25519_verify(r + 208, r, M5_OWNER_MIG_BODY_LEN, TEST_PK) != AIENOS_SIG_OK); /* domain matters */
}

static void t_wrong_key_refused(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t r[L];
    m5_owner_migration_sign(&m, TEST_SK, r);
    CHECK(VERIFY(r, L, TEST_PK2, &m, 1, &o) == M5_ERR_AUTH);
    CHECK(all_zero(&o, sizeof o));
    /* key id swapped to the verifier's key, signature still by key 1 */
    uint8_t kid2[32];
    sha256_hash(TEST_PK2, 32, kid2);
    memcpy(r + 16, kid2, 32);
    CHECK(VERIFY(r, L, TEST_PK2, &m, 1, &o) == M5_ERR_AUTH);
    /* signed by key 2 over a body that names key 1 */
    uint8_t b[L];
    m5_owner_migration_body(&m, TEST_PK, b);
    raw_sign(b, TEST_SK2);
    CHECK(VERIFY(b, L, TEST_PK, &m, 1, &o) == M5_ERR_AUTH);
    /* validly signed by key 2, verified with key 2, but the body names key 1 */
    CHECK(VERIFY(b, L, TEST_PK2, &m, 1, &o) == M5_ERR_AUTH);
    CHECK(all_zero(&o, sizeof o));
}

static void t_unsigned_refused(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t b[L];
    CHECK(m5_owner_migration_body(&m, TEST_PK, b) == M5_OK);
    CHECK(all_zero(b + 208, 64));
    CHECK(VERIFY(b, L, TEST_PK, &m, 1, &o) == M5_ERR_AUTH);
    CHECK(all_zero(&o, sizeof o));
}

static void t_every_byte_flip_refused(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t r[L];
    m5_owner_migration_sign(&m, TEST_SK, r);
    static const uint8_t flips[] = { 0x01, 0x80 };
    for (size_t i = 0; i < L; i++)
        for (size_t f = 0; f < 2; f++) {
            r[i] ^= flips[f];
            int rc = VERIFY(r, L, TEST_PK, &m, 1, &o);
            if (rc >= 0 || !all_zero(&o, sizeof o)) { printf("  byte %zu flip %02x accepted\n", i, flips[f]); g_fail = 1; }
            r[i] ^= flips[f];
        }
    CHECK(VERIFY(r, L, TEST_PK, &m, 1, &o) == M5_OK);
}

/* A field changed and correctly re-signed by the owner must still be refused
 * when it does not match what the verifier expects. */
static void t_field_mismatch_refused(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t r[L];
#define RESIGNED(stmt, want) do { m5_owner_migration x = m; stmt; m5_owner_migration_sign(&x, TEST_SK, r); \
        CHECK(VERIFY(r, L, TEST_PK, &m, 1, &o) == (want)); CHECK(all_zero(&o, sizeof o)); } while (0)
    RESIGNED(x.source_store_uuid[3] ^= 1, M5_ERR_BINDING);
    RESIGNED(x.dest_store_uuid[15] ^= 1, M5_ERR_BINDING);
    RESIGNED(x.agent_root_id[31] ^= 1, M5_ERR_BINDING);
    RESIGNED(x.source_store_generation = 8, M5_ERR_BINDING);
    RESIGNED(x.source_store_generation = 10, M5_ERR_BINDING);
    RESIGNED(x.store_format_version = 2, M5_ERR_BINDING);
    RESIGNED(x.envelope_count = 2, M5_ERR_BINDING);
    RESIGNED(x.envelope_set_digest[0] ^= 1, M5_ERR_BINDING);
    RESIGNED(x.migration_manifest_digest[0] ^= 1, M5_ERR_BINDING);
    RESIGNED(x.owner_hierarchy_generation = 2, M5_ERR_BINDING);
    RESIGNED(x.identity_class = M5_ID_TEST, M5_ERR_IDENTITY);
    /* migrating a store onto itself, even when the verifier expects it */
    m5_owner_migration s = m;
    memcpy(s.dest_store_uuid, s.source_store_uuid, 16);
    m5_owner_migration_sign(&s, TEST_SK, r);
    CHECK(VERIFY(r, L, TEST_PK, &s, 1, &o) == M5_ERR_BINDING);
#undef RESIGNED
}

static void t_format_refused_even_when_signed(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t b[L];
#define BADFMT(stmt) do { m5_owner_migration_body(&m, TEST_PK, b); stmt; raw_sign(b, TEST_SK); \
        CHECK(VERIFY(b, L, TEST_PK, &m, 1, &o) == M5_ERR_FORMAT); CHECK(all_zero(&o, sizeof o)); } while (0)
    BADFMT(b[7] = '2');
    BADFMT(put16(b + 8, 2));
    BADFMT(put16(b + 8, 0));
    BADFMT(put16(b + 10, 1));
    BADFMT(b[13] = 1);
    BADFMT(b[15] = 0x80);
    BADFMT(b[12] = 0);
    BADFMT(b[12] = 3);
#undef BADFMT
}

static void t_replay_refused(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t r[L];
    m5_owner_migration_sign(&m, TEST_SK, r); /* counter 2 */
    CHECK(VERIFY(r, L, TEST_PK, &m, 0, &o) == M5_OK);
    CHECK(VERIFY(r, L, TEST_PK, &m, 1, &o) == M5_OK);
    CHECK(VERIFY(r, L, TEST_PK, &m, 2, &o) == M5_ERR_REPLAY);
    CHECK(VERIFY(r, L, TEST_PK, &m, 3, &o) == M5_ERR_REPLAY);
    CHECK(VERIFY(r, L, TEST_PK, &m, UINT64_MAX, &o) == M5_ERR_REPLAY);
    CHECK(all_zero(&o, sizeof o));
    /* an older, validly signed record after a newer one was accepted */
    m5_owner_migration n = m; n.migration_counter = 7;
    uint8_t rn[L];
    m5_owner_migration_sign(&n, TEST_SK, rn);
    CHECK(VERIFY(rn, L, TEST_PK, &m, 2, &o) == M5_OK);
    CHECK(VERIFY(r, L, TEST_PK, &m, o.migration_counter, &o) == M5_ERR_REPLAY);
    /* counter 0 can never be accepted */
    m5_owner_migration z = m; z.migration_counter = 0;
    m5_owner_migration_sign(&z, TEST_SK, r);
    CHECK(VERIFY(r, L, TEST_PK, &m, 0, &o) == M5_ERR_REPLAY);
    /* top of the range */
    z.migration_counter = UINT64_MAX;
    m5_owner_migration_sign(&z, TEST_SK, r);
    CHECK(VERIFY(r, L, TEST_PK, &m, UINT64_MAX - 1, &o) == M5_OK);
}

static void t_truncated_and_extended_refused(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t r[2 * L];
    m5_owner_migration_sign(&m, TEST_SK, r);
    memset(r + L, 0, L);
    for (size_t n = 0; n < L; n++) {
        /* exact-size heap copy so ASan sees any read past the given length */
        uint8_t *t = malloc(n ? n : 1);
        memcpy(t, r, n);
        if (VERIFY(t, n, TEST_PK, &m, 1, &o) != M5_ERR_BOUNDS) { printf("  length %zu not refused\n", n); g_fail = 1; }
        free(t);
    }
    CHECK(VERIFY(r, L + 1, TEST_PK, &m, 1, &o) == M5_ERR_BOUNDS);
    CHECK(VERIFY(r, 2 * L, TEST_PK, &m, 1, &o) == M5_ERR_BOUNDS);
    CHECK(all_zero(&o, sizeof o));
    CHECK(VERIFY(r, L, TEST_PK, &m, 1, &o) == M5_OK);
}

static void t_sign_body_refusals(void)
{
    m5_owner_migration m = own_fixture(), o;
    uint8_t b[L];
    m5_owner_migration_body(&m, TEST_PK, b);
    CHECK(m5_owner_migration_sign_body(b, TEST_SK2) == M5_ERR_BINDING); /* key does not match the body */
    CHECK(all_zero(b + 208, 64));
    CHECK(m5_owner_migration_sign_body(b, TEST_SK) == M5_OK);
    CHECK(m5_owner_migration_sign_body(b, TEST_SK) == M5_ERR_FORMAT); /* already signed */
    CHECK(VERIFY(b, L, TEST_PK, &m, 1, &o) == M5_OK);
    m5_owner_migration_body(&m, TEST_PK, b);
    b[0] = 'X';
    CHECK(m5_owner_migration_sign_body(b, TEST_SK) == M5_ERR_FORMAT);
    m5_owner_migration bad = m; bad.identity_class = 0;
    CHECK(m5_owner_migration_body(&bad, TEST_PK, b) == M5_ERR_ARG);
    CHECK(m5_owner_migration_sign(&bad, TEST_SK, b) == M5_ERR_ARG && all_zero(b, L));
    CHECK(m5_owner_migration_verify(NULL, L, TEST_PK, M5_ID_PRODUCTION, &m, 0, &o) == M5_ERR_ARG);
    CHECK(m5_owner_migration_verify(b, L, TEST_PK, M5_ID_PRODUCTION, NULL, 0, &o) == M5_ERR_ARG);
}

static void t_test_class_refused_in_production(void)
{
    m5_owner_migration m = own_fixture(), o;
    m5_owner_migration t = m; t.identity_class = M5_ID_TEST;
    uint8_t r[L];
    m5_owner_migration_sign(&t, TEST_SK, r);
    CHECK(VERIFY(r, L, TEST_PK, &m, 1, &o) == M5_ERR_IDENTITY);
    CHECK(m5_owner_migration_verify(r, L, TEST_PK, M5_ID_TEST, &t, 1, &o) == M5_OK);
    CHECK(m5_owner_migration_verify(r, L, TEST_PK, M5_ID_TEST, &m, 1, &o) == M5_ERR_IDENTITY);
}

static void t_envelope_set_digest(void)
{
    uint8_t d[32], want[32], ids[3][32];
    /* known answer computed independently: SHA-256(domain\0 || n u32 || ids) */
    uint8_t buf[sizeof("AIENOS-M5-ENVSET-V1") + 4 + 96];
    memcpy(buf, "AIENOS-M5-ENVSET-V1", sizeof("AIENOS-M5-ENVSET-V1"));
    put32(buf + sizeof("AIENOS-M5-ENVSET-V1"), 3);
    memcpy(buf + sizeof("AIENOS-M5-ENVSET-V1") + 4, IDS, 96);
    sha256_hash(buf, sizeof buf, want);
    CHECK(m5_envelope_set_digest((const uint8_t (*)[32])IDS, 3, d) == M5_OK && memcmp(d, want, 32) == 0);
    /* empty set is allowed and differs */
    CHECK(m5_envelope_set_digest(NULL, 0, d) == M5_OK && memcmp(d, want, 32) != 0);
    /* a subset differs */
    CHECK(m5_envelope_set_digest((const uint8_t (*)[32])IDS, 2, d) == M5_OK && memcmp(d, want, 32) != 0);
    /* non-canonical: unsorted or duplicate */
    memcpy(ids, IDS, sizeof ids);
    memcpy(ids[0], IDS[1], 32); memcpy(ids[1], IDS[0], 32);
    CHECK(m5_envelope_set_digest((const uint8_t (*)[32])ids, 3, d) == M5_ERR_FORMAT);
    memcpy(ids, IDS, sizeof ids);
    memcpy(ids[2], ids[1], 32);
    CHECK(m5_envelope_set_digest((const uint8_t (*)[32])ids, 3, d) == M5_ERR_FORMAT);
    CHECK(m5_envelope_set_digest(NULL, 1, d) == M5_ERR_ARG);
    /* one byte of one id changes the digest */
    memcpy(ids, IDS, sizeof ids);
    ids[2][31] ^= 1;
    CHECK(m5_envelope_set_digest((const uint8_t (*)[32])ids, 3, d) == M5_OK && memcmp(d, want, 32) != 0);
}

/* ---------- full authorization: MAC'd manifest + owner signature ---------- */
#define AUTH_OWNER(mig, own, last) m5_migration_authorize_owner(mig, M5_MIGRATION_LEN, SK.k_root_auth, own, L, \
        TEST_PK, M5_ID_PRODUCTION, &em, &eo, last, &om, &oo)

static void t_authorize_owner(void)
{
    m5_migration em = mig_fixture(), om;
    m5_owner_migration eo = own_fixture(), oo;
    uint8_t own[L], mig[M5_MIGRATION_LEN];
    memcpy(mig, MIG, sizeof mig);
    m5_owner_migration_sign(&eo, TEST_SK, own);
    CHECK(AUTH_OWNER(mig, own, 1) == M5_OK);
    CHECK(om.migration_counter == 2 && oo.migration_counter == 2 && oo.envelope_count == 3);
    /* replay of both records */
    CHECK(AUTH_OWNER(mig, own, 2) == M5_ERR_REPLAY);
    CHECK(all_zero(&om, sizeof om) && all_zero(&oo, sizeof oo));
    /* owner record from the wrong key */
    uint8_t own2[L];
    m5_owner_migration_sign(&eo, TEST_SK2, own2);
    CHECK(AUTH_OWNER(mig, own2, 1) == M5_ERR_AUTH);
    CHECK(all_zero(&om, sizeof om) && all_zero(&oo, sizeof oo));
    /* manifest under the wrong store key */
    uint8_t migbad[M5_MIGRATION_LEN];
    m5_migration_seal(&em, SK.k_artifact, migbad);
    CHECK(AUTH_OWNER(migbad, own, 1) == M5_ERR_AUTH);
    /* owner signed a different (validly MAC'd) manifest */
    m5_migration other = em; other.source_anchor_counter = 6;
    uint8_t mig_other[M5_MIGRATION_LEN];
    m5_migration_seal(&other, SK.k_root_auth, mig_other);
    em.source_anchor_counter = 6;
    CHECK(AUTH_OWNER(mig_other, own, 1) == M5_ERR_BINDING);
    em.source_anchor_counter = 5;
    /* owner counter differs from the manifest counter */
    m5_owner_migration c = eo; c.migration_counter = 3;
    m5_owner_migration_sign(&c, TEST_SK, own2);
    CHECK(AUTH_OWNER(mig, own2, 1) == M5_ERR_BINDING);
    CHECK(all_zero(&om, sizeof om) && all_zero(&oo, sizeof oo));
    /* owner record disagrees with the manifest on destination */
    m5_owner_migration dd = eo; dd.dest_store_uuid[0] ^= 1;
    m5_owner_migration_sign(&dd, TEST_SK, own2);
    CHECK(AUTH_OWNER(mig, own2, 1) == M5_ERR_BINDING);
    /* migrated envelope set differs from what the verifier holds */
    eo.envelope_set_digest[5] ^= 1;
    CHECK(AUTH_OWNER(mig, own, 1) == M5_ERR_BINDING);
    eo.envelope_set_digest[5] ^= 1;
    /* truncated owner record */
    CHECK(m5_migration_authorize_owner(mig, M5_MIGRATION_LEN, SK.k_root_auth, own, L - 1, TEST_PK,
                                       M5_ID_PRODUCTION, &em, &eo, 1, &om, &oo) == M5_ERR_BOUNDS);
    CHECK(AUTH_OWNER(mig, own, 1) == M5_OK);
}

static const struct { const char *name; void (*fn)(void); } TESTS[] = {
#define T(f) { #f, f }
    T(t_roundtrip), T(t_layout_pinned), T(t_wrong_key_refused), T(t_unsigned_refused),
    T(t_every_byte_flip_refused), T(t_field_mismatch_refused), T(t_format_refused_even_when_signed),
    T(t_replay_refused), T(t_truncated_and_extended_refused), T(t_sign_body_refusals),
    T(t_test_class_refused_in_production), T(t_envelope_set_digest), T(t_authorize_owner),
#undef T
};

int main(void)
{
    int failed = 0;
    fixtures();
    for (size_t i = 0; i < sizeof TESTS / sizeof TESTS[0]; i++) {
        g_fail = 0;
        TESTS[i].fn();
        printf("%s %s\n", g_fail ? "FAIL" : "ok  ", TESTS[i].name);
        if (g_fail) failed++;
    }
    printf("%zu tests, %d failed\n", sizeof TESTS / sizeof TESTS[0], failed);
    printf("AIENOS_M5_MIGRATION_SIG: %s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
