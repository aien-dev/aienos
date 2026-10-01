/* native/m5 tests: key hierarchy, envelopes, corruption matrix,
 * all-or-nothing open, anti-rollback, identity separation, migration,
 * deterministic recovery. Host-only (hosted libc), not QEMU.
 * Last line: "M5_NATIVE: PASS" (exit 0) or "M5_NATIVE: FAIL" (exit 1). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../m5.h"
#include "../../argus/sha256.h"

static int g_fail;
#define CHECK(c) do { if (!(c)) { printf("  check failed: %s (line %d)\n", #c, __LINE__); g_fail = 1; } } while (0)

static int all_zero(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) if (p[i]) return 0; return 1; }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17; return rng_state; }

/* ---------- fixtures ---------- */
#define CS 64u
#define PT_LEN 224u /* 4 chunks: 64, 64, 64, 32 */
#define ENV_LEN (80u + PT_LEN + 4u * 16u)
#define CHUNK_OFF(i) (80u + (i) * (CS + 16u))

static uint8_t K_VOL[32], NONCE8[8], PT[PT_LEN];
static m5_subkeys SK, SK_TEST;
static m5_object_binding OBJ;
static uint8_t ENV[ENV_LEN];
static uint8_t COMMIT[M5_COMMIT_LEN], ANCHOR[M5_ANCHOR_LEN];

static void binding_init(m5_object_binding *b, uint8_t cls)
{
    memset(b, 0, sizeof *b);
    memset(b->store_uuid, 0xA0, 16);
    b->object_kind = 7;
    b->object_version = 1;
    memset(b->object_id, 0xB0, 16);
    b->key_generation = 3;
    b->store_generation = 9;
    b->identity_class = cls;
}

static void make_commit(const m5_object_binding *b, const uint8_t *env, size_t len, uint64_t counter,
                        const uint8_t key[32], uint8_t out[M5_COMMIT_LEN])
{
    m5_commit c;
    memset(&c, 0, sizeof c);
    c.obj = *b;
    c.counter = counter;
    c.object_sequence = 1;
    sha256_hash(env, len, c.envelope_digest);
    m5_commit_seal(&c, key, out);
}

static void make_anchor(uint8_t cls, const uint8_t uuid[16], uint64_t sg, uint64_t kg, uint64_t ctr,
                        const uint8_t commit[M5_COMMIT_LEN], const uint8_t key[32], uint8_t out[M5_ANCHOR_LEN])
{
    m5_anchor a;
    memset(&a, 0, sizeof a);
    a.identity_class = cls;
    memcpy(a.store_uuid, uuid, 16);
    a.store_generation = sg;
    a.key_generation = kg;
    a.counter = ctr;
    sha256_hash(commit, M5_COMMIT_LEN, a.commit_digest);
    m5_anchor_seal(&a, key, out, M5_ANCHOR_LEN);
}

static void fixtures(void)
{
    for (int i = 0; i < 32; i++) K_VOL[i] = (uint8_t)(0x11 + i);
    for (int i = 0; i < 8; i++) NONCE8[i] = (uint8_t)(0xC0 + i);
    for (unsigned i = 0; i < PT_LEN; i++) PT[i] = (uint8_t)(i * 7 + 1);
    m5_derive_subkeys(K_VOL, M5_ID_PRODUCTION, 1, &SK);
    m5_derive_subkeys(K_VOL, M5_ID_TEST, 1, &SK_TEST);
    binding_init(&OBJ, M5_ID_PRODUCTION);
    size_t n = 0;
    if (m5_envelope_seal(SK.k_artifact, &OBJ, NONCE8, CS, PT, PT_LEN, ENV, sizeof ENV, &n) != M5_OK || n != ENV_LEN) {
        printf("fixture seal failed\n");
        g_fail = 1;
    }
    make_commit(&OBJ, ENV, ENV_LEN, 5, SK.k_root_auth, COMMIT);
    make_anchor(M5_ID_PRODUCTION, OBJ.store_uuid, 9, 3, 5, COMMIT, SK.k_root_auth, ANCHOR);
}

/* Open env (copied to an exact-size heap buffer so ASan sees over-reads) and
 * require refusal with an all-zero output. Returns the error code. */
static int open_refused(const uint8_t *env, size_t len, const m5_object_binding *b, uint8_t mode)
{
    uint8_t *e = malloc(len ? len : 1);
    memcpy(e, env, len);
    uint8_t out[1024];
    memset(out, 0xAA, sizeof out);
    size_t n = 77;
    int rc = m5_envelope_open(SK.k_artifact, mode, b, e, len, out, sizeof out, &n);
    CHECK(rc < 0);
    CHECK(n == 0);
    CHECK(all_zero(out, sizeof out));
    free(e);
    return rc;
}

/* ---------- 1. key hierarchy ---------- */
static void t_hkdf_rfc5869_case1(void)
{
    static const uint8_t prk[32] = {0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
                                    0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5};
    static const uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    static const uint8_t okm[42] = {0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
                                    0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
                                    0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65};
    uint8_t out[42];
    CHECK(m5_hkdf_expand(prk, info, sizeof info, out, sizeof out) == M5_OK);
    CHECK(memcmp(out, okm, 42) == 0);
    uint8_t big[1];
    CHECK(m5_hkdf_expand(prk, info, 10, big, 255 * 32 + 1) == M5_ERR_BOUNDS);
}

static void t_subkeys_deterministic_and_separated(void)
{
    m5_subkeys a, b, t, g2, v1;
    CHECK(m5_derive_subkeys(K_VOL, M5_ID_PRODUCTION, 1, &a) == M5_OK);
    CHECK(m5_derive_subkeys(K_VOL, M5_ID_PRODUCTION, 1, &b) == M5_OK);
    CHECK(memcmp(&a, &b, sizeof a) == 0);
    CHECK(memcmp(a.k_cortex, a.k_agent, 32) && memcmp(a.k_agent, a.k_artifact, 32) &&
          memcmp(a.k_artifact, a.k_root_auth, 32) && memcmp(a.k_cortex, a.k_root_auth, 32));
    m5_derive_subkeys(K_VOL, M5_ID_TEST, 1, &t);
    CHECK(memcmp(a.k_root_auth, t.k_root_auth, 32) != 0);
    CHECK(memcmp(a.k_artifact, t.k_artifact, 32) != 0);
    m5_derive_subkeys(K_VOL, M5_ID_PRODUCTION, 2, &g2);
    CHECK(memcmp(a.k_root_auth, g2.k_root_auth, 32) != 0);
    m5_derive_subkeys_v1(K_VOL, &v1);
    CHECK(memcmp(a.k_root_auth, v1.k_root_auth, 32) != 0);
    CHECK(m5_derive_subkeys(K_VOL, 0, 1, &b) == M5_ERR_ARG);
    CHECK(m5_derive_subkeys(K_VOL, 3, 1, &b) == M5_ERR_ARG);
    m5_subkeys_wipe(&a);
    CHECK(all_zero((uint8_t *)&a, sizeof a));
}

static void t_object_key_binds_every_field(void)
{
    uint8_t base[32], k[32];
    m5_derive_object_key(SK.k_artifact, &OBJ, base);
    for (int f = 0; f < 7; f++) {
        m5_object_binding b = OBJ;
        switch (f) {
        case 0: b.store_uuid[3] ^= 1; break;
        case 1: b.object_kind++; break;
        case 2: b.object_version++; break;
        case 3: b.object_id[15] ^= 1; break;
        case 4: b.key_generation++; break;
        case 5: b.store_generation++; break;
        case 6: b.identity_class = M5_ID_TEST; break;
        }
        m5_derive_object_key(SK.k_artifact, &b, k);
        CHECK(memcmp(base, k, 32) != 0);
    }
}

static m5_keyslot slot_fixture(void)
{
    m5_keyslot s;
    memset(&s, 0, sizeof s);
    s.slot_type = M5_SLOT_RECOVERY_RAW_SECRET;
    s.slot_id = 1;
    s.key_epoch = 3;
    return s;
}

static void t_keyslot_wrap_unwrap(void)
{
    uint8_t kek[32], nonce[12], uuid[16], kv[32], enc[M5_KEYSLOT_LEN];
    memset(kek, 0x42, 32); memset(nonce, 0x24, 12); memset(uuid, 0xA0, 16);
    m5_keyslot s = slot_fixture(), d;
    CHECK(m5_keyslot_wrap(&s, uuid, kek, K_VOL, nonce) == M5_OK);
    m5_keyslot_encode(&s, enc);
    CHECK(m5_keyslot_decode(enc, sizeof enc, &d) == M5_OK);
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_OK);
    CHECK(memcmp(kv, K_VOL, 32) == 0);
    CHECK(memcmp(K_VOL + 0, enc + 56, 32) != 0); /* wrapped, not plain */
}

static void t_keyslot_refusals(void)
{
    uint8_t kek[32], bad[32], nonce[12], uuid[16], uuid2[16], kv[32], enc[M5_KEYSLOT_LEN];
    memset(kek, 0x42, 32); memset(bad, 0x43, 32); memset(nonce, 0x24, 12);
    memset(uuid, 0xA0, 16); memset(uuid2, 0xA1, 16);
    m5_keyslot s = slot_fixture(), d;
    m5_keyslot_wrap(&s, uuid, kek, K_VOL, nonce);
    memset(kv, 0x55, 32);
    CHECK(m5_keyslot_unwrap(&s, uuid, bad, kv) == M5_ERR_AUTH && all_zero(kv, 32));
    CHECK(m5_keyslot_unwrap(&s, uuid2, kek, kv) == M5_ERR_AUTH && all_zero(kv, 32));
    d = s; d.slot_id = 2;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_AUTH);
    d = s; d.key_epoch = 4;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_AUTH);
    d = s; d.wrap_tag[0] ^= 1;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_AUTH);
    d = s; d.slot_type = M5_SLOT_EMPTY;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_FORMAT);
    d = s; d.wrap_suite = 2;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_FORMAT);
    /* in-memory descriptor values the decoder would refuse; wrap with an
     * unknown type cannot be produced by m5_keyslot_wrap, so build it by hand */
    d = s; d.argon_t_cost = 11;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_BOUNDS && all_zero(kv, 32));
    d = s; d.slot_type = 9;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_FORMAT);
    m5_keyslot_encode(&s, enc);
    CHECK(m5_keyslot_decode(enc, sizeof enc - 1, &d) == M5_ERR_BOUNDS);
    enc[0] = 9; CHECK(m5_keyslot_decode(enc, sizeof enc, &d) == M5_ERR_FORMAT); enc[0] = 3;
    put32(enc + 32, 131073); CHECK(m5_keyslot_decode(enc, sizeof enc, &d) == M5_ERR_BOUNDS); put32(enc + 32, 0);
    enc[120] = 1; CHECK(m5_keyslot_decode(enc, sizeof enc, &d) == M5_ERR_FORMAT);
    enc[120] = 0;
    enc[1] = 2; CHECK(m5_keyslot_decode(enc, sizeof enc, &d) == M5_ERR_FORMAT); enc[1] = 1;
    enc[2] = 3; CHECK(m5_keyslot_decode(enc, sizeof enc, &d) == M5_ERR_FORMAT); enc[2] = 0;
    enc[3] = 1; CHECK(m5_keyslot_decode(enc, sizeof enc, &d) == M5_ERR_FORMAT); enc[3] = 0;
    CHECK(m5_keyslot_decode(enc, sizeof enc, &d) == M5_OK);
    d = s; d.kdf_suite = 3;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_FORMAT);
    d = s; d.flags = 0x80;
    CHECK(m5_keyslot_unwrap(&d, uuid, kek, kv) == M5_ERR_FORMAT);
}

static m5_secman secman_fixture(uint8_t cls)
{
    m5_secman m;
    memset(&m, 0, sizeof m);
    m.identity_class = cls;
    memset(m.store_uuid, 0xA0, 16);
    m.generation = 9; m.security_sequence = 4; m.epoch = 5; m.key_epoch = 3;
    m.owner_hierarchy_generation = 1;
    memset(m.keyslot_manifest_id, 0x31, 32);
    memset(m.agent_root_id, 0x32, 32);
    return m;
}

static void t_secman_roundtrip_and_owner_generation_field(void)
{
    m5_secman m = secman_fixture(M5_ID_PRODUCTION), o;
    uint8_t buf[M5_SECMAN_LEN];
    CHECK(m5_secman_seal(&m, SK.k_root_auth, buf) == M5_OK);
    CHECK(m5_secman_open(buf, sizeof buf, SK.k_root_auth, M5_ID_PRODUCTION, &o) == M5_OK);
    CHECK(o.owner_hierarchy_generation == 1 && o.generation == 9 && o.key_epoch == 3);
    CHECK(memcmp(o.root_mac, m.root_mac, 32) == 0);
}

static void t_secman_wrong_root_auth_key_refused(void)
{
    m5_secman m = secman_fixture(M5_ID_PRODUCTION), o;
    uint8_t buf[M5_SECMAN_LEN];
    m5_secman_seal(&m, SK.k_root_auth, buf);
    m5_subkeys g2, other;
    m5_derive_subkeys(K_VOL, M5_ID_PRODUCTION, 2, &g2); /* other owner hierarchy generation */
    uint8_t kv2[32]; memset(kv2, 0x99, 32);
    m5_derive_subkeys(kv2, M5_ID_PRODUCTION, 1, &other); /* other volume */
    CHECK(m5_secman_open(buf, sizeof buf, g2.k_root_auth, M5_ID_PRODUCTION, &o) == M5_ERR_AUTH);
    CHECK(m5_secman_open(buf, sizeof buf, other.k_root_auth, M5_ID_PRODUCTION, &o) == M5_ERR_AUTH);
    CHECK(m5_secman_open(buf, sizeof buf, SK.k_artifact, M5_ID_PRODUCTION, &o) == M5_ERR_AUTH);
}

static void t_secman_every_byte_tamper_refused(void)
{
    m5_secman m = secman_fixture(M5_ID_PRODUCTION), o;
    uint8_t buf[M5_SECMAN_LEN];
    m5_secman_seal(&m, SK.k_root_auth, buf);
    for (size_t i = 0; i < sizeof buf; i++) {
        buf[i] ^= 0x01;
        CHECK(m5_secman_open(buf, sizeof buf, SK.k_root_auth, M5_ID_PRODUCTION, &o) < 0);
        buf[i] ^= 0x01;
    }
    CHECK(m5_secman_open(buf, sizeof buf - 1, SK.k_root_auth, M5_ID_PRODUCTION, &o) == M5_ERR_BOUNDS);
}


/* The C v2 manifest is a separate format: its own magic, and a Rust kind-22
 * v1 shaped buffer (256 bytes, "AIENSEC1") is refused, never misread. */
static void t_secman_distinct_from_rust_v1(void)
{
    m5_secman m = secman_fixture(M5_ID_PRODUCTION), o;
    uint8_t buf[M5_SECMAN_LEN];
    m5_secman_seal(&m, SK.k_root_auth, buf);
    CHECK(memcmp(buf, "AIENSEC2", 8) == 0);
    CHECK(memcmp(buf, "AIENSEC1", 8) != 0);
    uint8_t v1[256];
    memcpy(v1, buf, sizeof v1);
    memcpy(v1, "AIENSEC1", 8);
    v1[8] = 1; v1[9] = 0;
    CHECK(m5_secman_open(v1, sizeof v1, SK.k_root_auth, M5_ID_PRODUCTION, &o) == M5_ERR_BOUNDS);
    uint8_t relabeled[M5_SECMAN_LEN];
    memcpy(relabeled, buf, sizeof relabeled);
    memcpy(relabeled, "AIENSEC1", 8);
    CHECK(m5_secman_open(relabeled, sizeof relabeled, SK.k_root_auth, M5_ID_PRODUCTION, &o) == M5_ERR_FORMAT);
}
/* ---------- 2. envelopes ---------- */
static void t_env_roundtrip_sizes(void)
{
    static const size_t sizes[] = {0, 1, 63, 64, 65, 224, 1000};
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        size_t len = m5_envelope_len(sizes[k], CS);
        uint8_t *env = malloc(len), *pt = malloc(sizes[k] + 1), *out = malloc(sizes[k] + 1);
        for (size_t i = 0; i < sizes[k]; i++) pt[i] = (uint8_t)rnd();
        size_t n = 0, m = 0;
        CHECK(m5_envelope_seal(SK.k_artifact, &OBJ, NONCE8, CS, pt, sizes[k], env, len, &n) == M5_OK && n == len);
        CHECK(m5_envelope_open(SK.k_artifact, M5_ID_PRODUCTION, &OBJ, env, n, out, sizes[k] + 1, &m) == M5_OK);
        CHECK(m == sizes[k] && memcmp(out, pt, m) == 0);
        free(env); free(pt); free(out);
    }
    /* default 64 KiB chunking, 3 chunks */
    size_t pl = 150000, len = m5_envelope_len(pl, M5_ENV_MAX_CHUNK);
    uint8_t *env = malloc(len), *pt = malloc(pl), *out = malloc(pl);
    memset(pt, 0x5A, pl);
    size_t n = 0, m = 0;
    CHECK(len == 80 + pl + 3 * 16);
    CHECK(m5_envelope_seal(SK.k_artifact, &OBJ, NONCE8, M5_ENV_MAX_CHUNK, pt, pl, env, len, &n) == M5_OK);
    CHECK(m5_envelope_open(SK.k_artifact, M5_ID_PRODUCTION, &OBJ, env, n, out, pl, &m) == M5_OK && m == pl);
    CHECK(memcmp(out, pt, pl) == 0);
    free(env); free(pt); free(out);
    CHECK(m5_envelope_len(M5_ENV_MAX_PLAINTEXT + 1, M5_ENV_MAX_CHUNK) == 0);
    CHECK(m5_envelope_len(10, 0) == 0 && m5_envelope_len(10, M5_ENV_MAX_CHUNK + 1) == 0);
    CHECK(m5_envelope_len(M5_ENV_MAX_CHUNKS + 1, 1) == 0);
}

static void t_env_header_bounds_each_field(void)
{
    uint8_t e[ENV_LEN];
    struct { size_t off; int width; uint64_t v; } edges[] = {
        {16, 4, 0}, {16, 4, M5_ENV_MAX_CHUNK + 1}, {16, 4, 0xFFFFFFFFu}, {16, 4, 1},
        {20, 8, 0}, {20, 8, PT_LEN + 1}, {20, 8, M5_ENV_MAX_PLAINTEXT + 1}, {20, 8, UINT64_MAX},
        {20, 8, UINT64_MAX - 15},
        {68, 4, 0}, {68, 4, 3}, {68, 4, 5}, {68, 4, M5_ENV_MAX_CHUNKS + 1}, {68, 4, 0xFFFFFFFFu},
        {8, 2, 1}, {10, 2, 2}, {12, 4, 1}, {72, 1, 0}, {72, 1, 3}, {73, 1, 1}, {79, 1, 0x80},
    };
    for (size_t k = 0; k < sizeof edges / sizeof edges[0]; k++) {
        memcpy(e, ENV, ENV_LEN);
        if (edges[k].width == 8) put64(e + edges[k].off, edges[k].v);
        else if (edges[k].width == 4) put32(e + edges[k].off, (uint32_t)edges[k].v);
        else if (edges[k].width == 2) { e[edges[k].off] = (uint8_t)edges[k].v; e[edges[k].off + 1] = 0; }
        else e[edges[k].off] = (uint8_t)edges[k].v;
        open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION);
    }
    m5_env_header h;
    memcpy(e, ENV, ENV_LEN);
    put32(e + 68, 3); /* count disagrees with total/chunk_size */
    CHECK(m5_envelope_parse_header(e, ENV_LEN, &h) == M5_ERR_BOUNDS);
    CHECK(m5_envelope_parse_header(ENV, ENV_LEN + 1, &h) == M5_ERR_BOUNDS);
    CHECK(m5_envelope_parse_header(ENV, ENV_LEN - 1, &h) == M5_ERR_BOUNDS);
    CHECK(m5_envelope_parse_header(ENV, 79, &h) == M5_ERR_BOUNDS);
    CHECK(m5_envelope_parse_header(ENV, ENV_LEN, &h) == M5_OK && h.chunk_count == 4);
    /* a trailing byte must not be ignored */
    uint8_t big[ENV_LEN + 1];
    memcpy(big, ENV, ENV_LEN); big[ENV_LEN] = 0;
    CHECK(open_refused(big, sizeof big, &OBJ, M5_ID_PRODUCTION) == M5_ERR_BOUNDS);
    put32(e + 68, 3);
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_BOUNDS);
}

static void t_env_hostile_header_fuzz(void)
{
    static const uint64_t edge[] = {0, 1, 2, 15, 16, 63, 64, 65, 79, 80, 4095, 4096, 4097, 65535, 65536, 65537,
                                    0x7FFFFFFF, 0xFFFFFFFF, 0x100000000ull, M5_ENV_MAX_PLAINTEXT,
                                    M5_ENV_MAX_PLAINTEXT + 1, UINT64_MAX - 1, UINT64_MAX};
    const size_t ne = sizeof edge / sizeof edge[0];
    uint8_t tmp[1024];
    unsigned accepted = 0;
    for (int it = 0; it < 20000; it++) {
        size_t len = ENV_LEN;
        memcpy(tmp, ENV, ENV_LEN);
        switch (it % 5) {
        case 0: for (int j = 1 + (int)(rnd() % 4); j > 0; j--) tmp[rnd() % 80] ^= (uint8_t)(1 + rnd() % 255); break;
        case 1: { static const size_t off[] = {16, 20, 68}; size_t o = off[rnd() % 3];
                  if (o == 20) put64(tmp + o, edge[rnd() % ne]); else put32(tmp + o, (uint32_t)edge[rnd() % ne]); } break;
        case 2: len = (size_t)(rnd() % sizeof tmp); for (size_t i = ENV_LEN; i < len; i++) tmp[i] = (uint8_t)rnd(); break;
        case 3: len = (size_t)(rnd() % sizeof tmp); for (size_t i = 0; i < len; i++) tmp[i] = (uint8_t)rnd();
                if (len >= 8) { memcpy(tmp, "AIENENV1", 8); }
                break;
        case 4: put32(tmp + 16, (uint32_t)edge[rnd() % ne]); put64(tmp + 20, edge[rnd() % ne]);
                put32(tmp + 68, (uint32_t)edge[rnd() % ne]); len = (size_t)(rnd() % sizeof tmp); break;
        }
        if (len == ENV_LEN && memcmp(tmp, ENV, ENV_LEN) == 0) continue;
        uint8_t *e = malloc(len ? len : 1);
        memcpy(e, tmp, len);
        uint8_t out[300];
        memset(out, 0xAA, sizeof out);
        size_t n = 1;
        int rc = m5_envelope_open(SK.k_artifact, M5_ID_PRODUCTION, &OBJ, e, len, out, sizeof out, &n);
        if (rc == M5_OK) accepted++;
        CHECK(rc < 0);
        if (rc < 0) { CHECK(n == 0); CHECK(all_zero(out, sizeof out)); }
        m5_env_header h;
        (void)m5_envelope_parse_header(e, len, &h);
        free(e);
    }
    CHECK(accepted == 0);
}

/* ---------- 3. all-or-nothing ---------- */
static void t_all_or_nothing_late_chunk_failure_zeroes_output(void)
{
    uint8_t e[ENV_LEN];
    for (unsigned c = 0; c < 4; c++) {
        memcpy(e, ENV, ENV_LEN);
        e[CHUNK_OFF(c) + 5] ^= 0x10; /* chunks before c verify, c fails */
        CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
    }
    /* output buffer larger than plaintext: the whole buffer is zero, not just the prefix */
    memcpy(e, ENV, ENV_LEN);
    e[CHUNK_OFF(3) + 40] ^= 1; /* last chunk tag */
    uint8_t out[4096];
    memset(out, 0xEE, sizeof out);
    size_t n = 5;
    CHECK(m5_envelope_open(SK.k_artifact, M5_ID_PRODUCTION, &OBJ, e, ENV_LEN, out, sizeof out, &n) == M5_ERR_AUTH);
    CHECK(n == 0 && all_zero(out, sizeof out));
    /* too-small output is refused before any plaintext is written */
    memset(out, 0xEE, sizeof out);
    CHECK(m5_envelope_open(SK.k_artifact, M5_ID_PRODUCTION, &OBJ, ENV, ENV_LEN, out, PT_LEN - 1, &n) == M5_ERR_SPACE);
    CHECK(all_zero(out, PT_LEN - 1));
}

/* ---------- 4. corruption matrix ---------- */
static void t_corrupt_header(void)
{
    uint8_t e[ENV_LEN];
    /* bytes that pass every structural check: object id, nonce prefix */
    memcpy(e, ENV, ENV_LEN); e[44] ^= 1;
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
    memcpy(e, ENV, ENV_LEN); e[0] ^= 1;
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_FORMAT);
}
static void corrupt_chunk(unsigned c)
{
    uint8_t e[ENV_LEN];
    memcpy(e, ENV, ENV_LEN); e[CHUNK_OFF(c)] ^= 0x80;
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
}
static void t_corrupt_first_chunk(void) { corrupt_chunk(0); }
static void t_corrupt_middle_chunk(void) { corrupt_chunk(1); corrupt_chunk(2); }
static void t_corrupt_last_chunk(void) { corrupt_chunk(3); }

static int recover(const uint8_t *commit, const uint8_t *anchor, size_t alen, const m5_candidate *c, size_t n,
                   uint8_t *out, size_t cap, size_t *chosen)
{
    size_t ol = 9;
    memset(out, 0xAA, cap);
    int rc = m5_recover_object(SK.k_root_auth, SK.k_artifact, M5_ID_PRODUCTION, OBJ.store_uuid,
                               commit, M5_COMMIT_LEN, anchor, alen, c, n, out, cap, &ol, chosen);
    if (rc < 0) { CHECK(ol == 0); CHECK(all_zero(out, cap)); CHECK(*chosen == SIZE_MAX); }
    else CHECK(ol == PT_LEN);
    return rc;
}

static void t_corrupt_commit_record(void)
{
    m5_candidate c[1] = {{ENV, ENV_LEN}};
    uint8_t out[PT_LEN]; size_t ch;
    uint8_t bad[M5_COMMIT_LEN];
    for (size_t i = 0; i < M5_COMMIT_LEN; i++) {
        memcpy(bad, COMMIT, sizeof bad); bad[i] ^= 0x04;
        CHECK(recover(bad, ANCHOR, M5_ANCHOR_LEN, c, 1, out, sizeof out, &ch) < 0);
    }
    memcpy(bad, COMMIT, sizeof bad); bad[90] ^= 1; /* envelope digest field */
    CHECK(recover(bad, ANCHOR, M5_ANCHOR_LEN, c, 1, out, sizeof out, &ch) == M5_ERR_AUTH);
    m5_commit co;
    CHECK(m5_commit_open(bad, sizeof bad, SK.k_root_auth, M5_ID_PRODUCTION, &co) == M5_ERR_AUTH);
}

static void t_corrupt_rollback_anchor(void)
{
    m5_candidate c[1] = {{ENV, ENV_LEN}};
    uint8_t out[PT_LEN]; size_t ch;
    uint8_t bad[M5_ANCHOR_LEN];
    for (size_t i = 0; i < M5_ANCHOR_LEN; i++) {
        memcpy(bad, ANCHOR, sizeof bad); bad[i] ^= 0x02;
        CHECK(recover(COMMIT, bad, M5_ANCHOR_LEN, c, 1, out, sizeof out, &ch) < 0);
    }
    memcpy(bad, ANCHOR, sizeof bad); bad[48] ^= 1; /* counter */
    m5_anchor a;
    CHECK(m5_anchor_open(bad, sizeof bad, SK.k_root_auth, M5_ID_PRODUCTION, &a) == M5_ERR_AUTH);
    CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN - 1, c, 1, out, sizeof out, &ch) == M5_ERR_BOUNDS);
}

static void t_corrupt_key_generation(void)
{
    uint8_t e[ENV_LEN];
    memcpy(e, ENV, ENV_LEN); put64(e + 52, 4);
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_BINDING);
    m5_object_binding b = OBJ; b.key_generation = 4; /* attacker also relabels the expectation */
    CHECK(open_refused(e, ENV_LEN, &b, M5_ID_PRODUCTION) == M5_ERR_AUTH);
    CHECK(open_refused(ENV, ENV_LEN, &b, M5_ID_PRODUCTION) == M5_ERR_BINDING);
}

static void t_corrupt_store_generation(void)
{
    uint8_t e[ENV_LEN];
    memcpy(e, ENV, ENV_LEN); put64(e + 60, 8);
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_BINDING);
    m5_object_binding b = OBJ; b.store_generation = 8;
    CHECK(open_refused(e, ENV_LEN, &b, M5_ID_PRODUCTION) == M5_ERR_AUTH);
    CHECK(open_refused(ENV, ENV_LEN, &b, M5_ID_PRODUCTION) == M5_ERR_BINDING);
}

static void t_truncate_drop_last_chunk(void)
{
    uint8_t e[ENV_LEN];
    size_t tl = CHUNK_OFF(3);
    CHECK(open_refused(ENV, tl, &OBJ, M5_ID_PRODUCTION) == M5_ERR_BOUNDS);
    memcpy(e, ENV, tl); put64(e + 20, 192); put32(e + 68, 3); /* header rewritten to match */
    CHECK(open_refused(e, tl, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
}

static void t_extend_append_chunk(void)
{
    uint8_t e[ENV_LEN + CS + 16];
    memcpy(e, ENV, ENV_LEN);
    memcpy(e + ENV_LEN, ENV + CHUNK_OFF(0), CS + 16);
    CHECK(open_refused(e, sizeof e, &OBJ, M5_ID_PRODUCTION) == M5_ERR_BOUNDS);
    /* rewrite the last chunk position: 4 full chunks + appended chunk 0 as #5 */
    uint8_t f[80 + 5 * (CS + 16)];
    memset(f, 0, sizeof f);
    memcpy(f, ENV, ENV_LEN);
    memcpy(f + CHUNK_OFF(4), ENV + CHUNK_OFF(0), CS + 16);
    put64(f + 20, 4 * CS + CS); put32(f + 68, 5);
    CHECK(open_refused(f, sizeof f, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
}

static void t_reorder_chunks(void)
{
    uint8_t e[ENV_LEN];
    memcpy(e, ENV, ENV_LEN);
    memcpy(e + CHUNK_OFF(1), ENV + CHUNK_OFF(2), CS + 16);
    memcpy(e + CHUNK_OFF(2), ENV + CHUNK_OFF(1), CS + 16);
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
}

static void t_splice_cross_object(void)
{
    m5_object_binding b2 = OBJ;
    b2.object_id[0] ^= 0xFF;
    uint8_t env2[ENV_LEN], e[ENV_LEN];
    size_t n;
    CHECK(m5_envelope_seal(SK.k_artifact, &b2, NONCE8, CS, PT, PT_LEN, env2, sizeof env2, &n) == M5_OK);
    /* whole envelope of object 2 presented as object 1 */
    CHECK(open_refused(env2, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_BINDING);
    /* one chunk of object 2 spliced into object 1 (same nonce prefix, same plaintext) */
    memcpy(e, ENV, ENV_LEN);
    memcpy(e + CHUNK_OFF(1), env2 + CHUNK_OFF(1), CS + 16);
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
    /* chunk from another store generation of the same object */
    m5_object_binding b3 = OBJ; b3.store_generation = 10;
    uint8_t env3[ENV_LEN];
    m5_envelope_seal(SK.k_artifact, &b3, NONCE8, CS, PT, PT_LEN, env3, sizeof env3, &n);
    memcpy(e, ENV, ENV_LEN);
    memcpy(e + CHUNK_OFF(2), env3 + CHUNK_OFF(2), CS + 16);
    CHECK(open_refused(e, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
    /* other object kind or store uuid */
    m5_object_binding b4 = OBJ; b4.object_kind = 8;
    CHECK(open_refused(ENV, ENV_LEN, &b4, M5_ID_PRODUCTION) == M5_ERR_AUTH);
    b4 = OBJ; b4.store_uuid[0] ^= 1;
    CHECK(open_refused(ENV, ENV_LEN, &b4, M5_ID_PRODUCTION) == M5_ERR_AUTH);
}

/* ---------- 5. anti-rollback ---------- */
static m5_disk_state disk_now(void)
{
    m5_disk_state d;
    d.store_generation = 9; d.key_generation = 3; d.counter = 5;
    sha256_hash(COMMIT, M5_COMMIT_LEN, d.commit_digest);
    return d;
}
#define EVAL(buf, len, gen, d) m5_evaluate_anti_rollback(SK.k_root_auth, M5_ID_PRODUCTION, OBJ.store_uuid, buf, len, gen, d)

static void t_anchor_caller_buffer_roundtrip(void)
{
    m5_anchor a, o;
    memset(&a, 0, sizeof a);
    a.identity_class = M5_ID_PRODUCTION; memcpy(a.store_uuid, OBJ.store_uuid, 16);
    a.store_generation = 9; a.key_generation = 3; a.counter = 5;
    uint8_t buf[M5_ANCHOR_LEN];
    CHECK(m5_anchor_seal(&a, SK.k_root_auth, buf, sizeof buf - 1) == M5_ERR_SPACE);
    CHECK(m5_anchor_seal(&a, SK.k_root_auth, buf, sizeof buf) == M5_OK);
    CHECK(m5_anchor_open(buf, sizeof buf, SK.k_root_auth, M5_ID_PRODUCTION, &o) == M5_OK);
    CHECK(o.counter == 5 && o.store_generation == 9 && o.key_generation == 3);
}

static void t_rb_valid_resume_and_advance(void)
{
    m5_disk_state d = disk_now();
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_RB_VALID_RESUME);
    d.counter = 6; d.store_generation = 10; d.commit_digest[0] ^= 1;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_RB_PREPARED_ADVANCE);
    d.key_generation = 4;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_RB_PREPARED_ADVANCE);
}

static void t_rb_older_store_generation_refused(void)
{
    m5_disk_state d = disk_now();
    d.store_generation = 8; d.counter = 6;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_ERR_ROLLBACK);
}
static void t_rb_older_key_generation_refused(void)
{
    m5_disk_state d = disk_now();
    d.key_generation = 2; d.counter = 6;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_ERR_ROLLBACK);
}
static void t_rb_lower_counter_refused(void)
{
    m5_disk_state d = disk_now();
    d.counter = 4;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_ERR_ROLLBACK);
    d.counter = 0;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_ERR_ROLLBACK);
}
static void t_rb_fork_at_same_counter_refused(void)
{
    m5_disk_state d = disk_now();
    d.commit_digest[31] ^= 1;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_ERR_ROLLBACK);
    d = disk_now(); d.store_generation = 10;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_ERR_ROLLBACK);
}
static void t_rb_counter_jump_inconsistent(void)
{
    m5_disk_state d = disk_now();
    d.counter = 7;
    CHECK(EVAL(ANCHOR, M5_ANCHOR_LEN, 0, &d) == M5_ERR_INCONSISTENT);
    /* anchor at the counter ceiling: counter 0 is a rollback, not a wrapped advance */
    uint8_t top[M5_ANCHOR_LEN];
    make_anchor(M5_ID_PRODUCTION, OBJ.store_uuid, 9, 3, UINT64_MAX, COMMIT, SK.k_root_auth, top);
    d = disk_now(); d.counter = 0;
    CHECK(EVAL(top, M5_ANCHOR_LEN, 0, &d) == M5_ERR_ROLLBACK);
}
static void t_rb_forged_anchor_refused(void)
{
    m5_disk_state d = disk_now();
    uint8_t forged[M5_ANCHOR_LEN];
    uint8_t fake[32]; memset(fake, 0x77, 32);
    make_anchor(M5_ID_PRODUCTION, OBJ.store_uuid, 0, 0, 0, COMMIT, fake, forged); /* attacker lowers the anchor */
    d.counter = 1; d.store_generation = 1; d.key_generation = 1;
    CHECK(EVAL(forged, M5_ANCHOR_LEN, 0, &d) == M5_ERR_AUTH);
    make_anchor(M5_ID_PRODUCTION, OBJ.store_uuid, 9, 3, 5, COMMIT, SK.k_artifact, forged); /* wrong subkey */
    d = disk_now();
    CHECK(EVAL(forged, M5_ANCHOR_LEN, 0, &d) == M5_ERR_AUTH);
}
static void t_rb_missing_anchor_and_genesis(void)
{
    m5_disk_state d = disk_now();
    CHECK(EVAL(NULL, 0, 0, &d) == M5_ERR_ROLLBACK);
    CHECK(EVAL(NULL, 0, 1, &d) == M5_RB_GENESIS);
}
static void t_rb_anchor_other_store_refused(void)
{
    uint8_t other[16], a2[M5_ANCHOR_LEN];
    memset(other, 0xA7, 16);
    make_anchor(M5_ID_PRODUCTION, other, 9, 3, 5, COMMIT, SK.k_root_auth, a2);
    m5_disk_state d = disk_now();
    CHECK(EVAL(a2, M5_ANCHOR_LEN, 0, &d) == M5_ERR_BINDING);
}

/* ---------- 6. identity separation ---------- */
static void t_identity_production_refuses_test(void)
{
    m5_object_binding tb; binding_init(&tb, M5_ID_TEST);
    uint8_t env[ENV_LEN]; size_t n;
    CHECK(m5_envelope_seal(SK.k_artifact, &tb, NONCE8, CS, PT, PT_LEN, env, sizeof env, &n) == M5_OK);
    /* production mode, header TEST, caller expects PRODUCTION */
    CHECK(open_refused(env, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_IDENTITY);
    /* production mode, caller expectation TEST */
    CHECK(open_refused(env, ENV_LEN, &tb, M5_ID_PRODUCTION) == M5_ERR_IDENTITY);
    /* header PRODUCTION but expectation TEST in production mode */
    CHECK(open_refused(ENV, ENV_LEN, &tb, M5_ID_PRODUCTION) == M5_ERR_IDENTITY);
    /* TEST manifest, commit, anchor under the same key are refused in production */
    m5_secman m = secman_fixture(M5_ID_TEST), o;
    uint8_t sb[M5_SECMAN_LEN];
    m5_secman_seal(&m, SK.k_root_auth, sb);
    CHECK(m5_secman_open(sb, sizeof sb, SK.k_root_auth, M5_ID_PRODUCTION, &o) == M5_ERR_IDENTITY);
    uint8_t cb[M5_COMMIT_LEN], ab[M5_ANCHOR_LEN];
    m5_commit co; m5_anchor ao;
    make_commit(&tb, env, ENV_LEN, 5, SK.k_root_auth, cb);
    CHECK(m5_commit_open(cb, sizeof cb, SK.k_root_auth, M5_ID_PRODUCTION, &co) == M5_ERR_IDENTITY);
    make_anchor(M5_ID_TEST, OBJ.store_uuid, 9, 3, 5, cb, SK.k_root_auth, ab);
    CHECK(m5_anchor_open(ab, sizeof ab, SK.k_root_auth, M5_ID_PRODUCTION, &ao) == M5_ERR_IDENTITY);
}

static void t_identity_test_refuses_production(void)
{
    m5_object_binding tb; binding_init(&tb, M5_ID_TEST);
    uint8_t out[PT_LEN]; size_t n = 1;
    memset(out, 0xAA, sizeof out);
    CHECK(m5_envelope_open(SK.k_artifact, M5_ID_TEST, &tb, ENV, ENV_LEN, out, sizeof out, &n) == M5_ERR_IDENTITY);
    CHECK(all_zero(out, sizeof out));
    m5_secman m = secman_fixture(M5_ID_PRODUCTION), o;
    uint8_t sb[M5_SECMAN_LEN];
    m5_secman_seal(&m, SK.k_root_auth, sb);
    CHECK(m5_secman_open(sb, sizeof sb, SK.k_root_auth, M5_ID_TEST, &o) == M5_ERR_IDENTITY);
    m5_commit co;
    CHECK(m5_commit_open(COMMIT, M5_COMMIT_LEN, SK.k_root_auth, M5_ID_TEST, &co) == M5_ERR_IDENTITY);
    /* a TEST-hierarchy store works in TEST mode */
    m5_secman t = secman_fixture(M5_ID_TEST);
    m5_secman_seal(&t, SK_TEST.k_root_auth, sb);
    CHECK(m5_secman_open(sb, sizeof sb, SK_TEST.k_root_auth, M5_ID_TEST, &o) == M5_OK);
}

static void t_identity_relabel_breaks_mac(void)
{
    m5_secman t = secman_fixture(M5_ID_TEST), o;
    uint8_t sb[M5_SECMAN_LEN];
    m5_secman_seal(&t, SK_TEST.k_root_auth, sb);
    sb[12] = M5_ID_PRODUCTION;
    CHECK(m5_secman_open(sb, sizeof sb, SK_TEST.k_root_auth, M5_ID_PRODUCTION, &o) == M5_ERR_AUTH);
    CHECK(m5_secman_open(sb, sizeof sb, SK.k_root_auth, M5_ID_PRODUCTION, &o) == M5_ERR_AUTH);
    /* relabel a TEST envelope as PRODUCTION */
    m5_object_binding tb; binding_init(&tb, M5_ID_TEST);
    uint8_t env[ENV_LEN]; size_t n;
    m5_envelope_seal(SK_TEST.k_artifact, &tb, NONCE8, CS, PT, PT_LEN, env, sizeof env, &n);
    env[72] = M5_ID_PRODUCTION;
    CHECK(open_refused(env, ENV_LEN, &OBJ, M5_ID_PRODUCTION) == M5_ERR_AUTH);
    /* relabel a TEST commit record and anchor */
    uint8_t cb[M5_COMMIT_LEN], ab[M5_ANCHOR_LEN];
    m5_commit co; m5_anchor ao;
    make_commit(&tb, env, ENV_LEN, 5, SK_TEST.k_root_auth, cb);
    cb[10] = M5_ID_PRODUCTION;
    CHECK(m5_commit_open(cb, sizeof cb, SK_TEST.k_root_auth, M5_ID_PRODUCTION, &co) == M5_ERR_AUTH);
    make_anchor(M5_ID_TEST, OBJ.store_uuid, 9, 3, 5, cb, SK_TEST.k_root_auth, ab);
    ab[10] = M5_ID_PRODUCTION;
    CHECK(m5_anchor_open(ab, sizeof ab, SK_TEST.k_root_auth, M5_ID_PRODUCTION, &ao) == M5_ERR_AUTH);
}

/* ---------- 7. migration ---------- */
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
    sha256_hash(COMMIT, M5_COMMIT_LEN, m.source_commit_digest);
    return m;
}
#define MIG_AUTH(buf, e, last, o) m5_migration_authorize(buf, M5_MIGRATION_LEN, SK.k_root_auth, M5_ID_PRODUCTION, e, last, o)

static void t_mig_authorized(void)
{
    m5_migration m = mig_fixture(), o;
    uint8_t b[M5_MIGRATION_LEN];
    CHECK(m5_migration_seal(&m, SK.k_root_auth, b) == M5_OK);
    CHECK(MIG_AUTH(b, &m, 1, &o) == M5_OK && o.migration_counter == 2);
}
static void t_mig_wrong_key_refused(void)
{
    m5_migration m = mig_fixture(), o;
    uint8_t b[M5_MIGRATION_LEN];
    m5_migration_seal(&m, SK.k_artifact, b);
    CHECK(MIG_AUTH(b, &m, 1, &o) == M5_ERR_AUTH);
    m5_migration_seal(&m, SK.k_root_auth, b);
    for (size_t i = 0; i < sizeof b; i++) {
        b[i] ^= 0x08;
        CHECK(MIG_AUTH(b, &m, 1, &o) < 0);
        b[i] ^= 0x08;
    }
}
static void t_mig_replay_refused(void)
{
    m5_migration m = mig_fixture(), o;
    uint8_t b[M5_MIGRATION_LEN];
    m5_migration_seal(&m, SK.k_root_auth, b);
    CHECK(MIG_AUTH(b, &m, 2, &o) == M5_ERR_REPLAY);
    CHECK(MIG_AUTH(b, &m, 7, &o) == M5_ERR_REPLAY);
}
static void t_mig_binding_refusals(void)
{
    m5_migration m = mig_fixture(), e, o;
    uint8_t b[M5_MIGRATION_LEN];
    m5_migration_seal(&m, SK.k_root_auth, b);
    e = m; e.source_store_uuid[0] ^= 1; CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_BINDING);
    e = m; e.dest_store_uuid[0] ^= 1; CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_BINDING);
    e = m; e.source_store_generation = 8; CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_BINDING);
    e = m; e.source_anchor_counter = 4; CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_BINDING);
    e = m; e.source_commit_digest[0] ^= 1; CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_BINDING);
    e = m; e.agent_root_id[0] ^= 1; CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_BINDING);
    e = m; e.genesis_store_uuid[0] ^= 1; CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_BINDING);
    e = m; e.owner_hierarchy_generation = 2; CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_BINDING);
    CHECK(all_zero((uint8_t *)&o, sizeof o));
    /* migrating a store onto itself */
    m5_migration s = m; memcpy(s.dest_store_uuid, s.source_store_uuid, 16);
    m5_migration_seal(&s, SK.k_root_auth, b);
    CHECK(MIG_AUTH(b, &s, 1, &o) == M5_ERR_BINDING);
}
static void t_mig_test_identity_refused_in_production(void)
{
    m5_migration m = mig_fixture(), o;
    m.identity_class = M5_ID_TEST;
    uint8_t b[M5_MIGRATION_LEN];
    m5_migration_seal(&m, SK.k_root_auth, b);
    m5_migration e = mig_fixture();
    CHECK(MIG_AUTH(b, &e, 1, &o) == M5_ERR_IDENTITY);
}

/* ---------- 8. deterministic recovery ---------- */
static void t_recovery_deterministic(void)
{
    /* candidates: committed version, an older version, an uncommitted newer torn copy, junk */
    m5_object_binding old = OBJ; old.store_generation = 8;
    m5_object_binding nw = OBJ; nw.store_generation = 10;
    uint8_t env_old[ENV_LEN], env_new[ENV_LEN], junk[100];
    size_t n;
    m5_envelope_seal(SK.k_artifact, &old, NONCE8, CS, PT, PT_LEN, env_old, sizeof env_old, &n);
    m5_envelope_seal(SK.k_artifact, &nw, NONCE8, CS, PT, PT_LEN, env_new, sizeof env_new, &n);
    env_new[CHUNK_OFF(3) + 1] ^= 1; /* torn, never committed */
    memset(junk, 0x3C, sizeof junk);
    m5_candidate base[4] = {{env_old, ENV_LEN}, {ENV, ENV_LEN}, {env_new, ENV_LEN}, {junk, sizeof junk}};
    uint8_t first[PT_LEN], out[PT_LEN];
    size_t ch;
    CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN, base, 4, first, sizeof first, &ch) == M5_OK);
    CHECK(ch == 1 && memcmp(first, PT, PT_LEN) == 0);
    for (int r = 0; r < 64; r++) {
        m5_candidate c[4];
        memcpy(c, base, sizeof c);
        for (int i = 3; i > 0; i--) { int j = (int)(rnd() % (uint64_t)(i + 1)); m5_candidate t = c[i]; c[i] = c[j]; c[j] = t; }
        CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN, c, 4, out, sizeof out, &ch) == M5_OK);
        CHECK(ch < 4 && c[ch].bytes == ENV);
        CHECK(memcmp(out, first, PT_LEN) == 0);
    }
}
static void t_recovery_torn_refused(void)
{
    uint8_t torn[ENV_LEN], out[PT_LEN];
    size_t ch;
    memcpy(torn, ENV, ENV_LEN);
    memset(torn + CHUNK_OFF(2), 0, ENV_LEN - CHUNK_OFF(2)); /* tail never reached the media */
    m5_candidate c[1] = {{torn, ENV_LEN}};
    CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN, c, 1, out, sizeof out, &ch) == M5_ERR_TORN);
    m5_candidate c2[1] = {{ENV, CHUNK_OFF(2)}};
    CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN, c2, 1, out, sizeof out, &ch) == M5_ERR_TORN);
    CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN, NULL, 0, out, sizeof out, &ch) == M5_ERR_TORN);
}
static void t_recovery_ambiguous_refused(void)
{
    uint8_t torn[ENV_LEN], out[PT_LEN];
    size_t ch;
    memcpy(torn, ENV, ENV_LEN);
    torn[CHUNK_OFF(1)] ^= 1;
    m5_candidate c[2] = {{ENV, ENV_LEN}, {torn, ENV_LEN}};
    CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN, c, 2, out, sizeof out, &ch) == M5_ERR_AMBIGUOUS);
    m5_candidate d[2] = {{torn, ENV_LEN}, {ENV, ENV_LEN}};
    CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN, d, 2, out, sizeof out, &ch) == M5_ERR_AMBIGUOUS);
    /* identical duplicate copies are not ambiguous */
    uint8_t dup[ENV_LEN];
    memcpy(dup, ENV, ENV_LEN);
    m5_candidate e[2] = {{dup, ENV_LEN}, {ENV, ENV_LEN}};
    CHECK(recover(COMMIT, ANCHOR, M5_ANCHOR_LEN, e, 2, out, sizeof out, &ch) == M5_OK && ch == 0);
}
static void t_recovery_old_commit_is_rollback(void)
{
    /* anchor advanced to counter 6 for a newer commit; the old commit (counter 5) is replayed */
    m5_object_binding nw = OBJ; nw.store_generation = 10;
    uint8_t env_new[ENV_LEN], cnew[M5_COMMIT_LEN], anew[M5_ANCHOR_LEN], out[PT_LEN];
    size_t n, ch;
    m5_envelope_seal(SK.k_artifact, &nw, NONCE8, CS, PT, PT_LEN, env_new, sizeof env_new, &n);
    make_commit(&nw, env_new, ENV_LEN, 6, SK.k_root_auth, cnew);
    make_anchor(M5_ID_PRODUCTION, OBJ.store_uuid, 10, 3, 6, cnew, SK.k_root_auth, anew);
    m5_candidate c[2] = {{ENV, ENV_LEN}, {env_new, ENV_LEN}};
    CHECK(recover(COMMIT, anew, M5_ANCHOR_LEN, c, 2, out, sizeof out, &ch) == M5_ERR_ROLLBACK);
    CHECK(recover(cnew, anew, M5_ANCHOR_LEN, c, 2, out, sizeof out, &ch) == M5_OK && ch == 1);
    /* new commit written, anchor not yet advanced: prepared advance is recoverable */
    CHECK(recover(cnew, ANCHOR, M5_ANCHOR_LEN, c, 2, out, sizeof out, &ch) == M5_OK && ch == 1);
    /* missing anchor is not silently treated as genesis */
    CHECK(recover(COMMIT, NULL, 0, c, 2, out, sizeof out, &ch) == M5_ERR_ROLLBACK);
}
static void t_recovery_store_binding(void)
{
    /* commit for store B, anchor for store A whose digest names that commit */
    m5_object_binding bb = OBJ; memset(bb.store_uuid, 0xB7, 16);
    uint8_t envb[ENV_LEN], cb[M5_COMMIT_LEN], ab[M5_ANCHOR_LEN], out[PT_LEN];
    size_t n, ch;
    m5_envelope_seal(SK.k_artifact, &bb, NONCE8, CS, PT, PT_LEN, envb, sizeof envb, &n);
    make_commit(&bb, envb, ENV_LEN, 5, SK.k_root_auth, cb);
    make_anchor(M5_ID_PRODUCTION, OBJ.store_uuid, 9, 3, 5, cb, SK.k_root_auth, ab);
    m5_candidate c[1] = {{envb, ENV_LEN}};
    CHECK(recover(cb, ab, M5_ANCHOR_LEN, c, 1, out, sizeof out, &ch) == M5_ERR_BINDING);
}

struct test { const char *name; void (*fn)(void); };
static const struct test TESTS[] = {
#define T(x) {#x, x}
    T(t_hkdf_rfc5869_case1), T(t_subkeys_deterministic_and_separated), T(t_object_key_binds_every_field),
    T(t_keyslot_wrap_unwrap), T(t_keyslot_refusals), T(t_secman_roundtrip_and_owner_generation_field),
    T(t_secman_wrong_root_auth_key_refused), T(t_secman_every_byte_tamper_refused), T(t_secman_distinct_from_rust_v1),
    T(t_env_roundtrip_sizes), T(t_env_header_bounds_each_field), T(t_env_hostile_header_fuzz),
    T(t_all_or_nothing_late_chunk_failure_zeroes_output),
    T(t_corrupt_header), T(t_corrupt_first_chunk), T(t_corrupt_middle_chunk), T(t_corrupt_last_chunk),
    T(t_corrupt_commit_record), T(t_corrupt_rollback_anchor), T(t_corrupt_key_generation),
    T(t_corrupt_store_generation), T(t_truncate_drop_last_chunk), T(t_extend_append_chunk),
    T(t_reorder_chunks), T(t_splice_cross_object),
    T(t_anchor_caller_buffer_roundtrip), T(t_rb_valid_resume_and_advance), T(t_rb_older_store_generation_refused),
    T(t_rb_older_key_generation_refused), T(t_rb_lower_counter_refused), T(t_rb_fork_at_same_counter_refused),
    T(t_rb_counter_jump_inconsistent), T(t_rb_forged_anchor_refused), T(t_rb_missing_anchor_and_genesis),
    T(t_rb_anchor_other_store_refused),
    T(t_identity_production_refuses_test), T(t_identity_test_refuses_production), T(t_identity_relabel_breaks_mac),
    T(t_mig_authorized), T(t_mig_wrong_key_refused), T(t_mig_replay_refused), T(t_mig_binding_refusals),
    T(t_mig_test_identity_refused_in_production),
    T(t_recovery_deterministic), T(t_recovery_torn_refused), T(t_recovery_ambiguous_refused),
    T(t_recovery_old_commit_is_rollback), T(t_recovery_store_binding),
#undef T
};

int main(void)
{
    int failed = 0;
    fixtures();
    if (g_fail) { printf("M5_NATIVE: FAIL\n"); return 1; }
    for (size_t i = 0; i < sizeof TESTS / sizeof TESTS[0]; i++) {
        g_fail = 0;
        TESTS[i].fn();
        printf("%s %s\n", g_fail ? "FAIL" : "ok  ", TESTS[i].name);
        if (g_fail) failed++;
    }
    printf("%zu tests, %d failed\n", sizeof TESTS / sizeof TESTS[0], failed);
    printf("M5_NATIVE: %s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
