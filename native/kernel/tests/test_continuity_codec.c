/* test_continuity_codec.c -- host tests of svc/continuity_codec.c (C
 * continuity port, cut 1; contract native/kernel/CONTINUITY_RECOVERY_CONTRACT.md,
 * aienos#222). Oracle: crates/aienos-kernel/src/continuity.rs at 4a116e5
 * ("rs:" below).
 *
 * 1. Known answers. Expected bytes are written out by hand from the Rust
 *    encoders, each piece citing the Rust line that emits it. Hash values
 *    (root/child branch ids, logical ObjectIds) were computed outside this
 *    code with coreutils sha256sum over printf-built inputs, not with the C
 *    code under test. Cut 2 adds Rust-emitted golden vectors (D-1, section 6).
 * 2. Round trips (twin of rs tests continuity_tests.rs:286, 87h).
 * 3. One refusal per rule, with the Rust error class and reason text.
 * 4. Branch-table lineage (twin of continuity_tests.rs:328, 87i).
 * 5. K-1 (PROPOSED): 16384-byte cap on encode and decode.
 * Mutants (make continuity-mutants) must each turn this test FAIL. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "continuity_codec.h"
#include "store_v1.h" /* sv1_object_id: independent C twin of ObjectId::calculate */

static const char *why;
static uint8_t buf[CC_MAX_OBJECT_BYTES + 1024]; /* decoders read from here */
static uint8_t out[CC_MAX_OBJECT_BYTES + 1024];
static struct cc_state st, st2;
static struct cc_wal wal, wal2;
static struct cc_manifest man, man2;
static uint8_t stmt[CC_MAX_WAL_RECORDS][CC_MAX_STATEMENT_BYTES];

/* ---- known-answer builder ---- */
static uint8_t kat[4096];
static size_t kn;
static void k_str(const char *s) { size_t n = strlen(s); memcpy(kat + kn, s, n); kn += n; }
static void k_rep(uint8_t b, size_t n) { memset(kat + kn, b, n); kn += n; }
static void k_le(uint64_t v, int n) { for (int i = 0; i < n; i++) kat[kn++] = (uint8_t)(v >> (8 * i)); }
static int hexv(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }
static void unhex(const char *h, uint8_t *o) { for (size_t i = 0; h[2 * i]; i++) o[i] = (uint8_t)(hexv(h[2 * i]) << 4 | hexv(h[2 * i + 1])); }
static void k_hex(const char *h) { unhex(h, kat + kn); kn += strlen(h) / 2; }

/* sha256sum("AIENOS_ROOT_BRANCH_v1:" || 0x11 x 32) */
#define RB_HEX "89f5fd9d69301a1ab4cce49d57b3f711fb9c36524807ef53fada8119ac24f803"
/* sha256sum("AIENOS_CHILD_BRANCH_v1:" || RB || index u64 BE) for index 0, 1, 2^32, 2^64-1 */
#define C0_HEX "0be1954eac96e977c2eabee2a079600ad249b7c46b4f07910089098041f55785"
#define C1_HEX "909874bd0bd38ea9b278982665b3f33ed29b5c76340719bccf030bc59bebcc55"
#define C32_HEX "35b2e2d23d315594bfdb01277cdce8ad5aedf79641e11b7a82c9d08a6c5e669a"
#define CMAX_HEX "d9716d516fb3c31b21dc4e9a9e748a928a5a53d60642c0251094e47aeb8d22fd"
/* sha256sum("AIENOS-STORE-OBJECT-V1\0" || kind u16 LE || 1 u16 LE || len u64 LE || bytes)
 * over the four known-answer objects below (store/v1.rs:63-78). */
#define ID_ROOT_HEX "d231e0aaba16e227a5330c590d60f0367d42930593bca2092df9fe3ae23f6bf7"
#define ID_MANI_HEX "e8ba64304b22ed1f65c810a6735420dca321b42b6136caddc5214c5e0a509287"
#define ID_BRAN_HEX "561ec891c466d831b187ad19016c2800e56aa9947dfb356792c127e003682b20"
#define ID_WAL_HEX "1e6f48f3e32c1dbc13b200f112deae41668f0b5048e17578d99fe1583d344faf"

static uint8_t AGENT[32]; /* 0x11 x 32, as continuity_tests.rs:8 */

static int is(int got, int cls, const char *w)
{
    return got == cls && why && strcmp(why, w) == 0;
}

static int id_matches(uint16_t kind, const uint8_t *b, size_t n, const char *hex)
{
    uint8_t a[32], c[32], e[32];
    unhex(hex, e);
    if (cc_object_id(kind, b, n, a) != CC_OK || sv1_object_id(kind, 1, b, n, c) != 0)
        return 0;
    return memcmp(a, e, 32) == 0 && memcmp(c, e, 32) == 0;
}

/* ---- 1. derivations ---- */
static void test_branch_ids(void)
{
    uint8_t rb[32], c[32], e[32];
    cc_root_branch_id(AGENT, rb);
    unhex(RB_HEX, e);
    CHECK(memcmp(rb, e, 32) == 0);
    static const struct { uint64_t ix; const char *hex; } v[] = {
        {0, C0_HEX}, {1, C1_HEX}, {0x100000000ull, C32_HEX}, {UINT64_MAX, CMAX_HEX}};
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        cc_child_branch_id(rb, v[i].ix, c);
        unhex(v[i].hex, e);
        CHECK(memcmp(c, e, 32) == 0); /* index big-endian, rs:82 (MC-6) */
    }
    CHECK(cc_object_id(0, AGENT, 32, c) == CC_E_ARG); /* v1.rs:64 */
    CHECK(cc_object_id(CC_KIND_AGENT_ROOT, AGENT, 0, c) == CC_E_ARG);
}

/* ---- AgentRoot ---- */
static void root_kat(void) /* rs:205-215, total 112 */
{
    kn = 0;
    k_str("AIENROOT");               /* rs:91 MAGIC_ROOT (:34) */
    k_le(0, 2);                      /* rs:92 FORMAT_VERSION 0 */
    k_le(0, 2);                      /* rs:93 reserved */
    k_le(96, 4);                     /* rs:94 body_len = ROOT_BODY (:202) */
    k_rep(0x11, 32);                 /* rs:208 agent_id */
    k_rep(0x5a, 16);                 /* rs:209 store_uuid */
    k_hex(RB_HEX);                   /* rs:210 root_branch */
    k_le(0x0102030405060708ull, 8);  /* rs:211 provisioned_generation LE */
    k_le(2, 1);                      /* rs:212 source Qualification (:190) */
    k_rep(0, 7);                     /* rs:213 reserved */
}
static void root_val(struct cc_root *r)
{
    memset(r, 0, sizeof *r);
    memcpy(r->agent_id, AGENT, 32);
    memset(r->store_uuid, 0x5a, 16);
    unhex(RB_HEX, r->root_branch);
    r->provisioned_generation = 0x0102030405060708ull;
    r->source = CC_SOURCE_QUALIFICATION;
}
static int root_eq(const struct cc_root *a, const struct cc_root *b)
{
    return !memcmp(a->agent_id, b->agent_id, 32) && !memcmp(a->store_uuid, b->store_uuid, 16) &&
           !memcmp(a->root_branch, b->root_branch, 32) &&
           a->provisioned_generation == b->provisioned_generation && a->source == b->source;
}
/* Decode n bytes copied to buf (buf is larger, so a broken bound check reads
 * inside the array and the test reports instead of crashing). */
static int dec_root(const uint8_t *b, size_t n, struct cc_root *r)
{
    memmove(buf, b, n);
    why = 0;
    return cc_root_decode(buf, n, r, &why);
}

static void test_root(void)
{
    struct cc_root v, d;
    size_t n = 0;
    root_val(&v);
    root_kat();
    CHECK(kn == CC_ROOT_BYTES);
    CHECK(cc_root_encode(&v, out, sizeof out, &n, &why) == CC_OK && n == kn && !memcmp(out, kat, kn));
    CHECK(id_matches(CC_KIND_AGENT_ROOT, kat, kn, ID_ROOT_HEX));
    CHECK(dec_root(kat, kn, &d) == CC_OK && root_eq(&d, &v));

    /* 87h: every single-bit flip is refused or changes the decoded value. */
    int unnoticed = 0;
    for (size_t i = 0; i < kn * 8; i++) {
        uint8_t t[CC_ROOT_BYTES];
        memcpy(t, kat, kn);
        t[i / 8] ^= (uint8_t)(1u << (i % 8));
        if (dec_root(t, kn, &d) == CC_OK && root_eq(&d, &v))
            unnoticed++;
    }
    CHECK(unnoticed == 0);

    uint8_t t[CC_ROOT_BYTES + 8];
    /* truncated: last byte cut, body_len says 95 so the header agrees (rs:123-132) */
    memcpy(t, kat, kn); t[12] = 95;
    CHECK(is(dec_root(t, kn - 1, &d), CC_E_CORRUPT, "truncated object"));
    /* truncated inside the header (rs:107-118) */
    CHECK(is(dec_root(kat, 10, &d), CC_E_CORRUPT, "truncated object"));
    CHECK(is(dec_root(kat, 0, &d), CC_E_CORRUPT, "truncated object"));
    /* trailing: one extra byte, body_len says 97 (rs:160-165) */
    memcpy(t, kat, kn); t[kn] = 0; t[12] = 97;
    CHECK(is(dec_root(t, kn + 1, &d), CC_E_CORRUPT, "trailing bytes"));
    /* plain extra byte: body length mismatch (rs:118) */
    memcpy(t, kat, kn); t[kn] = 0;
    CHECK(is(dec_root(t, kn + 1, &d), CC_E_CORRUPT, "body length mismatch"));
    CHECK(is(dec_root(kat, kn - 1, &d), CC_E_CORRUPT, "body length mismatch"));
    memcpy(t, kat, kn); t[0] ^= 0x20;
    CHECK(is(dec_root(t, kn, &d), CC_E_CORRUPT, "bad magic")); /* rs:107 */
    memcpy(t, kat, kn); t[8] = 1;
    CHECK(is(dec_root(t, kn, &d), CC_E_CORRUPT, "unsupported continuity format version")); /* rs:110 */
    memcpy(t, kat, kn); t[9] = 1;
    CHECK(is(dec_root(t, kn, &d), CC_E_CORRUPT, "unsupported continuity format version"));
    memcpy(t, kat, kn); t[11] = 0x80;
    CHECK(is(dec_root(t, kn, &d), CC_E_CORRUPT, "nonzero header reserved")); /* rs:115 */
    memcpy(t, kat, kn); t[111] = 1;
    CHECK(is(dec_root(t, kn, &d), CC_E_CORRUPT, "nonzero reserved")); /* rs:229 */
    memcpy(t, kat, kn); t[104] = 3;
    CHECK(is(dec_root(t, kn, &d), CC_E_CORRUPT, "unknown provisioning source")); /* rs:227 */
    memcpy(t, kat, kn); t[104] = 0;
    CHECK(is(dec_root(t, kn, &d), CC_E_CORRUPT, "unknown provisioning source"));
    /* zero agent: checked before the derivation (rs:231 before :234) */
    struct cc_root z = v;
    memset(z.agent_id, 0, 32);
    cc_root_branch_id(z.agent_id, z.root_branch);
    CHECK(cc_root_encode(&z, out, sizeof out, &n, &why) == CC_OK);
    CHECK(is(dec_root(out, n, &d), CC_E_CORRUPT, "zero agent id"));
    z = v;
    memset(z.root_branch, 0x99, 32); /* as continuity_tests.rs:313 */
    CHECK(cc_root_encode(&z, out, sizeof out, &n, &why) == CC_OK);
    CHECK(is(dec_root(out, n, &d), CC_E_CORRUPT, "root branch does not derive from agent"));
    /* the right magic for another kind is refused (kind check by magic) */
    memcpy(t, kat, kn); memcpy(t, "AIENMANI", 8);
    CHECK(is(dec_root(t, kn, &d), CC_E_CORRUPT, "bad magic"));

    /* encoder: caller bugs, nothing truncated */
    z = v; z.source = 0;
    CHECK(cc_root_encode(&z, out, sizeof out, &n, &why) == CC_E_ARG && n == 0);
    memset(out, 0xee, 16);
    CHECK(cc_root_encode(&v, out, CC_ROOT_BYTES - 1, &n, &why) == CC_E_ARG && n == 0 && out[0] == 0xee);
}

/* ---- ContinuityManifest ---- */
static void mani_kat(void) /* rs:264-282, total 168 */
{
    kn = 0;
    k_str("AIENMANI"); k_le(0, 2); k_le(0, 2); /* rs:91-93, MAGIC_MANIFEST (:35) */
    k_le(120 + 32, 4);                         /* rs:94 body (:268) */
    k_rep(0xa1, 32);                           /* rs:271 root */
    k_rep(0x00, 32);                           /* rs:272 previous None = zero */
    k_le(1, 8);                                /* rs:273 sequence */
    k_le(1, 8);                                /* rs:274 incarnation */
    k_rep(0xb2, 32);                           /* rs:275 agent_state */
    k_le(1, 2);                                /* rs:276 cortex_wal count */
    k_rep(0, 6);                               /* rs:277 reserved */
    k_rep(0xc3, 32);                           /* rs:279 cortex_wal[0] */
}
static void mani_val(struct cc_manifest *m)
{
    memset(m, 0, sizeof *m);
    memset(m->root, 0xa1, 32);
    m->sequence = 1;
    m->incarnation = 1;
    memset(m->agent_state, 0xb2, 32);
    m->n_wal = 1;
    memset(m->wal[0], 0xc3, 32);
}
static int mani_eq(const struct cc_manifest *a, const struct cc_manifest *b)
{
    return !memcmp(a->root, b->root, 32) && !memcmp(a->previous, b->previous, 32) &&
           a->sequence == b->sequence && a->incarnation == b->incarnation &&
           !memcmp(a->agent_state, b->agent_state, 32) && a->n_wal == b->n_wal &&
           !memcmp(a->wal, b->wal, 32 * (size_t)a->n_wal);
}
static int dec_mani(const uint8_t *b, size_t n)
{
    memmove(buf, b, n);
    why = 0;
    return cc_manifest_decode(buf, n, &man2, &why);
}

static void test_manifest(void)
{
    size_t n = 0;
    mani_val(&man);
    mani_kat();
    CHECK(kn == 168);
    CHECK(cc_manifest_encode(&man, out, sizeof out, &n, &why) == CC_OK && n == kn && !memcmp(out, kat, kn));
    CHECK(id_matches(CC_KIND_MANIFEST, kat, kn, ID_MANI_HEX));
    CHECK(dec_mani(kat, kn) == CC_OK && mani_eq(&man2, &man));

    uint8_t t[256];
    memcpy(t, kat, kn); t[130] = 1;
    CHECK(is(dec_mani(t, kn), CC_E_CORRUPT, "nonzero reserved")); /* rs:292 */
    /* count 2 with only one id present, body_len unchanged: truncated (rs:298) */
    memcpy(t, kat, kn); t[128] = 2;
    CHECK(is(dec_mani(t, kn), CC_E_CORRUPT, "truncated object"));
    memcpy(t, kat, kn); t[128] = 65;
    CHECK(is(dec_mani(t, kn), CC_E_CORRUPT, "too many cortex WAL segments")); /* rs:293-295 */
    memcpy(t, kat, kn); t[80] = 0;
    CHECK(is(dec_mani(t, kn), CC_E_CORRUPT, "manifest sequence/previous mismatch")); /* seq 0, rs:301 */
    memcpy(t, kat, kn); t[80] = 2;
    CHECK(is(dec_mani(t, kn), CC_E_CORRUPT, "manifest sequence/previous mismatch")); /* seq 2, no previous */
    memcpy(t, kat, kn); t[48] = 1;
    CHECK(is(dec_mani(t, kn), CC_E_CORRUPT, "manifest sequence/previous mismatch")); /* seq 1 with previous */
    memcpy(t, kat, kn); t[48] = 1; t[80] = 2;
    CHECK(dec_mani(t, kn) == CC_OK && man2.sequence == 2 && man2.previous[0] == 1);

    /* 64 WAL ids is the largest manifest (2184 bytes); 65 is Limit (rs:265-267) */
    man.n_wal = CC_MAX_WAL_SEGMENTS;
    CHECK(cc_manifest_encode(&man, out, sizeof out, &n, &why) == CC_OK && n == 2184);
    CHECK(dec_mani(out, n) == CC_OK && man2.n_wal == 64);
    man.n_wal = CC_MAX_WAL_SEGMENTS + 1;
    CHECK(is(cc_manifest_encode(&man, out, sizeof out, &n, &why), CC_E_LIMIT, "too many cortex WAL segments") && n == 0);
}

/* ---- AgentState ---- */
static void bran_kat(void) /* genesis(AGENT, 1) + fork(root): rs:392-409, total 224 */
{
    kn = 0;
    k_str("AIENBRAN"); k_le(0, 2); k_le(0, 2); /* rs:91-93, MAGIC_BRANCHES (:36) */
    k_le(48 + 2 * 80, 4);                      /* rs:94 body (:394) */
    k_rep(0x11, 32);                           /* rs:397 agent_id */
    k_le(1, 8);                                /* rs:398 written_at */
    k_le(2, 4);                                /* rs:399 branch count */
    k_rep(0, 4);                               /* rs:400 reserved */
    /* sorted by id (rs:387-388): C0 (0x0b..) < RB (0x89..) */
    k_hex(C0_HEX);                             /* rs:402 id = child_branch_id(RB, 0) */
    k_hex(RB_HEX);                             /* rs:403 parent */
    k_le(1, 4);                                /* rs:404 depth */
    k_rep(0, 4);                               /* rs:405 reserved */
    k_le(0, 8);                                /* rs:406 forks */
    k_hex(RB_HEX);                             /* rs:402 root id */
    k_rep(0, 32);                              /* rs:403 parent None = zero */
    k_le(0, 4);                                /* rs:404 depth 0 */
    k_rep(0, 4);                               /* rs:405 */
    k_le(1, 8);                                /* rs:406 forks 1 (rs:382) */
}
static int dec_state(const uint8_t *b, size_t n)
{
    memmove(buf, b, n);
    why = 0;
    return cc_state_decode(buf, n, &st2, &why);
}
static int state_eq(const struct cc_state *a, const struct cc_state *b)
{
    if (memcmp(a->agent_id, b->agent_id, 32) || a->written_at != b->written_at || a->n != b->n)
        return 0;
    for (uint32_t i = 0; i < a->n; i++)
        if (memcmp(a->br[i].id, b->br[i].id, 32) || memcmp(a->br[i].parent, b->br[i].parent, 32) ||
            a->br[i].depth != b->br[i].depth || a->br[i].forks != b->br[i].forks)
            return 0;
    return 1;
}
static long idx_of(const struct cc_state *s, const uint8_t id[32])
{
    for (uint32_t i = 0; i < s->n; i++)
        if (!memcmp(s->br[i].id, id, 32))
            return (long)i;
    return -1;
}

static void test_state(void)
{
    size_t n = 0;
    uint8_t rb[32], child[32], gchild[32], e[32];
    cc_root_branch_id(AGENT, rb);
    cc_state_genesis(&st, AGENT, 1);
    CHECK(st.n == 1 && cc_state_validate(&st, &why) == CC_OK);
    CHECK(cc_state_fork(&st, rb, child, &why) == CC_OK);
    unhex(C0_HEX, e);
    CHECK(memcmp(child, e, 32) == 0);
    bran_kat();
    CHECK(kn == 224);
    CHECK(cc_state_encode(&st, out, sizeof out, &n, &why) == CC_OK && n == kn && !memcmp(out, kat, kn));
    CHECK(id_matches(CC_KIND_AGENT_STATE, kat, kn, ID_BRAN_HEX));
    CHECK(dec_state(kat, kn) == CC_OK && state_eq(&st2, &st));

    /* second fork of the root takes index 1 (rs:373, :382) */
    st2 = st;
    CHECK(cc_state_fork(&st2, rb, gchild, &why) == CC_OK);
    unhex(C1_HEX, e);
    CHECK(memcmp(gchild, e, 32) == 0 && st2.n == 3);
    /* 87h tail: fork of a fork (depth 2) round-trips */
    CHECK(cc_state_fork(&st2, child, gchild, &why) == CC_OK);
    CHECK(st2.br[idx_of(&st2, gchild)].depth == 2);
    CHECK(cc_state_encode(&st2, out, sizeof out, &n, &why) == CC_OK);
    static struct cc_state keep;
    keep = st2;
    CHECK(dec_state(out, n) == CC_OK && state_eq(&st2, &keep));

    uint8_t t[256];
    memcpy(t, kat, kn); t[60] = 1;
    CHECK(is(dec_state(t, kn), CC_E_CORRUPT, "nonzero reserved")); /* rs:416 */
    memcpy(t, kat, kn); t[64 + 68] = 1;
    CHECK(is(dec_state(t, kn), CC_E_CORRUPT, "nonzero reserved")); /* rs:425 */
    memcpy(t, kat, kn); t[56] = 0;
    CHECK(is(dec_state(t, kn), CC_E_CORRUPT, "branch count out of range")); /* rs:417 */
    memcpy(t, kat, kn); t[56] = 3;
    CHECK(is(dec_state(t, kn), CC_E_CORRUPT, "truncated object")); /* rs:422 */
    memcpy(t, kat, kn); t[56] = 0x01; t[57] = 0x01; /* 257 */
    CHECK(is(dec_state(t, kn), CC_E_CORRUPT, "branch count out of range"));
    memcpy(t, kat, kn); t[56] = 1; t[12] = 48 + 80; /* header length disagrees with the input length */
    CHECK(is(dec_state(t, kn), CC_E_CORRUPT, "body length mismatch"));
    memcpy(t, kat, kn); t[56] = 1;
    CHECK(is(dec_state(t, kn), CC_E_CORRUPT, "trailing bytes"));
    /* swap the two branches: not strictly sorted (rs:452-454) */
    memcpy(t, kat, kn); memcpy(t + 64, kat + 144, 80); memcpy(t + 144, kat + 64, 80);
    CHECK(is(dec_state(t, kn), CC_E_CORRUPT, "branches not strictly sorted"));

    /* 87i twins (continuity_tests.rs:328-346) through validate */
    long ci = idx_of(&st, child), ri = idx_of(&st, rb);
    st2 = st; st2.br[ci].depth = 5;
    CHECK(is(cc_state_validate(&st2, &why), CC_E_CORRUPT, "branch lineage is inconsistent"));
    st2 = st; st2.br[ri].forks = 2;
    CHECK(is(cc_state_validate(&st2, &why), CC_E_CORRUPT, "fork indexes are not contiguous"));
    st2 = st; st2.br[ri] = st2.br[ci]; st2.n = 1; /* root removed */
    CHECK(is(cc_state_validate(&st2, &why), CC_E_CORRUPT, "parent branch is absent"));
    cc_state_genesis(&st2, AGENT, 1); st2.br[0].depth = 1;
    CHECK(is(cc_state_validate(&st2, &why), CC_E_CORRUPT, "unexpected root branch"));
    st2 = st; st2.agent_id[0] ^= 1; /* root id no longer derives from the agent */
    CHECK(is(cc_state_validate(&st2, &why), CC_E_CORRUPT, "unexpected root branch"));
    st2 = st; st2.br[ci].id[31] ^= 1; /* child id not derived from its parent */
    CHECK(is(cc_state_validate(&st2, &why), CC_E_CORRUPT, "branch lineage is inconsistent"));
    st2 = st; st2.br[ci].depth = UINT32_MAX;
    CHECK(is(cc_state_validate(&st2, &why), CC_E_CORRUPT, "branch lineage is inconsistent"));
    /* encode runs validate first (rs:393) */
    st2 = st; st2.br[ri].forks = 2;
    CHECK(is(cc_state_encode(&st2, out, sizeof out, &n, &why), CC_E_CORRUPT, "fork indexes are not contiguous") && n == 0);
    /* Hostile fork counts: terminates, refused. Child index 0 under a parent
     * claiming 2^64-1 forks with a sum that would wrap to the child count. */
    st2 = st; st2.br[ri].forks = UINT64_MAX; st2.br[ci].forks = 2;
    CHECK(is(cc_state_validate(&st2, &why), CC_E_CORRUPT, "fork indexes are not contiguous"));
    st2 = st; st2.br[ri].forks = UINT64_MAX; st2.br[ci].id[31] ^= 1;
    CHECK(cc_state_validate(&st2, &why) == CC_E_CORRUPT);

    /* fork refusals (rs:366-387) */
    st2 = st; memset(e, 0x77, 32);
    CHECK(is(cc_state_fork(&st2, e, gchild, &why), CC_E_CORRUPT, "fork parent is absent"));
    st2 = st; st2.n = CC_MAX_BRANCHES;
    CHECK(is(cc_state_fork(&st2, rb, gchild, &why), CC_E_LIMIT, "too many branches"));
    st2 = st; st2.br[ci].depth = UINT32_MAX;
    CHECK(is(cc_state_fork(&st2, child, gchild, &why), CC_E_LIMIT, "branch depth"));
    /* collision: parent forks rewound to 0 re-derives the existing child; the
     * parent's count still advances, as in Rust (rs:382 before :383-387) */
    st2 = st; st2.br[ri].forks = 0;
    CHECK(is(cc_state_fork(&st2, rb, gchild, &why), CC_E_CORRUPT, "child branch id collision"));
    CHECK(st2.n == 2 && st2.br[ri].forks == 1);

    /* K-1 (PROPOSED): 204 branches = exactly 16384 bytes; 205 is Limit. */
    cc_state_genesis(&st2, AGENT, 1);
    int ok = 1;
    while (st2.n < CC_MAX_BRANCHES_IN_CAP)
        ok &= cc_state_fork(&st2, rb, gchild, &why) == CC_OK;
    CHECK(ok && st2.n == 204);
    CHECK(cc_state_encode(&st2, out, sizeof out, &n, &why) == CC_OK && n == CC_MAX_OBJECT_BYTES);
    CHECK(dec_state(out, n) == CC_OK && st2.n == 204);
    CHECK(cc_state_fork(&st2, rb, gchild, &why) == CC_OK && st2.n == 205); /* Rust bound is 256 */
    memset(out, 0xee, 64);
    CHECK(cc_state_encode(&st2, out, sizeof out, &n, &why) == CC_E_LIMIT && n == 0 && out[0] == 0xee);
}

/* ---- CortexWalSegment ---- */
static void wal_kat(void) /* rs:528-552, total 107 */
{
    kn = 0;
    k_str("AIENCWAL"); k_le(0, 2); k_le(0, 2); /* rs:91-93, MAGIC_WAL (:37) */
    k_le(16 + 37 + 38, 4);                     /* rs:94 body (:532, :537) */
    k_le(3, 8);                                /* rs:541 sequence */
    k_le(2, 4);                                /* rs:542 record count */
    k_rep(0, 4);                               /* rs:543 reserved */
    k_le(6, 1); k_le(0, 1); k_le(1, 2);        /* rs:545-547 OperatorDecision, reserved, len */
    k_rep(0x42, 32); k_str("a");               /* rs:548-549 */
    k_le(2, 1); k_le(0, 1); k_le(2, 2);        /* rs:545-547 VerifiedFact */
    k_rep(0x42, 32); k_str("bb");              /* rs:548-549 */
}
static int dec_wal(const uint8_t *b, size_t n)
{
    memmove(buf, b, n);
    why = 0;
    return cc_wal_decode(buf, n, &wal2, &why);
}

static void test_wal(void)
{
    size_t n = 0;
    memset(&wal, 0, sizeof wal);
    wal.sequence = 3;
    wal.n = 2;
    wal.rec[0].status = 6; memset(wal.rec[0].evidence_hash, 0x42, 32); wal.rec[0].len = 1; wal.rec[0].statement = (const uint8_t *)"a";
    wal.rec[1].status = 2; memset(wal.rec[1].evidence_hash, 0x42, 32); wal.rec[1].len = 2; wal.rec[1].statement = (const uint8_t *)"bb";
    wal_kat();
    CHECK(kn == 107);
    CHECK(cc_wal_encode(&wal, out, sizeof out, &n, &why) == CC_OK && n == kn && !memcmp(out, kat, kn));
    CHECK(id_matches(CC_KIND_CORTEX_WAL, kat, kn, ID_WAL_HEX));
    CHECK(dec_wal(kat, kn) == CC_OK && wal2.sequence == 3 && wal2.n == 2);
    CHECK(wal2.rec[0].status == 6 && wal2.rec[0].len == 1 && wal2.rec[0].statement == buf + 68 &&
          wal2.rec[0].statement[0] == 'a' && wal2.rec[0].evidence_hash[31] == 0x42);
    CHECK(wal2.rec[1].status == 2 && wal2.rec[1].len == 2 && wal2.rec[1].statement == buf + 105 &&
          !memcmp(wal2.rec[1].statement, "bb", 2));

    uint8_t t[256];
    memcpy(t, kat, kn); t[28] = 1;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "nonzero reserved")); /* rs:558 */
    memcpy(t, kat, kn); t[33] = 1;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "nonzero reserved")); /* rs:566 */
    memcpy(t, kat, kn); t[24] = 0;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "WAL segment record count")); /* rs:559 */
    memcpy(t, kat, kn); t[24] = 65;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "WAL segment record count"));
    memcpy(t, kat, kn); t[32] = 7;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "unknown epistemic status")); /* rs:564-565 */
    memcpy(t, kat, kn); t[32] = 0;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "unknown epistemic status"));
    memcpy(t, kat, kn); t[34] = 0;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "statement length")); /* rs:568 */
    memcpy(t, kat, kn); t[34] = 0x01; t[35] = 0x04; /* 1025 */
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "statement length"));
    /* last statement claims 3 bytes, header agrees with the real length:
     * the statement read runs past the end (rs:572) */
    memcpy(t, kat, kn); t[71] = 3;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "truncated object"));
    /* count 3, only two records present */
    memcpy(t, kat, kn); t[24] = 3;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "truncated object"));
    memcpy(t, kat, kn); t[71] = 1;
    CHECK(is(dec_wal(t, kn), CC_E_CORRUPT, "trailing bytes"));

    /* encoder bounds (rs:529-536) */
    struct cc_wal w = wal;
    w.n = 0;
    CHECK(is(cc_wal_encode(&w, out, sizeof out, &n, &why), CC_E_LIMIT, "WAL segment record count") && n == 0);
    w = wal; w.rec[1].len = 0;
    CHECK(is(cc_wal_encode(&w, out, sizeof out, &n, &why), CC_E_LIMIT, "statement length"));
    w = wal; w.rec[1].len = CC_MAX_STATEMENT_BYTES + 1; w.rec[1].statement = stmt[0];
    CHECK(is(cc_wal_encode(&w, out, sizeof out, &n, &why), CC_E_LIMIT, "statement length"));
    w = wal; w.rec[0].status = 9;
    CHECK(cc_wal_encode(&w, out, sizeof out, &n, &why) == CC_E_ARG);

    /* every status 1..6 and statement lengths 1 and 1024 round-trip */
    memset(&w, 0, sizeof w);
    w.sequence = 9;
    w.n = 7;
    for (uint32_t i = 0; i < 7; i++) {
        w.rec[i].status = (uint8_t)(i % 6 + 1);
        memset(w.rec[i].evidence_hash, (int)i, 32);
        memset(stmt[i], 'A' + (int)i, CC_MAX_STATEMENT_BYTES);
        w.rec[i].len = i == 6 ? CC_MAX_STATEMENT_BYTES : 1;
        w.rec[i].statement = stmt[i];
    }
    CHECK(cc_wal_encode(&w, out, sizeof out, &n, &why) == CC_OK && n == 16 + 16 + 7 * 36 + 6 + 1024);
    CHECK(dec_wal(out, n) == CC_OK && wal2.n == 7 && wal2.rec[6].len == 1024 && wal2.rec[5].status == 6 &&
          wal2.rec[6].statement[1023] == 'G');

    /* K-1 (PROPOSED, MC-11): a Rust-legal 64 x 1024 segment (67872 bytes)
     * is Limit, never truncated, nothing written. */
    memset(&w, 0, sizeof w);
    w.sequence = 1;
    w.n = CC_MAX_WAL_RECORDS;
    for (uint32_t i = 0; i < CC_MAX_WAL_RECORDS; i++) {
        w.rec[i].status = 1;
        w.rec[i].len = CC_MAX_STATEMENT_BYTES;
        w.rec[i].statement = stmt[i];
    }
    memset(out, 0xee, 64);
    n = 123;
    CHECK(is(cc_wal_encode(&w, out, sizeof out, &n, &why), CC_E_LIMIT,
             "continuity object exceeds the 16384-byte sealed Store cap") && n == 0 && out[0] == 0xee);
}

/* K-1 on decode (PROPOSED): more than 16384 bytes is Limit before parsing. */
static void test_decode_cap(void)
{
    memset(buf, 0, sizeof buf);
    memcpy(buf, "AIENCWAL", 8);
    CHECK(cc_wal_decode(buf, CC_MAX_OBJECT_BYTES + 1, &wal2, &why) == CC_E_LIMIT);
    CHECK(cc_state_decode(buf, CC_MAX_OBJECT_BYTES + 1, &st2, &why) == CC_E_LIMIT);
    struct cc_root r;
    CHECK(cc_root_decode(buf, CC_MAX_OBJECT_BYTES + 1, &r, &why) == CC_E_LIMIT);
    CHECK(cc_manifest_decode(buf, CC_MAX_OBJECT_BYTES + 1, &man2, &why) == CC_E_LIMIT);
    /* exactly 16384 is parsed (refused here only as Corrupt) */
    CHECK(cc_wal_decode(buf, CC_MAX_OBJECT_BYTES, &wal2, &why) == CC_E_CORRUPT);
}

/* ---- D-1 golden vectors and D-2 decode agreement (cut 2) ----
 * Fixtures are emitted by the Rust oracle (crates/aienos-kernel/src/
 * continuity_vectors.rs) and read here at run time: the directory is argv[1],
 * else the CC_FIXTURE_DIR compile-time define (set by the Makefile).
 *   continuity_vectors.txt  bid / vec / deferred lines (D-1)
 *   continuity_verdicts.txt reason table + one verdict string per vector (D-2) */
#define V_MAX 64
#define V_BYTES_MAX 2300 /* largest vector: manifest with 64 WAL ids, 2184 */
#define R_MAX 32
static char fbuf_v[1 << 17], fbuf_d[1 << 18];
static struct vec {
    char name[48];
    uint16_t kind;
    uint8_t oid[32];
    uint8_t bytes[V_BYTES_MAX];
    size_t n;
    const char *verdict; /* into fbuf_d, 8n+1 chars, not NUL terminated */
    size_t verdict_len;
} vecs[V_MAX];
static int n_vecs, n_deferred, n_bids;
static struct { char c; char cls[8]; char why[64]; } reasons[R_MAX];
static int n_reasons;
/* Comparison counters: the gate asserts the work was actually done, so a
 * skipped comparison is a FAIL, not a silent pass (mutants SKIP_D1/SKIP_D2). */
static unsigned long d1_compared, d2_compared, d2_expected;
static int quiet; /* silence expected divergences in the tamper test */

static int read_file(const char *dir, const char *name, char *dst, size_t cap)
{
    char path[512];
    if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path)
        return 0;
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("  cannot open %s\n", path);
        return 0;
    }
    size_t n = fread(dst, 1, cap - 1, f);
    int big = fgetc(f) != EOF;
    fclose(f);
    dst[n] = 0;
    return n > 0 && !big;
}
/* Strict hex: exactly 2*n lowercase digits, then end of token. */
static int hex_n(const char *s, size_t n, uint8_t *o)
{
    for (size_t i = 0; i < 2 * n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    for (size_t i = 0; i < n; i++)
        o[i] = (uint8_t)(hexv(s[2 * i]) << 4 | hexv(s[2 * i + 1]));
    return 1;
}
/* Next line of a NUL-terminated buffer: returns its start, NUL-terminates it,
 * advances *p. NULL at end. */
static char *next_line(char **p)
{
    char *s = *p, *e;
    if (!*s)
        return 0;
    for (e = s; *e && *e != '\n'; e++)
        ;
    if (*e)
        *e++ = 0;
    *p = e;
    return s;
}
/* Split off the next space-separated token of *l (in place). */
static char *tok(char **l)
{
    char *s = *l, *e;
    if (!s || !*s)
        return 0;
    for (e = s; *e && *e != ' '; e++)
        ;
    if (*e)
        *e++ = 0;
    *l = e;
    return s;
}

static int load_fixtures(const char *dir)
{
    char *p, *l;
    if (!read_file(dir, "continuity_vectors.txt", fbuf_v, sizeof fbuf_v) ||
        !read_file(dir, "continuity_verdicts.txt", fbuf_d, sizeof fbuf_d))
        return 0;
    for (p = fbuf_v; (l = next_line(&p));) {
        char *kw = tok(&l), *name = tok(&l);
        if (!kw || kw[0] == '#')
            continue;
        if (!name)
            return 0;
        if (!strcmp(kw, "bid")) {
            n_bids++;
        } else if (!strcmp(kw, "deferred")) {
            n_deferred++;
        } else if (!strcmp(kw, "vec")) {
            char *kind = tok(&l), *oid = tok(&l), *bytes = l;
            if (!kind || !oid || !bytes || n_vecs >= V_MAX || strlen(name) >= sizeof vecs[0].name)
                return 0;
            struct vec *v = &vecs[n_vecs++];
            strcpy(v->name, name);
            v->kind = (uint16_t)strtoul(kind, 0, 10);
            size_t hl = strlen(bytes);
            if (!hex_n(oid, 32, v->oid) || hl % 2 || hl / 2 > V_BYTES_MAX || strlen(oid) != 64)
                return 0;
            v->n = hl / 2;
            if (!hex_n(bytes, v->n, v->bytes))
                return 0;
        } else {
            return 0;
        }
    }
    for (p = fbuf_d; (l = next_line(&p));) {
        char *kw = tok(&l), *name = tok(&l);
        if (!kw || kw[0] == '#')
            continue;
        if (!name)
            return 0;
        if (!strcmp(kw, "reason")) {
            char *cls = tok(&l);
            if (!cls || n_reasons >= R_MAX || strlen(name) != 1 || strlen(cls) >= 8 || strlen(l) >= 64)
                return 0;
            reasons[n_reasons].c = name[0];
            strcpy(reasons[n_reasons].cls, cls);
            strcpy(reasons[n_reasons].why, l);
            n_reasons++;
        } else if (!strcmp(kw, "verdict")) {
            int found = 0;
            for (int i = 0; i < n_vecs; i++)
                if (!strcmp(vecs[i].name, name) && !vecs[i].verdict) {
                    vecs[i].verdict = l;
                    vecs[i].verdict_len = strlen(l);
                    found = 1;
                }
            if (!found)
                return 0;
        } else {
            return 0;
        }
    }
    return 1;
}

/* C verdict of one byte string, in the fixture alphabet: '.' accept, else the
 * reason code whose (class, why) the C decoder returned; '?' if C returned a
 * class or text the Rust oracle never does (itself a divergence). */
static char c_verdict(uint16_t kind, const uint8_t *b, size_t n)
{
    struct cc_root r;
    int e;
    memmove(buf, b, n);
    why = 0;
    switch (kind) {
    case CC_KIND_AGENT_ROOT: e = cc_root_decode(buf, n, &r, &why); break;
    case CC_KIND_MANIFEST: e = cc_manifest_decode(buf, n, &man2, &why); break;
    case CC_KIND_AGENT_STATE: e = cc_state_decode(buf, n, &st2, &why); break;
    case CC_KIND_CORTEX_WAL: e = cc_wal_decode(buf, n, &wal2, &why); break;
    default: return '?';
    }
    if (e == CC_OK)
        return '.';
    const char *cls = e == CC_E_CORRUPT ? "Corrupt" : e == CC_E_LIMIT ? "Limit" : 0;
    for (int i = 0; cls && why && i < n_reasons; i++)
        if (!strcmp(reasons[i].cls, cls) && !strcmp(reasons[i].why, why))
            return reasons[i].c;
    return '?';
}

/* D-1: ObjectId (two independent C implementations) and, when the vector is
 * accepted, decode then encode reproduces the bytes exactly. */
static int d1_ok(uint16_t kind, const uint8_t *b, size_t n, const uint8_t oid[32], int accepted)
{
    uint8_t a[32], c[32], re[V_BYTES_MAX + 64];
    size_t rn = 0;
    int ok = 1;
#ifndef CC_MUTANT_SKIP_D1
    d1_compared++;
    ok = cc_object_id(kind, b, n, a) == CC_OK && sv1_object_id(kind, 1, b, n, c) == 0 &&
         !memcmp(a, oid, 32) && !memcmp(c, oid, 32);
    if (accepted) {
        struct cc_root r;
        memmove(buf, b, n);
        why = 0;
        int e = CC_E_ARG;
        switch (kind) {
        case CC_KIND_AGENT_ROOT:
            e = cc_root_decode(buf, n, &r, &why) || cc_root_encode(&r, re, sizeof re, &rn, &why);
            break;
        case CC_KIND_MANIFEST:
            e = cc_manifest_decode(buf, n, &man2, &why) || cc_manifest_encode(&man2, re, sizeof re, &rn, &why);
            break;
        case CC_KIND_AGENT_STATE:
            e = cc_state_decode(buf, n, &st2, &why) || cc_state_encode(&st2, re, sizeof re, &rn, &why);
            break;
        case CC_KIND_CORTEX_WAL:
            e = cc_wal_decode(buf, n, &wal2, &why) || cc_wal_encode(&wal2, re, sizeof re, &rn, &why);
            break;
        }
        ok = ok && e == CC_OK && rn == n && !memcmp(re, b, n);
    }
#else
    (void)kind; (void)b; (void)n; (void)oid; (void)accepted; (void)a; (void)c; (void)re; (void)rn;
#endif
    return ok;
}

/* D-2: verdict of the untouched vector and of every single-bit flip must equal
 * the Rust verdict string. Returns the number of disagreements; prints the
 * first few. */
static unsigned long d2_mismatches(const char *name, uint16_t kind, const uint8_t *b, size_t n,
                                   const char *verdict, size_t vlen)
{
    uint8_t t[V_BYTES_MAX];
    unsigned long bad = 0;
    if (vlen != 8 * n + 1)
        return 1;
    memcpy(t, b, n);
#ifndef CC_MUTANT_SKIP_D2
    if (c_verdict(kind, t, n) != verdict[0])
        bad++;
    d2_compared++;
    for (size_t i = 0; i < n * 8; i++) {
        t[i / 8] ^= (uint8_t)(1u << (i % 8));
        char cv = c_verdict(kind, t, n);
        t[i / 8] ^= (uint8_t)(1u << (i % 8));
        d2_compared++;
        if (cv != verdict[i + 1]) {
            if (bad++ < 3 && !quiet)
                printf("  D-2 divergence %s bit %zu: C '%c' Rust '%c'\n", name, i, cv, verdict[i + 1]);
        }
    }
#else
    (void)name; (void)kind; (void)verdict;
#endif
    return bad;
}

static void test_golden(void)
{
    CHECK(n_vecs == 22 && n_bids == 5 && n_deferred == 4 && n_reasons == 21);
    /* Branch ids named in the fixture equal the C derivation (D-1). */
    {
        uint8_t rb[32], e[32];
        cc_root_branch_id(AGENT, rb);
        CHECK(hex_n(RB_HEX, 32, e) && !memcmp(rb, e, 32));
    }
    for (int i = 0; i < n_vecs; i++) {
        struct vec *v = &vecs[i];
        int expect_ok = strcmp(v->name, "state_forksum_overflow") != 0;
        CHECK(v->verdict != 0);
        if (!v->verdict)
            continue;
        d2_expected += 8 * v->n + 1;
        /* the Rust verdict of the untouched vector: accept, except the hostile one */
        CHECK((v->verdict[0] == '.') == expect_ok);
        int ok = d1_ok(v->kind, v->bytes, v->n, v->oid, v->verdict[0] == '.');
        if (!ok)
            printf("  D-1 mismatch: %s\n", v->name);
        CHECK(ok);
        unsigned long bad = d2_mismatches(v->name, v->kind, v->bytes, v->n, v->verdict, v->verdict_len);
        if (bad)
            printf("  D-2: %s: %lu disagreements with Rust\n", v->name, bad);
        CHECK(bad == 0);
    }
    /* The work was done: every vector, every bit (not skipped, not truncated). */
    CHECK(d1_compared == (unsigned long)n_vecs);
    CHECK(d2_compared == d2_expected && d2_expected > 80000);
    printf("  golden: %d vectors, %lu D-2 verdicts compared (C vs Rust)\n", n_vecs, d2_compared);
}

/* The comparisons refuse tampered vectors: a flipped byte, a flipped ObjectId
 * bit and an altered verdict character are each detected. */
static void test_tampered(void)
{
    struct vec *v = &vecs[0]; /* root_operator, accepted */
    uint8_t t[V_BYTES_MAX], o[32];
    char vs[1024];
    quiet = 1;
    CHECK(v->verdict && d1_ok(v->kind, v->bytes, v->n, v->oid, 1));
    memcpy(t, v->bytes, v->n);
    t[100] ^= 0x01; /* inside the provisioned generation: still decodes, bytes differ */
    CHECK(!d1_ok(v->kind, t, v->n, v->oid, 1));
    memcpy(o, v->oid, 32);
    o[31] ^= 0x80;
    CHECK(!d1_ok(v->kind, v->bytes, v->n, o, 1));
    CHECK(v->verdict_len < sizeof vs);
    memcpy(vs, v->verdict, v->verdict_len);
    CHECK(d2_mismatches(v->name, v->kind, v->bytes, v->n, vs, v->verdict_len) == 0);
    vs[0] = 'a'; /* untouched vector claimed refused */
    CHECK(d2_mismatches(v->name, v->kind, v->bytes, v->n, vs, v->verdict_len) == 1);
    memcpy(vs, v->verdict, v->verdict_len);
    vs[1 + 8 * 20] = vs[1 + 8 * 20] == 'f' ? 'a' : 'f'; /* a flip verdict altered */
    CHECK(d2_mismatches(v->name, v->kind, v->bytes, v->n, vs, v->verdict_len) == 1);
    /* wrong length of verdict string is itself a disagreement */
    CHECK(d2_mismatches(v->name, v->kind, v->bytes, v->n, vs, v->verdict_len - 1) == 1);
    /* a bit-flipped vector decodes to the verdict Rust gives for that flip */
    memcpy(t, v->bytes, v->n);
    t[0] ^= 0x01; /* magic */
    CHECK(c_verdict(v->kind, t, v->n) == 'a');
}

int main(int argc, char **argv)
{
    memset(AGENT, 0x11, 32);
    test_branch_ids();
    test_root();
    test_manifest();
    test_state();
    test_wal();
    test_decode_cap();
#ifdef CC_FIXTURE_DIR
    const char *dir = argc > 1 ? argv[1] : CC_FIXTURE_DIR;
#else
    const char *dir = argc > 1 ? argv[1] : 0;
#endif
    int loaded = dir && load_fixtures(dir);
    CHECK(loaded);
    if (loaded) {
        test_golden();
        test_tampered();
    }
    return ck_t_verdict("test_continuity_codec");
}
