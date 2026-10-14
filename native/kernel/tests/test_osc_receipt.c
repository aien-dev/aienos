/* test_osc_receipt.c -- host test for artifact/osc_receipt.c (Omega realization receipt v1, aienos#383) under
 * the kernel's own policy (core/osc_admit.c ck_osc_policy, linked in).
 *
 * Built twice: with CK_SEED0B_TEST_ANCHOR=1 (the qualification policy: checker2's TEST key anchored) and without
 * it (the release policy: no receipt anchor, release mode). Checks:
 *   - every line of tests/fixtures/osc_receipt/expected.txt: the receipt, minted by omega checker2, verified
 *     against the admitted unit gives the stated kernel verdict (checker2's own verdict for the same policy is
 *     recorded beside it by make-receipts.sh); in the release build every one is refused;
 *   - the trust inputs: the TEST key header against the fixtures, the pinned checker identity, the target hash,
 *     the revoked fixture id, the owner root listed but never trusted;
 *   - each structure reason, the order of the checks, anchor rules, epoch window edges, every single-bit flip;
 *   - the Store receipt table of osc_admit.c (kept by name, oversize, full).
 * The mutation run (Makefile osc-receipt-mutants) requires this test to FAIL with any one MUT guard removed. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "osc_admit.h"
#include "osc_receipt.h"
#include "osc_receipt_anchor.h"
#include "osc_receipt_test_anchor.h"
#include "osc_unit.h"
#include "osc_unit_test_anchor.h"
#include "sha256.h"
#include "aienos_sig.h"

#ifndef OSC_FIXTURE_DIR
#define OSC_FIXTURE_DIR "native/kernel/tests/fixtures"
#endif

static char out[8192];
static size_t outn;
void ck_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + outn, sizeof out - outn, fmt, ap);
    va_end(ap);
    if (n > 0 && outn + (size_t)n < sizeof out) outn += (size_t)n;
}

static size_t slurp(const char *rel, uint8_t *buf, size_t cap)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", OSC_FIXTURE_DIR, rel);
    FILE *f = fopen(path, "rb");
    if (!f) { printf("  cannot open %s\n", path); return 0; }
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

static const char *unit_path(const char *u)
{
    if (!strcmp(u, "a01")) return "osc_unit/vectors/a01_valid_min.unit";
    if (!strcmp(u, "l01")) return "osc_unit/launch/l01_launch_fns.unit";
    if (!strcmp(u, "osh_lex")) return "osh/osh_lex.unit";
    if (!strcmp(u, "osh_parse")) return "osh/osh_parse.unit";
    if (!strcmp(u, "osh_expand")) return "osh/osh_expand.unit";
    return "?";
}

/* the unit admitted with the container TEST key (admission is not what is tested here) */
static int admit(const char *u, struct osc_accept *a)
{
    static uint8_t buf[OSC_UNIT_MAX_BYTES];
    size_t n = slurp(unit_path(u), buf, sizeof buf);
    struct osc_policy p;
    memset(&p, 0, sizeof p);
    static const uint8_t (*const ta)[32] = &osc_unit_test1_pk;
    p.test_anchors = ta;
    p.n_test = 1;
    p.unit_formats = OSC_PROFILE_UNIT_FORMATS;
    p.abi_versions = OSC_PROFILE_ABI;
    p.cap_domains = 1u << 1;
    return n && osc_unit_admit(buf, n, &p, a) == OSC_OK;
}

static size_t rcpt(const char *name, uint8_t *b)
{
    char rel[128];
    snprintf(rel, sizeof rel, "osc_receipt/%s", name);
    return slurp(rel, b, 1024);
}

/* "VALID" -> 0, else the kernel code whose name is RECEIPT_<name>; ~0u if unknown */
static unsigned code_of(const char *name)
{
    if (!strcmp(name, "VALID")) return 0;
    for (unsigned c = 64; c < 96; c++) {
        const char *k = osc_code_name(c);
        if (!strncmp(k, "RECEIPT_", 8) && !strcmp(k + 8, name)) return c;
    }
    return ~0u;
}

static void hex(const uint8_t *p, size_t n, char *o)
{
    for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", p[i]);
}

static uint8_t test_fp[1][32], producer[32];

static void apply_variant(struct osc_policy *p, const char *v)
{
    if (!strcmp(v, "release")) p->release = 1;
    if (!strcmp(v, "revoke_key")) { p->rcpt_revoked_keys = (const uint8_t (*)[32])test_fp; p->n_rcpt_revoked_keys = 1; }
    if (!strcmp(v, "producer")) p->rcpt_producer = producer;
}

static void expected_table(void)
{
    char path[512], line[512];
    snprintf(path, sizeof path, "%s/osc_receipt/expected.txt", OSC_FIXTURE_DIR);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (!f) return;
    int n = 0, refused = 0;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char name[64], unit[64], variant[32], c2[64], kv[64], idhex[80];
        if (sscanf(line, "%63s unit=%63s variant=%31s checker2=%63s kernel=%63s id=%79s", name, unit, variant, c2, kv,
                   idhex) != 6) { CHECK(0); continue; }
        uint8_t r[1024];
        size_t len = rcpt(name, r);
        struct osc_accept a;
        CHECK(admit(unit, &a));
        struct osc_policy p;
        ck_osc_policy(&p);
        apply_variant(&p, variant);
        struct osc_receipt_info info;
        unsigned got = osc_receipt_verify(r, len, &a, &p, &info), want = code_of(kv);
        CHECK(want != ~0u);
#ifdef CK_SEED0B_TEST_ANCHOR
        if (got != want) printf("  %s unit=%s variant=%s: got %u %s, want %s\n", name, unit, variant, got, osc_code_name(got), kv);
        CHECK(got == want);
        /* where the kernel checks what checker2 checks, the verdicts agree (the oracle) */
        CHECK(!strcmp(c2, kv));
#else
        /* release policy: TEST receipts are refused; only a structure fault is reported before that */
        unsigned rel = want == OSC_RCPT_SIZE ? OSC_RCPT_SIZE : OSC_RCPT_TEST_SIGNER_IN_PRODUCTION;
        if (got != rel) printf("  release %s: got %u %s\n", name, got, osc_code_name(got));
        CHECK(got == rel);
#endif
        if (got) refused++;
        if (len == OSC_RCPT_BYTES) {
            char h[65];
            hex(info.id, 32, h);
            CHECK(info.have_id && !strcmp(h, idhex));
        }
        n++;
    }
    fclose(f);
    CHECK(n == 22);
    printf("  expected.txt: %d cases, %d refused\n", n, refused);
}

static void trust_inputs(void)
{
    uint8_t r[1024], h[32];
    CHECK(rcpt("a01.rcpt", r) == OSC_RCPT_BYTES);
    /* the TEST key header is the key whose fingerprint checker2 wrote, and it verifies (a01 is VALID above) */
    sha256_hash(osc_rcpt_test_pk, 32, h);
    CHECK(memcmp(h, r + 320, 32) == 0);
    CHECK(memcmp(osc_rcpt_test_pk, osc_unit_test1_pk, 32) != 0); /* not the container TEST key */
    CHECK(memcmp(osc_rcpt_checker_ids[0], r + 144, 32) == 0);    /* pinned checker identity = the minting checker2 */
    osc_receipt_target_hash(OSC_RCPT_TARGET_NAME, strlen(OSC_RCPT_TARGET_NAME), h);
    CHECK(memcmp(h, r + 208, 32) == 0);                          /* target constant = what issue --target wrote */
    uint8_t rv[1024];
    size_t rl = rcpt("n_revoked_id.rcpt", rv);
    sha256_hash(rv, rl, h);
    CHECK(rl == OSC_RCPT_BYTES && memcmp(h, osc_rcpt_qual_revoked_id, 32) == 0);
    struct osc_policy p;
    ck_osc_policy(&p);
    CHECK(p.n_rcpt_owner == 0 && p.rcpt_owner_anchors == NULL);  /* owner root listed, not trusted */
    CHECK(p.n_rcpt_checkers == 1 && p.rcpt_target != NULL && p.rcpt_producer == NULL && p.rcpt_firmware == NULL);
    CHECK(p.rcpt_epoch_floor == 10 && p.rcpt_epoch_now == 20 && p.n_rcpt_revoked_keys == 0);
    for (unsigned i = 0; i < p.n_rcpt_test; i++) CHECK(memcmp(p.rcpt_test_anchors[i], osc_rcpt_owner_root_pk, 32) != 0);
#ifdef CK_SEED0B_TEST_ANCHOR
    CHECK(!p.release && p.n_rcpt_test == 1 && memcmp(p.rcpt_test_anchors[0], osc_rcpt_test_pk, 32) == 0);
    CHECK(p.n_rcpt_revoked_ids == 1);
#else
    CHECK(p.release && p.n_rcpt_test == 0 && p.n_rcpt_revoked_ids == 0);
#endif
    /* the owner root constant is the ceremony key of docs/OWNER_KEY_CEREMONY.md (aienos#380) */
    static const char owner_hex[] = "578ada3cb0c2d154623ac089191023c8ad4bc5e63b8ccd1a38db2d679b8c9e76";
    char oh[65];
    hex(osc_rcpt_owner_root_pk, 32, oh);
    CHECK(!strcmp(oh, owner_hex));
}

/* the qualification policy, with the TEST anchor whatever this binary's build is */
static struct osc_policy qual(void)
{
    struct osc_policy p;
    ck_osc_policy(&p);
    static const uint8_t (*const rta)[32] = &osc_rcpt_test_pk;
    static const uint8_t (*const rid)[32] = &osc_rcpt_qual_revoked_id;
    p.release = 0;
    p.rcpt_test_anchors = rta;
    p.n_rcpt_test = 1;
    p.rcpt_revoked_ids = rid;
    p.n_rcpt_revoked_ids = 1;
    return p;
}

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

static unsigned v(const uint8_t *r, size_t len, const struct osc_accept *a, const struct osc_policy *p)
{
    return osc_receipt_verify(r, len, a, p, NULL);
}

static void structure_and_order(void)
{
    uint8_t g[1024], r[1024];
    CHECK(rcpt("a01.rcpt", g) == OSC_RCPT_BYTES);
    struct osc_accept a;
    CHECK(admit("a01", &a));
    struct osc_policy p = qual();
    CHECK(v(g, 416, &a, &p) == 0);
    CHECK(v(NULL, 416, &a, &p) == OSC_RCPT_MISSING);
    CHECK(v(g, 0, &a, &p) == OSC_RCPT_MISSING);
    CHECK(v(g, 416, NULL, &p) == OSC_RCPT_ARGUMENT);
    CHECK(v(g, 416, &a, NULL) == OSC_RCPT_ARGUMENT);
    CHECK(v(g, 415, &a, &p) == OSC_RCPT_SIZE);
    CHECK(v(g, 417, &a, &p) == OSC_RCPT_SIZE);
#define MUTATE(stmt, want) do { memcpy(r, g, 416); stmt; unsigned got_ = v(r, 416, &a, &p); \
        if (got_ != (want)) { printf("  %s: got %u %s\n", #stmt, got_, osc_code_name(got_)); } \
        CHECK(got_ == (want)); } while (0)
    MUTATE(r[0] ^= 1, OSC_RCPT_MAGIC);
    MUTATE(r[7] = 1, OSC_RCPT_MAGIC);
    MUTATE(put16(r + 8, 2), OSC_RCPT_VERSION);
    MUTATE(put16(r + 8, 0), OSC_RCPT_VERSION);
    MUTATE(put16(r + 12, 2), OSC_RCPT_SIGNATURE_ALGORITHM);
    MUTATE(put16(r + 10, 3), OSC_RCPT_SIGNER_CLASS);
    MUTATE(put16(r + 10, 0), OSC_RCPT_SIGNER_CLASS);
    MUTATE(put16(r + 14, 3), OSC_RCPT_EVIDENCE_CLASS);
    MUTATE(put16(r + 14, 0), OSC_RCPT_EVIDENCE_CLASS);
    MUTATE(put16(r + 14, 2), OSC_RCPT_BAD_SIGNATURE); /* class 2 is well formed; the signature covers the change */
    MUTATE(put64(r + 312, 9), OSC_RCPT_EPOCH_ORDER);   /* expiry 9 < policy epoch 10 */
    MUTATE(put64(r + 312, 10), OSC_RCPT_BAD_SIGNATURE); /* expiry == epoch is in order */
    /* order: the first failing step wins */
    MUTATE((r[0] ^= 1, put16(r + 8, 2)), OSC_RCPT_MAGIC);
    MUTATE((put16(r + 8, 2), put16(r + 12, 2)), OSC_RCPT_VERSION);
    MUTATE((put16(r + 12, 2), put16(r + 10, 3)), OSC_RCPT_SIGNATURE_ALGORITHM);
    MUTATE((put16(r + 10, 3), put16(r + 14, 3)), OSC_RCPT_SIGNER_CLASS);
    MUTATE((put16(r + 14, 3), put64(r + 312, 9)), OSC_RCPT_EVIDENCE_CLASS);
    MUTATE((put64(r + 312, 9), r[400] ^= 1), OSC_RCPT_EPOCH_ORDER);
    MUTATE(r[400] ^= 1, OSC_RCPT_BAD_SIGNATURE);
    MUTATE(r[303] ^= 1, OSC_RCPT_BAD_SIGNATURE);     /* last byte of the input digest, signed */
    MUTATE(r[351] ^= 1, OSC_RCPT_UNTRUSTED_SIGNER);   /* last fingerprint byte */
    MUTATE(r[320] ^= 1, OSC_RCPT_UNTRUSTED_SIGNER);    /* fingerprint names no anchor */
    MUTATE(put16(r + 10, 2), OSC_RCPT_UNTRUSTED_SIGNER); /* OWNER class: no owner anchor in the kernel policy */
    p.release = 1;
    MUTATE((void)0, OSC_RCPT_TEST_SIGNER_IN_PRODUCTION);
    MUTATE(put64(r + 312, 9), OSC_RCPT_EPOCH_ORDER);   /* structure before class policy */
    MUTATE(put16(r + 10, 2), OSC_RCPT_UNTRUSTED_SIGNER);
    /* release: an owner anchor other than the listed owner root is not honoured (here the TEST key as "owner") */
    static const uint8_t (*const tk)[32] = &osc_rcpt_test_pk;
    p.rcpt_owner_anchors = tk;
    p.n_rcpt_owner = 1;
    p.n_rcpt_test = 0; /* so the both-classes rule (guard 11) cannot answer for the owner-root rule (guard 10) */
    MUTATE(put16(r + 10, 2), OSC_RCPT_UNTRUSTED_SIGNER);
    p.release = 0;
    p.n_rcpt_test = 0;
    MUTATE(put16(r + 10, 2), OSC_RCPT_BAD_SIGNATURE); /* qualification honours it, then the class byte breaks the sig */
    /* a key anchored in both classes is refused */
    p = qual();
    p.rcpt_owner_anchors = tk;
    p.n_rcpt_owner = 1;
    MUTATE((void)0, OSC_RCPT_UNTRUSTED_SIGNER);
    p = qual();
    static const uint8_t (*const ok)[32] = &osc_rcpt_owner_root_pk;
    p.rcpt_test_anchors = ok;                          /* wrong key in the TEST set */
    MUTATE((void)0, OSC_RCPT_UNTRUSTED_SIGNER);
    p = qual();
    p.n_rcpt_test = 0;
    MUTATE((void)0, OSC_RCPT_UNTRUSTED_SIGNER);
#undef MUTATE
}

static void policy_edges(void)
{
    uint8_t g[1024], rv[1024], fw[1024], np[1024];
    CHECK(rcpt("a01.rcpt", g) == OSC_RCPT_BYTES);
    CHECK(rcpt("n_revoked_id.rcpt", rv) == OSC_RCPT_BYTES);
    CHECK(rcpt("n_firmware.rcpt", fw) == OSC_RCPT_BYTES);
    CHECK(rcpt("n_producer.rcpt", np) == OSC_RCPT_BYTES);
    struct osc_accept a;
    CHECK(admit("a01", &a));
    struct osc_policy p = qual();
    struct osc_receipt_info info;
    /* revocation: the id is checked before the key */
    p.rcpt_revoked_keys = (const uint8_t (*)[32])test_fp;
    p.n_rcpt_revoked_keys = 1;
    CHECK(osc_receipt_verify(rv, 416, &a, &p, &info) == OSC_RCPT_REVOKED && info.revoked == OSC_RCPT_REVOKED_ID);
    CHECK(osc_receipt_verify(g, 416, &a, &p, &info) == OSC_RCPT_REVOKED && info.revoked == OSC_RCPT_REVOKED_KEY);
    p = qual();
    p.n_rcpt_revoked_ids = 0;
    CHECK(v(rv, 416, &a, &p) == 0);
    /* revocation before freshness: a revoked receipt that is also stale says REVOKED */
    p = qual();
    p.rcpt_epoch_floor = 12;
    CHECK(v(rv, 416, &a, &p) == OSC_RCPT_REVOKED);
    /* epoch window, inclusive at both ends (a01: policy epoch 10, expiry 1000) */
    p = qual();
    p.rcpt_epoch_now = 1000;
    CHECK(v(g, 416, &a, &p) == 0);
    p.rcpt_epoch_now = 1001;
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_EXPIRED);
    p.rcpt_epoch_now = 10;
    CHECK(v(g, 416, &a, &p) == 0);
    p.rcpt_epoch_now = 9;
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_NOT_YET_VALID);
    p.rcpt_epoch_now = 20;
    p.rcpt_epoch_floor = 11;
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_STALE_EPOCH);
    p.rcpt_epoch_now = 2000; /* stale wins over expired */
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_STALE_EPOCH);
    p = qual();
    /* checker list required; empty refuses every receipt */
    p.n_rcpt_checkers = 0;
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_UNTRUSTED_CHECKER);
    p = qual();
    p.rcpt_epoch_now = 2000; /* freshness before checker identity */
    p.n_rcpt_checkers = 0;
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_EXPIRED);
    /* binding: target required */
    p = qual();
    p.rcpt_target = NULL;
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_WRONG_TARGET);
    p = qual();
    p.n_rcpt_checkers = 0; /* checker before binding */
    p.rcpt_target = NULL;
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_UNTRUSTED_CHECKER);
    /* firmware: a policy that names one accepts exactly that one */
    p = qual();
    p.rcpt_firmware = fw + 240;
    CHECK(v(fw, 416, &a, &p) == 0);
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_WRONG_FIRMWARE);
    /* producer: NULL means none (all zero); a policy that names one accepts exactly that one */
    p = qual();
    CHECK(v(np, 416, &a, &p) == OSC_RCPT_WRONG_PRODUCER);
    p.rcpt_producer = np + 176;
    CHECK(v(np, 416, &a, &p) == 0);
    CHECK(v(g, 416, &a, &p) == OSC_RCPT_WRONG_PRODUCER);
    /* the binding reads the admitted unit: a different code hash in the verdict is EXECUTABLE_MISMATCH, a different
     * IR hash PROGRAM_MISMATCH (program before executable) */
    p = qual();
    struct osc_accept b = a;
    b.code_sha256[31] ^= 1;
    CHECK(v(g, 416, &b, &p) == OSC_RCPT_EXECUTABLE_MISMATCH);
    b.ir_sha256[0] ^= 1;
    CHECK(v(g, 416, &b, &p) == OSC_RCPT_PROGRAM_MISMATCH);
    /* every single-bit flip of a valid receipt is refused */
    uint8_t r[416];
    int flips = 0, accepted = 0;
    for (unsigned i = 0; i < 416; i++)
        for (unsigned bit = 0; bit < 8; bit++) {
            memcpy(r, g, 416);
            r[i] ^= (uint8_t)(1u << bit);
            if (v(r, 416, &a, &p) == 0) accepted++;
            flips++;
        }
    CHECK(flips == 3328 && accepted == 0);
    printf("  single-bit flips of a01.rcpt: %d refused of %d\n", flips - accepted, flips);
    /* the verifier is pure: the same inputs give the same verdict and the inputs are not written */
    uint8_t before[416];
    memcpy(before, g, 416);
    CHECK(v(g, 416, &a, &p) == 0 && v(g, 416, &a, &p) == 0 && memcmp(before, g, 416) == 0);
}

/* Re-sign a receipt in memory with checker2's published TEST key (spec section 3: seed = SHA-256 of the stated
 * string; the key is a TEST key by definition, never a release signer). Written from spec section 3; it must
 * reproduce checker2's own signature on an unchanged receipt (Ed25519 is deterministic), which cross-checks the
 * signed-message construction of the verifier from a second direction. */
static void test_seed(uint8_t sk[32])
{
    static const char s[] = "OMEGA-CHECKER2-TEST-KEY-v1 NOT FOR PRODUCTION";
    sha256_hash((const uint8_t *)s, sizeof s - 1, sk);
}

static void resign(uint8_t *r)
{
    static const char body_dom[] = "OMEGA-REALIZATION-RECEIPT-V1", sig_dom[] = "OMEGA-REALIZATION-RECEIPT-SIG-V1";
    uint8_t msg[sizeof sig_dom + 32], sk[32];
    sha256_ctx c;
    memcpy(msg, sig_dom, sizeof sig_dom);
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)body_dom, sizeof body_dom);
    sha256_update(&c, r, OSC_RCPT_SIGNED_BYTES);
    sha256_final(&c, msg + sizeof sig_dom);
    test_seed(sk);
    CHECK(aienos_ed25519_sign(r + OSC_RCPT_SIGNED_BYTES, msg, sizeof msg, sk) == AIENOS_SIG_OK);
    memset(sk, 0, sizeof sk);
}

static void resigned(void)
{
    uint8_t g[1024], r[416], sk[32], pk[32];
    CHECK(rcpt("a01.rcpt", g) == OSC_RCPT_BYTES);
    test_seed(sk);
    CHECK(aienos_ed25519_public_key(pk, sk) == AIENOS_SIG_OK && memcmp(pk, osc_rcpt_test_pk, 32) == 0);
    memcpy(r, g, 416);
    memset(r + 352, 0, 64);
    resign(r);
    CHECK(memcmp(r, g, 416) == 0); /* same bytes as checker2 wrote */
    struct osc_accept a;
    CHECK(admit("a01", &a));
    struct osc_policy p = qual();
    /* evidence class 2, correctly signed: refused LRAT_PROOFS_REQUIRED, and only after every section 6 step */
    memcpy(r, g, 416);
    put16(r + 14, 2);
    resign(r);
    CHECK(v(r, 416, &a, &p) == OSC_RCPT_LRAT_PROOFS_REQUIRED);
    memcpy(r, g, 416);
    put16(r + 14, 2);
    r[208] ^= 1;
    resign(r);
    CHECK(v(r, 416, &a, &p) == OSC_RCPT_WRONG_TARGET);
    /* a signed class 1 receipt with a changed field reaches the step that reads that field */
    memcpy(r, g, 416);
    r[272] ^= 1; /* input digest: NOT CHECKED, still valid */
    r[16] ^= 1;  /* requirements digest: NOT CHECKED for class 1, still valid */
    resign(r);
    CHECK(v(r, 416, &a, &p) == 0);
    memcpy(r, g, 416);
    put64(r + 304, 15); /* policy epoch 15, now 20: valid; now 14: NOT_YET_VALID */
    resign(r);
    CHECK(v(r, 416, &a, &p) == 0);
    p.rcpt_epoch_now = 14;
    CHECK(v(r, 416, &a, &p) == OSC_RCPT_NOT_YET_VALID);
}

static void names(void)
{
    CHECK(!strcmp(osc_code_name(OSC_RCPT_MISSING), "RECEIPT_MISSING"));
    CHECK(!strcmp(osc_code_name(OSC_RCPT_REVOKED), "RECEIPT_REVOKED"));
    CHECK(!strcmp(osc_code_name(OSC_RCPT_DEPENDENCIES_MISMATCH), "RECEIPT_DEPENDENCIES_MISMATCH"));
    CHECK(!strcmp(osc_code_name(OSC_RCPT_LRAT_PROOFS_REQUIRED), "RECEIPT_LRAT_PROOFS_REQUIRED") && !strcmp(osc_code_name(95), "?"));
    CHECK(!strcmp(osc_code_name(72), "?") && !strcmp(osc_code_name(85), "?") && !strcmp(osc_code_name(89), "?"));
    CHECK(!strcmp(osc_code_name(OSC_CODE_HASH_MISMATCH), "CODE_HASH_MISMATCH")); /* unit codes unchanged */
    /* spec reason n is kernel code 64 + n */
    CHECK(OSC_RCPT_SIZE == OSC_RCPT_BASE + 1 && OSC_RCPT_UNTRUSTED_CHECKER == OSC_RCPT_BASE + 22);
}

static void store_table(void)
{
    uint8_t g[1024], big[600];
    CHECK(rcpt("a01.rcpt", g) == OSC_RCPT_BYTES);
    CHECK(ck_osc_is_receipt(g, 416) && !ck_osc_is_receipt(g, 7) && !ck_osc_is_receipt(NULL, 416));
    CHECK(!ck_osc_is_receipt((const uint8_t *)"OSCUNIT\0", 8));
    size_t len = 99;
    CHECK(ck_osc_receipt_find("a01.rcpt", &len) == NULL && len == 0);
    outn = 0;
    ck_osc_receipt_candidate("a01.rcpt", g, 416);
    CHECK(strstr(out, "osc_receipt: a01.rcpt STORED bytes=416 id=613e1cece39535842e2b3e406147b837b4bb1ed91628caf54735c7c09cb70996 ") != NULL);
    const uint8_t *k = ck_osc_receipt_find("a01.rcpt", &len);
    CHECK(k != NULL && len == 416 && memcmp(k, g, 416) == 0);
    CHECK(ck_osc_receipt_find("a01.rcp", &len) == NULL && ck_osc_receipt_find("a01.rcpt2", &len) == NULL);
    memcpy(big, g, 416);
    memset(big + 416, 0, sizeof big - 416);
    ck_osc_receipt_candidate("big.rcpt", big, sizeof big);
    k = ck_osc_receipt_find("big.rcpt", &len);
    struct osc_accept a;
    CHECK(admit("a01", &a));
    struct osc_policy p = qual();
    CHECK(k != NULL && len == 512 && v(k, len, &a, &p) == OSC_RCPT_SIZE);
    char nm[16];
    for (unsigned i = 0; i < 30; i++) {
        snprintf(nm, sizeof nm, "f%u.rcpt", i);
        ck_osc_receipt_candidate(nm, g, 416);
    }
    CHECK(strstr(out, "osc_receipt: f21.rcpt STORED") != NULL && strstr(out, "osc_receipt: f22.rcpt DROPPED") != NULL);
    CHECK(ck_osc_receipt_find("f22.rcpt", &len) == NULL);
    outn = 0;
    ck_osc_summary();
    CHECK(strstr(out, "osc_receipts: seen=32 stored=24 dropped=8 ") != NULL);
}

int main(void)
{
    sha256_hash(osc_rcpt_test_pk, 32, test_fp[0]);
    {
        uint8_t np[1024];
        CHECK(rcpt("n_producer.rcpt", np) == OSC_RCPT_BYTES);
        memcpy(producer, np + 176, 32);
    }
#ifdef CK_SEED0B_TEST_ANCHOR
    printf("  policy: qualification (CK_SEED0B_TEST_ANCHOR)\n");
#else
    printf("  policy: release\n");
#endif
    expected_table();
    trust_inputs();
    structure_and_order();
    policy_edges();
    names();
    resigned();
    store_table();
    return ck_t_verdict("test_osc_receipt");
}
