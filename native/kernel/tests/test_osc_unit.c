/* test_osc_unit.c -- host conformance harness for artifact/osc_unit.c.
 * Runs every line of the frozen OSC_UNIT_ARTIFACT v1 vector files (copied to
 * tests/fixtures/osc_unit, provenance there): expected.txt (container
 * verdicts), lookups.txt (exact-name lookups) and state.txt (loader-state
 * scenarios, codes 29 and 30), and requires the stated verdict byte for byte.
 * Keys are the spec's THROWAWAY TEST keys. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "osc_unit.h"
#include "osc_unit_test_anchor.h"
#include "sha256.h"

#ifndef OSC_FIXTURE_DIR
#define OSC_FIXTURE_DIR "native/kernel/tests/fixtures/osc_unit"
#endif

static const char *fixdir = OSC_FIXTURE_DIR;
static uint8_t key_test[32], key_owner[32];

static int hexval(int c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }

static int load_key(const char *name, uint8_t out[32])
{
    char path[512], line[256];
    snprintf(path, sizeof path, "%s/keys/%s", fixdir, name);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(line, sizeof line, f)) { fclose(f); return 0; }
    fclose(f);
    for (int i = 0; i < 32; i++) {
        int h = hexval(line[2 * i]), l = hexval(line[2 * i + 1]);
        if (h < 0 || l < 0) return 0;
        out[i] = (uint8_t)(h * 16 + l);
    }
    return 1;
}

static uint8_t *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long l = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(l > 0 ? (size_t)l : 1);
    if (b && fread(b, 1, (size_t)l, f) != (size_t)l) { free(b); b = 0; }
    fclose(f);
    *n = b ? (size_t)l : 0;
    return b;
}

static void hex(const uint8_t *p, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", p[i]);
}

/* loader-state scenario */
struct state { int noreserve; int have_gens; unsigned dom[8], kind[8]; uint32_t id[8]; uint64_t gen[8]; int n; };

static int st_lookup(void *ctx, unsigned dom, unsigned kind, uint32_t id, uint64_t *cur)
{
    struct state *s = ctx;
    for (int i = 0; i < s->n; i++)
        if (s->dom[i] == dom && s->kind[i] == kind && s->id[i] == id) { *cur = s->gen[i]; return 0; }
    return 1;
}
static int st_reserve(void *ctx, const struct osc_accept *a) { (void)a; return ((struct state *)ctx)->noreserve; }

static struct osc_policy policy_for(const char *mode, const char *domains, const char *anchors, struct state *st)
{
    static uint8_t t[1][32], o[1][32];
    struct osc_policy p;
    memset(&p, 0, sizeof p);
    p.release = strcmp(mode, "release") == 0;
    memcpy(t[0], key_test, 32);
    memcpy(o[0], key_owner, 32);
    if (strchr(anchors, 'T')) { p.test_anchors = t; p.n_test = 1; }
    if (strchr(anchors, 'O')) { p.owner_anchors = o; p.n_owner = 1; }
    p.unit_formats = OSC_PROFILE_UNIT_FORMATS;
    p.abi_versions = OSC_PROFILE_ABI;
    for (const char *c = domains; *c; c++)
        if (*c >= '0' && *c <= '9') p.cap_domains |= 1u << (*c - '0');
    p.ctx = st;
    if (st && st->have_gens) p.gen_lookup = st_lookup;
    if (st && st->noreserve) p.reserve = st_reserve;
    return p;
}

static void verdict_text(unsigned rc, const struct osc_accept *a, char *out, size_t n)
{
    if (rc == OSC_OK) {
        char d[65], i[65];
        hex(a->unit_digest, 32, d);
        hex(a->ir_sha256, 32, i);
        snprintf(out, n, "ACCEPT unit_digest=%s program_id=%s", d, i);
    } else {
        snprintf(out, n, "REFUSED %s %u", osc_code_name(rc), rc);
    }
}

static unsigned admit_file(const char *vec, const struct osc_policy *p, struct osc_accept *a, uint8_t **keep, size_t *kn)
{
    char path[512];
    size_t n;
    snprintf(path, sizeof path, "%s/vectors/%s", fixdir, vec);
    uint8_t *b = slurp(path, &n);
    if (!b) return 999;
    unsigned rc = osc_unit_admit(b, n, p, a);
    if (keep) { *keep = b; *kn = n; } else free(b);
    return rc;
}

/* run lines of a vector file; kind 0 expected, 1 lookups, 2 state. Returns lines checked. */
static int run_file(const char *name, int kind)
{
    char path[512], line[1024];
    int count = 0;
    snprintf(path, sizeof path, "%s/vectors/%s", fixdir, name);
    FILE *f = fopen(path, "r");
    CHECK(f != 0);
    if (!f) return 0;
    static struct osc_accept acc;
    while (fgets(line, sizeof line, f)) {
        char vec[128], mode[32], dom[32], anc[8], arg[128] = "", want[600];
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
        if (!l || line[0] == '#') continue;
        int ok;
        if (kind == 0) ok = sscanf(line, "%127s %31s %31s %7s %599[^\n]", vec, mode, dom, anc, want) == 5;
        else ok = sscanf(line, "%127s %31s %31s %7s %127s %599[^\n]", vec, mode, dom, anc, arg, want) == 6;
        CHECK(ok);
        if (!ok) continue;
        struct state st;
        memset(&st, 0, sizeof st);
        if (kind == 2) {
            if (strcmp(arg, "noreserve") == 0) st.noreserve = 1;
            else if (strncmp(arg, "gens=", 5) == 0) {
                st.have_gens = 1;
                unsigned d, k, id; unsigned long long g;
                if (sscanf(arg + 5, "%u:%u:%u=%llu", &d, &k, &id, &g) == 4) {
                    st.dom[0] = d; st.kind[0] = k; st.id[0] = id; st.gen[0] = g; st.n = 1;
                } else CHECK(0);
            } else CHECK(0);
        }
        struct osc_policy p = policy_for(mode, dom, anc, &st);
        uint8_t *bytes = 0; size_t bn = 0;
        unsigned rc = admit_file(vec, &p, &acc, &bytes, &bn);
        char got[700];
        if (kind == 1) {
            if (rc != OSC_OK) { snprintf(got, sizeof got, "REFUSED %s %u", osc_code_name(rc), rc); }
            else {
                int fi = osc_unit_lookup(&acc, arg, strlen(arg));
                if (fi < 0) snprintf(got, sizeof got, "REFUSED %s %d", osc_code_name(OSC_LAUNCH_BAD_ENTRY), OSC_LAUNCH_BAD_ENTRY);
                else snprintf(got, sizeof got, "ACCEPT fn_index=%d", fi);
            }
        } else {
            verdict_text(rc, &acc, got, sizeof got);
        }
        free(bytes);
        if (strcmp(got, want) != 0) {
            printf("  MISMATCH %s [%s]\n    want: %s\n    got:  %s\n", vec, arg, want, got);
            ck_t_fail++;
        }
        ck_t_run++;
        count++;
    }
    fclose(f);
    return count;
}

/* Every single-byte flip and every truncation of the valid vector must be refused, never crash
 * (run under ASAN/UBSAN by `make sanitize`). */
static void test_flips_and_truncations(void)
{
    char path[512];
    size_t n;
    snprintf(path, sizeof path, "%s/vectors/a01_valid_min.unit", fixdir);
    uint8_t *b = slurp(path, &n);
    CHECK(b != 0);
    if (!b) return;
    struct state st; memset(&st, 0, sizeof st);
    struct osc_policy p = policy_for("qualification", "1", "T", &st);
    static struct osc_accept acc;
    CHECK(osc_unit_admit(b, n, &p, &acc) == OSC_OK);
    int accepted = 0;
    for (size_t i = 0; i < n; i++) {
        b[i] ^= 0x01;
        if (osc_unit_admit(b, n, &p, &acc) == OSC_OK) accepted++;
        b[i] ^= 0x01;
    }
    CHECK(accepted == 0);
    for (size_t l = 0; l < n; l++) {
        unsigned rc = osc_unit_admit(b, l, &p, &acc);
        CHECK(rc != OSC_OK);
    }
    CHECK(osc_unit_admit(0, 0, &p, &acc) != OSC_OK);
    free(b);
}

/* Section 8.4 on hand-picked words. */
static void test_words(void)
{
    static const uint32_t allowed[] = {
        0x8B010002u,  /* add x2, x0, x1 */   0xD2800020u,  /* movz x0, #1 */
        0xD65F03C0u,  /* ret */              0xD63F0200u,  /* blr x16 */
        0xA9BF7BFDu,  /* stp x29, x30, [sp, #-16]! */  0xA8C17BFDu, /* ldp x29, x30, [sp], #16 */
        0xD4200060u,  /* brk #3 */          0x94000010u,  /* bl */
        0x38606800u | (1u << 16) | (2u << 5) | 3u, /* ldrb w3, [x2, x0] shape */
    };
    static const uint32_t refused[] = {
        0xD4000001u,  /* svc #0 */           0xD4000002u,  /* hvc #0 */
        0xD4000003u,  /* smc #0 */           0xD5033FDFu,  /* isb */
        0xD503201Fu,  /* nop */              0xD53B4200u,  /* mrs x0, nzcv-ish */
        0xD51B4200u,  /* msr */              0xD69F03E0u,  /* eret */
        0xC85F7C00u,  /* ldxr */             0x1E602800u,  /* fadd d0, d0, d0 */
        0xD4200000u,  /* brk #0 */           0xD42001E0u,  /* brk #15 */
        0xD63F03E0u,  /* blr xzr-slot (rn=31) */ 0xD4400000u, /* hlt */
        0x00000000u,  /* udf */              0xFFFFFFFFu,
        0xCB000000u | (3u << 22), /* sub with ROR shift */
        0x9A80F400u,  /* csinc cond NV */    0x5400000Eu,  /* b.al */
        0x5400000Fu,  /* b.nv */
    };
    for (size_t i = 0; i < sizeof allowed / sizeof allowed[0]; i++) CHECK(osc_a64_word_allowed(allowed[i]));
    for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
        CHECK(!osc_a64_word_allowed(refused[i]));
    }
    /* ldp Rt == Rt2 (x1, x1) refused by the round trip; stp with Rt == Rt2 is allowed. */
    CHECK(!osc_a64_word_allowed(0xA9400000u | (1u << 10) | (2u << 5) | 1u));
    CHECK(osc_a64_word_allowed(0xA9000000u | (1u << 10) | (2u << 5) | 1u));
    /* writeback base equal to a transfer register */
    CHECK(!osc_a64_word_allowed(0xA9800000u | (3u << 10) | (2u << 5) | 2u));
}

/* Lookup is by exact name only. Two entries forced to share a name_hash (a
 * case no signed vector can carry: it needs a SHA-256 collision) must still
 * resolve by name, and an absent name with that hash must not match. */
static void test_lookup_ignores_name_hash(void)
{
    static struct osc_accept a;
    memset(&a, 0, sizeof a);
    a.function_count = 2;
    const char *nm[2] = {"add", "sub"};
    for (unsigned i = 0; i < 2; i++) {
        a.entry[i].fn_index = (uint16_t)(7 + i);
        a.entry[i].name_len = 3;
        memcpy(a.entry[i].name, nm[i], 4);
        memset(a.entry[i].name_hash, 0xAB, 16);
    }
    CHECK(osc_unit_lookup(&a, "add", 3) == 7);
    CHECK(osc_unit_lookup(&a, "sub", 3) == 8);
    CHECK(osc_unit_lookup(&a, "mul", 3) == -1);
    CHECK(osc_unit_lookup(&a, "ad", 2) == -1);
    CHECK(osc_unit_lookup(&a, "addx", 4) == -1);
}

static void test_anchor_matches_fixture(void)
{
    CHECK(memcmp(osc_unit_test1_pk, key_test, 32) == 0);
}

/* Spec 8.2 step 16: a loader whose staging maximum is smaller than the file refuses with
 * RESOURCE_UNAVAILABLE before parsing; a file that fits is judged normally. */
static void test_staging_maximum(void)
{
    static struct osc_accept acc;
    struct state st;
    memset(&st, 0, sizeof st);
    struct osc_policy p = policy_for("qualification", "1", "T", &st);
    uint8_t *b = 0; size_t n = 0;
    CHECK(admit_file("a01_valid_min.unit", &p, &acc, &b, &n) == OSC_OK);
    CHECK(n > 128);
    p.staging_max = n - 1;
    CHECK(osc_unit_admit(b, n, &p, &acc) == OSC_RESOURCE_UNAVAILABLE);
    p.staging_max = n;
    CHECK(osc_unit_admit(b, n, &p, &acc) == OSC_OK);
    free(b);
}

int main(int argc, char **argv)
{
    if (argc > 1) fixdir = argv[1];
    CHECK(load_key("test1.pub", key_test));
    CHECK(load_key("owner1.pub", key_owner));
    test_anchor_matches_fixture();
    int ne = run_file("expected.txt", 0);
    int nl = run_file("lookups.txt", 1);
    int ns = run_file("state.txt", 2);
    printf("osc_unit conformance: container=%d lookups=%d state=%d\n", ne, nl, ns);
    CHECK(ne == 57 && nl == 6 && ns == 3);
    test_staging_maximum();
    test_words();
    test_lookup_ignores_name_hash();
    test_flips_and_truncations();
    return ck_t_verdict("test_osc_unit");
}
