/* ck_artifact_tool.c -- host tool for the C kernel P2_ARTIFACT gate.
 * C port of the commands of crates/aienos-artifact-tool that the gate uses
 * (pack, sign, id, verify, negative-corpus, receipt from-hex|check|sign-test|
 * verify), plus "bundle", which packs candidates into the fw_cfg file the C
 * kernel reads (opt/aienos/artifacts).
 *
 * TEST ONLY: sign / negative-corpus / receipt sign-test use the RFC 8032
 * TEST 1 (artifact) and TEST 2 (receipt) seeds. These are public test
 * vectors, never owner key material, and the tool has no other keys. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aienos_sig.h"
#include "ck_artifact.h"
#include "sha256.h"

static const uint8_t test1_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};
static const uint8_t test2_seed[32] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
};
/* RFC 8032 TEST 3 seed: a well-formed key no anchor set trusts (H15). */
static const uint8_t untrusted_seed[32] = {
    0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
};

static void die(const char *m)
{
    fprintf(stderr, "error: %s\n", m);
    exit(1);
}

struct buf {
    uint8_t *p;
    size_t n;
};

static struct buf readf(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    struct buf b = {0, 0};
    size_t cap = 0;
    for (;;) {
        if (b.n == cap) {
            cap = cap ? cap * 2 : 4096;
            if (cap > ((size_t)64 << 20))
                die("input too large");
            b.p = realloc(b.p, cap);
            if (!b.p)
                die("out of memory");
        }
        size_t r = fread(b.p + b.n, 1, cap - b.n, f);
        b.n += r;
        if (r == 0)
            break;
    }
    if (ferror(f))
        die("read error");
    fclose(f);
    return b;
}

static void writef(const char *path, const uint8_t *p, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f || (n && fwrite(p, 1, n, f) != n) || fclose(f) != 0) {
        fprintf(stderr, "error: cannot write %s\n", path);
        exit(1);
    }
}

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static void phex(const char *label, const uint8_t *b)
{
    char h[65];
    hex(b, 32, h);
    printf("%s%s\n", label, h);
}

/* ---- minimal manifest JSON (the Rust Manifest, deny_unknown_fields) ---- */
struct manifest {
    uint32_t entry;
    unsigned ncaps;
    struct cka_cap caps[CKA_MAX_CAPS];
    struct cka_env env;
};

struct js {
    const char *s;
    size_t i, n;
};

static void ws(struct js *j)
{
    while (j->i < j->n && (j->s[j->i] == ' ' || j->s[j->i] == '\n' || j->s[j->i] == '\r' ||
                           j->s[j->i] == '\t'))
        j->i++;
}

static void expect(struct js *j, char c)
{
    ws(j);
    if (j->i >= j->n || j->s[j->i] != c)
        die("manifest: malformed JSON");
    j->i++;
}

static int peek(struct js *j, char c)
{
    ws(j);
    return j->i < j->n && j->s[j->i] == c;
}

static void key(struct js *j, char *out, size_t cap)
{
    expect(j, '"');
    size_t k = 0;
    while (j->i < j->n && j->s[j->i] != '"') {
        if (j->s[j->i] == '\\' || k + 1 >= cap)
            die("manifest: unsupported key");
        out[k++] = j->s[j->i++];
    }
    out[k] = 0;
    expect(j, '"');
    expect(j, ':');
}

static uint64_t num(struct js *j, uint64_t max)
{
    ws(j);
    uint64_t v = 0;
    size_t start = j->i;
    while (j->i < j->n && j->s[j->i] >= '0' && j->s[j->i] <= '9') {
        unsigned d = (unsigned)(j->s[j->i++] - '0');
        if (v > (UINT64_MAX - d) / 10)
            die("manifest: number overflow");
        v = v * 10 + d;
    }
    if (j->i == start || (j->i - start > 1 && j->s[start] == '0'))
        die("manifest: expected an unsigned integer");
    if (v > max)
        die("manifest: number out of range for its field");
    return v;
}

#define U16 0xffffu
#define U32 0xffffffffu

static void parse_cap(struct js *j, struct cka_cap *c)
{
    unsigned seen = 0;
    expect(j, '{');
    while (!peek(j, '}')) {
        char k[40];
        key(j, k, sizeof k);
        unsigned bit;
        if (!strcmp(k, "resource_kind")) c->kind = (uint16_t)num(j, U16), bit = 1;
        else if (!strcmp(k, "resource_id")) c->id = (uint32_t)num(j, U32), bit = 2;
        else if (!strcmp(k, "rights")) c->rights = (uint32_t)num(j, U32), bit = 4;
        else if (!strcmp(k, "bounds_kind")) c->bounds = (uint32_t)num(j, U32), bit = 8;
        else if (!strcmp(k, "max_operations")) c->max_ops = (uint32_t)num(j, U32), bit = 16;
        else if (!strcmp(k, "max_bytes")) c->max_bytes = num(j, UINT64_MAX), bit = 32;
        else if (!strcmp(k, "byte_offset")) c->off = num(j, UINT64_MAX), bit = 64;
        else if (!strcmp(k, "byte_length")) c->len = num(j, UINT64_MAX), bit = 128;
        else die("manifest: unknown capability field");
        if (seen & bit)
            die("manifest: duplicate field");
        seen |= bit;
        if (!peek(j, '}'))
            expect(j, ',');
    }
    expect(j, '}');
    if (seen != 255)
        die("manifest: missing capability field");
}

static void parse_env(struct js *j, struct cka_env *e)
{
    unsigned seen = 0;
    expect(j, '{');
    while (!peek(j, '}')) {
        char k[40];
        key(j, k, sizeof k);
        unsigned bit;
        if (!strcmp(k, "code_pages")) e->code_pages = (uint32_t)num(j, U32), bit = 1;
        else if (!strcmp(k, "data_pages")) e->data_pages = (uint32_t)num(j, U32), bit = 2;
        else if (!strcmp(k, "stack_pages")) e->stack_pages = (uint32_t)num(j, U32), bit = 4;
        else if (!strcmp(k, "max_capabilities")) e->max_caps = (uint16_t)num(j, U16), bit = 8;
        else if (!strcmp(k, "ipc_messages")) e->ipc_msgs = (uint32_t)num(j, U32), bit = 16;
        else if (!strcmp(k, "ipc_bytes")) e->ipc_bytes = (uint32_t)num(j, U32), bit = 32;
        else if (!strcmp(k, "cpu_ticks")) e->cpu = num(j, UINT64_MAX), bit = 64;
        else if (!strcmp(k, "elapsed_ticks")) e->elapsed = num(j, UINT64_MAX), bit = 128;
        else if (!strcmp(k, "syscall_count")) e->syscalls = (uint32_t)num(j, U32), bit = 256;
        else die("manifest: unknown resources field");
        if (seen & bit)
            die("manifest: duplicate field");
        seen |= bit;
        if (!peek(j, '}'))
            expect(j, ',');
    }
    expect(j, '}');
    if (seen != 511)
        die("manifest: missing resources field");
}

static void parse_manifest(const struct buf *b, struct manifest *m)
{
    struct js j = {(const char *)b->p, 0, b->n};
    unsigned seen = 0;
    memset(m, 0, sizeof *m);
    expect(&j, '{');
    while (!peek(&j, '}')) {
        char k[40];
        key(&j, k, sizeof k);
        unsigned bit;
        if (!strcmp(k, "entry_offset")) {
            m->entry = (uint32_t)num(&j, U32);
            bit = 1;
        } else if (!strcmp(k, "capabilities")) {
            expect(&j, '[');
            while (!peek(&j, ']')) {
                if (m->ncaps >= CKA_MAX_CAPS)
                    die("code, data, and capability count are outside v0 bounds");
                parse_cap(&j, &m->caps[m->ncaps++]);
                if (!peek(&j, ']'))
                    expect(&j, ',');
            }
            expect(&j, ']');
            bit = 2;
        } else if (!strcmp(k, "resources")) {
            parse_env(&j, &m->env);
            bit = 4;
        } else {
            die("manifest: unknown field");
        }
        if (seen & bit)
            die("manifest: duplicate field");
        seen |= bit;
        if (!peek(&j, '}'))
            expect(&j, ',');
    }
    expect(&j, '}');
    ws(&j);
    if (j.i != j.n || seen != 7)
        die("manifest: missing field or trailing data");
}

/* ---- pack (main.rs pack_bytes, same byte layout) ---- */
static struct buf pack(const struct manifest *m, const uint8_t *code, size_t clen,
                       const uint8_t *data, size_t dlen)
{
    if (clen == 0 || dlen == 0 || m->ncaps > 16)
        die("code, data, and capability count are outside v0 bounds");
    size_t res = CKA_CAPS_OFFSET + (size_t)m->ncaps * CKA_CAP_SIZE;
    size_t pay = (res + CKA_ENV_SIZE + 15) & ~(size_t)15;
    size_t plen = clen + dlen;
    size_t sig = pay + plen;
    size_t total = sig + CKA_SIG_SIZE;
    if (total > CKA_MAX_ARTIFACT || plen > CKA_MAX_PAYLOAD)
        die("artifact exceeds v0 maximum size");
    if ((uint64_t)m->env.data_pages * 4096u > 0xffffffffu)
        die("data page overflow");
    struct buf b = {calloc(1, total), total};
    if (!b.p)
        die("out of memory");
    uint8_t *p = b.p;
    memcpy(p, "AIENART\0", 8);
    cka_wr16(p + 8, 0);
    cka_wr16(p + 10, CKA_HEADER_SIZE);
    cka_wr16(p + 12, CKA_TARGET_AARCH64_LE);
    cka_wr16(p + 14, CKA_ABI_V1);
    cka_wr32(p + 20, (uint32_t)total);
    cka_wr32(p + 24, 128);
    cka_wr16(p + 28, 2);
    cka_wr16(p + 30, CKA_SECTION_SIZE);
    cka_wr32(p + 36, m->entry);
    cka_wr32(p + 40, CKA_CAPS_OFFSET);
    cka_wr16(p + 44, (uint16_t)m->ncaps);
    cka_wr16(p + 46, CKA_CAP_SIZE);
    cka_wr32(p + 48, (uint32_t)res);
    cka_wr16(p + 52, CKA_ENV_SIZE);
    cka_wr32(p + 56, (uint32_t)pay);
    cka_wr32(p + 60, (uint32_t)plen);
    cka_wr32(p + 64, (uint32_t)sig);
    cka_wr16(p + 68, CKA_SIG_SIZE);
    cka_wr16(p + 70, 1);
    /* sections: kind, perms, rel, flen, mlen, align 4096 */
    uint8_t *s = p + 128;
    cka_wr16(s, 1), cka_wr16(s + 2, 5), cka_wr32(s + 8, 0), cka_wr32(s + 12, (uint32_t)clen);
    cka_wr32(s + 16, (uint32_t)clen), cka_wr32(s + 20, 4096);
    s += 32;
    cka_wr16(s, 2), cka_wr16(s + 2, 3), cka_wr32(s + 8, (uint32_t)clen);
    cka_wr32(s + 12, (uint32_t)dlen), cka_wr32(s + 16, m->env.data_pages * 4096u);
    cka_wr32(s + 20, 4096);
    for (unsigned i = 0; i < m->ncaps; i++)
        cka_cap_encode(&m->caps[i], p + CKA_CAPS_OFFSET + i * CKA_CAP_SIZE);
    cka_env_encode(&m->env, p + res);
    memcpy(p + pay, code, clen);
    memcpy(p + pay + clen, data, dlen);
    cka_wr16(p + sig, 1);
    struct cka_parsed pa;
    int e = cka_parse(p, total, &pa);
    for (unsigned i = 0; !e && i < pa.ncaps; i++)
        e = cka_cap_validate(&pa.caps[i]);
    if (!e)
        e = cka_env_validate(&pa.env, pa.ncaps);
    if (e) {
        fprintf(stderr, "error: packed artifact refused: %s\n", cka_error_name((unsigned)e));
        exit(1);
    }
    return b;
}

static void sign_with(struct buf *b, const uint8_t seed[32])
{
    struct cka_parsed p;
    struct cka_ident id;
    int e = cka_identify(b->p, b->n, &p, &id);
    if (e) {
        fprintf(stderr, "error: does not parse: %s\n", cka_error_name((unsigned)e));
        exit(1);
    }
    uint8_t pk[32], msg[64];
    size_t mlen;
    if (aienos_ed25519_public_key(pk, seed) != AIENOS_SIG_OK)
        die("public key");
    uint8_t *blk = b->p + p.sig_off;
    sha256_hash(pk, 32, blk + 4);
    cka_signature_message(id.id, msg, &mlen);
    if (aienos_ed25519_sign(blk + 36, msg, mlen, seed) != AIENOS_SIG_OK)
        die("sign");
}

static int verify_test(const struct buf *b, struct cka_parsed *p, struct cka_ident *id,
                       uint8_t fp[32])
{
    const uint8_t (*anchors)[32] = &cka_test1_pk;
    return cka_verify(b->p, b->n, anchors, 1, p, id, fp);
}

/* ---- negative corpus (corpus.rs, same cases, names and expectations) ---- */
#define MOV_X0_0 0xd2800000u
#define MOV_X8_2 0xd2800048u
#define MOV_X8_6 0xd28000c8u
#define MOV_X8_99 0xd2800c68u
#define SVC_0 0xd4000001u
#define B_SELF 0x14000000u
#define BR_X2 0xd61f0040u
#define SUB_X9_SP_16 0xd10043e9u
#define BR_X9 0xd61f0120u

static size_t words(uint8_t *out, const uint32_t *w, size_t n)
{
    for (size_t i = 0; i < n; i++)
        cka_wr32(out + 4 * i, w[i]);
    return 4 * n;
}

static struct cka_cap seed_read(uint32_t rights)
{
    struct cka_cap c = {3, 1, rights, 1, 4, 32, 0, 32};
    return c;
}

static struct cka_env res(uint32_t code, uint32_t data, uint32_t stack, uint16_t caps,
                          uint32_t sys)
{
    struct cka_env e = {code, data, stack, caps, 0, 0, 100000000, 100000000, sys};
    return e;
}

static struct buf signed_art(unsigned ncaps, struct cka_cap cap, struct cka_env env,
                             const uint32_t *w, size_t nw, const char *data8)
{
    struct manifest m;
    memset(&m, 0, sizeof m);
    m.ncaps = ncaps;
    m.caps[0] = cap;
    m.env = env;
    uint8_t code[64];
    size_t cl = words(code, w, nw);
    struct buf b = pack(&m, code, cl, (const uint8_t *)data8, 8);
    sign_with(&b, test1_seed);
    return b;
}

static const uint32_t exit0_w[] = {MOV_X0_0, MOV_X8_2, SVC_0, B_SELF};

static struct buf clone(const struct buf *b, size_t extra)
{
    struct buf c = {calloc(1, b->n + extra + 1), b->n};
    if (!c.p)
        die("out of memory");
    memcpy(c.p, b->p, b->n);
    return c;
}

static void corpus(const char *dir)
{
    struct buf base = signed_art(1, seed_read(1), res(1, 1, 1, 1, 8), exit0_w, 4, "BASELINE");
    size_t payload = cka_rd32(base.p + 56);
    size_t resource = CKA_CAPS_OFFSET + CKA_CAP_SIZE;
    size_t sig = base.n - 100;
    char path[4096], exp[8192];
    size_t el = 0;
    exp[0] = 0;
#define EMIT(NAME, BUF, EXPECT, WHAT)                                                     \
    do {                                                                                   \
        snprintf(path, sizeof path, "%s/%s", dir, NAME);                                   \
        writef(path, (BUF).p, (BUF).n);                                                    \
        el += (size_t)snprintf(exp + el, sizeof exp - el, "%s %s # %s\n", NAME, EXPECT, WHAT); \
        free((BUF).p);                                                                     \
    } while (0)
#define MUT(NAME, STMT, EXPECT, WHAT)                                                      \
    do {                                                                                   \
        struct buf b = clone(&base, 1);                                                    \
        STMT;                                                                              \
        EMIT(NAME, b, EXPECT, WHAT);                                                       \
    } while (0)
#define V(R, C) "rejected verified " R " " C
    MUT("H01-BAD-MAGIC.AIEN", b.p[0] = 'X', V("BadMagic", "0x1"), "magic is not AIENART\\0");
    MUT("H02-VERSION.AIEN", cka_wr16(b.p + 8, 1), V("UnsupportedVersion", "0x2"),
        "format_version 1 (unsupported)");
    MUT("H03-TARGET.AIEN", cka_wr16(b.p + 12, 2), V("WrongTarget", "0x3"),
        "target_arch 2 (not AArch64 LE)");
    MUT("H04-ABI.AIEN", cka_wr16(b.p + 14, 2), V("WrongAbi", "0x4"), "abi_version 2 (not ABI v1)");
    MUT("H05-TRUNCATED.AIEN", b.n -= 10, V("WrongLength", "0x7"), "last 10 bytes cut off");
    MUT("H06-TRAILING.AIEN", b.p[b.n++] = 0, V("WrongLength", "0x7"),
        "one byte appended after the signature block");
    MUT("H07-TOTAL-LENGTH.AIEN", cka_wr32(b.p + 20, cka_rd32(b.p + 20) + 1),
        V("WrongLength", "0x7"), "total_length field one larger than the file");
    MUT("H08-OFFSET-OVERFLOW.AIEN", cka_wr32(b.p + 60, 0xffffffffu), V("ResourceLimit", "0xe"),
        "payload_length 0xffffffff (offset + length overflows)");
    MUT("H09-SECTION-OVERLAP.AIEN", cka_wr32(b.p + 160 + 8, 4), V("BadSection", "0xb"),
        "data section starts inside the code section");
    MUT("H10-ENTRY-OUTSIDE.AIEN", cka_wr32(b.p + 36, 0x1000), V("BadEntryPoint", "0xc"),
        "entry_offset beyond the code bytes");
    MUT("H11-PAYLOAD-MUTATED.AIEN", b.p[payload] ^= 1, V("BadSignature", "0x12"),
        "one code byte changed after signing");
    MUT("H12-CAPS-MUTATED.AIEN", cka_wr32(b.p + CKA_CAPS_OFFSET + 8, 3), V("BadSignature", "0x12"),
        "requested rights READ -> READ|WRITE after signing");
    MUT("H13-ENVELOPE-MUTATED.AIEN", cka_wr32(b.p + resource + 8, 2), V("BadSignature", "0x12"),
        "stack_pages 1 -> 2 after signing");
    MUT("H14-SIGNATURE-MUTATED.AIEN", b.p[sig + 40] ^= 1, V("BadSignature", "0x12"),
        "one signature byte changed");
    MUT("H15-UNKNOWN-SIGNER.AIEN", sign_with(&b, untrusted_seed), V("UntrustedSigner", "0x11"),
        "valid Ed25519 signature by a key no anchor trusts");
    MUT("H16-SIG-FORMAT.AIEN", cka_wr16(b.p + sig, 2), V("BadSignatureFormat", "0xf"),
        "signature block algorithm 2");
    MUT("H17-RESERVED-HEADER.AIEN", b.p[100] = 1, V("ReservedNonZero", "0x8"),
        "reserved header byte 100 nonzero");
    MUT("H18-RIGHTS-UNKNOWN.AIEN", cka_wr32(b.p + CKA_CAPS_OFFSET + 8, 1u | 1u << 6),
        V("MalformedCapability", "0xd"), "requested rights bit 6 (undefined)");
    MUT("H19-CAP-COUNT.AIEN", cka_wr16(b.p + 44, 17), V("ResourceLimit", "0xe"),
        "capability_count 17 (> 16)");
    MUT("H20-ENVELOPE-LIMIT.AIEN", cka_wr32(b.p + resource, 65), V("ResourceLimit", "0xe"),
        "code_pages 65 (> 64); refused while parsing, before signature checks");
    {
        struct buf b = signed_art(0, seed_read(0), res(64, 64, 16, 0, 4), exit0_w, 4, "LARGEST!");
        EMIT("H21-LARGEST-ENVELOPE.AIEN", b, "admitted exited:0x0 0",
             "largest valid envelope: 64 code, 64 data, 16 stack pages");
    }
    MUT("H22-WX-SECTION.AIEN", cka_wr16(b.p + 128 + 2, 7), V("BadSection", "0xb"),
        "code section permissions R|W|X");
    {
        static const uint32_t w[] = {BR_X2};
        struct buf b = signed_art(0, seed_read(0), res(1, 1, 1, 0, 4), w, 1, "DATAPAGE");
        EMIT("H23-EXEC-DATA.AIEN", b, "admitted fault:exec-nx 0",
             "branches into its own data page (mapped RW+NX)");
    }
    {
        static const uint32_t w[] = {SUB_X9_SP_16, BR_X9};
        struct buf b = signed_art(0, seed_read(0), res(1, 1, 1, 0, 4), w, 2, "STACKPAG");
        EMIT("H24-EXEC-STACK.AIEN", b, "admitted fault:exec-nx 0",
             "branches onto its own stack (mapped RW+NX)");
    }
    {
        static const uint32_t w[] = {MOV_X8_99, SVC_0, B_SELF};
        struct buf b = signed_art(0, seed_read(0), res(1, 1, 1, 0, 4), w, 3, "BADSYSCL");
        EMIT("H25-BAD-SYSCALL.AIEN", b, "admitted bad-syscall:99 0", "invokes undefined syscall 99");
    }
    {
        static const uint32_t w[] = {MOV_X0_0, MOV_X8_6, SVC_0, SVC_0, SVC_0, MOV_X8_2, SVC_0, B_SELF};
        struct buf b = signed_art(0, seed_read(0), res(1, 1, 1, 0, 2), w, 8, "OVERRUN!");
        EMIT("H26-SYSCALL-BUDGET.AIEN", b, "admitted resource-overrun 0",
             "third syscall exceeds syscall_count 2");
    }
    {
        struct cka_env r = res(1, 1, 1, 1, 8);
        r.ipc_msgs = 1;
        r.ipc_bytes = 64;
        struct buf b = signed_art(1, seed_read(1), r, exit0_w, 4, "IPCWANTS");
        EMIT("H27-POLICY-IPC.AIEN", b, "rejected authorized ResourceLimit 0xe",
             "requests 1 IPC message; local policy allows none");
    }
    {
        struct buf b = signed_art(1, seed_read(2), res(1, 1, 1, 1, 8), exit0_w, 4, "WRITEREQ");
        EMIT("H28-WRITE-ONLY-REQUEST.AIEN", b, "admitted exited:0x0 0",
             "requests only WRITE on the SEED object; policy grants READ at most");
    }
    {
        struct buf b = signed_art(1, seed_read(3), res(1, 1, 1, 1, 8), exit0_w, 4, "RWREQUST");
        EMIT("H29-READ-WRITE-REQUEST.AIEN", b, "admitted exited:0x0 1",
             "requests READ|WRITE; granted READ only");
    }
    snprintf(path, sizeof path, "%s/expected.txt", dir);
    writef(path, (const uint8_t *)exp, el);
    free(base.p);
    printf("NEGATIVE_CORPUS: TEST ONLY SEED-0B qualification inputs written\n");
}

/* ---- fw_cfg bundle: "AIENBND\0", u32 count, {u16 nlen, name, u32 len, bytes} ---- */
static void bundle(int argc, char **argv)
{
    const char *out = argv[0];
    size_t cap = 12, n = 12;
    uint8_t *b = malloc(cap);
    if (!b)
        die("out of memory");
    memcpy(b, "AIENBND\0", 8);
    unsigned count = 0;
    for (int i = 1; i < argc; i++) {
        const char *name = strrchr(argv[i], '/');
        name = name ? name + 1 : argv[i];
        size_t nl = strlen(name);
        if (nl == 0 || nl > 32)
            die("bundle: candidate names are 1..32 bytes");
        struct buf f = readf(argv[i]);
        size_t need = n + 2 + nl + 4 + f.n;
        if (need > cap) {
            cap = need * 2;
            b = realloc(b, cap);
            if (!b)
                die("out of memory");
        }
        cka_wr16(b + n, (uint16_t)nl);
        memcpy(b + n + 2, name, nl);
        cka_wr32(b + n + 2 + nl, (uint32_t)f.n);
        memcpy(b + n + 6 + nl, f.p, f.n);
        n = need;
        count++;
        free(f.p);
    }
    cka_wr32(b + 8, count);
    writef(out, b, n);
    free(b);
    printf("BUNDLE: %u candidates\n", count);
}

/* ---- receipts (receipt_cmd.rs) ---- */
static void read_receipt(const char *path, uint8_t r[CKA_RECEIPT_SIZE])
{
    struct buf b = readf(path);
    if (b.n != CKA_RECEIPT_SIZE) {
        fprintf(stderr, "error: receipt must be exactly 512 bytes, got %zu\n", b.n);
        exit(1);
    }
    memcpy(r, b.p, CKA_RECEIPT_SIZE);
    free(b.p);
}

static void decoded(const uint8_t *b, struct cka_receipt *r)
{
    int e = cka_receipt_decode(b, r);
    if (e) {
        fprintf(stderr, "error: receipt rejected: %s\n", cka_error_name((unsigned)e));
        exit(1);
    }
}

static const char *decision(const struct cka_receipt *r)
{
    return r->decision == CKR_ADMITTED ? "Admitted" : "Rejected";
}

static int receipt(int argc, char **argv)
{
    static const uint8_t zero[32];
    uint8_t rec[CKA_RECEIPT_SIZE];
    struct cka_receipt r;
    char h[65];
    if (argc == 3 && !strcmp(argv[0], "from-hex")) {
        const char *t = argv[1];
        if (strlen(t) != 2 * CKA_RECEIPT_SIZE)
            die("expected 1024 lowercase hex characters");
        for (unsigned i = 0; i < CKA_RECEIPT_SIZE; i++) {
            unsigned v = 0;
            for (int k = 0; k < 2; k++) {
                char c = t[2 * i + k];
                if (c >= '0' && c <= '9') v = v * 16 + (unsigned)(c - '0');
                else if (c >= 'a' && c <= 'f') v = v * 16 + (unsigned)(c - 'a' + 10);
                else die("expected 1024 lowercase hex characters");
            }
            rec[i] = (uint8_t)v;
        }
        writef(argv[2], rec, CKA_RECEIPT_SIZE);
        printf("FROM_HEX: PASS\n");
        return 0;
    }
    if (argc == 3 && !strcmp(argv[0], "check")) {
        read_receipt(argv[1], rec);
        if (cka_receipt_is_signed(rec))
            die("kernel-emitted receipts must be unsigned");
        decoded(rec, &r);
        int admitted = r.decision == CKR_ADMITTED;
        struct buf a = readf(argv[2]);
        struct cka_parsed p;
        struct cka_ident id;
        const uint8_t *fields[5] = {r.id, r.payload, r.signer, r.requested, r.resources};
        static const char *names[5] = {"artifact_id", "payload_digest",
                                       "artifact_signer_fingerprint",
                                       "requested_capability_digest", "resource_envelope_digest"};
        if (cka_identify(a.p, a.n, &p, &id) != 0) {
            if (admitted)
                die("admitted receipt for an artifact the host cannot parse");
            for (int i = 0; i < 5; i++)
                if (memcmp(fields[i], zero, 32)) {
                    fprintf(stderr, "error: %s must be zero for an unparseable artifact\n",
                            names[i]);
                    return 1;
                }
        } else {
            const uint8_t *want[5] = {id.id, id.payload, p.fp, id.requested, id.resources};
            for (int i = 0; i < 5; i++)
                if (memcmp(fields[i], want[i], 32) &&
                    !(!admitted && !memcmp(fields[i], zero, 32))) {
                    fprintf(stderr, "error: %s does not bind the supplied artifact\n", names[i]);
                    return 1;
                }
            if (admitted && !memcmp(r.granted, zero, 32))
                die("admitted receipt without a granted-capability digest");
        }
        free(a.p);
        uint8_t d[32];
        cka_receipt_digest(rec, d);
        hex(d, 32, h);
        printf("RECEIPT_CHECK: PASS digest=%s decision=%s tier=SEED-0B-QEMU stage=%u reason=0x%x "
               "status=%s exit=%d syscalls=%u reads_ok=%u denials=%u flags=0x%02x\n",
               h, decision(&r), r.stage, r.reason, cka_status_name(r.status), r.exit, r.syscalls,
               r.reads, r.denials, r.result_flags);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[0], "sign-test")) {
        read_receipt(argv[1], rec);
        decoded(rec, &r);
        if (cka_receipt_sign(rec, test2_seed) != 0)
            die("cannot sign receipt");
        writef(argv[2], rec, CKA_RECEIPT_SIZE);
        uint8_t fp[32];
        sha256_hash(cka_test2_pk, 32, fp);
        printf("RECEIPT_SIGN: TEST ONLY SEED-0B QUALIFICATION RECEIPT KEY\n");
        phex("RECEIPT_SIGNER_FINGERPRINT: ", fp);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[0], "verify")) {
        read_receipt(argv[1], rec);
        const uint8_t (*anchors)[32] = &cka_test2_pk;
        int e = cka_receipt_verify(rec, anchors, 1);
        if (e) {
            fprintf(stderr, "error: receipt verification failed: %s\n", cka_error_name((unsigned)e));
            return 1;
        }
        decoded(rec, &r);
        uint8_t d[32];
        cka_receipt_digest(rec, d);
        hex(d, 32, h);
        printf("RECEIPT_VERIFY: PASS digest=%s decision=%s tier=SEED-0B-QEMU "
               "trust=SEED-0B-TEST-ONLY\n", h, decision(&r));
        return 0;
    }
    die("usage: receipt from-hex HEX OUT | check REC ARTIFACT | sign-test IN OUT | verify REC");
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 6 && !strcmp(argv[1], "pack")) {
        struct buf mj = readf(argv[2]), c = readf(argv[3]), d = readf(argv[4]);
        struct manifest m;
        parse_manifest(&mj, &m);
        struct buf o = pack(&m, c.p, c.n, d.p, d.n);
        writef(argv[5], o.p, o.n);
        printf("PACK: PASS\n");
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "sign")) {
        struct buf b = readf(argv[2]);
        struct cka_parsed p;
        if (cka_parse(b.p, b.n, &p) != 0)
            die("does not parse");
        sign_with(&b, test1_seed);
        if (cka_parse(b.p, b.n, &p) != 0)
            die("signed artifact does not parse");
        writef(argv[3], b.p, b.n);
        uint8_t fp[32];
        sha256_hash(cka_test1_pk, 32, fp);
        printf("SIGN: TEST ONLY SEED-0B QUALIFICATION IDENTITY\n");
        phex("SIGNER_FINGERPRINT: ", fp);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "id")) {
        struct buf b = readf(argv[2]);
        struct cka_parsed p;
        struct cka_ident id;
        int e = cka_identify(b.p, b.n, &p, &id);
        if (e) {
            fprintf(stderr, "error: %s\n", cka_error_name((unsigned)e));
            return 1;
        }
        phex("", id.id);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "verify")) {
        struct buf b = readf(argv[2]);
        struct cka_parsed p;
        struct cka_ident id;
        uint8_t fp[32];
        int e = verify_test(&b, &p, &id, fp);
        if (e) {
            fprintf(stderr, "error: %s\n", cka_error_name((unsigned)e));
            return 1;
        }
        printf("VERIFY: PASS\n");
        phex("ARTIFACT_ID: ", id.id);
        phex("PAYLOAD_SHA256: ", id.payload);
        phex("SIGNER_FINGERPRINT: ", fp);
        printf("TRUST_TIER: SEED-0B-QUALIFICATION-TEST-ONLY\n");
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "negative-corpus")) {
        corpus(argv[2]);
        return 0;
    }
    if (argc >= 3 && !strcmp(argv[1], "bundle")) {
        bundle(argc - 2, argv + 2);
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "receipt"))
        return receipt(argc - 2, argv + 2);
    fprintf(stderr, "usage: ck_artifact_tool pack MANIFEST CODE DATA OUT | sign IN OUT | id F | "
                    "verify F | negative-corpus DIR | bundle OUT FILE... | receipt ...\n");
    return 2;
}
