/* format.c -- SEED-0B artifact parse, capability and envelope records,
 * identity digests and signature verification (format.rs, capability.rs,
 * resource.rs, id.rs, canonical.rs, verify.rs). */
#include "ck_artifact.h"
#include "aienos_sig.h"
#include "sha256.h"

#define DOM(s) (s), (sizeof(s))

/* RFC 8032 section 7.1 test vectors: TEST ONLY, never an owner key. */
const uint8_t cka_test1_pk[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
const uint8_t cka_test2_pk[32] = {
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c};

static const char *const err_names[21] = {
    "Ok", "BadMagic", "UnsupportedVersion", "WrongTarget", "WrongAbi", "LengthOverflow",
    "Truncated", "WrongLength", "ReservedNonZero", "UnsupportedFlags", "SectionOverlap",
    "BadSection", "BadEntryPoint", "MalformedCapability", "ResourceLimit", "BadSignatureFormat",
    "DigestMismatch", "UntrustedSigner", "BadSignature", "RightsEscalation", "MalformedReceipt"};
static const char *const load_names[10] = {
    "NoFrames", "StagingTooLarge", "Mapping", "MappedDigestMismatch", "WxAudit",
    "CapabilityInstall", "SchedulerFull", "ExecutedDigestMismatch", "Reclaim", "FirmwareRead"};
static const char *const stage_names[10] = {"none",   "received", "staged", "verified", "authorized",
                                            "reserved", "mapped", "hashed", "sealed",   "caps"};

const char *cka_error_name(unsigned code)
{
    if (code < 21)
        return err_names[code];
    if (code >= 0x101 && code <= 0x10a)
        return load_names[code - 0x101];
    return "?";
}

const char *cka_stage_name(unsigned stage)
{
    return stage < 10 ? stage_names[stage] : "?";
}

static int all_zero(const uint8_t *b, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= b[i];
    return acc == 0;
}

static int eq32(const uint8_t *a, const uint8_t *b)
{
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++)
        acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}

void cka_digest_domain(const char *domain, size_t dlen, const uint8_t *b, size_t len,
                       uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)domain, dlen);
    if (len)
        sha256_update(&c, b, len);
    sha256_final(&c, out);
}

/* ---- capability records (capability.rs) ---- */
void cka_cap_encode(const struct cka_cap *c, uint8_t o[CKA_CAP_SIZE])
{
    for (unsigned i = 0; i < CKA_CAP_SIZE; i++)
        o[i] = 0;
    cka_wr16(o, c->kind);
    cka_wr32(o + 4, c->id);
    cka_wr32(o + 8, c->rights);
    cka_wr32(o + 12, c->bounds);
    cka_wr32(o + 16, c->max_ops);
    cka_wr64(o + 24, c->max_bytes);
    cka_wr64(o + 32, c->off);
    cka_wr64(o + 40, c->len);
}

int cka_cap_validate(const struct cka_cap *c)
{
    if ((c->kind != CKA_KIND_OBJECT && c->kind != CKA_KIND_CHANNEL) || c->id == 0 ||
        c->rights == 0 || (c->rights & ~CKA_VALID_RIGHTS) || c->max_ops == 0 || c->max_bytes == 0)
        return CKA_MALFORMED_CAP;
    if (c->kind == CKA_KIND_OBJECT && c->bounds == 1) {
        if (c->off + c->len < c->off)
            return CKA_LENGTH_OVERFLOW;
        if (c->len == 0 || c->max_bytes > c->len)
            return CKA_MALFORMED_CAP;
        return CKA_OK;
    }
    if (c->kind == CKA_KIND_CHANNEL && c->bounds == 2)
        return (c->off || c->len) ? CKA_MALFORMED_CAP : CKA_OK;
    return CKA_MALFORMED_CAP;
}

int cka_cap_decode(const uint8_t b[CKA_CAP_SIZE], struct cka_cap *c)
{
    if (cka_rd16(b + 2) || cka_rd32(b + 20))
        return CKA_RESERVED_NONZERO;
    c->kind = cka_rd16(b);
    c->id = cka_rd32(b + 4);
    c->rights = cka_rd32(b + 8);
    c->bounds = cka_rd32(b + 12);
    c->max_ops = cka_rd32(b + 16);
    c->max_bytes = cka_rd64(b + 24);
    c->off = cka_rd64(b + 32);
    c->len = cka_rd64(b + 40);
    return cka_cap_validate(c);
}

int cka_cap_is_attenuation_of(const struct cka_cap *g, const struct cka_cap *r)
{
    if (cka_cap_validate(g) || cka_cap_validate(r) || g->kind != r->kind || g->id != r->id ||
        g->bounds != r->bounds || (g->rights & ~r->rights) || g->max_ops > r->max_ops ||
        g->max_bytes > r->max_bytes)
        return 0;
    if (g->bounds == 1)
        return g->off >= r->off && g->off + g->len <= r->off + r->len;
    return 1;
}

/* ---- envelope (resource.rs) ---- */
void cka_env_encode(const struct cka_env *e, uint8_t o[CKA_ENV_SIZE])
{
    for (unsigned i = 0; i < CKA_ENV_SIZE; i++)
        o[i] = 0;
    cka_wr32(o, e->code_pages);
    cka_wr32(o + 4, e->data_pages);
    cka_wr32(o + 8, e->stack_pages);
    cka_wr16(o + 12, e->max_caps);
    cka_wr32(o + 16, e->ipc_msgs);
    cka_wr32(o + 20, e->ipc_bytes);
    cka_wr64(o + 24, e->cpu);
    cka_wr64(o + 32, e->elapsed);
    cka_wr32(o + 40, e->syscalls);
}

int cka_env_validate(const struct cka_env *e, unsigned ncaps)
{
    if (e->code_pages < 1 || e->code_pages > 64 || e->data_pages < 1 || e->data_pages > 64 ||
        e->stack_pages < 1 || e->stack_pages > 16 || ncaps > e->max_caps ||
        e->max_caps > CKA_MAX_CAPS || e->ipc_msgs > 1024 || e->ipc_bytes > 1048576u ||
        e->cpu < 1 || e->cpu > 1000000000ull || e->elapsed < 1 || e->elapsed > 1000000000ull ||
        e->syscalls < 1 || e->syscalls > 65536)
        return CKA_RESOURCE_LIMIT;
    return CKA_OK;
}

static int env_decode(const uint8_t *b, unsigned ncaps, struct cka_env *e)
{
    if (cka_rd16(b + 14) || cka_rd32(b + 44))
        return CKA_RESERVED_NONZERO;
    e->code_pages = cka_rd32(b);
    e->data_pages = cka_rd32(b + 4);
    e->stack_pages = cka_rd32(b + 8);
    e->max_caps = cka_rd16(b + 12);
    e->ipc_msgs = cka_rd32(b + 16);
    e->ipc_bytes = cka_rd32(b + 20);
    e->cpu = cka_rd64(b + 24);
    e->elapsed = cka_rd64(b + 32);
    e->syscalls = cka_rd32(b + 40);
    return cka_env_validate(e, ncaps);
}

/* ---- parse (format.rs) ---- */
static void section_read(const uint8_t *b, struct cka_section *s)
{
    s->kind = cka_rd16(b);
    s->perms = cka_rd16(b + 2);
    s->rel = cka_rd32(b + 8);
    s->flen = cka_rd32(b + 12);
    s->mlen = cka_rd32(b + 16);
    s->align = cka_rd32(b + 20);
}

int cka_parse(const uint8_t *b, size_t len, struct cka_parsed *p)
{
    static const uint8_t magic[8] = {'A', 'I', 'E', 'N', 'A', 'R', 'T', 0};
    if (len < CKA_HEADER_SIZE)
        return CKA_TRUNCATED;
    if (len > CKA_MAX_ARTIFACT)
        return CKA_RESOURCE_LIMIT;
    for (int i = 0; i < 8; i++)
        if (b[i] != magic[i])
            return CKA_BAD_MAGIC;
    if (cka_rd16(b + 8) != 0 || cka_rd16(b + 10) != CKA_HEADER_SIZE)
        return CKA_UNSUPPORTED_VERSION;
    p->target = cka_rd16(b + 12);
    p->abi = cka_rd16(b + 14);
    if (p->target != CKA_TARGET_AARCH64_LE)
        return CKA_WRONG_TARGET;
    if (p->abi != CKA_ABI_V1)
        return CKA_WRONG_ABI;
    if (cka_rd32(b + 16) != 0)
        return CKA_UNSUPPORTED_FLAGS;
    p->total = cka_rd32(b + 20);
    if (p->total != len)
        return CKA_WRONG_LENGTH;
    if (cka_rd32(b + 24) != CKA_HEADER_SIZE || cka_rd16(b + 28) != 2 ||
        cka_rd16(b + 30) != CKA_SECTION_SIZE || cka_rd16(b + 32) || cka_rd16(b + 34))
        return CKA_UNSUPPORTED_VERSION;
    p->entry = cka_rd32(b + 36);
    if (cka_rd32(b + 40) != CKA_CAPS_OFFSET || cka_rd16(b + 46) != CKA_CAP_SIZE ||
        cka_rd16(b + 52) != CKA_ENV_SIZE || cka_rd16(b + 54) != 0)
        return CKA_UNSUPPORTED_VERSION;
    if (!all_zero(b + 72, CKA_HEADER_SIZE - 72))
        return CKA_RESERVED_NONZERO;
    p->ncaps = cka_rd16(b + 44);
    if (p->ncaps > CKA_MAX_CAPS)
        return CKA_RESOURCE_LIMIT;
    p->res_off = cka_rd32(b + 48);
    if (p->res_off != CKA_CAPS_OFFSET + CKA_CAP_SIZE * p->ncaps)
        return CKA_SECTION_OVERLAP;
    uint32_t env_end = p->res_off + CKA_ENV_SIZE;
    p->payload_off = cka_rd32(b + 56);
    if (p->payload_off != ((env_end + 15u) & ~15u))
        return CKA_SECTION_OVERLAP;
    /* total == len >= 128 here; the gap lies inside the file only if it fits */
    if ((uint64_t)p->payload_off > len)
        return CKA_WRONG_LENGTH;
    if (!all_zero(b + env_end, p->payload_off - env_end))
        return CKA_RESERVED_NONZERO;
    p->payload_len = cka_rd32(b + 60);
    if (p->payload_len > CKA_MAX_PAYLOAD)
        return CKA_RESOURCE_LIMIT;
    if (cka_rd16(b + 68) != CKA_SIG_SIZE || cka_rd16(b + 70) != 1)
        return CKA_BAD_SIG_FORMAT;
    p->sig_off = cka_rd32(b + 64);
    if ((uint64_t)p->sig_off != (uint64_t)p->payload_off + p->payload_len)
        return CKA_SECTION_OVERLAP;
    if ((uint64_t)p->sig_off + CKA_SIG_SIZE != p->total)
        return CKA_WRONG_LENGTH;
    const uint8_t *s0 = b + 128, *s1 = b + 160;
    if (cka_rd32(s0 + 4) || !all_zero(s0 + 24, 8) || cka_rd32(s1 + 4) || !all_zero(s1 + 24, 8))
        return CKA_RESERVED_NONZERO;
    section_read(s0, &p->code);
    section_read(s1, &p->data);
    const struct cka_section *c = &p->code, *d = &p->data;
    if (c->kind != 1 || c->perms != 5 || c->rel != 0 || c->flen == 0 || c->mlen != c->flen ||
        c->align != 4096)
        return CKA_BAD_SECTION;
    if (d->kind != 2 || d->perms != 3 || d->rel != c->flen || d->flen == 0 || d->mlen < d->flen ||
        d->align != 4096)
        return CKA_BAD_SECTION;
    if ((uint64_t)c->flen + d->flen != p->payload_len)
        return CKA_SECTION_OVERLAP;
    for (unsigned i = 0; i < p->ncaps; i++) {
        int rc = cka_cap_decode(b + CKA_CAPS_OFFSET + CKA_CAP_SIZE * i, &p->caps[i]);
        if (rc)
            return rc;
    }
    for (unsigned i = 1; i < p->ncaps; i++) {
        const struct cka_cap *a = &p->caps[i - 1], *z = &p->caps[i];
        if (!(a->kind < z->kind || (a->kind == z->kind && a->id < z->id)))
            return CKA_MALFORMED_CAP;
    }
    int rc = env_decode(b + p->res_off, p->ncaps, &p->env);
    if (rc)
        return rc;
    if ((uint64_t)c->mlen > (uint64_t)p->env.code_pages * 4096u ||
        (uint64_t)d->mlen > (uint64_t)p->env.data_pages * 4096u)
        return CKA_RESOURCE_LIMIT;
    if ((p->entry & 3) || (uint64_t)p->entry + 4 > c->flen)
        return CKA_BAD_ENTRY;
    const uint8_t *sg = b + p->sig_off;
    p->sig_alg = cka_rd16(sg);
    if (p->sig_alg != 1)
        return CKA_BAD_SIG_FORMAT;
    if (sg[2] || sg[3])
        return CKA_RESERVED_NONZERO;
    if (p->sig_alg != cka_rd16(b + 70))
        return CKA_BAD_SIG_FORMAT;
    for (int i = 0; i < 32; i++)
        p->fp[i] = sg[4 + i];
    for (int i = 0; i < 64; i++)
        p->sig[i] = sg[36 + i];
    return CKA_OK;
}

int cka_identify(const uint8_t *b, size_t len, struct cka_parsed *p, struct cka_ident *id)
{
    if (len > CKA_MAX_ARTIFACT)
        return CKA_RESOURCE_LIMIT;
    int rc = cka_parse(b, len, p);
    if (rc)
        return rc;
    cka_digest_domain(DOM("AIENOS-ARTIFACT-V1"), b, p->sig_off, id->id);
    sha256_hash(b + p->payload_off, p->payload_len, id->payload);
    cka_digest_domain(DOM("AIENOS-ARTIFACT-CAP-REQUESTS-V1"), b + CKA_CAPS_OFFSET,
                      (size_t)CKA_CAP_SIZE * p->ncaps, id->requested);
    uint8_t env[CKA_ENV_SIZE];
    cka_env_encode(&p->env, env);
    cka_digest_domain(DOM("AIENOS-ARTIFACT-RESOURCES-V1"), env, sizeof env, id->resources);
    return CKA_OK;
}

void cka_signature_message(const uint8_t id[32], uint8_t *msg, size_t *len)
{
    static const char dom[] = "AIENOS-ARTIFACT-SIGNATURE-V1";
    size_t n = sizeof dom;
    for (size_t i = 0; i < n; i++)
        msg[i] = (uint8_t)dom[i];
    for (int i = 0; i < 32; i++)
        msg[n + i] = id[i];
    *len = n + 32;
}

int cka_verify(const uint8_t *b, size_t len, const uint8_t (*anchors)[32], unsigned nanchors,
               struct cka_parsed *p, struct cka_ident *id, uint8_t signer_fp[32])
{
    int rc = cka_identify(b, len, p, id);
    if (rc)
        return rc;
    const uint8_t *key = 0;
    uint8_t fp[32];
    for (unsigned i = 0; i < nanchors && !key; i++) {
        sha256_hash(anchors[i], 32, fp);
        if (eq32(fp, p->fp))
            key = anchors[i];
    }
    if (!key)
        return CKA_UNTRUSTED_SIGNER;
    sha256_hash(key, 32, fp);
    if (!eq32(fp, p->fp))
        return CKA_UNTRUSTED_SIGNER;
    uint8_t msg[96];
    size_t mlen;
    cka_signature_message(id->id, msg, &mlen);
    if (aienos_ed25519_verify(p->sig, msg, mlen, key) != 0)
        return CKA_BAD_SIGNATURE;
    for (int i = 0; i < 32; i++)
        signer_fp[i] = p->fp[i];
    return CKA_OK;
}

void cka_grants_digest(const struct cka_cap *g, unsigned n, uint8_t out[32])
{
    sha256_ctx c;
    static const char dom[] = "AIENOS-ADMISSION-CAP-GRANTS-V1";
    uint8_t rec[CKA_CAP_SIZE];
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)dom, sizeof dom);
    for (unsigned i = 0; i < n; i++) {
        cka_cap_encode(&g[i], rec);
        sha256_update(&c, rec, sizeof rec);
    }
    sha256_final(&c, out);
}
