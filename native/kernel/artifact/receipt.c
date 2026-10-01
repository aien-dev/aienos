/* receipt.c -- SEED-0B admission receipts (port of aienos-artifact
 * receipt.rs): 512-byte canonical record, digest, nonce, validation and the
 * TEST-ONLY qualification signature. */
#include "ck_artifact.h"
#include "aienos_sig.h"
#include "sha256.h"

static const char rmagic[8] = "AIENRCP";
static const char sig_dom[] = "AIENOS-ADMISSION-RECEIPT-SIGNATURE-V1";

const char *cka_status_name(uint32_t s)
{
    static const char *const n[6] = {"NotRun", "Exited", "Timeout",
                                     "Fault",  "BadSyscall", "ResourceOverrun"};
    return s < 6 ? n[s] : "?";
}

void cka_receipt_nonce(const uint8_t verifier[32], uint64_t seq, uint8_t out[16])
{
    static const char dom[] = "AIENOS-ADMISSION-RECEIPT-NONCE-V1";
    uint8_t s[8], d[32];
    sha256_ctx c;
    cka_wr64(s, seq);
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)dom, sizeof dom);
    sha256_update(&c, verifier, 32);
    sha256_update(&c, s, 8);
    sha256_final(&c, d);
    for (int i = 0; i < 16; i++)
        out[i] = d[i];
}

static void put(uint8_t *o, const uint8_t *s, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        o[i] = s[i];
}

void cka_receipt_encode(const struct cka_receipt *r, uint8_t o[CKA_RECEIPT_SIZE])
{
    for (unsigned i = 0; i < CKA_RECEIPT_SIZE; i++)
        o[i] = 0;
    put(o, (const uint8_t *)rmagic, 8);
    cka_wr16(o + 10, 96);
    cka_wr32(o + 12, CKA_RECEIPT_SIZE);
    cka_wr32(o + 16, r->flags);
    cka_wr16(o + 20, r->decision);
    cka_wr16(o + 22, r->tier);
    cka_wr64(o + 24, r->seq);
    put(o + 32, r->nonce, 16);
    cka_wr64(o + 48, r->time);
    cka_wr32(o + 64, r->status);
    cka_wr32(o + 68, (uint32_t)r->exit);
    cka_wr32(o + 72, r->result_flags);
    cka_wr16(o + 76, r->stage);
    cka_wr16(o + 78, r->reason);
    cka_wr32(o + 80, r->syscalls);
    cka_wr32(o + 84, r->reads);
    cka_wr32(o + 88, r->denials);
    cka_wr32(o + 92, r->frames);
    put(o + 96, r->id, 32);
    put(o + 128, r->payload, 32);
    put(o + 160, r->signer, 32);
    put(o + 192, r->policy, 32);
    put(o + 224, r->requested, 32);
    put(o + 256, r->granted, 32);
    put(o + 288, r->resources, 32);
    put(o + 320, r->verifier, 32);
    put(o + 352, r->machine, 32);
    cka_wr64(o + 384, r->generation);
    cka_wr64(o + 392, r->context);
    if (r->sig_alg) {
        cka_wr16(o + 400, r->sig_alg);
        put(o + 404, r->fp, 32);
        put(o + 436, r->sig, 64);
    }
}

static int nz(const uint8_t *b, unsigned from, unsigned to)
{
    uint8_t acc = 0;
    for (unsigned i = from; i < to; i++)
        acc |= b[i];
    return acc != 0;
}

int cka_receipt_decode(const uint8_t b[CKA_RECEIPT_SIZE], struct cka_receipt *r)
{
    for (int i = 0; i < 8; i++)
        if (b[i] != (uint8_t)rmagic[i])
            return CKA_BAD_MAGIC;
    if (cka_rd16(b + 8) != 0 || cka_rd16(b + 10) != 96 || cka_rd32(b + 12) != CKA_RECEIPT_SIZE)
        return CKA_UNSUPPORTED_VERSION;
    r->flags = cka_rd32(b + 16);
    r->result_flags = cka_rd32(b + 72);
    if ((r->flags & ~7u) || (r->result_flags & ~0xffu))
        return CKA_UNSUPPORTED_FLAGS;
    if (nz(b, 56, 64) || nz(b, 500, 512))
        return CKA_RESERVED_NONZERO;
    r->sig_alg = 0;
    if (nz(b, 400, 500)) {
        if (cka_rd16(b + 400) != 1)
            return CKA_BAD_SIG_FORMAT;
        if (b[402] || b[403])
            return CKA_RESERVED_NONZERO;
        r->sig_alg = 1;
    }
    r->decision = cka_rd16(b + 20);
    r->tier = cka_rd16(b + 22);
    r->status = cka_rd32(b + 64);
    if ((r->decision != CKR_ADMITTED && r->decision != CKR_REJECTED) ||
        r->tier != CKR_TIER_SEED0B_QEMU || r->status > CKR_RESOURCE_OVERRUN)
        return CKA_MALFORMED_RECEIPT;
    r->seq = cka_rd64(b + 24);
    put(r->nonce, b + 32, 16);
    r->time = cka_rd64(b + 48);
    r->exit = (int32_t)cka_rd32(b + 68);
    r->stage = cka_rd16(b + 76);
    r->reason = cka_rd16(b + 78);
    r->syscalls = cka_rd32(b + 80);
    r->reads = cka_rd32(b + 84);
    r->denials = cka_rd32(b + 88);
    r->frames = cka_rd32(b + 92);
    put(r->id, b + 96, 32);
    put(r->payload, b + 128, 32);
    put(r->signer, b + 160, 32);
    put(r->policy, b + 192, 32);
    put(r->requested, b + 224, 32);
    put(r->granted, b + 256, 32);
    put(r->resources, b + 288, 32);
    put(r->verifier, b + 320, 32);
    put(r->machine, b + 352, 32);
    r->generation = cka_rd64(b + 384);
    r->context = cka_rd64(b + 392);
    put(r->fp, b + 404, 32);
    put(r->sig, b + 436, 64);
    return CKA_OK;
}

int cka_receipt_validate(const struct cka_receipt *r)
{
    static const uint8_t zero[32];
    int bad = CKA_MALFORMED_RECEIPT;
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++)
        acc |= (uint8_t)(r->machine[i] ^ zero[i]);
    if (!(r->flags & 1) && acc)
        return bad;
    if (!(r->flags & 2) && (r->generation || r->context))
        return bad;
    if (!(r->flags & 4) && r->time)
        return bad;
    int reason_ok = (r->reason >= 1 && r->reason <= 19) || (r->reason >= 0x101 && r->reason <= 0x10a);
    if (r->stage > 9 || (r->reason && !reason_ok))
        return bad;
    if (r->decision == CKR_REJECTED) {
        if (!r->stage || !r->reason || r->status != CKR_NOT_RUN || r->exit || r->syscalls ||
            r->reads || r->denials || (r->result_flags & ~CKR_F_RECLAIMED))
            return bad;
    } else if (r->stage || r->reason) {
        return bad;
    }
    if ((r->result_flags & CKR_F_CANARY) && (r->status != CKR_EXITED || r->exit))
        return bad;
    uint8_t n[16];
    cka_receipt_nonce(r->verifier, r->seq, n);
    acc = 0;
    for (int i = 0; i < 16; i++)
        acc |= (uint8_t)(n[i] ^ r->nonce[i]);
    return acc ? bad : CKA_OK;
}

void cka_receipt_digest(const uint8_t b[CKA_RECEIPT_SIZE], uint8_t out[32])
{
    static const char dom[] = "AIENOS-ADMISSION-RECEIPT-V1";
    cka_digest_domain(dom, sizeof dom, b, CKA_RECEIPT_SIGNED_LEN, out);
}

int cka_receipt_is_signed(const uint8_t b[CKA_RECEIPT_SIZE])
{
    return nz(b, CKA_RECEIPT_SIGNED_LEN, CKA_RECEIPT_SIZE);
}

static void sig_message(const uint8_t digest[32], uint8_t *m, size_t *len)
{
    for (size_t i = 0; i < sizeof sig_dom; i++)
        m[i] = (uint8_t)sig_dom[i];
    put(m + sizeof sig_dom, digest, 32);
    *len = sizeof sig_dom + 32;
}

int cka_receipt_sign(uint8_t b[CKA_RECEIPT_SIZE], const uint8_t seed[32])
{
    struct cka_receipt r;
    if (cka_receipt_is_signed(b))
        return CKA_BAD_SIG_FORMAT;
    int rc = cka_receipt_decode(b, &r);
    if (rc)
        return rc;
    uint8_t d[32], pk[32], m[96];
    size_t mlen;
    cka_receipt_digest(b, d);
    sig_message(d, m, &mlen);
    if (aienos_ed25519_public_key(pk, seed) != AIENOS_SIG_OK ||
        aienos_ed25519_sign(b + 436, m, mlen, seed) != AIENOS_SIG_OK)
        return CKA_BAD_SIGNATURE;
    cka_wr16(b + 400, 1);
    sha256_hash(pk, 32, b + 404);
    return CKA_OK;
}

int cka_receipt_verify(const uint8_t b[CKA_RECEIPT_SIZE], const uint8_t (*anchors)[32],
                       unsigned nanchors)
{
    struct cka_receipt r;
    int rc = cka_receipt_decode(b, &r);
    if (rc)
        return rc;
    if (!r.sig_alg)
        return CKA_BAD_SIG_FORMAT;
    const uint8_t *key = 0;
    uint8_t fp[32];
    for (unsigned i = 0; i < nanchors && !key; i++) {
        sha256_hash(anchors[i], 32, fp);
        uint8_t acc = 0;
        for (int k = 0; k < 32; k++)
            acc |= (uint8_t)(fp[k] ^ r.fp[k]);
        if (!acc)
            key = anchors[i];
    }
    if (!key)
        return CKA_UNTRUSTED_SIGNER;
    uint8_t d[32], m[96];
    size_t mlen;
    cka_receipt_digest(b, d);
    sig_message(d, m, &mlen);
    return aienos_ed25519_verify(r.sig, m, mlen, key) == AIENOS_SIG_OK ? CKA_OK : CKA_BAD_SIGNATURE;
}

void cka_verifier_identity(const char *commit, uint8_t feature, uint8_t out[32])
{
    static const char dom[] = "AIENOS-VERIFIER-IDENTITY-V1";
    uint8_t id[45];
    int ok = 1;
    for (int i = 0; i < 40 && ok; i++) {
        char c = commit[i];
        ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        id[i] = (uint8_t)c;
    }
    if (ok && commit[40] == 0) {
        cka_wr16(id + 40, CKA_TARGET_AARCH64_LE);
        cka_wr16(id + 42, CKA_ABI_V1);
        id[44] = feature;
        cka_digest_domain(dom, sizeof dom, id, sizeof id, out);
    } else {
        static const char unpinned[] = "unpinned-build";
        cka_digest_domain(dom, sizeof dom, (const uint8_t *)unpinned, sizeof unpinned - 1, out);
    }
}
