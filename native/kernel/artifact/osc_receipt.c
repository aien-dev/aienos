/* osc_receipt.c -- Omega realization receipt v1 verification. See osc_receipt.h and omega
 * spec/one-layer-receipts.md. Written from the spec: section 2 (layout), 3 (signature), 5 (checker identity),
 * 6 (order and reasons). One comment per step of section 6; the first failure decides the result.
 *
 * MUT(n) marks a guard the host mutation run (Makefile osc-receipt-mutants) removes, one at a time: with
 * -DOSC_RCPT_MUTANT=n guard n is skipped and tests/test_osc_receipt.c must fail. Mutants build only with
 * OSC_RCPT_HOST_TEST; a kernel build refuses the flag. */
#include <string.h>
#include "osc_receipt.h"
#include "osc_receipt_anchor.h"
#include "aienos_sig.h"
#include "sha256.h"

#ifdef OSC_RCPT_MUTANT
#ifndef OSC_RCPT_HOST_TEST
#error "receipt mutants are TEST-only host builds (OSC_RCPT_HOST_TEST)"
#endif
#define MUT(n) (OSC_RCPT_MUTANT == (n))
#else
#define MUT(n) 0
#endif

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* constant time over the 32 bytes (keys, hashes, identities; AGENTS.md section 6) */
static int eq32(const uint8_t *a, const uint8_t *b)
{
    uint8_t d = 0;
    for (unsigned i = 0; i < 32; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static int in_list(const uint8_t *v, const uint8_t (*list)[32], unsigned n)
{
    int hit = 0;
    for (unsigned i = 0; list && i < n; i++)
        hit |= eq32(v, list[i]);
    return hit;
}

/* Index of the anchor whose SHA-256 is fp, or -1. */
static int anchor_by_fp(const uint8_t *fp, const uint8_t (*anchors)[32], unsigned n)
{
    int found = -1;
    for (unsigned i = 0; anchors && i < n; i++) {
        uint8_t h[32];
        sha256_hash(anchors[i], 32, h);
        if (eq32(h, fp) && found < 0)
            found = (int)i;
    }
    return found;
}

void osc_receipt_target_hash(const char *name, size_t name_len, uint8_t out[32])
{
    static const char dom[] = "OMEGA-TARGET-V1"; /* + its terminating NUL (16 bytes) */
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)dom, sizeof dom);
    sha256_update(&c, (const uint8_t *)name, name_len);
    sha256_final(&c, out);
}

/* SHA-256("OMEGA-RECEIPT-DEPS-V1\0" || u32 count = 0): the empty dependency list (spec section 2, offset 112). */
static void empty_deps(uint8_t out[32])
{
    static const char dom[] = "OMEGA-RECEIPT-DEPS-V1";
    static const uint8_t zero_count[4] = { 0, 0, 0, 0 };
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)dom, sizeof dom);
    sha256_update(&c, zero_count, sizeof zero_count);
    sha256_final(&c, out);
}

static const uint8_t zero32[32];

unsigned osc_receipt_verify(const uint8_t *r, size_t len, const struct osc_accept *a, const struct osc_policy *p,
                            struct osc_receipt_info *info)
{
    struct osc_receipt_info local;
    if (!info)
        info = &local;
    memset(info, 0, sizeof *info);
    if (!r || len == 0)
        return OSC_RCPT_MISSING;
    if (!a || !p)
        return OSC_RCPT_ARGUMENT;

    /* 1. Structure: SIZE, MAGIC, VERSION, SIGNATURE_ALGORITHM, SIGNER_CLASS, EVIDENCE_CLASS, EPOCH_ORDER */
    if (!MUT(1) && len != OSC_RCPT_BYTES)
        return OSC_RCPT_SIZE;
    sha256_hash(r, OSC_RCPT_BYTES, info->id);
    info->have_id = 1;
    if (!MUT(2) && memcmp(r, "OMRCPT1\0", 8) != 0)
        return OSC_RCPT_MAGIC;
    if (!MUT(3) && rd16(r + 8) != 1)
        return OSC_RCPT_VERSION;
    unsigned cls = rd16(r + 10), alg = rd16(r + 12), ev = rd16(r + 14);
    info->signer_class = (uint16_t)cls;
    info->evidence_class = (uint16_t)ev;
    info->policy_epoch = rd64(r + 304);
    info->expiry_epoch = rd64(r + 312);
    if (!MUT(4) && alg != 1)
        return OSC_RCPT_SIGNATURE_ALGORITHM;
    if (!MUT(5) && cls != OSC_SIGNER_TEST && cls != OSC_SIGNER_OWNER)
        return OSC_RCPT_SIGNER_CLASS;
    if (!MUT(6) && ev != 1 && ev != 2)
        return OSC_RCPT_EVIDENCE_CLASS;
    if (!MUT(7) && info->expiry_epoch < info->policy_epoch)
        return OSC_RCPT_EPOCH_ORDER;

    /* 2. Class policy. Release mode is the spec's production mode: only OWNER receipts. The key comes from the
     * verifier's own anchor set for the receipt's class, matched by fingerprint, never from the receipt. In
     * release mode the only owner anchor honoured is the listed owner root; a key anchored in both classes is
     * refused. */
    if (!MUT(8) && p->release && cls != OSC_SIGNER_OWNER)
        return OSC_RCPT_TEST_SIGNER_IN_PRODUCTION;
    const uint8_t *fp = r + 320;
    const uint8_t (*mine)[32] = cls == OSC_SIGNER_TEST ? p->rcpt_test_anchors : p->rcpt_owner_anchors;
    unsigned n_mine = cls == OSC_SIGNER_TEST ? p->n_rcpt_test : p->n_rcpt_owner;
    int k = anchor_by_fp(fp, mine, n_mine);
    if (!MUT(9) && k < 0)
        return OSC_RCPT_UNTRUSTED_SIGNER;
    if (k < 0) /* only reachable under mutant 9: there is no key to verify with */
        return OSC_RCPT_BAD_SIGNATURE;
    const uint8_t *pk = mine[k];
    if (!MUT(10) && p->release && cls == OSC_SIGNER_OWNER && !eq32(pk, osc_rcpt_owner_root_pk))
        return OSC_RCPT_UNTRUSTED_SIGNER;
    {
        const uint8_t (*other)[32] = cls == OSC_SIGNER_TEST ? p->rcpt_owner_anchors : p->rcpt_test_anchors;
        unsigned n_other = cls == OSC_SIGNER_TEST ? p->n_rcpt_owner : p->n_rcpt_test;
        if (!MUT(11) && in_list(pk, other, n_other))
            return OSC_RCPT_UNTRUSTED_SIGNER;
    }

    /* 3. Signature over "OMEGA-REALIZATION-RECEIPT-SIG-V1\0" || SHA-256("OMEGA-REALIZATION-RECEIPT-V1\0" || [0,352)) */
    {
        static const char body_dom[] = "OMEGA-REALIZATION-RECEIPT-V1";
        static const char sig_dom[] = "OMEGA-REALIZATION-RECEIPT-SIG-V1";
        uint8_t msg[sizeof sig_dom + 32];
        sha256_ctx c;
        memcpy(msg, sig_dom, sizeof sig_dom);
        sha256_init(&c);
        sha256_update(&c, (const uint8_t *)body_dom, sizeof body_dom);
        sha256_update(&c, r, OSC_RCPT_SIGNED_BYTES);
        sha256_final(&c, msg + sizeof sig_dom);
        _Static_assert(sizeof msg == 65, "signed message is 65 bytes");
        if (!MUT(12) && aienos_ed25519_verify(r + OSC_RCPT_SIGNED_BYTES, msg, sizeof msg, pk) != AIENOS_SIG_OK)
            return OSC_RCPT_BAD_SIGNATURE;
    }

    /* 4. Revocation: receipt id, then signer key fingerprint */
    if (!MUT(13) && in_list(info->id, p->rcpt_revoked_ids, p->n_rcpt_revoked_ids)) {
        info->revoked = OSC_RCPT_REVOKED_ID;
        return OSC_RCPT_REVOKED;
    }
    if (!MUT(14) && in_list(fp, p->rcpt_revoked_keys, p->n_rcpt_revoked_keys)) {
        info->revoked = OSC_RCPT_REVOKED_KEY;
        return OSC_RCPT_REVOKED;
    }

    /* 5. Freshness in policy epochs (no clock), window inclusive at both ends */
    if (!MUT(15) && info->policy_epoch < p->rcpt_epoch_floor)
        return OSC_RCPT_STALE_EPOCH;
    if (!MUT(16) && p->rcpt_epoch_now > info->expiry_epoch)
        return OSC_RCPT_EXPIRED;
    if (!MUT(17) && p->rcpt_epoch_now < info->policy_epoch)
        return OSC_RCPT_NOT_YET_VALID;

    /* 6. Checker identity: in the accepted list (an empty list refuses every receipt) */
    if (!MUT(18) && !in_list(r + 144, p->rcpt_checkers, p->n_rcpt_checkers))
        return OSC_RCPT_UNTRUSTED_CHECKER;

    /* 7. Binding to the unit being launched */
    if (!MUT(19) && (!p->rcpt_target || !eq32(r + 208, p->rcpt_target)))
        return OSC_RCPT_WRONG_TARGET;
    if (!MUT(20) && !eq32(r + 240, p->rcpt_firmware ? p->rcpt_firmware : zero32))
        return OSC_RCPT_WRONG_FIRMWARE;
    if (!MUT(21) && !eq32(r + 48, a->ir_sha256))
        return OSC_RCPT_PROGRAM_MISMATCH;
    if (!MUT(22) && !eq32(r + 80, a->code_sha256))
        return OSC_RCPT_EXECUTABLE_MISMATCH;
    if (!MUT(23) && p->rcpt_producer && !eq32(r + 176, p->rcpt_producer))
        return OSC_RCPT_WRONG_PRODUCER;
    {
        uint8_t deps[32];
        empty_deps(deps);
        if (!MUT(24) && !eq32(r + 112, deps))
            return OSC_RCPT_DEPENDENCIES_MISMATCH;
    }

    /* 8. Evidence class 2 (spec section 10): valid only when the same LRAT proofs are given and replayed. The
     * kernel is given none and has no LRAT checker, so class 2 is refused (fail closed). The spec does not place
     * this check in the section 6 order; it runs last, after every section 6 step passed. */
    if (!MUT(25) && ev == 2)
        return OSC_RCPT_LRAT_PROOFS_REQUIRED;
    return 0;
}
