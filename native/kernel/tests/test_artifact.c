/* test_artifact.c -- host test of the C artifact library (format, TEST-key
 * verification, admission policy, receipts) that the kernel loader uses.
 * The pack/sign helpers come from the in-tree tool (its main is renamed). */
#define main ck_artifact_tool_main
#include "../tools/ck_artifact_tool.c"
#undef main

#include "ck_test.h"

static struct cka_limits plenty(void)
{
    struct cka_limits l = {1000, 1000, 1000, 16, 0, 0, 1000000000ull, 1000000000ull, 65536};
    return l;
}

static void test_verify_and_admit(void)
{
    struct buf b = signed_art(1, seed_read(1), res(1, 1, 1, 1, 8), exit0_w, 4, "BASELINE");
    struct cka_parsed p;
    struct cka_ident id;
    uint8_t fp[32], pkfp[32];
    CHECK(cka_identify(b.p, b.n, &p, &id) == 0);
    CHECK(verify_test(&b, &p, &id, fp) == 0);
    sha256_hash(cka_test1_pk, 32, pkfp);
    CHECK(memcmp(fp, pkfp, 32) == 0);

    /* Production trust (no anchors): the same artifact is refused. */
    CHECK(cka_verify(b.p, b.n, 0, 0, &p, &id, fp) == CKA_UNTRUSTED_SIGNER);

    /* Qualification policy admits it with the requested read grant. */
    struct cka_policy pol;
    struct cka_decision d;
    struct cka_limits avail = plenty();
    CHECK(verify_test(&b, &p, &id, fp) == 0);
    cka_boot_policy(&pol, &cka_test1_pk, 1);
    CHECK(cka_evaluate(&pol, &p, fp, &avail, &d) == 0);
    CHECK(d.ngrants == 1 && d.grants[0].rights == 1 && d.grants[0].id == 1);

    /* No frames available: ResourceLimit, never a partial admission. */
    avail.code_pages = avail.data_pages = avail.stack_pages = 0;
    CHECK(cka_evaluate(&pol, &p, fp, &avail, &d) == CKA_RESOURCE_LIMIT);

    /* A policy without signers refuses the TEST signer. */
    struct cka_policy prod;
    cka_boot_policy(&prod, 0, 0);
    avail = plenty();
    CHECK(cka_evaluate(&prod, &p, fp, &avail, &d) != 0);
    uint8_t d1[32], d2[32];
    cka_policy_digest(&pol, d1);
    cka_policy_digest(&prod, d2);
    CHECK(memcmp(d1, d2, 32) != 0);

    /* Any payload byte flipped: refused at verification. */
    struct buf t = clone(&b, 0);
    t.p[p.payload_off] ^= 1;
    CHECK(cka_verify(t.p, t.n, &cka_test1_pk, 1, &p, &id, fp) != 0);
    /* Truncated: refused before any signature work. */
    CHECK(cka_identify(b.p, 100, &p, &id) != 0);
    free(t.p);
    free(b.p);
}

static void test_receipt(void)
{
    struct cka_receipt r, back;
    uint8_t rec[CKA_RECEIPT_SIZE], dg[32], dg2[32], ver[32];
    memset(&r, 0, sizeof r);
    cka_verifier_identity("0123456789abcdef0123456789abcdef01234567", 1, ver);
    r.decision = CKR_ADMITTED;
    r.tier = CKR_TIER_SEED0B_QEMU;
    r.seq = 1;
    memcpy(r.verifier, ver, 32);
    cka_receipt_nonce(ver, 1, r.nonce);
    r.status = CKR_EXITED;
    r.result_flags = 0xff;
    r.syscalls = 9;
    r.reads = 3;
    r.denials = 5;
    r.frames = 9;
    memset(r.id, 0x11, 32);
    memset(r.payload, 0x22, 32);
    memset(r.signer, 0x33, 32);
    memset(r.policy, 0x44, 32);
    memset(r.requested, 0x55, 32);
    memset(r.granted, 0x66, 32);
    memset(r.resources, 0x77, 32);
    CHECK(cka_receipt_validate(&r) == 0);
    cka_receipt_encode(&r, rec);
    CHECK(cka_receipt_decode(rec, &back) == 0);
    CHECK(back.seq == 1 && back.syscalls == 9 && back.result_flags == 0xff);
    cka_receipt_digest(rec, dg);
    cka_receipt_digest(rec, dg2);
    CHECK(memcmp(dg, dg2, 32) == 0);
    CHECK(!cka_receipt_is_signed(rec));
    CHECK(cka_receipt_sign(rec, test2_seed) == 0);
    CHECK(cka_receipt_verify(rec, &cka_test2_pk, 1) == 0);
    CHECK(cka_receipt_verify(rec, &cka_test1_pk, 1) != 0);
    rec[20] ^= 1;
    CHECK(cka_receipt_verify(rec, &cka_test2_pk, 1) != 0);

    /* An admitted receipt cannot carry a rejection stage. */
    r.stage = CKS_VERIFIED;
    r.reason = CKA_BAD_SIGNATURE;
    CHECK(cka_receipt_validate(&r) != 0);
}

static void test_names(void)
{
    CHECK(strcmp(cka_error_name(CKA_UNTRUSTED_SIGNER), "UntrustedSigner") == 0);
    CHECK(strcmp(cka_error_name(CKL_WX_AUDIT), "WxAudit") == 0);
    CHECK(strcmp(cka_stage_name(CKS_VERIFIED), "verified") == 0 ||
          strcmp(cka_stage_name(CKS_VERIFIED), "Verified") == 0);
}

int main(void)
{
    test_verify_and_admit();
    test_receipt();
    test_names();
    return ck_t_verdict("test_artifact");
}
