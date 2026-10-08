/* osc_admit.c -- kernel policy and reporting for OSC unit admission.
 *
 * Policy (OSC_UNIT_ARTIFACT.md section 8.1), all local to this build:
 *   - ordinary build: release mode, no TEST anchor, no OWNER anchor. A TEST
 *     unit is refused TEST_SIGNER_IN_RELEASE, an OWNER unit UNTRUSTED_SIGNER
 *     (OWNER anchors are not provisioned until TRUST-1).
 *   - qualification build (CK_SEED0B_TEST_ANCHOR=1): qualification mode with
 *     the throwaway TEST key of the conformance vectors as the only TEST
 *     anchor, announced TEST ONLY. OWNER anchors stay empty.
 *   - capability domain 1 only (kernel IPC table, 32-bit generations); the
 *     kernel holds no resource state at admission, so any pinned generation is
 *     STALE (the lookup finds nothing). No reservation: launch is a later cut.
 * QEMU qualifies nothing physical. */
#include "ck_internal.h"
#include "osc_admit.h"
#include "osc_unit.h"
#ifdef CK_SEED0B_TEST_ANCHOR
#include "osc_unit_test_anchor.h"
#endif

static unsigned seen, accepted, refused, oversize, announced;
static struct osc_accept acc; /* ~5 KB: static, not on the kernel stack */

static int no_resource(void *ctx, unsigned domain, unsigned kind, uint32_t id, uint64_t *cur)
{
    (void)ctx; (void)domain; (void)kind; (void)id; (void)cur;
    return 1;
}

/* The Store and the native staging area hold at most 160 pages per artifact (= CK_ART_MAX_BYTES in
 * svc/artifact_store.h, 655,360 bytes; spec 8.2 step 16). */
#define OSC_STAGING_MAX (160u * 4096u)

static void hex(char *out, const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static void policy(struct osc_policy *p)
{
    memset(p, 0, sizeof *p);
    p->unit_formats = OSC_PROFILE_UNIT_FORMATS;
    p->abi_versions = OSC_PROFILE_ABI;
    p->cap_domains = 1u << 1;
    p->staging_max = OSC_STAGING_MAX;
    p->gen_lookup = no_resource;
#ifdef CK_SEED0B_TEST_ANCHOR
    static const uint8_t (*const ta)[32] = &osc_unit_test1_pk;
    p->release = 0;
    p->test_anchors = ta;
    p->n_test = 1;
#else
    p->release = 1;
#endif
}

int ck_osc_is_unit(const uint8_t *b, size_t len)
{
    return b && len >= 8 && memcmp(b, "OSCUNIT\0", 8) == 0;
}

unsigned ck_osc_candidate(const char *name, const uint8_t *b, size_t len)
{
    struct osc_policy p;
    policy(&p);
    if (!announced) {
        announced = 1;
#ifdef CK_SEED0B_TEST_ANCHOR
        ck_printf("osc_policy: mode=qualification test_anchors=1 (throwaway TEST key, TEST ONLY) owner_anchors=0 "
                  "domains=1 gen_width=32; QEMU, not physical\n");
#else
        ck_printf("osc_policy: mode=release test_anchors=0 owner_anchors=0 (none provisioned) "
                  "domains=1 gen_width=32; QEMU, not physical\n");
#endif
    }
    unsigned rc = osc_unit_admit(b, len, &p, &acc);
    seen++;
    if (rc == OSC_OK) {
        char d[65], i[65];
        hex(d, acc.unit_digest, 32);
        hex(i, acc.ir_sha256, 32);
        accepted++;
        ck_printf("osc_unit: %s ACCEPT unit_digest=%s program_id=%s funcs=%u caps=%u signer=%s\n", name, d, i,
                  (unsigned)acc.function_count, (unsigned)acc.cap_count,
                  acc.signer_class == OSC_SIGNER_TEST ? "TEST" : "OWNER");
    } else {
        refused++;
        ck_printf("osc_unit: %s REFUSED code=%u name=%s\n", name, rc, osc_code_name(rc));
    }
    return rc;
}

void ck_osc_oversize(const char *name, uint64_t len)
{
    oversize++;
    ck_printf("osc_unit: %s REFUSED code=%u name=%s reason=staging_too_large bytes=%llu limit=%u "
              "(content not read, format unknown; refusal by the Store size limit)\n",
              name, (unsigned)OSC_RESOURCE_UNAVAILABLE, osc_code_name(OSC_RESOURCE_UNAVAILABLE),
              (unsigned long long)len, (unsigned)OSC_STAGING_MAX);
}

void ck_osc_summary(void)
{
    if (seen || oversize)
        ck_printf("osc_units: seen=%u accepted=%u refused=%u oversize=%u (admission only, nothing launched)\n", seen, accepted,
                  refused, oversize);
}
