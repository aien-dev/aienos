/* security.h -- the security boot stage: the native capability authority
 * (AEGIS, native/capability) and ARGUS (native/argus) with its ARGUS-1
 * containment bridge and gate, brought up the way the e2e bridge test does,
 * then two in-kernel self-checks:
 *   caps:  the Rust ipc demo semantics on the C authority (grant, attenuated
 *          delegation, amplification refused, forged reference denied,
 *          revoke of the ancestor denies the delegated copy);
 *   argus: the ARGUS-1 first narrow-revoke invariant (I1 one narrow revoke,
 *          I5 no authority expansion).
 * Not a qualification: it runs on whatever CPU the kernel runs on. */
#ifndef AIENOS_CK_SECURITY_H
#define AIENOS_CK_SECURITY_H
#include <stdint.h>
#include "aienos_capability.h"

typedef struct {
    /* caps */
    int caps_granted, caps_attenuated, caps_amplify_denied, caps_forged_denied, caps_revoked_denied;
    int caps_ok;
    /* argus */
    uint32_t findings_before;     /* findings drained after the caps check */
    uint32_t trigger_findings;    /* findings from the trigger event (want 1) */
    int decision, execution;      /* AIENOS_CONTAIN_* of the receipts */
    uint32_t revokes_during;      /* observer REVOKE announcements during submit (want 1) */
    uint32_t mints_during;        /* observer MINT announcements during the ARGUS run (want 0) */
    uint32_t executor_mints;      /* MINTs with subject AIENOS_CONTAIN_SUBJ after create (want 0) */
    int target_denied_code;       /* validate rc on the revoked target */
    int unrelated_same_subject;   /* validate rc, want 0 */
    int unrelated_other_subject;  /* validate rc, want 0 */
    int executor_unchanged;       /* rights == REVOKE only, same generation, LIVE */
    int health_ok, bridge_ok;
    int argus_ok;
    const char *fail;             /* first failed step, NULL when both ok */
} ck_sec_report;

/* Bring up authority + ARGUS and run both checks. 0 when both pass. The
 * authority and ARGUS stay up (kernel lifetime); ck_security_shutdown frees
 * them (host tests). */
int ck_security_run(ck_sec_report *r);
void ck_security_shutdown(void);
#endif
