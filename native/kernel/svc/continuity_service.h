/* continuity_service.h -- production continuity on the resident lifecycle
 * (native v1 plan P05, cut 1; aienos#35, #31).
 *
 * Linked only into a CK_SERVICE=1 image (and the host stage test with
 * CK_CONT_SERVICE_HOST_TEST). The TEST-ONLY mode selection of
 * svc/continuity_boot.c (plan line on the disk, modes 5..11, the TEST
 * operator key, the Recovery Core) is never part of this image: the Makefile
 * cont_check refuses its symbols and strings in every service image.
 *
 * What runs, once per Store open (store stage with keys, or `unlock`):
 *   unprovisioned Store -> PROVISIONED: identity (AgentRoot, genesis
 *       AgentState, Manifest 1) AND the genesis ALLEN subject (kind 24,
 *       sequence 1) in ONE Store transaction (svc/continuity_subject_provision.c);
 *       entropy from the kernel RNDR service, no fallback (NO_ENTROPY refuses).
 *   provisioned Store -> the ALLEN subject is restored read-only first; absent,
 *       corrupt, forked or foreign subject: REFUSED, nothing written, never
 *       minted over. Then cr_resume commits incarnation + 1 (RESUMED), or on a
 *       degraded mount restores without writing (RESUMED_READONLY: commits refused).
 *   anything else (Conflict, Corrupt, Limit, Store error) -> REFUSED.
 * A REFUSED outcome keeps the lifecycle LOCKED: the Store keys are erased and
 * the disk bytes are left as found (svc/store_boot.c).
 *
 * Genesis inputs (v1, deterministic, public): provenance = SHA-256("AIENOS/ALLEN/PROVENANCE-V1"
 * || owner root public key (if the image carries one) || store uuid); cortex
 * lineage = SHA-256("AIENOS/ALLEN/CORTEX-LINEAGE-V1" || store uuid): the Cortex of
 * this subject is the sealed Store on this disk (CURRENT_EXECUTION_PLAN addendum,
 * conflict 3; the Omega CxStore adapter of P06 writes the records).
 *
 * Not here (limits): Cortex records / the approved note are not yet continuity
 * WAL records (P06); no Recovery Core in the service image (its operator key
 * is TEST-only); no TPM; hardware NOT_RUN. */
#ifndef CK_CONTINUITY_SERVICE_H
#define CK_CONTINUITY_SERVICE_H
#include <stddef.h>
#include <stdint.h>
#include "continuity_codec.h"
#include "store_sealed.h"

enum {
    CK_CONT_NONE = 0,             /* not started (Store locked / stopped) */
    CK_CONT_PROVISIONED = 1,      /* identity + genesis subject minted, one transaction */
    CK_CONT_RESUMED = 2,          /* restored; incarnation + 1 committed */
    CK_CONT_RESUMED_READONLY = 3, /* degraded mount: restored, nothing written, commits refused */
    CK_CONT_REFUSED = -1,         /* explicit refusal: lifecycle stays LOCKED */
};

/* source: CC_SOURCE_OPERATOR (hardware staging image) or CC_SOURCE_QUALIFICATION
 * (TEST-key service image, QEMU). owner_pk/owner_pk_len: the build-time owner
 * root public key or NULL/0. Prints its "continuity:" and "allen:" lines. */
int ck_cont_service_start(ss_store *s, const uint8_t store_uuid[16], const uint8_t *owner_pk,
                          size_t owner_pk_len, uint8_t source);
int ck_cont_service_state(void);    /* CK_CONT_* of the last start (CK_CONT_NONE after stop) */
int ck_cont_service_writable(void); /* 1 after PROVISIONED or RESUMED */
/* "continuity=<word> agent=<8 hex> incarnation=<n> subject_seq=<n>" (NUL-terminated). */
void ck_cont_service_status(char *out, size_t cap);
const uint8_t *ck_cont_service_agent(void); /* 32 bytes, or NULL before a successful start */
uint64_t ck_cont_service_incarnation(void); /* durable incarnation of this boot, 0 before a successful start */
void ck_cont_service_stop(void);            /* forget the view (the Store keys are gone) */
#endif
