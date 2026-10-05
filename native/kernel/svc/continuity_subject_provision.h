/* continuity_subject_provision.h -- ALLEN genesis at identity provisioning.
 *
 * ARCH-0035 (PROPOSED) / OS-0018 (PROPOSED). A single-subject installation
 * creates its ALLEN subject exactly once: in the SAME Store transaction that
 * creates its identity. cs_provision runs cr_provision (OS-0016 provisioning,
 * unchanged) over a sink that appends the genesis subject object (kind 24,
 * sequence 1) to cr_provision's one transaction (AgentRoot, AgentState,
 * Manifest 1): four objects, one ss_transact, one generation. There is no
 * second WAL, no second database and no separate write: the subject inherits
 * the Store's commit protocol (payload objects, catalog, commit record,
 * flushes, superblock, anchor). A crash anywhere leaves either an
 * unprovisioned Store or an identity WITH its subject, never one without
 * the other.
 *
 * Restore never comes here. A provisioned Store whose subject is absent,
 * corrupt, forked or foreign is reported by cs_resolve and never minted over.
 *
 * Kernel-side composition only (it needs cr_provision and the entropy
 * source); omega links continuity_subject.c without this file. No thread, no
 * wait, no clock, no scheduling, no authority. */
#ifndef CK_CONTINUITY_SUBJECT_PROVISION_H
#define CK_CONTINUITY_SUBJECT_PROVISION_H

#include <stdint.h>

#include "continuity_commit.h"
#include "continuity_subject.h"

#if defined(CK_HARDWARE_STAGING) && defined(CS_MUTANT_PROVISION_SPLIT_TXN)
#error "continuity subject provision mutants are TEST-only and refused under CK_HARDWARE_STAGING"
#endif

/* What the provisioning request supplies about the subject. */
struct cs_genesis {
    uint8_t provenance[32]; /* nonzero: who/what established the subject */
    uint8_t origin;         /* CS_ORIGIN_OPERATOR or CS_ORIGIN_PROMOTED */
    uint8_t cortex[32];     /* memory lineage reference; nonzero required */
};

/* Identity + ALLEN genesis in one transaction. Refusals, in order: null or
 * invalid genesis input (CR_E_ARG, nothing read); kind-24 objects already in
 * the Store (CR_CORRUPT "subject objects without an agent root" when there is
 * no root; a Store with a root is CR_ALREADY_PROVISIONED from cr_provision);
 * then every cr_provision refusal unchanged. On success returns CR_RESOLVED
 * with the identity view in *out, the genesis subject in *subj and its
 * ObjectId in subj_id, after re-resolving both from the Store (post-condition:
 * exactly one subject object, sequence 1, bound to this root and agent). */
int cs_provision(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
                 struct cr_txwork *tw, struct ck_rng *rng, const uint8_t store_uuid[16],
                 uint8_t source, const struct cs_genesis *g, struct cr_view *out,
                 struct cs_subject *subj, uint8_t subj_id[32], const char **why, int *store_rc);

#endif
