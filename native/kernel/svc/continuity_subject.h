/* continuity_subject.h -- ALLEN subject state: continuity object kind 24.
 *
 * ARCH-0035 (PROPOSED) / OS-0018 (PROPOSED). ALLEN is the durable subject the
 * AIEN organism sustains: one chain of content-addressed Store v1 objects
 * bound to the AgentRoot (kind 16, OS-0016) of this Store. Each object says
 * what the subject currently intends (standing intents), which Cortex
 * promotions it holds as its own (knowledge references, by digest only), and
 * which Cortex journal lineage is its memory. It holds no capability, weight,
 * model, machine, process or queue reference: the model is not the subject.
 *
 * This file is a codec plus a resolver. It has no thread, no wait, no clock,
 * no scheduling and no authority: nothing here can mint, grant or dispatch.
 * The kernel resolves subject state like any continuity object (OS-0016
 * step 3 discipline: fork, gap, foreign root or undecodable object stop with
 * CORRUPT; a Store with a root but no subject object is ABSENT, never minted).
 *
 * Encoding (little-endian, fixed layout, no_std style; header as
 * continuity_codec.c): 16-byte header {magic "AIENSUBJ", format_version u16
 * = 0, reserved u16 = 0, body length u32}, then
 *   root        32   logical ObjectId of the AgentRoot this subject belongs to
 *   agent       32   LogicalAgentId (must equal that AgentRoot's)
 *   previous    32   ObjectId of the prior subject object; zero for sequence 1
 *   sequence     8   previous.sequence + 1; 1 for the genesis subject object
 *   cortex      32   lineage reference: digest of the Cortex journal's genesis
 *                    record (rx_cortex record id 1); zero = unbound
 *   provenance  32   who/what established this object (operator key id or a
 *                    receipt digest); nonzero required
 *   origin       1   CS_ORIGIN_OPERATOR or CS_ORIGIN_PROMOTED
 *   reserved     7   zero
 *   n_intents    2   0..CS_MAX_INTENTS
 *   n_knowledge  2   0..CS_MAX_KNOWLEDGE
 *   reserved     4   zero
 *   intents      n_intents * 96, strictly ascending by id
 *   knowledge    n_knowledge * 48, strictly ascending by digest
 * Largest object: 16 + 184 + 64*96 + 64*48 = 9416 bytes, under the K-1 cap.
 *
 * Intent (96 bytes): id 32, supersedes 32 (zero = none), kind u32, state u8,
 * reserved 3, since u64 (sequence of the subject object that created it),
 * payload 2 x u64. id = SHA-256("AIENOS_INTENT_v0:" || agent || kind LE32 ||
 * since LE64 || payload[0] LE64 || payload[1] LE64), checked on decode.
 * Rules: at most one ACTIVE intent per (kind, payload[0]) slot; a SUPERSEDED
 * intent is named by exactly one newer intent's `supersedes`; `supersedes`
 * must name an intent in the same table whose state is SUPERSEDED;
 * since <= sequence.
 *
 * Knowledge (48 bytes): digest 32 (cx_digest of a CX_K_PROMOTION record),
 * record u64 (its id in that journal, informative), since u64.
 *
 * Kinds of standing intent in v0: CS_INTENT_GOAL_LATENCY, the one goal shape
 * the resident AIEN faculty reads today (omega rx_aien.h: regime, target ns
 * per call). payload[0] = regime, payload[1] = target ns. */
#ifndef CK_CONTINUITY_SUBJECT_H
#define CK_CONTINUITY_SUBJECT_H

#include <stddef.h>
#include <stdint.h>

#include "continuity_codec.h"
#include "continuity_commit.h"
#include "continuity_resolve.h"

#if defined(CK_HARDWARE_STAGING) && \
    (defined(CS_MUTANT_ACCEPT_FOREIGN) || defined(CS_MUTANT_ACCEPT_TWO_ACTIVE) || \
     defined(CS_MUTANT_SKIP_INTENT_ID) || defined(CS_MUTANT_ACCEPT_FORK))
#error "continuity subject mutants are TEST-only and refused under CK_HARDWARE_STAGING"
#endif

#define CC_KIND_SUBJECT 24u

#define CS_MAX_INTENTS 64u
#define CS_MAX_KNOWLEDGE 64u
#define CS_INTENT_BYTES 96u
#define CS_KNOWLEDGE_BYTES 48u
#define CS_FIXED_BODY 184u
#define CS_MAX_BYTES (CC_HEADER_BYTES + CS_FIXED_BODY + CS_MAX_INTENTS * CS_INTENT_BYTES + \
                      CS_MAX_KNOWLEDGE * CS_KNOWLEDGE_BYTES)

#define CS_ORIGIN_OPERATOR 1u
#define CS_ORIGIN_PROMOTED 2u

#define CS_INTENT_GOAL_LATENCY 1u

#define CS_ACTIVE 1u
#define CS_INACTIVE 2u
#define CS_SUPERSEDED 3u

struct cs_intent {
    uint8_t id[32];
    uint8_t supersedes[32]; /* zero = none */
    uint32_t kind;
    uint8_t state; /* CS_ACTIVE / CS_INACTIVE / CS_SUPERSEDED */
    uint64_t since;
    uint64_t payload[2];
};

struct cs_knowledge {
    uint8_t digest[32];
    uint64_t record;
    uint64_t since;
};

struct cs_subject {
    uint8_t root[32];
    uint8_t agent[32];
    uint8_t previous[32];
    uint64_t sequence;
    uint8_t cortex[32];
    uint8_t provenance[32];
    uint8_t origin;
    uint32_t n_intents;
    uint32_t n_knowledge;
    struct cs_intent in[CS_MAX_INTENTS];
    struct cs_knowledge kn[CS_MAX_KNOWLEDGE];
};

/* ---- codec (CC_OK / CC_E_CORRUPT / CC_E_LIMIT / CC_E_ARG, as continuity_codec.h) ---- */
void cs_intent_id(const uint8_t agent[32], uint32_t kind, uint64_t since, const uint64_t payload[2],
                  uint8_t out[32]);
int cs_subject_validate(const struct cs_subject *s, const char **why);
int cs_subject_encode(const struct cs_subject *s, uint8_t *out, size_t cap, size_t *len,
                      const char **why);
int cs_subject_decode(const uint8_t *in, size_t len, struct cs_subject *s, const char **why);
/* Logical ObjectId of the encoded object (kind 24, claim version 1): the
 * subject digest. Content only; the same bytes give the same id on any
 * machine, under any model, in any process. */
int cs_subject_id(const uint8_t *bytes, size_t len, uint8_t out[32]);

/* ---- editing (in memory; nothing here touches storage) ---- */
/* First subject object for a resolved continuity view: sequence 1, no
 * previous, no intents, no knowledge, Cortex unbound. */
void cs_subject_genesis(struct cs_subject *s, const struct cr_view *v, const uint8_t provenance[32],
                        uint8_t origin);
/* Prepare the successor of a persisted object: previous = prev_id,
 * sequence + 1, new provenance/origin; intents and knowledge are kept. */
void cs_subject_advance(struct cs_subject *s, const uint8_t prev_id[32],
                        const uint8_t provenance[32], uint8_t origin);
/* Add an ACTIVE standing intent created at this object's sequence. If another
 * ACTIVE intent holds the same (kind, payload[0]) slot it becomes SUPERSEDED
 * and the new intent names it; the table stays sorted. CC_E_LIMIT when full. */
int cs_subject_intend(struct cs_subject *s, uint32_t kind, const uint64_t payload[2],
                      uint8_t id_out[32], const char **why);
/* Retire an ACTIVE intent (state INACTIVE). CC_E_ARG if absent or not active. */
int cs_subject_retire(struct cs_subject *s, const uint8_t id[32], const char **why);
/* Hold a Cortex promotion as subject knowledge; duplicates are refused. */
int cs_subject_hold(struct cs_subject *s, const uint8_t digest[32], uint64_t record,
                    const char **why);
/* Bind (or re-bind) the Cortex lineage reference. */
void cs_subject_bind_cortex(struct cs_subject *s, const uint8_t lineage[32]);
/* The ACTIVE intent in slot (kind, payload[0]); NULL if none. */
const struct cs_intent *cs_subject_active(const struct cs_subject *s, uint32_t kind, uint64_t slot);

/* ---- resolver / committer over the continuity source and sink ---- */
#define CS_RESOLVED 0 /* out holds the head of the chain; out_id its ObjectId */
#define CS_ABSENT 1   /* the Store has a root but no subject object: not minted */
/* Other returns are CR_CORRUPT, CR_LIMIT, CR_STORE, CR_E_ARG (continuity_resolve.h). */
int cs_resolve(const struct cr_source *src, struct cr_work *w, const struct cr_view *v,
               struct cs_subject *out, uint8_t out_id[32], const char **why, int *store_rc);
/* Encode and commit one subject object in its own Store transaction. The
 * object must validate and must continue the chain the caller resolved:
 * cs_resolve is run first; its head id must equal s->previous (or the Store
 * must be ABSENT and s->sequence 1). Returns CS_RESOLVED with out_id, or
 * CR_CORRUPT / CR_LIMIT / CR_STORE / CR_E_ARG; nothing is written on refusal. */
int cs_commit(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
              const struct cr_view *v, const struct cs_subject *s, uint8_t out_id[32],
              const char **why, int *store_rc);

#endif
