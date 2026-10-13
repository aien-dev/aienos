/* context_proposal.h -- exact preview / approval / commit binding for the
 * resident lifecycle (native v1 gate N3, aienos#329).
 *
 * Pure logic (no kernel calls; SHA-256 of native/argus): host-tested by
 * tests/test_context.c; bound to the sealed Store by core/lifecycle.c.
 *
 * When a proposal becomes pending (`task <text>` accepted, or a generated
 * reply), the binding records:
 *   request   (incarnation, seq): the durable continuity incarnation of this
 *             boot (svc/continuity_service.c, +1 every boot) and a per-boot
 *             proposal counter, so a request id is never reused across
 *             restarts of the same agent;
 *   gen       the Store generation the proposal was made against (the
 *             authoritative state the operator saw);
 *   kind, len, sha   the exact artifact bytes shown for approval (SHA-256);
 *   key       the idempotence key SHA-256("aienos.commit.key.v1" 0x00 ||
 *             agent || inc || seq || gen || kind || sha) (integers LE).
 * `approve` rebuilds the bytes from the pending state and commits only when
 * ck_prop_check passes: absent (nothing bound), changed (other bytes or kind)
 * and stale (the Store generation moved since the proposal: something else
 * committed in between) are refused and nothing is written. The committed
 * object is the artifact bytes followed by the trailer of ck_prop_trailer,
 * whose last line is "key: <64 hex>\n"; before committing, the lifecycle
 * scans the committed objects for that key and refuses a replay
 * (ck_prop_has_key). `cancel`, `deny` and `shutdown` only forget the binding:
 * nothing is written. A pending proposal is memory only: it never survives a
 * restart, and a new boot has a new incarnation, so no restart can approve
 * (and so duplicate) an earlier proposal. */
#ifndef AIENOS_CK_CONTEXT_PROPOSAL_H
#define AIENOS_CK_CONTEXT_PROPOSAL_H

#include <stddef.h>
#include <stdint.h>

enum {
    CK_PROP_OK = 0,
    CK_PROP_E_ABSENT = -1,  /* nothing bound */
    CK_PROP_E_CHANGED = -2, /* bytes or kind differ from the bound ones */
    CK_PROP_E_STALE = -3,   /* the Store generation moved since the proposal */
};

/* "\nrequest: inc=<u64> seq=<u64> gen=<u64>\nsha256: <64>\nkey: <64>\n" upper bound */
#define CK_PROP_TRAILER_MAX (1 + 14 + 3 * 25 + 1 + 8 + 64 + 1 + 5 + 64 + 1)

typedef struct {
    int active;
    uint64_t inc, seq, gen;
    uint16_t kind;
    size_t len;
    uint8_t sha[32];
    uint8_t key[32];
} ck_prop;

void ck_prop_clear(ck_prop *p);
/* Bind the pending artifact. agent: the provisioned agent id (32 bytes). */
void ck_prop_bind(ck_prop *p, const uint8_t agent[32], uint64_t inc, uint64_t seq, uint64_t gen, uint16_t kind,
                  const uint8_t *bytes, size_t len);
/* 0 when `bytes` (kind) are exactly the bound ones and the Store is still at
 * the bound generation; else a CK_PROP_E_* code. */
int ck_prop_check(const ck_prop *p, uint64_t gen_now, uint16_t kind, const uint8_t *bytes, size_t len);
/* Write the trailer; returns its length, 0 when cap is too small or nothing is bound. */
size_t ck_prop_trailer(const ck_prop *p, char *out, size_t cap);
/* 1 when a committed object ends with the trailer line "key: <hex(key)>\n". */
int ck_prop_has_key(const uint8_t *obj, size_t len, const uint8_t key[32]);
const char *ck_prop_strerror(int rc);

#endif
