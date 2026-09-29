/*
 * aienos_capability.h -- native AIENOS capability authority.
 *
 * The view can check a reference. The admin can change the table. The
 * reaction world is given the view. Cognition has no path to the admin.
 *
 * Slot rules: a reference is an index plus a generation, a reused slot does
 * not honor the old reference, generation is 64 bits and never wraps, a
 * restarted table starts above every generation the old table used,
 * delegation can only narrow rights, and revoking an ancestor revokes the
 * descendants. Each entry carries its subject, epoch, lease, full 64-bit
 * resource, and office rights that cannot be delegated.
 *
 * The declarations below match omega/src/runtime/aienos_cap.h in name and
 * layout, so the reaction world links this file without change.
 */
#ifndef AIENOS_CAPABILITY_H
#define AIENOS_CAPABILITY_H

#include <stdint.h>

#define AIENOS_CAP_MAX 256u
#define AIENOS_CAP_MAX_DEPTH 8u
#define AIENOS_CAP_TOKEN_LEN 32u
#define AIENOS_CAP_RES_AUTHORITY 0ull

#define AIENOS_CAP_OK 0
#define AIENOS_CAP_ERR_BOUNDS (-1)
#define AIENOS_CAP_ERR_STALE_GEN (-2)
#define AIENOS_CAP_ERR_REVOKED (-3)
#define AIENOS_CAP_ERR_EPOCH (-4)
#define AIENOS_CAP_ERR_SUBJECT (-5)
#define AIENOS_CAP_ERR_RESOURCE (-6)
#define AIENOS_CAP_ERR_RIGHTS (-7)
#define AIENOS_CAP_ERR_EXPIRED (-8)
#define AIENOS_CAP_ERR_CHAIN (-9)
#define AIENOS_CAP_ERR_AMPLIFY (-10)
#define AIENOS_CAP_ERR_NOT_DELEGABLE (-11)
#define AIENOS_CAP_ERR_FULL (-12)
#define AIENOS_CAP_ERR_IO (-13)
#define AIENOS_CAP_ERR_STATE (-14)
#define AIENOS_CAP_ERR_UNAUTHORIZED (-15)
#define AIENOS_CAP_ERR_OVERFLOW (-16)
#define AIENOS_CAP_ERR_EXHAUSTED (-17)

#define AIENOS_CAP_RIGHT_READ 0x1u
#define AIENOS_CAP_RIGHT_WRITE 0x2u
#define AIENOS_CAP_RIGHT_EFFECT 0x4u
#define AIENOS_CAP_RIGHT_DELEGATE 0x8u
#define AIENOS_CAP_RIGHT_MINT 0x10u
#define AIENOS_CAP_RIGHT_REVOKE 0x20u
#define AIENOS_CAP_RIGHT_RECLAIM 0x40u
#define AIENOS_CAP_RIGHT_EPOCH 0x80u
#define AIENOS_CAP_RIGHT_CLOCK 0x100u
/* Authorizes a lineage transition. Intelligence may propose the next
 * generation. Only a holder of this right may promote it, and the right
 * cannot be handed on. */
#define AIENOS_CAP_RIGHT_PROMOTE 0x200u
#define AIENOS_CAP_RIGHT_PRIVILEGED                                                \
    (AIENOS_CAP_RIGHT_MINT | AIENOS_CAP_RIGHT_REVOKE | AIENOS_CAP_RIGHT_RECLAIM | \
     AIENOS_CAP_RIGHT_EPOCH | AIENOS_CAP_RIGHT_CLOCK | AIENOS_CAP_RIGHT_PROMOTE)
#define AIENOS_CAP_RIGHT_KNOWN                                                     \
    (AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE | AIENOS_CAP_RIGHT_EFFECT |   \
     AIENOS_CAP_RIGHT_DELEGATE | AIENOS_CAP_RIGHT_PRIVILEGED)

#define AIENOS_CAP_STATE_FREE 0u
#define AIENOS_CAP_STATE_LIVE 1u
#define AIENOS_CAP_STATE_REVOKED 2u

#define AIENOS_CAP_PARENT_NONE UINT32_MAX

typedef struct AienosCapAdmin AienosCapAdmin;
typedef struct AienosCapView AienosCapView;

typedef struct {
    uint32_t cap_id;
    uint64_t generation;
} AienosCapRef;

typedef struct {
    uint32_t cap_id;
    uint64_t generation;
    uint32_t state;
    uint32_t issuer;
    uint32_t subject;
    uint32_t rights;
    uint64_t resource;
    uint64_t epoch;
    uint64_t lease_expiry;
    uint32_t parent_id;
    uint64_t parent_generation;
    uint32_t minted_by_id;
    uint64_t minted_by_generation;
} AienosCapEntry;

typedef struct {
    uint32_t issuer;
    uint32_t subject;
    uint64_t resource;
    uint32_t rights;
    uint64_t lease_ticks;
    AienosCapRef parent;
    AienosCapRef authority;
} AienosCapMint;

int aienos_cap_start(AienosCapAdmin **admin, AienosCapView **view);
void aienos_cap_stop(AienosCapAdmin *admin, AienosCapView *view);
int aienos_cap_office(const AienosCapAdmin *admin, AienosCapRef *out);
int aienos_cap_mint(AienosCapAdmin *admin, const AienosCapMint *request, AienosCapRef *out);
int aienos_cap_revoke(AienosCapAdmin *admin, AienosCapRef authority, AienosCapRef target);
int aienos_cap_reclaim(AienosCapAdmin *admin, AienosCapRef authority, uint32_t cap_id);
int aienos_cap_advance_clock(AienosCapAdmin *admin, AienosCapRef authority, uint64_t ticks);
int aienos_cap_bump_epoch(AienosCapAdmin *admin, AienosCapRef authority);
int aienos_cap_kill(AienosCapAdmin *admin);
int aienos_cap_restart(AienosCapAdmin *admin);
int aienos_cap_validate(const AienosCapView *view, AienosCapRef cap, uint32_t subject,
                       uint64_t resource, uint32_t rights, AienosCapEntry *out);
int aienos_cap_inspect(const AienosCapView *view, AienosCapRef cap, AienosCapEntry *out);
uint64_t aienos_cap_clock(const AienosCapView *view);
int aienos_cap_cognition_mint(const AienosCapView *view, const AienosCapMint *request,
                             const uint8_t *token);
int aienos_cap_cognition_admin(const AienosCapView *view, uint32_t op, AienosCapRef authority,
                              AienosCapRef target);
int aienos_cap_force_generation(AienosCapAdmin *admin, uint32_t cap_id, uint64_t generation);
int aienos_cap_generation_advance(uint64_t generation, uint64_t *out);

/* Authority observer. The authority announces its own transitions, so a
 * watcher sees a mint or revoke no matter which caller asked for it.
 *
 * The observer is set on the admin handle. The view has no path to it, and
 * aienos_cap_validate never calls it.
 *
 * Calls, one per state change, with the entry as it is after the change:
 *   MINT      new entry; a refused mint calls with entry NULL and its code
 *   REVOKE    the target, then one call per descendant revoked with it,
 *             each ancestor before its descendants
 *   RECLAIM   the freed slot (state FREE, next generation)
 *   EPOCH     the entry of the authority that bumped it (the new epoch is
 *             not carried)
 *   CLOCK     the entry of the authority that moved it (the new clock is
 *             not carried; aienos_cap_clock reads it)
 *   KILL      entry NULL
 *   RESTART   the new office entry (slot 0, new boot generation)
 * A refused admin operation calls with entry NULL and the refusal code,
 * except a call refused for a NULL argument, and a restart that fails
 * before it takes the lock (out of memory, or /dev/urandom unreadable):
 * those are not announced.
 * aienos_cap_force_generation (the test seam) is not announced.
 * AIENOS_CAP_OBS_VALIDATE_DENIED is reserved and never sent: validate runs
 * on the view, which holds no observer, and it has no slow path to put
 * one on.
 *
 * The entry is a copy taken under the table lock. It never holds the office
 * token: the token is kept outside the table and outside AienosCapEntry.
 * The call is made after the table lock is released, so a slow observer
 * does not hold up validate or other admin operations. The callback gets
 * a const entry and no admin handle, so its arguments give it no way to
 * change the table.
 *
 * Ordering: calls from one thread arrive in the order that thread's
 * operations changed the table. When admin operations run on several
 * threads at once, calls may arrive in a different order than the changes;
 * a caller that needs strict order serializes its admin calls.
 * After aienos_cap_set_observer(admin, NULL, NULL) returns, no new call
 * starts; a call already under way on another thread may still finish.
 *
 * With no observer set, each admin operation pays one NULL check. */
#define AIENOS_CAP_OBS_MINT 1u
#define AIENOS_CAP_OBS_REVOKE 2u
#define AIENOS_CAP_OBS_RECLAIM 3u
#define AIENOS_CAP_OBS_EPOCH 4u
#define AIENOS_CAP_OBS_CLOCK 5u
#define AIENOS_CAP_OBS_KILL 6u
#define AIENOS_CAP_OBS_RESTART 7u
#define AIENOS_CAP_OBS_VALIDATE_DENIED 8u

typedef void (*AienosCapObserver)(void *ctx, uint32_t op, const AienosCapEntry *entry,
                                  int result);

int aienos_cap_set_observer(AienosCapAdmin *admin, AienosCapObserver fn, void *ctx);

/* Office token check, constant time. The token never enters the table.
 * Nothing in this library calls it: admin operations are gated by holding
 * the admin handle plus a live reference with the matching office right.
 * The token is kept for a caller that wants a second factor. */
int aienos_cap_authorize(const AienosCapAdmin *admin, const uint8_t *presented);

#endif
