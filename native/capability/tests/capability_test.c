/*
 * capability_test.c -- rules of the native capability authority.
 *
 * Each case names the rule it holds. A failure prints the line and the
 * process exits nonzero.
 */
#include "../aienos_capability.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond)                                                     \
    do {                                                                \
        checks++;                                                       \
        if (!(cond)) {                                                  \
            failures++;                                                 \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                               \
    } while (0)

#define EQ(a, b) CHECK((a) == (b))

/* Entries are compared field by field, never with memcmp. AienosCapEntry
 * has padding (after cap_id, parent_id and minted_by_id), and a struct copy
 * such as `*out = *e` need not copy padding bytes, so memcmp can see stack
 * garbage in the padding of two equal entries. How a compiler copies differs
 * by target (the suspected cause of the x86-64 CI baseline failure). */
static int same_entry(const AienosCapEntry *x, const AienosCapEntry *y) {
    return x->cap_id == y->cap_id && x->generation == y->generation && x->state == y->state &&
           x->issuer == y->issuer && x->subject == y->subject && x->rights == y->rights &&
           x->resource == y->resource && x->epoch == y->epoch &&
           x->lease_expiry == y->lease_expiry && x->parent_id == y->parent_id &&
           x->parent_generation == y->parent_generation &&
           x->minted_by_id == y->minted_by_id &&
           x->minted_by_generation == y->minted_by_generation;
}

static const AienosCapRef NONE = {AIENOS_CAP_PARENT_NONE, 0};

typedef struct {
    AienosCapAdmin *admin;
    AienosCapView *view;
} Auth;

static Auth boot(void) {
    Auth a = {0};
    if (aienos_cap_start(&a.admin, &a.view) != AIENOS_CAP_OK) {
        fprintf(stderr, "start failed\n");
        exit(2);
    }
    return a;
}

static AienosCapRef office(const Auth *a) {
    AienosCapRef r;
    aienos_cap_office(a->admin, &r);
    return r;
}

static int root_mint(Auth *a, uint32_t subject, uint64_t resource, uint32_t rights,
                     AienosCapRef *out) {
    AienosCapMint m = {3, subject, resource, rights, 0, NONE, office(a)};
    return aienos_cap_mint(a->admin, &m, out);
}

static int child_mint(Auth *a, AienosCapRef parent, uint32_t issuer, uint32_t subject,
                      uint64_t resource, uint32_t rights, AienosCapRef *out) {
    AienosCapMint m = {issuer, subject, resource, rights, 0, parent, parent};
    return aienos_cap_mint(a->admin, &m, out);
}

static int validate(Auth *a, AienosCapRef c, uint32_t subject, uint64_t resource,
                    uint32_t rights) {
    return aienos_cap_validate(a->view, c, subject, resource, rights, NULL);
}

static void high_half_resource_is_kept(void) {
    Auth a = boot();
    uint64_t wide = (1ull << 32) | 0x51;
    AienosCapRef cap;
    EQ(root_mint(&a, 1, wide, AIENOS_CAP_RIGHT_READ, &cap), AIENOS_CAP_OK);
    EQ(validate(&a, cap, 1, wide, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    EQ(validate(&a, cap, 1, 0x51, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_RESOURCE);
    aienos_cap_stop(a.admin, a.view);
}

static void forged_stale_subject_resource_and_rights_fail_closed(void) {
    Auth a = boot();
    AienosCapRef cap, reused, live;
    EQ(root_mint(&a, 1, 0x20, AIENOS_CAP_RIGHT_WRITE, &cap), AIENOS_CAP_OK);
    EQ(validate(&a, (AienosCapRef){200, 7}, 1, 0x20, AIENOS_CAP_RIGHT_WRITE),
       AIENOS_CAP_ERR_STALE_GEN);
    EQ(validate(&a, (AienosCapRef){300, 1}, 1, 0x20, AIENOS_CAP_RIGHT_WRITE),
       AIENOS_CAP_ERR_BOUNDS);
    EQ(aienos_cap_revoke(a.admin, office(&a), cap), AIENOS_CAP_OK);
    EQ(aienos_cap_reclaim(a.admin, office(&a), cap.cap_id), AIENOS_CAP_OK);
    EQ(root_mint(&a, 7, 0x20, AIENOS_CAP_RIGHT_WRITE, &reused), AIENOS_CAP_OK);
    EQ(reused.cap_id, cap.cap_id);
    EQ(reused.generation, cap.generation + 1);
    EQ(validate(&a, cap, 1, 0x20, AIENOS_CAP_RIGHT_WRITE), AIENOS_CAP_ERR_STALE_GEN);
    EQ(root_mint(&a, 1, 0x20, AIENOS_CAP_RIGHT_READ, &live), AIENOS_CAP_OK);
    EQ(validate(&a, live, 9, 0x20, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_SUBJECT);
    EQ(validate(&a, live, 1, 0x30, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_RESOURCE);
    EQ(validate(&a, live, 1, 0x20, AIENOS_CAP_RIGHT_WRITE), AIENOS_CAP_ERR_RIGHTS);
    aienos_cap_stop(a.admin, a.view);
}

static void amplification_lease_epoch_and_revoked_ancestor_fail(void) {
    Auth a = boot();
    AienosCapRef parent, child, out;
    AienosCapEntry e;
    EQ(root_mint(&a, 1, 0x20, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE, &parent),
       AIENOS_CAP_OK);
    EQ(child_mint(&a, parent, 1, 2, 0x20, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE, &out),
       AIENOS_CAP_ERR_AMPLIFY);
    EQ(child_mint(&a, parent, 1, 2, 0x20, AIENOS_CAP_RIGHT_READ, &child), AIENOS_CAP_OK);
    EQ(aienos_cap_revoke(a.admin, office(&a), parent), AIENOS_CAP_OK);
    EQ(aienos_cap_inspect(a.view, child, &e), AIENOS_CAP_OK);
    EQ(e.state, AIENOS_CAP_STATE_REVOKED);
    EQ(validate(&a, child, 2, 0x20, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_REVOKED);
    aienos_cap_stop(a.admin, a.view);

    a = boot();
    AienosCapRef leased, fresh;
    AienosCapMint m = {3, 1, 0x10, AIENOS_CAP_RIGHT_READ, 5, NONE, office(&a)};
    EQ(aienos_cap_mint(a.admin, &m, &leased), AIENOS_CAP_OK);
    EQ(aienos_cap_advance_clock(a.admin, office(&a), 10), AIENOS_CAP_OK);
    EQ(validate(&a, leased, 1, 0x10, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_EXPIRED);
    EQ(root_mint(&a, 1, 0x10, AIENOS_CAP_RIGHT_READ, &fresh), AIENOS_CAP_OK);
    EQ(aienos_cap_bump_epoch(a.admin, office(&a)), AIENOS_CAP_OK);
    EQ(validate(&a, fresh, 1, 0x10, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_EPOCH);
    /* The office itself was issued in the old epoch. */
    EQ(aienos_cap_bump_epoch(a.admin, office(&a)), AIENOS_CAP_ERR_EPOCH);
    aienos_cap_stop(a.admin, a.view);
}

static void child_lease_cannot_outlive_parent(void) {
    Auth a = boot();
    AienosCapRef parent, out;
    AienosCapMint m = {3, 1, 0x40, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE, 10, NONE,
                       office(&a)};
    EQ(aienos_cap_mint(a.admin, &m, &parent), AIENOS_CAP_OK);
    AienosCapMint forever = {1, 2, 0x40, AIENOS_CAP_RIGHT_READ, 0, parent, parent};
    EQ(aienos_cap_mint(a.admin, &forever, &out), AIENOS_CAP_ERR_AMPLIFY);
    AienosCapMint longer = {1, 2, 0x40, AIENOS_CAP_RIGHT_READ, 11, parent, parent};
    EQ(aienos_cap_mint(a.admin, &longer, &out), AIENOS_CAP_ERR_AMPLIFY);
    AienosCapMint shorter = {1, 2, 0x40, AIENOS_CAP_RIGHT_READ, 10, parent, parent};
    EQ(aienos_cap_mint(a.admin, &shorter, &out), AIENOS_CAP_OK);
    AienosCapMint overflow = {3, 1, 0x41, AIENOS_CAP_RIGHT_READ, 0, NONE, office(&a)};
    EQ(aienos_cap_advance_clock(a.admin, office(&a), 3), AIENOS_CAP_OK);
    overflow.lease_ticks = UINT64_MAX;
    EQ(aienos_cap_mint(a.admin, &overflow, &out), AIENOS_CAP_ERR_OVERFLOW);
    aienos_cap_stop(a.admin, a.view);
}

static void privileged_rights_cannot_be_delegated_and_office_stays(void) {
    Auth a = boot();
    AienosCapRef revoker, out;
    EQ(root_mint(&a, 1, AIENOS_CAP_RES_AUTHORITY,
                 AIENOS_CAP_RIGHT_REVOKE | AIENOS_CAP_RIGHT_DELEGATE, &out),
       AIENOS_CAP_ERR_NOT_DELEGABLE);
    EQ(root_mint(&a, 1, AIENOS_CAP_RES_AUTHORITY, AIENOS_CAP_RIGHT_REVOKE, &revoker),
       AIENOS_CAP_OK);
    EQ(child_mint(&a, revoker, 3, 2, AIENOS_CAP_RES_AUTHORITY, AIENOS_CAP_RIGHT_REVOKE, &out),
       AIENOS_CAP_ERR_NOT_DELEGABLE);
    EQ(aienos_cap_revoke(a.admin, revoker, office(&a)), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(validate(&a, office(&a), 0, AIENOS_CAP_RES_AUTHORITY, AIENOS_CAP_RIGHT_MINT),
       AIENOS_CAP_OK);
    aienos_cap_stop(a.admin, a.view);
}

static void promote_right_cannot_be_delegated(void) {
    Auth a = boot();
    AienosCapRef promoter, out;
    EQ(root_mint(&a, 4, 0x905, AIENOS_CAP_RIGHT_PROMOTE | AIENOS_CAP_RIGHT_DELEGATE, &out),
       AIENOS_CAP_ERR_NOT_DELEGABLE);
    EQ(root_mint(&a, 4, 0x905, AIENOS_CAP_RIGHT_PROMOTE, &promoter), AIENOS_CAP_OK);
    EQ(child_mint(&a, promoter, 4, 5, 0x905, AIENOS_CAP_RIGHT_PROMOTE, &out),
       AIENOS_CAP_ERR_NOT_DELEGABLE);
    EQ(validate(&a, promoter, 4, 0x905, AIENOS_CAP_RIGHT_PROMOTE), AIENOS_CAP_OK);
    EQ(validate(&a, promoter, 9, 0x905, AIENOS_CAP_RIGHT_PROMOTE), AIENOS_CAP_ERR_SUBJECT);
    aienos_cap_stop(a.admin, a.view);
}

static void generation_exhaustion_fails_closed(void) {
    uint64_t next = 0;
    EQ(aienos_cap_generation_advance(UINT64_MAX, &next), AIENOS_CAP_ERR_EXHAUSTED);
    EQ(aienos_cap_generation_advance((uint64_t)UINT32_MAX, &next), AIENOS_CAP_OK);
    EQ(next, (uint64_t)UINT32_MAX + 1);
    Auth a = boot();
    AienosCapRef cap, replacement;
    EQ(root_mint(&a, 1, 0x10, AIENOS_CAP_RIGHT_READ, &cap), AIENOS_CAP_OK);
    EQ(aienos_cap_revoke(a.admin, office(&a), cap), AIENOS_CAP_OK);
    EQ(aienos_cap_force_generation(a.admin, cap.cap_id, UINT64_MAX), AIENOS_CAP_OK);
    EQ(aienos_cap_reclaim(a.admin, office(&a), cap.cap_id), AIENOS_CAP_ERR_EXHAUSTED);
    EQ(validate(&a, cap, 1, 0x10, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_STALE_GEN);
    EQ(root_mint(&a, 1, 0x11, AIENOS_CAP_RIGHT_READ, &replacement), AIENOS_CAP_OK);
    CHECK(replacement.cap_id != cap.cap_id);
    /* A live slot cannot be moved onto a chosen generation. */
    EQ(aienos_cap_force_generation(a.admin, replacement.cap_id, 99), AIENOS_CAP_ERR_STATE);
    /* No start above an exhausted generation exists, so restart refuses
     * rather than reuse one. */
    EQ(aienos_cap_restart(a.admin), AIENOS_CAP_ERR_EXHAUSTED);
    aienos_cap_stop(a.admin, a.view);
}

static void restart_invalidates_and_cognition_cannot_mint(void) {
    Auth a = boot();
    AienosCapRef old, out;
    EQ(root_mint(&a, 1, 0x12, AIENOS_CAP_RIGHT_READ, &old), AIENOS_CAP_OK);
    AienosCapRef old_office = office(&a);
    EQ(aienos_cap_kill(a.admin), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x13, AIENOS_CAP_RIGHT_READ, &out), AIENOS_CAP_ERR_IO);
    EQ(aienos_cap_restart(a.admin), AIENOS_CAP_OK);
    EQ(validate(&a, old, 1, 0x12, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_STALE_GEN);
    CHECK(validate(&a, old_office, 0, AIENOS_CAP_RES_AUTHORITY, AIENOS_CAP_RIGHT_MINT) !=
          AIENOS_CAP_OK);

    uint64_t before = aienos_cap_clock(a.view);
    AienosCapMint m = {1, 1, 1, AIENOS_CAP_RIGHT_READ, 0, NONE, office(&a)};
    uint8_t guess[AIENOS_CAP_TOKEN_LEN];
    memset(guess, 0, sizeof guess);
    EQ(aienos_cap_cognition_mint(a.view, &m, guess), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(aienos_cap_cognition_admin(a.view, 1, office(&a), old), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(aienos_cap_clock(a.view), before);
    EQ(aienos_cap_authorize(a.admin, guess), AIENOS_CAP_ERR_UNAUTHORIZED);
    aienos_cap_stop(a.admin, a.view);
}

/* The old defect: a reclaim moved a slot to boot+1, and the restart started
 * the new table at boot+1 too, so the pre-restart reference validated
 * again once the same slot was minted for the same subject and resource. */
static void reclaimed_reference_stays_dead_after_restart(void) {
    Auth a = boot();
    AienosCapRef first, second, fresh;
    EQ(root_mint(&a, 1, 0x40, AIENOS_CAP_RIGHT_READ, &first), AIENOS_CAP_OK);
    EQ(aienos_cap_revoke(a.admin, office(&a), first), AIENOS_CAP_OK);
    EQ(aienos_cap_reclaim(a.admin, office(&a), first.cap_id), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x40, AIENOS_CAP_RIGHT_READ, &second), AIENOS_CAP_OK);
    EQ(second.cap_id, first.cap_id);
    EQ(second.generation, first.generation + 1);
    EQ(aienos_cap_restart(a.admin), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x40, AIENOS_CAP_RIGHT_READ, &fresh), AIENOS_CAP_OK);
    EQ(fresh.cap_id, second.cap_id);
    CHECK(fresh.generation > second.generation);
    EQ(validate(&a, second, 1, 0x40, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_STALE_GEN);
    EQ(validate(&a, first, 1, 0x40, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_STALE_GEN);
    EQ(validate(&a, fresh, 1, 0x40, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    aienos_cap_stop(a.admin, a.view);
}

static void restarts_and_authorities_never_share_a_start(void) {
    Auth a = boot();
    Auth b = boot();
    AienosCapRef a0 = office(&a);
    AienosCapRef b0 = office(&b);
    CHECK(b0.generation > a0.generation);
    EQ(aienos_cap_restart(a.admin), AIENOS_CAP_OK);
    AienosCapRef a1 = office(&a);
    EQ(aienos_cap_restart(a.admin), AIENOS_CAP_OK);
    AienosCapRef a2 = office(&a);
    CHECK(a1.generation > b0.generation);
    CHECK(a2.generation > a1.generation);
    aienos_cap_stop(a.admin, a.view);
    aienos_cap_stop(b.admin, b.view);
}

static void generation_above_32_bits_is_kept(void) {
    Auth a = boot();
    uint64_t high = ((uint64_t)1 << 32) + 5;
    AienosCapRef cap;
    /* Slot 1 is the first free slot after the office. */
    EQ(aienos_cap_force_generation(a.admin, 1, high), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x50, AIENOS_CAP_RIGHT_READ, &cap), AIENOS_CAP_OK);
    EQ(cap.cap_id, 1u);
    EQ(cap.generation, high);
    EQ(validate(&a, cap, 1, 0x50, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    AienosCapRef truncated = {cap.cap_id, (uint32_t)cap.generation};
    EQ(validate(&a, truncated, 1, 0x50, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_STALE_GEN);
    AienosCapEntry e;
    EQ(aienos_cap_inspect(a.view, cap, &e), AIENOS_CAP_OK);
    EQ(e.generation, high);
    EQ(aienos_cap_restart(a.admin), AIENOS_CAP_OK);
    CHECK(office(&a).generation > high);
    EQ(validate(&a, cap, 1, 0x50, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_STALE_GEN);
    aienos_cap_stop(a.admin, a.view);
}

static void ordinary_capability_cannot_administer_and_depth_stops(void) {
    Auth a = boot();
    AienosCapRef world, cur, out;
    EQ(root_mint(&a, 1, 0x10, AIENOS_CAP_RIGHT_READ, &world), AIENOS_CAP_OK);
    EQ(aienos_cap_revoke(a.admin, world, world), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(aienos_cap_advance_clock(a.admin, world, 1), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(aienos_cap_bump_epoch(a.admin, world), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(aienos_cap_reclaim(a.admin, world, world.cap_id), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(root_mint(&a, 1, 0x20, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE, &cur),
       AIENOS_CAP_OK);
    for (int i = 0; i < 8; i++) {
        EQ(child_mint(&a, cur, 3, 2, 0x20, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE,
                      &cur),
           AIENOS_CAP_OK);
    }
    EQ(child_mint(&a, cur, 3, 2, 0x20, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE, &out),
       AIENOS_CAP_ERR_CHAIN);
    aienos_cap_stop(a.admin, a.view);
}

static void table_fills_then_refuses(void) {
    Auth a = boot();
    AienosCapRef out;
    for (uint32_t i = 1; i < AIENOS_CAP_MAX; i++)
        EQ(root_mint(&a, 1, i, AIENOS_CAP_RIGHT_READ, &out), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x999, AIENOS_CAP_RIGHT_READ, &out), AIENOS_CAP_ERR_FULL);
    aienos_cap_stop(a.admin, a.view);
}

/* ---- Observer: the authority announces its own transitions. ---- */

/* The observer gets AienosCapEntry and nothing else. Its layout is pinned
 * here: 13 fields, 88 bytes, no room for the 32-byte office token. */
_Static_assert(sizeof(AienosCapEntry) == 88, "AienosCapEntry layout changed");

#define REC_MAX 1024

typedef struct {
    uint32_t op;
    int rc;
    int has_entry;
    AienosCapEntry entry;
} Rec;

typedef struct {
    uint32_t n;
    Rec r[REC_MAX];
} Recorder;

static void record(void *ctx, uint32_t op, const AienosCapEntry *entry, int result) {
    Recorder *rec = ctx;
    if (rec->n >= REC_MAX) return;
    Rec *r = &rec->r[rec->n++];
    r->op = op;
    r->rc = result;
    r->has_entry = entry != NULL;
    if (entry) r->entry = *entry;
    else memset(&r->entry, 0, sizeof r->entry);
}

/* The recorded entry is exactly what the view already shows for it. */
static int matches_view(Auth *a, const Rec *r) {
    AienosCapEntry now;
    AienosCapRef ref = {r->entry.cap_id, r->entry.generation};
    if (aienos_cap_inspect(a->view, ref, &now) != AIENOS_CAP_OK) return 0;
    return same_entry(&now, &r->entry);
}

static void observer_sees_each_admin_operation_once(void) {
    Auth a = boot();
    static Recorder rec;
    memset(&rec, 0, sizeof rec);
    EQ(aienos_cap_set_observer(NULL, record, &rec), AIENOS_CAP_ERR_STATE);
    EQ(aienos_cap_set_observer(a.admin, record, &rec), AIENOS_CAP_OK);

    AienosCapRef cap;
    EQ(root_mint(&a, 5, 0x77, AIENOS_CAP_RIGHT_READ, &cap), AIENOS_CAP_OK);
    EQ(rec.n, 1u);
    EQ(rec.r[0].op, AIENOS_CAP_OBS_MINT);
    EQ(rec.r[0].rc, AIENOS_CAP_OK);
    EQ(rec.r[0].has_entry, 1);
    EQ(rec.r[0].entry.cap_id, cap.cap_id);
    EQ(rec.r[0].entry.generation, cap.generation);
    EQ(rec.r[0].entry.state, AIENOS_CAP_STATE_LIVE);
    EQ(rec.r[0].entry.subject, 5u);
    EQ(rec.r[0].entry.resource, 0x77ull);
    EQ(rec.r[0].entry.minted_by_id, 0u);
    CHECK(matches_view(&a, &rec.r[0]));

    EQ(aienos_cap_revoke(a.admin, office(&a), cap), AIENOS_CAP_OK);
    EQ(rec.n, 2u);
    EQ(rec.r[1].op, AIENOS_CAP_OBS_REVOKE);
    EQ(rec.r[1].rc, AIENOS_CAP_OK);
    EQ(rec.r[1].entry.cap_id, cap.cap_id);
    EQ(rec.r[1].entry.state, AIENOS_CAP_STATE_REVOKED);
    CHECK(matches_view(&a, &rec.r[1]));

    EQ(aienos_cap_reclaim(a.admin, office(&a), cap.cap_id), AIENOS_CAP_OK);
    EQ(rec.n, 3u);
    EQ(rec.r[2].op, AIENOS_CAP_OBS_RECLAIM);
    EQ(rec.r[2].rc, AIENOS_CAP_OK);
    EQ(rec.r[2].entry.cap_id, cap.cap_id);
    EQ(rec.r[2].entry.state, AIENOS_CAP_STATE_FREE);
    EQ(rec.r[2].entry.generation, cap.generation + 1);

    EQ(aienos_cap_advance_clock(a.admin, office(&a), 4), AIENOS_CAP_OK);
    EQ(rec.n, 4u);
    EQ(rec.r[3].op, AIENOS_CAP_OBS_CLOCK);
    EQ(rec.r[3].rc, AIENOS_CAP_OK);
    EQ(rec.r[3].entry.cap_id, 0u);
    CHECK(matches_view(&a, &rec.r[3]));

    AienosCapRef before_epoch = office(&a);
    EQ(aienos_cap_bump_epoch(a.admin, office(&a)), AIENOS_CAP_OK);
    EQ(rec.n, 5u);
    EQ(rec.r[4].op, AIENOS_CAP_OBS_EPOCH);
    EQ(rec.r[4].rc, AIENOS_CAP_OK);
    EQ(rec.r[4].entry.cap_id, before_epoch.cap_id);
    EQ(rec.r[4].entry.generation, before_epoch.generation);

    EQ(aienos_cap_kill(a.admin), AIENOS_CAP_OK);
    EQ(rec.n, 6u);
    EQ(rec.r[5].op, AIENOS_CAP_OBS_KILL);
    EQ(rec.r[5].rc, AIENOS_CAP_OK);
    EQ(rec.r[5].has_entry, 0);

    EQ(aienos_cap_restart(a.admin), AIENOS_CAP_OK);
    EQ(rec.n, 7u);
    EQ(rec.r[6].op, AIENOS_CAP_OBS_RESTART);
    EQ(rec.r[6].rc, AIENOS_CAP_OK);
    EQ(rec.r[6].entry.cap_id, 0u);
    EQ(rec.r[6].entry.generation, office(&a).generation);
    CHECK(rec.r[6].entry.generation > before_epoch.generation);
    CHECK(matches_view(&a, &rec.r[6]));

    /* The observer stays set across the restart. */
    EQ(root_mint(&a, 5, 0x78, AIENOS_CAP_RIGHT_READ, &cap), AIENOS_CAP_OK);
    EQ(rec.n, 8u);
    EQ(rec.r[7].op, AIENOS_CAP_OBS_MINT);
    aienos_cap_stop(a.admin, a.view);
}

static void observer_sees_cascade_ancestor_first(void) {
    Auth a = boot();
    static Recorder rec;
    memset(&rec, 0, sizeof rec);
    uint32_t dr = AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE;
    AienosCapRef top, x, y, mid, low, other;
    EQ(root_mint(&a, 1, 0x60, dr, &top), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x61, AIENOS_CAP_RIGHT_READ, &x), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x62, AIENOS_CAP_RIGHT_READ, &y), AIENOS_CAP_OK);
    EQ(child_mint(&a, top, 1, 2, 0x60, dr, &mid), AIENOS_CAP_OK);
    /* Free x's slot so the grandchild lands below its parent's index: the
     * cascade then needs a second pass to reach it. */
    EQ(aienos_cap_revoke(a.admin, office(&a), x), AIENOS_CAP_OK);
    EQ(aienos_cap_reclaim(a.admin, office(&a), x.cap_id), AIENOS_CAP_OK);
    EQ(child_mint(&a, mid, 2, 3, 0x60, AIENOS_CAP_RIGHT_READ, &low), AIENOS_CAP_OK);
    CHECK(low.cap_id < mid.cap_id);
    EQ(root_mint(&a, 1, 0x63, AIENOS_CAP_RIGHT_READ, &other), AIENOS_CAP_OK);

    EQ(aienos_cap_set_observer(a.admin, record, &rec), AIENOS_CAP_OK);
    EQ(aienos_cap_revoke(a.admin, office(&a), top), AIENOS_CAP_OK);
    EQ(rec.n, 3u);
    for (uint32_t i = 0; i < 3; i++) {
        EQ(rec.r[i].op, AIENOS_CAP_OBS_REVOKE);
        EQ(rec.r[i].rc, AIENOS_CAP_OK);
        EQ(rec.r[i].has_entry, 1);
        EQ(rec.r[i].entry.state, AIENOS_CAP_STATE_REVOKED);
        CHECK(matches_view(&a, &rec.r[i]));
    }
    EQ(rec.r[0].entry.cap_id, top.cap_id);
    EQ(rec.r[1].entry.cap_id, mid.cap_id);
    EQ(rec.r[1].entry.parent_id, top.cap_id);
    EQ(rec.r[2].entry.cap_id, low.cap_id);
    EQ(rec.r[2].entry.parent_id, mid.cap_id);
    /* Unrelated entries are not announced. */
    for (uint32_t i = 0; i < rec.n; i++) {
        CHECK(rec.r[i].entry.cap_id != other.cap_id);
        CHECK(rec.r[i].entry.cap_id != y.cap_id);
    }
    aienos_cap_stop(a.admin, a.view);
}

static void observer_sees_refusals_with_their_code(void) {
    Auth a = boot();
    static Recorder rec;
    memset(&rec, 0, sizeof rec);
    AienosCapRef parent, world, out;
    EQ(root_mint(&a, 1, 0x20, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE, &parent),
       AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x21, AIENOS_CAP_RIGHT_READ, &world), AIENOS_CAP_OK);
    EQ(aienos_cap_set_observer(a.admin, record, &rec), AIENOS_CAP_OK);

    EQ(child_mint(&a, parent, 1, 2, 0x20, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE, &out),
       AIENOS_CAP_ERR_AMPLIFY);
    EQ(rec.n, 1u);
    EQ(rec.r[0].op, AIENOS_CAP_OBS_MINT);
    EQ(rec.r[0].rc, AIENOS_CAP_ERR_AMPLIFY);
    EQ(rec.r[0].has_entry, 0);

    EQ(aienos_cap_revoke(a.admin, world, parent), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(aienos_cap_reclaim(a.admin, office(&a), parent.cap_id), AIENOS_CAP_ERR_STATE);
    EQ(aienos_cap_advance_clock(a.admin, world, 1), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(aienos_cap_bump_epoch(a.admin, world), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(rec.n, 5u);
    EQ(rec.r[1].op, AIENOS_CAP_OBS_REVOKE);
    EQ(rec.r[1].rc, AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(rec.r[2].op, AIENOS_CAP_OBS_RECLAIM);
    EQ(rec.r[2].rc, AIENOS_CAP_ERR_STATE);
    EQ(rec.r[3].op, AIENOS_CAP_OBS_CLOCK);
    EQ(rec.r[3].rc, AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(rec.r[4].op, AIENOS_CAP_OBS_EPOCH);
    EQ(rec.r[4].rc, AIENOS_CAP_ERR_UNAUTHORIZED);
    for (uint32_t i = 1; i < 5; i++) EQ(rec.r[i].has_entry, 0);

    /* A dead writer refuses a mint; the refusal is announced too. */
    EQ(aienos_cap_kill(a.admin), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x22, AIENOS_CAP_RIGHT_READ, &out), AIENOS_CAP_ERR_IO);
    EQ(rec.n, 7u);
    EQ(rec.r[6].op, AIENOS_CAP_OBS_MINT);
    EQ(rec.r[6].rc, AIENOS_CAP_ERR_IO);
    aienos_cap_stop(a.admin, a.view);
}

static void observer_is_silent_for_the_view_and_after_clear(void) {
    Auth a = boot();
    static Recorder rec;
    memset(&rec, 0, sizeof rec);
    AienosCapRef cap, out;
    AienosCapEntry e;
    EQ(root_mint(&a, 1, 0x30, AIENOS_CAP_RIGHT_READ, &cap), AIENOS_CAP_OK);
    EQ(aienos_cap_set_observer(a.admin, record, &rec), AIENOS_CAP_OK);

    /* Successful and denied validates, inspect, clock, and cognition's
     * refused attempts: none of them is announced. */
    EQ(validate(&a, cap, 1, 0x30, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    EQ(aienos_cap_validate(a.view, cap, 1, 0x30, AIENOS_CAP_RIGHT_READ, &e), AIENOS_CAP_OK);
    EQ(validate(&a, cap, 9, 0x30, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_SUBJECT);
    EQ(validate(&a, (AienosCapRef){300, 1}, 1, 0x30, AIENOS_CAP_RIGHT_READ),
       AIENOS_CAP_ERR_BOUNDS);
    EQ(aienos_cap_inspect(a.view, cap, &e), AIENOS_CAP_OK);
    (void)aienos_cap_clock(a.view);
    uint8_t guess[AIENOS_CAP_TOKEN_LEN] = {0};
    AienosCapMint m = {1, 1, 1, AIENOS_CAP_RIGHT_READ, 0, NONE, office(&a)};
    EQ(aienos_cap_cognition_mint(a.view, &m, guess), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(aienos_cap_cognition_admin(a.view, 1, office(&a), cap), AIENOS_CAP_ERR_UNAUTHORIZED);
    EQ(rec.n, 0u);

    EQ(aienos_cap_set_observer(a.admin, NULL, &rec), AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, 0x31, AIENOS_CAP_RIGHT_READ, &out), AIENOS_CAP_OK);
    EQ(aienos_cap_revoke(a.admin, office(&a), out), AIENOS_CAP_OK);
    EQ(aienos_cap_reclaim(a.admin, office(&a), out.cap_id), AIENOS_CAP_OK);
    EQ(aienos_cap_advance_clock(a.admin, office(&a), 1), AIENOS_CAP_OK);
    EQ(aienos_cap_bump_epoch(a.admin, office(&a)), AIENOS_CAP_OK);
    EQ(aienos_cap_kill(a.admin), AIENOS_CAP_OK);
    EQ(aienos_cap_restart(a.admin), AIENOS_CAP_OK);
    EQ(rec.n, 0u);
    aienos_cap_stop(a.admin, a.view);
}

/* Seeded random operations against two authorities, one watched and one
 * not. The watched one keeps a shadow table built only from the calls it
 * receives. After every step: both return the same code and slot, and every
 * shadow entry equals what the view shows. This is what ARGUS does with
 * the calls, so it is checked the way ARGUS would use them. */
typedef struct {
    AienosCapEntry e[AIENOS_CAP_MAX];
    int known[AIENOS_CAP_MAX];
    int bad;
} Shadow;

static void shadow_apply(void *ctx, uint32_t op, const AienosCapEntry *entry, int result) {
    Shadow *sh = ctx;
    if (op == AIENOS_CAP_OBS_RESTART && result == AIENOS_CAP_OK) {
        memset(sh->known, 0, sizeof sh->known);
    }
    if (!entry) return;
    if (result != AIENOS_CAP_OK || entry->cap_id >= AIENOS_CAP_MAX) {
        sh->bad = 1;
        return;
    }
    sh->e[entry->cap_id] = *entry;
    sh->known[entry->cap_id] = 1;
}

static uint64_t rng_next(uint64_t *x) {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    return *x;
}

static int random_step(Auth *a, uint64_t *rng, AienosCapRef *pool, uint32_t *pool_n,
                       uint32_t *slot_out) {
    uint32_t kind = (uint32_t)(rng_next(rng) % 100);
    AienosCapRef pick = *pool_n ? pool[rng_next(rng) % *pool_n] : office(a);
    AienosCapRef out = {AIENOS_CAP_PARENT_NONE, 0};
    int rc;
    *slot_out = AIENOS_CAP_PARENT_NONE;
    uint32_t rights = (uint32_t)(rng_next(rng) % 16) | AIENOS_CAP_RIGHT_READ;
    if (kind < 30) {
        AienosCapMint m = {3, (uint32_t)(rng_next(rng) % 4), rng_next(rng) % 4, rights,
                           rng_next(rng) % 3 ? 0 : rng_next(rng) % 20, NONE, office(a)};
        rc = aienos_cap_mint(a->admin, &m, &out);
    } else if (kind < 55) {
        AienosCapEntry pe;
        uint64_t res = 0;
        if (aienos_cap_inspect(a->view, pick, &pe) == AIENOS_CAP_OK) res = pe.resource;
        AienosCapMint m = {1, (uint32_t)(rng_next(rng) % 4), res, rights & ~AIENOS_CAP_RIGHT_WRITE,
                           rng_next(rng) % 20, pick, pick};
        rc = aienos_cap_mint(a->admin, &m, &out);
    } else if (kind < 72) {
        rc = aienos_cap_revoke(a->admin, office(a), pick);
    } else if (kind < 85) {
        rc = aienos_cap_reclaim(a->admin, office(a), pick.cap_id);
    } else if (kind < 93) {
        rc = aienos_cap_advance_clock(a->admin, rng_next(rng) % 8 ? office(a) : pick,
                                      rng_next(rng) % 5);
    } else if (kind < 96) {
        rc = aienos_cap_bump_epoch(a->admin, office(a));
    } else if (kind < 98) {
        rc = aienos_cap_restart(a->admin);
    } else {
        rc = aienos_cap_validate(a->view, pick, 1, 1, AIENOS_CAP_RIGHT_READ, NULL);
    }
    if (rc == AIENOS_CAP_OK && out.cap_id != AIENOS_CAP_PARENT_NONE) {
        *slot_out = out.cap_id;
        if (*pool_n < 512) pool[(*pool_n)++] = out;
        else pool[rng_next(rng) % 512] = out;
    }
    return rc;
}

static int shadow_matches(Auth *a, const Shadow *sh) {
    if (sh->bad) return 0;
    for (uint32_t i = 0; i < AIENOS_CAP_MAX; i++) {
        if (!sh->known[i]) continue;
        AienosCapEntry now;
        AienosCapRef ref = {i, sh->e[i].generation};
        int rc = aienos_cap_inspect(a->view, ref, &now);
        if (sh->e[i].state == AIENOS_CAP_STATE_FREE) {
            if (rc != AIENOS_CAP_ERR_STATE) return 0;
            continue;
        }
        /* The epoch and clock move without touching entries; the entry
         * itself must be exactly what the shadow holds. */
        if (rc != AIENOS_CAP_OK || !same_entry(&now, &sh->e[i])) return 0;
    }
    return 1;
}

static void observer_shadow_matches_table_under_random_operations(uint64_t base_seed,
                                                                  uint32_t seeds,
                                                                  uint32_t steps) {
    static Shadow shadow;
    static AienosCapRef pool_w[512], pool_u[512];
    for (uint32_t s = 0; s < seeds; s++) {
        uint64_t seed = base_seed + s * 0x9e3779b97f4a7c15ull;
        if (seed == 0) seed = 1;
        uint64_t rw = seed, ru = seed;
        uint32_t nw = 0, nu = 0;
        Auth w = boot();
        Auth u = boot();
        memset(&shadow, 0, sizeof shadow);
        AienosCapEntry office_entry;
        aienos_cap_inspect(w.view, office(&w), &office_entry);
        shadow.e[0] = office_entry;
        shadow.known[0] = 1;
        EQ(aienos_cap_set_observer(w.admin, shadow_apply, &shadow), AIENOS_CAP_OK);
        uint32_t same = 1, shadow_ok = 1;
        for (uint32_t i = 0; i < steps; i++) {
            uint32_t sw, su;
            int rcw = random_step(&w, &rw, pool_w, &nw, &sw);
            int rcu = random_step(&u, &ru, pool_u, &nu, &su);
            if (rcw != rcu || sw != su) same = 0;
            if (!shadow_matches(&w, &shadow)) shadow_ok = 0;
            if (!same || !shadow_ok) {
                fprintf(stderr, "seed %llu step %u: rc %d/%d slot %u/%u shadow %u\n",
                        (unsigned long long)seed, i, rcw, rcu, sw, su, shadow_ok);
                break;
            }
        }
        CHECK(same);
        CHECK(shadow_ok);
        aienos_cap_stop(w.admin, w.view);
        aienos_cap_stop(u.admin, u.view);
    }
}


/* Rights are a superset check: a reference holding READ must not pass a
 * request for READ|WRITE. Kills mutant validate_partial_rights (any-overlap
 * instead of all-of). */
static void validate_needs_every_requested_right(void) {
    Auth a = boot();
    AienosCapRef cap;
    EQ(root_mint(&a, 1, 0x60, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_EFFECT, &cap),
       AIENOS_CAP_OK);
    EQ(validate(&a, cap, 1, 0x60, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    EQ(validate(&a, cap, 1, 0x60, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_EFFECT), AIENOS_CAP_OK);
    EQ(validate(&a, cap, 1, 0x60, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE),
       AIENOS_CAP_ERR_RIGHTS);
    EQ(validate(&a, cap, 1, 0x60,
                AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_EFFECT | AIENOS_CAP_RIGHT_DELEGATE),
       AIENOS_CAP_ERR_RIGHTS);
    aienos_cap_stop(a.admin, a.view);
}

/* A lease of n ticks is good for clock values below start+n and dead at
 * exactly start+n. Kills mutant lease_expiry_off_by_one (> instead of >=). */
static void lease_ends_exactly_at_expiry_tick(void) {
    Auth a = boot();
    AienosCapRef leased;
    AienosCapMint m = {3, 1, 0x70, AIENOS_CAP_RIGHT_READ, 5, NONE, office(&a)};
    EQ(aienos_cap_mint(a.admin, &m, &leased), AIENOS_CAP_OK);
    EQ(aienos_cap_advance_clock(a.admin, office(&a), 4), AIENOS_CAP_OK);
    EQ(validate(&a, leased, 1, 0x70, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    EQ(aienos_cap_advance_clock(a.admin, office(&a), 1), AIENOS_CAP_OK);
    EQ(aienos_cap_clock(a.view), 5u);
    EQ(validate(&a, leased, 1, 0x70, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_EXPIRED);
    aienos_cap_stop(a.admin, a.view);
}

/* Fault injection for the chain walk in validate.
 *
 * Through the public calls a live child of a non-live parent cannot exist:
 * revoke cascades to every descendant, and reclaim and force_generation
 * only touch non-live slots. So the "parent must be LIVE" step in validate
 * is defense in depth, and only a corrupted table can reach it. This test
 * corrupts the table on purpose: it flips the parent's state with no
 * cascade and checks validate still refuses the child with CHAIN.
 *
 * It reaches the table through a mirror of the private layout in
 * aienos_capability.c (CapShared/CapState). The mirror is checked against
 * the public view before anything is written; any layout drift fails this
 * test loudly instead of poking the wrong bytes. Kills mutant
 * validate_parent_live. */
typedef struct {
    uint64_t boot_gen;
    uint64_t epoch;
    uint64_t clock;
    AienosCapEntry entries[AIENOS_CAP_MAX];
    bool delivered[AIENOS_CAP_MAX];
    bool writer_alive;
} MirrorCapState;

typedef struct {
    pthread_mutex_t state_lock;
    MirrorCapState state;
} MirrorCapShared;

static void validate_refuses_child_of_non_live_parent_in_corrupt_table(void) {
    Auth a = boot();
    AienosCapRef parent, child;
    AienosCapEntry pe, ce, oe;
    EQ(root_mint(&a, 1, 0x80, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE, &parent),
       AIENOS_CAP_OK);
    EQ(child_mint(&a, parent, 1, 2, 0x80, AIENOS_CAP_RIGHT_READ, &child), AIENOS_CAP_OK);
    EQ(validate(&a, child, 2, 0x80, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    EQ(aienos_cap_inspect(a.view, parent, &pe), AIENOS_CAP_OK);
    EQ(aienos_cap_inspect(a.view, child, &ce), AIENOS_CAP_OK);
    EQ(aienos_cap_inspect(a.view, office(&a), &oe), AIENOS_CAP_OK);

    MirrorCapShared *sh = *(MirrorCapShared *const *)a.admin;
    int layout_ok = sh != NULL && sh->state.epoch == 1 && sh->state.clock == 0 &&
                    sh->state.writer_alive && sh->state.delivered[child.cap_id] &&
                    same_entry(&sh->state.entries[0], &oe) &&
                    same_entry(&sh->state.entries[parent.cap_id], &pe) &&
                    same_entry(&sh->state.entries[child.cap_id], &ce);
    CHECK(layout_ok);
    if (layout_ok) {
        AienosCapEntry *p = &sh->state.entries[parent.cap_id];
        p->state = AIENOS_CAP_STATE_REVOKED; /* no cascade: child stays LIVE */
        EQ(aienos_cap_inspect(a.view, child, &ce), AIENOS_CAP_OK);
        EQ(ce.state, AIENOS_CAP_STATE_LIVE);
        EQ(validate(&a, child, 2, 0x80, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_CHAIN);
        p->state = AIENOS_CAP_STATE_FREE;
        EQ(validate(&a, child, 2, 0x80, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_CHAIN);
        p->state = AIENOS_CAP_STATE_LIVE;
        EQ(validate(&a, child, 2, 0x80, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    }
    aienos_cap_stop(a.admin, a.view);
}

/* #266: a privileged right is an authority-office right. A capability that
 * carries privileged rights on another resource (the operator CONTROL
 * resource) is honored by validate for that resource, but never accepted by
 * the authority operations. */
static void control_resource_capability_cannot_operate_the_authority(void) {
    Auth a = boot();
    const uint64_t control = 0xC0DEull;
    AienosCapRef halt, victim, ok;
    const uint32_t all_priv = AIENOS_CAP_RIGHT_PRIVILEGED & ~AIENOS_CAP_RIGHT_PROMOTE;
    EQ(root_mint(&a, 1, control, AIENOS_CAP_RIGHT_EPOCH | AIENOS_CAP_RIGHT_READ, &halt),
       AIENOS_CAP_OK);
    EQ(root_mint(&a, 1, control, all_priv, &ok), AIENOS_CAP_OK);
    EQ(root_mint(&a, 2, 0x77, AIENOS_CAP_RIGHT_READ, &victim), AIENOS_CAP_OK);
    /* Negative: no authority operation accepts a control-resource capability. */
    EQ(aienos_cap_bump_epoch(a.admin, halt), AIENOS_CAP_ERR_RESOURCE);
    EQ(aienos_cap_bump_epoch(a.admin, ok), AIENOS_CAP_ERR_RESOURCE);
    EQ(aienos_cap_advance_clock(a.admin, ok, 1), AIENOS_CAP_ERR_RESOURCE);
    EQ(aienos_cap_revoke(a.admin, ok, victim), AIENOS_CAP_ERR_RESOURCE);
    EQ(aienos_cap_reclaim(a.admin, ok, victim.cap_id), AIENOS_CAP_ERR_RESOURCE);
    AienosCapMint m = {3, 2, 0x78, AIENOS_CAP_RIGHT_READ, 0, NONE, ok};
    AienosCapRef out;
    EQ(aienos_cap_mint(a.admin, &m, &out), AIENOS_CAP_ERR_RESOURCE);
    /* Nothing moved: victim still live, epoch unchanged (office still works). */
    EQ(validate(&a, victim, 2, 0x77, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    /* Regression: operator stop/status/resume checks on CONTROL still pass. */
    EQ(validate(&a, halt, 1, control, AIENOS_CAP_RIGHT_EPOCH), AIENOS_CAP_OK);
    EQ(validate(&a, halt, 1, control, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_OK);
    EQ(validate(&a, ok, 1, control, AIENOS_CAP_RIGHT_CLOCK), AIENOS_CAP_OK);
    /* Regression: the real office still performs every operation. */
    EQ(aienos_cap_advance_clock(a.admin, office(&a), 1), AIENOS_CAP_OK);
    EQ(aienos_cap_revoke(a.admin, office(&a), victim), AIENOS_CAP_OK);
    EQ(aienos_cap_reclaim(a.admin, office(&a), victim.cap_id), AIENOS_CAP_OK);
    /* Authority-resource privileged delegate-free caps still work too. */
    AienosCapRef reclaimer;
    EQ(root_mint(&a, 1, AIENOS_CAP_RES_AUTHORITY, AIENOS_CAP_RIGHT_CLOCK, &reclaimer),
       AIENOS_CAP_OK);
    EQ(aienos_cap_advance_clock(a.admin, reclaimer, 1), AIENOS_CAP_OK);
    EQ(aienos_cap_bump_epoch(a.admin, office(&a)), AIENOS_CAP_OK);
    aienos_cap_stop(a.admin, a.view);
}

int main(int argc, char **argv) {
    uint64_t base_seed = argc > 1 ? strtoull(argv[1], NULL, 0) : 0x5eedull;
    control_resource_capability_cannot_operate_the_authority();
    high_half_resource_is_kept();
    forged_stale_subject_resource_and_rights_fail_closed();
    amplification_lease_epoch_and_revoked_ancestor_fail();
    child_lease_cannot_outlive_parent();
    privileged_rights_cannot_be_delegated_and_office_stays();
    promote_right_cannot_be_delegated();
    generation_exhaustion_fails_closed();
    restart_invalidates_and_cognition_cannot_mint();
    reclaimed_reference_stays_dead_after_restart();
    restarts_and_authorities_never_share_a_start();
    generation_above_32_bits_is_kept();
    ordinary_capability_cannot_administer_and_depth_stops();
    table_fills_then_refuses();
    validate_needs_every_requested_right();
    lease_ends_exactly_at_expiry_tick();
    validate_refuses_child_of_non_live_parent_in_corrupt_table();
    observer_sees_each_admin_operation_once();
    observer_sees_cascade_ancestor_first();
    observer_sees_refusals_with_their_code();
    observer_is_silent_for_the_view_and_after_clear();
    observer_shadow_matches_table_under_random_operations(base_seed, 20, 5000);
    printf("capability: seed %llu\n", (unsigned long long)base_seed);
    printf("capability: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
