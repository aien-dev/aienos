/*
 * capability_test.c -- rules of the native capability authority.
 *
 * Each case names the rule it holds. A failure prints the line and the
 * process exits nonzero.
 */
#include "../aienos_capability.h"

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

static void generation_wrap_restarts_and_cognition_cannot_mint(void) {
    uint32_t next = 0;
    EQ(aienos_cap_generation_advance(UINT32_MAX, &next), AIENOS_CAP_ERR_EXHAUSTED);
    Auth a = boot();
    AienosCapRef cap, replacement, old, out;
    EQ(root_mint(&a, 1, 0x10, AIENOS_CAP_RIGHT_READ, &cap), AIENOS_CAP_OK);
    EQ(aienos_cap_revoke(a.admin, office(&a), cap), AIENOS_CAP_OK);
    EQ(aienos_cap_force_generation(a.admin, cap.cap_id, UINT32_MAX), AIENOS_CAP_OK);
    EQ(aienos_cap_reclaim(a.admin, office(&a), cap.cap_id), AIENOS_CAP_ERR_EXHAUSTED);
    EQ(validate(&a, cap, 1, 0x10, AIENOS_CAP_RIGHT_READ), AIENOS_CAP_ERR_STALE_GEN);
    EQ(root_mint(&a, 1, 0x11, AIENOS_CAP_RIGHT_READ, &replacement), AIENOS_CAP_OK);
    CHECK(replacement.cap_id != cap.cap_id);
    /* A live slot cannot be moved onto a chosen generation. */
    EQ(aienos_cap_force_generation(a.admin, replacement.cap_id, 99), AIENOS_CAP_ERR_STATE);

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

int main(void) {
    high_half_resource_is_kept();
    forged_stale_subject_resource_and_rights_fail_closed();
    amplification_lease_epoch_and_revoked_ancestor_fail();
    child_lease_cannot_outlive_parent();
    privileged_rights_cannot_be_delegated_and_office_stays();
    promote_right_cannot_be_delegated();
    generation_wrap_restarts_and_cognition_cannot_mint();
    ordinary_capability_cannot_administer_and_depth_stops();
    table_fills_then_refuses();
    printf("capability: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
