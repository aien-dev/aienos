/*
 * aienos_capability.c -- native AIENOS capability authority.
 *
 * AienosCapView can check a reference. It cannot mint, revoke, reclaim, move
 * the clock, or change the epoch. Those operations take AienosCapAdmin, and
 * they refuse to run unless the caller presents a live reference holding the
 * matching office right. The office token is held beside the table, never in
 * it.
 */
#include "aienos_capability.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t boot_gen;
    uint64_t epoch;
    uint64_t clock;
    AienosCapEntry entries[AIENOS_CAP_MAX];
    bool delivered[AIENOS_CAP_MAX];
    bool writer_alive;
} CapState;

typedef struct {
    pthread_mutex_t state_lock;
    CapState state;
    pthread_mutex_t token_lock;
    uint8_t token[AIENOS_CAP_TOKEN_LEN];
    atomic_uint holders;
} CapShared;

struct AienosCapAdmin {
    CapShared *shared;
};

struct AienosCapView {
    CapShared *shared;
};

/* A later authority starts higher, so a reference from a stopped authority
 * cannot validate against the new one. */
static atomic_uint next_boot_gen = 1;

static int take_boot_gen(uint32_t *out) {
    unsigned cur = atomic_load_explicit(&next_boot_gen, memory_order_relaxed);
    for (;;) {
        if (cur == 0 || cur == UINT32_MAX) return AIENOS_CAP_ERR_EXHAUSTED;
        if (atomic_compare_exchange_weak_explicit(&next_boot_gen, &cur, cur + 1,
                                                  memory_order_acq_rel,
                                                  memory_order_relaxed)) {
            *out = cur;
            return AIENOS_CAP_OK;
        }
    }
}

int aienos_cap_generation_advance(uint32_t generation, uint32_t *out) {
    if (generation == UINT32_MAX) return AIENOS_CAP_ERR_EXHAUSTED;
    if (out) *out = generation + 1;
    return AIENOS_CAP_OK;
}

static int add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (b > UINT64_MAX - a) return AIENOS_CAP_ERR_OVERFLOW;
    *out = a + b;
    return AIENOS_CAP_OK;
}

static bool expired(const CapState *s, const AienosCapEntry *e) {
    return e->lease_expiry != 0 && s->clock >= e->lease_expiry;
}

static int bootstrap(CapState *s, uint32_t boot_gen) {
    if (boot_gen == 0 || boot_gen == UINT32_MAX) return AIENOS_CAP_ERR_EXHAUSTED;
    memset(s, 0, sizeof *s);
    s->boot_gen = boot_gen;
    s->epoch = 1;
    s->clock = 0;
    s->writer_alive = true;
    for (uint32_t i = 0; i < AIENOS_CAP_MAX; i++) {
        s->entries[i].cap_id = i;
        s->entries[i].generation = boot_gen;
        s->entries[i].state = AIENOS_CAP_STATE_FREE;
        s->entries[i].parent_id = AIENOS_CAP_PARENT_NONE;
    }
    AienosCapEntry *office = &s->entries[0];
    office->state = AIENOS_CAP_STATE_LIVE;
    office->resource = AIENOS_CAP_RES_AUTHORITY;
    office->rights = AIENOS_CAP_RIGHT_PRIVILEGED;
    office->epoch = 1;
    s->delivered[0] = true;
    return AIENOS_CAP_OK;
}

static int state_inspect(const CapState *s, AienosCapRef cap, AienosCapEntry *out) {
    if (cap.cap_id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_BOUNDS;
    const AienosCapEntry *e = &s->entries[cap.cap_id];
    if (e->generation != cap.generation) return AIENOS_CAP_ERR_STALE_GEN;
    if (e->state == AIENOS_CAP_STATE_FREE) return AIENOS_CAP_ERR_STATE;
    *out = *e;
    return AIENOS_CAP_OK;
}

static int state_validate(const CapState *s, AienosCapRef cap, uint32_t subject,
                          uint64_t resource, uint32_t rights, AienosCapEntry *out) {
    if (cap.cap_id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_BOUNDS;
    AienosCapEntry chain[AIENOS_CAP_MAX_DEPTH + 1];
    uint32_t n = 0;
    uint32_t id = cap.cap_id;
    while (id != AIENOS_CAP_PARENT_NONE) {
        if (n > AIENOS_CAP_MAX_DEPTH || id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_CHAIN;
        chain[n] = s->entries[id];
        id = chain[n].parent_id;
        n++;
    }
    const AienosCapEntry *e = &chain[0];
    if (e->generation != cap.generation) return AIENOS_CAP_ERR_STALE_GEN;
    if (e->state != AIENOS_CAP_STATE_LIVE) return AIENOS_CAP_ERR_REVOKED;
    if (e->epoch != s->epoch) return AIENOS_CAP_ERR_EPOCH;
    if (expired(s, e)) return AIENOS_CAP_ERR_EXPIRED;
    for (uint32_t i = 1; i < n; i++) {
        const AienosCapEntry *parent = &chain[i];
        const AienosCapEntry *child = &chain[i - 1];
        if (parent->generation != child->parent_generation) return AIENOS_CAP_ERR_CHAIN;
        if (parent->state != AIENOS_CAP_STATE_LIVE) return AIENOS_CAP_ERR_CHAIN;
        if (parent->epoch != s->epoch) return AIENOS_CAP_ERR_CHAIN;
        if (expired(s, parent)) return AIENOS_CAP_ERR_CHAIN;
    }
    if (e->subject != subject) return AIENOS_CAP_ERR_SUBJECT;
    if (e->resource != resource) return AIENOS_CAP_ERR_RESOURCE;
    if ((e->rights & rights) != rights) return AIENOS_CAP_ERR_RIGHTS;
    if (out) *out = *e;
    return AIENOS_CAP_OK;
}

static int chain_ok(const CapState *s, uint32_t entry_id) {
    uint32_t depth = 0;
    for (;;) {
        const AienosCapEntry *e = &s->entries[entry_id];
        if (e->parent_id == AIENOS_CAP_PARENT_NONE) return AIENOS_CAP_OK;
        depth++;
        if (depth > AIENOS_CAP_MAX_DEPTH) return AIENOS_CAP_ERR_CHAIN;
        if (e->parent_id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_CHAIN;
        const AienosCapEntry *parent = &s->entries[e->parent_id];
        if (parent->generation != e->parent_generation ||
            parent->state != AIENOS_CAP_STATE_LIVE)
            return AIENOS_CAP_ERR_CHAIN;
        entry_id = e->parent_id;
    }
}

static uint32_t ancestor_hops(const CapState *s, uint32_t entry_id) {
    uint32_t hops = 0;
    for (;;) {
        const AienosCapEntry *e = &s->entries[entry_id];
        if (e->parent_id == AIENOS_CAP_PARENT_NONE || hops > AIENOS_CAP_MAX_DEPTH) return hops;
        if (e->parent_id >= AIENOS_CAP_MAX) return AIENOS_CAP_MAX_DEPTH + 1;
        hops++;
        entry_id = e->parent_id;
    }
}

/* The caller must present a delivered, live, current reference that holds
 * every right in `need`. */
static int auth_use(const CapState *s, AienosCapRef authority, uint32_t need, uint32_t *index) {
    if (authority.cap_id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_UNAUTHORIZED;
    uint32_t i = authority.cap_id;
    if (!s->delivered[i]) return AIENOS_CAP_ERR_UNAUTHORIZED;
    const AienosCapEntry *e = &s->entries[i];
    if (e->generation != authority.generation) return AIENOS_CAP_ERR_STALE_GEN;
    if (e->state != AIENOS_CAP_STATE_LIVE) return AIENOS_CAP_ERR_REVOKED;
    if (e->epoch != s->epoch) return AIENOS_CAP_ERR_EPOCH;
    if (expired(s, e)) return AIENOS_CAP_ERR_EXPIRED;
    int rc = chain_ok(s, i);
    if (rc != AIENOS_CAP_OK) return rc;
    if ((e->rights & need) != need) return AIENOS_CAP_ERR_UNAUTHORIZED;
    *index = i;
    return AIENOS_CAP_OK;
}

static int lease_expiry(const CapState *s, uint64_t ticks, uint64_t *out) {
    if (ticks == 0) {
        *out = 0;
        return AIENOS_CAP_OK;
    }
    return add_u64(s->clock, ticks, out);
}

static int state_mint(CapState *s, const AienosCapMint *r, AienosCapRef *out) {
    if (!s->writer_alive) return AIENOS_CAP_ERR_IO;
    if (r->rights == 0 || (r->rights & ~AIENOS_CAP_RIGHT_KNOWN) != 0) return AIENOS_CAP_ERR_RIGHTS;
    if ((r->rights & AIENOS_CAP_RIGHT_PRIVILEGED) && (r->rights & AIENOS_CAP_RIGHT_DELEGATE))
        return AIENOS_CAP_ERR_NOT_DELEGABLE;

    uint32_t auth_index;
    int rc;
    if (r->parent.cap_id == AIENOS_CAP_PARENT_NONE) {
        rc = auth_use(s, r->authority, AIENOS_CAP_RIGHT_MINT, &auth_index);
        if (rc != AIENOS_CAP_OK) return rc;
        const AienosCapEntry *auth = &s->entries[auth_index];
        if ((r->rights & AIENOS_CAP_RIGHT_PRIVILEGED) & ~auth->rights)
            return AIENOS_CAP_ERR_UNAUTHORIZED;
    } else {
        if (r->authority.cap_id != r->parent.cap_id ||
            r->authority.generation != r->parent.generation)
            return AIENOS_CAP_ERR_UNAUTHORIZED;
        rc = auth_use(s, r->authority, 0, &auth_index);
        if (rc != AIENOS_CAP_OK) return rc;
        const AienosCapEntry *auth = &s->entries[auth_index];
        if (!(auth->rights & AIENOS_CAP_RIGHT_DELEGATE)) return AIENOS_CAP_ERR_NOT_DELEGABLE;
        if (r->parent.cap_id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_BOUNDS;
        if (auth->resource != r->resource) return AIENOS_CAP_ERR_RESOURCE;
        if (r->rights & ~auth->rights) return AIENOS_CAP_ERR_AMPLIFY;
        if (r->rights & AIENOS_CAP_RIGHT_PRIVILEGED) return AIENOS_CAP_ERR_NOT_DELEGABLE;
        if (ancestor_hops(s, r->parent.cap_id) >= AIENOS_CAP_MAX_DEPTH)
            return AIENOS_CAP_ERR_CHAIN;
        if (auth->lease_expiry != 0) {
            uint64_t child;
            rc = lease_expiry(s, r->lease_ticks, &child);
            if (rc != AIENOS_CAP_OK) return rc;
            if (child == 0 || child > auth->lease_expiry) return AIENOS_CAP_ERR_AMPLIFY;
        }
    }
    uint64_t expiry;
    rc = lease_expiry(s, r->lease_ticks, &expiry);
    if (rc != AIENOS_CAP_OK) return rc;
    const AienosCapEntry auth = s->entries[auth_index];
    bool saw_exhausted = false;
    for (uint32_t i = 0; i < AIENOS_CAP_MAX; i++) {
        AienosCapEntry *e = &s->entries[i];
        if (e->state != AIENOS_CAP_STATE_FREE) continue;
        if (e->generation == UINT32_MAX) {
            saw_exhausted = true;
            continue;
        }
        e->state = AIENOS_CAP_STATE_LIVE;
        e->issuer = r->issuer;
        e->subject = r->subject;
        e->resource = r->resource;
        e->rights = r->rights;
        e->epoch = s->epoch;
        e->lease_expiry = expiry;
        e->parent_id = r->parent.cap_id;
        e->parent_generation =
            r->parent.cap_id == AIENOS_CAP_PARENT_NONE ? 0 : r->parent.generation;
        e->minted_by_id = auth.cap_id;
        e->minted_by_generation = auth.generation;
        s->delivered[i] = true;
        if (out) *out = (AienosCapRef){e->cap_id, e->generation};
        return AIENOS_CAP_OK;
    }
    return saw_exhausted ? AIENOS_CAP_ERR_EXHAUSTED : AIENOS_CAP_ERR_FULL;
}

static void cascade_revoke(CapState *s) {
    for (uint32_t guard = 0; guard < AIENOS_CAP_MAX; guard++) {
        bool changed = false;
        for (uint32_t i = 0; i < AIENOS_CAP_MAX; i++) {
            AienosCapEntry *e = &s->entries[i];
            uint32_t pid = e->parent_id;
            if (e->state != AIENOS_CAP_STATE_LIVE || pid == AIENOS_CAP_PARENT_NONE) continue;
            if (pid >= AIENOS_CAP_MAX) continue;
            const AienosCapEntry *parent = &s->entries[pid];
            if (parent->generation == e->parent_generation &&
                parent->state == AIENOS_CAP_STATE_REVOKED) {
                e->state = AIENOS_CAP_STATE_REVOKED;
                changed = true;
            }
        }
        if (!changed) break;
    }
}

static int state_revoke(CapState *s, AienosCapRef authority, AienosCapRef target) {
    if (!s->writer_alive) return AIENOS_CAP_ERR_IO;
    uint32_t auth_index;
    int rc = auth_use(s, authority, AIENOS_CAP_RIGHT_REVOKE, &auth_index);
    if (rc != AIENOS_CAP_OK) return rc;
    if (target.cap_id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_BOUNDS;
    uint32_t auth_rights = s->entries[auth_index].rights;
    AienosCapEntry *e = &s->entries[target.cap_id];
    if (e->generation != target.generation) return AIENOS_CAP_ERR_STALE_GEN;
    if (e->state != AIENOS_CAP_STATE_LIVE) return AIENOS_CAP_ERR_STATE;
    if ((e->rights & AIENOS_CAP_RIGHT_PRIVILEGED) & ~auth_rights) return AIENOS_CAP_ERR_UNAUTHORIZED;
    e->state = AIENOS_CAP_STATE_REVOKED;
    cascade_revoke(s);
    return AIENOS_CAP_OK;
}

static int state_reclaim(CapState *s, AienosCapRef authority, uint32_t cap_id) {
    if (!s->writer_alive) return AIENOS_CAP_ERR_IO;
    uint32_t auth_index;
    int rc = auth_use(s, authority, AIENOS_CAP_RIGHT_RECLAIM, &auth_index);
    if (rc != AIENOS_CAP_OK) return rc;
    if (cap_id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_BOUNDS;
    AienosCapEntry *e = &s->entries[cap_id];
    if (e->state != AIENOS_CAP_STATE_REVOKED) return AIENOS_CAP_ERR_STATE;
    uint32_t next;
    rc = aienos_cap_generation_advance(e->generation, &next);
    if (rc != AIENOS_CAP_OK) return rc;
    e->generation = next;
    e->state = AIENOS_CAP_STATE_FREE;
    e->rights = 0;
    e->lease_expiry = 0;
    e->parent_id = AIENOS_CAP_PARENT_NONE;
    e->parent_generation = 0;
    s->delivered[cap_id] = false;
    return AIENOS_CAP_OK;
}

static int state_advance_clock(CapState *s, AienosCapRef authority, uint64_t ticks) {
    if (!s->writer_alive) return AIENOS_CAP_ERR_IO;
    uint32_t idx;
    int rc = auth_use(s, authority, AIENOS_CAP_RIGHT_CLOCK, &idx);
    if (rc != AIENOS_CAP_OK) return rc;
    return add_u64(s->clock, ticks, &s->clock);
}

static int state_bump_epoch(CapState *s, AienosCapRef authority) {
    if (!s->writer_alive) return AIENOS_CAP_ERR_IO;
    uint32_t idx;
    int rc = auth_use(s, authority, AIENOS_CAP_RIGHT_EPOCH, &idx);
    if (rc != AIENOS_CAP_OK) return rc;
    return add_u64(s->epoch, 1, &s->epoch);
}

/* Test seam. Puts a free or revoked slot on a chosen generation so the
 * exhaustion rule can be shown without four billion reclamations. Refuses a
 * live slot, so it cannot mint a forged generation. */
static int state_force_generation(CapState *s, uint32_t cap_id, uint32_t generation) {
    if (cap_id >= AIENOS_CAP_MAX) return AIENOS_CAP_ERR_BOUNDS;
    AienosCapEntry *e = &s->entries[cap_id];
    if (e->state == AIENOS_CAP_STATE_LIVE) return AIENOS_CAP_ERR_STATE;
    if (generation == 0) return AIENOS_CAP_ERR_EXHAUSTED;
    e->generation = generation;
    return AIENOS_CAP_OK;
}

static bool fill_token(uint8_t token[AIENOS_CAP_TOKEN_LEN]) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return false;
    size_t got = fread(token, 1, AIENOS_CAP_TOKEN_LEN, f);
    fclose(f);
    return got == AIENOS_CAP_TOKEN_LEN;
}

static void release(CapShared *shared) {
    if (atomic_fetch_sub_explicit(&shared->holders, 1, memory_order_acq_rel) == 1) {
        pthread_mutex_destroy(&shared->state_lock);
        pthread_mutex_destroy(&shared->token_lock);
        memset(shared->token, 0, sizeof shared->token);
        free(shared);
    }
}

#define LOCKED(shared, expr)                                  \
    ({                                                        \
        pthread_mutex_lock(&(shared)->state_lock);            \
        __typeof__(expr) locked_rc_ = (expr);                 \
        pthread_mutex_unlock(&(shared)->state_lock);          \
        locked_rc_;                                           \
    })

int aienos_cap_start(AienosCapAdmin **admin_out, AienosCapView **view_out) {
    if (!admin_out || !view_out) return AIENOS_CAP_ERR_STATE;
    uint32_t boot;
    int rc = take_boot_gen(&boot);
    if (rc != AIENOS_CAP_OK) return rc;
    CapShared *shared = calloc(1, sizeof *shared);
    AienosCapAdmin *admin = calloc(1, sizeof *admin);
    AienosCapView *view = calloc(1, sizeof *view);
    if (!shared || !admin || !view) {
        free(shared);
        free(admin);
        free(view);
        return AIENOS_CAP_ERR_IO;
    }
    rc = bootstrap(&shared->state, boot);
    if (rc == AIENOS_CAP_OK && !fill_token(shared->token)) rc = AIENOS_CAP_ERR_IO;
    if (rc != AIENOS_CAP_OK) {
        free(shared);
        free(admin);
        free(view);
        return rc;
    }
    pthread_mutex_init(&shared->state_lock, NULL);
    pthread_mutex_init(&shared->token_lock, NULL);
    atomic_init(&shared->holders, 2);
    admin->shared = shared;
    view->shared = shared;
    *admin_out = admin;
    *view_out = view;
    return AIENOS_CAP_OK;
}

void aienos_cap_stop(AienosCapAdmin *admin, AienosCapView *view) {
    if (admin) {
        release(admin->shared);
        free(admin);
    }
    if (view) {
        release(view->shared);
        free(view);
    }
}

int aienos_cap_office(const AienosCapAdmin *admin, AienosCapRef *out) {
    if (!admin) return AIENOS_CAP_ERR_STATE;
    CapShared *sh = admin->shared;
    pthread_mutex_lock(&sh->state_lock);
    AienosCapRef office = {0, sh->state.entries[0].generation};
    pthread_mutex_unlock(&sh->state_lock);
    if (out) *out = office;
    return AIENOS_CAP_OK;
}

int aienos_cap_mint(AienosCapAdmin *admin, const AienosCapMint *request, AienosCapRef *out) {
    if (!admin || !request) return AIENOS_CAP_ERR_STATE;
    AienosCapMint r = *request;
    AienosCapRef got;
    int rc = LOCKED(admin->shared, state_mint(&admin->shared->state, &r, &got));
    if (rc == AIENOS_CAP_OK && out) *out = got;
    return rc;
}

int aienos_cap_revoke(AienosCapAdmin *admin, AienosCapRef authority, AienosCapRef target) {
    if (!admin) return AIENOS_CAP_ERR_STATE;
    return LOCKED(admin->shared, state_revoke(&admin->shared->state, authority, target));
}

int aienos_cap_reclaim(AienosCapAdmin *admin, AienosCapRef authority, uint32_t cap_id) {
    if (!admin) return AIENOS_CAP_ERR_STATE;
    return LOCKED(admin->shared, state_reclaim(&admin->shared->state, authority, cap_id));
}

int aienos_cap_advance_clock(AienosCapAdmin *admin, AienosCapRef authority, uint64_t ticks) {
    if (!admin) return AIENOS_CAP_ERR_STATE;
    return LOCKED(admin->shared, state_advance_clock(&admin->shared->state, authority, ticks));
}

int aienos_cap_bump_epoch(AienosCapAdmin *admin, AienosCapRef authority) {
    if (!admin) return AIENOS_CAP_ERR_STATE;
    return LOCKED(admin->shared, state_bump_epoch(&admin->shared->state, authority));
}

int aienos_cap_kill(AienosCapAdmin *admin) {
    if (!admin) return AIENOS_CAP_ERR_STATE;
    CapShared *sh = admin->shared;
    pthread_mutex_lock(&sh->state_lock);
    sh->state.writer_alive = false;
    pthread_mutex_unlock(&sh->state_lock);
    return AIENOS_CAP_OK;
}

/* Replace the table with the next boot generation. Outstanding references
 * fail against the new table. The office token is replaced. */
int aienos_cap_restart(AienosCapAdmin *admin) {
    if (!admin) return AIENOS_CAP_ERR_STATE;
    uint32_t boot;
    int rc = take_boot_gen(&boot);
    if (rc != AIENOS_CAP_OK) return rc;
    CapState *fresh = malloc(sizeof *fresh);
    if (!fresh) return AIENOS_CAP_ERR_IO;
    rc = bootstrap(fresh, boot);
    uint8_t token[AIENOS_CAP_TOKEN_LEN];
    if (rc == AIENOS_CAP_OK && !fill_token(token)) rc = AIENOS_CAP_ERR_IO;
    if (rc != AIENOS_CAP_OK) {
        free(fresh);
        return rc;
    }
    CapShared *sh = admin->shared;
    pthread_mutex_lock(&sh->state_lock);
    sh->state = *fresh;
    pthread_mutex_unlock(&sh->state_lock);
    free(fresh);
    pthread_mutex_lock(&sh->token_lock);
    memcpy(sh->token, token, sizeof token);
    pthread_mutex_unlock(&sh->token_lock);
    memset(token, 0, sizeof token);
    return AIENOS_CAP_OK;
}

int aienos_cap_validate(const AienosCapView *view, AienosCapRef cap, uint32_t subject,
                       uint64_t resource, uint32_t rights, AienosCapEntry *out) {
    if (!view) return AIENOS_CAP_ERR_STATE;
    AienosCapEntry e;
    int rc = LOCKED(view->shared,
                    state_validate(&view->shared->state, cap, subject, resource, rights, &e));
    if (rc == AIENOS_CAP_OK && out) *out = e;
    return rc;
}

int aienos_cap_inspect(const AienosCapView *view, AienosCapRef cap, AienosCapEntry *out) {
    if (!view) return AIENOS_CAP_ERR_STATE;
    AienosCapEntry e;
    int rc = LOCKED(view->shared, state_inspect(&view->shared->state, cap, &e));
    if (rc == AIENOS_CAP_OK && out) *out = e;
    return rc;
}

uint64_t aienos_cap_clock(const AienosCapView *view) {
    if (!view) return 0;
    CapShared *sh = view->shared;
    pthread_mutex_lock(&sh->state_lock);
    uint64_t clock = sh->state.clock;
    pthread_mutex_unlock(&sh->state_lock);
    return clock;
}

/* Cognition's mint attempt. The view has no office token, so this cannot
 * change the table no matter what reference or token bytes are supplied. */
int aienos_cap_cognition_mint(const AienosCapView *view, const AienosCapMint *request,
                             const uint8_t *token) {
    (void)request;
    (void)token;
    if (!view) return AIENOS_CAP_ERR_STATE;
    return AIENOS_CAP_ERR_UNAUTHORIZED;
}

int aienos_cap_cognition_admin(const AienosCapView *view, uint32_t op, AienosCapRef authority,
                              AienosCapRef target) {
    (void)op;
    (void)authority;
    (void)target;
    if (!view) return AIENOS_CAP_ERR_STATE;
    return AIENOS_CAP_ERR_UNAUTHORIZED;
}

int aienos_cap_force_generation(AienosCapAdmin *admin, uint32_t cap_id, uint32_t generation) {
    if (!admin) return AIENOS_CAP_ERR_STATE;
    return LOCKED(admin->shared,
                  state_force_generation(&admin->shared->state, cap_id, generation));
}

int aienos_cap_authorize(const AienosCapAdmin *admin, const uint8_t *presented) {
    if (!admin || !presented) return AIENOS_CAP_ERR_UNAUTHORIZED;
    CapShared *sh = admin->shared;
    uint8_t diff = 0;
    pthread_mutex_lock(&sh->token_lock);
    for (uint32_t i = 0; i < AIENOS_CAP_TOKEN_LEN; i++) diff |= sh->token[i] ^ presented[i];
    pthread_mutex_unlock(&sh->token_lock);
    return diff == 0 ? AIENOS_CAP_OK : AIENOS_CAP_ERR_UNAUTHORIZED;
}
