/*
 * stub_state.h -- test-only, in-memory ArgusStateOps over small arrays, plus
 * the deterministic synthetic corpora (lane E).
 *
 * This is NOT the ARGUS core. Lane D owns the real shadow state
 * (argus_core.c). The stub exists so detector tests can populate shadow state
 * directly, and so the corpora can be replayed without the core.
 * stub_state_apply() is a tiny reference "apply" whose rules are the lane E
 * proposal for how the core updates shadow state (see stub_state.c).
 *
 * The stub never defines struct ArgusStateView: a StubState pointer is cast
 * to the opaque view type and back, so this file links next to argus_core.c.
 */
#ifndef ARGUS_STUB_STATE_H
#define ARGUS_STUB_STATE_H
#include "../argus_abi.h"

#define STUB_MAX_CAPS      128
#define STUB_MAX_MACHINES   16
#define STUB_MAX_ARTIFACTS 128
#define STUB_MAX_LEASES     64
#define STUB_MAX_PROVIDERS  16

typedef struct {
    ArgusCapShadow      caps[STUB_MAX_CAPS];
    size_t              n_caps;
    ArgusMachineShadow  machines[STUB_MAX_MACHINES];
    size_t              n_machines;
    ArgusArtifactShadow artifacts[STUB_MAX_ARTIFACTS];
    size_t              n_artifacts;
    ArgusLeaseShadow    leases[STUB_MAX_LEASES];
    size_t              n_leases;
    ArgusProviderShadow providers[STUB_MAX_PROVIDERS];
    size_t              n_providers;
    ArgusWorldShadow    worlds[ARGUS_WORLD_STORES];   /* per store (v1.1), insertion order */
    size_t              n_worlds;
    uint8_t             policy[ARGUS_DIGEST_LEN];
    uint8_t             runtime[ARGUS_DIGEST_LEN];
} StubState;

void                  stub_state_init(StubState *s);
const ArgusStateOps  *stub_state_ops(void);
const ArgusStateView *stub_state_view(const StubState *s);

/* Direct population for tests. Insert or replace by key. ARGUS_ERR_FULL when full. */
int stub_put_cap(StubState *s, const ArgusCapShadow *c);
int stub_put_machine(StubState *s, const ArgusMachineShadow *m);
int stub_put_artifact(StubState *s, const ArgusArtifactShadow *a);
int stub_put_lease(StubState *s, const ArgusLeaseShadow *l);
int stub_put_provider(StubState *s, const ArgusProviderShadow *p);
/* Set (insert or replace) the World shadow of one store. ARGUS_ERR_FULL when ARGUS_WORLD_STORES are taken. */
int stub_set_world(StubState *s, uint32_t store_id, uint64_t generation, const uint8_t digest[ARGUS_DIGEST_LEN], uint64_t sequence);

/* Reference apply of one event AFTER detection, following the argus_abi.h apply
 * rules and machine lifecycle (see stub_state.c). */
int stub_state_apply(StubState *s, const ArgusEvent *ev);

/* Local copy of lane B's argus_event_min_class table (weakest legal class per
 * kind) used by the corpus generators until integration. */
uint8_t stub_min_class(uint16_t kind);

/* ---- corpora ---------------------------------------------------------------- */

typedef struct {
    uint64_t sequence;   /* the injected event */
    uint16_t code;       /* ARGUS_F_* expected on that event */
} ArgusExpectedFinding;

/* Deterministic synthetic "legal day": exactly `max` events (sequence 1..max),
 * every one legal under the argus_abi.h validate and apply rules, every one
 * attributed to a joined machine, lease ids never reused. Replayed through
 * detect-then-apply it must yield ZERO findings (ARGUS_FALSE_POSITIVE_BASELINE,
 * synthetic). Returns events written. */
size_t argus_corpus_benign(ArgusEvent *out, size_t max, uint64_t seed);

/* The same legal day with violations injected on a fixed cadence (one every
 * ARGUS_CORPUS_HOSTILE_EVERY events, cycling through 28 injection types that
 * cover all twelve detectors, codes 1..10, 14 and 15).
 * Each injected event triggers exactly one finding; the (sequence, code)
 * pairs are written to `expect` (up to expect_max, count in *n_expect).
 * Returns events written (exactly `max`). */
#define ARGUS_CORPUS_HOSTILE_EVERY 50u
size_t argus_corpus_hostile(ArgusEvent *out, size_t max, uint64_t seed,
                            ArgusExpectedFinding *expect, size_t expect_max, size_t *n_expect);

#endif /* ARGUS_STUB_STATE_H */
