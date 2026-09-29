/*
 * test_argus_core.c -- lane D unit tests: every table update, sequence
 * anomaly, table-full behaviour, telemetry loss, overflow, incidents, ops.
 * Linked against tests/stub_lanes_d.c (lane B/E stand-ins).
 */
#include "test_common_d.h"
#include <stdlib.h>

static _Alignas(16) uint8_t mem[1 << 17];

static ArgusCore *fresh(void)
{
    ArgusCore *c = NULL;
    stub_detect_mode = 1;
    if (argus_core_init(&c, mem, sizeof mem) != ARGUS_OK) { fprintf(stderr, "init failed\n"); exit(2); }
    return c;
}

static int ing(ArgusCore *c, const ArgusEvent *e, ArgusFinding *f, size_t *n)
{
    return argus_core_ingest(c, e, f, 16, n);
}

static void t_init(void)
{
    ArgusCore *c = NULL;
    CHECK(argus_core_footprint() > 0 && argus_core_footprint() <= sizeof mem);
    CHECK(argus_core_init(NULL, mem, sizeof mem) == ARGUS_ERR_ARG);
    CHECK(argus_core_init(&c, NULL, sizeof mem) == ARGUS_ERR_ARG);
    CHECK(argus_core_init(&c, mem, argus_core_footprint() - 1) == ARGUS_ERR_ARG);
    CHECK(argus_core_init(&c, mem + 1, sizeof mem - 1) == ARGUS_ERR_ARG);
    CHECK(argus_core_init(&c, mem, argus_core_footprint()) == ARGUS_OK);
    CHECK(argus_core_view(c) != NULL && argus_core_ops() != NULL);
    ArgusCoreHealth h;
    argus_core_health(c, &h);
    CHECK(h.events_received == 0 && h.incidents_open == 0);
    size_t n;
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_USED, 1);
    CHECK(argus_core_ingest(NULL, &e, NULL, 0, &n) == ARGUS_ERR_ARG);
    CHECK(argus_core_ingest(c, NULL, NULL, 0, &n) == ARGUS_ERR_ARG);
    CHECK(argus_core_ingest(c, &e, NULL, 4, &n) == ARGUS_ERR_ARG);
    CHECK(argus_core_ingest(c, &e, NULL, 0, NULL) == ARGUS_ERR_ARG);
    stub_detect_mode = 0;   /* stub raises FORGED for cap 0: no room -> OVERFLOW, n 0 */
    CHECK(argus_core_ingest(c, &e, NULL, 0, &n) == ARGUS_ERR_OVERFLOW && n == 0);
    stub_detect_mode = 1; e.sequence = 2;
    CHECK(argus_core_ingest(c, &e, NULL, 0, &n) == ARGUS_OK && n == 0);
}

static void t_malformed(void)
{
    ArgusCore *c = fresh();
    ArgusFinding f[16]; size_t n = 99;
    uint8_t d0[32], d1[32];
    argus_core_state_digest(c, d0);
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1);
    e.cap_id = 3; e.version = 2;
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 1);
    CHECK(f[0].code == ARGUS_F_MALFORMED_EVENT && f[0].severity == ARGUS_SEV_MEDIUM && f[0].sequence == 1);
    CHECK(f[0].detector == ARGUS_F_MALFORMED_EVENT && f[0].cap_id == 3 && f[0].confidence == ARGUS_CONF_DETERMINISTIC);
    uint8_t ed[32]; argus_event_digest(&e, ed);
    CHECK(memcmp(f[0].event_digest, ed, 32) == 0);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1); e.cap_id = 3; e.flags = 0x80;
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 1);
    e = ev_make(99, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 1);
    /* core guards (header validate rules): cap_id >= ARGUS_CAP_MAX, sequence UINT64_MAX */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1); e.cap_id = ARGUS_CAP_MAX; e.principal = 1234;
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 1 && f[0].code == ARGUS_F_MALFORMED_EVENT);
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 1); e.cap_id = 300;
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 1 && f[0].code == ARGUS_F_MALFORMED_EVENT);
    e = ev_make(ARGUS_EV_CAPABILITY_DENIED, UINT64_MAX);
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 1 && f[0].sequence == UINT64_MAX);
    /* cap 0 of output: still MALFORMED, finding counted */
    e = ev_make(99, 1);
    CHECK(argus_core_ingest(c, &e, NULL, 0, &n) == ARGUS_ERR_MALFORMED && n == 0);
    ArgusCoreHealth h; argus_core_health(c, &h);
    CHECK(h.events_received == 7 && h.events_rejected == 7 && h.findings_emitted == 7);
    CHECK(h.incidents_open == 0 && h.tables_full == 0 && h.events_not_applied == 0);
    uint8_t z[32] = {0};
    CHECK(memcmp(h.chain, z, 32) == 0);
    argus_core_state_digest(c, d1);
    CHECK(memcmp(d0, d1, 32) == 0);
    /* rejected events do not consume the producer sequence */
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
}

static void t_caps(void)
{
    ArgusCore *c = fresh();
    const ArgusStateOps *o = argus_core_ops(); const ArgusStateView *v = argus_core_view(c);
    ArgusFinding f[16]; size_t n; ArgusCapShadow s;
    CHECK(o->cap(v, 7, &s) == ARGUS_ERR_STATE);
    CHECK(o->cap(v, 999, &s) == ARGUS_ERR_STATE);
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1);
    e.cap_id = 7; e.cap_generation = 4; e.principal = 42; e.object_id = 0x13; e.resource = 0xABCDEF0123ull;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK);
    CHECK(s.cap_id == 7 && s.generation == 4 && s.state == ARGUS_SHADOW_LIVE && s.subject == 42);
    CHECK(s.rights == 0x13 && s.resource == 0xABCDEF0123ull && s.granted_sequence == 1 && s.revoked_sequence == 0);
    /* stale grant: AUTHORITY_REPLAY, not applied */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 2); e.cap_id = 7; e.cap_generation = 3; e.principal = 9;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY);
    CHECK(f[0].severity == ARGUS_SEV_HIGH && f[0].prior_sequence == 1 && f[0].sequence == 2 && f[0].principal == 9);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.generation == 4 && s.subject == 42);
    /* equal-generation grant on a LIVE slot: replay too */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 3); e.cap_id = 7; e.cap_generation = 4; e.principal = 9;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.subject == 42 && s.granted_sequence == 1);
    /* denied grant ignored */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 4); e.cap_id = 8; e.outcome = ARGUS_OUTCOME_DENIED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->cap(v, 8, &s) == ARGUS_ERR_STATE);
    /* cap_id 0 = none: no update, no error */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 5); e.cap_id = 0;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->cap(v, 0, &s) == ARGUS_ERR_STATE);
    /* revoke above the live generation: replay, not applied */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 21); e.cap_id = 7; e.cap_generation = 5;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY && f[0].prior_sequence == 1);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_LIVE && s.generation == 4);
    /* revoke at the live generation applies */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 25); e.cap_id = 7; e.cap_generation = 4;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED && s.revoked_sequence == 25 && s.subject == 42);
    /* double revoke: replay (prior = the revocation) */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 26); e.cap_id = 7; e.cap_generation = 4;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY && f[0].prior_sequence == 25);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.revoked_sequence == 25);
    /* grant replay at the revoked generation does not revive */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 27); e.cap_id = 7; e.cap_generation = 4; e.principal = 42;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY && f[0].prior_sequence == 25);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED);
    /* regrant at higher generation revives */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 28); e.cap_id = 7; e.cap_generation = 5; e.principal = 43;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_LIVE && s.generation == 5 && s.revoked_sequence == 0);
    /* revoking an older generation: replay, not applied */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 30); e.cap_id = 7; e.cap_generation = 4;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_LIVE && s.generation == 5);
    /* revoke of an unseen slot: replay, creates no entry (even at UINT64_MAX) */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 31); e.cap_id = 200; e.cap_generation = UINT64_MAX;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY && f[0].prior_sequence == 0);
    CHECK(o->cap(v, 200, &s) == ARGUS_ERR_STATE);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 32); e.cap_id = 200; e.cap_generation = 1;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->cap(v, 200, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_LIVE);
    /* denied/error revoke of an unseen slot is not a replay (never applied anyway) */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 33); e.cap_id = 201; e.outcome = ARGUS_OUTCOME_DENIED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    /* highest slot 255 works; 256 is malformed, never table-full */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 34); e.cap_id = 255; e.cap_generation = 1;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->cap(v, 255, &s) == ARGUS_OK);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 35); e.cap_id = 256; e.cap_generation = 1; e.principal = 5;
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 1 && f[0].code == ARGUS_F_MALFORMED_EVENT);
    ArgusCoreHealth h; argus_core_health(c, &h);
    CHECK(h.tables_full == 0 && h.events_not_applied == 7 && h.events_rejected == 1);
}

static void t_leases(void)
{
    ArgusCore *c = fresh();
    const ArgusStateOps *o = argus_core_ops(); const ArgusStateView *v = argus_core_view(c);
    ArgusFinding f[16]; size_t n; ArgusLeaseShadow s;
    ArgusEvent e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, 1);
    e.object_id = 77; e.principal = 3; e.resource = 0x55;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->lease(v, 77, &s) == ARGUS_OK && s.lease_id == 77 && s.subject == 3 && s.scope == 0x55 && s.state == ARGUS_SHADOW_LIVE && s.sequence == 1);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_USED, 2); e.object_id = 77; e.principal = 4;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->lease(v, 77, &s) == ARGUS_OK && s.subject == 3);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_REVOKED, 3); e.object_id = 77;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->lease(v, 77, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED && s.sequence == 3);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, 4); e.object_id = 77; e.principal = 9;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->lease(v, 77, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED && s.subject == 3);
    /* revoke of an unknown lease: no entry */
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_REVOKED, 5); e.object_id = 78;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->lease(v, 78, &s) == ARGUS_ERR_STATE);
    ArgusCoreHealth h0; argus_core_health(c, &h0);
    CHECK(h0.events_not_applied == 2);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, 6); e.object_id = 0;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->lease(v, 0, &s) == ARGUS_ERR_STATE);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, 7); e.object_id = 79; e.outcome = ARGUS_OUTCOME_ERROR;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->lease(v, 79, &s) == ARGUS_ERR_STATE);
    /* re-CREATE on a LIVE lease: not applied (no hijack of subject/scope) */
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, 60); e.object_id = 80; e.principal = 3; e.resource = 1;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, 61); e.object_id = 80; e.principal = 9; e.resource = UINT64_MAX;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    CHECK(o->lease(v, 80, &s) == ARGUS_OK && s.subject == 3 && s.scope == 1 && s.sequence == 60);
    argus_core_health(c, &h0);
    CHECK(h0.events_not_applied == 3);
    /* fill to the table size then overflow */
    uint64_t seq = 62;
    for (uint32_t id = 100; id < 100 + ARGUS_CORE_LEASES - 2; id++) {
        e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, seq++); e.object_id = id;
        CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    }
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, seq++); e.object_id = 5000;
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1 && f[0].code == ARGUS_F_TELEMETRY_LOSS && f[0].severity == ARGUS_SEV_CRITICAL);
    CHECK(o->lease(v, 5000, &s) == ARGUS_ERR_STATE);
    /* existing lease still updatable when full */
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_REVOKED, seq++); e.object_id = 100;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    ArgusCoreHealth h; argus_core_health(c, &h);
    uint8_t z[32] = {0};
    CHECK(memcmp(h.chain, z, 32) != 0);
    CHECK(h.tables_full == 1);
}

static void t_artifacts(void)
{
    ArgusCore *c = fresh();
    const ArgusStateOps *o = argus_core_ops(); const ArgusStateView *v = argus_core_view(c);
    ArgusFinding f[16]; size_t n; ArgusArtifactShadow s;
    ArgusEvent e = ev_make(ARGUS_EV_ARTIFACT_ADMITTED, 1); dg(e.evidence_digest, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->artifact(v, e.evidence_digest, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_LIVE && s.sequence == 1);
    e = ev_make(ARGUS_EV_ARTIFACT_REJECTED, 2); dg(e.evidence_digest, 2); e.outcome = ARGUS_OUTCOME_DENIED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->artifact(v, e.evidence_digest, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REJECTED);
    e = ev_make(ARGUS_EV_ARTIFACT_ADMITTED, 3); dg(e.evidence_digest, 2);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->artifact(v, e.evidence_digest, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REJECTED);
    e = ev_make(ARGUS_EV_ARTIFACT_REJECTED, 4); dg(e.evidence_digest, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->artifact(v, e.evidence_digest, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REJECTED && s.sequence == 4);
    e = ev_make(ARGUS_EV_ARTIFACT_REJECTED, 5); dg(e.evidence_digest, 3); e.outcome = ARGUS_OUTCOME_ERROR;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->artifact(v, e.evidence_digest, &s) == ARGUS_ERR_STATE);
    e = ev_make(ARGUS_EV_ARTIFACT_ADMITTED, 1); mid(e.machine_id, 9); dg(e.evidence_digest, 4); e.code = -3; /* OK but nonzero code: not admitted */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->artifact(v, e.evidence_digest, &s) == ARGUS_ERR_STATE);
    e = ev_make(ARGUS_EV_ARTIFACT_ADMITTED, 6); /* zero digest = none */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->artifact(v, e.evidence_digest, &s) == ARGUS_ERR_STATE);
    uint64_t seq = 7;
    for (uint32_t i = 10; i < 10 + ARGUS_CORE_ARTIFACTS - 2; i++) {
        e = ev_make(ARGUS_EV_ARTIFACT_ADMITTED, seq++); dg(e.evidence_digest, i);
        CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    }
    e = ev_make(ARGUS_EV_ARTIFACT_ADMITTED, seq++); dg(e.evidence_digest, 9999);
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1 && f[0].code == ARGUS_F_TELEMETRY_LOSS);
}

static void t_machines(void)
{
    ArgusCore *c = fresh();
    const ArgusStateOps *o = argus_core_ops(); const ArgusStateView *v = argus_core_view(c);
    ArgusFinding f[16]; size_t n; ArgusMachineShadow s; ArgusCoreHealth h;
    ArgusEvent e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_OBSERVED && s.joined_sequence == 1 && s.changed_sequence == 1);
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 2); e.object_id = ARGUS_TRUST_QUARANTINED; e.resource = ARGUS_TRUST_TRUSTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED && s.changed_sequence == 2);
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 3); /* rejoin: no laundering */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED && s.joined_sequence == 1);
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 4); e.object_id = 77; /* invalid trust ignored */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED);
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 40); e.object_id = 0; e.resource = ARGUS_TRUST_TRUSTED; /* 0 ignored */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED);
    argus_core_health(c, &h);
    CHECK(h.events_not_applied == 0);
    /* self-upgrade QUARANTINED -> TRUSTED: ignored, counted */
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 41); e.object_id = ARGUS_TRUST_TRUSTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED && s.changed_sequence == 2);
    /* rank is not enum order: QUARANTINED(4) -> REATTESTATION_REQUIRED(6) is UP the rank: ignored */
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 42); e.object_id = ARGUS_TRUST_REATTESTATION_REQUIRED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED);
    /* QUARANTINED -> UNTRUSTED is down: applied */
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 43); e.object_id = ARGUS_TRUST_UNTRUSTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_UNTRUSTED && s.changed_sequence == 43);
    argus_core_health(c, &h);
    CHECK(h.events_not_applied == 2);
    /* trust change for an unknown machine: no entry, counted */
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 1); mid(e.machine_id, 2); e.object_id = ARGUS_TRUST_TRUSTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->machine(v, e.machine_id, &s) == ARGUS_ERR_STATE);
    argus_core_health(c, &h);
    CHECK(h.events_not_applied == 3);
    /* ... so the real JOIN afterwards works normally (not bricked, not pre-seeded) */
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 2); mid(e.machine_id, 2);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_OBSERVED && s.joined_sequence == 2);
    /* OBSERVED -> REATTESTATION_REQUIRED -> RESTRICTED: both down */
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 3); mid(e.machine_id, 2); e.object_id = ARGUS_TRUST_REATTESTATION_REQUIRED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_REATTESTATION_REQUIRED);
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 4); mid(e.machine_id, 2); e.object_id = ARGUS_TRUST_RESTRICTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_RESTRICTED);
    /* remove machine 1: tombstone keeps trust, joined_sequence 0 */
    e = ev_make(ARGUS_EV_MACHINE_REMOVED, 50); mid(e.machine_id, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_UNTRUSTED && s.joined_sequence == 0 && s.changed_sequence == 50);
    /* downward trust change on a tombstone still applies; upward does not */
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 51); mid(e.machine_id, 1); e.object_id = ARGUS_TRUST_OBSERVED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_UNTRUSTED);
    /* rejoin of the tombstone: quarantine/untrusted survives, joined again */
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 52); mid(e.machine_id, 1); e.object_id = ARGUS_TRUST_TRUSTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_UNTRUSTED && s.joined_sequence == 52);
    /* remove of an unknown machine: nothing */
    e = ev_make(ARGUS_EV_MACHINE_REMOVED, 53); mid(e.machine_id, 77);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_ERR_STATE);
    /* machine 2 unaffected */
    mid(e.machine_id, 2);
    CHECK(o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_RESTRICTED);
    /* JOINED trust = weaker of OBSERVED and the claim */
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 3); e.object_id = ARGUS_TRUST_RESTRICTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_RESTRICTED && s.joined_sequence == 1);
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 4); e.object_id = 9;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_OBSERVED);
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 5); e.object_id = ARGUS_TRUST_TRUSTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_OBSERVED);
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 6); e.object_id = ARGUS_TRUST_REATTESTATION_REQUIRED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_REATTESTATION_REQUIRED);
    /* a JOINED of a known live machine may lower trust, never raise it */
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 2); mid(e.machine_id, 4); e.object_id = ARGUS_TRUST_QUARANTINED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED && s.joined_sequence == 1 && s.changed_sequence == 2);
    /* table stays sorted by machine_id; fill to capacity then one more is FULL */
    uint32_t have = 6;   /* machines 1..6 */
    for (uint32_t m = 1000 + ARGUS_CORE_MACHINES; m > 1000 + have; m--) {   /* descending ids: insert at front */
        e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, m);   /* own producer stream */
        CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    }
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 500);
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1 && f[0].code == ARGUS_F_TELEMETRY_LOSS);
    CHECK(o->machine(v, e.machine_id, &s) == ARGUS_ERR_STATE);
    for (uint32_t m = 1; m <= 6; m++) {
        mid(e.machine_id, m);
        CHECK(o->machine(v, e.machine_id, &s) == ARGUS_OK);
    }
    mid(e.machine_id, 1000 + ARGUS_CORE_MACHINES);
    CHECK(o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_OBSERVED);
    argus_core_health(c, &h);
    CHECK(h.tables_full == 1);
}

static void t_providers_world_policy(void)
{
    ArgusCore *c = fresh();
    const ArgusStateOps *o = argus_core_ops(); const ArgusStateView *v = argus_core_view(c);
    ArgusFinding f[16]; size_t n; ArgusProviderShadow p; ArgusWorldShadow w; uint8_t d[32], z[32] = {0};
    ArgusEvent e = ev_make(ARGUS_EV_PROVIDER_DISCOVERED, 1); dg(e.evidence_digest, 7);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->provider(v, e.evidence_digest, &p) == ARGUS_OK && p.state == ARGUS_SHADOW_LIVE && p.sequence == 1);
    e = ev_make(ARGUS_EV_PROVIDER_QUARANTINED, 2); dg(e.evidence_digest, 7);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->provider(v, e.evidence_digest, &p) == ARGUS_OK && p.state == ARGUS_SHADOW_REVOKED && p.sequence == 2);
    e = ev_make(ARGUS_EV_PROVIDER_DISCOVERED, 3); dg(e.evidence_digest, 7);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->provider(v, e.evidence_digest, &p) == ARGUS_OK && p.state == ARGUS_SHADOW_REVOKED);
    e = ev_make(ARGUS_EV_PROVIDER_QUARANTINED, 4); dg(e.evidence_digest, 8);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->provider(v, e.evidence_digest, &p) == ARGUS_OK && p.state == ARGUS_SHADOW_REVOKED);
    uint64_t seq = 5;
    for (uint32_t i = 20; i < 20 + ARGUS_CORE_PROVIDERS - 2; i++) {
        e = ev_make(ARGUS_EV_PROVIDER_DISCOVERED, seq++); dg(e.evidence_digest, i);
        CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    }
    e = ev_make(ARGUS_EV_PROVIDER_DISCOVERED, seq++); dg(e.evidence_digest, 999);
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1);

    CHECK(o->world(v, &w) == ARGUS_ERR_STATE);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, seq++); e.world_generation = 0x100000003ull; dg(e.evidence_digest, 31);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->world(v, &w) == ARGUS_OK && w.generation == 0x100000003ull && memcmp(w.digest, e.evidence_digest, 32) == 0);
    uint64_t wseq = e.sequence;
    ArgusCoreHealth h0, h1; argus_core_health(c, &h0);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, seq++); e.world_generation = 2; dg(e.evidence_digest, 32);      /* rollback */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->world(v, &w) == ARGUS_OK && w.generation == 0x100000003ull && w.sequence == wseq);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, seq++); e.world_generation = UINT64_MAX; dg(e.evidence_digest, 33); /* skip */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->world(v, &w) == ARGUS_OK && w.generation == 0x100000003ull);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, seq++); e.world_generation = 0x100000003ull; dg(e.evidence_digest, 34); /* conflict */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->world(v, &w) == ARGUS_OK && w.digest[0] == 31 && w.sequence == wseq);
    argus_core_health(c, &h1);
    CHECK(h1.events_not_applied == h0.events_not_applied + 3);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, seq++); e.world_generation = 0x100000003ull; dg(e.evidence_digest, 31); /* idempotent */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->world(v, &w) == ARGUS_OK && w.sequence == wseq);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, seq++); e.world_generation = 0; dg(e.evidence_digest, 35);            /* unknown */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->world(v, &w) == ARGUS_OK && w.sequence == wseq);
    argus_core_health(c, &h1);
    CHECK(h1.events_not_applied == h0.events_not_applied + 3);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, seq++); e.world_generation = 0x100000004ull; dg(e.evidence_digest, 36); /* +1 */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->world(v, &w) == ARGUS_OK && w.generation == 0x100000004ull && w.sequence == e.sequence);

    CHECK(o->policy_digest(v, d) == ARGUS_OK && memcmp(d, z, 32) == 0);
    e = ev_make(ARGUS_EV_POLICY_CHANGED, seq++); dg(e.evidence_digest, 41);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->policy_digest(v, d) == ARGUS_OK && memcmp(d, e.evidence_digest, 32) == 0);
    e = ev_make(ARGUS_EV_RUNTIME_BUILD_CHANGED, seq++); dg(e.evidence_digest, 42);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->runtime_digest(v, d) == ARGUS_OK && memcmp(d, e.evidence_digest, 32) == 0);
    e = ev_make(ARGUS_EV_RUNTIME_BUILD_CHANGED, seq++); dg(e.evidence_digest, 43); e.outcome = ARGUS_OUTCOME_DENIED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->runtime_digest(v, d) == ARGUS_OK && d[0] == 42);
}

static void t_sequence(void)
{
    ArgusCore *c = fresh();
    const ArgusStateOps *o = argus_core_ops(); const ArgusStateView *v = argus_core_view(c);
    ArgusFinding f[16]; size_t n; ArgusCapShadow s;
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_USED, 5);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 5); e.principal = 11;            /* repeat */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1);
    CHECK(f[0].code == ARGUS_F_SEQUENCE_ANOMALY && f[0].severity == ARGUS_SEV_HIGH && f[0].prior_sequence == 5 && f[0].sequence == 5 && f[0].principal == 11);
    uint8_t ed[32]; argus_event_digest(&e, ed);
    CHECK(memcmp(f[0].event_digest, ed, 32) == 0);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 3); e.cap_id = 9; e.cap_generation = 1;  /* decrease: detected, NOT applied */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_SEQUENCE_ANOMALY && f[0].prior_sequence == 5);
    CHECK(o->cap(v, 9, &s) == ARGUS_ERR_STATE);
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 4);                              /* high-water mark stays 5 */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].prior_sequence == 5);
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 6);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    /* consumer stream on the same machine is separate */
    e = ev_make(ARGUS_EV_TELEMETRY_DROPPED, 1); e.flags = ARGUS_FLAG_CONSUMER; e.object_id = ARGUS_CLASS_AUDIT; e.resource = 3;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    /* another machine is separate */
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 1); mid(e.machine_id, 2);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    ArgusCoreHealth h; argus_core_health(c, &h);
    CHECK(h.findings_emitted == 3 && h.incidents_open == 2);   /* (11, SEQ) and (0, SEQ) */
    CHECK(h.events_not_applied == 3 && h.producers_untracked == 0);
    /* lane E still runs on an anomalous event (stub mode 0: forged use) */
    stub_detect_mode = 0;
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 6); e.cap_id = 77;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 2 && f[0].code == ARGUS_F_SEQUENCE_ANOMALY && f[1].code == ARGUS_F_FORGED_CAPABILITY);
    stub_detect_mode = 1;
    /* sequence UINT64_MAX is malformed and does not move the high-water mark */
    e = ev_make(ARGUS_EV_CAPABILITY_USED, UINT64_MAX);
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED);
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 7);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
}

static void t_producers_full(void)
{
    ArgusCore *c = fresh();
    ArgusFinding f[16]; size_t n;
    for (uint32_t m = 0; m < ARGUS_CORE_PRODUCERS; m++) {
        ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_DENIED, 1); mid(e.machine_id, 1000 + m);
        CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    }
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_DENIED, 1); mid(e.machine_id, 5000);
    /* first untracked event: one CRITICAL loss + FULL; later ones only counted */
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1 && f[0].code == ARGUS_F_TELEMETRY_LOSS && f[0].severity == ARGUS_SEV_CRITICAL);
    e.sequence = 2;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    mid(e.machine_id, 5001);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    e.kind = ARGUS_EV_CAPABILITY_GRANTED; e.cap_id = 300; e.sequence = 3;   /* out-of-range cap: malformed, not FULL */
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 1 && f[0].code == ARGUS_F_MALFORMED_EVENT);
    /* untracked streams are still applied */
    e.cap_id = 30; e.cap_generation = 1; e.sequence = 4;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && argus_core_ops()->cap(argus_core_view(c), 30, &(ArgusCapShadow){0}) == ARGUS_OK);
    ArgusCoreHealth h; argus_core_health(c, &h);
    CHECK(h.producers_untracked == 4 && h.tables_full == 1);
    /* tracked streams keep working */
    e = ev_make(ARGUS_EV_CAPABILITY_DENIED, 1); mid(e.machine_id, 1000);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_SEQUENCE_ANOMALY);
}

static void t_telemetry(void)
{
    ArgusCore *c = fresh();
    ArgusFinding f[16]; size_t n;
    ArgusEvent e = ev_make(ARGUS_EV_TELEMETRY_DROPPED, 1); e.flags = ARGUS_FLAG_CONSUMER; e.class_ = ARGUS_CLASS_CRITICAL;
    e.object_id = ARGUS_CLASS_CRITICAL; e.resource = 4;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_TELEMETRY_LOSS && f[0].severity == ARGUS_SEV_CRITICAL);
    e.sequence = 2; e.object_id = ARGUS_CLASS_SECURITY;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].severity == ARGUS_SEV_HIGH);
    e.sequence = 3; e.object_id = ARGUS_CLASS_AUDIT;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    e.sequence = 4; e.object_id = ARGUS_CLASS_INFORMATIONAL;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    ArgusCoreHealth h; argus_core_health(c, &h);
    CHECK(h.findings_emitted == 2 && h.incidents_open == 1);
}

static void t_prestate_and_detectors(void)
{
    ArgusCore *c = fresh();
    ArgusFinding f[16]; size_t n;
    stub_detect_mode = 3;
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1); e.cap_id = 12; e.cap_generation = 1;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && stub_probe_rc == ARGUS_ERR_STATE);  /* detector saw pre-grant state */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 2); e.cap_id = 12; e.cap_generation = 1;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && stub_probe_rc == ARGUS_OK && stub_probe_cap.state == ARGUS_SHADOW_LIVE);
    stub_detect_mode = 0;
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 3); e.cap_id = 12; e.cap_generation = 1; e.principal = 50;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_REVOKED_CAPABILITY_USED && f[0].prior_sequence == 2);
    uint8_t ed[32]; argus_event_digest(&e, ed);
    CHECK(memcmp(f[0].event_digest, ed, 32) == 0);   /* core stamps lane E findings */
    e.sequence = 4; e.cap_id = 13;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_FORGED_CAPABILITY);
    ArgusCoreHealth h; argus_core_health(c, &h);
    CHECK(h.findings_emitted == 2 && h.incidents_open == 2);
    e.sequence = 5; e.cap_id = 12;                  /* same (principal, code): no new incident */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1);
    argus_core_health(c, &h);
    CHECK(h.incidents_open == 2);
}

static void t_overflow(void)
{
    ArgusCore *c = fresh();
    const ArgusStateOps *o = argus_core_ops(); const ArgusStateView *v = argus_core_view(c);
    ArgusFinding f[16]; size_t n; ArgusCapShadow s;
    stub_detect_mode = 2;
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1); e.cap_id = 20; e.cap_generation = 1;
    CHECK(argus_core_ingest(c, &e, f, 4, &n) == ARGUS_ERR_OVERFLOW && n == 4);
    CHECK(o->cap(v, 20, &s) == ARGUS_OK);            /* state applied despite the small buffer */
    ArgusCoreHealth h; argus_core_health(c, &h);
    CHECK(h.findings_emitted == ARGUS_CORE_MAX_FINDINGS - 2);
    /* replay verdict + table full + canned + telemetry drop: core findings survive in scratch */
    ArgusFinding big[ARGUS_CORE_MAX_FINDINGS];
    stub_detect_mode = 1;
    for (uint32_t i = 0; i < ARGUS_CORE_PROVIDERS; i++) {
        e = ev_make(ARGUS_EV_PROVIDER_DISCOVERED, 10 + i); dg(e.evidence_digest, 100 + i);
        CHECK(argus_core_ingest(c, &e, big, ARGUS_CORE_MAX_FINDINGS, &n) == ARGUS_OK);
    }
    stub_detect_mode = 2;
    e = ev_make(ARGUS_EV_PROVIDER_QUARANTINED, 100); dg(e.evidence_digest, 999);
    CHECK(argus_core_ingest(c, &e, big, ARGUS_CORE_MAX_FINDINGS, &n) == ARGUS_ERR_FULL && n == ARGUS_CORE_MAX_FINDINGS - 1);
    CHECK(big[n - 1].code == ARGUS_F_TELEMETRY_LOSS);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 101); e.cap_id = 20; e.cap_generation = 1;   /* replay of the grant */
    CHECK(argus_core_ingest(c, &e, big, ARGUS_CORE_MAX_FINDINGS, &n) == ARGUS_OK && n == ARGUS_CORE_MAX_FINDINGS - 2);
    CHECK(big[0].code == ARGUS_F_AUTHORITY_REPLAY && big[1].code == ARGUS_F_FORGED_CAPABILITY);
    e = ev_make(ARGUS_EV_TELEMETRY_DROPPED, 1); e.flags = ARGUS_FLAG_CONSUMER; e.object_id = ARGUS_CLASS_CRITICAL; e.resource = 1;
    mid(e.machine_id, 1);
    e.sequence = 1;
    CHECK(argus_core_ingest(c, &e, big, ARGUS_CORE_MAX_FINDINGS, &n) == ARGUS_OK && n == ARGUS_CORE_MAX_FINDINGS - 1);
    e.sequence = 1;                                   /* anomaly + canned + drop */
    CHECK(argus_core_ingest(c, &e, big, ARGUS_CORE_MAX_FINDINGS, &n) == ARGUS_OK && n == ARGUS_CORE_MAX_FINDINGS - 1);
    CHECK(big[0].code == ARGUS_F_SEQUENCE_ANOMALY && big[n - 1].code == ARGUS_F_TELEMETRY_LOSS);
    stub_detect_mode = 1;
}

static void t_digest(void)
{
    ArgusCore *c = fresh();
    ArgusFinding f[16]; size_t n;
    uint8_t d0[32], d1[32], d2[32];
    argus_core_state_digest(c, d0);
    argus_core_state_digest(c, d1);
    CHECK(memcmp(d0, d1, 32) == 0);
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1); e.cap_id = 1; e.cap_generation = 1;
    ing(c, &e, f, &n);
    argus_core_state_digest(c, d1);
    CHECK(memcmp(d0, d1, 32) != 0);
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 2); e.cap_id = 1; e.cap_generation = 1;  /* observation only: producer hwm moves */
    ing(c, &e, f, &n);
    argus_core_state_digest(c, d2);
    CHECK(memcmp(d1, d2, 32) != 0);
    /* same state reached through a different path gives the same digest */
    static _Alignas(16) uint8_t m2[1 << 17];
    ArgusCore *c2 = NULL;
    argus_core_init(&c2, m2, sizeof m2);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1); e.cap_id = 1; e.cap_generation = 1;
    ing(c2, &e, f, &n);
    e = ev_make(ARGUS_EV_CAPABILITY_DENIED, 2); e.outcome = ARGUS_OUTCOME_DENIED;
    ing(c2, &e, f, &n);
    argus_core_state_digest(c2, d0);
    CHECK(memcmp(d0, d2, 32) == 0);
}


static void t_digest_domain_and_order(void)
{
    ArgusFinding f[16]; size_t n;
    static _Alignas(16) uint8_t m1[1 << 17], m2[1 << 17];
    ArgusCore *a = NULL, *b = NULL;
    stub_detect_mode = 1;
    argus_core_init(&a, m1, sizeof m1);
    argus_core_init(&b, m2, sizeof m2);
    /* empty core: state digest != zero chain, != chain of anything */
    uint8_t da[32], db[32], z[32] = {0};
    argus_core_state_digest(a, da);
    CHECK(memcmp(da, z, 32) != 0);
    /* same machine SET joined in a different order (each on its own stream) -> same digest */
    for (uint32_t i = 0; i < 5; i++) {
        ArgusEvent e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 10 + i);
        argus_core_ingest(a, &e, f, 16, &n);
        e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 14 - i);
        argus_core_ingest(b, &e, f, 16, &n);
    }
    argus_core_state_digest(a, da);
    argus_core_state_digest(b, db);
    CHECK(memcmp(da, db, 32) == 0);
    ArgusCoreHealth ha, hb; argus_core_health(a, &ha); argus_core_health(b, &hb);
    CHECK(memcmp(ha.chain, hb.chain, 32) != 0);          /* the event chain is order-sensitive */
    CHECK(memcmp(da, ha.chain, 32) != 0);
    /* a different trust on one machine changes the digest */
    ArgusEvent e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 2); mid(e.machine_id, 12); e.object_id = ARGUS_TRUST_QUARANTINED;
    argus_core_ingest(b, &e, f, 16, &n);
    argus_core_state_digest(b, db);
    CHECK(memcmp(da, db, 32) != 0);
    /* tombstone differs from live */
    argus_core_init(&b, m2, sizeof m2);
    for (uint32_t i = 0; i < 5; i++) {
        e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 10 + i);
        argus_core_ingest(b, &e, f, 16, &n);
    }
    e = ev_make(ARGUS_EV_MACHINE_REMOVED, 2); mid(e.machine_id, 12);
    argus_core_ingest(b, &e, f, 16, &n);
    argus_core_state_digest(b, db);
    CHECK(memcmp(da, db, 32) != 0);
}

static void t_incidents(void)
{
    ArgusCore *c = fresh();
    ArgusFinding f[16]; size_t n; ArgusCoreHealth h;
    stub_detect_mode = 0;   /* forged use -> CRITICAL per principal */
    for (uint32_t p = 0; p < ARGUS_CORE_INCIDENTS + 5; p++) {
        ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_USED, 1 + p); e.cap_id = 1; e.principal = 1000 + p;
        CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1);
    }
    argus_core_health(c, &h);
    CHECK(h.incidents_open == ARGUS_CORE_INCIDENTS && h.incidents_untracked == 5);
    CHECK(h.findings_emitted == ARGUS_CORE_INCIDENTS + 5);
    /* MEDIUM findings never become incidents */
    ArgusEvent e = ev_make(99, 1);
    ing(c, &e, f, &n);
    argus_core_health(c, &h);
    CHECK(h.incidents_untracked == 5);
    stub_detect_mode = 1;
}

/* Mirrors of lane G's hostile scenarios for the rules the core owns (stub detectors). */
static void t_hostile_rules(void)
{
    ArgusFinding f[16]; size_t n; ArgusCapShadow s; ArgusCoreHealth h;
    const ArgusStateOps *o = argus_core_ops();
    /* G-3: exact byte replay after revoke: anomaly only (not also 13), stays REVOKED */
    ArgusCore *c = fresh();
    ArgusEvent g = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1); g.cap_id = 5; g.cap_generation = 1; g.principal = 7;
    ing(c, &g, f, &n);
    ArgusEvent e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 2); e.cap_id = 5; e.cap_generation = 1;
    ing(c, &e, f, &n);
    CHECK(ing(c, &g, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_SEQUENCE_ANOMALY);
    CHECK(o->cap(argus_core_view(c), 5, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED);
    /* same replay with a fresh sequence: 13, stays REVOKED; a later use is revoked-use */
    g.sequence = 3;
    CHECK(ing(c, &g, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY && f[0].prior_sequence == 2);
    stub_detect_mode = 0;
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 4); e.cap_id = 5; e.cap_generation = 1; e.principal = 7;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_REVOKED_CAPABILITY_USED);
    stub_detect_mode = 1;
    argus_core_health(c, &h);
    CHECK(h.events_not_applied == 2 && h.incidents_open == 3);
    /* G-4: forged REVOKED at UINT64_MAX on an unseen slot poisons nothing */
    c = fresh();
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 1); e.cap_id = 5; e.cap_generation = UINT64_MAX;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 2); e.cap_id = 5; e.cap_generation = 1; e.principal = 7;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    stub_detect_mode = 0;
    e = ev_make(ARGUS_EV_CAPABILITY_USED, 3); e.cap_id = 5; e.cap_generation = 1; e.principal = 7;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    stub_detect_mode = 1;
    /* G-4: forged REVOKED at UINT64_MAX on a LIVE slot is not applied either */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 4); e.cap_id = 5; e.cap_generation = UINT64_MAX;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_AUTHORITY_REPLAY && f[0].prior_sequence == 2);
    CHECK(o->cap(argus_core_view(c), 5, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_LIVE && s.generation == 1);
    /* G-15: a skipping commit is not adopted; the legitimate successor is */
    c = fresh();
    ArgusWorldShadow w;
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, 1); e.world_generation = 1; dg(e.evidence_digest, 1);
    ing(c, &e, f, &n);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, 2); e.world_generation = UINT64_MAX; dg(e.evidence_digest, 99);
    ing(c, &e, f, &n);
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, 3); e.world_generation = 2; dg(e.evidence_digest, 2);
    ing(c, &e, f, &n);
    CHECK(o->world(argus_core_view(c), &w) == ARGUS_OK && w.generation == 2 && w.sequence == 3);
    /* G-8: quarantine survives remove + rejoin */
    c = fresh();
    ArgusMachineShadow ms;
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 3); ing(c, &e, f, &n);
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 2); mid(e.machine_id, 3); e.object_id = ARGUS_TRUST_QUARANTINED; ing(c, &e, f, &n);
    e = ev_make(ARGUS_EV_MACHINE_REMOVED, 3); mid(e.machine_id, 3); ing(c, &e, f, &n);
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 4); mid(e.machine_id, 3); ing(c, &e, f, &n);
    CHECK(o->machine(argus_core_view(c), e.machine_id, &ms) == ARGUS_OK && ms.trust == ARGUS_TRUST_QUARANTINED && ms.joined_sequence == 4);
    /* G-8: 17th machine is still tracked (table 64) */
    c = fresh();
    for (uint32_t m = 1; m <= 17; m++) {
        e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 100 + m);
        CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    }
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 2); mid(e.machine_id, 117); e.object_id = ARGUS_TRUST_QUARANTINED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(argus_core_view(c), e.machine_id, &ms) == ARGUS_OK && ms.trust == ARGUS_TRUST_QUARANTINED);
    /* G-21: 40 producers are all tracked; a replay on the 41st stream is flagged */
    c = fresh();
    for (uint32_t m = 0; m < 40; m++) {
        e = ev_make(ARGUS_EV_CAPABILITY_DENIED, 1 + m); mid(e.machine_id, 1000 + m); ing(c, &e, f, &n);
    }
    e = ev_make(ARGUS_EV_CAPABILITY_DENIED, 7); mid(e.machine_id, 5000);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_SEQUENCE_ANOMALY);
    argus_core_health(c, &h);
    CHECK(h.producers_untracked == 0);
}

int main(void)
{
    t_init();
    t_malformed();
    t_caps();
    t_leases();
    t_artifacts();
    t_machines();
    t_providers_world_policy();
    t_sequence();
    t_producers_full();
    t_telemetry();
    t_prestate_and_detectors();
    t_overflow();
    t_digest();
    t_digest_domain_and_order();
    t_incidents();
    t_hostile_rules();
    printf("test_argus_core: %d passed, %d failed (footprint %zu bytes)\n", t_pass, t_fail, argus_core_footprint());
    return t_fail ? 1 : 0;
}
