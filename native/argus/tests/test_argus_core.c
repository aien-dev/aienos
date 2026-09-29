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
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED && n == 0);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 1); e.cap_id = 3; e.flags = 0x80;
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED);
    e = ev_make(99, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_MALFORMED);
    ArgusCoreHealth h; argus_core_health(c, &h);
    CHECK(h.events_received == 3 && h.events_rejected == 3);
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
    /* stale grant ignored */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 2); e.cap_id = 7; e.cap_generation = 3; e.principal = 9;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.generation == 4 && s.subject == 42);
    /* denied grant ignored */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 3); e.cap_id = 8; e.outcome = ARGUS_OUTCOME_DENIED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->cap(v, 8, &s) == ARGUS_ERR_STATE);
    /* cap_id 0 = none: no update, no error */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 4); e.cap_id = 0;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->cap(v, 0, &s) == ARGUS_ERR_STATE);
    /* revoke */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 5); e.cap_id = 7; e.cap_generation = 4;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED && s.revoked_sequence == 5 && s.subject == 42);
    /* regrant at higher generation revives */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 6); e.cap_id = 7; e.cap_generation = 5; e.principal = 43;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->cap(v, 7, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_LIVE && s.generation == 5 && s.revoked_sequence == 0);
    /* revoking an older generation is ignored */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 7); e.cap_id = 7; e.cap_generation = 4;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->cap(v, 7, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_LIVE);
    /* revoke of an unseen slot creates a REVOKED entry */
    e = ev_make(ARGUS_EV_CAPABILITY_REVOKED, 8); e.cap_id = 200; e.cap_generation = 2;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->cap(v, 200, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED && s.generation == 2 && s.subject == 0);
    /* highest slot 255 works, 256 cannot be shadowed */
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 9); e.cap_id = 255; e.cap_generation = 1;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->cap(v, 255, &s) == ARGUS_OK);
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 10); e.cap_id = 256; e.cap_generation = 1; e.principal = 5;
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1);
    CHECK(f[0].code == ARGUS_F_TELEMETRY_LOSS && f[0].severity == ARGUS_SEV_CRITICAL && f[0].sequence == 10);
    CHECK(f[0].confidence == ARGUS_CONF_DETERMINISTIC && f[0].detector == ARGUS_F_TELEMETRY_LOSS && f[0].cap_id == 256);
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
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->lease(v, 77, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED && s.subject == 3);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_REVOKED, 5); e.object_id = 78;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->lease(v, 78, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, 6); e.object_id = 0;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->lease(v, 0, &s) == ARGUS_ERR_STATE);
    e = ev_make(ARGUS_EV_CREDENTIAL_LEASE_CREATED, 7); e.object_id = 79; e.outcome = ARGUS_OUTCOME_ERROR;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->lease(v, 79, &s) == ARGUS_ERR_STATE);
    /* fill to 64 then overflow */
    uint64_t seq = 8;
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
    ArgusFinding f[16]; size_t n; ArgusMachineShadow s;
    ArgusEvent e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    CHECK(o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_OBSERVED && s.joined_sequence == 1 && s.changed_sequence == 1);
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 2); e.resource = ARGUS_TRUST_QUARANTINED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED && s.changed_sequence == 2);
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 3); /* rejoin: no laundering */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED && s.joined_sequence == 1);
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 4); e.resource = 77; /* invalid trust ignored */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_QUARANTINED);
    /* trust change for unknown machine creates it with joined 0 (its own producer stream) */
    e = ev_make(ARGUS_EV_MACHINE_TRUST_CHANGED, 1); mid(e.machine_id, 2); e.resource = ARGUS_TRUST_TRUSTED;
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 0 && o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_TRUSTED && s.joined_sequence == 0);
    /* remove machine 1; machine 2 stays */
    e = ev_make(ARGUS_EV_MACHINE_REMOVED, 5); mid(e.machine_id, 1);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->machine(v, e.machine_id, &s) == ARGUS_ERR_STATE);
    mid(e.machine_id, 2);
    CHECK(o->machine(v, e.machine_id, &s) == ARGUS_OK && s.trust == ARGUS_TRUST_TRUSTED);
    /* fill the machine table to 16, then one more is FULL */
    for (uint32_t m = 100; m < 100 + ARGUS_CORE_MACHINES - 1; m++) {
        e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, m);   /* own producer stream */
        CHECK(ing(c, &e, f, &n) == ARGUS_OK);
    }
    e = ev_make(ARGUS_EV_MACHINE_JOINED, 1); mid(e.machine_id, 500);
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1 && f[0].code == ARGUS_F_TELEMETRY_LOSS);
    CHECK(o->machine(v, e.machine_id, &s) == ARGUS_ERR_STATE);
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
    e = ev_make(ARGUS_EV_WORLD_COMMITTED, seq++); e.world_generation = 2; dg(e.evidence_digest, 32);
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && o->world(v, &w) == ARGUS_OK && w.generation == 0x100000003ull && w.sequence == wseq);

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
    e = ev_make(ARGUS_EV_CAPABILITY_GRANTED, 3); e.cap_id = 9; e.cap_generation = 1;  /* decrease, still applied */
    CHECK(ing(c, &e, f, &n) == ARGUS_OK && n == 1 && f[0].code == ARGUS_F_SEQUENCE_ANOMALY && f[0].prior_sequence == 5);
    CHECK(o->cap(v, 9, &s) == ARGUS_OK);
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
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1 && f[0].code == ARGUS_F_TELEMETRY_LOSS && f[0].severity == ARGUS_SEV_CRITICAL);
    e.kind = ARGUS_EV_CAPABILITY_GRANTED; e.cap_id = 300; e.sequence = 2;   /* producer AND table fail: one finding */
    CHECK(ing(c, &e, f, &n) == ARGUS_ERR_FULL && n == 1);
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
    /* repeat + table full + canned: core findings survive in scratch */
    e.sequence = 1; e.cap_id = 400;
    ArgusFinding big[ARGUS_CORE_MAX_FINDINGS];
    CHECK(argus_core_ingest(c, &e, big, ARGUS_CORE_MAX_FINDINGS, &n) == ARGUS_ERR_FULL && n == ARGUS_CORE_MAX_FINDINGS - 1);
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
    printf("test_argus_core: %d passed, %d failed (footprint %zu bytes)\n", t_pass, t_fail, argus_core_footprint());
    return t_fail ? 1 : 0;
}
