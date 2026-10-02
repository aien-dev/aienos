/* continuity_recovery.c -- see continuity_recovery.h. */
#include <stdio.h>
#include <string.h>

#include "continuity_recovery.h"

#define UNIT SV1_UNIT

static int is_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* Sealed mount refusals (store_sealed.h SS_E_*, -301..-314). */
static int is_sealed_error(int rc) { return rc <= SS_E_ARG && rc >= SS_E_FORMAT_VERSION; }

int rc_inspect(const struct rc_env *e, struct rc_record *rec)
{
    if (!e || !rec || !e->dev || !e->anchor || !e->keys || !e->ws || !e->store || !e->w || !e->view ||
        !e->dev->read_unit)
        return -1;
    static uint8_t raw[2][UNIT]; /* single-threaded kernel scratch, like cr_work */
    memset(rec, 0, sizeof *rec);
    for (unsigned s = 0; s < 2; s++) {
        memset(raw[s], 0, UNIT);
        rec->slot[s] = RC_SLOT_READ_ERROR;
        if (e->dev->read_unit(e->dev->ctx, s, raw[s]) != 0) {
            memset(raw[s], 0, UNIT); /* recovery_core.rs:109-133: an unreadable unit hashes as zero */
            continue;
        }
        if (is_zero(raw[s], UNIT)) {
            rec->slot[s] = RC_SLOT_ZERO;
            continue;
        }
        sv1_superblock sb;
        if (sv1_superblock_decode(raw[s], UNIT, s, &sb) == 0) {
            rec->slot[s] = RC_SLOT_SUPERBLOCK;
            rec->slot_generation[s] = sb.generation;
            if (!rec->have_uuid) {
                rec->have_uuid = 1;
                memcpy(rec->uuid, sb.store_uuid, 16);
            }
        } else {
            rec->slot[s] = RC_SLOT_UNDECODABLE;
        }
    }
    cr_state_digest(raw[0], raw[1], rec->state_digest);

    /* Mount without writing (ss_open never writes). */
    memset(e->store, 0, sizeof *e->store);
    int rc = ss_open(e->store, e->dev, e->anchor, e->anchor_lba, e->keys, e->ws);
    if (rc != 0) {
        rec->mount_rc = rc;
        rec->reason = rc == ST_M_UNFORMATTED ? RC_STORE_UNFORMATTED
                      : is_sealed_error(rc)  ? RC_SEALED_REFUSAL
                                             : RC_STORE_MOUNT;
        return 0;
    }
    rec->have_mount = 1;
    rec->mount_state = e->store->st.state;
    rec->peer = e->store->st.peer;
    rec->generation = ss_generation(e->store);

    struct cr_source src;
    cr_bind_sealed(&src, e->store);
    uint32_t n = src.count(src.ctx);
    rec->have_catalog = 1;
    for (uint32_t i = 0; i < n; i++) {
        uint16_t kind = 0, ver = 0;
        if (src.entry(src.ctx, i, &kind, &ver) != 0) continue;
        if (kind == CC_KIND_AGENT_ROOT)
            rec->n_roots++;
        else if (kind == CC_KIND_MANIFEST)
            rec->n_manifests++;
        else
            rec->n_other++;
    }

    const char *why = NULL;
    int srcrc = 0;
    int o = cr_resolve(&src, e->w, e->view, &why, &srcrc);
#ifdef RC_MUTANT_DEGRADED_IS_UNPROVISIONED
    /* MR-5 (the fe2c2bd bug): continuity decides first, a degraded mount that resolves no identity
     * reads as Unprovisioned. */
    if (o == CR_UNPROVISIONED) {
        rec->reason = RC_UNPROVISIONED;
        rec->have_identity = 0;
        return 0;
    }
#endif
    if (rec->mount_state == ST_DEGRADED_RECOVERY) {
        /* Degraded takes precedence (INV-14): what the valid (older) root says about
         * continuity is not the whole story. */
        rec->reason = RC_DEGRADED;
    } else if (o == CR_RESOLVED) {
        rec->reason = RC_REASON_NONE;
    } else if (o == CR_UNPROVISIONED) {
        rec->reason = RC_UNPROVISIONED;
    } else if (o == CR_CONFLICT) {
        rec->reason = RC_CONFLICT;
    } else if (o == CR_CORRUPT && why) {
        rec->reason = RC_CONTINUITY_CORRUPT;
        rec->why = why;
    } else {
        rec->reason = RC_CONTINUITY_CORRUPT;
        rec->why = "continuity unreadable";
    }
    if (o == CR_RESOLVED) {
        rec->have_identity = 1;
        memcpy(rec->agent_id, e->view->root.agent_id, 32);
    }
#ifdef RC_MUTANT_INSPECT_WRITES
    /* MR-1: "repair on inspect". */
    if (rec->reason == RC_DEGRADED && rec->peer == ST_PEER_MALFORMED && e->dev->write_unit) {
        static const uint8_t zero[UNIT];
        (void)e->dev->write_unit(e->dev->ctx, 1u - st_active_slot(&e->store->st), zero);
    }
#endif
    return 0;
}

int rc_applicable(const struct rc_record *rec)
{
    if (!rec || !rec->have_mount) return 0;
    switch (rec->reason) {
    case RC_DEGRADED:
#ifdef RC_MUTANT_REPAIR_NO_IDENTITY
        if (rec->peer == ST_PEER_MALFORMED) return CR_ACTION_REPAIR_DEGRADED_PEER;
#else
        if (rec->peer == ST_PEER_MALFORMED && rec->have_identity) return CR_ACTION_REPAIR_DEGRADED_PEER;
#endif
        return 0;
    case RC_UNPROVISIONED:
#ifdef RC_MUTANT_DEGRADED_IS_UNPROVISIONED
        return CR_ACTION_PROVISION_IDENTITY;
#else
        if (rec->mount_state == ST_VALID) return CR_ACTION_PROVISION_IDENTITY;
        return 0;
#endif
    default:
        return 0;
    }
}

int rc_challenge(const struct rc_record *rec, uint8_t action, uint8_t out[32])
{
    if (!rec || !rec->have_uuid || !rec->have_mount) return 0;
    cr_challenge(rec->uuid, rec->generation, action, rec->state_digest, out);
    return 1;
}

const char *rc_outcome_name(int rc)
{
    switch (rc) {
    case RC_OK: return "Ok";
    case RC_NOT_APPLICABLE: return "NotApplicable";
    case RC_UNAUTHORISED: return "Unauthorised";
    case RC_IO: return "Io";
    case RC_CONTINUITY: return "Continuity";
    case RC_E_ARG: return "BadArgument";
    default: return "?";
    }
}

/* recovery_core.rs:219-235: applicable first, then the operator response. */
static int authorise(const struct rc_record *rec, uint8_t action, const uint8_t key[32],
                     const uint8_t response[32])
{
    if (rc_applicable(rec) != action) return RC_NOT_APPLICABLE;
    uint8_t ch[32];
    if (!rc_challenge(rec, action, ch)) return RC_NOT_APPLICABLE;
    if (!cr_operator_verify(key, ch, response)) return RC_UNAUTHORISED;
    return RC_OK;
}

static int env_ok(const struct rc_env *e) { return e && e->tw && e->dev && e->store; }

int rc_repair_degraded_peer(const struct rc_env *e, const uint8_t operator_key[32],
                            const uint8_t response[32], struct rc_record *after)
{
    if (!env_ok(e) || !operator_key || !response || !e->dev->write_unit || !e->dev->flush) return RC_E_ARG;
    struct rc_record rec;
    if (rc_inspect(e, &rec) != 0) return RC_E_ARG;
    int a = authorise(&rec, CR_ACTION_REPAIR_DEGRADED_PEER, operator_key, response);
    if (a != RC_OK) return a;
    /* The valid root is the slot the engine mounted; the other one goes (INV-17). */
    uint32_t active = st_active_slot(&e->store->st);
#ifdef RC_MUTANT_REPAIR_ACTIVE
    uint32_t victim = active; /* MR-6 */
#else
    uint32_t victim = 1u - active;
#endif
    if (active > 1u) return RC_IO;
    static const uint8_t zero[UNIT];
    if (e->dev->write_unit(e->dev->ctx, victim, zero) != 0) return RC_IO;
    if (e->dev->flush(e->dev->ctx) != 0) return RC_IO;
    if (after) (void)rc_inspect(e, after);
    return RC_OK;
}

int rc_provision_identity(const struct rc_env *e, const uint8_t operator_key[32],
                          const uint8_t response[32], struct ck_rng *rng, struct cr_view *out,
                          int *cr_outcome, const char **why, int *store_rc)
{
    if (!env_ok(e) || !e->w || !operator_key || !response || !rng || !out) return RC_E_ARG;
    struct rc_record rec;
    if (rc_inspect(e, &rec) != 0) return RC_E_ARG;
    int a = authorise(&rec, CR_ACTION_PROVISION_IDENTITY, operator_key, response);
    if (a != RC_OK) return a;
    if (!rec.have_uuid) return RC_NOT_APPLICABLE;
    /* inspection left the Store open at exactly the state that was authorised */
    struct cr_source src;
    struct cr_sink snk;
    struct cr_sealed_sink sk = {e->store, NULL, NULL};
    cr_bind_sealed(&src, e->store);
    cr_bind_sealed_sink(&snk, &sk);
#ifdef RC_MUTANT_PROVISION_QUALIFICATION
    uint8_t source = CC_SOURCE_QUALIFICATION; /* MR-9 */
#else
    uint8_t source = CC_SOURCE_OPERATOR; /* INV-18 */
#endif
    int o = cr_provision(&src, &snk, e->w, e->tw, rng, rec.uuid, source, out, why, store_rc);
    if (cr_outcome) *cr_outcome = o;
    return o == CR_RESOLVED ? RC_OK : RC_CONTINUITY;
}

/* ---- markers ---- */

const char *rc_peer_name(int peer)
{
    switch (peer) {
    case ST_PEER_ZERO: return "Zero";
    case ST_PEER_VALID: return "Valid";
    case ST_PEER_MALFORMED: return "Malformed";
    case ST_PEER_GRAPH_BAD_NEWER: return "GraphBadNewer";
    case ST_PEER_GRAPH_BAD_OLDER: return "GraphBadOlder";
    default: return "?";
    }
}

static size_t fin(char *out, size_t cap, int n)
{
    if (n < 0 || (size_t)n >= cap) {
        if (cap) out[0] = 0;
        return 0;
    }
    return (size_t)n;
}

size_t rc_reason_text(char *out, size_t cap, const struct rc_record *r)
{
    if (!out || !cap || !r) return 0;
    switch (r->reason) {
    case RC_STORE_UNFORMATTED: return fin(out, cap, snprintf(out, cap, "StoreUnformatted"));
    case RC_STORE_MOUNT: return fin(out, cap, snprintf(out, cap, "StoreMount(%d)", r->mount_rc));
    case RC_SEALED_REFUSAL: return fin(out, cap, snprintf(out, cap, "SealedRefusal(%d)", r->mount_rc));
    case RC_UNPROVISIONED: return fin(out, cap, snprintf(out, cap, "Unprovisioned"));
    case RC_CONFLICT: return fin(out, cap, snprintf(out, cap, "Conflict"));
    case RC_CONTINUITY_CORRUPT:
        return fin(out, cap, snprintf(out, cap, "ContinuityCorrupt(\"%s\")", r->why ? r->why : ""));
    case RC_DEGRADED: return fin(out, cap, snprintf(out, cap, "Degraded(%s)", rc_peer_name(r->peer)));
    default: return fin(out, cap, snprintf(out, cap, "None"));
    }
}

size_t rc_marker_entry(char *out, size_t cap, const struct rc_record *r)
{
    if (!out || !cap || !r) return 0;
    if (r->reason == RC_REASON_NONE) return fin(out, cap, snprintf(out, cap, "RECOVERY_CORE: NOT_NEEDED"));
    char t[160];
    if (!rc_reason_text(t, sizeof t, r)) return 0;
    return fin(out, cap, snprintf(out, cap, "RECOVERY_CORE: ENTERED reason=%s", t));
}

static const char *action_name(uint8_t a)
{
    return a == CR_ACTION_REPAIR_DEGRADED_PEER ? "repair-degraded-peer"
           : a == CR_ACTION_PROVISION_IDENTITY ? "provision-identity"
                                               : "?";
}

static void hex(const uint8_t *p, size_t n, char *o)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        o[2 * i] = H[p[i] >> 4];
        o[2 * i + 1] = H[p[i] & 15];
    }
    o[2 * n] = 0;
}

size_t rc_marker_challenge(char *out, size_t cap, const struct rc_record *r, uint8_t action)
{
    uint8_t ch[32];
    char h[65];
    if (!out || !cap || !rc_challenge(r, action, ch)) return 0;
    hex(ch, 32, h);
    return fin(out, cap, snprintf(out, cap, "RECOVERY_CHALLENGE: action=%s challenge=%s", action_name(action), h));
}

size_t rc_marker_refused(char *out, size_t cap, int rc, int cr_outcome)
{
    if (!out || !cap) return 0;
    if (rc == RC_CONTINUITY)
        return fin(out, cap, snprintf(out, cap, "RECOVERY_REFUSED (Continuity(%s))", cr_outcome_name(cr_outcome)));
    return fin(out, cap, snprintf(out, cap, "RECOVERY_REFUSED (%s)", rc_outcome_name(rc)));
}

size_t rc_marker_done(char *out, size_t cap, uint8_t action, const uint8_t *agent)
{
    char h[65];
    if (!out || !cap) return 0;
    if (!agent) return fin(out, cap, snprintf(out, cap, "RECOVERY_ACTION: %s DONE", action_name(action)));
    hex(agent, 32, h);
    return fin(out, cap, snprintf(out, cap, "RECOVERY_ACTION: %s DONE agent=%s", action_name(action), h));
}
