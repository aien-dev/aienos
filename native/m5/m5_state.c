/* M5 commit record, anti-rollback anchor, migration manifest and
 * deterministic recovery. Port of security.rs sections 4-5 (C v2 layouts). */
#include "m5_internal.h"
#include "../argus/sha256.h"

/* ---- commit record (written after sealing) ----
 * 0 "AIENCMT1" | 8 version u16 = 2 | 10 identity_class | 11 reserved | 12 kind u16
 * | 14 object_version u16 | 16 store_uuid | 32 envelope_id[16] | 48 store_generation
 * | 56 key_generation | 64 counter | 72 object_sequence | 80 object_id[32]
 * | 112 mac = HMAC(k_root_auth, "AIENOS-M5-COMMIT-V2\0" || bytes[0..112])
 * object_id is SHA-256 of the sealed envelope, so Store generation and the
 * ObjectId are bound here, after sealing, never inside the envelope. */
#define COMMIT_DOMAIN "AIENOS-M5-COMMIT-V2"
#define COMMIT_MAC_OFF 112

int m5_commit_seal(const m5_commit *c, const uint8_t k_root_auth[32], uint8_t out[M5_COMMIT_LEN])
{
    if (!c || !k_root_auth || !out) return M5_ERR_ARG;
    if (!m5_valid_class(c->obj.identity_class)) return M5_ERR_ARG;
    memset(out, 0, M5_COMMIT_LEN);
    memcpy(out, "AIENCMT1", 8);
    m5_put16(out + 8, 2);
    out[10] = c->obj.identity_class;
    m5_put16(out + 12, c->obj.object_kind);
    m5_put16(out + 14, c->obj.object_version);
    memcpy(out + 16, c->obj.store_uuid, 16);
    memcpy(out + 32, c->obj.envelope_id, 16);
    m5_put64(out + 48, c->store_generation);
    m5_put64(out + 56, c->obj.key_generation);
    m5_put64(out + 64, c->counter);
    m5_put64(out + 72, c->object_sequence);
    memcpy(out + 80, c->object_id, 32);
    m5_mac(k_root_auth, COMMIT_DOMAIN, sizeof(COMMIT_DOMAIN), out, COMMIT_MAC_OFF, out + COMMIT_MAC_OFF);
    return M5_OK;
}

int m5_commit_open(const uint8_t *b, size_t len, const uint8_t k_root_auth[32],
                   uint8_t mode, m5_commit *c)
{
    if (!b || !k_root_auth || !c) return M5_ERR_ARG;
    memset(c, 0, sizeof *c);
    if (len != M5_COMMIT_LEN) return M5_ERR_BOUNDS;
    if (memcmp(b, "AIENCMT1", 8) != 0 || m5_get16(b + 8) != 2 || b[11] != 0) return M5_ERR_FORMAT;
    if (!m5_valid_class(b[10])) return M5_ERR_FORMAT;
    uint8_t mac[32];
    m5_mac(k_root_auth, COMMIT_DOMAIN, sizeof(COMMIT_DOMAIN), b, COMMIT_MAC_OFF, mac);
    int ok = aienos_ct_equal(mac, b + COMMIT_MAC_OFF, 32);
    if (!ok) return M5_ERR_AUTH; /* GUARD:commit-mac */
    if (b[10] != mode) return M5_ERR_IDENTITY; /* GUARD:commit-class */
    c->obj.identity_class = b[10];
    c->obj.object_kind = m5_get16(b + 12);
    c->obj.object_version = m5_get16(b + 14);
    memcpy(c->obj.store_uuid, b + 16, 16);
    memcpy(c->obj.envelope_id, b + 32, 16);
    c->store_generation = m5_get64(b + 48);
    c->obj.key_generation = m5_get64(b + 56);
    c->counter = m5_get64(b + 64);
    c->object_sequence = m5_get64(b + 72);
    memcpy(c->object_id, b + 80, 32);
    return M5_OK;
}

int m5_commit_check_object(const m5_commit *c, const uint8_t *env, size_t env_len)
{
    if (!c || !env) return M5_ERR_ARG;
    uint8_t dg[32];
    sha256_hash(env, env_len, dg);
    if (!aienos_ct_equal(dg, c->object_id, 32)) return M5_ERR_TORN; /* GUARD:commit-objid */
    m5_env_header h;
    int rc = m5_envelope_parse_header(env, env_len, &h);
    if (rc != M5_OK) return rc;
    if (memcmp(h.envelope_id, c->obj.envelope_id, 16) != 0) return M5_ERR_BINDING; /* GUARD:commit-envid */
    if (h.key_epoch != c->obj.key_generation) return M5_ERR_BINDING; /* GUARD:commit-keygen */
    return M5_OK;
}

/* ---- anti-rollback anchor ----
 * 0 "AIENRBA1" | 8 version u16 = 1 | 10 identity_class | 11..16 reserved
 * | 16 store_uuid | 32 store_generation | 40 key_generation | 48 counter
 * | 56 commit_digest[32] | 88 mac = HMAC(k_root_auth, "AIENOS-M5-ANCHOR-V1\0" || bytes[0..88]) */
#define ANCHOR_DOMAIN "AIENOS-M5-ANCHOR-V1"
#define ANCHOR_MAC_OFF 88

int m5_anchor_seal(const m5_anchor *a, const uint8_t k_root_auth[32], uint8_t *out, size_t out_len)
{
    if (!a || !k_root_auth || !out) return M5_ERR_ARG;
    if (out_len < M5_ANCHOR_LEN) return M5_ERR_SPACE;
    if (!m5_valid_class(a->identity_class)) return M5_ERR_ARG;
    memset(out, 0, M5_ANCHOR_LEN);
    memcpy(out, "AIENRBA1", 8);
    m5_put16(out + 8, 1);
    out[10] = a->identity_class;
    memcpy(out + 16, a->store_uuid, 16);
    m5_put64(out + 32, a->store_generation);
    m5_put64(out + 40, a->key_generation);
    m5_put64(out + 48, a->counter);
    memcpy(out + 56, a->commit_digest, 32);
    m5_mac(k_root_auth, ANCHOR_DOMAIN, sizeof(ANCHOR_DOMAIN), out, ANCHOR_MAC_OFF, out + ANCHOR_MAC_OFF);
    return M5_OK;
}

int m5_anchor_open(const uint8_t *b, size_t len, const uint8_t k_root_auth[32],
                   uint8_t mode, m5_anchor *a)
{
    if (!b || !k_root_auth || !a) return M5_ERR_ARG;
    memset(a, 0, sizeof *a);
    if (len != M5_ANCHOR_LEN) return M5_ERR_BOUNDS;
    if (memcmp(b, "AIENRBA1", 8) != 0 || m5_get16(b + 8) != 1) return M5_ERR_FORMAT;
    if (!m5_all_zero(b + 11, 5) || !m5_valid_class(b[10])) return M5_ERR_FORMAT;
    uint8_t mac[32];
    m5_mac(k_root_auth, ANCHOR_DOMAIN, sizeof(ANCHOR_DOMAIN), b, ANCHOR_MAC_OFF, mac);
    if (!aienos_ct_equal(mac, b + ANCHOR_MAC_OFF, 32)) return M5_ERR_AUTH; /* GUARD:anchor-mac */
    if (b[10] != mode) return M5_ERR_IDENTITY; /* GUARD:anchor-class */
    a->identity_class = b[10];
    memcpy(a->store_uuid, b + 16, 16);
    a->store_generation = m5_get64(b + 32);
    a->key_generation = m5_get64(b + 40);
    a->counter = m5_get64(b + 48);
    memcpy(a->commit_digest, b + 56, 32);
    return M5_OK;
}

int m5_evaluate_anti_rollback(const uint8_t k_root_auth[32], uint8_t mode,
                              const uint8_t store_uuid[16],
                              const uint8_t *anchor_buf, size_t anchor_len,
                              int allow_genesis, const m5_disk_state *d)
{
    if (!k_root_auth || !store_uuid || !d) return M5_ERR_ARG;
    if (anchor_len == 0) return allow_genesis ? M5_RB_GENESIS : M5_ERR_ROLLBACK; /* GUARD:anchor-missing */
    if (!anchor_buf) return M5_ERR_ARG;
    m5_anchor a;
    int rc = m5_anchor_open(anchor_buf, anchor_len, k_root_auth, mode, &a);
    if (rc != M5_OK) return rc;
    if (memcmp(a.store_uuid, store_uuid, 16) != 0) return M5_ERR_BINDING; /* GUARD:anchor-store */
    if (d->store_generation < a.store_generation) return M5_ERR_ROLLBACK; /* GUARD:rb-storegen */
    if (d->key_generation < a.key_generation) return M5_ERR_ROLLBACK; /* GUARD:rb-keygen */
    if (d->counter < a.counter) return M5_ERR_ROLLBACK; /* GUARD:rb-counter */
    if (d->counter == a.counter) {
        int same = aienos_ct_equal(d->commit_digest, a.commit_digest, 32) &&
                   d->store_generation == a.store_generation &&
                   d->key_generation == a.key_generation;
        return same ? M5_RB_VALID_RESUME : M5_ERR_ROLLBACK; /* fork at the anchored counter */
    }
    if (d->counter - a.counter == 1) return M5_RB_PREPARED_ADVANCE; /* d > a here: no wrap */
    return M5_ERR_INCONSISTENT;
}

/* ---- migration manifest ----
 * 0 "AIENMIG1" | 8 version u16 = 2 | 10 flags u16 = 0 | 12 identity_class | 13..16 reserved
 * | 16 agent_root_id[32] | 48 genesis_store_uuid | 64 source_store_uuid | 80 dest_store_uuid
 * | 96 source_store_generation | 104 source_anchor_counter | 112 migration_counter
 * | 120 owner_hierarchy_generation | 128 source_commit_digest[32]
 * | 160 mac = HMAC(k_root_auth(source), "AIENOS-M5-MIGRATION-V2\0" || bytes[0..160]) */
#define MIG_DOMAIN "AIENOS-M5-MIGRATION-V2"
#define MIG_MAC_OFF 160

int m5_migration_seal(const m5_migration *m, const uint8_t k_root_auth[32], uint8_t out[M5_MIGRATION_LEN])
{
    if (!m || !k_root_auth || !out) return M5_ERR_ARG;
    if (!m5_valid_class(m->identity_class)) return M5_ERR_ARG;
    memset(out, 0, M5_MIGRATION_LEN);
    memcpy(out, "AIENMIG1", 8);
    m5_put16(out + 8, 2);
    out[12] = m->identity_class;
    memcpy(out + 16, m->agent_root_id, 32);
    memcpy(out + 48, m->genesis_store_uuid, 16);
    memcpy(out + 64, m->source_store_uuid, 16);
    memcpy(out + 80, m->dest_store_uuid, 16);
    m5_put64(out + 96, m->source_store_generation);
    m5_put64(out + 104, m->source_anchor_counter);
    m5_put64(out + 112, m->migration_counter);
    m5_put64(out + 120, m->owner_hierarchy_generation);
    memcpy(out + 128, m->source_commit_digest, 32);
    m5_mac(k_root_auth, MIG_DOMAIN, sizeof(MIG_DOMAIN), out, MIG_MAC_OFF, out + MIG_MAC_OFF);
    return M5_OK;
}

int m5_migration_authorize(const uint8_t *b, size_t len, const uint8_t k_root_auth[32],
                           uint8_t mode, const m5_migration *e,
                           uint64_t last_migration_counter, m5_migration *m)
{
    if (!b || !k_root_auth || !e || !m) return M5_ERR_ARG;
    memset(m, 0, sizeof *m);
    if (len != M5_MIGRATION_LEN) return M5_ERR_BOUNDS;
    if (memcmp(b, "AIENMIG1", 8) != 0 || m5_get16(b + 8) != 2 || m5_get16(b + 10) != 0)
        return M5_ERR_FORMAT;
    if (!m5_all_zero(b + 13, 3) || !m5_valid_class(b[12])) return M5_ERR_FORMAT;
    uint8_t mac[32];
    m5_mac(k_root_auth, MIG_DOMAIN, sizeof(MIG_DOMAIN), b, MIG_MAC_OFF, mac);
    if (!aienos_ct_equal(mac, b + MIG_MAC_OFF, 32)) return M5_ERR_AUTH; /* GUARD:mig-mac */
    if (b[12] != mode || e->identity_class != mode) return M5_ERR_IDENTITY; /* GUARD:mig-class */
    m->identity_class = b[12];
    memcpy(m->agent_root_id, b + 16, 32);
    memcpy(m->genesis_store_uuid, b + 48, 16);
    memcpy(m->source_store_uuid, b + 64, 16);
    memcpy(m->dest_store_uuid, b + 80, 16);
    m->source_store_generation = m5_get64(b + 96);
    m->source_anchor_counter = m5_get64(b + 104);
    m->migration_counter = m5_get64(b + 112);
    m->owner_hierarchy_generation = m5_get64(b + 120);
    memcpy(m->source_commit_digest, b + 128, 32);
    int rc = M5_OK;
    if (rc == M5_OK && memcmp(m->source_store_uuid, m->dest_store_uuid, 16) == 0) rc = M5_ERR_BINDING; /* GUARD:mig-self */
    if (rc == M5_OK && memcmp(m->source_store_uuid, e->source_store_uuid, 16) != 0) rc = M5_ERR_BINDING; /* GUARD:mig-source */
    if (rc == M5_OK && memcmp(m->dest_store_uuid, e->dest_store_uuid, 16) != 0) rc = M5_ERR_BINDING; /* GUARD:mig-dest */
    if (rc == M5_OK && memcmp(m->agent_root_id, e->agent_root_id, 32) != 0) rc = M5_ERR_BINDING;
    if (rc == M5_OK && memcmp(m->genesis_store_uuid, e->genesis_store_uuid, 16) != 0) rc = M5_ERR_BINDING;
    if (rc == M5_OK && m->source_store_generation != e->source_store_generation) rc = M5_ERR_BINDING; /* GUARD:mig-gen */
    if (rc == M5_OK && m->source_anchor_counter != e->source_anchor_counter) rc = M5_ERR_BINDING; /* GUARD:mig-anchor */
    if (rc == M5_OK && m->owner_hierarchy_generation != e->owner_hierarchy_generation) rc = M5_ERR_BINDING;
    if (rc == M5_OK && !aienos_ct_equal(m->source_commit_digest, e->source_commit_digest, 32)) rc = M5_ERR_BINDING; /* GUARD:mig-digest */
    if (rc == M5_OK && m->migration_counter <= last_migration_counter) rc = M5_ERR_REPLAY; /* GUARD:mig-replay */
    if (rc != M5_OK) memset(m, 0, sizeof *m);
    return rc;
}

/* ---- deterministic recovery ---- */

int m5_recover_object(const uint8_t k_root_auth[32], const uint8_t domain_key[32],
                      uint8_t mode, const uint8_t store_uuid[16],
                      const uint8_t *commit_buf, size_t commit_len,
                      const uint8_t *anchor_buf, size_t anchor_len,
                      const m5_candidate *cands, size_t n_cands,
                      uint8_t *out, size_t out_cap, size_t *out_len, size_t *chosen)
{
    if (out && out_cap) aienos_wipe(out, out_cap);
    if (out_len) *out_len = 0;
    if (chosen) *chosen = SIZE_MAX;
    if (!k_root_auth || !domain_key || !store_uuid || !commit_buf || !out_len || !chosen ||
        (!cands && n_cands) || (!out && out_cap))
        return M5_ERR_ARG;

    m5_commit c;
    int rc = m5_commit_open(commit_buf, commit_len, k_root_auth, mode, &c);
    if (rc != M5_OK) return rc;
    if (memcmp(c.obj.store_uuid, store_uuid, 16) != 0) return M5_ERR_BINDING; /* GUARD:rec-store */

    m5_disk_state d;
    d.store_generation = c.store_generation;
    d.key_generation = c.obj.key_generation;
    d.counter = c.counter;
    sha256_hash(commit_buf, M5_COMMIT_LEN, d.commit_digest);
    rc = m5_evaluate_anti_rollback(k_root_auth, mode, store_uuid, anchor_buf, anchor_len, 0, &d);
    if (rc < 0) return rc;

    /* The commit record is the only authority. Scan every candidate (order
     * independent): exact digest matches are the committed version; any other
     * copy that claims the committed object version is a conflict. */
    size_t first = SIZE_MAX;
    int conflict = 0;
    for (size_t i = 0; i < n_cands; i++) {
        if (!cands[i].bytes) continue;
        uint8_t dg[32];
        sha256_hash(cands[i].bytes, cands[i].len, dg);
        if (aienos_ct_equal(dg, c.object_id, 32)) {
            if (first == SIZE_MAX) first = i;
            continue;
        }
        /* Raw header fields only: a torn copy still names the object it claims. */
        if (cands[i].len >= 60 && memcmp(cands[i].bytes, "AIENENV1", 8) == 0 &&
            memcmp(cands[i].bytes + 28, c.obj.envelope_id, 16) == 0 &&
            m5_get64(cands[i].bytes + 52) == c.obj.key_generation)
            conflict = 1;
    }
    if (first == SIZE_MAX) return M5_ERR_TORN; /* GUARD:rec-torn */
    if (conflict) return M5_ERR_AMBIGUOUS; /* GUARD:rec-conflict */

    rc = m5_envelope_open(domain_key, mode, &c.obj, cands[first].bytes, cands[first].len,
                          out, out_cap, out_len);
    if (rc != M5_OK) return rc;
    *chosen = first;
    return M5_OK;
}
