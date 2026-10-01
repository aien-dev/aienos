/* M5 owner-signed migration record: Ed25519 (native/sig) over a 208-byte
 * body that binds source and destination store, agent root, source store
 * generation, store format version, the set of migrated envelope ObjectIds,
 * the MAC'd migration manifest and a monotonic migration counter.
 * No heap, clock or I/O. Layout: m5.h. */
#include "m5_internal.h"
#include "../argus/sha256.h"
#include "../sig/aienos_sig.h"

#define OMG_DOMAIN "AIENOS-M5-OWNER-MIGRATION-V1"
#define ENVSET_DOMAIN "AIENOS-M5-ENVSET-V1"
#define OMG_SIG_OFF M5_OWNER_MIG_BODY_LEN

int m5_envelope_set_digest(const uint8_t (*ids)[32], uint32_t n, uint8_t out[32])
{
    if (!out || (!ids && n)) return M5_ERR_ARG;
    for (uint32_t i = 1; i < n; i++) {
        if (memcmp(ids[i - 1], ids[i], 32) >= 0) return M5_ERR_FORMAT; /* GUARD:osig-envset-order */
    }
    uint8_t cnt[4];
    m5_put32(cnt, n);
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)ENVSET_DOMAIN, sizeof(ENVSET_DOMAIN));
    sha256_update(&c, cnt, 4);
    for (uint32_t i = 0; i < n; i++) sha256_update(&c, ids[i], 32);
    sha256_final(&c, out);
    return M5_OK;
}

static void omg_encode(const m5_owner_migration *m, const uint8_t key_id[32], uint8_t *out)
{
    memset(out, 0, M5_OWNER_MIG_LEN);
    memcpy(out, "AIENOMG1", 8);
    m5_put16(out + 8, 1);
    out[12] = m->identity_class;
    memcpy(out + 16, key_id, 32);
    memcpy(out + 48, m->agent_root_id, 32);
    memcpy(out + 80, m->source_store_uuid, 16);
    memcpy(out + 96, m->dest_store_uuid, 16);
    m5_put64(out + 112, m->source_store_generation);
    m5_put32(out + 120, m->store_format_version);
    m5_put32(out + 124, m->envelope_count);
    memcpy(out + 128, m->envelope_set_digest, 32);
    memcpy(out + 160, m->migration_manifest_digest, 32);
    m5_put64(out + 192, m->migration_counter);
    m5_put64(out + 200, m->owner_hierarchy_generation);
}

static void omg_decode(const uint8_t *b, m5_owner_migration *m)
{
    m->identity_class = b[12];
    memcpy(m->owner_key_id, b + 16, 32);
    memcpy(m->agent_root_id, b + 48, 32);
    memcpy(m->source_store_uuid, b + 80, 16);
    memcpy(m->dest_store_uuid, b + 96, 16);
    m->source_store_generation = m5_get64(b + 112);
    m->store_format_version = m5_get32(b + 120);
    m->envelope_count = m5_get32(b + 124);
    memcpy(m->envelope_set_digest, b + 128, 32);
    memcpy(m->migration_manifest_digest, b + 160, 32);
    m->migration_counter = m5_get64(b + 192);
    m->owner_hierarchy_generation = m5_get64(b + 200);
}

/* Magic, version, flags, reserved bytes and class. */
static int omg_check_format(const uint8_t *b)
{
    if (memcmp(b, "AIENOMG1", 8) != 0) return M5_ERR_FORMAT; /* GUARD:osig-magic */
    if (m5_get16(b + 8) != 1 || m5_get16(b + 10) != 0) return M5_ERR_FORMAT; /* GUARD:osig-version */
    if (!m5_all_zero(b + 13, 3)) return M5_ERR_FORMAT; /* GUARD:osig-reserved */
    if (!m5_valid_class(b[12])) return M5_ERR_FORMAT;
    return M5_OK;
}

/* Signed message: domain (with its NUL) || body[0..208]. */
#define OMG_MSG_LEN (sizeof(OMG_DOMAIN) + M5_OWNER_MIG_BODY_LEN)
static void omg_message(const uint8_t *rec, uint8_t msg[OMG_MSG_LEN])
{
    memcpy(msg, OMG_DOMAIN, sizeof(OMG_DOMAIN));
    memcpy(msg + sizeof(OMG_DOMAIN), rec, M5_OWNER_MIG_BODY_LEN);
}

int m5_owner_migration_body(const m5_owner_migration *m, const uint8_t owner_pk[32],
                            uint8_t out[M5_OWNER_MIG_LEN])
{
    if (!m || !owner_pk || !out) return M5_ERR_ARG;
    if (!m5_valid_class(m->identity_class)) return M5_ERR_ARG;
    uint8_t key_id[32];
    sha256_hash(owner_pk, 32, key_id);
    omg_encode(m, key_id, out);
    return M5_OK;
}

int m5_owner_migration_sign_body(uint8_t rec[M5_OWNER_MIG_LEN], const uint8_t owner_sk[32])
{
    if (!rec || !owner_sk) return M5_ERR_ARG;
    int rc = omg_check_format(rec);
    if (rc != M5_OK) return rc;
    if (!m5_all_zero(rec + OMG_SIG_OFF, 64)) return M5_ERR_FORMAT; /* already signed */
    uint8_t pk[32], key_id[32], msg[OMG_MSG_LEN];
    if (aienos_ed25519_public_key(pk, owner_sk) != AIENOS_SIG_OK) return M5_ERR_ARG;
    sha256_hash(pk, 32, key_id);
    if (!aienos_ct_equal(key_id, rec + 16, 32)) return M5_ERR_BINDING;
    omg_message(rec, msg);
    if (aienos_ed25519_sign(rec + OMG_SIG_OFF, msg, sizeof msg, owner_sk) != AIENOS_SIG_OK) {
        aienos_wipe(rec + OMG_SIG_OFF, 64);
        return M5_ERR_ARG;
    }
    return M5_OK;
}

int m5_owner_migration_sign(const m5_owner_migration *m, const uint8_t owner_sk[32],
                            uint8_t out[M5_OWNER_MIG_LEN])
{
    if (!m || !owner_sk || !out) return M5_ERR_ARG;
    uint8_t pk[32];
    if (aienos_ed25519_public_key(pk, owner_sk) != AIENOS_SIG_OK) return M5_ERR_ARG;
    int rc = m5_owner_migration_body(m, pk, out);
    if (rc == M5_OK) rc = m5_owner_migration_sign_body(out, owner_sk);
    if (rc != M5_OK) memset(out, 0, M5_OWNER_MIG_LEN);
    return rc;
}

int m5_owner_migration_verify(const uint8_t *b, size_t len, const uint8_t owner_pk[32],
                              uint8_t mode, const m5_owner_migration *e,
                              uint64_t last_migration_counter, m5_owner_migration *m)
{
    if (!b || !owner_pk || !e || !m) return M5_ERR_ARG;
    memset(m, 0, sizeof *m);
    if (len != M5_OWNER_MIG_LEN) return M5_ERR_BOUNDS; /* GUARD:osig-len */
    int rc = omg_check_format(b);
    if (rc != M5_OK) return rc;
    if (b[12] != mode || e->identity_class != mode) return M5_ERR_IDENTITY; /* GUARD:osig-class */
    uint8_t key_id[32], msg[OMG_MSG_LEN];
    sha256_hash(owner_pk, 32, key_id);
    if (!aienos_ct_equal(key_id, b + 16, 32)) return M5_ERR_AUTH; /* GUARD:osig-keyid */
    omg_message(b, msg);
    if (aienos_ed25519_verify(b + OMG_SIG_OFF, msg, sizeof msg, owner_pk) != AIENOS_SIG_OK) return M5_ERR_AUTH; /* GUARD:osig-sig */
    omg_decode(b, m);
    if (rc == M5_OK && memcmp(m->source_store_uuid, m->dest_store_uuid, 16) == 0) rc = M5_ERR_BINDING; /* GUARD:osig-self */
    if (rc == M5_OK && memcmp(m->source_store_uuid, e->source_store_uuid, 16) != 0) rc = M5_ERR_BINDING; /* GUARD:osig-source */
    if (rc == M5_OK && memcmp(m->dest_store_uuid, e->dest_store_uuid, 16) != 0) rc = M5_ERR_BINDING; /* GUARD:osig-dest */
    if (rc == M5_OK && memcmp(m->agent_root_id, e->agent_root_id, 32) != 0) rc = M5_ERR_BINDING; /* GUARD:osig-agent */
    if (rc == M5_OK && m->source_store_generation != e->source_store_generation) rc = M5_ERR_BINDING; /* GUARD:osig-gen */
    if (rc == M5_OK && m->store_format_version != e->store_format_version) rc = M5_ERR_BINDING; /* GUARD:osig-format */
    if (rc == M5_OK && m->envelope_count != e->envelope_count) rc = M5_ERR_BINDING; /* GUARD:osig-envcount */
    if (rc == M5_OK && !aienos_ct_equal(m->envelope_set_digest, e->envelope_set_digest, 32)) rc = M5_ERR_BINDING; /* GUARD:osig-envset */
    if (rc == M5_OK && !aienos_ct_equal(m->migration_manifest_digest, e->migration_manifest_digest, 32)) rc = M5_ERR_BINDING; /* GUARD:osig-manifest */
    if (rc == M5_OK && m->owner_hierarchy_generation != e->owner_hierarchy_generation) rc = M5_ERR_BINDING; /* GUARD:osig-ownergen */
    if (rc == M5_OK && m->migration_counter <= last_migration_counter) rc = M5_ERR_REPLAY; /* GUARD:osig-replay */
    if (rc != M5_OK) memset(m, 0, sizeof *m);
    return rc;
}

int m5_migration_authorize_owner(const uint8_t *mig_buf, size_t mig_len,
                                 const uint8_t k_root_auth[32],
                                 const uint8_t *own_buf, size_t own_len,
                                 const uint8_t owner_pk[32], uint8_t mode,
                                 const m5_migration *em, const m5_owner_migration *eo,
                                 uint64_t last_migration_counter,
                                 m5_migration *out_mig, m5_owner_migration *out_own)
{
    if (!mig_buf || !k_root_auth || !own_buf || !owner_pk || !em || !eo || !out_mig || !out_own)
        return M5_ERR_ARG;
    memset(out_mig, 0, sizeof *out_mig);
    memset(out_own, 0, sizeof *out_own);
    int rc = m5_migration_authorize(mig_buf, mig_len, k_root_auth, mode, em,
                                    last_migration_counter, out_mig);
    if (rc != M5_OK) return rc;
    /* The owner record must name this exact manifest and agree with it. */
    m5_owner_migration e;
    memset(&e, 0, sizeof e);
    e.identity_class = out_mig->identity_class;
    memcpy(e.agent_root_id, out_mig->agent_root_id, 32);
    memcpy(e.source_store_uuid, out_mig->source_store_uuid, 16);
    memcpy(e.dest_store_uuid, out_mig->dest_store_uuid, 16);
    e.source_store_generation = out_mig->source_store_generation;
    e.store_format_version = eo->store_format_version;
    e.envelope_count = eo->envelope_count;
    memcpy(e.envelope_set_digest, eo->envelope_set_digest, 32);
    sha256_hash(mig_buf, M5_MIGRATION_LEN, e.migration_manifest_digest); /* GUARD:osig-bind-manifest */
    e.owner_hierarchy_generation = out_mig->owner_hierarchy_generation;
    rc = m5_owner_migration_verify(own_buf, own_len, owner_pk, mode, &e,
                                   last_migration_counter, out_own);
    if (rc == M5_OK && out_own->migration_counter != out_mig->migration_counter) rc = M5_ERR_BINDING; /* GUARD:osig-bind-counter */
    if (rc != M5_OK) {
        memset(out_mig, 0, sizeof *out_mig);
        memset(out_own, 0, sizeof *out_own);
    }
    return rc;
}
