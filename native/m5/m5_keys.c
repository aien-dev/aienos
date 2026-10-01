/* M5 key hierarchy: HKDF-Expand, subkeys, per-object keys, keyslots,
 * SecurityManifest. Port of security.rs sections 1-3. */
#include "m5_internal.h"

void m5_mac(const uint8_t key[32], const char *domain, size_t domain_len,
            const uint8_t *body, size_t body_len, uint8_t out[32])
{
    aienos_hmac_sha256_ctx c;
    aienos_hmac_sha256_init(&c, key);
    aienos_hmac_sha256_update(&c, (const uint8_t *)domain, domain_len);
    aienos_hmac_sha256_update(&c, body, body_len);
    aienos_hmac_sha256_final(&c, out);
}

int m5_hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                   uint8_t *out, size_t out_len)
{
    if (!prk || (!info && info_len) || (!out && out_len)) return M5_ERR_ARG;
    if (out_len > 255 * 32) return M5_ERR_BOUNDS;
    uint8_t t[32];
    size_t t_len = 0, written = 0;
    for (unsigned counter = 1; written < out_len; counter++) {
        aienos_hmac_sha256_ctx c;
        uint8_t ctr = (uint8_t)counter;
        aienos_hmac_sha256_init(&c, prk);
        aienos_hmac_sha256_update(&c, t, t_len);
        aienos_hmac_sha256_update(&c, info, info_len);
        aienos_hmac_sha256_update(&c, &ctr, 1);
        aienos_hmac_sha256_final(&c, t);
        t_len = 32;
        size_t n = out_len - written < 32 ? out_len - written : 32;
        memcpy(out + written, t, n);
        written += n;
    }
    aienos_wipe(t, sizeof t);
    return M5_OK;
}

#define LBL(s) (const uint8_t *)(s), sizeof(s) - 1

void m5_derive_subkeys_v1(const uint8_t k_vol[32], m5_subkeys *out)
{
    m5_hkdf_expand(k_vol, LBL("AIENOS/M5/CORTEX-V1"), out->k_cortex, 32);
    m5_hkdf_expand(k_vol, LBL("AIENOS/M5/AGENT-STATE-V1"), out->k_agent, 32);
    m5_hkdf_expand(k_vol, LBL("AIENOS/M5/ARTIFACT-V1"), out->k_artifact, 32);
    m5_hkdf_expand(k_vol, LBL("AIENOS/M5/ROOT-AUTH-V1"), out->k_root_auth, 32);
}

#define OWNER_LABEL "AIENOS/M5/OWNER-HIERARCHY-V2"

int m5_derive_subkeys(const uint8_t k_vol[32], uint8_t identity_class,
                      uint64_t owner_hierarchy_generation, m5_subkeys *out)
{
    if (!k_vol || !out) return M5_ERR_ARG;
    if (!m5_valid_class(identity_class)) { aienos_wipe(out, sizeof *out); return M5_ERR_ARG; }
    uint8_t info[sizeof(OWNER_LABEL) + 1 + 8];
    memset(info, 0, sizeof info);
    memcpy(info, OWNER_LABEL, sizeof(OWNER_LABEL)); /* includes the NUL separator */
    info[sizeof(OWNER_LABEL)] = identity_class; /* GUARD:class-in-kdf */
    m5_put64(info + sizeof(OWNER_LABEL) + 1, owner_hierarchy_generation);
    uint8_t k_class[32];
    m5_hkdf_expand(k_vol, info, sizeof info, k_class, 32);
    m5_derive_subkeys_v1(k_class, out);
    aienos_wipe(k_class, sizeof k_class);
    return M5_OK;
}

void m5_subkeys_wipe(m5_subkeys *k) { aienos_wipe(k, sizeof *k); }

#define OBJECT_LABEL "AIENOS/M5/OBJECT-KEY-V2"

int m5_derive_object_key(const uint8_t domain_key[32], const m5_object_binding *b, uint8_t out[32])
{
    if (!domain_key || !b || !out) return M5_ERR_ARG;
    uint8_t info[sizeof(OBJECT_LABEL) + 16 + 2 + 2 + 16 + 8 + 8 + 1];
    uint8_t *p = info;
    memcpy(p, OBJECT_LABEL, sizeof(OBJECT_LABEL)); p += sizeof(OBJECT_LABEL);
    memcpy(p, b->store_uuid, 16); p += 16;
    m5_put16(p, b->object_kind); p += 2;
    m5_put16(p, b->object_version); p += 2;
    memcpy(p, b->object_id, 16); p += 16;
    m5_put64(p, b->key_generation); p += 8;
    m5_put64(p, b->store_generation); p += 8;
    *p = b->identity_class;
    return m5_hkdf_expand(domain_key, info, sizeof info, out, 32);
}

/* ---- keyslots ---- */

void m5_keyslot_encode(const m5_keyslot *s, uint8_t out[M5_KEYSLOT_LEN])
{
    memset(out, 0, M5_KEYSLOT_LEN);
    out[0] = s->slot_type; out[1] = s->wrap_suite; out[2] = s->kdf_suite; out[3] = s->flags;
    m5_put32(out + 4, s->slot_id);
    m5_put64(out + 8, s->key_epoch);
    memcpy(out + 16, s->salt, 16);
    m5_put32(out + 32, s->argon_m_kib);
    m5_put32(out + 36, s->argon_t_cost);
    m5_put32(out + 40, s->argon_p_cost);
    memcpy(out + 44, s->wrap_nonce, 12);
    memcpy(out + 56, s->wrapped_k_vol, 32);
    memcpy(out + 88, s->wrap_tag, 16);
    m5_put32(out + 104, s->payload_offset);
    m5_put32(out + 108, s->payload_length);
}

/* Value checks shared by decode and unwrap, so a struct built in memory
 * cannot bypass what the serialized form would be refused for. */
static int keyslot_check(const m5_keyslot *s)
{
    if (s->slot_type > M5_SLOT_RECOVERY_RAW_SECRET) return M5_ERR_FORMAT;
    if (s->argon_m_kib > 131072 || s->argon_t_cost > 10 || s->argon_p_cost > 16) return M5_ERR_BOUNDS;
    /* ADR 0017: wrap_suite 0x01 only (an Empty slot may hold 0), kdf_suite
     * 0x00..0x02, no flag bits defined. */
    if (s->slot_type != M5_SLOT_EMPTY && s->wrap_suite != M5_WRAP_SUITE_GCMSIV) return M5_ERR_FORMAT; /* GUARD:slot-suite */
    if (s->slot_type == M5_SLOT_EMPTY && s->wrap_suite > M5_WRAP_SUITE_GCMSIV) return M5_ERR_FORMAT;
    if (s->kdf_suite > 0x02) return M5_ERR_FORMAT; /* GUARD:slot-kdf */
    if (s->flags != 0) return M5_ERR_FORMAT; /* GUARD:slot-flags */
    return M5_OK;
}

int m5_keyslot_decode(const uint8_t *b, size_t len, m5_keyslot *s)
{
    if (!b || !s) return M5_ERR_ARG;
    if (len != M5_KEYSLOT_LEN) return M5_ERR_BOUNDS;
    if (b[0] > M5_SLOT_RECOVERY_RAW_SECRET) return M5_ERR_FORMAT;
    s->slot_type = b[0]; s->wrap_suite = b[1]; s->kdf_suite = b[2]; s->flags = b[3];
    s->slot_id = m5_get32(b + 4);
    s->key_epoch = m5_get64(b + 8);
    memcpy(s->salt, b + 16, 16);
    s->argon_m_kib = m5_get32(b + 32);
    s->argon_t_cost = m5_get32(b + 36);
    s->argon_p_cost = m5_get32(b + 40);
    if (keyslot_check(s) != M5_OK) return keyslot_check(s);
    memcpy(s->wrap_nonce, b + 44, 12);
    memcpy(s->wrapped_k_vol, b + 56, 32);
    memcpy(s->wrap_tag, b + 88, 16);
    s->payload_offset = m5_get32(b + 104);
    s->payload_length = m5_get32(b + 108);
    if (!m5_all_zero(b + 112, 16)) return M5_ERR_FORMAT;
    return M5_OK;
}

#define KEYSLOT_AAD_LABEL "AIENOS-M5-KEYSLOT-V2"
#define KEYSLOT_AAD_LEN (sizeof(KEYSLOT_AAD_LABEL) + 16 + 4 + 1 + 8)

static void keyslot_aad(const m5_keyslot *s, const uint8_t store_uuid[16], uint8_t aad[KEYSLOT_AAD_LEN])
{
    uint8_t *p = aad;
    memcpy(p, KEYSLOT_AAD_LABEL, sizeof(KEYSLOT_AAD_LABEL)); p += sizeof(KEYSLOT_AAD_LABEL);
    memcpy(p, store_uuid, 16); p += 16;
    m5_put32(p, s->slot_id); p += 4;
    *p++ = s->slot_type;
    m5_put64(p, s->key_epoch);
}

int m5_keyslot_wrap(m5_keyslot *s, const uint8_t store_uuid[16], const uint8_t kek[32],
                    const uint8_t k_vol[32], const uint8_t nonce[12])
{
    if (!s || !store_uuid || !kek || !k_vol || !nonce) return M5_ERR_ARG;
    if (s->slot_type == M5_SLOT_EMPTY || s->slot_type > M5_SLOT_RECOVERY_RAW_SECRET) return M5_ERR_FORMAT;
    uint8_t aad[KEYSLOT_AAD_LEN], ct[48];
    s->wrap_suite = M5_WRAP_SUITE_GCMSIV;
    memcpy(s->wrap_nonce, nonce, 12);
    keyslot_aad(s, store_uuid, aad);
    if (aienos_gcmsiv_seal(kek, nonce, aad, sizeof aad, k_vol, 32, ct, sizeof ct) != AIENOS_CRYPTO_OK)
        return M5_ERR_ARG;
    memcpy(s->wrapped_k_vol, ct, 32);
    memcpy(s->wrap_tag, ct + 32, 16);
    return M5_OK;
}

int m5_keyslot_unwrap(const m5_keyslot *s, const uint8_t store_uuid[16],
                      const uint8_t kek[32], uint8_t k_vol_out[32])
{
    if (!k_vol_out) return M5_ERR_ARG;
    memset(k_vol_out, 0, 32);
    if (!s || !store_uuid || !kek) return M5_ERR_ARG;
    if (s->slot_type == M5_SLOT_EMPTY) return M5_ERR_FORMAT; /* GUARD:slot-empty */
    if (keyslot_check(s) != M5_OK) return keyslot_check(s); /* GUARD:slot-check */
    if (s->wrap_suite != M5_WRAP_SUITE_GCMSIV) return M5_ERR_FORMAT;
    uint8_t aad[KEYSLOT_AAD_LEN], ct[48];
    keyslot_aad(s, store_uuid, aad);
    memcpy(ct, s->wrapped_k_vol, 32);
    memcpy(ct + 32, s->wrap_tag, 16);
    if (aienos_gcmsiv_open(kek, s->wrap_nonce, aad, sizeof aad, ct, sizeof ct, k_vol_out, 32) != AIENOS_CRYPTO_OK) {
        aienos_wipe(k_vol_out, 32);
        return M5_ERR_AUTH;
    }
    return M5_OK;
}

/* ---- SecurityManifest (C v2) ----
 * 0 magic "AIENSEC2" (distinct from Rust kind-22 "AIENSEC1") | 8 version u16 = 2 | 10 flags u16 = 0 | 12 identity_class u8
 * | 13..16 reserved | 16 store_uuid | 32 generation | 40 security_sequence
 * | 48 epoch | 56 key_epoch | 64 prev id | 96 keyslot id | 128 agent_root id
 * | 160 continuity id | 192 migration id | 224 owner_hierarchy_generation
 * | 232 root_mac (HMAC(k_root_auth, "AIENOS-M5-ROOT-AUTH-V2\0" || bytes[0..232])) */
#define SECMAN_MAC_OFF 232
#define ROOT_AUTH_DOMAIN "AIENOS-M5-ROOT-AUTH-V2"

static void secman_encode_body(const m5_secman *m, uint8_t out[M5_SECMAN_LEN])
{
    memset(out, 0, M5_SECMAN_LEN);
    memcpy(out, "AIENSEC2", 8);
    m5_put16(out + 8, 2);
    out[12] = m->identity_class;
    memcpy(out + 16, m->store_uuid, 16);
    m5_put64(out + 32, m->generation);
    m5_put64(out + 40, m->security_sequence);
    m5_put64(out + 48, m->epoch);
    m5_put64(out + 56, m->key_epoch);
    memcpy(out + 64, m->previous_security_manifest_id, 32);
    memcpy(out + 96, m->keyslot_manifest_id, 32);
    memcpy(out + 128, m->agent_root_id, 32);
    memcpy(out + 160, m->continuity_manifest_id, 32);
    memcpy(out + 192, m->migration_manifest_id, 32);
    m5_put64(out + 224, m->owner_hierarchy_generation);
}

int m5_secman_seal(m5_secman *m, const uint8_t k_root_auth[32], uint8_t out[M5_SECMAN_LEN])
{
    if (!m || !k_root_auth || !out) return M5_ERR_ARG;
    if (!m5_valid_class(m->identity_class)) return M5_ERR_ARG;
    secman_encode_body(m, out);
    m5_mac(k_root_auth, ROOT_AUTH_DOMAIN, sizeof(ROOT_AUTH_DOMAIN), out, SECMAN_MAC_OFF, m->root_mac);
    memcpy(out + SECMAN_MAC_OFF, m->root_mac, 32);
    return M5_OK;
}

int m5_secman_open(const uint8_t *b, size_t len, const uint8_t k_root_auth[32],
                   uint8_t mode, m5_secman *m)
{
    if (!b || !k_root_auth || !m) return M5_ERR_ARG;
    memset(m, 0, sizeof *m);
    if (len != M5_SECMAN_LEN) return M5_ERR_BOUNDS;
    if (memcmp(b, "AIENSEC2", 8) != 0 || m5_get16(b + 8) != 2 || m5_get16(b + 10) != 0)
        return M5_ERR_FORMAT;
    if (!m5_all_zero(b + 13, 3)) return M5_ERR_FORMAT;
    if (!m5_valid_class(b[12])) return M5_ERR_FORMAT;
    uint8_t mac[32];
    m5_mac(k_root_auth, ROOT_AUTH_DOMAIN, sizeof(ROOT_AUTH_DOMAIN), b, SECMAN_MAC_OFF, mac);
    int ok = aienos_ct_equal(mac, b + SECMAN_MAC_OFF, 32);
    aienos_wipe(mac, sizeof mac);
    if (!ok) return M5_ERR_AUTH; /* GUARD:secman-mac */
    if (b[12] != mode) return M5_ERR_IDENTITY; /* GUARD:secman-class */
    m->identity_class = b[12];
    memcpy(m->store_uuid, b + 16, 16);
    m->generation = m5_get64(b + 32);
    m->security_sequence = m5_get64(b + 40);
    m->epoch = m5_get64(b + 48);
    m->key_epoch = m5_get64(b + 56);
    memcpy(m->previous_security_manifest_id, b + 64, 32);
    memcpy(m->keyslot_manifest_id, b + 96, 32);
    memcpy(m->agent_root_id, b + 128, 32);
    memcpy(m->continuity_manifest_id, b + 160, 32);
    memcpy(m->migration_manifest_id, b + 192, 32);
    m->owner_hierarchy_generation = m5_get64(b + 224);
    memcpy(m->root_mac, b + SECMAN_MAC_OFF, 32);
    return M5_OK;
}
