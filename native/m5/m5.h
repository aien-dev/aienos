/* AIENOS M5 encrypted-object envelope and security layer, in C.
 *
 * Port of crates/aienos-kernel/src/crypto/envelope.rs and
 * crates/aienos-kernel/src/security.rs on top of native/crypto
 * (AES-256-GCM-SIV, HMAC-SHA-256) and native/argus/sha256.
 * No heap, no clock, no I/O, no randomness: nonces and buffers come from the
 * caller. Secret scratch is wiped before returning. See README.md for where
 * the byte formats differ from the Rust reference.
 */
#ifndef AIENOS_M5_H
#define AIENOS_M5_H

#include <stddef.h>
#include <stdint.h>

/* ---- return codes ---- */
#define M5_OK 0
#define M5_ERR_ARG (-1)          /* NULL pointer, bad parameter */
#define M5_ERR_FORMAT (-2)       /* magic/version/flags/reserved/enum invalid */
#define M5_ERR_BOUNDS (-3)       /* a length or count field out of bounds */
#define M5_ERR_AUTH (-4)         /* MAC or AEAD tag did not verify */
#define M5_ERR_BINDING (-5)      /* authentic but bound to another object/store/generation */
#define M5_ERR_IDENTITY (-6)     /* PRODUCTION/TEST identity class mismatch */
#define M5_ERR_ROLLBACK (-7)     /* older generation, lower counter, fork, or missing anchor */
#define M5_ERR_INCONSISTENT (-8) /* counter jumped more than one ahead of the anchor */
#define M5_ERR_TORN (-9)         /* committed object version not present intact */
#define M5_ERR_AMBIGUOUS (-10)   /* conflicting copies claim the committed version */
#define M5_ERR_REPLAY (-11)      /* migration counter not above the last accepted one */
#define M5_ERR_SPACE (-12)       /* caller buffer too small */

/* ---- identity class (production vs test) ---- */
#define M5_ID_PRODUCTION 1
#define M5_ID_TEST 2

/* ---- HKDF-SHA-256 expand (RFC 5869 section 2.3), 32-byte PRK ---- */
int m5_hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                   uint8_t *out, size_t out_len);

/* ---- key hierarchy ---- */
typedef struct {
    uint8_t k_cortex[32];
    uint8_t k_agent[32];
    uint8_t k_artifact[32];
    uint8_t k_root_auth[32];
} m5_subkeys;

/* Rust-compatible derive_subkeys: HKDF-Expand(K_vol, "AIENOS/M5/<X>-V1"). */
void m5_derive_subkeys_v1(const uint8_t k_vol[32], m5_subkeys *out);
/* Owner hierarchy (C v2): K_class = HKDF-Expand(K_vol, "AIENOS/M5/OWNER-HIERARCHY-V2\0"
 * || identity_class || owner_hierarchy_generation:u64le), then the v1 labels
 * under K_class. Returns M5_ERR_ARG for an unknown identity class. */
int m5_derive_subkeys(const uint8_t k_vol[32], uint8_t identity_class,
                      uint64_t owner_hierarchy_generation, m5_subkeys *out);
void m5_subkeys_wipe(m5_subkeys *k);

/* Pre-seal binding of one envelope. Per AGENTS.md section 3 it holds no
 * ObjectId (SHA-256 of the sealed bytes, which does not exist yet) and no
 * Store generation: those are bound after sealing, in the commit record.
 * envelope_id is the 16-byte logical id carried in the envelope header;
 * key_generation is the header key_epoch. */
typedef struct {
    uint8_t store_uuid[16];
    uint16_t object_kind;
    uint16_t object_version;
    uint8_t envelope_id[16];
    uint64_t key_generation;
    uint8_t identity_class;
} m5_object_binding;

/* Per-object key from a domain subkey (k_cortex/k_agent/k_artifact):
 * HKDF-Expand(domain, "AIENOS/M5/OBJECT-KEY-V2\0" || store_uuid || kind ||
 * version || envelope_id || key_generation || identity_class). */
int m5_derive_object_key(const uint8_t domain_key[32], const m5_object_binding *b,
                         uint8_t out[32]);

/* ---- keyslot (128-byte descriptor, same layout as Rust KeySlotDescriptor) ---- */
#define M5_KEYSLOT_LEN 128
#define M5_SLOT_EMPTY 0
#define M5_SLOT_TPM2_POLICY_AUTHORIZE 1
#define M5_SLOT_RECOVERY_ARGON2ID 2
#define M5_SLOT_RECOVERY_RAW_SECRET 3
#define M5_WRAP_SUITE_GCMSIV 0x01

typedef struct {
    uint8_t slot_type, wrap_suite, kdf_suite, flags;
    uint32_t slot_id;
    uint64_t key_epoch;
    uint8_t salt[16];
    uint32_t argon_m_kib, argon_t_cost, argon_p_cost;
    uint8_t wrap_nonce[12];
    uint8_t wrapped_k_vol[32];
    uint8_t wrap_tag[16];
    uint32_t payload_offset, payload_length;
} m5_keyslot;

void m5_keyslot_encode(const m5_keyslot *s, uint8_t out[M5_KEYSLOT_LEN]);
int m5_keyslot_decode(const uint8_t *buf, size_t len, m5_keyslot *out);
/* Wrap K_vol under kek. AAD binds store_uuid, slot_id, slot_type, key_epoch. */
int m5_keyslot_wrap(m5_keyslot *s, const uint8_t store_uuid[16], const uint8_t kek[32],
                    const uint8_t k_vol[32], const uint8_t nonce[12]);
/* On any failure k_vol_out is zero. */
int m5_keyslot_unwrap(const m5_keyslot *s, const uint8_t store_uuid[16],
                      const uint8_t kek[32], uint8_t k_vol_out[32]);

/* ---- SecurityManifest (kind 22): byte-compatible with Rust v1 ----
 * 256 bytes, magic "AIENSEC1", format_version 1, flags 0, reserved 0,
 * root_mac = HMAC(k_root_auth, "AIENOS-M5-ROOT-AUTH-V1\0" || bytes[0..224]).
 * Identity class and owner hierarchy generation are not wire fields: they are
 * bound through k_root_auth, which m5_derive_subkeys derives from (K_vol,
 * identity_class, owner_hierarchy_generation). A manifest sealed under one
 * class or owner generation fails the MAC under any other. */
#define M5_SECMAN_LEN 256
typedef struct {
    uint8_t store_uuid[16];
    uint64_t generation;
    uint64_t security_sequence;
    uint64_t epoch;
    uint64_t key_epoch;
    uint8_t previous_security_manifest_id[32];
    uint8_t keyslot_manifest_id[32];
    uint8_t agent_root_id[32];
    uint8_t continuity_manifest_id[32];
    uint8_t migration_manifest_id[32];
    uint8_t root_mac[32];
} m5_secman;

/* Compute root_mac under k_root_auth and encode. */
int m5_secman_seal(m5_secman *m, const uint8_t k_root_auth[32], uint8_t out[M5_SECMAN_LEN]);
/* Bounded decode; the MAC must verify under k_root_auth. */
int m5_secman_open(const uint8_t *buf, size_t len, const uint8_t k_root_auth[32], m5_secman *out);

/* ---- chunked AES-256-GCM-SIV envelope: Rust V1 header, 64 bytes ----
 * 0 magic "AIENENV1" | 8 version u16 = 1 | 10 cipher_suite u16 = 1
 * | 12 flags u32 = 0 | 16 chunk_size u32 | 20 total_plaintext_len u64
 * | 28 envelope_id[16] | 44 nonce_prefix[8] | 52 key_epoch u64 | 60 reserved u32 = 0
 * Chunk AAD (AGENTS.md section 3, envelope.rs compute_chunk_aad, 111 bytes):
 * "AIENOS-M5-CHUNK-V1\0" || store_uuid || kind u16 || version u16 || header[64]
 * || chunk_index u32 || chunk_plaintext_length u32. Nonce: prefix[8] || index u32. */
#define M5_ENV_HEADER_LEN 64
#define M5_ENV_MAX_CHUNK 65536u
#define M5_ENV_MAX_CHUNKS 4096u /* C-only cap; Rust seals 64 KiB chunks, <= 1024 */
#define M5_ENV_MAX_PLAINTEXT (UINT64_C(64) * 1024 * 1024)
#define M5_TAG_LEN 16

typedef struct {
    uint16_t version;
    uint16_t cipher_suite;
    uint32_t flags;
    uint32_t chunk_size;
    uint64_t total_plaintext_len;
    uint8_t envelope_id[16];
    uint8_t nonce_prefix[8];
    uint64_t key_epoch;
    uint32_t chunk_count; /* derived, not a wire field */
} m5_env_header;

/* Envelope length for pt_len bytes in chunk_size chunks, 0 if out of bounds. */
size_t m5_envelope_len(uint64_t pt_len, uint32_t chunk_size);
/* Bounded header parse: every length field is checked before use and
 * env_len must equal the length the header implies. */
int m5_envelope_parse_header(const uint8_t *env, size_t env_len, m5_env_header *h);
int m5_envelope_seal(const uint8_t domain_key[32], const m5_object_binding *b,
                     const uint8_t nonce_prefix[8], uint32_t chunk_size,
                     const uint8_t *pt, size_t pt_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);
/* All-or-nothing: on any error out[0..out_cap) is all zero and *out_len is 0. */
int m5_envelope_open(const uint8_t domain_key[32], uint8_t mode, const m5_object_binding *expect,
                     const uint8_t *env, size_t env_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/* ---- commit record (object level, written after sealing), 144 bytes,
 * MAC by k_root_auth. Binds the ObjectId (SHA-256 of the sealed envelope
 * bytes) to its store generation, key generation and security counter. ---- */
#define M5_COMMIT_LEN 144
typedef struct {
    m5_object_binding obj;      /* store_uuid, kind, version, envelope_id, key generation, class */
    uint64_t store_generation;
    uint64_t counter;           /* monotonic security counter (anchor counter) */
    uint64_t object_sequence;
    uint8_t object_id[32];      /* ObjectId = SHA-256 of the committed envelope bytes */
} m5_commit;

int m5_commit_seal(const m5_commit *c, const uint8_t k_root_auth[32], uint8_t out[M5_COMMIT_LEN]);
int m5_commit_open(const uint8_t *buf, size_t len, const uint8_t k_root_auth[32],
                   uint8_t mode, m5_commit *out);
/* Post-seal check of envelope bytes against a verified commit record:
 * SHA-256(env) must equal object_id (M5_ERR_TORN), and the header's
 * envelope_id and key_epoch must equal the commit's (M5_ERR_BINDING). */
int m5_commit_check_object(const m5_commit *c, const uint8_t *env, size_t env_len);

/* ---- anti-rollback anchor, 120 bytes, MAC by k_root_auth ----
 * Persistence is the caller's buffer only. On hardware this is TPM NV,
 * blocked on TRUST-1 Gate 6. */
#define M5_ANCHOR_LEN 120
typedef struct {
    uint8_t identity_class;
    uint8_t store_uuid[16];
    uint64_t store_generation;
    uint64_t key_generation;
    uint64_t counter;
    uint8_t commit_digest[32]; /* SHA-256 of the commit record at this counter */
} m5_anchor;

int m5_anchor_seal(const m5_anchor *a, const uint8_t k_root_auth[32], uint8_t *buf, size_t buf_len);
int m5_anchor_open(const uint8_t *buf, size_t len, const uint8_t k_root_auth[32],
                   uint8_t mode, m5_anchor *out);

typedef struct {
    uint64_t store_generation;
    uint64_t key_generation;
    uint64_t counter;
    uint8_t commit_digest[32];
} m5_disk_state;

#define M5_RB_VALID_RESUME 1
#define M5_RB_PREPARED_ADVANCE 2
#define M5_RB_GENESIS 3
/* Returns a positive decision or a negative error. An empty anchor buffer is
 * genesis only when allow_genesis is set, otherwise a rollback. */
int m5_evaluate_anti_rollback(const uint8_t k_root_auth[32], uint8_t mode,
                              const uint8_t store_uuid[16],
                              const uint8_t *anchor_buf, size_t anchor_len,
                              int allow_genesis, const m5_disk_state *disk);

/* ---- migration manifest (kind 23), C v2 layout, 192 bytes, MAC by the
 * source store's k_root_auth. The owner public-key signature is a separate
 * record, m5_owner_migration below (native/sig Ed25519). ---- */
#define M5_MIGRATION_LEN 192
typedef struct {
    uint8_t identity_class;
    uint8_t agent_root_id[32];
    uint8_t genesis_store_uuid[16];
    uint8_t source_store_uuid[16];
    uint8_t dest_store_uuid[16];
    uint64_t source_store_generation;
    uint64_t source_anchor_counter;
    uint64_t migration_counter;
    uint64_t owner_hierarchy_generation;
    uint8_t source_commit_digest[32];
} m5_migration;

int m5_migration_seal(const m5_migration *m, const uint8_t k_root_auth[32],
                      uint8_t out[M5_MIGRATION_LEN]);
/* expect carries the source/destination/generation the verifier holds;
 * migration_counter must be above last_migration_counter. */
int m5_migration_authorize(const uint8_t *buf, size_t len, const uint8_t k_root_auth[32],
                           uint8_t mode, const m5_migration *expect,
                           uint64_t last_migration_counter, m5_migration *out);

/* ---- deterministic recovery (object/envelope level, no disk layer) ---- */
typedef struct {
    const uint8_t *bytes;
    size_t len;
} m5_candidate;

/* Picks the candidate whose SHA-256 equals the verified commit record's
 * object_id (ObjectId), after the commit is checked against the anchor. Refuses
 * (no silent repair) when the committed version is absent or torn
 * (M5_ERR_TORN) or when another copy claims the same object version with
 * different bytes (M5_ERR_AMBIGUOUS). On success the plaintext is in out and
 * *chosen is the index of the first matching candidate. All-or-nothing on out. */
int m5_recover_object(const uint8_t k_root_auth[32], const uint8_t domain_key[32],
                      uint8_t mode, const uint8_t store_uuid[16],
                      const uint8_t *commit_buf, size_t commit_len,
                      const uint8_t *anchor_buf, size_t anchor_len,
                      const m5_candidate *cands, size_t n_cands,
                      uint8_t *out, size_t out_cap, size_t *out_len, size_t *chosen);

/* ---- owner-signed migration record (C v1), 272 bytes, Ed25519 by the
 * owner key (native/sig, pure Ed25519, RFC 8032). The 192-byte migration
 * manifest above is MAC-bound to the source store's K_root_auth, which proves
 * the store approved the move; this record proves the OWNER approved it.
 * Layout (little endian, reserved bytes zero):
 * 0 "AIENOMG1" | 8 version u16 = 1 | 10 flags u16 = 0 | 12 identity_class | 13..16 reserved
 * | 16 owner_key_id[32] = SHA-256(owner public key)
 * | 48 agent_root_id[32] | 80 source_store_uuid[16] | 96 dest_store_uuid[16]
 * | 112 source_store_generation u64 | 120 store_format_version u32
 * | 124 envelope_count u32 | 128 envelope_set_digest[32]
 * | 160 migration_manifest_digest[32] = SHA-256 of the 192-byte MAC'd manifest
 * | 192 migration_counter u64 | 200 owner_hierarchy_generation u64
 * | 208 signature[64] = Ed25519(owner, "AIENOS-M5-OWNER-MIGRATION-V1\0" || bytes[0..208])
 * An unsigned body is the same 272 bytes with an all-zero signature. ---- */
#define M5_OWNER_MIG_LEN 272
#define M5_OWNER_MIG_BODY_LEN 208
typedef struct {
    uint8_t identity_class;
    uint8_t owner_key_id[32];             /* SHA-256 of the owner public key */
    uint8_t agent_root_id[32];
    uint8_t source_store_uuid[16];
    uint8_t dest_store_uuid[16];
    uint64_t source_store_generation;
    uint32_t store_format_version;
    uint32_t envelope_count;
    uint8_t envelope_set_digest[32];      /* m5_envelope_set_digest of the migrated ObjectIds */
    uint8_t migration_manifest_digest[32];
    uint64_t migration_counter;           /* monotonic; must exceed the last accepted one */
    uint64_t owner_hierarchy_generation;
} m5_owner_migration;

/* SHA-256("AIENOS-M5-ENVSET-V1\0" || n u32 || ids[0] || ... || ids[n-1]).
 * ids must be strictly ascending (canonical set: sorted, no duplicates),
 * else M5_ERR_FORMAT. ids may be NULL when n is 0. */
int m5_envelope_set_digest(const uint8_t (*ids)[32], uint32_t n, uint8_t out[32]);

/* Unsigned body for an offline signer: m's fields, owner_key_id computed from
 * owner_pk (m->owner_key_id is ignored), signature all zero. */
int m5_owner_migration_body(const m5_owner_migration *m, const uint8_t owner_pk[32],
                            uint8_t out[M5_OWNER_MIG_LEN]);
/* Signs an unsigned body in place. Refuses a malformed body, a body whose
 * signature field is not all zero (M5_ERR_FORMAT) and a key whose public key
 * does not match owner_key_id (M5_ERR_BINDING). */
int m5_owner_migration_sign_body(uint8_t rec[M5_OWNER_MIG_LEN], const uint8_t owner_sk[32]);
/* body + sign in one step (owner_pk derived from owner_sk). */
int m5_owner_migration_sign(const m5_owner_migration *m, const uint8_t owner_sk[32],
                            uint8_t out[M5_OWNER_MIG_LEN]);
/* Verifies a signed record against the trusted owner public key and the
 * verifier's expectations (every field except owner_key_id and
 * migration_counter must equal expect's), then refuses a counter not above
 * last_migration_counter (M5_ERR_REPLAY). Wrong length: M5_ERR_BOUNDS; bad
 * magic/version/flags/reserved/class: M5_ERR_FORMAT; another class than
 * mode: M5_ERR_IDENTITY; another owner key or a bad or missing signature:
 * M5_ERR_AUTH; field mismatch or source == destination: M5_ERR_BINDING.
 * out is all zero on every error. */
int m5_owner_migration_verify(const uint8_t *buf, size_t len, const uint8_t owner_pk[32],
                              uint8_t mode, const m5_owner_migration *expect,
                              uint64_t last_migration_counter, m5_owner_migration *out);
/* Full migration authorization: the MAC'd manifest under the source
 * K_root_auth (m5_migration_authorize) AND the owner signature over a record
 * that names that exact manifest (digest) with the same identity class,
 * agent root, source, destination, source store generation, migration
 * counter and owner hierarchy generation. expect_own supplies the fields the
 * manifest does not carry (store_format_version, envelope_count,
 * envelope_set_digest); its other fields are taken from expect_mig. Both
 * outputs are all zero on every error. */
int m5_migration_authorize_owner(const uint8_t *mig_buf, size_t mig_len,
                                 const uint8_t k_root_auth[32],
                                 const uint8_t *own_buf, size_t own_len,
                                 const uint8_t owner_pk[32], uint8_t mode,
                                 const m5_migration *expect_mig,
                                 const m5_owner_migration *expect_own,
                                 uint64_t last_migration_counter,
                                 m5_migration *out_mig, m5_owner_migration *out_own);

#endif /* AIENOS_M5_H */
