/* store_boot.c -- see store_boot.h. */
#include "store_boot.h"
#include "artifact_store.h"
#include <stddef.h>
#include "ck.h"
#include "disk_layout.h"
#include "m5.h"
#include "sha256.h"
#include "store_v1.h"
#include "store_crash.h"
#include "continuity_boot.h"
#ifdef CK_PI5_FACT
#include "pi5_fact.h"
#endif
#ifdef CK_SERVICE
#include "continuity_service.h"
#endif

#ifdef CK_HARDWARE_STAGING
/* Hardware staging image: owner provisioning generated at build time by
 * tools/ck_owner_gen.c from CK_OWNER_PUBKEYS= and CK_MACHINE_ID= (public
 * material only). No TEST label, TEST uuid or TEST key code is compiled. */
#include "ck_owner_prov.h"
#if !defined(CK_OWNER_PROVISIONED) || CK_OWNER_PROVISIONED != 1
#error "CK_HARDWARE_STAGING needs the generated owner provisioning header (make full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=<file> CK_MACHINE_ID=<file>)"
#endif
#if defined(CK_STORE_TEST_KEYS)
#error "CK_STORE_TEST_KEYS (TEST Store keys, TEST uuid) cannot be combined with CK_HARDWARE_STAGING"
#endif
#if defined(CK_PI5_UNLOCK)
#error "CK_PI5_UNLOCK cannot be combined with CK_HARDWARE_STAGING"
#endif
#define CK_SB_HW 1
#elif defined(CK_PI5_UNLOCK)
/* Pi unlock image (CK_PI5_UNLOCK): the Store opens only through the Slot 1 recovery-secret path
 * (ck_store_pi5_unlock_run). No TEST keys, no TEST uuid are compiled, and the policy is the
 * hardware one: TEST-identity keys are refused before any disk access. It needs no owner
 * provisioning header (the store uuid is drawn at genesis or read from the manifest). */
#if defined(CK_STORE_TEST_KEYS) || defined(CK_PI5_STORE) || defined(CK_TEST_STORE_CRASH) || defined(CK_SERVICE)
#error "CK_PI5_UNLOCK cannot be combined with TEST keys, CK_PI5_STORE, CK_TEST_STORE_CRASH or CK_SERVICE"
#endif
#define CK_SB_HW 1
#else
#define CK_STORE_TEST_KEYS 1
#define CK_SB_HW 0
#endif

/* TEST-ONLY Store crash hook (svc/store_crash.h), only in the image built
 * with CK_TEST_STORE_CRASH=1; never with CK_HARDWARE_STAGING. */
#ifdef CK_TEST_STORE_CRASH
#define CK_SB_HOOK ck_store_crash_hook
#else
#define CK_SB_HOOK 0
#endif

#ifdef CK_STORE_TEST_KEYS
#define LABEL_KVOL "AIENOS-LANE18-TEST-KVOL-NOT-SECRET"

const uint8_t ck_store_test_uuid[16] = {'A', 'I', 'E', 'N', '-', 'T', 'E', 'S',
                                        'T', '-', 'B', 'O', 'O', 'T', '0', '1'};
#endif

static void bz(void *p, size_t n)
{
    volatile uint8_t *b = p;
    while (n--) *b++ = 0;
}
static void bcp(void *d, const void *s, size_t n)
{
    uint8_t *o = d;
    const uint8_t *i = s;
    while (n--) *o++ = *i++;
}
static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#ifdef CK_STORE_TEST_KEYS
void ck_store_test_keys(ss_keys *k)
{
    uint8_t kvol[32];
    m5_subkeys sk;
    sha256_hash((const uint8_t *)LABEL_KVOL, sizeof LABEL_KVOL - 1, kvol);
    bz(k, sizeof *k);
    m5_derive_subkeys(kvol, M5_ID_TEST, 0, &sk);
    k->identity_class = M5_ID_TEST;
    k->key_generation = 1;
    bcp(k->k_root_auth, sk.k_root_auth, 32);
    bcp(k->k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);
    bz(kvol, sizeof kvol);
}
#endif

/* BLOCKED_OPERATOR seam. Production Store keys derive from K_vol (ADR 0017),
 * which is secret: it cannot come from the public owner material injected at
 * build time, and no in-kernel unwrap of a K_vol keyslot exists yet. The
 * operator must provide, through the TRUST-1 key ceremony: Gate 3 Owner Root
 * (offline), Gate 5/6 TPM PolicyAuthorize key + sealed Slot 0 KEK (K_vol
 * unwrapped at boot), or the Slot 1 recovery KEK. Until then this refuses and
 * there is no TEST fallback. */
int ck_store_production_keys(ss_keys *k)
{
    if (k) bz(k, sizeof *k);
    return CK_SB_E_BLOCKED_OPERATOR;
}

int ck_store_keys_admissible(const ss_keys *k, int hardware_staging)
{
    if (!k) return 0;
    if (k->identity_class == M5_ID_PRODUCTION) return 1;
    return k->identity_class == M5_ID_TEST && !hardware_staging;
}

static int fail(ck_store_report *r, const char *proof, const char *step, int rc)
{
    r->verdict = CK_SB_REFUSED;
    r->proof = proof;
    r->step = step;
    r->rc = rc;
    return rc ? rc : -1;
}

/* Blank = anchor units and the first two Store units read back all zero. */
static int bytes_differ(const uint8_t *a, const uint8_t *b, size_t n)
{
    int diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff != 0;
}

static int is_blank(const disk_dev *d, uint32_t bpu, uint8_t *buf, int *blank)
{
    *blank = 1;
    for (uint64_t u = 0; u < CK_LAYOUT_ANCHOR_UNITS + 2u; u++) {
        int rc = disk_read(d, u * bpu, bpu, buf);
        if (rc) return rc;
        for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++)
            if (buf[i]) {
                *blank = 0;
                return 0;
            }
    }
    return 0;
}

static const char *classify(int rc)
{
    switch (rc) {
    case SS_E_ROLLBACK:
    case SS_E_INCONSISTENT:
    case SS_E_ANCHOR:
        return "rollback";
    case SS_E_IO:
    case ST_M_IO:
        return "io";
    default:
        return (rc <= -101 && rc >= -107) ? "structural" : "keyed";
    }
}

/* Workspace lives across boots of the host test; the kernel uses it once. */
static ss_workspace *g_ws;
static ss_store *g_ss;
/* The newest SecurityManifest after a committed boot or rotation (P04 cut
 * 2a/2b): sequence and Store ObjectId the next manifest links to. */
static uint64_t g_secman_seq;
static uint8_t g_secman_sid[32];

/* SecurityManifest refusal: the Store is not served and the keys are wiped. */
static int secman_refuse(ck_store_report *r, const char *step)
{
    bz(&g_ss->keys, sizeof g_ss->keys);
    return fail(r, "keyed", step, CK_SB_E_SECMAN);
}
#ifdef CK_SERVICE
static int g_service_open;      /* Store open for the service lifetime (core/lifecycle.c) */
static int g_service_locked_rc; /* last production key source refusal */
static const disk_dev *g_disk;  /* boot disk kept bound while LOCKED, for a later unlock */
#endif

int store_boot_run(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                   ck_store_report *r)
{
    return store_boot_run_policy(d, keys, uuid, commit, CK_SB_HW, r);
}

/* static: the open Store (g_ss) keeps pointers to these devices and is
 * used after the boot returns (store_boot_store, the artifact read). */
static st_disk g_sd;
static st_dev g_sdev;
static ts_device g_tdev;

/* Geometry + workspace + device binding shared by the boot and the unlock.
 * Fills the layout fields of r; no disk access. */
static int bind_disk(const disk_dev *d, ck_store_report *r, uint32_t *bpu_out)
{
    if (d->block_size != 512 && d->block_size != 4096) return fail(r, "geometry", "block size", -1);
    uint32_t bpu = CK_LAYOUT_UNIT / d->block_size;
    uint64_t units = d->block_count / bpu;
    if (units < CK_LAYOUT_ANCHOR_UNITS + CK_LAYOUT_MIN_STORE_UNITS + CK_LAYOUT_PROBE_UNITS)
        return fail(r, "geometry", "disk too small", -1);
    r->anchor_lba = 0;
    r->store_base_lba = (uint64_t)CK_LAYOUT_ANCHOR_UNITS * bpu;
    r->store_units = units - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS;

    if (!g_ws) g_ws = ck_alloc(sizeof *g_ws);
    if (!g_ss) g_ss = ck_alloc(sizeof *g_ss);
    if (!g_ws || !g_ss) return fail(r, "io", "allocate workspace", -1);
    bz(g_ss, sizeof *g_ss);

    int rc = st_disk_bind(&g_sd, d, r->store_base_lba, r->store_units, &g_sdev);
    if (rc) return fail(r, "geometry", "st_disk_bind", rc);
    ss_ts_device(d, &g_tdev);
    *bpu_out = bpu;
    return 0;
}

/* The boot proper. genesis_obj (optional) is committed beside the boot record
 * in the first transaction of a disk this run formatted (the KeySlotManifest
 * of ck_store_unlock_boot); on a non-blank disk it is ignored. */
static int run_policy_ex(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                         int hardware_staging, const ss_object *genesis_obj, ck_store_report *r)
{
    bz(r, sizeof *r);
    bcp(r->prev_commit, "none", 5);
    if (!d || !keys || !uuid || !commit) return fail(r, "geometry", "arguments", -1);
    r->identity_class = keys->identity_class;
    /* Before any disk access: a hardware staging build never opens, and
     * never formats a blank disk, under TEST-identity keys. */
    if (!ck_store_keys_admissible(keys, hardware_staging))
        return fail(r, "keyed", "identity class not admissible in this build (TEST keys refused on hardware)",
                    CK_SB_E_TEST_KEYS);
    uint32_t bpu = 0;
    int rc = bind_disk(d, r, &bpu);
    if (rc) return rc;

    int blank = 0;
    rc = is_blank(d, bpu, g_ws->rd, &blank);
    if (rc) return fail(r, "io", "blank check read", rc);
    if (blank) {
        rc = ss_format(&g_sdev, &g_tdev, r->anchor_lba, uuid, keys, g_ws);
        if (rc) return fail(r, "commit", "format blank disk", rc);
        r->formatted = 1;
    }

    /* Proof 1: structural, unkeyed. */
    rc = st_open(&g_ss->st, &g_sdev, &g_ws->st);
    if (rc) return fail(r, rc == ST_M_IO ? "io" : "structural", "st_open (unkeyed)", rc);
    /* Proofs 2 and 3: keyed M5 + anti-rollback anchor. */
    bz(g_ss, sizeof *g_ss);
    rc = ss_open(g_ss, &g_sdev, &g_tdev, r->anchor_lba, keys, g_ws);
    if (rc) return fail(r, classify(rc), "ss_open (keyed + anchor)", rc);
    r->rb = g_ss->rb;
    r->gen_open = ss_generation(g_ss);

    /* Latest boot record = highest store generation among boot-kind claims. */
    int best = -1;
    for (uint32_t k = 0; k < g_ss->nclaims; k++) {
        const ss_claim *c = &g_ws->claims[k];
        if (c->c.obj.object_kind != CK_BOOT_KIND) continue;
        if (best < 0 || c->c.store_generation > g_ws->claims[best].c.store_generation) best = (int)k;
    }
    uint8_t rec[CK_BOOT_RECORD_LEN];
    if (best >= 0) {
        uint8_t sid[32];
        size_t len = 0;
        uint16_t kind = 0;
        bcp(sid, g_ws->claims[best].sid, 32);
        rc = ss_read(g_ss, sid, rec, sizeof rec, &len, &kind);
        if (rc) return fail(r, classify(rc), "read boot record", rc);
        if (len != CK_BOOT_RECORD_LEN || kind != CK_BOOT_KIND || get64(rec) != get64((const uint8_t *)"AIENBOOT") ||
            get32(rec + 8) != CK_BOOT_VERSION)
            return fail(r, "record", "boot record malformed (authenticated, wrong layout)", -1);
        r->boot_count_prev = get64(rec + 16);
        size_t i = 0;
        for (; i < CK_BOOT_COMMIT_MAX && rec[24 + i]; i++) r->prev_commit[i] = (char)rec[24 + i];
        r->prev_commit[i] = 0;
    } else if (!r->formatted && r->gen_open > 1) {
        return fail(r, "record", "store has history but no boot record", -1);
    }

    /* SecurityManifest (ADR 0017 section 2.5, P04 cut 2a): the newest
     * kind-22 claim must verify under these keys and bind this Store, its
     * keyslot and its key epoch; its security_sequence equals the number of
     * manifests on the Store (every boot transaction writes exactly one). */
    m5_secman sm;
    uint8_t sm_prev[32], zero32[32];
    uint32_t nsecman = 0;
    int sm_best = -1;
    bz(&sm, sizeof sm);
    bz(sm_prev, sizeof sm_prev);
    bz(zero32, sizeof zero32);
    for (uint32_t k = 0; k < g_ss->nclaims; k++) {
        const ss_claim *c = &g_ws->claims[k];
        if (c->c.obj.object_kind != CK_SECMAN_KIND) continue;
        nsecman++;
        if (sm_best < 0 || c->c.store_generation > g_ws->claims[sm_best].c.store_generation) sm_best = (int)k;
    }
    if (sm_best >= 0) {
        uint8_t smb[M5_SECMAN_LEN];
        size_t len = 0;
        uint16_t kind = 0;
        bcp(sm_prev, g_ws->claims[sm_best].sid, 32);
        rc = ss_read(g_ss, sm_prev, smb, sizeof smb, &len, &kind);
        if (rc) return fail(r, classify(rc), "read SecurityManifest", rc);
        if (len != M5_SECMAN_LEN || kind != CK_SECMAN_KIND || m5_secman_open(smb, len, keys->k_root_auth, &sm) != 0)
            return secman_refuse(r, "SecurityManifest malformed or not under these keys");
        if (bytes_differ(sm.store_uuid, g_ss->uuid, 16)) return secman_refuse(r, "SecurityManifest names another Store");
        if (bytes_differ(sm.keyslot_manifest_id, g_ss->has_keyslot ? g_ss->keyslot_sid : zero32, 32))
            return secman_refuse(r, "SecurityManifest does not bind this Store's KeySlotManifest");
        if (sm.key_epoch != keys->key_generation) return secman_refuse(r, "SecurityManifest key_epoch differs from the open keys");
        if (sm.generation != g_ws->claims[sm_best].c.store_generation)
            return secman_refuse(r, "SecurityManifest generation differs from the transaction that committed it");
        if (sm.security_sequence != nsecman) return secman_refuse(r, "SecurityManifest security_sequence is not the manifest count");
        r->secman_prev = 1;
    } else if (!r->formatted && r->gen_open > 1) {
        return secman_refuse(r, "store has history but no SecurityManifest");
    }

    r->boot_count_new = r->boot_count_prev + 1;
    bz(rec, sizeof rec);
    bcp(rec, "AIENBOOT", 8);
    put32(rec + 8, CK_BOOT_VERSION);
    put64(rec + 16, r->boot_count_new);
    for (size_t i = 0; i < CK_BOOT_COMMIT_MAX && commit[i]; i++) rec[24 + i] = (uint8_t)commit[i];
    /* The SecurityManifest of this transaction (sequence previous + 1). */
    uint8_t smb_new[M5_SECMAN_LEN];
    {
        m5_secman n;
        bz(&n, sizeof n);
        bcp(n.store_uuid, g_ss->uuid, 16);
        n.generation = r->gen_open + 1;
        n.security_sequence = sm.security_sequence + 1;
        n.epoch = n.generation;
        n.key_epoch = keys->key_generation;
        bcp(n.previous_security_manifest_id, sm_prev, 32);
        if (genesis_obj && r->formatted) {
            if (sv1_object_id(genesis_obj->kind, genesis_obj->version, genesis_obj->bytes, genesis_obj->len,
                              n.keyslot_manifest_id) != 0)
                return fail(r, "commit", "KeySlotManifest ObjectId", -1);
        } else if (g_ss->has_keyslot) {
            bcp(n.keyslot_manifest_id, g_ss->keyslot_sid, 32);
        }
        if (m5_secman_seal(&n, keys->k_root_auth, smb_new) != 0) return fail(r, "commit", "seal SecurityManifest", -1);
        r->secman_seq = n.security_sequence;
        r->secman_keyslot = bytes_differ(n.keyslot_manifest_id, zero32, 32);
    }
    ss_object objs[3] = {{CK_BOOT_KIND, CK_BOOT_VERSION, rec, sizeof rec},
                         {CK_SECMAN_KIND, 1, smb_new, M5_SECMAN_LEN},
                         {0, 0, 0, 0}};
    size_t nobjs = 2;
    if (genesis_obj && r->formatted) objs[nobjs++] = *genesis_obj;
#ifdef CK_TEST_STORE_CRASH
    ck_store_crash_opened(r->gen_open);
#endif
    uint8_t ids[3][32];
    rc = ss_transact(g_ss, objs, nobjs, CK_SB_HOOK, 0, ids);
    if (rc) return fail(r, "commit", "ss_transact", rc);
    rc = disk_flush(d);
    if (rc) return fail(r, "io", "flush", rc);
    r->gen_commit = ss_generation(g_ss);
    if (r->gen_commit != r->gen_open + 1) return fail(r, "commit", "generation did not advance by one", -1);
    g_secman_seq = r->secman_seq;
    bcp(g_secman_sid, ids[1], 32);
    r->verdict = CK_SB_COMMITTED;
    return 0;
}

int store_boot_run_policy(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                          int hardware_staging, ck_store_report *r)
{
    return run_policy_ex(d, keys, uuid, commit, hardware_staging, 0, r);
}

/* ---- recovery keyslot unlock (ADR 0017 section 2.4, Slot 1) ---- */

/* PRODUCTION-class Store keys from K_vol: owner hierarchy generation is the
 * manifest's active_key_epoch (1 in cut 1, no rotation yet). */
static int production_keys_from_kvol(const uint8_t k_vol[32], uint64_t epoch, ss_keys *k)
{
    m5_subkeys sk;
    bz(k, sizeof *k);
    int rc = m5_derive_subkeys(k_vol, M5_ID_PRODUCTION, epoch, &sk);
    if (rc) {
        m5_subkeys_wipe(&sk);
        return rc;
    }
    k->identity_class = M5_ID_PRODUCTION;
    k->key_generation = epoch;
    bcp(k->k_root_auth, sk.k_root_auth, 32);
    bcp(k->k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);
    return 0;
}

#define CK_RECOVERY_SLOT_ID 1u
#define CK_RECOVERY_EPOCH 1u

static uint8_t *g_ksm_buf; /* manifest bytes (bootstrap read / genesis encode) */

int ck_store_unlock_boot(const disk_dev *d, const uint8_t secret[CK_SB_SECRET_LEN], const uint8_t *expect_uuid,
                         const char *commit, int hardware_staging, ck_store_report *r)
{
    ss_keys keys;
    uint8_t k_vol[32], kek[32], uuid[16];
    m5_ksm m;
    int rc, blank = 0;
    uint32_t bpu = 0;
    size_t mlen = 0;

    bz(r, sizeof *r);
    bcp(r->prev_commit, "none", 5);
    r->identity_class = M5_ID_PRODUCTION;
    r->key_source = "recovery-keyslot";
    if (!d || !secret || !commit) return fail(r, "geometry", "arguments", -1);
    if (!g_ksm_buf) g_ksm_buf = ck_alloc(SS_KEYSLOT_MAX);
    if (!g_ksm_buf) return fail(r, "io", "allocate keyslot buffer", -1);
    rc = bind_disk(d, r, &bpu);
    if (rc) return rc;
    rc = is_blank(d, bpu, g_ws->rd, &blank);
    if (rc) return fail(r, "io", "blank check read", rc);

    bz(&m, sizeof m);
    bz(&keys, sizeof keys);
    if (blank) {
        /* Genesis: fresh K_vol, salt and nonce from the kernel entropy service;
         * refuse (no fallback) when RNDR refuses. The manifest goes into the
         * same first transaction as the boot record. */
        uint8_t fresh[32 + 16 + 12 + 16];
        if (ck_entropy_fill(fresh, sizeof fresh) != 0) {
            bz(fresh, sizeof fresh);
            return fail(r, "keyed", "genesis entropy (K_vol, salt, nonce) refused by the entropy service",
                        CK_SB_E_ENTROPY);
        }
        bcp(k_vol, fresh, 32);
        if (expect_uuid) bcp(uuid, expect_uuid, 16);
        else bcp(uuid, fresh + 60, 16);
        bcp(m.store_uuid, uuid, 16);
        m.manifest_sequence = 1;
        m.active_key_epoch = CK_RECOVERY_EPOCH;
        m.slot_count = 2; /* index 0 reserved for the TPM slot (Empty), index 1 recovery */
        m5_keyslot *sl = &m.slots[1];
        sl->slot_type = M5_SLOT_RECOVERY_RAW_SECRET;
        sl->wrap_suite = M5_WRAP_SUITE_GCMSIV;
        sl->kdf_suite = 0x02; /* HKDF-SHA256 */
        sl->slot_id = CK_RECOVERY_SLOT_ID;
        sl->key_epoch = CK_RECOVERY_EPOCH;
        bcp(sl->salt, fresh + 32, 16);
        rc = m5_recovery_kek(sl->salt, secret, CK_SB_SECRET_LEN, kek);
        if (rc == 0) rc = m5_keyslot_wrap(sl, uuid, kek, k_vol, fresh + 48);
        bz(fresh, sizeof fresh);
        bz(kek, sizeof kek);
        if (rc) {
            bz(k_vol, sizeof k_vol);
            return fail(r, "keyed", "wrap K_vol into the recovery keyslot", rc);
        }
        m5_ksm_encode(&m, g_ksm_buf);
        mlen = M5_KSM_FIXED_LEN;
        r->unlocked_genesis = 1;
    } else {
        /* Bootstrap: the manifest is read before any key exists, then the
         * keyed open re-binds the same bytes through the transaction record. */
        rc = ss_keyslot_bootstrap(&g_ss->st, &g_sdev, g_ws, g_ksm_buf, SS_KEYSLOT_MAX, &mlen);
        if (rc) return fail(r, rc == ST_M_IO ? "io" : "keyed", "no KeySlotManifest on a non-blank disk", rc == SS_E_KEYSLOT ? CK_SB_E_NO_KEYSLOT : rc);
        rc = m5_ksm_decode(g_ksm_buf, mlen, &m);
        if (rc) return fail(r, "keyed", "KeySlotManifest decode", CK_SB_E_KEYSLOT_BAD);
        if (expect_uuid) {
            int diff = 0;
            for (size_t i = 0; i < 16; i++) diff |= m.store_uuid[i] ^ expect_uuid[i];
            if (diff) return fail(r, "keyed", "KeySlotManifest store_uuid is not this machine's", CK_SB_E_KEYSLOT_BAD);
        }
        bcp(uuid, m.store_uuid, 16);
        const m5_keyslot *sl = 0;
        for (uint32_t i = 0; i < m.slot_count && i < M5_KSM_SLOTS; i++)
            if (m.slots[i].slot_type == M5_SLOT_RECOVERY_RAW_SECRET && m.slots[i].kdf_suite == 0x02 &&
                m.slots[i].wrap_suite == M5_WRAP_SUITE_GCMSIV) {
                sl = &m.slots[i];
                break;
            }
        if (!sl) return fail(r, "keyed", "no Recovery_RawSecret (HKDF) descriptor in the manifest", CK_SB_E_KEYSLOT_BAD);
        rc = m5_recovery_kek(sl->salt, secret, CK_SB_SECRET_LEN, kek);
        if (rc == 0) rc = m5_keyslot_unwrap(sl, uuid, kek, k_vol);
        bz(kek, sizeof kek);
        if (rc) {
            bz(k_vol, sizeof k_vol);
            return fail(r, "keyed", "recovery secret rejected (K_vol unwrap tag failed); disk not opened",
                        CK_SB_E_SECRET_REJECTED);
        }
        /* The epoch the descriptor wrapped under is the active one in cut 1. */
        if (sl->key_epoch != m.active_key_epoch) {
            bz(k_vol, sizeof k_vol);
            return fail(r, "keyed", "descriptor key_epoch differs from active_key_epoch (rotation not supported)",
                        CK_SB_E_KEYSLOT_BAD);
        }
    }
    rc = production_keys_from_kvol(k_vol, m.active_key_epoch, &keys);
    bz(k_vol, sizeof k_vol);
    if (rc) {
        bz(&keys, sizeof keys);
        return fail(r, "keyed", "derive PRODUCTION subkeys", rc);
    }
    {
        ss_object ks = {M5_KSM_KIND, 1, g_ksm_buf, mlen};
        int genesis = r->unlocked_genesis;
        rc = run_policy_ex(d, &keys, uuid, commit, hardware_staging, blank ? &ks : 0, r);
        r->key_source = "recovery-keyslot";
        r->unlocked_genesis = genesis;
        r->keyslot_seq = m.manifest_sequence;
        if (rc == 0 && !blank && !g_ss->has_keyslot) {
            /* Opened, but the keyed open did not bind the manifest we
             * bootstrapped from: refuse rather than serve an unbound keyslot. */
            bz(&g_ss->keys, sizeof g_ss->keys);
            rc = fail(r, "keyed", "KeySlotManifest not bound by the sealed transaction records", CK_SB_E_KEYSLOT_BAD);
        }
    }
    bz(&keys, sizeof keys);
    bz(g_ksm_buf, SS_KEYSLOT_MAX);
    return rc;
}

/* The Recovery_RawSecret (HKDF, GCM-SIV) descriptor of a decoded manifest. */
static m5_keyslot *recovery_slot(m5_ksm *m)
{
    for (uint32_t i = 0; i < m->slot_count && i < M5_KSM_SLOTS; i++)
        if (m->slots[i].slot_type == M5_SLOT_RECOVERY_RAW_SECRET && m->slots[i].kdf_suite == 0x02 &&
            m->slots[i].wrap_suite == M5_WRAP_SUITE_GCMSIV)
            return &m->slots[i];
    return 0;
}

int ck_store_rotate_recovery(const disk_dev *d, const uint8_t current[CK_SB_SECRET_LEN],
                             const uint8_t next[CK_SB_SECRET_LEN], ck_store_report *r)
{
    m5_ksm m;
    m5_keyslot *sl;
    uint8_t k_vol[32], kek[32], fresh[16 + 12], smb[M5_SECMAN_LEN], ids[2][32];
    size_t mlen = 0;
    uint16_t kind = 0;
    int rc;

    bz(r, sizeof *r);
    bcp(r->prev_commit, "none", 5);
    r->identity_class = M5_ID_PRODUCTION;
    r->key_source = "recovery-keyslot";
    if (!d || !current || !next) return fail(r, "geometry", "arguments", -1);
    if (!g_ss || !g_ws || !g_ksm_buf || g_ss->keys.identity_class != M5_ID_PRODUCTION || !g_ss->has_keyslot)
        return fail(r, "keyed", "no open production Store with a KeySlotManifest to rotate", CK_SB_E_NO_KEYSLOT);
    r->gen_open = ss_generation(g_ss);
    rc = ss_read(g_ss, g_ss->keyslot_sid, g_ksm_buf, SS_KEYSLOT_MAX, &mlen, &kind);
    if (rc || kind != M5_KSM_KIND) return fail(r, "keyed", "read the bound KeySlotManifest", rc ? rc : CK_SB_E_KEYSLOT_BAD);
    bz(&m, sizeof m);
    if (m5_ksm_decode(g_ksm_buf, mlen, &m) != 0 || m.arena_len != 0 || mlen != M5_KSM_FIXED_LEN)
        return fail(r, "keyed", "KeySlotManifest decode (raw-secret profile, no arena)", CK_SB_E_KEYSLOT_BAD);
    if (m.manifest_sequence != g_ss->nkeyslot)
        return fail(r, "keyed", "bound manifest sequence is not the chain length", CK_SB_E_KEYSLOT_BAD);
    sl = recovery_slot(&m);
    if (!sl) return fail(r, "keyed", "no Recovery_RawSecret (HKDF) descriptor in the manifest", CK_SB_E_KEYSLOT_BAD);
    /* proof of possession: the current secret must unwrap K_vol */
    rc = m5_recovery_kek(sl->salt, current, CK_SB_SECRET_LEN, kek);
    if (rc == 0) rc = m5_keyslot_unwrap(sl, g_ss->uuid, kek, k_vol);
    bz(kek, sizeof kek);
    if (rc) {
        bz(k_vol, sizeof k_vol);
        return fail(r, "keyed", "current recovery secret rejected (K_vol unwrap tag failed); nothing written",
                    CK_SB_E_SECRET_REJECTED);
    }
    if (ck_entropy_fill(fresh, sizeof fresh) != 0) {
        bz(k_vol, sizeof k_vol);
        bz(fresh, sizeof fresh);
        return fail(r, "keyed", "rotation entropy (salt, nonce) refused by the entropy service", CK_SB_E_ENTROPY);
    }
    /* next link of the chain: same K_vol and epoch, new salt, K_vol re-wrapped under the new KEK */
    m.manifest_sequence += 1;
    bcp(m.previous_keyslot_manifest_id, g_ss->keyslot_sid, 32);
    bcp(sl->salt, fresh, 16);
    rc = m5_recovery_kek(sl->salt, next, CK_SB_SECRET_LEN, kek);
    if (rc == 0) rc = m5_keyslot_wrap(sl, g_ss->uuid, kek, k_vol, fresh + 16);
    bz(kek, sizeof kek);
    bz(k_vol, sizeof k_vol);
    bz(fresh, sizeof fresh);
    if (rc) {
        bz(&m, sizeof m);
        return fail(r, "keyed", "wrap K_vol under the new recovery secret", rc);
    }
    m5_ksm_encode(&m, g_ksm_buf);
    r->keyslot_seq = m.manifest_sequence;
    bz(&m, sizeof m);
    /* the SecurityManifest of the rotation transaction binds the new manifest */
    {
        m5_secman n;
        bz(&n, sizeof n);
        bcp(n.store_uuid, g_ss->uuid, 16);
        n.generation = r->gen_open + 1;
        n.security_sequence = g_secman_seq + 1;
        n.epoch = n.generation;
        n.key_epoch = g_ss->keys.key_generation;
        bcp(n.previous_security_manifest_id, g_secman_sid, 32);
        if (sv1_object_id(M5_KSM_KIND, 1, g_ksm_buf, M5_KSM_FIXED_LEN, n.keyslot_manifest_id) != 0)
            return fail(r, "commit", "KeySlotManifest ObjectId", -1);
        if (m5_secman_seal(&n, g_ss->keys.k_root_auth, smb) != 0) return fail(r, "commit", "seal SecurityManifest", -1);
        r->secman_seq = n.security_sequence;
        r->secman_keyslot = 1;
        r->secman_prev = 1;
    }
    {
        ss_object objs[2] = {{M5_KSM_KIND, 1, g_ksm_buf, M5_KSM_FIXED_LEN}, {CK_SECMAN_KIND, 1, smb, M5_SECMAN_LEN}};
        rc = ss_transact(g_ss, objs, 2, CK_SB_HOOK, 0, ids);
    }
    bz(g_ksm_buf, SS_KEYSLOT_MAX);
    if (rc) return fail(r, "commit", "ss_transact", rc);
    rc = disk_flush(d);
    if (rc) return fail(r, "io", "flush", rc);
    r->gen_commit = ss_generation(g_ss);
    if (r->gen_commit != r->gen_open + 1) return fail(r, "commit", "generation did not advance by one", -1);
    g_secman_seq = r->secman_seq;
    bcp(g_secman_sid, ids[1], 32);
    r->verdict = CK_SB_COMMITTED;
    return 0;
}

static const char *rb_name(int rb)
{
    return rb == SS_RB_VALID_RESUME ? "valid-resume" : rb == SS_RB_PREPARED_ADVANCE ? "prepared-advance" :
           rb == SS_RB_GENESIS ? "genesis" : "?";
}

static const char *err_name(int rc)
{
    if (rc <= -301 && rc >= -313) return ss_strerror(rc);
    if (rc <= -101 && rc >= -212) return st_strerror(rc);
    if (rc == CK_SB_E_TEST_KEYS) return "TestKeysRefused";
    if (rc == CK_SB_E_BLOCKED_OPERATOR) return "BlockedOperator";
    if (rc == CK_SB_E_NO_KEYSLOT) return "NoKeyslotManifest";
    if (rc == CK_SB_E_SECRET_REJECTED) return "RecoverySecretRejected";
    if (rc == CK_SB_E_ENTROPY) return "EntropyRefused";
    if (rc == CK_SB_E_KEYSLOT_BAD) return "KeyslotManifestUnusable";
    if (rc == CK_SB_E_CONTINUITY) return "ContinuityRefused";
    if (rc == CK_SB_E_SECMAN) return "SecurityManifestRefused";
    return "error";
}

void store_boot_print(const ck_store_report *r)
{
    const char *fmt_line;
#ifdef CK_STORE_TEST_KEYS
    if (r->identity_class == M5_ID_TEST) {
        ck_printf("store: TEST identity, TEST keys (public label, not secret, not production); "
                  "anchor lba=%llu store lba=%llu units=%llu\n",
                  (unsigned long long)r->anchor_lba, (unsigned long long)r->store_base_lba,
                  (unsigned long long)r->store_units);
        fmt_line = "store: blank disk (all-zero anchor + Store head): formatted TEST store\n";
    } else
#endif
    {
        ck_printf("store: identity class=%u (%s); anchor lba=%llu store lba=%llu units=%llu\n",
                  (unsigned)r->identity_class, r->identity_class == M5_ID_PRODUCTION ? "production" : "refused",
                  (unsigned long long)r->anchor_lba, (unsigned long long)r->store_base_lba,
                  (unsigned long long)r->store_units);
        fmt_line = "store: blank disk (all-zero anchor + Store head): formatted production store\n";
    }
    if (r->formatted) ck_puts(fmt_line);
    if (r->key_source)
        ck_printf("store: key source=%s genesis=%d (K_vol source: the Slot 1 recovery descriptor; "
                  "TPM Slot 0 BLOCKED_HARDWARE; no rotation)\n", r->key_source, r->unlocked_genesis);
    if (r->verdict != CK_SB_COMMITTED) {
        ck_printf("store: REFUSED proof=%s step=\"%s\" rc=%d (%s); disk left as found, not reformatted\n",
                  r->proof, r->step, r->rc, err_name(r->rc));
        return;
    }
    ck_printf("store: opened generation=%llu boot_count=%llu prev_commit=%s anchor=%s\n",
              (unsigned long long)r->gen_open, (unsigned long long)r->boot_count_prev, r->prev_commit,
              rb_name(r->rb));
    ck_printf("store: committed generation=%llu boot_count=%llu\n", (unsigned long long)r->gen_commit,
              (unsigned long long)r->boot_count_new);
    ck_printf("store: security manifest sequence=%llu generation=%llu keyslot=%s previous=%s\n",
              (unsigned long long)r->secman_seq, (unsigned long long)r->gen_commit,
              r->secman_keyslot ? "bound" : "none", r->secman_prev ? "linked" : "genesis");
    ck_printf("store: limit: anchor shares this disk, so a whole-disk rollback is not detectable "
              "(needs TPM NV or another external counter)\n");
}

#ifdef CK_SERVICE
/* P05 cut 1: continuity (identity + ALLEN subject) runs on every Store open
 * (svc/continuity_service.c). 0 = REFUSED: the Store keys are erased, the
 * disk bytes stay as found, the lifecycle stays LOCKED and the NVMe stays
 * bound for the stop order. */
static int service_continuity(void)
{
#ifdef CK_HARDWARE_STAGING
    int o = ck_cont_service_start(g_ss, g_ss->uuid, ck_owner_root_pk, sizeof ck_owner_root_pk, CC_SOURCE_OPERATOR);
#else
    int o = ck_cont_service_start(g_ss, g_ss->uuid, 0, 0, CC_SOURCE_QUALIFICATION);
#endif
    if (o == CK_CONT_REFUSED) {
        bz(&g_ss->keys, sizeof g_ss->keys);
        g_service_locked_rc = CK_SB_E_CONTINUITY;
        ck_puts("store: service lifetime: continuity REFUSED, Store keys erased, lifecycle stays LOCKED "
                "(disk as found; NVMe stays bound for the stop order)\n");
        return 0;
    }
    return 1;
}
#endif

#ifdef CK_PI5_UNLOCK
/* Pi unlock image policy (ck_stage_store calls this, the host test pi5_unlock_test drives it).
 * secret NULL (no source gave one): refused before the disk is read, nothing written. Otherwise the
 * Slot 1 recovery path with the hardware policy: a wrong secret fails the K_vol unwrap tag before the
 * disk is opened; a disk with no KeySlotManifest (for example a TEST-tier Store) is refused; a blank
 * disk is formatted with a PRODUCTION-class Store under a freshly drawn uuid. */
int ck_store_pi5_unlock_run(const disk_dev *d, const uint8_t *secret, const char *commit, ck_store_report *r)
{
    if (!secret) {
        bz(r, sizeof *r);
        bcp(r->prev_commit, "none", 5);
        r->identity_class = M5_ID_PRODUCTION;
        r->key_source = "recovery-keyslot";
        return fail(r, "keyed", "no recovery secret source in this image; disk not read, not formatted",
                    CK_SB_E_BLOCKED_OPERATOR);
    }
    return ck_store_unlock_boot(d, secret, 0, commit ? commit : "unknown", CK_SB_HW, r);
}
#endif

#ifdef CK_PI5_FACT
#if !defined(CK_PI5_UNLOCK) || !defined(CK_PI5_UNLOCK_CARD)
#error "CK_PI5_FACT needs CK_PI5_UNLOCK and CK_PI5_UNLOCK_CARD (production-class Store, card request source)"
#endif
int ck_store_pi5_fact_stage(const ck_store_report *r)
{
    struct ck_fact_result fr;
    int rc = ck_pi5_fact_run(r->verdict == CK_SB_COMMITTED ? g_ss : 0, &ck_fact_req_boot, &fr);
    ck_fact_req_clear();
    return rc;
}
#endif

/* Kernel stage. ck_dev_boot_disk comes from dev/devices.c. */
const disk_dev *ck_dev_boot_disk(void);
void ck_dev_nvme_release(void);

int ck_stage_store(void)
{
    const disk_dev *d = ck_dev_boot_disk();
    if (!d) {
        ck_printf("store: REFUSED proof=io step=\"no boot disk\" (NVMe not bound; see nvme/dma_gate lines)\n");
        ck_art_stage_load(0, "no boot disk");
        return -1;
    }
    ss_keys keys;
    ck_store_report r;
    const char *commit = ck_commit();
    int rc;
#ifdef CK_HARDWARE_STAGING
    {
        uint8_t fp[32];
        sha256_hash(ck_owner_root_pk, sizeof ck_owner_root_pk, fp);
        ck_printf("owner: provisioned at build time (public only): owner_root_ed25519 sha256=%02x%02x%02x%02x%02x%02x%02x%02x "
                  "store_uuid=%02x%02x%02x%02x...\n",
                  fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7], ck_owner_store_uuid[0],
                  ck_owner_store_uuid[1], ck_owner_store_uuid[2], ck_owner_store_uuid[3]);
    }
    rc = ck_store_production_keys(&keys);
    if (rc) {
        bz(&keys, sizeof keys);
        ck_printf("store: REFUSED proof=keyed step=\"production Store key source\" rc=%d (BlockedOperator: "
                  "K_vol needs the TRUST-1 key ceremony, Gate 6 TPM keyslot or the operator recovery keyslot); "
                  "disk not read, not formatted\n",
                  rc);
        ck_art_stage_load(0, "production Store key source BLOCKED_OPERATOR");
#ifdef CK_SERVICE
        g_service_locked_rc = rc;
        g_disk = d;
        ck_puts("store: service lifetime: Store LOCKED, NVMe stays bound for `unlock <64-hex recovery secret>` "
                "or the lifecycle stop order\n");
#else
        ck_dev_nvme_release();
#endif
        return rc;
    }
    rc = store_boot_run(d, &keys, ck_owner_store_uuid, commit ? commit : "unknown", &r);
#else
#ifdef CK_TEST_STORE_CRASH
    d = ck_store_crash_setup(d);
#endif
#ifdef CK_TEST_CONTINUITY
    {
        /* K-7: a modes 5..11 plan runs the continuity / Recovery Core test
         * boot INSTEAD of the boot-record commit (svc/continuity_boot.h). */
        int crc = 0;
        if (ck_cont_boot_stage(d, &crc)) {
            ck_art_stage_load(0, "continuity test mode");
            ck_dev_nvme_release();
            return crc;
        }
    }
#endif
#if defined(CK_SERVICE) && !defined(CK_SERVICE_TEST_KEYS)
    /* Production service image without owner provisioning: the production
     * key source only (it refuses today: no in-kernel K_vol unwrap, P04). No
     * TEST key is ever used here. */
    rc = ck_store_production_keys(&keys);
    bz(&keys, sizeof keys);
    if (rc == 0) rc = CK_SB_E_BLOCKED_OPERATOR; /* no Store UUID without CK_HARDWARE_STAGING provisioning */
    ck_printf("store: REFUSED proof=keyed step=\"production Store key source\" rc=%d (service image stays LOCKED: "
              "K_vol needs the TRUST-1 key ceremony, Gate 6 TPM keyslot or the operator recovery keyslot); "
              "disk not read, not formatted\n", rc);
    ck_art_stage_load(0, "production Store key source BLOCKED_OPERATOR");
    g_service_locked_rc = rc;
    g_disk = d;
    ck_puts("store: service lifetime: Store LOCKED, NVMe stays bound for `unlock <64-hex recovery secret>` "
            "or the lifecycle stop order\n");
    (void)commit;
    return rc;
#else
#if defined(CK_PI5_UNLOCK)
    {
        uint8_t secret[CK_SB_SECRET_LEN];
        const char *src = 0;
        int have = ck_pi5_unlock_secret(secret, &src) == 0;
        if (have) ck_printf("unlock_source: %s\n", src ? src : "unknown");
        else ck_puts("unlock_source: none (no recovery secret given); Store not opened\n");
        rc = ck_store_pi5_unlock_run(d, have ? secret : 0, commit, &r);
        bz(secret, sizeof secret);
        bz(&keys, sizeof keys);
    }
#else
    ck_store_test_keys(&keys);
    rc = store_boot_run(d, &keys, ck_store_test_uuid, commit ? commit : "unknown", &r);
#endif
#endif
#endif
    bz(&keys, sizeof keys);
    store_boot_print(&r);
    /* Signed artifact candidates live in this Store: read them while the disk
     * is still bound (the loader verifies them later, as untrusted bytes). */
    ck_art_stage_load(r.verdict == CK_SB_COMMITTED ? g_ss : 0, r.step);
#ifdef CK_PI5_FACT
    {
        int frc = ck_store_pi5_fact_stage(&r);
        if (frc && rc == 0) rc = frc;
    }
#endif
#ifdef CK_SERVICE
    /* Service lifetime (core/lifecycle.c): an open Store keeps the NVMe bound
     * until the lifecycle stop order releases it, in that order. A refused
     * Store releases the disk now, exactly as the diagnostic image does. */
    if (r.verdict == CK_SB_COMMITTED) {
        if (!service_continuity()) return CK_SB_E_CONTINUITY;
        g_service_open = 1;
        ck_puts("store: service lifetime: Store open, NVMe stays bound until the lifecycle stop order\n");
        return rc;
    }
#endif
    ck_dev_nvme_release(); /* last disk user: revoke NVMe bus mastering */
    return rc;
}

#ifdef CK_SERVICE
int ck_store_service_ready(void)
{
    return g_service_open && g_ss;
}

/* Stop order step 1: erase the Store keys. Every commit is already durable
 * (ss_transact returns after its final flush), so nothing is pending. */
int ck_store_service_close(void)
{
    if (!g_service_open) return 0;
    g_service_open = 0;
    ck_cont_service_stop();
    if (g_ss) bz(&g_ss->keys, sizeof g_ss->keys);
    return 1;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* "unlock" while LOCKED. With no argument the production key source is asked
 * again and refuses (CK_SB_E_BLOCKED_OPERATOR: no TPM Slot 0 path). With the
 * operator's 64-hex recovery secret the Slot 1 keyslot path runs on the disk
 * kept bound at boot (ck_store_unlock_boot). The secret bytes are wiped
 * before return and never printed. Returns 1 only when the Store is open. */
int ck_store_service_unlock(const char *arg, size_t arg_len)
{
    if (g_service_open) return 1;
    if (arg_len == 0) {
        ss_keys keys;
        int rc = ck_store_production_keys(&keys);
        bz(&keys, sizeof keys);
        ck_printf("store: unlock REFUSED proof=keyed step=\"production Store key source\" rc=%d (%s)\n",
                  rc ? rc : g_service_locked_rc, "BlockedOperator: no TPM Slot 0 unwrap; give `unlock <64-hex recovery secret>`");
        return 0;
    }
    uint8_t secret[CK_SB_SECRET_LEN];
    if (arg_len != 2 * CK_SB_SECRET_LEN) {
        ck_printf("store: unlock REFUSED proof=keyed step=\"recovery secret syntax\" rc=%d (64 hex digits expected, got %u)\n",
                  CK_SB_E_SECRET_REJECTED, (unsigned)arg_len);
        return 0;
    }
    for (size_t i = 0; i < CK_SB_SECRET_LEN; i++) {
        int hi = hex_nibble(arg[2 * i]), lo = hex_nibble(arg[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            bz(secret, sizeof secret);
            ck_printf("store: unlock REFUSED proof=keyed step=\"recovery secret syntax\" rc=%d (not hex)\n",
                      CK_SB_E_SECRET_REJECTED);
            return 0;
        }
        secret[i] = (uint8_t)((hi << 4) | lo);
    }
    if (!g_disk) {
        bz(secret, sizeof secret);
        ck_printf("store: unlock REFUSED proof=io step=\"no boot disk bound\" rc=%d\n", g_service_locked_rc);
        return 0;
    }
    ck_store_report r;
    const char *commit = ck_commit();
#ifdef CK_HARDWARE_STAGING
    const uint8_t *expect = ck_owner_store_uuid;
#else
    const uint8_t *expect = 0;
#endif
    int rc = ck_store_unlock_boot(g_disk, secret, expect, commit ? commit : "unknown", CK_SB_HW, &r);
    bz(secret, sizeof secret);
    store_boot_print(&r);
    if (rc || r.verdict != CK_SB_COMMITTED) {
        ck_printf("store: unlock REFUSED proof=%s step=\"%s\" rc=%d (%s); still LOCKED, disk not reformatted\n",
                  r.proof, r.step, r.rc, err_name(r.rc));
        g_service_locked_rc = r.rc;
        return 0;
    }
    g_service_open = 1;
    ck_printf("store: unlock ok source=recovery-keyslot slot=%u genesis=%d generation=%llu boot_count=%llu\n",
              (unsigned)CK_RECOVERY_SLOT_ID, r.unlocked_genesis, (unsigned long long)r.gen_commit,
              (unsigned long long)r.boot_count_new);
    /* Signed artifact candidates live in this Store; read them now that it is open. */
    ck_art_stage_load(g_ss, r.step);
    if (!service_continuity()) {
        g_service_open = 0;
        return 0;
    }
    return 1;
}

/* 64 hex digits -> 32 secret bytes; 0 ok. out is wiped on refusal. */
static int parse_secret(const char *a, size_t n, uint8_t out[CK_SB_SECRET_LEN])
{
    if (n != 2 * CK_SB_SECRET_LEN) return -1;
    for (size_t i = 0; i < CK_SB_SECRET_LEN; i++) {
        int hi = hex_nibble(a[2 * i]), lo = hex_nibble(a[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            bz(out, CK_SB_SECRET_LEN);
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* "rotate <current 64-hex> <new 64-hex>" while READY (P04 cut 2b). Both
 * secrets are wiped before return and never printed. Returns 1 only when
 * the rotation transaction committed. */
int ck_store_service_rotate(const char *arg, size_t arg_len)
{
    uint8_t cur[CK_SB_SECRET_LEN], nxt[CK_SB_SECRET_LEN];
    ck_store_report r;
    if (!g_service_open || !g_disk) {
        ck_printf("store: rotate REFUSED proof=keyed step=\"Store not open\" rc=%d\n", CK_SB_E_NO_KEYSLOT);
        return 0;
    }
    if (arg_len != 4 * CK_SB_SECRET_LEN + 1 || arg[2 * CK_SB_SECRET_LEN] != ' ' ||
        parse_secret(arg, 2 * CK_SB_SECRET_LEN, cur) != 0 ||
        parse_secret(arg + 2 * CK_SB_SECRET_LEN + 1, 2 * CK_SB_SECRET_LEN, nxt) != 0) {
        bz(cur, sizeof cur);
        bz(nxt, sizeof nxt);
        ck_printf("store: rotate REFUSED proof=keyed step=\"recovery secret syntax\" rc=%d (two 64-hex secrets expected, got %u bytes)\n",
                  CK_SB_E_SECRET_REJECTED, (unsigned)arg_len);
        return 0;
    }
    int rc = ck_store_rotate_recovery(g_disk, cur, nxt, &r);
    bz(cur, sizeof cur);
    bz(nxt, sizeof nxt);
    if (rc || r.verdict != CK_SB_COMMITTED) {
        ck_printf("store: rotate REFUSED proof=%s step=\"%s\" rc=%d (%s); Store unchanged, still open\n", r.proof, r.step,
                  r.rc, err_name(r.rc));
        return 0;
    }
    ck_printf("store: rotated recovery keyslot manifest_sequence=%llu security_sequence=%llu generation=%llu (previous secret retired)\n",
              (unsigned long long)r.keyslot_seq, (unsigned long long)r.secman_seq, (unsigned long long)r.gen_commit);
    return 1;
}
#endif

ss_store *store_boot_store(void)
{
    return g_ss;
}
