/* test_continuity_recovery.c -- host tests of svc/continuity_recovery.c (C
 * continuity port, cut 5: Recovery Core inspection, repair, operator
 * provisioning; contract native/kernel/CONTINUITY_RECOVERY_CONTRACT.md section
 * 6.2, aienos#222). Oracle: crates/aienos-kernel/src/recovery_core.rs and
 * recovery_core_tests.rs.
 *
 * Storage: the REAL sealed Store (native/store, M5 envelopes, anchor) in a
 * file, at 4096 and 512 byte blocks. Entropy: the real ck_rng over a mocked
 * RNDR. Every inspection and every refused action must leave the image byte
 * for byte unchanged (INV-13, INV-16).
 *
 * One test per Rust recovery_core test row: 91d inspection never writes, 91e
 * repair needs the operator, 91f provisioning is operator only, 91g identity
 * lost in the newest root never looks unprovisioned, 91h malformed peer
 * without identity is not repaired, 91i orphans are Corrupt, 91j identity loss
 * offers no minting action, 91k challenges bind state and action. Rows 91l-91p
 * (operator auth primitive) are test_continuity_resolve (cut 3). The QEMU rows
 * 88-91c are NOT_RUN.
 * Mutants (make continuity-mutants) must each turn this test FAIL. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ck_test.h"
#include "continuity_recovery.h"
#include "disk_file.h"

#define CK_(c, ...)                                                            \
    do {                                                                       \
        ck_t_run++;                                                            \
        if (!(c)) {                                                            \
            ck_t_fail++;                                                       \
            printf("  FAIL %s:%d: %s: ", __FILE__, __LINE__, #c);              \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

#define A_UNITS 4u
#define S_UNITS 512u
#define T_UNITS (A_UNITS + S_UNITS)
#define IMG_BYTES ((size_t)T_UNITS * 4096u)

static ss_workspace g_ws;
static ss_store g_s;
static disk_file g_f;
static disk_dev g_d;
static st_disk g_sd;
static st_dev g_sdev;
static ts_device g_tdev;
static ss_keys g_k;
static uint32_t g_bs;
static char g_path[256];
static struct cr_work g_w;
static struct cr_txwork g_tw;
static struct cr_view g_v, g_v2, g_out;
static struct cr_source g_src;
static struct cr_sink g_snk;
static struct cr_sealed_sink g_sk;
static struct rc_env E;
static const uint8_t RUUID[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
static uint8_t snap_img[IMG_BYTES], now_img[IMG_BYTES];
static uint8_t OPKEY[32], BADKEY[32];

static int g_open;
static void dev_close(void)
{
    if (g_open) disk_file_close(&g_f);
    g_open = 0;
}
static int dev_open(int create)
{
    dev_close();
    uint32_t bpu = 4096u / g_bs;
    if (create) unlink(g_path);
    memset(&g_f, 0, sizeof g_f);
    if (disk_file_open(&g_f, &g_d, g_path, g_bs, (uint64_t)(A_UNITS + S_UNITS) * bpu, create) != 0) return -1;
    g_open = 1;
    if (st_disk_bind(&g_sd, &g_d, (uint64_t)A_UNITS * bpu, S_UNITS, &g_sdev) != 0) return -2;
    ss_ts_device(&g_d, &g_tdev);
    return 0;
}
static void make_keys(void)
{
    uint8_t kvol[32];
    memset(kvol, 0x77, 32);
    m5_subkeys sk;
    m5_derive_subkeys(kvol, M5_ID_TEST, 0, &sk);
    memset(&g_k, 0, sizeof g_k);
    g_k.identity_class = M5_ID_TEST;
    g_k.key_generation = 1;
    memcpy(g_k.k_root_auth, sk.k_root_auth, 32);
    memcpy(g_k.k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);
}
static void bind(void)
{
    g_sk.s = &g_s;
    g_sk.hook = NULL;
    g_sk.hook_arg = NULL;
    cr_bind_sealed(&g_src, &g_s);
    cr_bind_sealed_sink(&g_snk, &g_sk);
}
/* A formatted store, no identity. */
static void fresh(void)
{
    CK_(dev_open(1) == 0, "rig create");
    CK_(ss_format(&g_sdev, &g_tdev, 0, RUUID, &g_k, &g_ws) == 0, "format");
    CK_(ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws) == 0, "open genesis");
    bind();
}
static void env_open(void)
{
    CK_(dev_open(0) == 0, "reopen rig");
    E.dev = &g_sdev;
    E.anchor = &g_tdev;
    E.anchor_lba = 0;
    E.keys = &g_k;
    E.ws = &g_ws;
    E.store = &g_s;
    E.w = &g_w;
    E.tw = &g_tw;
    E.view = &g_v2;
}
static int file_load(uint8_t *dst)
{
    dev_close();
    FILE *f = fopen(g_path, "rb");
    if (!f) return -1;
    size_t n = fread(dst, 1, IMG_BYTES, f);
    fclose(f);
    return n == IMG_BYTES ? 0 : -2;
}
static void snapshot(void) { CK_(file_load(snap_img) == 0, "snapshot"); }
static int unchanged(void) { return file_load(now_img) == 0 && memcmp(now_img, snap_img, IMG_BYTES) == 0; }
/* Store-region unit u of the image now equals the snapshot. */
static int unit_same(unsigned u)
{
    size_t o = (size_t)(A_UNITS + u) * 4096u;
    return file_load(now_img) == 0 && memcmp(now_img + o, snap_img + o, 4096) == 0;
}
static int unit_zero(unsigned u)
{
    size_t o = (size_t)(A_UNITS + u) * 4096u;
    if (file_load(now_img) != 0) return 0;
    for (size_t i = 0; i < 4096; i++)
        if (now_img[o + i]) return 0;
    return 1;
}
static void fill_unit(unsigned u, uint8_t fillb)
{
    dev_close();
    FILE *f = fopen(g_path, "r+b");
    CK_(f != NULL, "open image");
    static uint8_t junk[4096];
    memset(junk, fillb, sizeof junk);
    if (f) {
        fseek(f, (long)((A_UNITS + u) * 4096u), SEEK_SET);
        CK_(fwrite(junk, 1, sizeof junk, f) == sizeof junk, "write junk");
        fclose(f);
    }
}
static void flip_byte(uint64_t unit, unsigned off)
{
    dev_close();
    FILE *f = fopen(g_path, "r+b");
    CK_(f != NULL, "open image");
    if (!f) return;
    long pos = (long)((A_UNITS + unit) * 4096u + off);
    uint8_t b = 0;
    fseek(f, pos, SEEK_SET);
    CK_(fread(&b, 1, 1, f) == 1, "read byte");
    b ^= 0xff;
    fseek(f, pos, SEEK_SET);
    CK_(fwrite(&b, 1, 1, f) == 1, "write byte");
    fclose(f);
}

/* ---- mocked RNDR ---- */
struct mock {
    int present;
    uint64_t ctr;
};
static struct mock g_m;
static struct ck_rng_ops g_ops;
static struct ck_rng g_rng;
static int m_present(void *c) { return ((struct mock *)c)->present; }
static int m_read(void *c, uint64_t *out)
{
    struct mock *m = c;
    uint64_t z = (m->ctr += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    *out = z ^ (z >> 31);
    return 1;
}
static void rng_init(uint64_t seed, int present)
{
    g_m.present = present;
    g_m.ctr = seed;
    g_ops.present = m_present;
    g_ops.read = m_read;
    g_ops.ctx = &g_m;
    memset(&g_rng, 0, sizeof g_rng);
    (void)ck_rng_probe(&g_rng, &g_ops);
}

static struct cc_record fact(const char *s)
{
    struct cc_record r;
    memset(&r, 0, sizeof r);
    r.status = CC_EPI_DIRECT_OBSERVATION;
    r.len = (uint16_t)strlen(s);
    r.statement = (const uint8_t *)s;
    return r;
}

static uint8_t g_agent[32], g_mem[32];

/* Provisioned (Qualification, as the Rust fixture) with one remembered fact. */
static void remembered(void)
{
    fresh();
    rng_init(5005, 1);
    const char *why = NULL;
    int rc = 0;
    CK_(cr_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, CC_SOURCE_QUALIFICATION, &g_v, &why, &rc) == CR_RESOLVED,
        "provision");
    struct cc_record r1 = fact("keep this");
    struct cr_update up = {NULL, &r1, 1};
    static struct cr_view cur;
    memcpy(&cur, &g_v, sizeof cur);
    CK_(cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &up, 0, &g_v, &why, &rc) == CR_RESOLVED, "remember");
    memcpy(g_agent, g_v.root.agent_id, 32);
    memcpy(g_mem, g_v.memory, 32);
}
static void degrade(uint8_t fillb)
{
    uint32_t active = st_active_slot(&g_s.st);
    fill_unit(1u - active, fillb);
}
static int raw_commit(uint16_t kind, const uint8_t *b, size_t n)
{
    ss_object so = {kind, 1, b, n};
    return ss_transact(&g_s, &so, 1, NULL, NULL, NULL);
}
/* first Store unit of the first AgentRoot envelope */
static uint64_t root_unit(void)
{
    for (uint32_t i = 0; i < g_s.nclaims; i++) {
        if (g_ws.claims[i].c.obj.object_kind != CC_KIND_AGENT_ROOT) continue;
        uint32_t n = 0;
        const sv1_entry *cat = st_catalog(&g_s.st, &n);
        for (uint32_t j = 0; j < n; j++)
            if (memcmp(cat[j].object_id, g_ws.claims[i].sid, 32) == 0) return cat[j].first_unit;
    }
    CK_(0, "no agent root envelope found");
    return 0;
}

static struct rc_record R, R2;
static void inspect(struct rc_record *r)
{
    env_open();
    CK_(rc_inspect(&E, r) == 0, "inspect");
}
static void respond(const struct rc_record *r, uint8_t action, const uint8_t key[32], uint8_t out[32])
{
    uint8_t ch[32];
    CK_(rc_challenge(r, action, ch) == 1, "challenge available");
    cr_operator_response(key, ch, out);
}
static int do_repair(const uint8_t resp[32], struct rc_record *after)
{
    env_open();
    return rc_repair_degraded_peer(&E, OPKEY, resp, after);
}
static int do_prov(const uint8_t key[32], const uint8_t resp[32], int *cro, const char **why)
{
    env_open();
    return rc_provision_identity(&E, key, resp, &g_rng, &g_out, cro, why, NULL);
}

/* ---- 91d: inspection never writes and names the reason (MR-1) ---- */
static void t_91d(void)
{
    char t[200];
    /* blank device */
    CK_(dev_open(1) == 0, "blank");
    snapshot();
    inspect(&R);
    CK_(unchanged(), "bs=%u inspect of a blank device wrote", g_bs);
    CK_(R.reason == RC_STORE_UNFORMATTED && !R.have_mount && rc_applicable(&R) == 0, "blank: reason %d mount_rc %d", R.reason, R.mount_rc);
    CK_(R.slot[0] == RC_SLOT_ZERO && R.slot[1] == RC_SLOT_ZERO && !R.have_uuid, "blank slots");
    CK_(rc_challenge(&R, CR_ACTION_PROVISION_IDENTITY, (uint8_t[32]){0}) == 0, "no challenge without uuid and mount");
    CK_(rc_marker_entry(t, sizeof t, &R) > 0 && strcmp(t, "RECOVERY_CORE: ENTERED reason=StoreUnformatted") == 0, "marker '%s'", t);

    /* formatted, no identity */
    fresh();
    snapshot();
    inspect(&R);
    CK_(unchanged(), "inspect of an unprovisioned store wrote");
    CK_(R.reason == RC_UNPROVISIONED && R.have_mount && R.mount_state == ST_VALID && !R.have_identity, "unprovisioned reason %d", R.reason);
    CK_(R.slot[0] == RC_SLOT_SUPERBLOCK && R.slot[1] == RC_SLOT_ZERO && R.have_uuid && memcmp(R.uuid, RUUID, 16) == 0,
        "slot views and uuid");
    CK_(R.have_catalog && R.n_roots == 0 && R.n_manifests == 0 && R.n_other == 0, "catalog counts");

    /* healthy */
    remembered();
    snapshot();
    inspect(&R);
    CK_(unchanged(), "inspect of a healthy store wrote");
    CK_(R.reason == RC_REASON_NONE && R.have_identity && memcmp(R.agent_id, g_agent, 32) == 0, "healthy: reason %d", R.reason);
    CK_(R.n_roots == 1 && R.n_manifests == 2 && rc_applicable(&R) == 0, "one root, two manifests, nothing applicable");
    CK_(rc_marker_entry(t, sizeof t, &R) > 0 && strcmp(t, "RECOVERY_CORE: NOT_NEEDED") == 0, "marker '%s'", t);

    /* degraded: malformed peer */
    degrade(0xa5);
    snapshot();
    uint32_t active_before = 0;
    inspect(&R);
    CK_(unchanged(), "inspect of a degraded store wrote (MR-1)");
    inspect(&R);
    CK_(unchanged(), "second inspect wrote");
    (void)active_before;
    CK_(R.reason == RC_DEGRADED && R.peer == ST_PEER_MALFORMED && R.mount_state == ST_DEGRADED_RECOVERY, "degraded reason %d", R.reason);
    CK_(R.have_identity && memcmp(R.agent_id, g_agent, 32) == 0, "record shows the same agent");
    CK_(R.slot[0] != R.slot[1] && (R.slot[0] == RC_SLOT_UNDECODABLE || R.slot[1] == RC_SLOT_UNDECODABLE), "one undecodable slot");
    CK_(rc_marker_entry(t, sizeof t, &R) > 0 && strcmp(t, "RECOVERY_CORE: ENTERED reason=Degraded(Malformed)") == 0, "marker '%s'", t);
    CK_(rc_applicable(&R) == CR_ACTION_REPAIR_DEGRADED_PEER, "88: repair offered");
    CK_(rc_marker_challenge(t, sizeof t, &R, CR_ACTION_REPAIR_DEGRADED_PEER) > 0 &&
            strncmp(t, "RECOVERY_CHALLENGE: action=repair-degraded-peer challenge=", 58) == 0 && strlen(t) == 58 + 64,
        "challenge marker '%s'", t);
    CK_(unchanged(), "markers wrote nothing");
    /* NULL arguments */
    CK_(rc_inspect(NULL, &R) == -1 && rc_inspect(&E, NULL) == -1, "NULL args");
}

/* ---- 91e (88a-c, 89, 89a, 89b): repair needs the operator, restores a writable store (MR-6) ---- */
static void t_91e(void)
{
    remembered();
    degrade(0xa5);
    inspect(&R);
    CK_(rc_applicable(&R) == CR_ACTION_REPAIR_DEGRADED_PEER, "applicable");
    uint8_t good[32], wrong_key[32], wrong_action[32], zero[32] = {0}, other_state[32];
    respond(&R, CR_ACTION_REPAIR_DEGRADED_PEER, OPKEY, good);
    respond(&R, CR_ACTION_REPAIR_DEGRADED_PEER, BADKEY, wrong_key);
    respond(&R, CR_ACTION_PROVISION_IDENTITY, OPKEY, wrong_action);
    /* a response to another state's challenge (88c) */
    cr_operator_response(OPKEY, (uint8_t[32]){0x42}, other_state);
    uint32_t active = st_active_slot(&g_s.st); /* g_s is the store inspect opened */
    snapshot();
    const uint8_t *bad[4] = {zero, wrong_key, wrong_action, other_state};
    char t[100];
    for (int i = 0; i < 4; i++) {
        int rc = do_repair(bad[i], NULL);
        CK_(rc == RC_UNAUTHORISED, "bad response %d: %s", i, rc_outcome_name(rc));
        CK_(unchanged(), "refused repair %d wrote", i);
    }
    CK_(rc_marker_refused(t, sizeof t, RC_UNAUTHORISED, 0) > 0 && strcmp(t, "RECOVERY_REFUSED (Unauthorised)") == 0, "marker '%s'", t);
    /* provisioning is not the applicable action */
    {
        int cro = -1;
        int rc = do_prov(OPKEY, wrong_action, &cro, NULL);
        CK_(rc == RC_NOT_APPLICABLE && unchanged(), "provision on a degraded store: %s", rc_outcome_name(rc));
    }
    /* 89: the authorised repair */
    snapshot();
    uint64_t gen = R.generation;
    int rc = do_repair(good, &R2);
    CK_(rc == RC_OK, "authorised repair: %s", rc_outcome_name(rc));
    CK_(R2.reason == RC_REASON_NONE && R2.mount_state == ST_VALID && R2.peer == ST_PEER_ZERO, "healthy after repair (reason %d)", R2.reason);
    CK_(unit_zero(1u - active), "the inactive slot is zero (MR-6)");
    CK_(unit_same(active), "the ACTIVE slot is byte for byte untouched (MR-6)");
    CK_(R2.generation == gen && R2.have_identity, "generation unchanged, identity kept");
    CK_(rc_marker_done(t, sizeof t, CR_ACTION_REPAIR_DEGRADED_PEER, NULL) > 0 &&
            strcmp(t, "RECOVERY_ACTION: repair-degraded-peer DONE") == 0, "marker '%s'", t);
    /* 89a: same identity and memory, writable again */
    env_open();
    {
        ss_store *s = &g_s;
        CK_(ss_open(s, &g_sdev, &g_tdev, 0, &g_k, &g_ws) == 0 && s->st.state == ST_VALID, "reopen valid");
        bind();
        int committed = 0;
        CK_(cr_resume(&g_src, &g_snk, &g_w, &g_tw, &g_v, &committed, NULL, NULL) == CR_RESOLVED && committed == 1, "resume writable");
        CK_(memcmp(g_v.root.agent_id, g_agent, 32) == 0 && memcmp(g_v.memory, g_mem, 32) == 0 && g_v.cortex_count == 1,
            "same agent, same memory");
    }
    /* 89b: replay of the old authorisation on the new state */
    snapshot();
    rc = do_repair(good, NULL);
    CK_(rc == RC_NOT_APPLICABLE, "replay: %s", rc_outcome_name(rc));
    CK_(unchanged(), "replay wrote");
    CK_(rc_marker_refused(t, sizeof t, rc, 0) > 0 && strcmp(t, "RECOVERY_REFUSED (NotApplicable)") == 0, "marker '%s'", t);
}

/* ---- 91f (90, 90a, 90b): provisioning is operator only and only on an unprovisioned store (MR-9) ---- */
static void t_91f(void)
{
    char t[200];
    fresh();
    inspect(&R);
    CK_(rc_applicable(&R) == CR_ACTION_PROVISION_IDENTITY, "90: provision offered");
    CK_(rc_marker_challenge(t, sizeof t, &R, CR_ACTION_PROVISION_IDENTITY) > 0, "challenge marker");
    uint8_t good[32], wrong_action[32], seven[32];
    memset(seven, 7, 32);
    respond(&R, CR_ACTION_PROVISION_IDENTITY, OPKEY, good);
    respond(&R, CR_ACTION_REPAIR_DEGRADED_PEER, OPKEY, wrong_action);
    snapshot();
    rng_init(6006, 1);
    int cro = -1;
    CK_(do_prov(OPKEY, seven, &cro, NULL) == RC_UNAUTHORISED && unchanged(), "90a: wrong response");
    CK_(do_prov(BADKEY, good, &cro, NULL) == RC_UNAUTHORISED && unchanged(), "90a: wrong key");
    CK_(do_prov(OPKEY, wrong_action, &cro, NULL) == RC_UNAUTHORISED && unchanged(), "response for the other action");
    /* repair is not applicable here */
    CK_(do_repair(wrong_action, NULL) == RC_NOT_APPLICABLE && unchanged(), "repair on an unprovisioned store");
    /* no entropy: authorised, but nothing may be minted without it */
    rng_init(6007, 0);
    CK_(do_prov(OPKEY, good, &cro, NULL) == RC_CONTINUITY && cro == CR_NO_ENTROPY && unchanged(), "no entropy: outcome %d", cro);
    CK_(rc_marker_refused(t, sizeof t, RC_CONTINUITY, cro) > 0 && strncmp(t, "RECOVERY_REFUSED (Continuity(", 29) == 0,
        "marker '%s'", t);
    /* 90b: authorised */
    rng_init(6008, 1);
    uint64_t gen = R.generation;
    int rc = do_prov(OPKEY, good, &cro, NULL);
    CK_(rc == RC_OK, "authorised provisioning: %s (cr %d)", rc_outcome_name(rc), cro);
    CK_(g_out.root.source == CC_SOURCE_OPERATOR, "source is Operator, not Qualification (INV-18, MR-9): %u", g_out.root.source);
    CK_(memcmp(g_out.root.store_uuid, RUUID, 16) == 0, "Store uuid from the inspection");
    CK_(g_out.manifest.sequence == 1 && g_out.manifest.incarnation == 1 && g_out.state.written_at == 1, "genesis view");
    CK_(g_out.root.provisioned_generation == gen + 1, "provisioned_generation");
    CK_(rc_marker_done(t, sizeof t, CR_ACTION_PROVISION_IDENTITY, g_out.root.agent_id) > 0 &&
            strncmp(t, "RECOVERY_ACTION: provision-identity DONE agent=", 47) == 0, "marker '%s'", t);
    uint8_t agent[32];
    memcpy(agent, g_out.root.agent_id, 32);
    /* a cold resume returns that agent, and the stored root says Operator */
    env_open();
    CK_(ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws) == 0, "cold open");
    bind();
    CK_(cr_resolve(&g_src, &g_w, &g_v, NULL, NULL) == CR_RESOLVED && memcmp(g_v.root.agent_id, agent, 32) == 0, "cold resolve");
    CK_(g_v.root.source == CC_SOURCE_OPERATOR, "stored source is Operator (MR-9)");
    int committed = 0;
    CK_(cr_resume(&g_src, &g_snk, &g_w, &g_tw, &g_v, &committed, NULL, NULL) == CR_RESOLVED && committed == 1 &&
            memcmp(g_v.root.agent_id, agent, 32) == 0,
        "cold resume returns that agent");
    /* the same authorisation cannot provision again */
    snapshot();
    CK_(do_prov(OPKEY, good, &cro, NULL) == RC_NOT_APPLICABLE && unchanged(), "replay");
}

static const char *refusal_ok(const struct rc_record *r)
{
    /* never Unprovisioned, never repairable */
    return (r->reason != RC_UNPROVISIONED && r->reason != RC_REASON_NONE && rc_applicable(r) == 0) ? NULL : "bad reason";
}

/* every action, with a response valid for the exact state if one can be formed, is refused and writes nothing */
static void all_actions_refused(const struct rc_record *r, const char *what)
{
    uint8_t resp[32];
    for (int a = 1; a <= 2; a++) {
        if (rc_challenge(r, (uint8_t)a, resp)) cr_operator_response(OPKEY, resp, resp);
        else memset(resp, 0x55, 32);
        int rc = a == 1 ? do_repair(resp, NULL) : do_prov(OPKEY, resp, &(int){0}, NULL);
        CK_(rc == RC_NOT_APPLICABLE, "%s: action %d: %s", what, a, rc_outcome_name(rc));
        CK_(unchanged(), "%s: action %d wrote", what, a);
    }
}

/* ---- 91g: identity lost in the newest root never looks unprovisioned (MR-5) ---- */
static void t_91g(void)
{
    char t[100];
    fresh();
    rng_init(7007, 1);
    const char *why = NULL;
    int rc = 0;
    CK_(cr_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, CC_SOURCE_QUALIFICATION, &g_v, &why, &rc) == CR_RESOLVED, "provision");
    flip_byte(root_unit(), 20);
    snapshot();
    inspect(&R);
    CK_(unchanged(), "inspect wrote");
    CK_(refusal_ok(&R) == NULL, "reason %d", R.reason);
    CK_(R.reason == RC_SEALED_REFUSAL || R.reason == RC_DEGRADED || R.reason == RC_STORE_MOUNT || R.reason == RC_CONTINUITY_CORRUPT,
        "a refusal reason");
    /* K-3 observed: the flipped ciphertext byte is refused by the sealed mount before continuity runs */
    CK_(R.reason == RC_SEALED_REFUSAL, "K-3 expected a sealed refusal, got reason %d rc %d", R.reason, R.mount_rc);
    CK_(rc_reason_text(t, sizeof t, &R) > 0 && strncmp(t, "SealedRefusal(", 14) == 0, "reason text '%s'", t);
    if (g_bs == 4096) printf("K-3/K-4 answer: byte 20 of the newest AgentRoot envelope flipped: reason=%d (RC_SEALED_REFUSAL=%d) mount_rc=%d (%s), mounted=%d\n", R.reason, RC_SEALED_REFUSAL, R.mount_rc, ss_strerror(R.mount_rc), R.have_mount);
    all_actions_refused(&R, "91g");
}

/* ---- 91h: a malformed peer with no resolvable identity is not repaired (MR-5, MR-7) ---- */
static void t_91h(void)
{
    fresh();
    degrade(0xa5);
    snapshot();
    inspect(&R);
    CK_(unchanged(), "inspect wrote");
    CK_(R.have_mount && R.mount_state == ST_DEGRADED_RECOVERY && R.peer == ST_PEER_MALFORMED, "degraded on a malformed peer");
    CK_(R.reason == RC_DEGRADED, "reason is Degraded, never Unprovisioned (MR-5): %d", R.reason);
    CK_(!R.have_identity && rc_applicable(&R) == 0, "no identity: nothing applicable (MR-5, MR-7): %d", rc_applicable(&R));
    all_actions_refused(&R, "91h");
}

/* ---- 91i: orphaned continuity objects are Corrupt, not Unprovisioned ---- */
static void t_91i(void)
{
    fresh();
    struct cc_manifest m;
    memset(&m, 0, sizeof m);
    memset(m.root, 0x77, 32);
    m.sequence = 1;
    m.incarnation = 1;
    memset(m.agent_state, 0x66, 32);
    static uint8_t b[CC_MAX_OBJECT_BYTES];
    size_t n = 0;
    CK_(cc_manifest_encode(&m, b, sizeof b, &n, NULL) == CC_OK && raw_commit(CC_KIND_MANIFEST, b, n) == 0, "orphan manifest");
    snapshot();
    inspect(&R);
    CK_(unchanged(), "inspect wrote");
    CK_(R.reason == RC_CONTINUITY_CORRUPT && R.why && !strcmp(R.why, "continuity objects without an agent root"),
        "reason %d why %s", R.reason, R.why ? R.why : "-");
    CK_(rc_applicable(&R) == 0, "nothing applicable");
    all_actions_refused(&R, "91i");
}

/* ---- 91j: identity loss through corruption offers no action that mints ---- */
static void t_91j(void)
{
    remembered();
    flip_byte(root_unit(), 20);
    snapshot();
    inspect(&R);
    CK_(unchanged(), "inspect wrote");
    CK_(R.reason == RC_SEALED_REFUSAL || R.reason == RC_STORE_MOUNT || R.reason == RC_CONTINUITY_CORRUPT || R.reason == RC_DEGRADED,
        "refusal reason %d", R.reason);
    CK_(rc_applicable(&R) == 0, "no action applicable");
    /* 91: ENTERED, and no challenge is offered */
    char t[200];
    CK_(rc_marker_entry(t, sizeof t, &R) > 0 && strncmp(t, "RECOVERY_CORE: ENTERED reason=", 30) == 0, "marker '%s'", t);
    CK_(rc_marker_challenge(t, sizeof t, &R, CR_ACTION_PROVISION_IDENTITY) == 0, "no challenge when no mount");
    uint8_t forged[32];
    memset(forged, 0x55, 32);
    CK_(do_prov(OPKEY, forged, &(int){0}, NULL) != RC_OK, "provision refused");
    CK_(do_repair(forged, NULL) != RC_OK, "repair refused");
    CK_(unchanged(), "no action wrote after identity loss");
    all_actions_refused(&R, "91j");
}

/* ---- 91k: challenges bind state and action (MR-2, MR-3 primitives are cut 3) ---- */
static void t_91k(void)
{
    remembered();
    degrade(0xa5);
    inspect(&R);
    uint8_t c1[32], c2[32], c3[32];
    CK_(rc_challenge(&R, CR_ACTION_REPAIR_DEGRADED_PEER, c1) == 1, "c1");
    degrade(0x5a); /* different on-disk state, same generation */
    inspect(&R2);
    CK_(rc_challenge(&R2, CR_ACTION_REPAIR_DEGRADED_PEER, c2) == 1, "c2");
    CK_(memcmp(c1, c2, 32) != 0, "different on-disk state, different challenge");
    CK_(memcmp(R.state_digest, R2.state_digest, 32) != 0, "digests differ");
    CK_(rc_challenge(&R, CR_ACTION_PROVISION_IDENTITY, c3) == 1 && memcmp(c1, c3, 32) != 0, "different action, different challenge");
    /* a response to the old state does not authorise a repair of the new one */
    uint8_t old[32];
    cr_operator_response(OPKEY, c1, old);
    snapshot();
    CK_(do_repair(old, NULL) == RC_UNAUTHORISED && unchanged(), "stale authorisation refused");
}

/* ---- k4: a newest generation that is sealed-valid but graph-broken (contract K-4) ----
 * Provision and remember one fact, then commit through the real sealed path a validly
 * encoded manifest (sequence 2, previous = the live manifest, right root) whose agent_state
 * object was never written. The anchor is fresh, so ss_open succeeds. Predicted from
 * continuity_recovery.c:51-61,83,102-111 and continuity_resolve.c:75,240-243:
 * mount Valid, resolve Corrupt "referenced object is absent", reason ContinuityCorrupt,
 * rc_applicable() none. Unbuilt: a graph-broken newest AgentRoot (needs a second root,
 * which resolves as Conflict, not graph damage) and a foreign-agent state. */
static void t_k4(void)
{
    char t[200];
    remembered();
    struct cc_manifest m;
    memset(&m, 0, sizeof m);
    memcpy(m.root, g_v.root_id, 32);
    memcpy(m.previous, g_v.manifest_id, 32);
    m.sequence = g_v.manifest.sequence + 1;
    m.incarnation = g_v.manifest.incarnation;
    memset(m.agent_state, 0x66, 32); /* never written */
    static uint8_t b[CC_MAX_OBJECT_BYTES];
    size_t n = 0;
    CK_(cc_manifest_encode(&m, b, sizeof b, &n, NULL) == CC_OK && raw_commit(CC_KIND_MANIFEST, b, n) == 0, "broken newer manifest");
    snapshot();
    inspect(&R);
    CK_(unchanged(), "inspect wrote");
    CK_(R.have_mount && R.mount_state == ST_VALID, "the store mounts (fresh anchor): have_mount %d state %d", R.have_mount, R.mount_state);
    CK_(R.reason == RC_CONTINUITY_CORRUPT && R.why && !strcmp(R.why, "referenced object is absent"),
        "K-4 reason %d why %s", R.reason, R.why ? R.why : "-");
    CK_(!R.have_identity, "no identity resolved");
    CK_(rc_reason_text(t, sizeof t, &R) > 0 && strncmp(t, "ContinuityCorrupt(", 18) == 0, "reason text '%s'", t);
    /* INV-15: no action mints. A mutant that returned an action here fails this line and all_actions_refused. */
    CK_(rc_applicable(&R) == 0, "no action applicable (INV-15)");
    if (g_bs == 4096) printf("K-4 answer: sealed-valid newest manifest with a missing agent_state: reason=%d (RC_CONTINUITY_CORRUPT=%d) why='%s' mounted=%d state=%d applicable=%d\n", R.reason, RC_CONTINUITY_CORRUPT, R.why ? R.why : "-", R.have_mount, R.mount_state, rc_applicable(&R));
    all_actions_refused(&R, "k4");
}

int main(void)
{
    make_keys();
    memset(OPKEY, 0x0f, 32);
    memset(BADKEY, 0x0e, 32);
    snprintf(g_path, sizeof g_path, "/tmp/ck_rc_test_%d.img", (int)getpid());
    static const uint32_t geos[2] = {4096u, 512u};
    for (int g = 0; g < 2; g++) {
        g_bs = geos[g];
        t_91d();
        t_91e();
        t_91f();
        t_91g();
        t_91h();
        t_91i();
        t_91j();
        t_91k();
        t_k4();
    }
    dev_close();
    unlink(g_path);
    return ck_t_verdict("test_continuity_recovery");
}
