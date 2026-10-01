/* security.c -- capability authority + ARGUS boot stage (see security.h).
 * Uses native/capability and native/argus through their public headers,
 * unmodified. Memory comes from ck_alloc. */
#include "security.h"
#include <stddef.h>
#include "argus_abi.h"
#include "argus_contain.h"
#include "argus_core.h"
#include "bridge/argus_aegis_bridge.h"
#include "aienos_contain.h"
#include "ck.h"
#include "ck_compat.h"
#ifdef CK_HARDWARE_STAGING
#include "ck_owner_prov.h" /* generated: owner public material + machine id */
#if !defined(CK_OWNER_PROVISIONED) || CK_OWNER_PROVISIONED != 1
#error "CK_HARDWARE_STAGING needs the generated owner provisioning header (CK_OWNER_PUBKEYS=, CK_MACHINE_ID=)"
#endif
_Static_assert(sizeof ck_owner_machine_id == ARGUS_MACHINE_ID_LEN, "machine id length");
#endif

/* Rust ipc demo resource ids are irrelevant here; these are local labels. */
#define SUBJ_A 1u
#define SUBJ_B 2u
#define RES_IPC 0xA1u
#define SUBJ_T 7u
#define SUBJ_U 8u
#define RES_T 0x1234u
#define RES_U 0x5678u

typedef struct {
    ArgusAegisBridge *bridge;
    uint32_t mints, revokes, executor_mints;
} obs_tap;

static struct {
    AienosCapAdmin *admin;
    AienosCapView *view;
    AienosCapRef office;
    void *core_mem, *contain_mem, *gate_mem, *bridge_mem;
    ArgusCore *core;
    ArgusContain *contain;
    AienosContain *gate;
    ArgusAegisBridge *bridge;
    AienosContainTablePolicy policy;
    AienosContainAuthorizer authz;
    obs_tap tap;
    uint8_t machine[ARGUS_MACHINE_ID_LEN];
    uint64_t seq;
    int up;
} S;

/* Counts what the authority announces, then forwards to the bridge (the
 * bridge's observer is what keeps ARGUS shadows and the gate lineage). */
static void tap_observer(void *ctx, uint32_t op, const AienosCapEntry *e, int result)
{
    obs_tap *t = ctx;
    if (op == AIENOS_CAP_OBS_MINT && e) {
        t->mints++;
        if (e->subject == AIENOS_CONTAIN_SUBJ) t->executor_mints++;
    }
    if (op == AIENOS_CAP_OBS_REVOKE && e) t->revokes++;
    if (t->bridge) argus_aegis_bridge_observer(t->bridge, op, e, result);
}

static void zero(void *p, size_t n)
{
    volatile uint8_t *b = p;
    while (n--) *b++ = 0;
}

static void ev_init(ArgusEvent *e, uint8_t cls, uint16_t kind)
{
    zero(e, sizeof *e);
    e->version = ARGUS_ABI_VERSION;
    e->class_ = cls;
    e->kind = kind;
    e->flags = (uint16_t)(1u << ARGUS_FLAG_STREAM_SHIFT);
    e->sequence = ++S.seq;
    for (uint32_t i = 0; i < ARGUS_MACHINE_ID_LEN; i++) e->machine_id[i] = S.machine[i];
}

static int bring_up(ck_sec_report *r)
{
    if (aienos_cap_start(&S.admin, &S.view) != AIENOS_CAP_OK) return r->fail = "cap_start", -1;
    if (aienos_cap_office(S.admin, &S.office) != AIENOS_CAP_OK) return r->fail = "cap_office", -1;
    S.core_mem = ck_alloc(argus_core_footprint());
    S.contain_mem = ck_alloc(argus_contain_footprint());
    S.gate_mem = ck_alloc(aienos_contain_footprint());
    S.bridge_mem = ck_alloc(argus_aegis_bridge_footprint());
    if (!S.core_mem || !S.contain_mem || !S.gate_mem || !S.bridge_mem) return r->fail = "alloc", -1;
    zero(S.core_mem, argus_core_footprint());
    zero(S.contain_mem, argus_contain_footprint());
    zero(S.gate_mem, aienos_contain_footprint());
    zero(S.bridge_mem, argus_aegis_bridge_footprint());
    if (argus_core_init(&S.core, S.core_mem, argus_core_footprint()) != ARGUS_OK) return r->fail = "argus_core_init", -1;
    if (argus_contain_init(&S.contain, S.contain_mem, argus_contain_footprint()) != ARGUS_OK)
        return r->fail = "argus_contain_init", -1;
#ifdef CK_HARDWARE_STAGING
    /* this machine's ARGUS id: provisioned at build time (CK_MACHINE_ID) */
    for (uint32_t i = 0; i < ARGUS_MACHINE_ID_LEN; i++) S.machine[i] = ck_owner_machine_id[i];
#else
    S.machine[0] = 0xA1; /* this machine's ARGUS id: fixed label, TEST */
#endif
    if (argus_aegis_bridge_init(&S.bridge, S.bridge_mem, argus_aegis_bridge_footprint(), S.core, S.contain, &S.gate,
                                S.view, S.machine) != ARGUS_OK)
        return r->fail = "bridge_init", -1;
    ArgusEvent joined;
    ev_init(&joined, ARGUS_CLASS_SECURITY, ARGUS_EV_MACHINE_JOINED);
    joined.outcome = ARGUS_OUTCOME_OK;
    joined.flags |= ARGUS_FLAG_SYNTHETIC;
    joined.object_id = ARGUS_TRUST_OBSERVED;
    joined.cap_id = ARGUS_CAP_NONE;
    if (argus_aegis_bridge_ingest(S.bridge, &joined) != ARGUS_OK) return r->fail = "ingest machine_joined", -1;
    /* Observer before create: the executor mint seeds both shadows. */
    S.tap.bridge = S.bridge;
    if (aienos_cap_set_observer(S.admin, tap_observer, &S.tap) != AIENOS_CAP_OK) return r->fail = "set_observer", -1;
    S.policy.verdict[AIENOS_CONTAIN_REVOKE_CAPABILITY] = AIENOS_CONTAIN_GRANT; /* all other types: 0 -> ESCALATE */
    S.authz.decide = aienos_contain_table_decide;
    S.authz.ctx = &S.policy;
    if (aienos_contain_create(&S.gate, S.gate_mem, aienos_contain_footprint(), S.admin, S.view, S.office, &S.authz) !=
        AIENOS_CONTAIN_OK)
        return r->fail = "contain_create", -1;
    if (argus_aegis_bridge_attach_gate(S.bridge) != ARGUS_OK) return r->fail = "attach_gate", -1;
    S.up = 1;
    return 0;
}

static int mint(uint32_t subject, uint64_t res, uint32_t rights, AienosCapRef parent, AienosCapRef auth,
                AienosCapRef *out)
{
    AienosCapMint m;
    zero(&m, sizeof m);
    m.issuer = 0;
    m.subject = subject;
    m.resource = res;
    m.rights = rights;
    m.lease_ticks = 0;
    m.parent = parent;
    m.authority = auth;
    return aienos_cap_mint(S.admin, &m, out);
}

/* Rust ipc demo semantics on the C authority. */
static int caps_check(ck_sec_report *r)
{
    AienosCapRef none = {AIENOS_CAP_PARENT_NONE, 0}, a, b, c;
    AienosCapEntry e;
    if (mint(SUBJ_A, RES_IPC, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE | AIENOS_CAP_RIGHT_DELEGATE, none,
             S.office, &a) != AIENOS_CAP_OK)
        return r->fail = "caps mint A", -1;
    r->caps_granted = aienos_cap_validate(S.view, a, SUBJ_A, RES_IPC, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE,
                                          &e) == AIENOS_CAP_OK;
    if (mint(SUBJ_B, RES_IPC, AIENOS_CAP_RIGHT_READ, a, a, &b) != AIENOS_CAP_OK) return r->fail = "caps delegate B", -1;
    r->caps_attenuated =
        aienos_cap_validate(S.view, b, SUBJ_B, RES_IPC, AIENOS_CAP_RIGHT_READ, &e) == AIENOS_CAP_OK &&
        aienos_cap_validate(S.view, b, SUBJ_B, RES_IPC, AIENOS_CAP_RIGHT_WRITE, &e) == AIENOS_CAP_ERR_RIGHTS;
    r->caps_amplify_denied = mint(SUBJ_B, RES_IPC, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_EFFECT, a, a, &c) ==
                             AIENOS_CAP_ERR_AMPLIFY;
    AienosCapRef forged = b;
    forged.generation ^= 0x5au; /* right slot, wrong generation */
    AienosCapRef forged2 = {AIENOS_CAP_MAX - 1u, b.generation};
    r->caps_forged_denied = aienos_cap_validate(S.view, forged, SUBJ_B, RES_IPC, AIENOS_CAP_RIGHT_READ, &e) != 0 &&
                            aienos_cap_validate(S.view, forged2, SUBJ_B, RES_IPC, AIENOS_CAP_RIGHT_READ, &e) != 0 &&
                            aienos_cap_validate(S.view, b, SUBJ_A, RES_IPC, AIENOS_CAP_RIGHT_READ, &e) != 0;
    if (aienos_cap_revoke(S.admin, S.office, a) != AIENOS_CAP_OK) return r->fail = "caps revoke A", -1;
    r->caps_revoked_denied =
        aienos_cap_validate(S.view, b, SUBJ_B, RES_IPC, AIENOS_CAP_RIGHT_READ, &e) == AIENOS_CAP_ERR_REVOKED &&
        aienos_cap_validate(S.view, a, SUBJ_A, RES_IPC, AIENOS_CAP_RIGHT_READ, &e) == AIENOS_CAP_ERR_REVOKED;
    r->caps_ok = r->caps_granted && r->caps_attenuated && r->caps_amplify_denied && r->caps_forged_denied &&
                 r->caps_revoked_denied;
    if (!r->caps_ok) return r->fail = "caps semantics", -1;
    return 0;
}

/* ARGUS-1 first narrow revoke (ARGUS1_SPEC I1, I5; mirrors
 * native/argus/tests/test_argus_containment_e2e.c and adds the unrelated
 * and authority checks). */
static int argus_check(ck_sec_report *r)
{
    ArgusFinding found[16];
    r->findings_before = (uint32_t)argus_aegis_bridge_take_findings(S.bridge, found, 16);
    AienosCapRef exec0;
    if (aienos_contain_executor(S.gate, &exec0) != AIENOS_CONTAIN_OK) return r->fail = "executor ref", -1;
    uint32_t exec_mints0 = S.tap.executor_mints;

    AienosCapRef none = {AIENOS_CAP_PARENT_NONE, 0}, t, u1, u2;
    if (mint(SUBJ_T, RES_T, AIENOS_CAP_RIGHT_READ, none, S.office, &t) || mint(SUBJ_T, RES_U, AIENOS_CAP_RIGHT_READ, none, S.office, &u1) ||
        mint(SUBJ_U, RES_T, AIENOS_CAP_RIGHT_READ, none, S.office, &u2))
        return r->fail = "argus mint target/unrelated", -1;
    AienosCapEntry e;
    if (aienos_cap_validate(S.view, t, SUBJ_T, RES_T, AIENOS_CAP_RIGHT_READ, &e) != AIENOS_CAP_OK)
        return r->fail = "target not granted before", -1;
    uint32_t mints0 = S.tap.mints, revokes0 = S.tap.revokes;

    /* Trigger: a successful use reported at a stale generation. */
    ArgusEvent use;
    ev_init(&use, ARGUS_CLASS_AUDIT, ARGUS_EV_CAPABILITY_USED);
    use.effect_class = ARGUS_EFFECT_NONE;
    use.outcome = ARGUS_OUTCOME_OK;
    use.code = AIENOS_CAP_ERR_STALE_GEN;
    use.cap_id = t.cap_id;
    use.cap_generation = t.generation;
    use.principal = SUBJ_T;
    if (argus_aegis_bridge_ingest(S.bridge, &use) != ARGUS_OK) return r->fail = "ingest trigger", -1;
    size_t nf = argus_aegis_bridge_take_findings(S.bridge, found, 16);
    r->trigger_findings = (uint32_t)nf;
    if (nf != 1 || found[0].code != ARGUS_F_STALE_GENERATION ||
        found[0].containment != ARGUS_CONTAIN_REVOKE_CAPABILITY)
        return r->fail = "trigger finding", -1;
    ArgusContainmentRequest req[1];
    ArgusEvent proposed[1];
    size_t np = 0;
    if (argus_contain_propose(S.contain, S.core, found, nf, &use, req, 1, proposed, 1, &np) != ARGUS_OK || np != 1)
        return r->fail = "propose", -1;
    if (argus_aegis_bridge_ingest(S.bridge, &proposed[0]) != ARGUS_OK) return r->fail = "ingest proposal", -1;
    AienosContainDecision dec;
    AienosContainResult res;
    zero(&dec, sizeof dec);
    zero(&res, sizeof res);
    if (argus_aegis_bridge_submit(S.bridge, &req[0], &dec, &res) != ARGUS_OK) return r->fail = "submit", -1;
    r->decision = (int)dec.status;
    r->execution = (int)res.status;
    r->revokes_during = S.tap.revokes - revokes0;
    r->mints_during = S.tap.mints - mints0;
    r->executor_mints = S.tap.executor_mints - exec_mints0;

    r->target_denied_code = aienos_cap_validate(S.view, t, SUBJ_T, RES_T, AIENOS_CAP_RIGHT_READ, &e);
    r->unrelated_same_subject = aienos_cap_validate(S.view, u1, SUBJ_T, RES_U, AIENOS_CAP_RIGHT_READ, &e);
    r->unrelated_other_subject = aienos_cap_validate(S.view, u2, SUBJ_U, RES_T, AIENOS_CAP_RIGHT_READ, &e);
    AienosCapRef exec1;
    AienosCapEntry ex;
    r->executor_unchanged = aienos_contain_executor(S.gate, &exec1) == AIENOS_CONTAIN_OK &&
                            exec1.cap_id == exec0.cap_id && exec1.generation == exec0.generation &&
                            aienos_cap_inspect(S.view, exec0, &ex) == AIENOS_CAP_OK &&
                            ex.state == AIENOS_CAP_STATE_LIVE && ex.rights == AIENOS_CAP_RIGHT_REVOKE &&
                            ex.subject == AIENOS_CONTAIN_SUBJ && r->executor_mints == 0 && r->mints_during == 0;
    ArgusContainHealth h;
    argus_contain_health(S.contain, &h);
    r->health_ok = h.requested == 1 && h.granted == 1 && h.confirmed == 1 && h.failed_scope == 0 &&
                   h.executions_unauthorized == 0;
    ArgusCoreHealth ch;
    argus_core_health(S.core, &ch);
    r->bridge_ok = argus_aegis_bridge_error(S.bridge) == ARGUS_OK && ch.events_rejected == 0;
    r->argus_ok = r->decision == AIENOS_CONTAIN_GRANT && r->execution == AIENOS_CONTAIN_DONE &&
                  r->revokes_during == 1 && r->target_denied_code == AIENOS_CAP_ERR_REVOKED &&
                  r->unrelated_same_subject == AIENOS_CAP_OK && r->unrelated_other_subject == AIENOS_CAP_OK &&
                  r->executor_unchanged && r->health_ok && r->bridge_ok;
    if (!r->argus_ok) return r->fail = "argus invariant", -1;
    return 0;
}

int ck_security_run(ck_sec_report *r)
{
    zero(r, sizeof *r);
    if (S.up) return r->fail = "already up", -1;
    zero(&S, sizeof S);
    if (bring_up(r)) return -1;
    int rc = caps_check(r);
    if (rc) return rc;
    return argus_check(r);
}

void ck_security_shutdown(void)
{
    if (S.admin) aienos_cap_set_observer(S.admin, 0, 0);
    if (S.gate) aienos_contain_destroy(S.gate);
    if (S.bridge) argus_aegis_bridge_destroy(S.bridge);
    if (S.admin) aienos_cap_stop(S.admin, S.view);
    if (S.bridge_mem) ck_free(S.bridge_mem);
    if (S.gate_mem) ck_free(S.gate_mem);
    if (S.contain_mem) ck_free(S.contain_mem);
    if (S.core_mem) ck_free(S.core_mem);
    zero(&S, sizeof S);
}

static const char *pick(int v, const char *y, const char *n) { return v ? y : n; }

int ck_stage_security(void)
{
    ck_sec_report r;
    int rc = ck_security_run(&r);
    int ent = ck_compat_entropy_source();
    ck_printf("caps: %s granted=%s attenuated=%s amplify=%s forged=%s revoked=%s office_token=%s\n",
              pick(r.caps_ok, "ok", "failed"), pick(r.caps_granted, "yes", "no"), pick(r.caps_attenuated, "yes", "no"),
              pick(r.caps_amplify_denied, "denied", "ALLOWED"), pick(r.caps_forged_denied, "denied", "ALLOWED"),
              pick(r.caps_revoked_denied, "denied", "ALLOWED"),
              ent == CK_ENTROPY_RNDR ? "rndr" : ent == CK_ENTROPY_HOST ? "host-urandom" : "none");
    if (ck_entropy_status() != 0)
        ck_printf("security: REFUSED kernel entropy %s (office token needs RNDR); capability office and ARGUS fail closed\n",
                  ck_entropy_reason());
    if (r.argus_ok) {
        ck_printf("argus: ok narrow_revoke=1 revoked=denied unrelated=granted authority=unchanged\n");
    } else {
        ck_printf("argus: FAIL step=%s narrow_revoke=%u decision=%d execution=%d trigger_findings=%u "
                  "revoked_rc=%d unrelated=%d/%d authority=%s mints=%u health=%s bridge=%s\n",
                  r.fail ? r.fail : "?", r.revokes_during, r.decision, r.execution, r.trigger_findings,
                  r.target_denied_code, r.unrelated_same_subject, r.unrelated_other_subject,
                  pick(r.executor_unchanged, "unchanged", "CHANGED"), r.mints_during, pick(r.health_ok, "ok", "bad"),
                  pick(r.bridge_ok, "ok", "error"));
    }
    return rc;
}
