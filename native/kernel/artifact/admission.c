/* admission.c -- the boot admission policy and its evaluation (port of
 * aienos-kernel admission.rs and the boot policy of artifact_loader.rs). */
#include "ck_artifact.h"
#include "sha256.h"

#define POLICY_HEADER 64u

void cka_boot_policy(struct cka_policy *pol, const uint8_t (*anchors)[32], unsigned nanchors)
{
    struct cka_limits l = {64, 64, 16, 16, 0, 0, 1000000000ull, 1000000000ull, 65536};
    struct cka_cap rule = {CKA_KIND_OBJECT, 1, 1, 1, 16, 32, 0, 32};
    pol->limits = l;
    pol->nrules = 1;
    pol->rules[0] = rule;
    if (nanchors > CKA_POLICY_MAX_SIGNERS)
        nanchors = CKA_POLICY_MAX_SIGNERS;
    pol->nsigners = nanchors;
    for (unsigned i = 0; i < nanchors; i++)
        sha256_hash(anchors[i], 32, pol->signers[i]);
}

size_t cka_policy_canonical(const struct cka_policy *pol, uint8_t *o, size_t cap)
{
    size_t need = POLICY_HEADER + (size_t)CKA_CAP_SIZE * pol->nrules + 32u * pol->nsigners;
    if (cap < need)
        return 0;
    for (size_t i = 0; i < POLICY_HEADER; i++)
        o[i] = 0;
    static const char magic[8] = "AIENPOL";
    for (int i = 0; i < 8; i++)
        o[i] = (uint8_t)magic[i];
    cka_wr16(o + 10, POLICY_HEADER);
    cka_wr16(o + 12, CKA_CAP_SIZE);
    cka_wr16(o + 14, (uint16_t)pol->nrules);
    const struct cka_limits *l = &pol->limits;
    cka_wr32(o + 16, l->code_pages);
    cka_wr32(o + 20, l->data_pages);
    cka_wr32(o + 24, l->stack_pages);
    cka_wr32(o + 28, l->max_caps);
    cka_wr32(o + 32, l->ipc_msgs);
    cka_wr32(o + 36, l->ipc_bytes);
    cka_wr64(o + 40, l->cpu);
    cka_wr64(o + 48, l->elapsed);
    cka_wr32(o + 56, l->syscalls);
    cka_wr16(o + 60, (uint16_t)pol->nsigners);
    size_t off = POLICY_HEADER;
    for (unsigned i = 0; i < pol->nrules; i++, off += CKA_CAP_SIZE)
        cka_cap_encode(&pol->rules[i], o + off);
    for (unsigned i = 0; i < pol->nsigners; i++, off += 32)
        for (int k = 0; k < 32; k++)
            o[off + k] = pol->signers[i][k];
    return off;
}

void cka_policy_digest(const struct cka_policy *pol, uint8_t out[32])
{
    uint8_t buf[POLICY_HEADER + CKA_CAP_SIZE * CKA_POLICY_MAX_RULES + 32 * CKA_POLICY_MAX_SIGNERS];
    size_t n = cka_policy_canonical(pol, buf, sizeof buf);
    static const char dom[] = "AIENOS-ADMISSION-POLICY-V1";
    cka_digest_domain(dom, sizeof dom, buf, n, out);
}

static int over(const struct cka_env *e, const struct cka_limits *l)
{
    return e->code_pages > l->code_pages || e->data_pages > l->data_pages ||
           e->stack_pages > l->stack_pages || (uint32_t)e->max_caps > l->max_caps ||
           e->ipc_msgs > l->ipc_msgs || e->ipc_bytes > l->ipc_bytes || e->cpu > l->cpu ||
           e->elapsed > l->elapsed || e->syscalls > l->syscalls;
}

/* intersect_request: 1 = grant written, 0 = skip, <0 = -error */
static int intersect(const struct cka_cap *req, const struct cka_cap *rule, struct cka_cap *g)
{
    uint32_t rights = req->rights & rule->rights;
    if (!rights)
        return 0;
    uint32_t ops = req->max_ops < rule->max_ops ? req->max_ops : rule->max_ops;
    uint64_t bytes = req->max_bytes < rule->max_bytes ? req->max_bytes : rule->max_bytes;
    uint64_t off, len;
    if (req->bounds == 1) {
        uint64_t rend = req->off + req->len, pend = rule->off + rule->len;
        if (rend < req->off || pend < rule->off)
            return -CKA_LENGTH_OVERFLOW;
        uint64_t start = req->off > rule->off ? req->off : rule->off;
        uint64_t end = rend < pend ? rend : pend;
        if (start >= end)
            return 0;
        off = start;
        len = end - start;
        if (len < bytes)
            bytes = len;
    } else if (req->bounds == 2) {
        off = len = 0;
    } else {
        return -CKA_MALFORMED_CAP;
    }
    if (!ops || !bytes)
        return 0;
    g->kind = req->kind;
    g->id = req->id;
    g->rights = rights;
    g->bounds = req->bounds;
    g->max_ops = ops;
    g->max_bytes = bytes;
    g->off = off;
    g->len = len;
    int rc = cka_cap_validate(g);
    return rc ? -rc : 1;
}

int cka_evaluate(const struct cka_policy *pol, const struct cka_parsed *p,
                 const uint8_t signer_fp[32], const struct cka_limits *avail,
                 struct cka_decision *d)
{
    d->ngrants = 0;
    if (p->target != CKA_TARGET_AARCH64_LE)
        return CKA_WRONG_TARGET;
    if (p->abi != CKA_ABI_V1)
        return CKA_WRONG_ABI;
    int known = 0;
    for (unsigned i = 0; i < pol->nsigners && !known; i++) {
        uint8_t acc = 0;
        for (int k = 0; k < 32; k++)
            acc |= (uint8_t)(pol->signers[i][k] ^ signer_fp[k]);
        known = acc == 0;
    }
    if (!known)
        return CKA_UNTRUSTED_SIGNER;
    if (p->entry & 3)
        return CKA_BAD_ENTRY;
    if (p->entry > 0xffffffffu - 4)
        return CKA_LENGTH_OVERFLOW;
    if (p->entry + 4 > p->code.flen)
        return CKA_BAD_ENTRY;
    if (p->payload_len > CKA_MAX_PAYLOAD)
        return CKA_RESOURCE_LIMIT;
    int rc = cka_env_validate(&p->env, p->ncaps);
    if (rc)
        return rc;
    if (over(&p->env, &pol->limits))
        return CKA_RESOURCE_LIMIT;
    if (p->env.code_pages > 0xffffffffu / 4096 || p->env.data_pages > 0xffffffffu / 4096 ||
        p->env.stack_pages > 0xffffffffu / 4096)
        return CKA_LENGTH_OVERFLOW;
    if (over(&p->env, avail))
        return CKA_RESOURCE_LIMIT;
    for (unsigned i = 0; i < p->ncaps; i++) {
        const struct cka_cap *req = &p->caps[i], *rule = 0;
        for (unsigned r = 0; r < pol->nrules && !rule; r++)
            if (pol->rules[r].kind == req->kind && pol->rules[r].id == req->id)
                rule = &pol->rules[r];
        if (!rule)
            continue;
        struct cka_cap g;
        int got = intersect(req, rule, &g);
        if (got < 0)
            return -got;
        if (!got)
            continue;
        if (!cka_cap_is_attenuation_of(&g, req) || !cka_cap_is_attenuation_of(&g, rule))
            return CKA_RIGHTS_ESCALATION;
        if (g.rights > 0xff)
            return CKA_RIGHTS_ESCALATION;
        d->grants[d->ngrants++] = g;
    }
    cka_grants_digest(d->grants, d->ngrants, d->granted_digest);
    return CKA_OK;
}
