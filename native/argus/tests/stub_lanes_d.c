/*
 * stub_lanes_d.c -- TEST-ONLY stand-ins for lane B (argus_event.c) and lane E
 * (argus_detect.c), so lane D's tests link before those lanes merge. The real
 * lanes replace this file at integration. The hash is FNV-1a spread over
 * 32 bytes: deterministic, NOT cryptographic, NOT SHA-256.
 *
 * argus_detect_run modes (set stub_detect_mode from a test):
 *   0 = tiny semantic detector using only the ops vtable (default)
 *   1 = no findings
 *   2 = emit as many canned findings as `cap` allows (overflow test)
 *   3 = record what the ops said about ev->cap_id (pre-state probe), no findings
 */
#include "../argus_abi.h"
#include "stub_lanes_d.h"

#include <string.h>

int stub_detect_mode = 0;
int stub_probe_rc = 0;
ArgusCapShadow stub_probe_cap;
uint64_t stub_detect_calls = 0;

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

static void stub_encode(const ArgusEvent *ev, uint8_t b[ARGUS_EVENT_SIZE])
{
    b[0] = ev->version; b[1] = ev->class_; put16(b + 2, ev->kind);
    b[4] = ev->effect_class; b[5] = ev->outcome; put16(b + 6, ev->flags);
    put64(b + 8, ev->sequence); put64(b + 16, ev->tick);
    put32(b + 24, ev->principal); put32(b + 28, (uint32_t)ev->code);
    put32(b + 32, ev->cap_id); put32(b + 36, ev->object_id);
    put64(b + 40, ev->cap_generation); put64(b + 48, ev->world_generation);
    put64(b + 56, ev->resource);
    memcpy(b + 64, ev->machine_id, ARGUS_MACHINE_ID_LEN);
    memcpy(b + 96, ev->evidence_digest, ARGUS_DIGEST_LEN);
}

static void fnv32(const uint8_t *a, size_t na, const uint8_t *b, size_t nb, uint8_t out[ARGUS_DIGEST_LEN])
{
    for (int lane = 0; lane < 4; lane++) {
        uint64_t h = 0xcbf29ce484222325ull ^ ((uint64_t)(lane + 1) * 0x9e3779b97f4a7c15ull);
        for (size_t i = 0; i < na; i++) { h ^= a[i]; h *= 0x100000001b3ull; }
        for (size_t i = 0; i < nb; i++) { h ^= b[i]; h *= 0x100000001b3ull; }
        put64(out + 8 * lane, h);
    }
}

static int kind_known(uint16_t k)
{
    switch (k) {
    case 1: case 2: case 3: case 4: case 10: case 11: case 12: case 20: case 21: case 22:
    case 30: case 31: case 32: case 40: case 41: case 42: case 43: case 50: case 51: case 52:
    case 60: case 61: case 62: case 63: case 70: case 71: case 72: case 80: case 81:
    case 90: case 91: case 92: case 93:   /* v1.2 containment kinds (TEST-ONLY stand-in for lane B) */
        return 1;
    default:
        return 0;
    }
}

int argus_event_validate(const ArgusEvent *ev)
{
    if (!ev) return ARGUS_ERR_ARG;
    if (ev->version != ARGUS_ABI_VERSION) return ARGUS_ERR_VERSION;
    if (ev->class_ < ARGUS_CLASS_CRITICAL || ev->class_ > ARGUS_CLASS_MAX) return ARGUS_ERR_MALFORMED;
    if (!kind_known(ev->kind)) return ARGUS_ERR_MALFORMED;
    if (ev->effect_class > ARGUS_EFFECT_MAX) return ARGUS_ERR_MALFORMED;
    if (ev->outcome < ARGUS_OUTCOME_OK || ev->outcome > ARGUS_OUTCOME_MAX) return ARGUS_ERR_MALFORMED;
    if (ev->flags & (uint16_t)~ARGUS_FLAG_KNOWN) return ARGUS_ERR_MALFORMED;
    if (ev->kind == ARGUS_EV_CAPABILITY_USE_SUMMARY && ev->outcome != ARGUS_OUTCOME_OK) return ARGUS_ERR_MALFORMED;   /* v1.1 */
    /* v1.2 TEST-ONLY stand-in for lane B's validate (spec section 3), replace when argus_event.c
     * lands: 90-93 class CRITICAL, effect NONE; CONSUMER flag on 90 always, never on 91-93. */
    if (ev->kind >= ARGUS_EV_CONTAINMENT_PROPOSED && ev->kind <= ARGUS_EV_AUTHORITY_ESCALATED) {
        if (ev->class_ != ARGUS_CLASS_CRITICAL || ev->effect_class != ARGUS_EFFECT_NONE) return ARGUS_ERR_MALFORMED;
        if (((ev->flags & ARGUS_FLAG_CONSUMER) != 0) != (ev->kind == ARGUS_EV_CONTAINMENT_PROPOSED)) return ARGUS_ERR_MALFORMED;
    }
    return ARGUS_OK;
}

void argus_event_digest(const ArgusEvent *ev, uint8_t out[ARGUS_DIGEST_LEN])
{
    uint8_t b[ARGUS_EVENT_SIZE];
    stub_encode(ev, b);
    fnv32(b, sizeof b, NULL, 0, out);
}

void argus_chain_extend(uint8_t chain[ARGUS_DIGEST_LEN], const ArgusEvent *ev)
{
    uint8_t b[ARGUS_EVENT_SIZE], prev[ARGUS_DIGEST_LEN];
    stub_encode(ev, b);
    memcpy(prev, chain, ARGUS_DIGEST_LEN);
    fnv32(prev, sizeof prev, b, sizeof b, chain);
}

void argus_finding_digest(const ArgusFinding *f, uint8_t out[ARGUS_DIGEST_LEN])
{
    fnv32((const uint8_t *)f, sizeof *f, NULL, 0, out);
}

static void mk(ArgusFinding *f, uint16_t code, uint8_t sev, uint8_t contain, const ArgusEvent *ev, uint64_t prior)
{
    memset(f, 0, sizeof *f);
    f->code = code; f->severity = sev; f->confidence = ARGUS_CONF_DETERMINISTIC;
    f->containment = contain; f->detector = code;
    f->sequence = ev->sequence; f->prior_sequence = prior;
    f->principal = ev->principal; f->cap_id = ev->cap_id; f->cap_generation = ev->cap_generation;
    memcpy(f->machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN);
}

int argus_detect_run(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                     ArgusFinding *out, size_t cap, size_t *n_out)
{
    stub_detect_calls++;
    *n_out = 0;
    if (stub_detect_mode == 1)
        return ARGUS_OK;
    if (stub_detect_mode == 2) {
        for (size_t i = 0; i < cap; i++)
            mk(&out[i], ARGUS_F_FORGED_CAPABILITY, ARGUS_SEV_HIGH, ARGUS_CONTAIN_REVOKE_CAPABILITY, ev, 0);
        *n_out = cap;
        return ARGUS_OK;
    }
    if (stub_detect_mode == 3) {
        memset(&stub_probe_cap, 0, sizeof stub_probe_cap);
        stub_probe_rc = ops->cap(v, ev->cap_id, &stub_probe_cap);
        return ARGUS_OK;
    }
    size_t n = 0;
    if (ev->kind == ARGUS_EV_CAPABILITY_USED && ev->outcome == ARGUS_OUTCOME_OK && cap > 0) {
        ArgusCapShadow s;
        if (ops->cap(v, ev->cap_id, &s) != ARGUS_OK)
            mk(&out[n++], ARGUS_F_FORGED_CAPABILITY, ARGUS_SEV_CRITICAL, ARGUS_CONTAIN_REVOKE_CAPABILITY, ev, 0);
        else if (s.state == ARGUS_SHADOW_REVOKED)
            mk(&out[n++], ARGUS_F_REVOKED_CAPABILITY_USED, ARGUS_SEV_CRITICAL, ARGUS_CONTAIN_REVOKE_CAPABILITY, ev, s.revoked_sequence);
        else if (ev->cap_generation < s.generation)
            mk(&out[n++], ARGUS_F_STALE_GENERATION, ARGUS_SEV_HIGH, ARGUS_CONTAIN_REVOKE_CAPABILITY, ev, s.granted_sequence);
    }
    if (ev->kind == ARGUS_EV_PROVIDER_USED && ev->outcome == ARGUS_OUTCOME_OK && n < cap) {
        ArgusProviderShadow p;
        if (ops->provider(v, ev->evidence_digest, &p) == ARGUS_OK && p.state == ARGUS_SHADOW_REVOKED)
            mk(&out[n++], ARGUS_F_QUARANTINED_USE, ARGUS_SEV_HIGH, ARGUS_CONTAIN_QUARANTINE_PROVIDER, ev, p.sequence);
    }
    if (ev->kind == ARGUS_EV_ARTIFACT_ACTIVATED && ev->outcome == ARGUS_OUTCOME_OK && n < cap) {
        ArgusArtifactShadow a;
        if (ops->artifact(v, ev->evidence_digest, &a) != ARGUS_OK || a.state != ARGUS_SHADOW_LIVE)
            mk(&out[n++], ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED, ARGUS_SEV_MEDIUM, ARGUS_CONTAIN_REJECT_ARTIFACT, ev, 0);
    }
    *n_out = n;
    return ARGUS_OK;
}
