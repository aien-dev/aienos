/*
 * argus_event.c -- ARGUS event ABI v1: canonical encoding, validation, digests.
 *
 * Encoding is field by field, little-endian, at the offsets documented in
 * argus_abi.h. The in-memory struct is never copied to the wire, so host
 * endianness and padding cannot leak into the bytes or the digests.
 *
 * argus_event_encode, argus_event_digest and argus_chain_extend never
 * validate: they produce canonical bytes for any event (the core hashes
 * internal records with sequence 0). Only decode and validate reject.
 *
 * Validation (argus_event_decode and argus_event_validate):
 *   version == ARGUS_ABI_VERSION         else ARGUS_ERR_VERSION
 *   class_ in 1..ARGUS_CLASS_MAX          else ARGUS_ERR_MALFORMED (all below too)
 *   kind in the enumerated ARGUS_EV_* set (ARGUS_EV_NONE is NOT accepted)
 *   class_ <= argus_event_min_class(kind) (as strong as the kind requires, or stronger)
 *   effect_class in 0..ARGUS_EFFECT_MAX
 *   outcome in 1..ARGUS_OUTCOME_MAX
 *   flags: any value (v1.1: bits 0-1 markers, bits 2-15 = producer stream id)
 *   ARGUS_FLAG_CONSUMER set if and only if kind == TELEMETRY_DROPPED or (v1.2)
 *     CONTAINMENT_PROPOSED
 *   v1.2 kinds 90-92: packed type/status/outcome rules, request_id != 0
 *     (validate_containment below); 93: floor CRITICAL, no CONSUMER
 *   cap_id < ARGUS_CAP_MAX, or == ARGUS_CAP_NONE ("no capability"; cap_id 0 is
 *     the authority OFFICE slot, a real capability)
 *   CAPABILITY_USE_SUMMARY (81): outcome OK (a summary counts successful
 *     validates only); any tick is accepted (producers write 0);
 *     world_generation (MIN generation) <= cap_generation (MAX), else
 *     malformed. object_id is not checked (forward-compat; producers write 0)
 *   sequence != 0 and sequence != UINT64_MAX
 *   EXTERNAL_EFFECT_REQUESTED/DENIED/COMMITTED carry effect_class EXTERNAL
 * Every one of the 128 bytes is carried by some field, so a buffer that
 * decodes successfully re-encodes to exactly the same bytes.
 *
 * Finding digest: SHA-256 over this 104-byte little-endian encoding of
 * ArgusFinding (never the struct):
 *   off 0  u16 code          off 2  u8 severity     off 3  u8 confidence
 *   off 4  u8  sync_allowed  off 5  u8 containment  off 6  u16 detector
 *   off 8  u64 sequence      off 16 u64 prior_sequence
 *   off 24 u32 principal     off 28 u32 cap_id      off 32 u64 cap_generation
 *   off 40 machine_id[32]    off 72 event_digest[32]              end 104
 */
#include "argus_abi.h"
#include "sha256.h"

#define ARGUS_FINDING_WIRE_SIZE 104u

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32); }
static void copy_bytes(uint8_t *dst, const uint8_t *src, size_t n) { for (size_t i = 0; i < n; i++) dst[i] = src[i]; }

/*
 * Weakest class a producer may give each kind (smaller number = stronger).
 * A producer may always label an event STRONGER than this, never weaker:
 * the ring's watermarks and the core's loss reporting are keyed on class,
 * so a weak label on a security-relevant kind would let it be dropped
 * first and reported as a harmless loss (HOSTILE_REVIEW G-6/G-7).
 *   CRITICAL: evidence of compromise, loss of evidence, trust/authority
 *             withdrawn, the trusted base changed, irreversible effects done
 *   SECURITY: authority granted or refused, new objects/machines/providers
 *             entering the system, effects requested/denied, World commits
 *   AUDIT:    routine use of authority that is already recorded
 *   v1.2: the containment kinds 90-93 are CRITICAL (spec section 3).
 * No v1 kind has an INFORMATIONAL floor. Unknown kinds (including NONE) -> 0.
 */
uint8_t argus_event_min_class(uint16_t kind)
{
    switch (kind) {
    case ARGUS_EV_INTEGRITY_VIOLATION: case ARGUS_EV_SIGNATURE_FAILURE:
    case ARGUS_EV_STALE_GENERATION: case ARGUS_EV_FORGED_CAPABILITY:
    case ARGUS_EV_TELEMETRY_DROPPED: case ARGUS_EV_PROVIDER_QUARANTINED:
    case ARGUS_EV_MACHINE_TRUST_CHANGED: case ARGUS_EV_MACHINE_REMOVED:
    case ARGUS_EV_POLICY_CHANGED: case ARGUS_EV_RUNTIME_BUILD_CHANGED:
    case ARGUS_EV_CAPABILITY_REVOKED: case ARGUS_EV_CREDENTIAL_LEASE_REVOKED:
    case ARGUS_EV_ARTIFACT_REJECTED: case ARGUS_EV_EXTERNAL_EFFECT_COMMITTED:
    case ARGUS_EV_CONTAINMENT_PROPOSED: case ARGUS_EV_CONTAINMENT_DECIDED:   /* v1.2 (spec 3) */
    case ARGUS_EV_CONTAINMENT_EXECUTED: case ARGUS_EV_AUTHORITY_ESCALATED:
        return ARGUS_CLASS_CRITICAL;
    case ARGUS_EV_CAPABILITY_GRANTED: case ARGUS_EV_CAPABILITY_DENIED:
    case ARGUS_EV_CREDENTIAL_LEASE_CREATED:
    case ARGUS_EV_ARTIFACT_ADMITTED: case ARGUS_EV_ARTIFACT_ACTIVATED:
    case ARGUS_EV_MACHINE_JOINED:
    case ARGUS_EV_PROVIDER_DISCOVERED: case ARGUS_EV_PROVIDER_CHANGED:
    case ARGUS_EV_EXTERNAL_EFFECT_REQUESTED: case ARGUS_EV_EXTERNAL_EFFECT_DENIED:
    case ARGUS_EV_WORLD_COMMITTED:
        return ARGUS_CLASS_SECURITY;
    case ARGUS_EV_CAPABILITY_USED: case ARGUS_EV_CREDENTIAL_LEASE_USED:
    case ARGUS_EV_PROVIDER_USED: case ARGUS_EV_CAPABILITY_USE_SUMMARY:
        return ARGUS_CLASS_AUDIT;
    default:
        return 0;
    }
}

/*
 * v1.2 containment kinds 90-92 (spec section 3, "Validate / ring rules"). object_id packs
 * type | status << 8 | finding_code << 16; world_generation is the request_id.
 *   type in 1..ARGUS_CONTAIN_MAX; request_id != 0
 *   90 PROPOSED: status 0, outcome OK
 *   91 DECIDED:  GRANT<->OK, DENY<->DENIED, ESCALATE<->ERROR
 *   92 EXECUTED: DONE/PARTIAL<->OK, FAILED<->DENIED or ERROR, UNAVAILABLE/FAILED_SCOPE<->ERROR;
 *                DONE for any type but RevokeCapability needs ARGUS_FLAG_SYNTHETIC (I2)
 * finding_code, code, tick, resource and effect_class are producer conventions, not checked
 * here (lane C / the offline checker judge them). 93 has only the floor and no-CONSUMER rules.
 */
static int validate_containment(const ArgusEvent *ev)
{
    unsigned type = ARGUS_CONTAIN_TYPE_OF(ev->object_id);
    unsigned status = ARGUS_CONTAIN_STATUS_OF(ev->object_id);
    unsigned out = ev->outcome;
    if (type < 1 || type > ARGUS_CONTAIN_MAX) return ARGUS_ERR_MALFORMED;
    if (ev->world_generation == 0) return ARGUS_ERR_MALFORMED;      /* request_id */
    switch (ev->kind) {
    case ARGUS_EV_CONTAINMENT_PROPOSED:
        return (status == ARGUS_CSTATUS_PROPOSED && out == ARGUS_OUTCOME_OK) ? ARGUS_OK : ARGUS_ERR_MALFORMED;
    case ARGUS_EV_CONTAINMENT_DECIDED:
        if (status == ARGUS_CSTATUS_GRANT) return out == ARGUS_OUTCOME_OK ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        if (status == ARGUS_CSTATUS_DENY) return out == ARGUS_OUTCOME_DENIED ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        if (status == ARGUS_CSTATUS_ESCALATE) return out == ARGUS_OUTCOME_ERROR ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        return ARGUS_ERR_MALFORMED;
    default: /* ARGUS_EV_CONTAINMENT_EXECUTED */
        switch (status) {
        case ARGUS_CSTATUS_DONE:
            if (type != ARGUS_CONTAIN_REVOKE_CAPABILITY && (ev->flags & ARGUS_FLAG_SYNTHETIC) == 0)
                return ARGUS_ERR_MALFORMED;                         /* I2: no live executor for it */
            return out == ARGUS_OUTCOME_OK ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        case ARGUS_CSTATUS_PARTIAL:
            return out == ARGUS_OUTCOME_OK ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        case ARGUS_CSTATUS_FAILED:
            return (out == ARGUS_OUTCOME_DENIED || out == ARGUS_OUTCOME_ERROR) ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        case ARGUS_CSTATUS_UNAVAILABLE: case ARGUS_CSTATUS_FAILED_SCOPE:
            return out == ARGUS_OUTCOME_ERROR ? ARGUS_OK : ARGUS_ERR_MALFORMED;
        default:
            return ARGUS_ERR_MALFORMED;
        }
    }
}

int argus_event_validate(const ArgusEvent *ev)
{
    if (!ev) return ARGUS_ERR_ARG;
    if (ev->version != ARGUS_ABI_VERSION) return ARGUS_ERR_VERSION;
    if (ev->class_ < ARGUS_CLASS_CRITICAL || ev->class_ > ARGUS_CLASS_MAX) return ARGUS_ERR_MALFORMED;
    uint8_t min = argus_event_min_class(ev->kind);
    if (min == 0) return ARGUS_ERR_MALFORMED;                       /* unknown kind */
    if (ev->class_ > min) return ARGUS_ERR_MALFORMED;               /* weaker than the kind allows */
    if (ev->effect_class > ARGUS_EFFECT_MAX) return ARGUS_ERR_MALFORMED;
    if (ev->outcome < ARGUS_OUTCOME_OK || ev->outcome > ARGUS_OUTCOME_MAX) return ARGUS_ERR_MALFORMED;
    /* v1.1: every flag bit is defined (bits 2-15 = stream id), so no reserved-bit check. */
    /* CONSUMER is set exactly on TELEMETRY_DROPPED and (v1.2) CONTAINMENT_PROPOSED: only
     * ARGUS reports its own losses and synthesizes its own proposals. */
    if (((ev->flags & ARGUS_FLAG_CONSUMER) != 0) !=
        (ev->kind == ARGUS_EV_TELEMETRY_DROPPED || ev->kind == ARGUS_EV_CONTAINMENT_PROPOSED))
        return ARGUS_ERR_MALFORMED;
    if (ev->kind >= ARGUS_EV_CONTAINMENT_PROPOSED && ev->kind <= ARGUS_EV_CONTAINMENT_EXECUTED) {
        int rc = validate_containment(ev);
        if (rc != ARGUS_OK) return rc;
    }
    if (ev->cap_id >= ARGUS_CAP_MAX && ev->cap_id != ARGUS_CAP_NONE)
        return ARGUS_ERR_MALFORMED;                                 /* the authority cannot mint it */
    if (ev->kind == ARGUS_EV_CAPABILITY_USE_SUMMARY && ev->outcome != ARGUS_OUTCOME_OK)
        return ARGUS_ERR_MALFORMED;                                 /* a summary counts successful validates only */
    if (ev->kind == ARGUS_EV_CAPABILITY_USE_SUMMARY && ev->world_generation > ev->cap_generation)
        return ARGUS_ERR_MALFORMED;                                 /* summary MIN generation above its MAX */
    if (ev->sequence == 0 || ev->sequence == UINT64_MAX) return ARGUS_ERR_MALFORMED;
    if ((ev->kind == ARGUS_EV_EXTERNAL_EFFECT_REQUESTED || ev->kind == ARGUS_EV_EXTERNAL_EFFECT_DENIED ||
         ev->kind == ARGUS_EV_EXTERNAL_EFFECT_COMMITTED) && ev->effect_class != ARGUS_EFFECT_EXTERNAL)
        return ARGUS_ERR_MALFORMED;
    return ARGUS_OK;
}

/* Canonical bytes of any event, valid or not. */
static void encode_raw(const ArgusEvent *ev, uint8_t o[ARGUS_EVENT_SIZE])
{
    o[0] = ev->version;
    o[1] = ev->class_;
    put16(o + 2, ev->kind);
    o[4] = ev->effect_class;
    o[5] = ev->outcome;
    put16(o + 6, ev->flags);
    put64(o + 8, ev->sequence);
    put64(o + 16, ev->tick);
    put32(o + 24, ev->principal);
    put32(o + 28, (uint32_t)ev->code);
    put32(o + 32, ev->cap_id);
    put32(o + 36, ev->object_id);
    put64(o + 40, ev->cap_generation);
    put64(o + 48, ev->world_generation);
    put64(o + 56, ev->resource);
    copy_bytes(o + 64, ev->machine_id, ARGUS_MACHINE_ID_LEN);
    copy_bytes(o + 96, ev->evidence_digest, ARGUS_DIGEST_LEN);
}

int argus_event_encode(const ArgusEvent *ev, uint8_t out[ARGUS_EVENT_SIZE])
{
    if (!ev || !out) return ARGUS_ERR_ARG;
    encode_raw(ev, out);   /* never validates (header convention); decode/validate do */
    return ARGUS_OK;
}

int argus_event_decode(const uint8_t in[ARGUS_EVENT_SIZE], ArgusEvent *out)
{
    if (!in || !out) return ARGUS_ERR_ARG;
    ArgusEvent ev;
    ev.version = in[0];
    ev.class_ = in[1];
    ev.kind = get16(in + 2);
    ev.effect_class = in[4];
    ev.outcome = in[5];
    ev.flags = get16(in + 6);
    ev.sequence = get64(in + 8);
    ev.tick = get64(in + 16);
    ev.principal = get32(in + 24);
    ev.code = (int32_t)get32(in + 28);
    ev.cap_id = get32(in + 32);
    ev.object_id = get32(in + 36);
    ev.cap_generation = get64(in + 40);
    ev.world_generation = get64(in + 48);
    ev.resource = get64(in + 56);
    copy_bytes(ev.machine_id, in + 64, ARGUS_MACHINE_ID_LEN);
    copy_bytes(ev.evidence_digest, in + 96, ARGUS_DIGEST_LEN);
    int rc = argus_event_validate(&ev);
    if (rc != ARGUS_OK) return rc;
    *out = ev;
    return ARGUS_OK;
}

void argus_event_digest(const ArgusEvent *ev, uint8_t out[ARGUS_DIGEST_LEN])
{
    uint8_t b[ARGUS_EVENT_SIZE];
    encode_raw(ev, b);
    sha256_hash(b, sizeof b, out);
}

void argus_chain_extend(uint8_t chain[ARGUS_DIGEST_LEN], const ArgusEvent *ev)
{
    uint8_t b[ARGUS_EVENT_SIZE];
    sha256_ctx c;
    encode_raw(ev, b);
    sha256_init(&c);
    sha256_update(&c, chain, ARGUS_DIGEST_LEN);
    sha256_update(&c, b, sizeof b);
    sha256_final(&c, chain);
}

void argus_finding_digest(const ArgusFinding *f, uint8_t out[ARGUS_DIGEST_LEN])
{
    uint8_t b[ARGUS_FINDING_WIRE_SIZE];
    put16(b + 0, f->code);
    b[2] = f->severity;
    b[3] = f->confidence;
    b[4] = f->sync_allowed;
    b[5] = f->containment;
    put16(b + 6, f->detector);
    put64(b + 8, f->sequence);
    put64(b + 16, f->prior_sequence);
    put32(b + 24, f->principal);
    put32(b + 28, f->cap_id);
    put64(b + 32, f->cap_generation);
    copy_bytes(b + 40, f->machine_id, ARGUS_MACHINE_ID_LEN);
    copy_bytes(b + 72, f->event_digest, ARGUS_DIGEST_LEN);
    sha256_hash(b, sizeof b, out);
}

/*
 * v1.2 ContainmentRequest canonical encoding (spec section 2): the fields in struct order,
 * little-endian, packed, ARGUS_CONTAIN_REQUEST_SIZE = 152 bytes. ArgusCapRef is 16 bytes in
 * memory but 12 on the wire (cap_id u32 at 16, generation u64 at 20).
 *   off   0 u64 incident_id       off   8 u8  containment     off   9 u8  severity
 *   off  10 u16 finding_code      off  12 u32 principal       off  16 u32 target.cap_id
 *   off  20 u64 target.generation off  28 machine_id[32]      off  60 finding_digest[32]
 *   off  92 u64 request_id        off 100 u64 finding_sequence
 *   off 108 u32 target_object     off 112 u32 target_rights   off 116 target_digest[32]
 *   off 148 u16 flags             off 150 u8  version         off 151 u8  reserved   end 152
 * Encode and digest never validate. Decode checks version first (ARGUS_ERR_VERSION), then
 * containment 1..ARGUS_CONTAIN_MAX, severity 1..ARGUS_SEV_CRITICAL, reserved 0, flags within
 * ARGUS_CREQ_KNOWN, request_id != 0, finding_sequence != 0 (else ARGUS_ERR_MALFORMED); the
 * output is untouched on error. Every byte is carried by a field, so a buffer that decodes
 * re-encodes to exactly the same bytes. Request digest = SHA-256 of the 152 bytes.
 */
static void creq_encode_raw(const ArgusContainmentRequest *r, uint8_t o[ARGUS_CONTAIN_REQUEST_SIZE])
{
    put64(o + 0, r->incident_id);
    o[8] = r->containment;
    o[9] = r->severity;
    put16(o + 10, r->finding_code);
    put32(o + 12, r->principal);
    put32(o + 16, r->target.cap_id);
    put64(o + 20, r->target.generation);
    copy_bytes(o + 28, r->machine_id, ARGUS_MACHINE_ID_LEN);
    copy_bytes(o + 60, r->finding_digest, ARGUS_DIGEST_LEN);
    put64(o + 92, r->request_id);
    put64(o + 100, r->finding_sequence);
    put32(o + 108, r->target_object);
    put32(o + 112, r->target_rights);
    copy_bytes(o + 116, r->target_digest, ARGUS_DIGEST_LEN);
    put16(o + 148, r->flags);
    o[150] = r->version;
    o[151] = r->reserved;
}

int argus_contain_request_encode(const ArgusContainmentRequest *r, uint8_t out[ARGUS_CONTAIN_REQUEST_SIZE])
{
    if (!r || !out) return ARGUS_ERR_ARG;
    creq_encode_raw(r, out);
    return ARGUS_OK;
}

int argus_contain_request_decode(const uint8_t in[ARGUS_CONTAIN_REQUEST_SIZE], ArgusContainmentRequest *out)
{
    if (!in || !out) return ARGUS_ERR_ARG;
    if (in[150] != ARGUS_CONTAIN_REQUEST_VERSION) return ARGUS_ERR_VERSION;
    ArgusContainmentRequest r;
    uint8_t *z = (uint8_t *)&r;
    for (size_t i = 0; i < sizeof r; i++) z[i] = 0;   /* padding deterministic (target, tail) */
    r.incident_id = get64(in + 0);
    r.containment = in[8];
    r.severity = in[9];
    r.finding_code = get16(in + 10);
    r.principal = get32(in + 12);
    r.target.cap_id = get32(in + 16);
    r.target.generation = get64(in + 20);
    copy_bytes(r.machine_id, in + 28, ARGUS_MACHINE_ID_LEN);
    copy_bytes(r.finding_digest, in + 60, ARGUS_DIGEST_LEN);
    r.request_id = get64(in + 92);
    r.finding_sequence = get64(in + 100);
    r.target_object = get32(in + 108);
    r.target_rights = get32(in + 112);
    copy_bytes(r.target_digest, in + 116, ARGUS_DIGEST_LEN);
    r.flags = get16(in + 148);
    r.version = in[150];
    r.reserved = in[151];
    if (r.containment < 1 || r.containment > ARGUS_CONTAIN_MAX) return ARGUS_ERR_MALFORMED;
    if (r.severity < ARGUS_SEV_INFO || r.severity > ARGUS_SEV_CRITICAL) return ARGUS_ERR_MALFORMED;
    if (r.reserved != 0) return ARGUS_ERR_MALFORMED;
    if ((r.flags & (uint16_t)~ARGUS_CREQ_KNOWN) != 0) return ARGUS_ERR_MALFORMED;
    if (r.request_id == 0 || r.finding_sequence == 0) return ARGUS_ERR_MALFORMED;   /* I1.c */
    *out = r;
    return ARGUS_OK;
}

void argus_contain_request_digest(const ArgusContainmentRequest *r, uint8_t out[ARGUS_DIGEST_LEN])
{
    uint8_t b[ARGUS_CONTAIN_REQUEST_SIZE];
    creq_encode_raw(r, b);
    sha256_hash(b, sizeof b, out);
}
