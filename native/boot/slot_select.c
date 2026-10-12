/* slot_select.c -- AIENOS native image slots: structural checks, slot
 * verification and the loader's / kernel's decision rules (slot_format.h).
 *
 * Freestanding C: no libc, no allocation, no I/O. The only outside symbols
 * are native/sig (aienos_sha512, aienos_ed25519_verify) and
 * native/argus/sha256.c (sha256_hash). The same object is meant for the UEFI
 * stub, the kernel and the hosted tool (native/kernel/tools/ck_slot_tool.c),
 * so the decision a test sees is the decision a loader would take.
 *
 * Rules (TRUST-1 Q19, ADR 0006), in the order ck_slot_select applies them:
 *   usable(s)  = ev[s].valid && ev[s].generation >= floor
 *   1. no control record: boot the highest usable generation (A on a tie);
 *      none usable -> recovery required. Nothing is written.
 *   2. a candidate is set, has tries left and is usable: boot it and hand
 *      back the control record with tries - 1 for the loader to COMMIT
 *      BEFORE jumping (that is what bounds attempts when the candidate hangs).
 *   3. a candidate is set but has no tries left, or is not usable: boot the
 *      active slot if usable (the candidate is abandoned by the kernel later;
 *      the loader writes nothing here, so a wedged kernel cannot loop).
 *   4. active usable: boot it.
 *   5. active not usable, the other slot usable: boot the other slot
 *      ("last-good never erased": media damage to one slot does not strand
 *      the machine).
 *   6. otherwise recovery required: the loader must not boot either slot.
 * The floor never lowers: ck_slot_promote raises it to the promoted image's
 * policy_generation. A validly signed image below the floor never boots. */
#include "slot_format.h"
#include "../sig/aienos_sig.h"
#include "../argus/sha256.h"

static int eq_bytes(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= p[i];
    return d == 0;
}

static void copy_bytes(uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++)
        dst[i] = src[i];
}

static int is_lower_hex(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

int ck_slot_manifest_check(const struct ck_slot_manifest *m, const char **why)
{
    static const uint8_t magic[8] = CK_SLOT_MANIFEST_MAGIC;
    const char *w = 0;
    if (!m)
        w = "null manifest";
    else if (!eq_bytes(m->magic, magic, 8))
        w = "bad magic";
    else if (m->version != CK_SLOT_MANIFEST_VERSION)
        w = "unsupported manifest version";
    else if (m->payload_kind != CK_SLOT_PAYLOAD_BOOTAA64)
        w = "unsupported payload kind";
    else if (m->loader_abi != CK_SLOT_LOADER_ABI)
        w = "loader ABI mismatch";
    else if (m->kernel_abi != CK_SLOT_KERNEL_ABI)
        w = "kernel ABI mismatch";
    else if (m->generation == 0)
        w = "generation is zero";
    else if (m->policy_generation > m->generation)
        w = "policy_generation above generation";
    else if (m->min_rollback_generation > m->generation)
        w = "min_rollback_generation above generation";
    else if (m->image_len == 0)
        w = "image_len is zero";
    else if (!eq_bytes(m->kernel_sha512, m->image_sha512, 64))
        w = "kernel_sha512 differs from image_sha512 (payload kind 1)";
    else if (m->timestamp == 0)
        w = "timestamp is zero";
    else if (m->flags != 0)
        w = "flags nonzero";
    else if (m->reserved0 != 0 || !all_zero(m->reserved1, sizeof m->reserved1))
        w = "reserved bytes nonzero";
    else if (!all_zero(m->pad, sizeof m->pad))
        w = "pad nonzero";
    if (!w) {
        for (unsigned i = 0; i < CK_SLOT_COMMIT_CHARS; i++)
            if (!is_lower_hex(m->commit[i])) {
                w = "commit is not 40 lower-case hex characters";
                break;
            }
    }
    if (!w) {
        int ended = 0;
        for (unsigned i = 0; i < CK_SLOT_PROVENANCE_CHARS; i++) {
            uint8_t c = m->provenance[i];
            if (c == 0) {
                ended = 1;
            } else if (ended || c < 0x20 || c > 0x7e) {
                w = "provenance is not zero-padded printable ASCII";
                break;
            }
        }
    }
    if (why)
        *why = w;
    return w ? -1 : 0;
}

int ck_slot_control_check(const struct ck_slot_control *c, const char **why)
{
    static const uint8_t magic[8] = CK_SLOT_CONTROL_MAGIC;
    const char *w = 0;
    if (!c)
        w = "null control";
    else if (!eq_bytes(c->magic, magic, 8))
        w = "bad control magic";
    else if (c->version != CK_SLOT_CONTROL_VERSION)
        w = "unsupported control version";
    else if (c->active_slot >= CK_SLOT_COUNT)
        w = "active_slot out of range";
    else if (c->candidate_slot != CK_SLOT_NONE && c->candidate_slot >= CK_SLOT_COUNT)
        w = "candidate_slot out of range";
    else if (c->candidate_slot == c->active_slot)
        w = "candidate_slot equals active_slot";
    else if (c->tries_remaining > CK_SLOT_MAX_TRIES)
        w = "tries_remaining above the bound";
    else if (c->candidate_slot == CK_SLOT_NONE && c->tries_remaining != 0)
        w = "tries_remaining without a candidate";
    else if (c->flags & ~(uint8_t)CK_SLOT_CTL_FLAG_CANDIDATE_FAILED)
        w = "unknown control flags";
    else if (c->last_good_generation != 0 && c->last_good_generation < c->generation_floor)
        w = "last_good_generation below the floor";
    else if (!all_zero(c->reserved, sizeof c->reserved))
        w = "control reserved bytes nonzero";
    if (why)
        *why = w;
    return w ? -1 : 0;
}

int ck_slot_verify(const struct ck_slot_manifest *m, const uint8_t *image, uint64_t image_cap,
                   const uint8_t (*keys)[32], unsigned nkeys, struct ck_slot_eval *ev)
{
    uint8_t digest[AIENOS_SHA512_DIGEST_LEN];
    uint8_t id[SHA256_DIGEST_SIZE];
    const char *why = 0;
    unsigned k;

    ev->valid = 0;
    ev->generation = 0;
    ev->policy_generation = 0;
    ev->why = 0;
    if (ck_slot_manifest_check(m, &why) != 0) {
        ev->why = why;
        return 0;
    }
    if (m->image_len > image_cap) {
        ev->why = "image_len exceeds the slot capacity";
        return 0;
    }
    if (!image) {
        ev->why = "no image bytes";
        return 0;
    }
    /* Signature before the (long) digest so a forged manifest costs nothing. */
    for (k = 0; k < nkeys; k++) {
        sha256_hash(keys[k], 32, id);
        if (eq_bytes(id, m->signer_id, 32))
            break;
    }
    if (k == nkeys) {
        ev->why = "signer_id names no trusted key";
        return 0;
    }
    if (aienos_ed25519_verify(m->signature, (const uint8_t *)m, CK_SLOT_TBS_BYTES, keys[k]) !=
        AIENOS_SIG_OK) {
        ev->why = "signature does not verify";
        return 0;
    }
    aienos_sha512(image, (size_t)m->image_len, digest);
    if (!eq_bytes(digest, m->image_sha512, 64)) {
        ev->why = "image SHA-512 mismatch";
        return 0;
    }
    ev->valid = 1;
    ev->generation = m->generation;
    ev->policy_generation = m->policy_generation;
    return 1;
}

static int usable(const struct ck_slot_eval *e, uint64_t floor)
{
    return e->valid && e->generation >= floor;
}

void ck_slot_select(const struct ck_slot_control *ctl, const struct ck_slot_eval ev[CK_SLOT_COUNT],
                    struct ck_slot_decision *d)
{
    const char *why;
    d->boot_slot = -1;
    d->reason = CK_SLOT_R_RECOVERY_REQUIRED;
    d->loader_write = 0;
    for (size_t i = 0; i < sizeof d->ctl_out; i++)
        ((uint8_t *)&d->ctl_out)[i] = 0;

    if (!ctl || ck_slot_control_check(ctl, &why) != 0) {
        /* Rule 1: no floor is known, so none is invented. */
        int a = usable(&ev[0], 0), b = usable(&ev[1], 0);
        if (a && (!b || ev[0].generation >= ev[1].generation))
            d->boot_slot = 0;
        else if (b)
            d->boot_slot = 1;
        d->reason = d->boot_slot < 0 ? CK_SLOT_R_RECOVERY_REQUIRED : CK_SLOT_R_NO_CONTROL;
        return;
    }

    {
        uint64_t floor = ctl->generation_floor;
        unsigned act = ctl->active_slot;
        unsigned other = act ^ 1u;
        if (ctl->candidate_slot != CK_SLOT_NONE) {
            unsigned cand = ctl->candidate_slot;
            if (ctl->tries_remaining > 0 && usable(&ev[cand], floor)) {
                d->boot_slot = (int)cand;
                d->reason = CK_SLOT_R_CANDIDATE_TRY;
                d->loader_write = 1;
                copy_bytes((uint8_t *)&d->ctl_out, (const uint8_t *)ctl, sizeof d->ctl_out);
                d->ctl_out.tries_remaining = (uint8_t)(ctl->tries_remaining - 1u);
                return;
            }
            if (usable(&ev[act], floor)) {
                d->boot_slot = (int)act;
                d->reason = ctl->tries_remaining == 0 ? CK_SLOT_R_CANDIDATE_EXHAUSTED
                                                       : CK_SLOT_R_CANDIDATE_INVALID;
                return;
            }
            /* Active unusable too. The candidate is the other slot and was
             * found unusable or out of tries, so the fallback rule below
             * cannot pick it: an exhausted candidate never boots on its own
             * authority (bounded attempts), and recovery is required. */
        }
        if (usable(&ev[act], floor)) {
            d->boot_slot = (int)act;
            d->reason = CK_SLOT_R_ACTIVE;
            return;
        }
        if (usable(&ev[other], floor) && ctl->candidate_slot != other) {
            d->boot_slot = (int)other;
            d->reason = CK_SLOT_R_ACTIVE_INVALID_FALLBACK;
            return;
        }
    }
}

void ck_slot_control_init(struct ck_slot_control *c, unsigned active_slot)
{
    static const uint8_t magic[8] = CK_SLOT_CONTROL_MAGIC;
    for (size_t i = 0; i < sizeof *c; i++)
        ((uint8_t *)c)[i] = 0;
    copy_bytes(c->magic, magic, 8);
    c->version = CK_SLOT_CONTROL_VERSION;
    c->active_slot = (uint8_t)(active_slot & 1u);
    c->candidate_slot = CK_SLOT_NONE;
    c->tries_remaining = 0;
}

int ck_slot_stage_candidate(struct ck_slot_control *c, unsigned slot, uint64_t generation, const char **why)
{
    const char *w = 0;
    if (ck_slot_control_check(c, &w) != 0) {
    } else if (slot >= CK_SLOT_COUNT)
        w = "slot out of range";
    else if (slot == c->active_slot)
        w = "cannot stage the active slot as a candidate";
    else if (generation < c->generation_floor)
        w = "candidate generation below the security floor";
    else if (c->last_good_generation != 0 && generation <= c->last_good_generation)
        w = "candidate generation not above the last good generation";
    if (w) {
        if (why)
            *why = w;
        return -1;
    }
    c->candidate_slot = (uint8_t)slot;
    c->tries_remaining = CK_SLOT_MAX_TRIES;
    c->flags &= (uint8_t)~CK_SLOT_CTL_FLAG_CANDIDATE_FAILED;
    if (why)
        *why = 0;
    return 0;
}

int ck_slot_promote(struct ck_slot_control *c, unsigned booted_slot, uint64_t generation,
                    uint64_t policy_generation, const char **why)
{
    const char *w = 0;
    if (ck_slot_control_check(c, &w) != 0) {
    } else if (booted_slot >= CK_SLOT_COUNT)
        w = "slot out of range";
    else if (c->candidate_slot == CK_SLOT_NONE || booted_slot != c->candidate_slot)
        w = "only the staged candidate can be promoted";
    else if (generation < c->generation_floor)
        w = "promoted generation below the security floor";
    else if (policy_generation > generation)
        w = "policy_generation above generation";
    if (w) {
        if (why)
            *why = w;
        return -1;
    }
    c->active_slot = (uint8_t)booted_slot;
    c->candidate_slot = CK_SLOT_NONE;
    c->tries_remaining = 0;
    c->flags &= (uint8_t)~CK_SLOT_CTL_FLAG_CANDIDATE_FAILED;
    c->last_good_generation = generation;
    if (policy_generation > c->generation_floor)
        c->generation_floor = policy_generation; /* never lowers */
    if (why)
        *why = 0;
    return 0;
}

int ck_slot_abandon_candidate(struct ck_slot_control *c, const char **why)
{
    const char *w = 0;
    if (ck_slot_control_check(c, &w) != 0) {
    } else if (c->candidate_slot == CK_SLOT_NONE)
        w = "no candidate to abandon";
    if (w) {
        if (why)
            *why = w;
        return -1;
    }
    c->candidate_slot = CK_SLOT_NONE;
    c->tries_remaining = 0;
    c->flags |= CK_SLOT_CTL_FLAG_CANDIDATE_FAILED;
    if (why)
        *why = 0;
    return 0;
}

const char *ck_slot_reason_text(enum ck_slot_reason r)
{
    switch (r) {
    case CK_SLOT_R_NONE: return "none";
    case CK_SLOT_R_CANDIDATE_TRY: return "candidate_try";
    case CK_SLOT_R_ACTIVE: return "active";
    case CK_SLOT_R_CANDIDATE_EXHAUSTED: return "candidate_exhausted_active";
    case CK_SLOT_R_CANDIDATE_INVALID: return "candidate_invalid_active";
    case CK_SLOT_R_ACTIVE_INVALID_FALLBACK: return "active_invalid_fallback";
    case CK_SLOT_R_NO_CONTROL: return "no_control_highest_generation";
    case CK_SLOT_R_RECOVERY_REQUIRED: return "recovery_required";
    }
    return "unknown";
}

/* ---- boot record (P11 cut 2b) ---------------------------------------------- */
void ck_slot_boot_seal(struct ck_slot_boot_record *b)
{
    sha256_hash((const uint8_t *)b, CK_SLOT_BOOT_SIGNED, b->digest);
}

int ck_slot_boot_check(const struct ck_slot_boot_record *b, const char **why)
{
    static const uint8_t magic[8] = CK_SLOT_BOOT_MAGIC;
    uint8_t d[SHA256_DIGEST_SIZE];
    const char *w = 0;
    if (!b)
        w = "no boot record";
    else if (!eq_bytes(b->magic, magic, 8))
        w = "bad boot record magic";
    else if (b->version != CK_SLOT_BOOT_VERSION)
        w = "unsupported boot record version";
    else {
        sha256_hash((const uint8_t *)b, CK_SLOT_BOOT_SIGNED, d);
        if (!eq_bytes(d, b->digest, sizeof d))
            w = "boot record digest mismatch";
        else if (b->boot_slot >= CK_SLOT_COUNT)
            w = "boot record slot out of range";
        else if (b->reason <= CK_SLOT_R_NONE || b->reason >= CK_SLOT_R_RECOVERY_REQUIRED)
            w = "boot record reason out of range";
        else if (b->control_present > 1)
            w = "boot record control flag out of range";
        else if (b->tries > CK_SLOT_MAX_TRIES)
            w = "boot record tries above the bound";
        else if (b->generation == 0 || b->policy_generation > b->generation)
            w = "boot record generation fields";
        else if (!all_zero(b->reserved, sizeof b->reserved))
            w = "boot record reserved bytes nonzero";
        else if (!b->control_present && (b->reason != CK_SLOT_R_NO_CONTROL || b->control_seq != 0))
            w = "boot record claims a decision without a control record";
        else if (b->control_present && b->reason == CK_SLOT_R_NO_CONTROL)
            w = "boot record claims no control with a control record";
    }
    if (why)
        *why = w;
    return w ? -1 : 0;
}

enum ck_slot_action ck_slot_kernel_action(const struct ck_slot_boot_record *b, const struct ck_slot_control *ctl,
                                          const struct ck_slot_manifest *booted, int healthy,
                                          struct ck_slot_control *out, const char **why)
{
    const char *w = 0;
    unsigned s;
    if (ck_slot_boot_check(b, &w) != 0) {
        if (why)
            *why = w;
        return CK_SLOT_A_REFUSE;
    }
    s = b->boot_slot;
    if (!ctl || ck_slot_control_check(ctl, &w) != 0) {
        if (why)
            *why = ctl ? w : "no control record on disk";
        return CK_SLOT_A_REFUSE;
    }
    if (!booted || ck_slot_manifest_check(booted, &w) != 0) {
        if (why)
            *why = booted ? w : "started slot's manifest unreadable";
        return CK_SLOT_A_REFUSE;
    }
    if (booted->generation != b->generation || booted->policy_generation != b->policy_generation ||
        !eq_bytes(booted->image_sha512, b->image_sha512, 64)) {
        if (why)
            *why = "started slot's manifest on disk differs from the boot record";
        return CK_SLOT_A_REFUSE;
    }
    copy_bytes((uint8_t *)out, (const uint8_t *)ctl, sizeof *out);
    if (b->reason == CK_SLOT_R_CANDIDATE_TRY) {
        if (ctl->candidate_slot != s) {
            if (why)
                *why = "control no longer names the started slot as candidate";
            return CK_SLOT_A_NONE;
        }
        if (!healthy) {
            if (why)
                *why = "health milestone not reached";
            return CK_SLOT_A_WAIT;
        }
        if (ck_slot_promote(out, s, booted->generation, booted->policy_generation, &w) != 0) {
            if (why)
                *why = w;
            return CK_SLOT_A_REFUSE;
        }
        if (why)
            *why = 0;
        return CK_SLOT_A_PROMOTE;
    }
    if ((b->reason == CK_SLOT_R_CANDIDATE_EXHAUSTED || b->reason == CK_SLOT_R_CANDIDATE_INVALID) &&
        ctl->candidate_slot != CK_SLOT_NONE && ctl->active_slot == s) {
        if (ck_slot_abandon_candidate(out, &w) != 0) {
            if (why)
                *why = w;
            return CK_SLOT_A_REFUSE;
        }
        if (why)
            *why = 0;
        return CK_SLOT_A_ABANDON;
    }
    if (why)
        *why = "nothing to write";
    return CK_SLOT_A_NONE;
}

const char *ck_slot_action_text(enum ck_slot_action a)
{
    switch (a) {
    case CK_SLOT_A_NONE: return "none";
    case CK_SLOT_A_PROMOTE: return "promote";
    case CK_SLOT_A_ABANDON: return "abandon";
    case CK_SLOT_A_WAIT: return "wait";
    case CK_SLOT_A_REFUSE: return "refuse";
    }
    return "unknown";
}
