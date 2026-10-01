/* continuity_resolve_sealed.c -- see continuity_resolve_sealed.h. */
#include <string.h>

#include "continuity_resolve_sealed.h"

static uint32_t sealed_count(void *ctx)
{
    const ss_store *s = ctx;
    return s->nclaims;
}

static int sealed_entry(void *ctx, uint32_t i, uint16_t *kind, uint16_t *version)
{
    const ss_store *s = ctx;
    if (i >= s->nclaims) return ST_E_INVALID_OBJECT;
    *kind = s->ws->claims[i].c.obj.object_kind;
    *version = s->ws->claims[i].c.obj.object_version;
    return 0;
}

static int sealed_read(void *ctx, uint32_t i, uint8_t *out, size_t cap, size_t *len)
{
    ss_store *s = ctx;
    if (i >= s->nclaims) return ST_E_INVALID_OBJECT;
    uint8_t sid[32];
    memcpy(sid, s->ws->claims[i].sid, 32);
    uint16_t kind = 0;
    int rc = ss_read(s, sid, out, cap, len, &kind);
    if (rc != 0) return rc;
    /* The claim and the envelope binding must agree on the application kind. */
    if (kind != s->ws->claims[i].c.obj.object_kind) return SS_E_ENVELOPE;
    return 0;
}

static uint64_t sealed_generation(void *ctx)
{
    return ss_generation(ctx);
}

static int sealed_mount_state(void *ctx)
{
    const ss_store *s = ctx;
    return s->st.state == ST_VALID ? CR_MOUNT_VALID : CR_MOUNT_DEGRADED;
}

void cr_bind_sealed(struct cr_source *out, ss_store *s)
{
    out->ctx = s;
    out->count = sealed_count;
    out->entry = sealed_entry;
    out->read = sealed_read;
    out->mount_state = sealed_mount_state;
    out->generation = sealed_generation;
}

void cr_state_digest_dev(const st_dev *dev, uint8_t out[32])
{
    uint8_t raw[2][SV1_UNIT];
    sha256_ctx h;
    for (unsigned u = 0; u < 2; u++) {
        memset(raw[u], 0, SV1_UNIT);
        if (!dev || !dev->read_unit || dev->read_unit(dev->ctx, u, raw[u]) != 0)
            memset(raw[u], 0, SV1_UNIT); /* recovery_core.rs:109-133: error leaves zero */
    }
    sha256_init(&h);
    sha256_update(&h, raw[0], SV1_UNIT);
    sha256_update(&h, raw[1], SV1_UNIT);
    sha256_final(&h, out);
}

static int sealed_transact(void *ctx, const struct cr_wobj *objs, size_t n)
{
    struct cr_sealed_sink *k = ctx;
    ss_object so[SS_MAX_OBJECTS];
    if (n == 0 || n > SS_MAX_OBJECTS) return SS_E_ARG;
    for (size_t i = 0; i < n; i++) {
        so[i].kind = objs[i].kind;
        so[i].version = objs[i].version;
        so[i].bytes = objs[i].bytes;
        so[i].len = objs[i].len;
    }
    return ss_transact(k->s, so, n, k->hook, k->hook_arg, NULL);
}

void cr_bind_sealed_sink(struct cr_sink *out, struct cr_sealed_sink *ctx)
{
    out->ctx = ctx;
    out->transact = sealed_transact;
}
