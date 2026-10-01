/* artifact_store.c -- see artifact_store.h. */
#include "artifact_store.h"
#include <stddef.h>
#include "ck.h"
#include "sha256.h"

static void az(void *p, size_t n)
{
    uint8_t *b = p;
    while (n--) *b++ = 0;
}
static void acp(void *d, const void *s, size_t n)
{
    uint8_t *o = d;
    const uint8_t *i = s;
    while (n--) *o++ = *i++;
}
static int aeq(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i]) return 0;
    return 1;
}
static uint32_t g32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static size_t slen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}
static uint16_t g16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
#ifdef CK_ART_STORE_WRITER
static void p32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void p16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
#endif

static const uint8_t IX_MAGIC[8] = {'A', 'I', 'E', 'N', 'A', 'I', 'X', '1'};
static const uint8_t CH_MAGIC[8] = {'A', 'I', 'E', 'N', 'A', 'C', 'H', '1'};

static uint32_t chunks_for(uint32_t len) { return (len + CK_ART_CHUNK_DATA - 1u) / CK_ART_CHUNK_DATA; }
static uint32_t chunk_size(uint32_t len, uint32_t i)
{
    uint32_t off = i * CK_ART_CHUNK_DATA, rest = len - off;
    return rest < CK_ART_CHUNK_DATA ? rest : CK_ART_CHUNK_DATA;
}

/* name: 1..32 bytes of printable ASCII without space, zero padded to 32. */
static int name_ok(const uint8_t *nlen, const uint8_t *name)
{
    if (*nlen == 0 || *nlen > CK_ART_NAME_MAX) return 0;
    for (uint32_t i = 0; i < CK_ART_NAME_MAX; i++) {
        if (i < *nlen) {
            if (name[i] < 0x21 || name[i] > 0x7e) return 0;
        } else if (name[i]) {
            return 0;
        }
    }
    return 1;
}

void ck_art_set_free(ck_art_set *set)
{
    if (!set) return;
    for (uint32_t i = 0; i < CK_ART_MAX_ENTRIES; i++)
        if (set->e[i].bytes) {
            ck_free(set->e[i].bytes);
            set->e[i].bytes = 0;
        }
}

static int bad(ck_art_set *set, const char **why, const char *w, uint8_t *buf, uint64_t *gens)
{
    ck_art_set_free(set);
    az(set, sizeof *set);
    if (why) *why = w;
    if (buf) ck_free(buf);
    if (gens) ck_free(gens);
    return -1;
}

int ck_art_collect(ss_store *s, ck_art_set *set, const char **why)
{
    if (why) *why = "ok";
    if (!set) return -1;
    az(set, sizeof *set);
    if (!s || !s->ws) {
        if (why) *why = "no Store";
        return -1;
    }
    ss_workspace *ws = s->ws;

    /* Newest index = highest Store generation among index-kind claims. */
    int best = -1;
    for (uint32_t k = 0; k < s->nclaims; k++) {
        const ss_claim *c = &ws->claims[k];
        if (c->c.obj.object_kind != CK_ART_INDEX_KIND) continue;
        if (best < 0 || c->c.store_generation > ws->claims[best].c.store_generation) best = (int)k;
    }
    if (best < 0) return 0;

    uint8_t *buf = ck_alloc(SS_MAX_PLAINTEXT);
    uint64_t *gens = ck_alloc(sizeof(uint64_t) * CK_ART_MAX_ENTRIES * CK_ART_MAX_CHUNKS);
    if (!buf || !gens) return bad(set, why, "out of memory", buf, gens);
    az(gens, sizeof(uint64_t) * CK_ART_MAX_ENTRIES * CK_ART_MAX_CHUNKS);

    uint8_t sid[32];
    size_t len = 0;
    uint16_t kind = 0;
    acp(sid, ws->claims[best].sid, 32);
    uint64_t igen = ws->claims[best].c.store_generation;
    if (ss_read(s, sid, buf, SS_MAX_PLAINTEXT, &len, &kind) != 0 || kind != CK_ART_INDEX_KIND)
        return bad(set, why, "index object read failed", buf, gens);
    if (len < CK_ART_INDEX_HDR || !aeq(buf, IX_MAGIC, 8) || g32(buf + 8) != CK_ART_VERSION)
        return bad(set, why, "index malformed (header)", buf, gens);
    uint32_t n = g32(buf + 12);
    if (n > CK_ART_MAX_ENTRIES || len != CK_ART_INDEX_HDR + (size_t)n * CK_ART_INDEX_ENTRY)
        return bad(set, why, "index malformed (count/length)", buf, gens);
    set->found = 1;
    set->index_generation = igen;
    sha256_hash(buf, len, set->index_sha256);
    set->count = n;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *e = buf + CK_ART_INDEX_HDR + (size_t)i * CK_ART_INDEX_ENTRY;
        ck_art_entry *a = &set->e[i];
        if (!name_ok(e, e + 4) || e[1] || e[2] || e[3] || g16(e + 42) || g32(e + 44))
            return bad(set, why, "index malformed (entry)", buf, gens);
        uint32_t blen = g32(e + 36);
        uint16_t ch = g16(e + 40);
        if (blen == 0) return bad(set, why, "index malformed (empty artifact)", buf, gens);
        acp(a->name, e + 4, e[0]);
        a->name[e[0]] = 0;
        for (uint32_t j = 0; j < i; j++)
            if (aeq(set->e[j].name, a->name, CK_ART_NAME_MAX + 1))
                return bad(set, why, "index malformed (duplicate name)", buf, gens);
        a->len = blen;
        a->chunks = ch;
        acp(a->want, e + 48, 32);
        if (blen > CK_ART_MAX_BYTES) {
            a->state = CK_ART_TOO_LARGE; /* never read; the loader refuses it */
            continue;
        }
        if (ch != chunks_for(blen)) return bad(set, why, "index malformed (chunk count)", buf, gens);
        a->state = CK_ART_MISSING; /* until every chunk is found */
        a->bytes = ck_alloc(blen);
        if (!a->bytes) return bad(set, why, "out of memory", buf, gens);
        az(a->bytes, blen);
    }

    /* Chunks: committed no later than the index, matching an entry exactly.
     * For one (entry, chunk) the newest generation wins. */
    for (uint32_t k = 0; k < s->nclaims; k++) {
        const ss_claim *c = &ws->claims[k];
        if (c->c.obj.object_kind != CK_ART_CHUNK_KIND) continue;
        uint64_t g = c->c.store_generation;
        if (g > igen) {
            set->chunks_ignored++;
            continue;
        }
        acp(sid, c->sid, 32);
        if (ss_read(s, sid, buf, SS_MAX_PLAINTEXT, &len, &kind) != 0 || kind != CK_ART_CHUNK_KIND)
            return bad(set, why, "chunk object read failed", buf, gens);
        int used = 0;
        if (len >= CK_ART_CHUNK_HDR && aeq(buf, CH_MAGIC, 8) && g32(buf + 8) == CK_ART_VERSION &&
            name_ok(buf + 20, buf + 24) && !buf[21] && !buf[22] && !buf[23]) {
            uint32_t tl = g32(buf + 12);
            uint16_t ci = g16(buf + 16), cc = g16(buf + 18);
            for (uint32_t i = 0; i < n; i++) {
                ck_art_entry *a = &set->e[i];
                if (a->state == CK_ART_TOO_LARGE || !a->bytes) continue;
                if (buf[20] != (uint8_t)slen(a->name) || !aeq(buf + 24, a->name, buf[20])) continue;
                if (!aeq(buf + 56, a->want, 32)) break; /* another write's chunk */
                if (tl != a->len || cc != a->chunks || ci >= cc) break;
                uint32_t sz = chunk_size(tl, ci);
                if (len != CK_ART_CHUNK_HDR + sz) break;
                uint64_t *slot = &gens[i * CK_ART_MAX_CHUNKS + ci];
                if (*slot && *slot >= g) break; /* an equal or newer copy already won */
                if (!*slot) a->present++;
                *slot = g;
                acp(a->bytes + (size_t)ci * CK_ART_CHUNK_DATA, buf + CK_ART_CHUNK_HDR, sz);
                used = 1;
                break;
            }
        }
        if (used) set->chunks_used++;
        else set->chunks_ignored++;
    }
    for (uint32_t i = 0; i < n; i++) {
        ck_art_entry *a = &set->e[i];
        if (a->state == CK_ART_TOO_LARGE) continue;
        if (a->present == a->chunks) sha256_hash(a->bytes, a->len, a->sha256);
        if (a->present == a->chunks && aeq(a->sha256, a->want, 32)) {
            a->state = CK_ART_OK;
        } else {
            if (a->present == a->chunks) a->state = CK_ART_MISMATCH;
            ck_free(a->bytes);
            a->bytes = 0;
        }
    }
    az(buf, SS_MAX_PLAINTEXT);
    ck_free(buf);
    ck_free(gens);
    return 0;
}

/* ---- kernel stage glue ---------------------------------------------------- */
static ck_art_set *g_set;
static struct ck_disk_artifact g_out[CK_ART_MAX_ENTRIES];
static struct ck_disk_artifacts g_res;
static int g_loaded;

static void hex(char *o, const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        o[2 * i] = d[b[i] >> 4];
        o[2 * i + 1] = d[b[i] & 15];
    }
    o[2 * n] = 0;
}

void ck_art_stage_load(ss_store *s, const char *refusal)
{
    char h[65];
    g_loaded = 1;
    az(&g_res, sizeof g_res);
    g_res.a = g_out;
    if (!s) {
        g_res.why = "boot disk Store refused";
        ck_printf("artifact_disk: none (Store refused: %s); no artifact bytes read\n", refusal ? refusal : "?");
        return;
    }
    if (!g_set) g_set = ck_alloc(sizeof *g_set);
    if (!g_set) {
        g_res.why = "out of memory";
        ck_printf("artifact_disk: none (out of memory)\n");
        return;
    }
    ck_art_set_free(g_set); /* bytes of an earlier load (host tests) */
    az(g_out, sizeof g_out);
    const char *why = 0;
    int rc = ck_art_collect(s, g_set, &why);
    if (rc < 0) {
        g_res.why = "artifact index refused";
        ck_printf("artifact_disk: REFUSED (%s); no artifact used\n", why);
        return;
    }
    if (!g_set->found) {
        g_res.why = "no artifact index in the boot disk Store";
        ck_printf("artifact_disk: none (no artifact index in the boot disk Store)\n");
        return;
    }
    hex(h, g_set->index_sha256, 32);
    ck_printf("artifact_disk: index generation=%llu entries=%u chunks_used=%u chunks_ignored=%u sha256=%s\n",
              (unsigned long long)g_set->index_generation, g_set->count, g_set->chunks_used,
              g_set->chunks_ignored, h);
    for (uint32_t i = 0; i < g_set->count; i++) {
        const ck_art_entry *a = &g_set->e[i];
        g_out[i].name = a->name;
        g_out[i].len = a->len;
        g_out[i].bytes = a->state == CK_ART_OK ? a->bytes : 0;
        g_out[i].state = a->state == CK_ART_OK ? CK_DISK_ART_OK :
                         a->state == CK_ART_TOO_LARGE ? CK_DISK_ART_TOO_LARGE : CK_DISK_ART_MISSING;
        if (a->state == CK_ART_OK) {
            hex(h, a->sha256, 32);
            ck_printf("artifact_disk: %s bytes=%u sha256=%s\n", a->name, a->len, h);
        } else if (a->state == CK_ART_TOO_LARGE) {
            ck_printf("artifact_disk: %s bytes=%u too-large (limit %u); not read\n", a->name, a->len,
                      CK_ART_MAX_BYTES);
        } else if (a->state == CK_ART_MISMATCH) {
            ck_printf("artifact_disk: %s bytes=%u assembled sha256 differs from the index; not used\n",
                      a->name, a->len);
        } else {
            ck_printf("artifact_disk: %s bytes=%u missing chunks=%u/%u; not used\n", a->name, a->len,
                      a->present, a->chunks);
        }
    }
    g_res.available = 1;
    g_res.why = "ok";
    g_res.generation = g_set->index_generation;
    g_res.count = g_set->count;
}

int ck_stage_disk_artifacts(struct ck_disk_artifacts *out)
{
    if (!out || !g_loaded) return -1;
    *out = g_res;
    return 0;
}

void ck_stage_disk_artifacts_free(void)
{
    if (g_set) {
        uint64_t nb = 0;
        uint32_t na = 0;
        for (uint32_t i = 0; i < CK_ART_MAX_ENTRIES; i++)
            if (g_set->e[i].bytes) {
                nb += g_set->e[i].len;
                na++;
            }
        ck_printf("artifact_disk: released heap copies artifacts=%u bytes=%llu\n", na, (unsigned long long)nb);
        ck_art_set_free(g_set);
        ck_free(g_set);
        g_set = 0;
    }
    az(g_out, sizeof g_out);
    az(&g_res, sizeof g_res);
}

/* ---- host writer ------------------------------------------------------------ */
#ifdef CK_ART_STORE_WRITER
static int put_name(uint8_t *nlen, uint8_t *name, const char *s)
{
    size_t l = s ? slen(s) : 0;
    if (l == 0 || l > CK_ART_NAME_MAX) return -1;
    *nlen = (uint8_t)l;
    az(name, CK_ART_NAME_MAX);
    acp(name, s, l);
    return name_ok(nlen, name) ? 0 : -1;
}

int ck_art_write(ss_store *s, const ck_art_input *in, size_t n)
{
    if (!s || (n && !in) || n > CK_ART_MAX_ENTRIES) return -1;
    static uint8_t chunk[SS_MAX_OBJECTS][SS_MAX_PLAINTEXT];
    static uint8_t index[CK_ART_INDEX_HDR + CK_ART_MAX_ENTRIES * CK_ART_INDEX_ENTRY];
    ss_object objs[SS_MAX_OBJECTS];
    size_t no = 0;
    az(index, sizeof index);
    acp(index, IX_MAGIC, 8);
    p32(index + 8, CK_ART_VERSION);
    p32(index + 12, (uint32_t)n);
    /* validate every entry before the first transaction */
    for (size_t i = 0; i < n; i++) {
        uint8_t nl, nm[CK_ART_NAME_MAX];
        if (put_name(&nl, nm, in[i].name)) return -2;
        size_t li = slen(in[i].name);
        for (size_t j = 0; j < i; j++) {
            size_t lj = slen(in[j].name);
            if (li == lj && aeq(in[j].name, in[i].name, li)) return -2;
        }
        if (in[i].len == 0 || in[i].len > CK_ART_MAX_BYTES || (!in[i].missing && !in[i].bytes)) return -3;
    }
    for (size_t i = 0; i < n; i++) {
        uint8_t *e = index + CK_ART_INDEX_HDR + i * CK_ART_INDEX_ENTRY;
        if (put_name(e, e + 4, in[i].name)) return -2;
        size_t li = slen(in[i].name);
        for (size_t j = 0; j < i; j++) {
            size_t lj = slen(in[j].name);
            if (li == lj && aeq(in[j].name, in[i].name, li)) return -2;
        }
        if (in[i].len == 0 || in[i].len > CK_ART_MAX_BYTES || (!in[i].missing && !in[i].bytes)) return -3;
        uint32_t len = (uint32_t)in[i].len, cc = chunks_for(len);
        p32(e + 36, len);
        p16(e + 40, (uint16_t)cc);
        uint8_t dg[32];
        az(dg, sizeof dg);
        if (!in[i].missing) sha256_hash(in[i].bytes, len, dg);
        acp(e + 48, dg, 32);
        if (in[i].missing) continue;
        for (uint32_t c = 0; c < cc; c++) {
            uint8_t *b = chunk[no];
            uint32_t sz = chunk_size(len, c);
            az(b, CK_ART_CHUNK_HDR);
            acp(b, CH_MAGIC, 8);
            p32(b + 8, CK_ART_VERSION);
            p32(b + 12, len);
            p16(b + 16, (uint16_t)c);
            p16(b + 18, (uint16_t)cc);
            put_name(b + 20, b + 24, in[i].name);
            acp(b + 56, dg, 32);
            acp(b + CK_ART_CHUNK_HDR, in[i].bytes + (size_t)c * CK_ART_CHUNK_DATA, sz);
            objs[no].kind = CK_ART_CHUNK_KIND;
            objs[no].version = CK_ART_VERSION;
            objs[no].bytes = b;
            objs[no].len = CK_ART_CHUNK_HDR + sz;
            if (++no == SS_MAX_OBJECTS) {
                int rc = ss_transact(s, objs, no, 0, 0, 0);
                if (rc) return rc;
                no = 0;
            }
        }
    }
    if (no) {
        int rc = ss_transact(s, objs, no, 0, 0, 0);
        if (rc) return rc;
    }
    ss_object ix = {CK_ART_INDEX_KIND, CK_ART_VERSION, index, CK_ART_INDEX_HDR + n * CK_ART_INDEX_ENTRY};
    return ss_transact(s, &ix, 1, 0, 0, 0);
}
#endif
