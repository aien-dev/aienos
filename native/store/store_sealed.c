/* store_sealed.c -- M5 sealed store over the C Store v1 engine.
 * See store_sealed.h for the design and README.md for the byte layouts. */
#include "store_sealed.h"

#include <string.h>

#include "../argus/sha256.h"
#include "../crypto/aienos_crypto.h"
#include "store_v1.h"

/* ---- sealed transaction record, kind SS_KIND_TXREC ----
 * 0 "AIENSTX1" | 8 version u16 = 2 (1 refused: SS_E_FORMAT_VERSION) | 10 identity_class | 11 reserved = 0
 * | 12 count u16 (1..SS_MAX_OBJECTS) | 14 reserved u16 = 0 | 16 store_uuid[16]
 * | 32 store_generation u64 | 40 counter u64 (= store_generation)
 * | 48 key_generation u64 | 56 previous_record_digest[32] (zero at generation 2)
 * | 88 count x (store_object_id[32] || m5 commit record[144])
 * | end-32 mac = HMAC(k_root_auth, "AIENOS-STORE-SEALED-TX-V1\0" || bytes[0..end-32])
 *
 * ---- anchor record, torn_slot region ----
 * 0 "AIENSAN1" | 8 version u16 = 1 | 10 identity_class | 11..16 zero
 * | 16 store_uuid[16] | 32 m5 anchor[120] | 152..4096 zero */
#define TX_DOMAIN "AIENOS-STORE-SEALED-TX-V1"
#define ENVID_DOMAIN "AIENOS-SEALED-ENVID-V2"
#define ENVID_KEY_INFO "AIENOS-SEALED-ENVID-KEY-V2"
#define TX_VERSION 2u /* 1 = predictable envelope ids (refused, SS_E_FORMAT_VERSION) */
#define AN_OFF 32u

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t a = 0;
    for (size_t i = 0; i < n; i++) a |= p[i];
    return a == 0;
}
static int valid_class(uint8_t c) { return c == M5_ID_PRODUCTION || c == M5_ID_TEST; }

const char *ss_strerror(int e)
{
    switch (e) {
    case SS_E_ARG: return "SealedArgument";
    case SS_E_IDENTITY: return "SealedIdentityMismatch";
    case SS_E_ROLLBACK: return "SealedRollback";
    case SS_E_INCONSISTENT: return "SealedAnchorInconsistent";
    case SS_E_ANCHOR: return "SealedAnchorCorrupt";
    case SS_E_IO: return "SealedAnchorIo";
    case SS_E_ENVELOPE: return "SealedEnvelopeRefused";
    case SS_E_TXREC: return "SealedRecordMalformed";
    case SS_E_ORDER: return "SealedOutOfOrder";
    case SS_E_DUPLICATE: return "SealedDuplicate";
    case SS_E_FOREIGN_KIND: return "SealedForeignKind";
    case SS_E_CRYPTO: return "SealedCryptoFailure";
    case SS_E_NEEDS_REOPEN: return "SealedNeedsReopen";
    case SS_E_FORMAT_VERSION: return "SealedFormatVersion";
    default: return st_strerror(e);
    }
}

/* ---- torn_slot device over disk_dev ---- */
static int tsd_read(void *c, uint64_t lba, uint32_t n, uint8_t *b)
{
    return disk_read((const disk_dev *)c, lba, n, b);
}
static int tsd_write(void *c, uint64_t lba, uint32_t n, const uint8_t *b)
{
    return disk_write((const disk_dev *)c, lba, n, b);
}
static int tsd_flush(void *c) { return disk_flush((const disk_dev *)c); }

void ss_ts_device(const disk_dev *disk, ts_device *out)
{
    out->ctx = (void *)(uintptr_t)disk;
    out->block_size = disk->block_size;
    out->block_count = disk->block_count;
    out->read = tsd_read;
    out->write = tsd_write;
    out->flush = tsd_flush;
}

static void tx_mac(const uint8_t key[32], const uint8_t *b, size_t body, uint8_t out[32])
{
    aienos_hmac_sha256_ctx c;
    aienos_hmac_sha256_init(&c, key);
    aienos_hmac_sha256_update(&c, (const uint8_t *)TX_DOMAIN, sizeof(TX_DOMAIN));
    aienos_hmac_sha256_update(&c, b, body);
    aienos_hmac_sha256_final(&c, out);
    memset(&c, 0, sizeof c);
}

static int anchor_write(ss_store *s, uint64_t gen, const uint8_t digest[32])
{
    uint8_t *r = s->ws->tsrec;
    memset(r, 0, TS_RECORD_BYTES);
    memcpy(r, "AIENSAN1", 8);
    put16(r + 8, 1);
    r[10] = s->keys.identity_class;
    memcpy(r + 16, s->uuid, 16);
    m5_anchor a;
    memset(&a, 0, sizeof a);
    a.identity_class = s->keys.identity_class;
    memcpy(a.store_uuid, s->uuid, 16);
    a.store_generation = gen;
    a.key_generation = s->keys.key_generation;
    a.counter = gen;
    memcpy(a.commit_digest, digest, 32);
    if (m5_anchor_seal(&a, s->keys.k_root_auth, r + AN_OFF, M5_ANCHOR_LEN) != M5_OK) return SS_E_CRYPTO;
    int rc = ts_commit(&s->ts, r);
    if (rc != TS_OK) {
        s->needs_reopen = 1;
        return rc == TS_EIO ? SS_E_IO : SS_E_ANCHOR;
    }
    s->anchor_gen = gen;
    return 0;
}

int ss_format(const st_dev *store, const ts_device *adev, uint64_t anchor_lba,
              const uint8_t uuid[16], const ss_keys *keys, ss_workspace *ws)
{
    if (!store || !adev || !uuid || !keys || !ws) return SS_E_ARG;
    if (!valid_class(keys->identity_class)) return SS_E_ARG;
    ss_store s;
    memset(&s, 0, sizeof s);
    s.ws = ws;
    s.keys = *keys;
    memcpy(s.uuid, uuid, 16);
    if (ts_open(&s.ts, adev, anchor_lba) != TS_OK) return SS_E_ANCHOR;
    /* 1. zero the anchor region so no record of an earlier store survives */
    memset(ws->tsrec, 0, TS_RECORD_BYTES);
    uint32_t bpu = s.ts.blocks_per_unit;
    for (uint32_t u = 0; u < TS_UNITS; u++)
        if (adev->write(adev->ctx, anchor_lba + (uint64_t)u * bpu, bpu, ws->tsrec) != 0) return SS_E_IO;
    if (adev->flush(adev->ctx) != 0) return SS_E_IO;
    /* 2. Store genesis */
    int rc = st_format(store, uuid);
    if (rc != 0) return rc;
    /* 3. generation-1 anchor */
    uint64_t seq;
    rc = ts_recover(&s.ts, ws->tsrec, &seq, NULL);
    if (rc == TS_EIO) return SS_E_IO;
    if (rc != TS_EMPTY) return SS_E_ANCHOR;
    uint8_t zero[32];
    memset(zero, 0, 32);
    return anchor_write(&s, 1, zero);
}

/* Open one sealed transaction record: format, class, store, MAC, then every
 * embedded M5 commit record. Appends its claims. */
static int tx_open(ss_store *s, const uint8_t *b, size_t len, ss_txinfo *info,
                   ss_claim *claims, uint32_t room, uint32_t *cnt)
{
    if (len < SS_TX_HDR + SS_TX_ENTRY + 32 || len > SS_TX_MAX) return SS_E_TXREC;
    if (memcmp(b, "AIENSTX1", 8) != 0) return SS_E_TXREC;
    if (get16(b + 8) == 1) return SS_E_FORMAT_VERSION; /* GUARD:tx-version-1 */
    if (get16(b + 8) != TX_VERSION || b[11] != 0 || get16(b + 14) != 0)
        return SS_E_TXREC;
    uint32_t n = get16(b + 12);
    if (n == 0 || n > SS_MAX_OBJECTS) return SS_E_TXREC;
    if (len != SS_TX_HDR + (size_t)n * SS_TX_ENTRY + 32) return SS_E_TXREC; /* GUARD:tx-length */
    if (b[10] != s->keys.identity_class) return SS_E_IDENTITY; /* GUARD:tx-class */
    if (memcmp(b + 16, s->uuid, 16) != 0) return SS_E_IDENTITY; /* GUARD:tx-store */
    uint8_t mac[32];
    tx_mac(s->keys.k_root_auth, b, len - 32, mac);
    if (!aienos_ct_equal(mac, b + len - 32, 32)) return SS_E_TXREC; /* GUARD:tx-mac */
    uint64_t gen = get64(b + 32), kgen = get64(b + 48);
    if (get64(b + 40) != gen) return SS_E_ORDER; /* GUARD:tx-counter */
    if (n > room) return SS_E_ENVELOPE;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *e = b + SS_TX_HDR + (size_t)i * SS_TX_ENTRY;
        m5_commit c;
        int rc = m5_commit_open(e + 32, M5_COMMIT_LEN, s->keys.k_root_auth, s->keys.identity_class, &c);
        if (rc == M5_ERR_IDENTITY) return SS_E_IDENTITY;
        if (rc != M5_OK) return SS_E_TXREC;
        if (memcmp(c.obj.store_uuid, s->uuid, 16) != 0) return SS_E_IDENTITY; /* GUARD:commit-store */
        if (c.store_generation != gen) return SS_E_ORDER; /* GUARD:commit-generation */
        if (c.counter != gen) return SS_E_ORDER; /* GUARD:commit-counter */
        if (c.obj.key_generation != kgen) return SS_E_ORDER;
        if (c.object_sequence != i) return SS_E_ORDER; /* GUARD:commit-sequence */
        memcpy(claims[i].sid, e, 32);
        claims[i].c = c;
    }
    info->gen = gen;
    sha256_hash(b, len, info->digest);
    memcpy(info->prev, b + 56, 32);
    *cnt = n;
    return 0;
}

static int find_entry(const sv1_entry *e, uint32_t n, const uint8_t id[32])
{
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = memcmp(e[mid].object_id, id, 32);
        if (c == 0) return (int)mid;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return -1;
}

/* "m5 open": every record and envelope in the Store catalog. */
static int verify_records(ss_store *s, uint64_t G)
{
    ss_workspace *ws = s->ws;
    uint32_t n;
    const sv1_entry *e = st_catalog(&s->st, &n);
    uint32_t ntx = 0, nc = 0, nenv = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (e[i].kind == SS_KIND_ENVELOPE && e[i].version == 1) {
            nenv++;
            continue;
        }
        if (e[i].kind != SS_KIND_TXREC || e[i].version != 1) return SS_E_FOREIGN_KIND; /* GUARD:foreign-kind */
        if (e[i].byte_length > SS_TX_MAX) return SS_E_TXREC;
        size_t len;
        int rc = st_read_object(&s->st, e[i].object_id, ws->rd, sizeof ws->rd, &len);
        if (rc != 0) return rc;
        uint32_t cnt;
        rc = tx_open(s, ws->rd, len, &ws->txs[ntx], ws->claims + nc, ST_CAT_CAP - nc, &cnt);
        if (rc != 0) return rc;
        ntx++;
        nc += cnt;
    }
    /* generations: exactly one record for each of 2..G */
    if (G - 1 > ST_CAT_CAP) return SS_E_ORDER;
    for (uint64_t g = 0; g + 1 < G; g++) ws->bygen[g] = UINT32_MAX;
    for (uint32_t t = 0; t < ntx; t++) {
        uint64_t g = ws->txs[t].gen;
        if (g < 2 || g > G) return SS_E_ORDER; /* GUARD:tx-gen-range */
        if (ws->bygen[g - 2] != UINT32_MAX) return SS_E_DUPLICATE; /* GUARD:tx-duplicate */
        ws->bygen[g - 2] = t;
    }
    uint8_t zero[32];
    memset(zero, 0, 32);
    for (uint64_t g = 2; g <= G; g++) {
        if (ws->bygen[g - 2] == UINT32_MAX) return SS_E_ORDER; /* GUARD:tx-gap */
        const uint8_t *want = g == 2 ? zero : ws->txs[ws->bygen[g - 3]].digest;
        if (memcmp(ws->txs[ws->bygen[g - 2]].prev, want, 32) != 0) return SS_E_ORDER; /* GUARD:tx-chain */
    }
    memcpy(s->last_tx_digest, G >= 2 ? ws->txs[ws->bygen[G - 2]].digest : zero, 32);
    /* envelopes: claims and envelope entries are in one-to-one correspondence */
    memset(ws->used, 0, n);
    for (uint32_t k = 0; k < nc; k++) {
        int at = find_entry(e, n, ws->claims[k].sid);
        if (at < 0 || e[at].kind != SS_KIND_ENVELOPE) return SS_E_ENVELOPE; /* GUARD:claim-present */
        if (ws->used[at]) return SS_E_DUPLICATE; /* GUARD:claim-once */
        ws->used[at] = 1;
        size_t len;
        int rc = st_read_object(&s->st, ws->claims[k].sid, ws->rd, sizeof ws->rd, &len);
        if (rc != 0) return rc;
        if (m5_commit_check_object(&ws->claims[k].c, ws->rd, len) != M5_OK) return SS_E_ENVELOPE; /* GUARD:envelope-digest */
    }
    if (nc != nenv) return SS_E_ENVELOPE; /* GUARD:unclaimed-envelope */
    s->nclaims = nc;
    return 0;
}

int ss_open(ss_store *s, const st_dev *store, const ts_device *adev, uint64_t anchor_lba,
            const ss_keys *keys, ss_workspace *ws)
{
    if (!s || !store || !adev || !keys || !ws) return SS_E_ARG;
    if (!valid_class(keys->identity_class)) return SS_E_ARG;
    memset(s, 0, sizeof *s);
    s->ws = ws;
    s->keys = *keys;
    /* 1. Store open */
    int rc = st_open(&s->st, store, &ws->st);
    if (rc != 0) return rc;
    memcpy(s->uuid, s->st.root.sb.store_uuid, 16);
    uint64_t G = st_generation(&s->st);
    /* 2. ts_recover */
    if (ts_open(&s->ts, adev, anchor_lba) != TS_OK) return SS_E_ANCHOR;
    uint64_t seq;
    rc = ts_recover(&s->ts, ws->tsrec, &seq, NULL);
    if (rc == TS_EIO) return SS_E_IO;
    if (rc != TS_OK && rc != TS_EMPTY) return SS_E_ANCHOR; /* GUARD:anchor-region */
    int have = rc == TS_OK;
    const uint8_t *r = ws->tsrec;
    if (have) {
        if (memcmp(r, "AIENSAN1", 8) != 0 || get16(r + 8) != 1 || !all_zero(r + 11, 5) ||
            !all_zero(r + AN_OFF + M5_ANCHOR_LEN, TS_RECORD_BYTES - AN_OFF - M5_ANCHOR_LEN))
            return SS_E_ANCHOR;
        if (r[10] != keys->identity_class) return SS_E_IDENTITY; /* GUARD:anchor-record-class */
        if (memcmp(r + 16, s->uuid, 16) != 0) return SS_E_IDENTITY; /* GUARD:anchor-record-store */
    }
    /* 3. m5 open */
    rc = verify_records(s, G);
    if (rc != 0) return rc;
    /* 4. m5_evaluate_anti_rollback */
    m5_disk_state d;
    memset(&d, 0, sizeof d);
    d.store_generation = G;
    d.key_generation = keys->key_generation;
    d.counter = G;
    memcpy(d.commit_digest, s->last_tx_digest, 32);
    rc = m5_evaluate_anti_rollback(keys->k_root_auth, keys->identity_class, s->uuid,
                                   have ? r + AN_OFF : NULL, have ? M5_ANCHOR_LEN : 0,
                                   G == 1, &d);
    switch (rc) {
    case M5_RB_VALID_RESUME: case M5_RB_PREPARED_ADVANCE: case M5_RB_GENESIS: break;
    case M5_ERR_ROLLBACK: return SS_E_ROLLBACK;
    case M5_ERR_INCONSISTENT: return SS_E_INCONSISTENT;
    case M5_ERR_IDENTITY: case M5_ERR_BINDING: return SS_E_IDENTITY;
    default: return SS_E_ANCHOR;
    }
    s->rb = rc == M5_RB_VALID_RESUME ? SS_RB_VALID_RESUME
          : rc == M5_RB_PREPARED_ADVANCE ? SS_RB_PREPARED_ADVANCE : SS_RB_GENESIS;
    s->anchor_gen = have ? get64(r + AN_OFF + 32) : 0;
    return 0;
}

void ss_tx_remac(ss_store *s)
{
    uint8_t *b = s->ws->tx;
    size_t len = s->ws->tx_len;
    tx_mac(s->keys.k_root_auth, b, len - 32, b + len - 32);
}

/* Envelope id (16 bytes) and nonce prefix (8 bytes) of the object at
 * (generation, index), V2 rule: the first 24 bytes of
 * HMAC(k_envid, "AIENOS-SEALED-ENVID-V2\0" || uuid || generation u64 ||
 * index u32 || kind u16 || version u16 || key_generation u64 ||
 * identity_class u8 || plaintext_len u64 || SHA-256(plaintext)),
 * k_envid = HKDF-Expand(k_domain, "AIENOS-SEALED-ENVID-KEY-V2\0", 32).
 * The envelope id also feeds the per-object key, so the AES-GCM-SIV
 * (key, nonce) pair of a chunk changes whenever the plaintext changes.
 * After a whole-disk rollback a rewrite of the same generation and index
 * with different bytes therefore never repeats a (key, nonce) pair; only a
 * rewrite of the identical object reproduces the identical envelope, which
 * shows an attacker nothing the old image did not already show. */
static int envid_derive(const ss_store *s, uint64_t gen, uint32_t index, uint16_t kind,
                        uint16_t version, const uint8_t *pt, size_t len, uint8_t out[32])
{
    uint8_t k[32], ph[32], m[16 + 8 + 4 + 2 + 2 + 8 + 1 + 8 + 32];
    if (m5_hkdf_expand(s->keys.k_domain, (const uint8_t *)ENVID_KEY_INFO, sizeof(ENVID_KEY_INFO), k,
                       sizeof k) != M5_OK)
        return SS_E_CRYPTO;
    sha256_hash(pt, len, ph);
    memcpy(m, s->uuid, 16);
    put64(m + 16, gen);
    put32(m + 24, index);
    put16(m + 28, kind);
    put16(m + 30, version);
    put64(m + 32, s->keys.key_generation);
    m[40] = s->keys.identity_class;
    put64(m + 41, (uint64_t)len);
    memcpy(m + 49, ph, 32);
    aienos_hmac_sha256_ctx c;
    aienos_hmac_sha256_init(&c, k);
    aienos_hmac_sha256_update(&c, (const uint8_t *)ENVID_DOMAIN, sizeof(ENVID_DOMAIN));
    aienos_hmac_sha256_update(&c, m, sizeof m);
    aienos_hmac_sha256_final(&c, out);
    memset(k, 0, sizeof k);
    return 0;
}

int ss_prepare(ss_store *s, const ss_object *o, size_t n)
{
    if (!s || !s->ws || (!o && n)) return SS_E_ARG;
    ss_workspace *ws = s->ws;
    ws->nobjs = 0;
    if (s->needs_reopen) return SS_E_NEEDS_REOPEN;
    if (s->st.state != ST_VALID) return ST_E_READ_ONLY_DEGRADED;
    if (n == 0 || n > SS_MAX_OBJECTS) return SS_E_ARG; /* GUARD:sealed-object-limit */
    uint64_t G = st_generation(&s->st);
    if (G == UINT64_MAX) return ST_E_GENERATION_EXHAUSTED;
    uint64_t ng = G + 1;
    uint8_t *tx = ws->tx;
    memset(tx, 0, SS_TX_MAX);
    for (size_t i = 0; i < n; i++) {
        if (o[i].len > SS_MAX_PLAINTEXT || (!o[i].bytes && o[i].len)) return SS_E_ARG; /* GUARD:sealed-size */
        if (o[i].kind == 0 || o[i].version == 0) return SS_E_ARG;
        uint8_t h[32];
        if (envid_derive(s, ng, (uint32_t)i, o[i].kind, o[i].version, o[i].bytes, o[i].len, h) != 0)
            return SS_E_CRYPTO;
        m5_object_binding b;
        memset(&b, 0, sizeof b);
        memcpy(b.store_uuid, s->uuid, 16);
        b.object_kind = o[i].kind;
        b.object_version = o[i].version;
        memcpy(b.envelope_id, h, 16);
        b.key_generation = s->keys.key_generation;
        b.identity_class = s->keys.identity_class;
        if (m5_envelope_seal(s->keys.k_domain, &b, h + 16, SS_CHUNK, o[i].bytes, o[i].len,
                             ws->env[i], SS_ENV_CAP, &ws->env_len[i]) != M5_OK)
            return SS_E_CRYPTO;
        uint8_t *e = tx + SS_TX_HDR + i * SS_TX_ENTRY;
        if (sv1_object_id(SS_KIND_ENVELOPE, 1, ws->env[i], ws->env_len[i], e) != 0) return SS_E_CRYPTO;
        m5_commit mc;
        memset(&mc, 0, sizeof mc);
        mc.obj = b;
        mc.store_generation = ng;
        mc.counter = ng;
        mc.object_sequence = i;
        sha256_hash(ws->env[i], ws->env_len[i], mc.object_id);
        if (m5_commit_seal(&mc, s->keys.k_root_auth, e + 32) != M5_OK) return SS_E_CRYPTO;
        ws->objs[i].kind = SS_KIND_ENVELOPE;
        ws->objs[i].version = 1;
        ws->objs[i].bytes = ws->env[i];
        ws->objs[i].len = ws->env_len[i];
    }
    memcpy(tx, "AIENSTX1", 8);
    put16(tx + 8, TX_VERSION);
    tx[10] = s->keys.identity_class;
    put16(tx + 12, (uint16_t)n);
    memcpy(tx + 16, s->uuid, 16);
    put64(tx + 32, ng);
    put64(tx + 40, ng);
    put64(tx + 48, s->keys.key_generation);
    memcpy(tx + 56, s->last_tx_digest, 32);
    ws->tx_len = SS_TX_HDR + n * SS_TX_ENTRY + 32;
    ss_tx_remac(s);
    ws->objs[n].kind = SS_KIND_TXREC;
    ws->objs[n].version = 1;
    ws->objs[n].bytes = tx;
    ws->objs[n].len = ws->tx_len;
    ws->nobjs = n + 1;
    return 0;
}

int ss_commit_prepared(ss_store *s, st_hook hook, void *arg)
{
    if (!s || !s->ws || s->ws->nobjs < 2) return SS_E_ARG;
    ss_workspace *ws = s->ws;
    if (s->needs_reopen) return SS_E_NEEDS_REOPEN;
    uint64_t G = st_generation(&s->st);
    /* catch a lagging anchor up to the committed Store generation first */
    int lag = 0;
    lag = s->anchor_gen != G; /* GUARD:anchor-catch-up */
    if (lag) {
        int rc = anchor_write(s, G, s->last_tx_digest);
        if (rc != 0) return rc;
        s->rb = SS_RB_VALID_RESUME;
    }
    int rc = st_transact(&s->st, ws->objs, ws->nobjs, hook, arg);
    if (rc != 0) return rc;
    /* Store generation G+1 is durable; record it, then advance the anchor */
    size_t n = (size_t)(ws->tx[12] | (ws->tx[13] << 8));
    ws->nobjs = 0;
    sha256_hash(ws->tx, ws->tx_len, s->last_tx_digest);
    for (size_t i = 0; i < n && s->nclaims < ST_CAT_CAP; i++) {
        const uint8_t *e = ws->tx + SS_TX_HDR + i * SS_TX_ENTRY;
        ss_claim *c = &ws->claims[s->nclaims++];
        memcpy(c->sid, e, 32);
        if (m5_commit_open(e + 32, M5_COMMIT_LEN, s->keys.k_root_auth, s->keys.identity_class, &c->c) != M5_OK)
            return SS_E_CRYPTO;
    }
    if (hook) hook(arg, SS_CP_BEFORE_ANCHOR);
    rc = anchor_write(s, G + 1, s->last_tx_digest);
    if (rc != 0) return rc;
    if (hook) hook(arg, SS_CP_AFTER_ANCHOR);
    return 0;
}

int ss_transact(ss_store *s, const ss_object *o, size_t n, st_hook hook, void *arg,
                uint8_t (*ids_out)[32])
{
    int rc = ss_prepare(s, o, n);
    if (rc != 0) return rc;
    if (ids_out)
        for (size_t i = 0; i < n; i++) memcpy(ids_out[i], s->ws->tx + SS_TX_HDR + i * SS_TX_ENTRY, 32);
    return ss_commit_prepared(s, hook, arg);
}

int ss_read(ss_store *s, const uint8_t sid[32], uint8_t *out, size_t cap, size_t *len,
            uint16_t *kind)
{
    if (len) *len = 0;
    if (!s || !s->ws || !sid || !out || !len) return SS_E_ARG;
    const ss_claim *c = NULL;
    for (uint32_t k = 0; k < s->nclaims; k++)
        if (memcmp(s->ws->claims[k].sid, sid, 32) == 0) { c = &s->ws->claims[k]; break; }
    if (!c) return ST_E_INVALID_OBJECT;
    size_t elen;
    int rc = st_read_object(&s->st, sid, s->ws->rd, sizeof s->ws->rd, &elen);
    if (rc != 0) return rc;
    if (m5_commit_check_object(&c->c, s->ws->rd, elen) != M5_OK) return SS_E_ENVELOPE; /* GUARD:read-digest */
    rc = m5_envelope_open(s->keys.k_domain, s->keys.identity_class, &c->c.obj, s->ws->rd, elen,
                          out, cap, len);
    if (rc == M5_ERR_SPACE) return SS_E_ARG;
    if (rc != M5_OK) return SS_E_ENVELOPE;
    /* the envelope id and nonce prefix must follow the V2 rule for these bytes */
    m5_env_header eh;
    uint8_t h[32];
    int bad = m5_envelope_parse_header(s->ws->rd, elen, &eh) != M5_OK ||
              c->c.object_sequence > UINT32_MAX ||
              envid_derive(s, c->c.store_generation, (uint32_t)c->c.object_sequence,
                           c->c.obj.object_kind, c->c.obj.object_version, out, *len, h) != 0;
    if (!bad) bad = memcmp(h, c->c.obj.envelope_id, 16) != 0 || memcmp(h + 16, eh.nonce_prefix, 8) != 0;
    if (bad) { memset(out, 0, *len); *len = 0; return SS_E_ENVELOPE; } /* GUARD:read-envid-rule */
    if (kind) *kind = c->c.obj.object_kind;
    return 0;
}
