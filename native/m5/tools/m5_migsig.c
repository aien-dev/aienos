/* m5_migsig: build, sign and verify M5 owner-signed migration records.
 * Hosted tool (libc I/O); the record logic is libaienos_m5 + native/sig.
 *
 *   m5_migsig pubkey SECRET_KEY_FILE PUBLIC_KEY_OUT
 *   m5_migsig body   SPEC_FILE PUBLIC_KEY_FILE BODY_OUT
 *   m5_migsig sign   SECRET_KEY_FILE BODY_FILE RECORD_OUT
 *   m5_migsig verify PUBLIC_KEY_FILE RECORD_FILE SPEC_FILE LAST_COUNTER
 *
 * The tool never creates a key. The owner secret key is only ever read from
 * the path given (Drake's offline Gate 3 ceremony); tests use TEST keys.
 * Secret key file: 32 raw bytes, 64 hex digits (+ optional newline), or the
 * 48-byte unencrypted PKCS#8 DER of an Ed25519 key; it must not be readable
 * by group or others. Public key file: 32 raw bytes, 64 hex digits, or the
 * 44-byte SubjectPublicKeyInfo DER. Output files are created new (O_EXCL).
 *
 * SPEC_FILE: one key=value per line, '#' comments, every key once except
 * envelope (any number, any order; the tool sorts and refuses duplicates):
 *   class=production|test  agent_root=<64 hex>  source_store=<32 hex>
 *   dest_store=<32 hex>  source_store_generation=<u64>  store_format_version=<u32>
 *   envelope=<64 hex ObjectId>  migration_manifest_digest=<64 hex>
 *   migration_counter=<u64>  owner_hierarchy_generation=<u64>
 *
 * Exit: 0 ok, 1 record refused (verify) or signing refused, 2 usage/I/O/spec error. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../m5.h"
#include "../../sig/aienos_sig.h"

#define MAX_ENVELOPES 65536u

static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    for (size_t i = 0; i < n; i++) v[i] = 0;
}

static int die(const char *msg, const char *arg)
{
    fprintf(stderr, "m5_migsig: %s%s%s\n", msg, arg ? ": " : "", arg ? arg : "");
    return 2;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Exactly 2*n hex digits. */
static int parse_hex(const char *s, size_t slen, uint8_t *out, size_t n)
{
    if (slen != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int h = hexval(s[2 * i]), l = hexval(s[2 * i + 1]);
        if (h < 0 || l < 0) return -1;
        out[i] = (uint8_t)(h << 4 | l);
    }
    return 0;
}

static int parse_u64(const char *s, uint64_t max, uint64_t *out)
{
    if (!*s || strlen(s) > 20) return -1;
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        uint64_t d = (uint64_t)(*p - '0');
        if (v > (UINT64_MAX - d) / 10) return -1;
        v = v * 10 + d;
    }
    if (v > max) return -1;
    *out = v;
    return 0;
}

/* Reads at most cap bytes; *len gets the size. Refuses a larger file. */
static int read_small(const char *path, uint8_t *buf, size_t cap, size_t *len, int secret)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return -1; }
    if (secret && (st.st_mode & 077)) { close(fd); return -3; }
    size_t n = 0;
    for (;;) {
        ssize_t r = read(fd, buf + n, cap - n);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        if (r == 0) break;
        n += (size_t)r;
        if (n == cap) {
            uint8_t extra;
            ssize_t r2 = read(fd, &extra, 1);
            if (r2 != 0) { close(fd); return -2; }
            break;
        }
    }
    close(fd);
    *len = n;
    return 0;
}

static const uint8_t PKCS8_PREFIX[16] = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                                          0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };
static const uint8_t SPKI_PREFIX[12] = { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
                                         0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };

/* 32 raw, 64 hex (+ "\n"), or DER with the given prefix. */
static int decode_key(const uint8_t *buf, size_t n, const uint8_t *prefix, size_t plen, uint8_t key[32])
{
    if (n == 32) { memcpy(key, buf, 32); return 0; }
    if (n == 64 || (n == 65 && buf[64] == '\n'))
        return parse_hex((const char *)buf, 64, key, 32);
    if (n == plen + 32 && memcmp(buf, prefix, plen) == 0) { memcpy(key, buf + plen, 32); return 0; }
    return -1;
}

static int load_secret(const char *path, uint8_t sk[32])
{
    uint8_t buf[80];
    size_t n = 0;
    int r = read_small(path, buf, sizeof buf, &n, 1);
    if (r == -3) { wipe(buf, sizeof buf); return die("secret key file is readable by group or others (chmod 600)", path); }
    if (r != 0) { wipe(buf, sizeof buf); return die("cannot read secret key file", path); }
    r = decode_key(buf, n, PKCS8_PREFIX, sizeof PKCS8_PREFIX, sk);
    wipe(buf, sizeof buf);
    if (r != 0) { wipe(sk, 32); return die("secret key file is not 32 raw bytes, 64 hex digits or Ed25519 PKCS#8 DER", path); }
    return 0;
}

static int load_public(const char *path, uint8_t pk[32])
{
    uint8_t buf[80];
    size_t n = 0;
    if (read_small(path, buf, sizeof buf, &n, 0) != 0) return die("cannot read public key file", path);
    if (decode_key(buf, n, SPKI_PREFIX, sizeof SPKI_PREFIX, pk) != 0)
        return die("public key file is not 32 raw bytes, 64 hex digits or Ed25519 SPKI DER", path);
    return 0;
}

static int write_new(const char *path, const void *data, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return die("cannot create output (it must not exist yet)", path);
    const uint8_t *p = data;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; close(fd); unlink(path); return die("write failed", path); }
        off += (size_t)w;
    }
    if (fsync(fd) != 0 || close(fd) != 0) { unlink(path); return die("write failed", path); }
    return 0;
}

static int cmp32(const void *a, const void *b) { return memcmp(a, b, 32); }

enum { K_CLASS, K_AGENT, K_SRC, K_DST, K_GEN, K_FMT, K_MAN, K_CTR, K_OGEN, K_N };
static const char *const KEYS[K_N] = { "class", "agent_root", "source_store", "dest_store",
                                       "source_store_generation", "store_format_version",
                                       "migration_manifest_digest", "migration_counter",
                                       "owner_hierarchy_generation" };

/* Parse SPEC_FILE into m (owner_key_id left zero). */
static int load_spec(const char *path, m5_owner_migration *m)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("cannot read spec file", path);
    memset(m, 0, sizeof *m);
    int seen[K_N] = { 0 };
    uint8_t (*ids)[32] = calloc(MAX_ENVELOPES, 32);
    if (!ids) { fclose(f); return die("out of memory", NULL); }
    uint32_t n_ids = 0;
    char line[256];
    int lineno = 0, rc = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') line[--len] = 0;
        else if (!feof(f)) { rc = die("spec line too long", path); break; }
        if (len && line[len - 1] == '\r') { rc = die("spec has CR line endings", path); break; }
        if (!len || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) { fprintf(stderr, "m5_migsig: spec line %d has no '='\n", lineno); rc = 2; break; }
        *eq = 0;
        const char *k = line, *v = eq + 1;
        size_t vl = strlen(v);
        uint64_t u = 0;
        int bad = 0;
        if (strcmp(k, "envelope") == 0) {
            if (n_ids >= MAX_ENVELOPES) { rc = die("too many envelope lines", path); break; }
            bad = parse_hex(v, vl, ids[n_ids], 32);
            if (!bad) n_ids++;
        } else {
            int idx = -1;
            for (int i = 0; i < K_N; i++) if (strcmp(k, KEYS[i]) == 0) idx = i;
            if (idx < 0) { fprintf(stderr, "m5_migsig: spec line %d: unknown key '%s'\n", lineno, k); rc = 2; break; }
            if (seen[idx]++) { fprintf(stderr, "m5_migsig: spec line %d: '%s' given twice\n", lineno, k); rc = 2; break; }
            switch (idx) {
            case K_CLASS:
                if (strcmp(v, "production") == 0) m->identity_class = M5_ID_PRODUCTION;
                else if (strcmp(v, "test") == 0) m->identity_class = M5_ID_TEST;
                else bad = 1;
                break;
            case K_AGENT: bad = parse_hex(v, vl, m->agent_root_id, 32); break;
            case K_SRC: bad = parse_hex(v, vl, m->source_store_uuid, 16); break;
            case K_DST: bad = parse_hex(v, vl, m->dest_store_uuid, 16); break;
            case K_GEN: bad = parse_u64(v, UINT64_MAX, &u); m->source_store_generation = u; break;
            case K_FMT: bad = parse_u64(v, UINT32_MAX, &u); m->store_format_version = (uint32_t)u; break;
            case K_MAN: bad = parse_hex(v, vl, m->migration_manifest_digest, 32); break;
            case K_CTR: bad = parse_u64(v, UINT64_MAX, &u); m->migration_counter = u; break;
            case K_OGEN: bad = parse_u64(v, UINT64_MAX, &u); m->owner_hierarchy_generation = u; break;
            }
        }
        if (bad) { fprintf(stderr, "m5_migsig: spec line %d: bad value for '%s'\n", lineno, k); rc = 2; break; }
    }
    if (!rc && ferror(f)) rc = die("cannot read spec file", path);
    fclose(f);
    for (int i = 0; !rc && i < K_N; i++)
        if (!seen[i]) { fprintf(stderr, "m5_migsig: spec is missing '%s'\n", KEYS[i]); rc = 2; }
    if (!rc) {
        qsort(ids, n_ids, 32, cmp32);
        m->envelope_count = n_ids;
        if (m5_envelope_set_digest((const uint8_t (*)[32])ids, n_ids, m->envelope_set_digest) != M5_OK)
            rc = die("duplicate envelope ObjectId in spec", path);
    }
    free(ids);
    return rc;
}

static void print_hex(const char *label, const uint8_t *p, size_t n)
{
    printf("%s=", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static const char *err_name(int rc)
{
    switch (rc) {
    case M5_ERR_ARG: return "ARG"; case M5_ERR_FORMAT: return "FORMAT"; case M5_ERR_BOUNDS: return "BOUNDS";
    case M5_ERR_AUTH: return "AUTH (wrong key or bad signature)"; case M5_ERR_BINDING: return "BINDING (field mismatch)";
    case M5_ERR_IDENTITY: return "IDENTITY (class)"; case M5_ERR_REPLAY: return "REPLAY (counter not above last)";
    default: return "error";
    }
}

static int cmd_pubkey(const char *skf, const char *out)
{
    uint8_t sk[32], pk[32];
    if (load_secret(skf, sk)) return 2;
    int r = aienos_ed25519_public_key(pk, sk);
    wipe(sk, sizeof sk);
    if (r != AIENOS_SIG_OK) return die("key derivation failed", NULL);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", pk[i]);
    hex[64] = '\n';
    return write_new(out, hex, 65);
}

static int cmd_body(const char *spec, const char *pkf, const char *out)
{
    m5_owner_migration m;
    uint8_t pk[32], rec[M5_OWNER_MIG_LEN];
    if (load_spec(spec, &m) || load_public(pkf, pk)) return 2;
    if (m5_owner_migration_body(&m, pk, rec) != M5_OK) return die("cannot build body", NULL);
    return write_new(out, rec, sizeof rec);
}

static int cmd_sign(const char *skf, const char *body, const char *out)
{
    uint8_t sk[32], rec[M5_OWNER_MIG_LEN + 1];
    size_t n = 0;
    int r = read_small(body, rec, sizeof rec, &n, 0);
    if (r != 0 || n != M5_OWNER_MIG_LEN) return die("body file is not a 272-byte record", body);
    if (load_secret(skf, sk)) return 2;
    r = m5_owner_migration_sign_body(rec, sk);
    wipe(sk, sizeof sk);
    if (r != M5_OK) { fprintf(stderr, "m5_migsig: signing refused: %s\n", err_name(r)); return 1; }
    return write_new(out, rec, M5_OWNER_MIG_LEN);
}

static int cmd_verify(const char *pkf, const char *recf, const char *spec, const char *last_s)
{
    uint8_t pk[32], rec[M5_OWNER_MIG_LEN + 1];
    m5_owner_migration e, o;
    uint64_t last;
    size_t n = 0;
    if (parse_u64(last_s, UINT64_MAX, &last)) return die("LAST_COUNTER is not a decimal u64", last_s);
    if (load_public(pkf, pk) || load_spec(spec, &e)) return 2;
    int r = read_small(recf, rec, sizeof rec, &n, 0);
    if (r == -1) return die("cannot read record", recf);
    if (r == -2) n = sizeof rec; /* longer than a record: the library refuses it */
    r = m5_owner_migration_verify(rec, n, pk, e.identity_class, &e, last, &o);
    if (r != M5_OK) { printf("M5_OWNER_MIGRATION_VERIFY: REFUSED %s\n", err_name(r)); return 1; }
    print_hex("owner_key_id", o.owner_key_id, 32);
    print_hex("source_store", o.source_store_uuid, 16);
    print_hex("dest_store", o.dest_store_uuid, 16);
    printf("source_store_generation=%llu\n", (unsigned long long)o.source_store_generation);
    printf("envelope_count=%u\n", o.envelope_count);
    printf("migration_counter=%llu\n", (unsigned long long)o.migration_counter);
    printf("M5_OWNER_MIGRATION_VERIFY: OK\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "pubkey") == 0) return cmd_pubkey(argv[2], argv[3]);
    if (argc == 5 && strcmp(argv[1], "body") == 0) return cmd_body(argv[2], argv[3], argv[4]);
    if (argc == 5 && strcmp(argv[1], "sign") == 0) return cmd_sign(argv[2], argv[3], argv[4]);
    if (argc == 6 && strcmp(argv[1], "verify") == 0) return cmd_verify(argv[2], argv[3], argv[4], argv[5]);
    fprintf(stderr, "usage: m5_migsig pubkey SECRET_KEY_FILE PUBLIC_KEY_OUT\n"
                    "       m5_migsig body SPEC_FILE PUBLIC_KEY_FILE BODY_OUT\n"
                    "       m5_migsig sign SECRET_KEY_FILE BODY_FILE RECORD_OUT\n"
                    "       m5_migsig verify PUBLIC_KEY_FILE RECORD_FILE SPEC_FILE LAST_COUNTER\n");
    return 2;
}
