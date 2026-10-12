/* ck_slot_tool -- host tool for the AIENOS native image slots
 * (native/boot/slot_format.h, slot_select.c; native v1 plan P11, gate N7).
 * Builds, signs, verifies and inspects slot manifests and control records,
 * and simulates the loader's decision over them. Hosted C, test and
 * provisioning tooling only, never part of an image. No outside libraries.
 *
 *   ck_slot_tool selftest
 *   ck_slot_tool make-manifest --image F --generation N --out M
 *       [--policy-generation N] [--min-rollback N] [--commit HEX40]
 *       [--provenance TEXT] [--timestamp N]       unsigned manifest (signature zero)
 *   ck_slot_tool show M                        print the manifest fields (structural check only)
 *   ck_slot_tool tbs M --pubkey HEX64 --out F    the 448 to-be-signed bytes, for an
 *       offline signer: openssl pkeyutl -sign -inkey owner_root.pem -rawin -in F -out SIG
 *       (signer_id = SHA-256(pubkey) lies inside the signed bytes, so it is set
 *       before the bytes are emitted; attach-sig checks the same bytes)
 *   ck_slot_tool attach-sig M --sig SIG --out M2 --pubkey HEX64
 *   ck_slot_tool sign-test M --out M2 [--test2]  RFC 8032 TEST 1 (or TEST 2) key. NEVER for hardware.
 *   ck_slot_tool verify M --image F (--keys FILE | --test-key) [--cap BYTES]
 *       FILE: tools/ck_owner_gen.c format, "owner_root_ed25519 <64 hex>"
 *   ck_slot_tool control-init --active 0|1 --out C
 *   ck_slot_tool control-show C
 *   ck_slot_tool stage C --slot N --generation N --out C2
 *   ck_slot_tool promote C --slot N --generation N --policy-generation N --out C2
 *   ck_slot_tool abandon C --out C2
 *   ck_slot_tool select (--control C | --no-control) --a M,IMG|none --b M,IMG|none
 *       (--keys FILE | --test-key) [--cap BYTES] [--out C2]   loader decision;
 *       --out writes ctl_out when the loader would have to commit it
 *   ck_slot_tool control-commit --region F --record C     torn-slot commit into a
 *       4-unit region file (512-byte blocks), as the kernel/loader would
 *   ck_slot_tool control-recover --region F --out C
 *   ck_slot_tool keys-c (--keys FILE | --test-key) --out F.c   trusted-key table
 *       compiled into SLOTLDR.EFI (native/boot/slot_loader.c)
 *   ck_slot_tool slots-image --disk IMG --bs 512|4096 --first LBA --last LBA
 *       [--a M,IMG] [--b M,IMG] [--control C]   write a slots partition (control
 *       region, manifests, images) into a disk image where SLOTLDR.EFI reads it
 * Every refusal prints "refused: <reason>" and exits 1. */
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../boot/slot_format.h"
#include "../../sig/aienos_sig.h"
#include "../../argus/sha256.h"
#include "../../store/torn_slot.h"
#include "../../boot/slot_control.h"

/* RFC 8032 section 7.1 TEST 1: seed and public key (the key ck_owner_gen refuses). */
static const uint8_t TEST1_SEED[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
static const uint8_t TEST1_PK[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
/* RFC 8032 section 7.1 TEST 2 seed: the "unknown signer" of the slot loader gate. */
static const uint8_t TEST2_SEED[32] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb};
static const uint8_t TEST2_PK[32] = {
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c};
static const uint8_t TEST3_PK[32] = {
    0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
    0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25};

#define MAX_KEYS 8u
#define DEFAULT_CAP (16u * 1024u * 1024u)

static int refuse(const char *why)
{
    printf("refused: %s\n", why);
    return 1;
}

static int read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf = 0;
    size_t cap = 0, n = 0;
    if (!f)
        return -1;
    for (;;) {
        if (n == cap) {
            cap = cap ? cap * 2 : 65536;
            buf = realloc(buf, cap);
            if (!buf) {
                fclose(f);
                return -1;
            }
        }
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (r == 0)
            break;
    }
    int err = ferror(f);
    fclose(f);
    if (err) {
        free(buf);
        return -1;
    }
    *out = buf;
    *len = n;
    return 0;
}

static int read_unit(const char *path, void *unit)
{
    uint8_t *b;
    size_t n;
    if (read_file(path, &b, &n) != 0)
        return -1;
    if (n != CK_SLOT_UNIT) {
        free(b);
        return -2;
    }
    memcpy(unit, b, CK_SLOT_UNIT);
    free(b);
    return 0;
}

static int write_file(const char *path, const void *p, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    size_t w = fwrite(p, 1, n, f);
    if (fclose(f) != 0 || w != n)
        return -1;
    return 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, uint8_t *out, size_t n)
{
    if (strlen(s) != 2 * n)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    return 0;
}

static int parse_u64(const char *s, uint64_t *v)
{
    char *end;
    errno = 0;
    if (!s || !*s)
        return -1;
    unsigned long long x = strtoull(s, &end, 10);
    if (errno || *end)
        return -1;
    *v = x;
    return 0;
}

static int is_test_key(const uint8_t pk[32])
{
    return memcmp(pk, TEST1_PK, 32) == 0 || memcmp(pk, TEST2_PK, 32) == 0 ||
           memcmp(pk, TEST3_PK, 32) == 0;
}

/* Owner public keys file (tools/ck_owner_gen.c format). */
static int load_keys(const char *path, uint8_t keys[MAX_KEYS][32], unsigned *nkeys, const char **why)
{
    uint8_t *b;
    size_t n;
    unsigned count = 0;
    if (read_file(path, &b, &n) != 0) {
        *why = "cannot read the keys file";
        return -1;
    }
    char *text = malloc(n + 1);
    if (!text) {
        free(b);
        *why = "out of memory";
        return -1;
    }
    memcpy(text, b, n);
    text[n] = 0;
    free(b);
    char *save = 0;
    for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(0, "\n", &save)) {
        while (*line == ' ' || *line == '\t' || *line == '\r')
            line++;
        if (*line == 0 || *line == '#')
            continue;
        char *name = line;
        char *sp = strpbrk(line, " \t");
        if (!sp) {
            free(text);
            *why = "keys file line without a value";
            return -1;
        }
        *sp++ = 0;
        while (*sp == ' ' || *sp == '\t')
            sp++;
        char *end = sp + strlen(sp);
        while (end > sp && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
            *--end = 0;
        if (strcmp(name, "owner_root_ed25519") != 0) {
            free(text);
            *why = "keys file names an unknown key";
            return -1;
        }
        if (count == MAX_KEYS) {
            free(text);
            *why = "too many keys";
            return -1;
        }
        if (parse_hex(sp, keys[count], 32) != 0) {
            free(text);
            *why = "owner_root_ed25519 is not 64 hex characters";
            return -1;
        }
        {
            uint8_t acc = 0;
            for (unsigned i = 0; i < 32; i++)
                acc |= (uint8_t)(keys[count][i] ^ keys[count][0]);
            if (acc == 0) {
                free(text);
                *why = "owner key has all bytes equal";
                return -1;
            }
        }
        if (is_test_key(keys[count])) {
            free(text);
            *why = "owner key is a known TEST key (use --test-key for tests)";
            return -1;
        }
        count++;
    }
    free(text);
    if (count == 0) {
        *why = "keys file holds no owner_root_ed25519";
        return -1;
    }
    *nkeys = count;
    return 0;
}

static void fill_manifest(struct ck_slot_manifest *m, const uint8_t *image, uint64_t image_len,
                          uint64_t generation, uint64_t policy_generation, uint64_t min_rollback,
                          const char *commit, const char *provenance, uint64_t timestamp)
{
    memset(m, 0, sizeof *m);
    memcpy(m->magic, CK_SLOT_MANIFEST_MAGIC, 8);
    m->version = CK_SLOT_MANIFEST_VERSION;
    m->payload_kind = CK_SLOT_PAYLOAD_BOOTAA64;
    m->loader_abi = CK_SLOT_LOADER_ABI;
    m->kernel_abi = CK_SLOT_KERNEL_ABI;
    m->generation = generation;
    m->policy_generation = policy_generation;
    m->min_rollback_generation = min_rollback;
    m->image_len = image_len;
    aienos_sha512(image, (size_t)image_len, m->image_sha512);
    memcpy(m->kernel_sha512, m->image_sha512, 64);
    memcpy(m->commit, commit, CK_SLOT_COMMIT_CHARS);
    {
        size_t pl = strlen(provenance);
        if (pl > CK_SLOT_PROVENANCE_CHARS)
            pl = CK_SLOT_PROVENANCE_CHARS;
        memcpy(m->provenance, provenance, pl);
    }
    m->timestamp = timestamp;
}

static void sign_manifest(struct ck_slot_manifest *m, const uint8_t seed[32])
{
    uint8_t pk[32];
    aienos_ed25519_public_key(pk, seed);
    sha256_hash(pk, 32, m->signer_id);
    aienos_ed25519_sign(m->signature, (const uint8_t *)m, CK_SLOT_TBS_BYTES, seed);
}

static const char *opt(int argc, char **argv, const char *name)
{
    for (int i = 2; i + 1 < argc; i++)
        if (strcmp(argv[i], name) == 0)
            return argv[i + 1];
    return 0;
}

static int flag(int argc, char **argv, const char *name)
{
    for (int i = 2; i < argc; i++)
        if (strcmp(argv[i], name) == 0)
            return 1;
    return 0;
}

static int get_keys(int argc, char **argv, uint8_t keys[MAX_KEYS][32], unsigned *nkeys)
{
    const char *why;
    const char *kf = opt(argc, argv, "--keys");
    if (flag(argc, argv, "--test-key")) {
        memcpy(keys[0], TEST1_PK, 32);
        *nkeys = 1;
        printf("keys: RFC 8032 TEST 1 (tests only, never for hardware)\n");
        return 0;
    }
    if (!kf)
        return refuse("give --keys FILE or --test-key");
    if (load_keys(kf, keys, nkeys, &why) != 0)
        return refuse(why);
    printf("keys: %u owner key(s) from %s\n", *nkeys, kf);
    return 0;
}

static void print_control(const struct ck_slot_control *c)
{
    printf("control: active=%u candidate=%s tries=%u flags=0x%02x floor=%llu last_good=%llu\n",
           c->active_slot,
           c->candidate_slot == CK_SLOT_NONE ? "none" : (c->candidate_slot ? "1" : "0"),
           c->tries_remaining, c->flags, (unsigned long long)c->generation_floor,
           (unsigned long long)c->last_good_generation);
}

static void print_manifest(const struct ck_slot_manifest *m)
{
    printf("manifest: generation=%llu policy=%llu min_rollback=%llu image_len=%llu kernel_abi=%u loader_abi=%u timestamp=%llu\n",
           (unsigned long long)m->generation, (unsigned long long)m->policy_generation,
           (unsigned long long)m->min_rollback_generation, (unsigned long long)m->image_len,
           m->kernel_abi, m->loader_abi, (unsigned long long)m->timestamp);
    printf("  commit=%.40s provenance=%.64s\n", (const char *)m->commit, (const char *)m->provenance);
    printf("  image_sha512=");
    for (unsigned i = 0; i < 64; i++)
        printf("%02x", m->image_sha512[i]);
    printf("\n  signer_id=");
    for (unsigned i = 0; i < 32; i++)
        printf("%02x", m->signer_id[i]);
    printf("\n");
}

/* ---- file-backed torn-slot device (512-byte blocks) ------------------------ */
struct filedev {
    uint8_t *bytes;
    size_t len;
};

static int fd_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf)
{
    struct filedev *d = ctx;
    if ((lba + count) * 512 > d->len)
        return -1;
    memcpy(buf, d->bytes + lba * 512, (size_t)count * 512);
    return 0;
}

static int fd_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    struct filedev *d = ctx;
    if ((lba + count) * 512 > d->len)
        return -1;
    memcpy(d->bytes + lba * 512, buf, (size_t)count * 512);
    return 0;
}

static int fd_flush(void *ctx)
{
    (void)ctx;
    return 0;
}

static void bind_dev(ts_device *dev, struct filedev *d)
{
    dev->ctx = d;
    dev->block_size = 512;
    dev->block_count = d->len / 512;
    dev->read = fd_read;
    dev->write = fd_write;
    dev->flush = fd_flush;
}

/* ---- keys-c rendering ------------------------------------------------------- */
/* Bounded append: on truncation or an encoding error *n becomes cap, which the
 * caller refuses as "key table too large"; never writes past buf[cap - 1] and
 * never computes a size from an offset past cap. */
static void app(char *buf, size_t cap, size_t *n, const char *fmt, ...)
{
    va_list ap;
    int r;
    if (*n >= cap)
        return;
    va_start(ap, fmt);
    r = vsnprintf(buf + *n, cap - *n, fmt, ap);
    va_end(ap);
    if (r < 0 || (size_t)r >= cap - *n)
        *n = cap;
    else
        *n += (size_t)r;
}

/* The C key table SLOTLDR.EFI is built with. Returns its length, or cap when
 * it does not fit (the caller refuses). */
static size_t keys_c_render(char *text, size_t cap, const uint8_t (*keys)[32], unsigned nkeys, int test)
{
    size_t n = 0;
    app(text, cap, &n,
        "/* Generated by ck_slot_tool keys-c (native/kernel/Makefile slot-loader). Do not edit. */\n"
        "#include <stdint.h>\n"
        "const unsigned ck_slot_loader_nkeys = %u;\n"
        "const char ck_slot_loader_key_note[] = \"%s\";\n"
        "const uint8_t ck_slot_loader_keys[%u][32] = {\n",
        nkeys,
        test ? "TEST-ONLY key (RFC 8032 TEST 1): never for hardware"
             : "trusted keys: owner_root_ed25519 from CK_SLOT_KEYS",
        nkeys);
    for (unsigned k = 0; k < nkeys; k++) {
        app(text, cap, &n, "    {");
        for (unsigned i = 0; i < 32; i++)
            app(text, cap, &n, "0x%02x%s", keys[k][i], i == 31 ? "" : ", ");
        app(text, cap, &n, "},\n");
    }
    app(text, cap, &n, "};\n");
    return n;
}

/* ---- self-test ------------------------------------------------------------- */
static unsigned g_checks, g_fails;

static void check(int ok, const char *what)
{
    g_checks++;
    if (!ok) {
        g_fails++;
        printf("  FAIL: %s\n", what);
    }
}

static void expect_refused(const struct ck_slot_manifest *m, const uint8_t *img, uint64_t cap,
                           const uint8_t (*keys)[32], unsigned nkeys, const char *why, const char *what)
{
    struct ck_slot_eval ev;
    ck_slot_verify(m, img, cap, keys, nkeys, &ev);
    g_checks++;
    if (ev.valid || !ev.why || strcmp(ev.why, why) != 0) {
        g_fails++;
        printf("  FAIL: %s: valid=%d why=%s (expected %s)\n", what, ev.valid, ev.why ? ev.why : "(none)", why);
    }
}

static int selftest(void)
{
    uint8_t keys[MAX_KEYS][32];
    uint8_t pk[32];
    static uint8_t img[10000];
    struct ck_slot_manifest good, m;
    struct ck_slot_eval ev;
    const char *why;
    uint32_t x = 0x12345678u;

    for (size_t i = 0; i < sizeof img; i++) {
        x = x * 1664525u + 1013904223u;
        img[i] = (uint8_t)(x >> 24);
    }
    aienos_ed25519_public_key(pk, TEST1_SEED);
    check(memcmp(pk, TEST1_PK, 32) == 0, "TEST 1 public key derives from the seed");
    aienos_ed25519_public_key(pk, TEST2_SEED);
    check(memcmp(pk, TEST2_PK, 32) == 0, "TEST 2 public key derives from the seed");
    aienos_ed25519_public_key(pk, TEST1_SEED);
    memcpy(keys[0], TEST1_PK, 32);

    fill_manifest(&good, img, sizeof img, 7, 5, 3, "0123456789abcdef0123456789abcdef01234567",
                  "selftest build", 1760000000ull);
    check(ck_slot_manifest_check(&good, &why) == 0, "unsigned manifest is structurally valid");
    sign_manifest(&good, TEST1_SEED);
    check(ck_slot_verify(&good, img, sizeof img, keys, 1, &ev) == 1, "signed manifest verifies");
    check(ev.generation == 7 && ev.policy_generation == 5, "eval carries generation and policy");
    check(ck_slot_verify(&good, img, sizeof img + 4096, keys, 1, &ev) == 1, "larger capacity still verifies");

    /* Mutations: each must be refused with the named reason. */
#define MUT(stmt, why_s, what) do { m = good; stmt; expect_refused(&m, img, sizeof img, keys, 1, why_s, what); } while (0)
    MUT(m.magic[0] ^= 1, "bad magic", "magic");
    MUT(m.version = 2, "unsupported manifest version", "version");
    MUT(m.payload_kind = 2, "unsupported payload kind", "payload kind");
    MUT(m.loader_abi = 2, "loader ABI mismatch", "loader abi");
    MUT(m.kernel_abi = 2, "kernel ABI mismatch", "kernel abi");
    MUT(m.generation = 0, "generation is zero", "generation 0");
    MUT(m.policy_generation = 8, "policy_generation above generation", "policy above");
    MUT(m.min_rollback_generation = 8, "min_rollback_generation above generation", "rollback above");
    MUT(m.image_len = 0, "image_len is zero", "image_len 0");
    MUT(m.kernel_sha512[3] ^= 1, "kernel_sha512 differs from image_sha512 (payload kind 1)", "kernel digest");
    MUT(m.timestamp = 0, "timestamp is zero", "timestamp");
    MUT(m.flags = 1, "flags nonzero", "flags");
    MUT(m.reserved0 = 1, "reserved bytes nonzero", "reserved0");
    MUT(m.reserved1[50] = 1, "reserved bytes nonzero", "reserved1");
    MUT(m.pad[100] = 1, "pad nonzero", "pad");
    MUT(m.commit[5] = 'A', "commit is not 40 lower-case hex characters", "commit upper");
    MUT(m.commit[39] = 'g', "commit is not 40 lower-case hex characters", "commit non-hex");
    MUT(m.provenance[2] = 0x01, "provenance is not zero-padded printable ASCII", "provenance control char");
    MUT(m.provenance[63] = 'x', "provenance is not zero-padded printable ASCII", "provenance after terminator");
    MUT(m.image_len = sizeof img + 1, "image_len exceeds the slot capacity", "image_len over capacity");
    MUT(m.image_len = sizeof img - 1, "signature does not verify", "image_len changed under the signature");
    MUT(m.generation = 9, "signature does not verify", "generation changed under the signature");
    MUT(m.signer_id[0] ^= 1, "signer_id names no trusted key", "signer_id");
    MUT(m.signature[10] ^= 1, "signature does not verify", "signature byte");
    MUT(m.signature[63] ^= 0x80, "signature does not verify", "signature high bit");
    MUT(m.image_sha512[0] ^= 1; m.kernel_sha512[0] ^= 1, "signature does not verify", "image digest under the signature");
#undef MUT
    {
        static uint8_t img2[sizeof img];
        memcpy(img2, img, sizeof img);
        img2[sizeof img - 1] ^= 1;
        ck_slot_verify(&good, img2, sizeof img, keys, 1, &ev);
        check(!ev.valid && strcmp(ev.why, "image SHA-512 mismatch") == 0, "flipped image byte");
        ck_slot_verify(&good, img, sizeof img - 1, keys, 1, &ev);
        check(!ev.valid && strcmp(ev.why, "image_len exceeds the slot capacity") == 0, "capacity below image_len");
        memcpy(keys[1], TEST2_PK, 32);
        ck_slot_verify(&good, img, sizeof img, keys + 1, 1, &ev);
        check(!ev.valid && strcmp(ev.why, "signer_id names no trusted key") == 0, "wrong key set");
        ck_slot_verify(&good, img, sizeof img, keys, 0, &ev);
        check(!ev.valid && strcmp(ev.why, "signer_id names no trusted key") == 0, "empty key set");
        ck_slot_verify(&good, img, sizeof img, keys, 2, &ev);
        check(ev.valid, "two-key set containing the signer verifies");
        ck_slot_verify(&good, 0, sizeof img, keys, 1, &ev);
        check(!ev.valid && strcmp(ev.why, "no image bytes") == 0, "null image");
        /* A manifest signed by a key that is NOT in the set, but whose signer_id is forged
         * to name a trusted key, must fail on the signature, not pass. */
        m = good;
        {
            uint8_t other_seed[32];
            memset(other_seed, 0x42, 32);
            aienos_ed25519_sign(m.signature, (const uint8_t *)&m, CK_SLOT_TBS_BYTES, other_seed);
        }
        ck_slot_verify(&m, img, sizeof img, keys, 1, &ev);
        check(!ev.valid && strcmp(ev.why, "signature does not verify") == 0, "forged signer_id with another key");
    }

    /* Control record structure. */
    {
        struct ck_slot_control c, d;
        ck_slot_control_init(&c, 0);
        check(ck_slot_control_check(&c, &why) == 0, "fresh control is valid");
#define CMUT(stmt, why_s, what) do { d = c; stmt; g_checks++; if (ck_slot_control_check(&d, &why) == 0 || strcmp(why, why_s) != 0) { g_fails++; printf("  FAIL: control %s: %s\n", what, why ? why : "(accepted)"); } } while (0)
        CMUT(d.magic[7] ^= 1, "bad control magic", "magic");
        CMUT(d.version = 0, "unsupported control version", "version");
        CMUT(d.active_slot = 2, "active_slot out of range", "active range");
        CMUT(d.candidate_slot = 2, "candidate_slot out of range", "candidate range");
        CMUT(d.candidate_slot = 0, "candidate_slot equals active_slot", "candidate == active");
        CMUT(d.candidate_slot = 1; d.tries_remaining = 4, "tries_remaining above the bound", "tries bound");
        CMUT(d.tries_remaining = 1, "tries_remaining without a candidate", "tries without candidate");
        CMUT(d.flags = 2, "unknown control flags", "flags");
        CMUT(d.generation_floor = 5; d.last_good_generation = 4, "last_good_generation below the floor", "last_good < floor");
        CMUT(d.reserved[1000] = 1, "control reserved bytes nonzero", "reserved");
#undef CMUT
    }

    /* Selection rules. */
    {
        struct ck_slot_control c;
        struct ck_slot_eval e[2];
        struct ck_slot_decision dec;
#define EV(i, v, g) do { e[i].valid = (v); e[i].generation = (g); e[i].policy_generation = (g); e[i].why = 0; } while (0)
        EV(0, 1, 5); EV(1, 1, 7);
        ck_slot_select(0, e, &dec);
        check(dec.boot_slot == 1 && dec.reason == CK_SLOT_R_NO_CONTROL && !dec.loader_write, "no control: highest generation");
        EV(0, 1, 7); EV(1, 1, 7);
        ck_slot_select(0, e, &dec);
        check(dec.boot_slot == 0 && dec.reason == CK_SLOT_R_NO_CONTROL, "no control: tie goes to A");
        EV(0, 0, 0); EV(1, 0, 0);
        ck_slot_select(0, e, &dec);
        check(dec.boot_slot == -1 && dec.reason == CK_SLOT_R_RECOVERY_REQUIRED, "no control, nothing valid: recovery");
        ck_slot_control_init(&c, 0);
        c.magic[0] ^= 1;
        EV(0, 1, 5); EV(1, 1, 7);
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 1 && dec.reason == CK_SLOT_R_NO_CONTROL, "corrupt control is treated as absent");

        ck_slot_control_init(&c, 0);
        EV(0, 1, 5); EV(1, 1, 7);
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 0 && dec.reason == CK_SLOT_R_ACTIVE && !dec.loader_write, "active boots, no write");
        EV(0, 0, 0); EV(1, 1, 7);
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 1 && dec.reason == CK_SLOT_R_ACTIVE_INVALID_FALLBACK && !dec.loader_write, "active invalid: fallback to the other slot");
        EV(0, 0, 0); EV(1, 0, 0);
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == -1 && dec.reason == CK_SLOT_R_RECOVERY_REQUIRED, "both invalid: recovery");

        /* Candidate tries, bounded. */
        ck_slot_control_init(&c, 0);
        c.generation_floor = 3;
        c.last_good_generation = 5;
        check(ck_slot_stage_candidate(&c, 1, 7, &why) == 0 && c.tries_remaining == 3, "stage candidate B gen 7");
        EV(0, 1, 5); EV(1, 1, 7);
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 1 && dec.reason == CK_SLOT_R_CANDIDATE_TRY && dec.loader_write && dec.ctl_out.tries_remaining == 2, "candidate try 1: tries 3 -> 2, loader write");
        c = dec.ctl_out;
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 1 && dec.loader_write && dec.ctl_out.tries_remaining == 1, "candidate try 2");
        c = dec.ctl_out;
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 1 && dec.loader_write && dec.ctl_out.tries_remaining == 0, "candidate try 3");
        c = dec.ctl_out;
        check(ck_slot_control_check(&c, &why) == 0, "control with 0 tries and a candidate is valid");
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 0 && dec.reason == CK_SLOT_R_CANDIDATE_EXHAUSTED && !dec.loader_write, "tries exhausted: active boots, no write");
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 0 && dec.reason == CK_SLOT_R_CANDIDATE_EXHAUSTED, "exhausted again: deterministic, no loop");
        EV(0, 0, 0);
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == -1 && dec.reason == CK_SLOT_R_RECOVERY_REQUIRED, "exhausted candidate never boots on its own authority");
        EV(0, 1, 5); EV(1, 0, 0);
        c.tries_remaining = 3;
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 0 && dec.reason == CK_SLOT_R_CANDIDATE_INVALID && !dec.loader_write, "invalid candidate: active boots, tries untouched");
        check(c.tries_remaining == 3, "select never mutates its input");

        /* Floor. */
        ck_slot_control_init(&c, 0);
        c.generation_floor = 10;
        EV(0, 1, 5); EV(1, 1, 12);
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == 1 && dec.reason == CK_SLOT_R_ACTIVE_INVALID_FALLBACK, "active below the floor: fallback to B above it");
        EV(1, 1, 9);
        ck_slot_select(&c, e, &dec);
        check(dec.boot_slot == -1 && dec.reason == CK_SLOT_R_RECOVERY_REQUIRED, "both below the floor: recovery");
        check(ck_slot_stage_candidate(&c, 1, 9, &why) != 0 && strcmp(why, "candidate generation below the security floor") == 0, "stage below floor refused");
        check(ck_slot_stage_candidate(&c, 0, 12, &why) != 0 && strcmp(why, "cannot stage the active slot as a candidate") == 0, "stage active slot refused");
        check(ck_slot_stage_candidate(&c, 2, 12, &why) != 0, "stage slot 2 refused");
        c.last_good_generation = 12;
        check(ck_slot_stage_candidate(&c, 1, 12, &why) != 0 && strcmp(why, "candidate generation not above the last good generation") == 0, "stage not above last good refused");
        check(ck_slot_stage_candidate(&c, 1, 13, &why) == 0, "stage gen 13 accepted");

        /* Promotion. */
        check(ck_slot_promote(&c, 0, 13, 11, &why) != 0 && strcmp(why, "only the staged candidate can be promoted") == 0, "promote non-candidate refused");
        check(ck_slot_promote(&c, 1, 13, 14, &why) != 0 && strcmp(why, "policy_generation above generation") == 0, "promote with policy above generation refused");
        check(ck_slot_promote(&c, 1, 13, 11, &why) == 0, "promote candidate");
        check(c.active_slot == 1 && c.candidate_slot == CK_SLOT_NONE && c.tries_remaining == 0, "promotion flips active, clears candidate");
        check(c.generation_floor == 11 && c.last_good_generation == 13, "promotion raises the floor to policy_generation");
        check(ck_slot_stage_candidate(&c, 0, 14, &why) == 0 && ck_slot_promote(&c, 0, 14, 4, &why) == 0 && c.generation_floor == 11, "promotion never lowers the floor");
        check(ck_slot_control_check(&c, &why) == 0, "control valid after two promotions");
        check(ck_slot_abandon_candidate(&c, &why) != 0 && strcmp(why, "no candidate to abandon") == 0, "abandon without candidate refused");
        check(ck_slot_stage_candidate(&c, 1, 15, &why) == 0 && ck_slot_abandon_candidate(&c, &why) == 0, "abandon candidate");
        check(c.candidate_slot == CK_SLOT_NONE && c.tries_remaining == 0 && (c.flags & CK_SLOT_CTL_FLAG_CANDIDATE_FAILED), "abandon clears candidate, sets the failed flag");
        check(ck_slot_stage_candidate(&c, 1, 16, &why) == 0 && !(c.flags & CK_SLOT_CTL_FLAG_CANDIDATE_FAILED), "a new stage clears the failed flag");
        check(ck_slot_control_check(&c, &why) == 0, "control valid at the end of the transitions");
        check(strcmp(ck_slot_reason_text(CK_SLOT_R_RECOVERY_REQUIRED), "recovery_required") == 0, "reason text");
#undef EV
    }

    /* Torn-slot persistence of the control record over 512-byte blocks. */
    {
        static uint8_t media[CK_SLOT_CONTROL_UNITS * CK_SLOT_UNIT];
        struct filedev fd = {media, sizeof media};
        ts_device dev;
        ts_region r;
        uint8_t rec[TS_RECORD_BYTES];
        uint64_t seq;
        struct ck_slot_control c, back;
        memset(media, 0, sizeof media);
        bind_dev(&dev, &fd);
        check(ts_open(&r, &dev, 0) == TS_OK, "torn-slot region opens at LBA 0");
        check(ts_recover(&r, rec, &seq, 0) == TS_EMPTY, "blank region recovers EMPTY");
        ck_slot_control_init(&c, 0);
        c.generation_floor = 2;
        check(ts_commit(&r, (const uint8_t *)&c) == TS_OK, "commit control #1");
        check(ts_recover(&r, (uint8_t *)&back, &seq, 0) == TS_OK && memcmp(&back, &c, sizeof c) == 0 && seq == 1, "recover control #1");
        check(ck_slot_stage_candidate(&c, 1, 9, &why) == 0 && ts_commit(&r, (const uint8_t *)&c) == TS_OK, "commit control #2 (staged)");
        check(ts_recover(&r, (uint8_t *)&back, &seq, 0) == TS_OK && back.candidate_slot == 1 && seq == 2, "recover control #2");
        /* Torn write: the next target is the slot that does NOT hold seq 2.
         * Overwrite only the first 512 bytes of that body (as a power cut
         * after one block would) and make sure #2 still comes back. */
        {
            int target = r.newest_slot == 0 ? 1 : 0;
            uint8_t partial[512];
            memset(partial, 0xEE, sizeof partial);
            fd_write(&fd, (uint64_t)target * 2u * 8u, 1, partial);
            check(ts_recover(&r, (uint8_t *)&back, &seq, 0) == TS_OK && seq == 2 && back.candidate_slot == 1, "torn body: previous record still recovered");
        }
        check(ck_slot_control_check(&back, &why) == 0, "recovered control is structurally valid");
    }

    /* P11 cut 2b: the boot record SLOTLDR.EFI hands the kernel, and the pure
     * kernel decision over it (svc/slot_service.c). Every check that flips one
     * field must be refused; every scenario names the action and the record. */
    {
        static struct ck_slot_boot_record b, bm;
        static struct ck_slot_control c, out;
        static struct ck_slot_manifest man;
        enum ck_slot_action a;
        fill_manifest(&man, img, sizeof img, 9, 4, 0, "0123456789abcdef0123456789abcdef01234567",
                      "selftest candidate", 1760000000ull);
        memset(&b, 0, sizeof b);
        memcpy(b.magic, CK_SLOT_BOOT_MAGIC, 8);
        b.version = CK_SLOT_BOOT_VERSION;
        b.boot_slot = 1;
        b.reason = CK_SLOT_R_CANDIDATE_TRY;
        b.tries = 2;
        b.control_present = 1;
        b.control_seq = 5;
        b.generation = man.generation;
        b.policy_generation = man.policy_generation;
        memcpy(b.image_sha512, man.image_sha512, 64);
        memcpy(b.loader_commit, "0123456789abcdef0123456789abcdef01234567", 40);
        ck_slot_boot_seal(&b);
        check(ck_slot_boot_check(&b, &why) == 0, "boot record: sealed record is valid");
#define BM(stmt, want, what)                                                                        \
        do {                                                                                        \
            bm = b;                                                                                 \
            stmt;                                                                                   \
            ck_slot_boot_seal(&bm);                                                                 \
            check(ck_slot_boot_check(&bm, &why) != 0 && strcmp(why, want) == 0, "boot record: " what); \
        } while (0)
        bm = b;
        bm.tries ^= 1;
        check(ck_slot_boot_check(&bm, &why) != 0 && strcmp(why, "boot record digest mismatch") == 0,
              "boot record: one changed byte without a reseal refused (digest)");
        BM(bm.magic[0] ^= 1, "bad boot record magic", "bad magic refused");
        BM(bm.version = 2, "unsupported boot record version", "version 2 refused");
        BM(bm.boot_slot = 2, "boot record slot out of range", "slot 2 refused");
        BM(bm.reason = CK_SLOT_R_NONE, "boot record reason out of range", "reason none refused");
        BM(bm.reason = CK_SLOT_R_RECOVERY_REQUIRED, "boot record reason out of range", "reason recovery_required refused");
        BM(bm.control_present = 2, "boot record control flag out of range", "control flag 2 refused");
        BM(bm.tries = CK_SLOT_MAX_TRIES + 1, "boot record tries above the bound", "tries above the bound refused");
        BM(bm.generation = 0, "boot record generation fields", "generation 0 refused");
        BM(bm.policy_generation = bm.generation + 1, "boot record generation fields", "policy above generation refused");
        BM(bm.reserved[79] = 1, "boot record reserved bytes nonzero", "reserved byte refused");
        BM(bm.control_present = 0, "boot record claims a decision without a control record",
           "decision without control refused");
        BM(bm.reason = CK_SLOT_R_NO_CONTROL, "boot record claims no control with a control record",
           "no_control with a control record refused");
#undef BM

        /* Candidate B on its try, control still names it. */
        ck_slot_control_init(&c, 0);
        c.generation_floor = 1;
        check(ck_slot_stage_candidate(&c, 1, 9, &why) == 0, "kernel action: fixture staged");
        c.tries_remaining = 2;
        a = ck_slot_kernel_action(&b, &c, &man, 0, &out, &why);
        check(a == CK_SLOT_A_WAIT && strcmp(why, "health milestone not reached") == 0,
              "kernel action: candidate not healthy -> WAIT (nothing written)");
        a = ck_slot_kernel_action(&b, &c, &man, 1, &out, &why);
        check(a == CK_SLOT_A_PROMOTE && out.active_slot == 1 && out.candidate_slot == CK_SLOT_NONE &&
                  out.tries_remaining == 0 && out.generation_floor == 4 && out.last_good_generation == 9 &&
                  ck_slot_control_check(&out, &why) == 0,
              "kernel action: healthy candidate -> PROMOTE (active=B, floor=policy 4, last_good=9)");
        check(ck_slot_kernel_action(&b, 0, &man, 1, &out, &why) == CK_SLOT_A_REFUSE &&
                  strcmp(why, "no control record on disk") == 0,
              "kernel action: no control record -> REFUSE");
        out = c;
        out.version = 9;
        check(ck_slot_kernel_action(&b, &out, &man, 1, &out, &why) == CK_SLOT_A_REFUSE,
              "kernel action: corrupt control record -> REFUSE");
        check(ck_slot_kernel_action(&b, &c, 0, 1, &out, &why) == CK_SLOT_A_REFUSE &&
                  strcmp(why, "started slot's manifest unreadable") == 0,
              "kernel action: unreadable manifest -> REFUSE");
        m = man;
        m.image_sha512[0] ^= 1;
        m.kernel_sha512[0] ^= 1; /* v1: kernel_sha512 == image_sha512, so the manifest stays well formed */
        check(ck_slot_kernel_action(&b, &c, &m, 1, &out, &why) == CK_SLOT_A_REFUSE &&
                  strcmp(why, "started slot's manifest on disk differs from the boot record") == 0,
              "kernel action: manifest digest differs from the boot record -> REFUSE");
        m = man;
        m.generation = 10;
        check(ck_slot_kernel_action(&b, &c, &m, 1, &out, &why) == CK_SLOT_A_REFUSE,
              "kernel action: manifest generation differs from the boot record -> REFUSE");
        bm = b;
        bm.digest[0] ^= 1;
        check(ck_slot_kernel_action(&bm, &c, &man, 1, &out, &why) == CK_SLOT_A_REFUSE &&
                  strcmp(why, "boot record digest mismatch") == 0,
              "kernel action: damaged boot record -> REFUSE");
        out = c;
        out.candidate_slot = CK_SLOT_NONE;
        out.tries_remaining = 0;
        check(ck_slot_kernel_action(&b, &out, &man, 1, &out, &why) == CK_SLOT_A_NONE,
              "kernel action: control no longer names the started slot -> NONE");

        /* A booted because B ran out of tries / failed verification. */
        fill_manifest(&m, img, sizeof img, 3, 1, 0, "0123456789abcdef0123456789abcdef01234567", "selftest active",
                      1760000000ull);
        bm = b;
        bm.boot_slot = 0;
        bm.reason = CK_SLOT_R_CANDIDATE_EXHAUSTED;
        bm.tries = 0;
        bm.generation = 3;
        bm.policy_generation = 1;
        memcpy(bm.image_sha512, m.image_sha512, 64);
        ck_slot_boot_seal(&bm);
        c.tries_remaining = 0;
        a = ck_slot_kernel_action(&bm, &c, &m, 0, &out, &why);
        check(a == CK_SLOT_A_ABANDON && out.active_slot == 0 && out.candidate_slot == CK_SLOT_NONE &&
                  (out.flags & CK_SLOT_CTL_FLAG_CANDIDATE_FAILED) && out.generation_floor == 1 &&
                  ck_slot_control_check(&out, &why) == 0,
              "kernel action: exhausted candidate -> ABANDON (failed flag, active A stays, not gated on health)");
        bm.reason = CK_SLOT_R_CANDIDATE_INVALID;
        ck_slot_boot_seal(&bm);
        check(ck_slot_kernel_action(&bm, &c, &m, 1, &out, &why) == CK_SLOT_A_ABANDON,
              "kernel action: invalid candidate -> ABANDON");
        bm.reason = CK_SLOT_R_ACTIVE;
        ck_slot_boot_seal(&bm);
        check(ck_slot_kernel_action(&bm, &c, &m, 1, &out, &why) == CK_SLOT_A_NONE,
              "kernel action: steady active boot -> NONE");
        bm.reason = CK_SLOT_R_CANDIDATE_EXHAUSTED;
        bm.boot_slot = 1;
        memcpy(bm.image_sha512, man.image_sha512, 64);
        bm.generation = 9;
        bm.policy_generation = 4;
        ck_slot_boot_seal(&bm);
        check(ck_slot_kernel_action(&bm, &c, &man, 1, &out, &why) == CK_SLOT_A_NONE,
              "kernel action: exhausted reason on the non-active slot -> NONE (never abandons its own active)");
        check(strcmp(ck_slot_action_text(CK_SLOT_A_PROMOTE), "promote") == 0, "action text");
    }

    /* The shared control-commit routine: commit, read back, sequence. */
    {
        static uint8_t media[CK_SLOT_CONTROL_UNITS * CK_SLOT_UNIT];
        struct filedev fd = {media, sizeof media};
        ts_device dev;
        ts_region r;
        uint64_t seq = 0, s2 = 0;
        static struct ck_slot_control c, back;
        memset(media, 0, sizeof media);
        bind_dev(&dev, &fd);
        check(ts_open(&r, &dev, 0) == TS_OK && ts_recover(&r, (uint8_t *)&back, &seq, 0) == TS_EMPTY,
              "control commit: blank region");
        ck_slot_control_init(&c, 0);
        check(ck_slot_control_commit(&r, &c, &seq) == TS_OK && seq == 1, "control commit: first record seq 1");
        check(ck_slot_stage_candidate(&c, 1, 2, &why) == 0 && ck_slot_control_commit(&r, &c, &s2) == TS_OK && s2 == 2,
              "control commit: second record seq 2");
        check(ts_recover(&r, (uint8_t *)&back, &seq, 0) == TS_OK && seq == 2 && memcmp(&back, &c, sizeof c) == 0,
              "control commit: read back equals what was committed");
    }

    /* keys-c rendering: bounded, refuses instead of overflowing. */
    {
        static char kt[8192], small[sizeof kt];
        size_t full = keys_c_render(kt, sizeof kt, &TEST1_PK, 1, 1);
        check(full > 0 && full < sizeof kt && strstr(kt, "TEST-ONLY key") != 0, "keys-c: TEST key table renders");
        check(keys_c_render(small, full + 1, &TEST1_PK, 1, 1) == full && memcmp(small, kt, full) == 0,
              "keys-c: exact-fit buffer gives the same bytes");
        check(keys_c_render(small, full, &TEST1_PK, 1, 1) == full, "keys-c: one byte short is refused (length = cap)");
        check(keys_c_render(small, 64, &TEST1_PK, 1, 1) == 64, "keys-c: a 64-byte buffer is refused (length = cap)");
        memset(keys, 0x5a, sizeof keys);
        check(keys_c_render(small, 512, (const uint8_t (*)[32])keys, MAX_KEYS, 0) == 512,
              "keys-c: eight keys into 512 bytes refused, no write past the buffer");
    }

    printf("CK_SLOT_TOOL_SELFTEST: %s (%u checks, %u failures)\n", g_fails ? "FAIL" : "PASS", g_checks, g_fails);
    return g_fails ? 1 : 0;
}

/* ---- CLI ------------------------------------------------------------------- */
static int cmd_make_manifest(int argc, char **argv)
{
    const char *image = opt(argc, argv, "--image"), *out = opt(argc, argv, "--out");
    const char *commit = opt(argc, argv, "--commit"), *prov = opt(argc, argv, "--provenance");
    uint64_t gen, pol = 0, minrb = 0, ts = 1;
    uint8_t *img;
    size_t len;
    struct ck_slot_manifest m;
    const char *why;
    if (!image || !out || parse_u64(opt(argc, argv, "--generation"), &gen) != 0)
        return refuse("make-manifest needs --image, --generation and --out");
    if (opt(argc, argv, "--policy-generation") && parse_u64(opt(argc, argv, "--policy-generation"), &pol) != 0)
        return refuse("bad --policy-generation");
    if (opt(argc, argv, "--min-rollback") && parse_u64(opt(argc, argv, "--min-rollback"), &minrb) != 0)
        return refuse("bad --min-rollback");
    if (opt(argc, argv, "--timestamp") && parse_u64(opt(argc, argv, "--timestamp"), &ts) != 0)
        return refuse("bad --timestamp");
    if (!commit)
        commit = "0000000000000000000000000000000000000000";
    if (strlen(commit) != CK_SLOT_COMMIT_CHARS)
        return refuse("--commit must be 40 characters");
    if (!prov)
        prov = "unspecified";
    if (strlen(prov) > CK_SLOT_PROVENANCE_CHARS)
        return refuse("--provenance longer than 64 characters");
    if (read_file(image, &img, &len) != 0)
        return refuse("cannot read the image");
    if (len == 0)
        return refuse("image is empty");
    fill_manifest(&m, img, len, gen, pol, minrb, commit, prov, ts);
    free(img);
    if (ck_slot_manifest_check(&m, &why) != 0)
        return refuse(why);
    if (write_file(out, &m, sizeof m) != 0)
        return refuse("cannot write the manifest");
    print_manifest(&m);
    printf("manifest written (unsigned): %s\n", out);
    return 0;
}

static int load_manifest(const char *path, struct ck_slot_manifest *m)
{
    int rc = read_unit(path, m);
    if (rc == -1)
        return refuse("cannot read the manifest");
    if (rc == -2)
        return refuse("manifest is not exactly 4096 bytes");
    return 0;
}

static int cmd_show(int argc, char **argv)
{
    struct ck_slot_manifest m;
    const char *why;
    if (argc < 3)
        return refuse("show M");
    if (load_manifest(argv[2], &m) != 0)
        return 1;
    print_manifest(&m);
    if (ck_slot_manifest_check(&m, &why) != 0)
        return refuse(why);
    printf("structure: OK (signature not checked; use verify)\n");
    return 0;
}

static int cmd_tbs(int argc, char **argv)
{
    struct ck_slot_manifest m;
    const char *out = opt(argc, argv, "--out"), *pkh = opt(argc, argv, "--pubkey");
    uint8_t pk[32];
    if (argc < 3 || !out || !pkh)
        return refuse("tbs M --pubkey HEX64 --out F");
    if (load_manifest(argv[2], &m) != 0)
        return 1;
    if (parse_hex(pkh, pk, 32) != 0)
        return refuse("--pubkey is not 64 hex characters");
    if (is_test_key(pk))
        return refuse("--pubkey is a known TEST key");
    /* signer_id is inside the signed bytes [0, CK_SLOT_TBS_BYTES): attach-sig and
     * the loader check the signature over the manifest with signer_id set, so the
     * offline signer must sign those same bytes. */
    sha256_hash(pk, 32, m.signer_id);
    if (write_file(out, &m, CK_SLOT_TBS_BYTES) != 0)
        return refuse("cannot write the to-be-signed bytes");
    printf("tbs: %u bytes written to %s\n", CK_SLOT_TBS_BYTES, out);
    return 0;
}

static int cmd_sign_test(int argc, char **argv)
{
    struct ck_slot_manifest m;
    const char *out = opt(argc, argv, "--out");
    const char *why;
    if (argc < 3 || !out)
        return refuse("sign-test M --out M2");
    if (load_manifest(argv[2], &m) != 0)
        return 1;
    sign_manifest(&m, flag(argc, argv, "--test2") ? TEST2_SEED : TEST1_SEED);
    if (ck_slot_manifest_check(&m, &why) != 0)
        return refuse(why);
    if (write_file(out, &m, sizeof m) != 0)
        return refuse("cannot write the manifest");
    printf("signed with RFC 8032 TEST %d: tests only, NEVER for hardware (ck_owner_gen refuses this key)\n",
           flag(argc, argv, "--test2") ? 2 : 1);
    return 0;
}

static int cmd_attach_sig(int argc, char **argv)
{
    struct ck_slot_manifest m;
    const char *out = opt(argc, argv, "--out"), *sigf = opt(argc, argv, "--sig"), *pkh = opt(argc, argv, "--pubkey");
    uint8_t *sig, pk[32];
    size_t n;
    const char *why;
    if (argc < 3 || !out || !sigf || !pkh)
        return refuse("attach-sig M --sig SIG --out M2 --pubkey HEX64");
    if (load_manifest(argv[2], &m) != 0)
        return 1;
    if (parse_hex(pkh, pk, 32) != 0)
        return refuse("--pubkey is not 64 hex characters");
    if (is_test_key(pk))
        return refuse("--pubkey is a known TEST key");
    if (read_file(sigf, &sig, &n) != 0)
        return refuse("cannot read the signature");
    if (n != 64) {
        free(sig);
        return refuse("signature is not 64 bytes");
    }
    sha256_hash(pk, 32, m.signer_id);
    memcpy(m.signature, sig, 64);
    free(sig);
    if (aienos_ed25519_verify(m.signature, (const uint8_t *)&m, CK_SLOT_TBS_BYTES, pk) != AIENOS_SIG_OK)
        return refuse("signature does not verify under --pubkey over the manifest's to-be-signed bytes");
    if (ck_slot_manifest_check(&m, &why) != 0)
        return refuse(why);
    if (write_file(out, &m, sizeof m) != 0)
        return refuse("cannot write the manifest");
    printf("signature attached and verified: %s\n", out);
    return 0;
}

static uint64_t cap_opt(int argc, char **argv)
{
    uint64_t cap = DEFAULT_CAP;
    if (opt(argc, argv, "--cap") && parse_u64(opt(argc, argv, "--cap"), &cap) != 0)
        return 0;
    return cap;
}

static int cmd_verify(int argc, char **argv)
{
    struct ck_slot_manifest m;
    struct ck_slot_eval ev;
    uint8_t keys[MAX_KEYS][32];
    unsigned nkeys;
    uint8_t *img;
    size_t len;
    const char *image = opt(argc, argv, "--image");
    uint64_t cap = cap_opt(argc, argv);
    if (argc < 3 || !image || !cap)
        return refuse("verify M --image F (--keys FILE | --test-key) [--cap BYTES]");
    if (load_manifest(argv[2], &m) != 0)
        return 1;
    if (get_keys(argc, argv, keys, &nkeys) != 0)
        return 1;
    if (read_file(image, &img, &len) != 0)
        return refuse("cannot read the image");
    if (m.image_len != len) {
        free(img);
        return refuse("image file length differs from manifest image_len");
    }
    ck_slot_verify(&m, img, cap, keys, nkeys, &ev);
    free(img);
    print_manifest(&m);
    if (!ev.valid)
        return refuse(ev.why);
    printf("verify: OK generation=%llu\n", (unsigned long long)ev.generation);
    return 0;
}

static int load_control(const char *path, struct ck_slot_control *c)
{
    const char *why;
    int rc = read_unit(path, c);
    if (rc == -1)
        return refuse("cannot read the control record");
    if (rc == -2)
        return refuse("control record is not exactly 4096 bytes");
    if (ck_slot_control_check(c, &why) != 0)
        return refuse(why);
    return 0;
}

static int save_control(const char *path, const struct ck_slot_control *c)
{
    if (write_file(path, c, sizeof *c) != 0)
        return refuse("cannot write the control record");
    print_control(c);
    printf("control written: %s\n", path);
    return 0;
}

static int cmd_control_init(int argc, char **argv)
{
    struct ck_slot_control c;
    uint64_t active;
    const char *out = opt(argc, argv, "--out");
    if (!out || parse_u64(opt(argc, argv, "--active"), &active) != 0 || active > 1)
        return refuse("control-init --active 0|1 --out C");
    ck_slot_control_init(&c, (unsigned)active);
    return save_control(out, &c);
}

static int cmd_control_show(int argc, char **argv)
{
    struct ck_slot_control c;
    if (argc < 3)
        return refuse("control-show C");
    if (load_control(argv[2], &c) != 0)
        return 1;
    print_control(&c);
    return 0;
}

static int cmd_transition(int argc, char **argv, const char *which)
{
    struct ck_slot_control c;
    const char *out = opt(argc, argv, "--out"), *why = 0;
    uint64_t slot = 0, gen = 0, pol = 0;
    int rc;
    if (argc < 3 || !out)
        return refuse("needs the control file and --out");
    if (load_control(argv[2], &c) != 0)
        return 1;
    if (strcmp(which, "abandon") != 0) {
        if (parse_u64(opt(argc, argv, "--slot"), &slot) != 0 || parse_u64(opt(argc, argv, "--generation"), &gen) != 0)
            return refuse("needs --slot and --generation");
    }
    if (strcmp(which, "stage") == 0)
        rc = ck_slot_stage_candidate(&c, (unsigned)slot, gen, &why);
    else if (strcmp(which, "promote") == 0) {
        if (parse_u64(opt(argc, argv, "--policy-generation"), &pol) != 0)
            return refuse("promote needs --policy-generation");
        rc = ck_slot_promote(&c, (unsigned)slot, gen, pol, &why);
    } else
        rc = ck_slot_abandon_candidate(&c, &why);
    if (rc != 0)
        return refuse(why);
    return save_control(out, &c);
}

static int load_slot(const char *spec, uint64_t cap, const uint8_t (*keys)[32], unsigned nkeys,
                     struct ck_slot_eval *ev, const char *name)
{
    struct ck_slot_manifest m;
    uint8_t *img;
    size_t len;
    char path[1024];
    const char *comma;
    ev->valid = 0;
    ev->why = "absent";
    ev->generation = 0;
    ev->policy_generation = 0;
    if (!spec || strcmp(spec, "none") == 0)
        return 0;
    comma = strchr(spec, ',');
    if (!comma || (size_t)(comma - spec) >= sizeof path)
        return refuse("slot spec must be MANIFEST,IMAGE or none");
    memcpy(path, spec, (size_t)(comma - spec));
    path[comma - spec] = 0;
    if (read_unit(path, &m) != 0) {
        printf("slot %s: manifest unreadable or not 4096 bytes, treated as invalid\n", name);
        ev->why = "manifest unreadable";
        return 0;
    }
    if (read_file(comma + 1, &img, &len) != 0) {
        printf("slot %s: image unreadable, treated as invalid\n", name);
        ev->why = "image unreadable";
        return 0;
    }
    ck_slot_verify(&m, img, len < cap ? len : cap, keys, nkeys, ev);
    if (ev->valid && m.image_len != len) {
        ev->valid = 0;
        ev->why = "image file length differs from manifest image_len";
    }
    free(img);
    return 0;
}

static int cmd_select(int argc, char **argv)
{
    struct ck_slot_control c, *ctl = 0;
    struct ck_slot_eval ev[2];
    struct ck_slot_decision d;
    uint8_t keys[MAX_KEYS][32];
    unsigned nkeys;
    const char *cf = opt(argc, argv, "--control"), *out = opt(argc, argv, "--out");
    uint64_t cap = cap_opt(argc, argv);
    if (!cap || (!cf && !flag(argc, argv, "--no-control")))
        return refuse("select (--control C | --no-control) --a M,IMG|none --b M,IMG|none (--keys FILE | --test-key) [--cap BYTES] [--out C2]");
    if (get_keys(argc, argv, keys, &nkeys) != 0)
        return 1;
    if (cf) {
        const char *why;
        int rc = read_unit(cf, &c);
        if (rc == 0 && ck_slot_control_check(&c, &why) == 0)
            ctl = &c;
        else
            printf("control: unreadable or corrupt, treated as absent\n");
    }
    if (load_slot(opt(argc, argv, "--a"), cap, keys, nkeys, &ev[0], "A") != 0)
        return 1;
    if (load_slot(opt(argc, argv, "--b"), cap, keys, nkeys, &ev[1], "B") != 0)
        return 1;
    for (unsigned i = 0; i < 2; i++)
        printf("slot %c: %s%s%s generation=%llu\n", 'A' + i, ev[i].valid ? "valid" : "invalid",
               ev[i].valid ? "" : " (", ev[i].valid ? "" : ev[i].why, (unsigned long long)ev[i].generation);
    if (ctl)
        print_control(ctl);
    ck_slot_select(ctl, ev, &d);
    printf("decision: boot_slot=%s reason=%s loader_write=%d\n",
           d.boot_slot < 0 ? "none" : (d.boot_slot ? "B" : "A"), ck_slot_reason_text(d.reason), d.loader_write);
    if (d.loader_write) {
        print_control(&d.ctl_out);
        if (out && write_file(out, &d.ctl_out, sizeof d.ctl_out) != 0)
            return refuse("cannot write ctl_out");
    }
    return d.boot_slot < 0 ? 2 : 0;
}

static int cmd_control_commit(int argc, char **argv)
{
    const char *region = opt(argc, argv, "--region"), *recf = opt(argc, argv, "--record");
    struct ck_slot_control c;
    uint8_t *bytes;
    size_t len;
    struct filedev fd;
    ts_device dev;
    ts_region r;
    uint8_t rec[TS_RECORD_BYTES];
    uint64_t seq;
    int rc;
    if (!region || !recf)
        return refuse("control-commit --region F --record C");
    if (load_control(recf, &c) != 0)
        return 1;
    if (read_file(region, &bytes, &len) != 0)
        return refuse("cannot read the region file");
    if (len != CK_SLOT_CONTROL_UNITS * CK_SLOT_UNIT) {
        free(bytes);
        return refuse("region file must be exactly 4 units (16384 bytes)");
    }
    fd.bytes = bytes;
    fd.len = len;
    bind_dev(&dev, &fd);
    if (ts_open(&r, &dev, 0) != TS_OK)
        return refuse("torn-slot open failed");
    rc = ts_recover(&r, rec, &seq, 0);
    if (rc != TS_OK && rc != TS_EMPTY) {
        free(bytes);
        return refuse("region is corrupt or conflicting: fail closed, not committing");
    }
    if (ts_commit(&r, (const uint8_t *)&c) != TS_OK) {
        free(bytes);
        return refuse("torn-slot commit failed");
    }
    if (write_file(region, bytes, len) != 0) {
        free(bytes);
        return refuse("cannot write the region file");
    }
    free(bytes);
    printf("control committed: seq=%llu into %s\n", (unsigned long long)r.newest_seq, region);
    return 0;
}

static int cmd_control_recover(int argc, char **argv)
{
    const char *region = opt(argc, argv, "--region"), *out = opt(argc, argv, "--out");
    uint8_t *bytes;
    size_t len;
    struct filedev fd;
    ts_device dev;
    ts_region r;
    struct ck_slot_control c;
    uint64_t seq;
    ts_slot_state st[2];
    int rc;
    const char *why;
    if (!region)
        return refuse("control-recover --region F [--out C]");
    if (read_file(region, &bytes, &len) != 0)
        return refuse("cannot read the region file");
    if (len != CK_SLOT_CONTROL_UNITS * CK_SLOT_UNIT) {
        free(bytes);
        return refuse("region file must be exactly 4 units (16384 bytes)");
    }
    fd.bytes = bytes;
    fd.len = len;
    bind_dev(&dev, &fd);
    if (ts_open(&r, &dev, 0) != TS_OK)
        return refuse("torn-slot open failed");
    rc = ts_recover(&r, (uint8_t *)&c, &seq, st);
    free(bytes);
    printf("torn-slot: rc=%d slotA=%d slotB=%d\n", rc, (int)st[0], (int)st[1]);
    if (rc == TS_EMPTY) {
        printf("control: none committed (loader rule: no control)\n");
        return 2;
    }
    if (rc != TS_OK)
        return refuse("region is corrupt or conflicting");
    if (ck_slot_control_check(&c, &why) != 0)
        return refuse(why);
    printf("seq=%llu\n", (unsigned long long)seq);
    print_control(&c);
    if (out && write_file(out, &c, sizeof c) != 0)
        return refuse("cannot write the control record");
    return 0;
}

/* keys-c: the trusted-key table SLOTLDR.EFI is built with (native/kernel
 * Makefile slot-loader). --keys FILE takes owner keys (TEST keys refused by
 * load_keys); --test-key embeds RFC 8032 TEST 1 and a TEST-ONLY note that the
 * Makefile's slot loader checks look for. Writes F only when it changes. */
static int cmd_keys_c(int argc, char **argv)
{
    uint8_t keys[MAX_KEYS][32];
    unsigned nkeys = 0;
    const char *out = opt(argc, argv, "--out"), *kf = opt(argc, argv, "--keys"), *why;
    int test = flag(argc, argv, "--test-key");
    char text[8192];
    size_t n = 0;
    uint8_t *old;
    size_t oldn;
    if (!out || (test == !!kf))
        return refuse("keys-c (--keys FILE | --test-key) --out F.c");
    if (test) {
        memcpy(keys[0], TEST1_PK, 32);
        nkeys = 1;
    } else if (load_keys(kf, keys, &nkeys, &why) != 0) {
        return refuse(why);
    }
    n = keys_c_render(text, sizeof text, (const uint8_t (*)[32])keys, nkeys, test);
    if (n >= sizeof text)
        return refuse("key table too large");
    if (read_file(out, &old, &oldn) == 0) {
        int same = oldn == n && memcmp(old, text, n) == 0;
        free(old);
        if (same) {
            printf("keys-c: %u key(s), %s unchanged\n", nkeys, out);
            return 0;
        }
    }
    if (write_file(out, text, n) != 0)
        return refuse("cannot write the key table");
    printf("keys-c: %u key(s)%s written to %s\n", nkeys, test ? " (TEST-ONLY)" : "", out);
    return 0;
}

/* slots-image: write a slots partition's content into a disk image, at the
 * partition's LBAs, exactly where SLOTLDR.EFI reads it (slot_format.h
 * geometry): the control region (zeroed, then the record committed through
 * the torn-slot protocol when --control is given), and for each slot its
 * manifest unit and image (or a zero manifest unit when absent). Test and
 * provisioning tooling for the QEMU gate scripts/qemu_ck_slot_loader_test.sh.
 *   slots-image --disk IMG --bs 512|4096 --first LBA --last LBA
 *       [--a M,IMG] [--b M,IMG] [--control C]
 * Prints "slots: units=U cap_units=C image_cap=B control_off=O a_off=X b_off=Y"
 * (byte offsets in the disk image). */
static int put_slot(FILE *f, const char *spec, uint64_t off, uint64_t cap, const char *name)
{
    static uint8_t zero[CK_SLOT_UNIT];
    struct ck_slot_manifest m;
    uint8_t *img = 0;
    size_t len = 0;
    char path[1024];
    const char *comma;
    if (fseeko(f, (off_t)off, SEEK_SET) != 0)
        return refuse("seek failed");
    if (!spec) {
        if (fwrite(zero, 1, sizeof zero, f) != sizeof zero)
            return refuse("write failed");
        printf("slot %s: empty (zero manifest unit)\n", name);
        return 0;
    }
    comma = strchr(spec, ',');
    if (!comma || (size_t)(comma - spec) >= sizeof path)
        return refuse("slot spec must be MANIFEST,IMAGE");
    memcpy(path, spec, (size_t)(comma - spec));
    path[comma - spec] = 0;
    if (load_manifest(path, &m) != 0)
        return 1;
    if (read_file(comma + 1, &img, &len) != 0)
        return refuse("cannot read the slot image");
    if (len > cap) {
        free(img);
        return refuse("slot image larger than the slot capacity");
    }
    if (fwrite(&m, 1, sizeof m, f) != sizeof m || fwrite(img, 1, len, f) != len) {
        free(img);
        return refuse("write failed");
    }
    if (len % CK_SLOT_UNIT && fwrite(zero, 1, CK_SLOT_UNIT - len % CK_SLOT_UNIT, f) != CK_SLOT_UNIT - len % CK_SLOT_UNIT) {
        free(img);
        return refuse("write failed");
    }
    free(img);
    printf("slot %s: manifest + %zu image bytes\n", name, len);
    return 0;
}

static int cmd_slots_image(int argc, char **argv)
{
    const char *disk = opt(argc, argv, "--disk"), *cf = opt(argc, argv, "--control");
    uint64_t bsz, first, last;
    static uint8_t region[CK_SLOT_CONTROL_UNITS * CK_SLOT_UNIT];
    if (!disk || parse_u64(opt(argc, argv, "--bs"), &bsz) != 0 || (bsz != 512 && bsz != 4096) ||
        parse_u64(opt(argc, argv, "--first"), &first) != 0 || parse_u64(opt(argc, argv, "--last"), &last) != 0 ||
        last < first)
        return refuse("slots-image --disk IMG --bs 512|4096 --first LBA --last LBA [--a M,IMG] [--b M,IMG] [--control C]");
    uint64_t units = (last - first + 1) * bsz / CK_SLOT_UNIT, cap_units = ck_slot_cap_units(units);
    if (cap_units < CK_SLOT_MIN_CAP_UNITS)
        return refuse("partition too small for two slots");
    uint64_t base = first * bsz, cap = (cap_units - 1) * CK_SLOT_UNIT;
    uint64_t a_off = base + ck_slot_manifest_unit(0, cap_units) * CK_SLOT_UNIT;
    uint64_t b_off = base + ck_slot_manifest_unit(1, cap_units) * CK_SLOT_UNIT;
    memset(region, 0, sizeof region);
    if (cf) {
        struct ck_slot_control c;
        struct filedev fd = {region, sizeof region};
        ts_device dev;
        ts_region r;
        uint8_t rec[TS_RECORD_BYTES];
        uint64_t seq;
        if (load_control(cf, &c) != 0)
            return 1;
        bind_dev(&dev, &fd);
        if (ts_open(&r, &dev, 0) != TS_OK || ts_recover(&r, rec, &seq, 0) != TS_EMPTY ||
            ts_commit(&r, (const uint8_t *)&c) != TS_OK)
            return refuse("torn-slot commit into the fresh region failed");
        print_control(&c);
    }
    FILE *f = fopen(disk, "r+b");
    if (!f)
        return refuse("cannot open the disk image");
    if (fseeko(f, (off_t)base, SEEK_SET) != 0 || fwrite(region, 1, sizeof region, f) != sizeof region) {
        fclose(f);
        return refuse("control region write failed");
    }
    if (put_slot(f, opt(argc, argv, "--a"), a_off, cap, "A") != 0 ||
        put_slot(f, opt(argc, argv, "--b"), b_off, cap, "B") != 0) {
        fclose(f);
        return 1;
    }
    if (fclose(f) != 0)
        return refuse("disk image close failed");
    printf("slots: units=%llu cap_units=%llu image_cap=%llu control_off=%llu a_off=%llu b_off=%llu\n",
           (unsigned long long)units, (unsigned long long)cap_units, (unsigned long long)cap,
           (unsigned long long)base, (unsigned long long)a_off, (unsigned long long)b_off);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return refuse("no mode (see the header of ck_slot_tool.c)");
    if (strcmp(argv[1], "selftest") == 0)
        return selftest();
    if (strcmp(argv[1], "make-manifest") == 0)
        return cmd_make_manifest(argc, argv);
    if (strcmp(argv[1], "show") == 0)
        return cmd_show(argc, argv);
    if (strcmp(argv[1], "tbs") == 0)
        return cmd_tbs(argc, argv);
    if (strcmp(argv[1], "sign-test") == 0)
        return cmd_sign_test(argc, argv);
    if (strcmp(argv[1], "attach-sig") == 0)
        return cmd_attach_sig(argc, argv);
    if (strcmp(argv[1], "verify") == 0)
        return cmd_verify(argc, argv);
    if (strcmp(argv[1], "control-init") == 0)
        return cmd_control_init(argc, argv);
    if (strcmp(argv[1], "control-show") == 0)
        return cmd_control_show(argc, argv);
    if (strcmp(argv[1], "stage") == 0 || strcmp(argv[1], "promote") == 0 || strcmp(argv[1], "abandon") == 0)
        return cmd_transition(argc, argv, argv[1]);
    if (strcmp(argv[1], "select") == 0)
        return cmd_select(argc, argv);
    if (strcmp(argv[1], "control-commit") == 0)
        return cmd_control_commit(argc, argv);
    if (strcmp(argv[1], "keys-c") == 0)
        return cmd_keys_c(argc, argv);
    if (strcmp(argv[1], "slots-image") == 0)
        return cmd_slots_image(argc, argv);
    if (strcmp(argv[1], "control-recover") == 0)
        return cmd_control_recover(argc, argv);
    return refuse("unknown mode");
}
