/* ck_owner_gen.c -- build-time owner provisioning for the C kernel
 * hardware staging image (make full CK_HARDWARE_STAGING=1).
 *
 *   ck_owner_gen <owner pubkeys file> <machine id file> <out header>
 *
 * Reads owner PUBLIC material and the machine identity, checks format and
 * length, refuses every known TEST value, and writes a C header with the
 * bytes (no labels, no file names, no comments copied from the inputs).
 * Nothing secret is ever read here: the Store volume key K_vol is not public
 * material and has no build-time source (store_boot.c
 * ck_store_production_keys, BLOCKED_OPERATOR on the TRUST-1 key ceremony).
 *
 * Input format (both files): text lines "<name> <hex>"; '#' starts a comment
 * line; blank lines are ignored; every name must appear exactly once; any
 * other name is refused.
 *   owner pubkeys file:  owner_root_ed25519 <64 hex>   Owner Root public key
 *   machine id file:     machine_id <64 hex>           ARGUS machine id (32 B)
 *                        store_uuid <32 hex>           boot Store uuid (16 B)
 *
 * Refused values: all bytes equal (all zero included); the RFC 8032 section
 * 7.1 TEST 1/2/3 public keys; the TEST machine id (0xA1 then 31 zero bytes);
 * the TEST store uuid "AIEN-TEST-BOOT01". Exit 0 and "CK_OWNER_GEN: OK" on
 * success, else exit 1, "CK_OWNER_GEN: REFUSED <reason>" and no header.
 * Hosted tool; never part of an image. No outside libraries. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Known TEST values. RFC 8032 section 7.1 TEST 1 and TEST 2 equal
 * native/kernel/artifact/format.c cka_test1_pk / cka_test2_pk. */
static const uint8_t RFC8032_T1[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
static const uint8_t RFC8032_T2[32] = {
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c};
static const uint8_t RFC8032_T3[32] = {
    0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
    0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25};
static const uint8_t TEST_MACHINE[32] = {0xA1};
static const uint8_t TEST_UUID[16] = {'A', 'I', 'E', 'N', '-', 'T', 'E', 'S',
                                      'T', '-', 'B', 'O', 'O', 'T', '0', '1'};

typedef struct {
    const char *name;
    size_t len;
    uint8_t v[32];
    int seen;
} field;

static void refuse(const char *what, const char *why)
{
    printf("CK_OWNER_GEN: REFUSED %s: %s\n", what, why);
    exit(1);
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void parse(const char *path, field *f, size_t nf)
{
    FILE *fp = fopen(path, "r");
    if (!fp) refuse(path, "cannot open");
    char line[512];
    unsigned ln = 0;
    while (fgets(line, sizeof line, fp)) {
        ln++;
        size_t n = strlen(line);
        if (n == sizeof line - 1 && line[n - 1] != '\n') refuse(path, "line too long");
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t'))
            line[--n] = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') continue;
        char *name = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p) refuse(path, "line without a value");
        *p++ = 0;
        while (*p == ' ' || *p == '\t') p++;
        char *hex = p;
        field *t = 0;
        for (size_t i = 0; i < nf; i++)
            if (!strcmp(f[i].name, name)) t = &f[i];
        if (!t) {
            printf("CK_OWNER_GEN: REFUSED %s line %u: unknown name \"%.64s\"\n", path, ln, name);
            exit(1);
        }
        if (t->seen) refuse(t->name, "given twice");
        if (strlen(hex) != 2 * t->len) {
            printf("CK_OWNER_GEN: REFUSED %s: need exactly %zu hex digits, got %zu\n", t->name, 2 * t->len,
                   strlen(hex));
            exit(1);
        }
        for (size_t i = 0; i < t->len; i++) {
            int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) refuse(t->name, "not hex");
            t->v[i] = (uint8_t)(hi << 4 | lo);
        }
        t->seen = 1;
    }
    if (ferror(fp)) refuse(path, "read error");
    fclose(fp);
    for (size_t i = 0; i < nf; i++)
        if (!f[i].seen) refuse(f[i].name, "missing");
}

static void check_value(const field *t)
{
    size_t same = 1;
    while (same < t->len && t->v[same] == t->v[0]) same++;
    if (same == t->len) refuse(t->name, "all bytes equal (placeholder, not an identity)");
}

static void emit(FILE *o, const char *sym, const field *t)
{
    fprintf(o, "static const uint8_t %s[%zu] __attribute__((unused)) = {", sym, t->len);
    for (size_t i = 0; i < t->len; i++) fprintf(o, "%s0x%02x", i ? ", " : "", t->v[i]);
    fprintf(o, "};\n");
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: ck_owner_gen <owner pubkeys file> <machine id file> <out header>\n");
        return 2;
    }
    field own[1] = {{"owner_root_ed25519", 32, {0}, 0}};
    field mach[2] = {{"machine_id", 32, {0}, 0}, {"store_uuid", 16, {0}, 0}};
    parse(argv[1], own, 1);
    parse(argv[2], mach, 2);
    check_value(&own[0]);
    check_value(&mach[0]);
    check_value(&mach[1]);
    if (!memcmp(own[0].v, RFC8032_T1, 32) || !memcmp(own[0].v, RFC8032_T2, 32) || !memcmp(own[0].v, RFC8032_T3, 32))
        refuse("owner_root_ed25519", "is an RFC 8032 TEST public key");
    if (!memcmp(mach[0].v, TEST_MACHINE, 32)) refuse("machine_id", "is the TEST machine id (0xA1)");
    if (!memcmp(mach[1].v, TEST_UUID, 16)) refuse("store_uuid", "is the TEST store uuid");
    if (!memcmp(own[0].v, mach[0].v, 32)) refuse("machine_id", "equals the owner root public key");

    char tmp[4096];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", argv[3]) >= (int)sizeof tmp) refuse(argv[3], "path too long");
    FILE *o = fopen(tmp, "w");
    if (!o) refuse(argv[3], "cannot write");
    fprintf(o, "/* Generated by native/kernel/tools/ck_owner_gen.c. Do not edit or commit. */\n"
               "#ifndef AIENOS_CK_OWNER_PROV_H\n#define AIENOS_CK_OWNER_PROV_H\n#include <stdint.h>\n"
               "#define CK_OWNER_PROVISIONED 1\n");
    emit(o, "ck_owner_root_pk", &own[0]);
    emit(o, "ck_owner_machine_id", &mach[0]);
    emit(o, "ck_owner_store_uuid", &mach[1]);
    fprintf(o, "#endif\n");
    if (fclose(o) || rename(tmp, argv[3])) {
        remove(tmp);
        refuse(argv[3], "cannot write");
    }
    printf("CK_OWNER_GEN: OK %s\n", argv[3]);
    return 0;
}
