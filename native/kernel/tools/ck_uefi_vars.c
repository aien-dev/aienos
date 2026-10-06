/* ck_uefi_vars -- host reader for an edk2 (AAVMF/OVMF) variable store file,
 * used by scripts/qemu_ck_rollback_test.sh (CK gate M0_ROLLBACK). It reads
 * the vars.fd a QEMU run left behind and prints the boot variables the
 * firmware itself holds, so the rollback checks do not depend on what a guest
 * program printed. Hosted C, test tooling only, never part of an image.
 * Read-only: the file is opened "rb" and never written.
 *
 *   ck_uefi_vars VARS.fd       print the live boot variables (below)
 *   ck_uefi_vars --self-test   parse synthetic stores; exit 0 only if every
 *                              case gives the expected answer
 *
 * Output (one line each, stable order, for diffing between boots):
 *   uefi_vars: store=authenticated|plain live=<n> obsolete=<n>
 *   BootOrder=<hex16,hex16,...>|absent
 *   BootNext=<hex16>|absent
 *   Boot<XXXX>=<description>        one per live Boot#### option, ascending
 * Exit 0 on success, 2 when the file is not a healthy edk2 variable store.
 *
 * Layout source (read, not recalled): edk2 tag edk2-stable202402 (the
 * firmware here is Ubuntu qemu-efi-aarch64 2024.02-2ubuntu0.9),
 * MdeModulePkg/Include/Guid/VariableFormat.h: VARIABLE_STORE_HEADER (GUID
 * signature, UINT32 Size, UINT8 Format 0x5a, UINT8 State 0xfe, UINT16, UINT32
 * = 28 bytes), VARIABLE_HEADER (32 bytes) and AUTHENTICATED_VARIABLE_HEADER
 * (60 bytes), StartId 0x55AA, State VAR_ADDED 0x3f / VAR_IN_DELETED_TRANSITION
 * 0xfe / VAR_DELETED 0xfd / VAR_HEADER_VALID_ONLY 0x7f, HEADER_ALIGNMENT 4,
 * name and data unpadded (ALIGNMENT 1). Store start: the firmware volume
 * header's HeaderLength (MdePkg/Include/Pi/PiFirmwareVolume.h, UINT16 at
 * offset 48, signature "_FVH" at offset 40). Which copy is live:
 * MdeModulePkg/Universal/Variable/RuntimeDxe/VariableParsing.c FindVariableEx
 * (State VAR_ADDED wins; a State VAR_ADDED & VAR_IN_DELETED_TRANSITION copy is
 * used only when no VAR_ADDED copy exists). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VARIABLE_DATA 0x55AAu
#define VAR_ADDED 0x3fu
#define VAR_IN_DELETED_TRANSITION 0xfeu
#define VAR_HEADER_VALID_ONLY 0x7fu
#define VAR_LIVE_IN_TRANSITION (VAR_ADDED & VAR_IN_DELETED_TRANSITION) /* 0x3e */
#define STORE_FORMATTED 0x5au
#define STORE_HEALTHY 0xfeu
#define STORE_HDR 28u
#define PLAIN_HDR 32u
#define AUTH_HDR 60u
#define MAX_VARS 4096

/* EFI_VARIABLE_GUID ddcf3616-3275-4164-98b6-fe85707ffe7d and
 * EFI_AUTHENTICATED_VARIABLE_GUID aaf32c78-947b-439a-a180-2e144ec37792, as
 * the bytes stored on flash (first three fields little-endian). */
static const uint8_t plain_sig[16] = {0x16, 0x36, 0xcf, 0xdd, 0x75, 0x32, 0x64, 0x41,
                                      0x98, 0xb6, 0xfe, 0x85, 0x70, 0x7f, 0xfe, 0x7d};
static const uint8_t auth_sig[16] = {0x78, 0x2c, 0xf3, 0xaa, 0x7b, 0x94, 0x9a, 0x43,
                                     0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92};
/* EFI_GLOBAL_VARIABLE 8be4df61-93ca-11d2-aa0d-00e098032b8c (UEFI spec 3.3). */
static const uint8_t global_guid[16] = {0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
                                        0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c};

struct var {
    uint8_t state;
    uint8_t guid[16];
    char name[64]; /* ASCII copy of the UCS-2 name; '?' for non-ASCII */
    const uint8_t *data;
    uint32_t data_size;
    int superseded;
};

struct store {
    int authenticated;
    unsigned live, obsolete, nvars;
    struct var v[MAX_VARS];
};

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)rd16(p) | (uint32_t)rd16(p + 2) << 16; }

/* Returns 0 and fills *s, or -1 with a reason on stderr. */
static int parse(const uint8_t *img, size_t len, struct store *s)
{
    memset(s, 0, sizeof *s);
    if (len < 64 || memcmp(img + 40, "_FVH", 4) != 0) {
        fprintf(stderr, "ck_uefi_vars: no firmware volume header (_FVH at offset 40)\n");
        return -1;
    }
    size_t base = rd16(img + 48);
    if (base < 56 || base + STORE_HDR > len) {
        fprintf(stderr, "ck_uefi_vars: bad FV HeaderLength %zu\n", base);
        return -1;
    }
    const uint8_t *sh = img + base;
    if (memcmp(sh, auth_sig, 16) == 0)
        s->authenticated = 1;
    else if (memcmp(sh, plain_sig, 16) != 0) {
        fprintf(stderr, "ck_uefi_vars: unknown variable store signature\n");
        return -1;
    }
    uint32_t size = rd32(sh + 16);
    if (sh[20] != STORE_FORMATTED || sh[21] != STORE_HEALTHY) {
        fprintf(stderr, "ck_uefi_vars: store not formatted/healthy (format=0x%02x state=0x%02x)\n",
                sh[20], sh[21]);
        return -1;
    }
    if (size < STORE_HDR || base + size > len) {
        fprintf(stderr, "ck_uefi_vars: store size %u exceeds file\n", size);
        return -1;
    }
    size_t end = base + size, hdr = s->authenticated ? AUTH_HDR : PLAIN_HDR;
    size_t off = (base + STORE_HDR + 3) & ~(size_t)3;
    while (off + hdr <= end && rd16(img + off) == VARIABLE_DATA) {
        const uint8_t *h = img + off;
        uint32_t name_size = rd32(h + hdr - 24), data_size = rd32(h + hdr - 20);
        const uint8_t *guid = h + hdr - 16;
        if (name_size > end - off - hdr || data_size > end - off - hdr - name_size) {
            fprintf(stderr, "ck_uefi_vars: variable at 0x%zx runs past the store\n", off);
            return -1;
        }
        if (s->nvars == MAX_VARS) {
            fprintf(stderr, "ck_uefi_vars: more than %d variables\n", MAX_VARS);
            return -1;
        }
        struct var *v = &s->v[s->nvars++];
        v->state = h[2];
        memcpy(v->guid, guid, 16);
        size_t n = 0;
        for (uint32_t i = 0; i + 1 < name_size && n < sizeof v->name - 1; i += 2) {
            uint16_t c = rd16(h + hdr + i);
            if (!c)
                break;
            v->name[n++] = c < 0x80 ? (char)c : '?';
        }
        v->name[n] = 0;
        v->data = h + hdr + name_size;
        v->data_size = data_size;
        off = (off + hdr + name_size + data_size + 3) & ~(size_t)3;
    }
    /* FindVariableEx: VAR_ADDED wins over an in-deleted-transition copy. */
    for (unsigned i = 0; i < s->nvars; i++) {
        struct var *a = &s->v[i];
        if (a->state != VAR_LIVE_IN_TRANSITION)
            continue;
        for (unsigned j = 0; j < s->nvars; j++)
            if (s->v[j].state == VAR_ADDED && !strcmp(s->v[j].name, a->name) &&
                !memcmp(s->v[j].guid, a->guid, 16))
                a->superseded = 1;
    }
    for (unsigned i = 0; i < s->nvars; i++) {
        struct var *a = &s->v[i];
        int live = a->state == VAR_ADDED || (a->state == VAR_LIVE_IN_TRANSITION && !a->superseded);
        if (live)
            s->live++;
        else
            s->obsolete++;
        a->superseded = !live; /* reuse: 1 = not live */
    }
    return 0;
}

static const struct var *find_global(const struct store *s, const char *name)
{
    for (unsigned i = 0; i < s->nvars; i++)
        if (!s->v[i].superseded && !memcmp(s->v[i].guid, global_guid, 16) &&
            !strcmp(s->v[i].name, name))
            return &s->v[i];
    return NULL;
}

static int is_boot_option(const char *n)
{
    if (strncmp(n, "Boot", 4) || strlen(n) != 8)
        return 0;
    for (int i = 4; i < 8; i++)
        if (!((n[i] >= '0' && n[i] <= '9') || (n[i] >= 'A' && n[i] <= 'F')))
            return 0;
    return 1;
}

static void report(const struct store *s, FILE *o)
{
    fprintf(o, "uefi_vars: store=%s live=%u obsolete=%u\n", s->authenticated ? "authenticated" : "plain",
            s->live, s->obsolete);
    const struct var *bo = find_global(s, "BootOrder");
    if (!bo)
        fprintf(o, "BootOrder=absent\n");
    else {
        fprintf(o, "BootOrder=");
        for (uint32_t i = 0; i + 1 < bo->data_size; i += 2)
            fprintf(o, "%s%04X", i ? "," : "", rd16(bo->data + i));
        fprintf(o, "%s\n", bo->data_size % 2 ? " (odd size)" : "");
    }
    const struct var *bn = find_global(s, "BootNext");
    if (!bn)
        fprintf(o, "BootNext=absent\n");
    else if (bn->data_size != 2)
        fprintf(o, "BootNext=bad-size-%u\n", bn->data_size);
    else
        fprintf(o, "BootNext=%04X\n", rd16(bn->data));
    /* Boot#### options in ascending name order. EFI_LOAD_OPTION: UINT32
     * Attributes, UINT16 FilePathListLength, CHAR16 Description[] (UEFI 3.1.3). */
    const char *prev = "";
    for (;;) {
        const struct var *next = NULL;
        for (unsigned i = 0; i < s->nvars; i++) {
            const struct var *v = &s->v[i];
            if (v->superseded || memcmp(v->guid, global_guid, 16) || !is_boot_option(v->name))
                continue;
            if (strcmp(v->name, prev) > 0 && (!next || strcmp(v->name, next->name) < 0))
                next = v;
        }
        if (!next)
            break;
        char desc[80];
        size_t n = 0;
        for (uint32_t i = 6; i + 1 < next->data_size && n < sizeof desc - 1; i += 2) {
            uint16_t c = rd16(next->data + i);
            if (!c)
                break;
            desc[n++] = c >= 0x20 && c < 0x7f ? (char)c : '?';
        }
        desc[n] = 0;
        fprintf(o, "%s=%s\n", next->name, desc);
        prev = next->name;
    }
}

/* ---- self-test: synthetic stores ---- */

static uint8_t *t_img;
static size_t t_off;

static void t_begin(int auth)
{
    memset(t_img, 0xff, 8192);
    memset(t_img, 0, 72);
    memcpy(t_img + 40, "_FVH", 4);
    t_img[48] = 72;
    memcpy(t_img + 72, auth ? auth_sig : plain_sig, 16);
    uint32_t size = 8192 - 72;
    memcpy(t_img + 88, &size, 4);
    t_img[92] = STORE_FORMATTED;
    t_img[93] = STORE_HEALTHY;
    memset(t_img + 94, 0, 6);
    t_off = 100;
}

static void t_var(int auth, uint8_t state, const char *name, const void *data, uint32_t dsize)
{
    size_t hdr = auth ? AUTH_HDR : PLAIN_HDR;
    uint8_t *h = t_img + t_off;
    memset(h, 0, hdr);
    h[0] = 0xaa;
    h[1] = 0x55;
    h[2] = state;
    h[4] = 7;
    uint32_t nsize = (uint32_t)(strlen(name) + 1) * 2;
    memcpy(h + hdr - 24, &nsize, 4);
    memcpy(h + hdr - 20, &dsize, 4);
    memcpy(h + hdr - 16, global_guid, 16);
    for (size_t i = 0; i <= strlen(name); i++) {
        h[hdr + 2 * i] = (uint8_t)name[i];
        h[hdr + 2 * i + 1] = 0;
    }
    memcpy(h + hdr + nsize, data, dsize);
    t_off = (t_off + hdr + nsize + dsize + 3) & ~(size_t)3;
}

static int t_expect(const char *label, const char *want_line, int want_present)
{
    static struct store s;
    char buf[4096];
    FILE *m = fmemopen(buf, sizeof buf, "w");
    int rc = parse(t_img, 8192, &s);
    if (rc == 0)
        report(&s, m);
    fclose(m);
    if (rc != 0) {
        printf("%s  %s (parse refused)\n", want_line ? "FAIL" : "PASS", label);
        return want_line ? 1 : 0;
    }
    if (!want_line) {
        printf("FAIL  %s (parse accepted a bad store)\n", label);
        return 1;
    }
    char needle[128];
    snprintf(needle, sizeof needle, "%s\n", want_line);
    int got = strstr(buf, needle) != NULL;
    printf("%s  %s\n", got == want_present ? "PASS" : "FAIL", label);
    return got != want_present;
}

static int self_test(void)
{
    static uint8_t img[8192];
    t_img = img;
    int bad = 0;
    const uint8_t order1[2] = {0x01, 0x00}, next0[2] = {0x00, 0x00}, order21[4] = {2, 0, 1, 0};
    uint8_t opt[6 + 2 * 17] = {1, 0, 0, 0, 0, 0};
    const char *d = "AIENOS Candidate";
    for (size_t i = 0; i <= strlen(d); i++)
        opt[6 + 2 * i] = (uint8_t)d[i];

    for (int auth = 0; auth <= 1; auth++) {
        t_begin(auth);
        t_var(auth, VAR_ADDED, "BootOrder", order1, 2);
        t_var(auth, VAR_ADDED, "BootNext", next0, 2);
        t_var(auth, VAR_ADDED, "Boot0000", opt, sizeof opt);
        bad |= t_expect(auth ? "auth: staged BootNext read" : "plain: staged BootNext read", "BootNext=0000", 1);
        bad |= t_expect("staged BootOrder read", "BootOrder=0001", 1);
        bad |= t_expect("Boot0000 description read", "Boot0000=AIENOS Candidate", 1);
    }
    /* The firmware deletes BootNext: the old header goes to VAR_DELETED. */
    t_begin(1);
    t_var(1, VAR_ADDED, "BootOrder", order1, 2);
    t_var(1, 0xfd, "BootNext", next0, 2);
    bad |= t_expect("deleted BootNext is absent", "BootNext=absent", 1);
    bad |= t_expect("deleted BootNext is not reported present", "BootNext=0000", 0);
    /* A header-only (interrupted add) BootNext is not live. */
    t_begin(1);
    t_var(1, VAR_HEADER_VALID_ONLY, "BootNext", next0, 2);
    bad |= t_expect("header-valid-only BootNext is absent", "BootNext=absent", 1);
    /* An in-deleted-transition copy is live while no newer copy exists. */
    t_begin(1);
    t_var(1, VAR_LIVE_IN_TRANSITION, "BootNext", next0, 2);
    bad |= t_expect("in-transition BootNext with no newer copy is live", "BootNext=0000", 1);
    /* BootOrder rewritten: the old copy in transition, the new one added. */
    t_begin(1);
    t_var(1, VAR_LIVE_IN_TRANSITION, "BootOrder", order1, 2);
    t_var(1, VAR_ADDED, "BootOrder", order21, 4);
    bad |= t_expect("newer BootOrder wins over the in-transition copy", "BootOrder=0002,0001", 1);
    bad |= t_expect("old BootOrder copy is not reported", "BootOrder=0001", 0);
    /* Nothing written yet. */
    t_begin(1);
    bad |= t_expect("empty store: BootOrder absent", "BootOrder=absent", 1);
    bad |= t_expect("empty store: BootNext absent", "BootNext=absent", 1);
    /* Refusals. */
    t_begin(1);
    t_img[93] = 0x00;
    bad |= t_expect("unhealthy store refused", NULL, 0);
    t_begin(1);
    t_img[72] ^= 1;
    bad |= t_expect("unknown store signature refused", NULL, 0);
    t_begin(1);
    memcpy(t_img + 40, "_FVX", 4);
    bad |= t_expect("missing _FVH refused", NULL, 0);
    t_begin(1);
    t_var(1, VAR_ADDED, "BootNext", next0, 2);
    uint32_t huge = 0x10000;
    memcpy(t_img + 100 + AUTH_HDR - 20, &huge, 4);
    bad |= t_expect("variable running past the store refused", NULL, 0);
    printf("CK_UEFI_VARS_SELF_TEST: %s\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--self-test"))
        return self_test();
    if (argc != 2 || argv[1][0] == '-') {
        fprintf(stderr, "usage: ck_uefi_vars VARS.fd | --self-test\n");
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 2;
    }
    size_t cap = 1u << 20, len = 0;
    uint8_t *img = malloc(cap);
    size_t n;
    while (img && (n = fread(img + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            uint8_t *bigger = realloc(img, cap * 2);
            if (!bigger) {
                free(img);
                img = NULL;
                break;
            }
            img = bigger;
            cap *= 2;
        }
    }
    fclose(f);
    if (!img) {
        fprintf(stderr, "ck_uefi_vars: out of memory\n");
        return 2;
    }
    static struct store s;
    int rc = parse(img, len, &s);
    if (rc == 0)
        report(&s, stdout);
    free(img);
    return rc == 0 ? 0 : 2;
}
