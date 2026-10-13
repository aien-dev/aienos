/* test_artifact_card.c -- core/artifact_card.c: the card artifact bundle of the EL0 artifact qualification image
 * (CK_ARTIFACT_CARD, PI5-7 cut 3). The parser is strict (magic, count, name bytes, uniqueness, lengths, exact
 * end of file) and a refused file leaves nothing behind for the loader. The layout is the one
 * tools/ck_artifact_tool.c "bundle" writes: "AIENBND\0", u32 count, count x {u16 name_len, name, u32 len, bytes}. */
#include <string.h>
#include "ck_test.h"
#include "artifact_card.h"

static size_t put(uint8_t *b, size_t at, const char *name, uint32_t len, uint8_t fill)
{
    size_t nl = strlen(name);
    b[at] = (uint8_t)nl;
    b[at + 1] = (uint8_t)(nl >> 8);
    memcpy(b + at + 2, name, nl);
    at += 2 + nl;
    b[at] = (uint8_t)len;
    b[at + 1] = (uint8_t)(len >> 8);
    b[at + 2] = (uint8_t)(len >> 16);
    b[at + 3] = (uint8_t)(len >> 24);
    memset(b + at + 4, fill, len);
    return at + 4 + len;
}

static size_t head(uint8_t *b, uint32_t count)
{
    memset(b, 0, 12);
    memcpy(b, "AIENBND", 8);
    b[8] = (uint8_t)count;
    b[9] = (uint8_t)(count >> 8);
    return 12;
}

static int refused(const uint8_t *b, size_t n, const char *want)
{
    struct ck_acard o;
    const char *why = 0;
    int rc = ck_acard_parse(b, n, &o, &why);
    int clean = o.count == 0 && o.e[0].name[0] == 0 && o.e[0].bytes == 0 && o.e[0].len == 0;
    return rc != 0 && why && strstr(why, want) != 0 && clean;
}

int main(void)
{
    static uint8_t b[CK_ACARD_FILE_MAX + 64];
    struct ck_acard o;
    const char *why = (const char *)1;
    size_t n;

    /* a well formed two-entry bundle */
    n = head(b, 2);
    n = put(b, n, "P25EXEC.AIEN", 100, 0xa1);
    n = put(b, n, "P25TAMP.AIEN", 7, 0xb2);
    CHECK(ck_acard_parse(b, n, &o, &why) == 0);
    CHECK(why == 0 && o.count == 2);
    CHECK(strcmp(o.e[0].name, "P25EXEC.AIEN") == 0 && o.e[0].len == 100 && o.e[0].bytes[0] == 0xa1 && o.e[0].bytes[99] == 0xa1);
    CHECK(strcmp(o.e[1].name, "P25TAMP.AIEN") == 0 && o.e[1].len == 7 && o.e[1].bytes == b + (n - 7));
    /* entry bytes are offered in place, never copied or reordered */
    CHECK(o.e[0].bytes + 100 + 2 + 12 + 4 == o.e[1].bytes);

    /* one-byte exact-end rule: a trailing byte is refused */
    b[n] = 0;
    CHECK(refused(b, n + 1, "bytes after the last entry"));
    /* a missing last byte is refused */
    CHECK(refused(b, n - 1, "past the end"));

    /* header */
    n = head(b, 1);
    n = put(b, n, "A", 4, 1);
    CHECK(ck_acard_parse(b, n, &o, &why) == 0);
    CHECK(refused(b, 11, "file size"));
    CHECK(refused(b, 0, "file size"));
    CHECK(ck_acard_parse(0, 12, &o, &why) != 0);
    CHECK(ck_acard_parse(b, n, 0, &why) != 0);
    b[0] = 'X';
    CHECK(refused(b, n, "bad magic"));
    b[0] = 'A';
    b[7] = 1; /* the NUL after AIENBND */
    CHECK(refused(b, n, "bad magic"));
    b[7] = 0;
    b[8] = 0;
    CHECK(refused(b, n, "entry count"));
    b[8] = 17;
    CHECK(refused(b, n, "entry count"));
    b[8] = 2; /* promises a second entry that is not there */
    CHECK(refused(b, n, "truncated"));
    b[8] = 1;
    b[11] = 1; /* count above 16 through the high bytes */
    CHECK(refused(b, n, "entry count"));
    b[11] = 0;

    /* names */
    n = head(b, 1);
    n = put(b, n, "", 4, 1);
    CHECK(refused(b, n, "name length"));
    n = head(b, 1);
    n = put(b, n, "123456789012345678901234567890123", 4, 1); /* 33 */
    CHECK(refused(b, n, "name length"));
    n = head(b, 1);
    n = put(b, n, "123456789012345678901234567890AB", 4, 1); /* 32 is fine */
    CHECK(ck_acard_parse(b, n, &o, &why) == 0 && strlen(o.e[0].name) == 32);
    n = head(b, 1);
    n = put(b, n, "A B", 4, 1);
    CHECK(refused(b, n, "printable"));
    n = head(b, 1);
    n = put(b, n, "A\x7f", 4, 1);
    CHECK(refused(b, n, "printable"));
    n = head(b, 2);
    n = put(b, n, "SAME", 4, 1);
    n = put(b, n, "SAME", 5, 2);
    CHECK(refused(b, n, "duplicate"));
    n = head(b, 2);
    n = put(b, n, "SAME", 4, 1);
    n = put(b, n, "SAMEX", 5, 2); /* a name that only starts like an earlier one is not a duplicate */
    CHECK(ck_acard_parse(b, n, &o, &why) == 0 && o.count == 2);

    /* lengths */
    n = head(b, 1);
    n = put(b, n, "A", 1, 9);
    CHECK(ck_acard_parse(b, n, &o, &why) == 0 && o.e[0].len == 1);
    n = head(b, 1);
    n = put(b, n, "A", 0, 9);
    CHECK(refused(b, n, "artifact length"));
    n = head(b, 1);
    n = put(b, n, "A", 4, 9);
    b[2 + 12 + 1] = 0xff;
    b[2 + 12 + 2] = 0xff;
    b[2 + 12 + 3] = 0xff;
    b[2 + 12 + 4] = 0xff; /* length 0xffffffff */
    CHECK(refused(b, n, "artifact length"));
    n = head(b, 1);
    n = put(b, n, "A", 40, 9);
    b[2 + 12 + 1] = 41; /* promises one byte more than the file holds */
    CHECK(refused(b, n, "past the end"));

    /* limits: 16 entries pass, a file of exactly the maximum size passes, one byte more is refused */
    n = head(b, 16);
    for (int i = 0; i < 16; i++) {
        char nm[4] = {'E', (char)('A' + i), 0, 0};
        n = put(b, n, nm, 3, (uint8_t)i);
    }
    CHECK(ck_acard_parse(b, n, &o, &why) == 0 && o.count == 16 && strcmp(o.e[15].name, "EP") == 0);
    n = head(b, 1);
    n = put(b, n, "BIG", CK_ACARD_FILE_MAX - 12 - 2 - 3 - 4, 5);
    CHECK(n == CK_ACARD_FILE_MAX);
    CHECK(ck_acard_parse(b, n, &o, &why) == 0 && o.e[0].len == CK_ACARD_FILE_MAX - 21);
    n = head(b, 1);
    n = put(b, n, "BIG", CK_ACARD_FILE_MAX - 12 - 2 - 3 - 4 + 1, 5);
    CHECK(refused(b, n, "file size"));

    return ck_t_verdict("test_artifact_card");
}
