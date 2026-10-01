/* test_fmt.c -- ck_vformat against the host libc snprintf for every
 * conversion and flag the kernel console documents. */
#include <stdint.h>
#include <string.h>
#include "ck_test.h"
#include "fmt.h"

#define SAME(...)                                                              \
    do {                                                                       \
        char a[256], b[256];                                                   \
        int na = ck_snprintf(a, sizeof a, __VA_ARGS__);                        \
        int nb = snprintf(b, sizeof b, __VA_ARGS__);                           \
        CHECK(strcmp(a, b) == 0 && na == nb);                                  \
        if (strcmp(a, b) || na != nb)                                          \
            printf("    ck=\"%s\"(%d) libc=\"%s\"(%d)\n", a, na, b, nb);       \
    } while (0)

int main(void)
{
    SAME("plain text");
    SAME("%s|%5s|%-5s|", "abc", "ab", "ab");
    SAME("%c%c", 'x', 'y');
    SAME("%d %d %d %i", 0, -1, 2147483647, -2147483647 - 1);
    SAME("%u %x %X", 4294967295u, 0xdeadbeefu, 0xabcu);
    SAME("%ld %lu %lx", -5l, 18446744073709551615ul, 0x123456789abcdeful);
    SAME("%lld %llu %llx", -9223372036854775807ll - 1, 18446744073709551615ull, 0xfull);
    SAME("%zu %zx", (size_t)12345, (size_t)0xfff);
    SAME("%016llx|%08x|%-8d|%5d|%05d", 0xabcull, 0x1u, 42, -7, -7);
    SAME("%*d|%-*d|", 6, 9, 4, 3);
    SAME("%hhu %hu %hd", 300, 70000, -3);
    SAME("100%%");
    SAME("%p", (void *)0x1234);
    SAME("%x", 0u);

    /* NULL %s prints "(null)", truncation keeps the full return count. */
    char t[8];
    const char *volatile nul = 0;
    CHECK(ck_snprintf(t, sizeof t, "%s", nul) == 6 && strcmp(t, "(null)") == 0);
    CHECK(ck_snprintf(t, sizeof t, "0123456789") == 10 && strcmp(t, "0123456") == 0);
    CHECK(ck_snprintf(t, 0, "abc") == 3);
    return ck_t_verdict("CK_FMT");
}
