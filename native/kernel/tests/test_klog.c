/* test_klog.c -- core/klog.c: head kept in order, ring keeps the newest
 * bytes, the dropped-bytes line, the cap. */
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "klog.h"

static char out[CK_KLOG_MAX + 16];

int main(void)
{
    /* Small log: read back exactly. */
    ck_klog_put("hello\n", 6);
    ck_klog_put("world\n", 6);
    size_t n = ck_klog_read(out, sizeof out);
    CHECK(n == 12 && memcmp(out, "hello\nworld\n", 12) == 0);
    CHECK(ck_klog_total() == 12);
    /* Cap is respected. */
    CHECK(ck_klog_read(out, 5) == 5 && memcmp(out, "hello", 5) == 0);
    CHECK(ck_klog_read(out, 0) == 0);

    /* Fill the head exactly, then less than one ring: nothing dropped. */
    ck_klog_clear();
    char *big = malloc(CK_KLOG_HEAD + 3 * CK_KLOG_TAIL);
    for (size_t i = 0; i < CK_KLOG_HEAD + 3 * CK_KLOG_TAIL; i++)
        big[i] = (char)('a' + i % 23);
    ck_klog_put(big, CK_KLOG_HEAD + 100);
    n = ck_klog_read(out, sizeof out);
    CHECK(n == CK_KLOG_HEAD + 100 && memcmp(out, big, n) == 0);

    /* Overflow the ring: head intact, dropped line, newest CK_KLOG_TAIL bytes. */
    ck_klog_clear();
    size_t put = CK_KLOG_HEAD + 2 * CK_KLOG_TAIL + 777;
    for (size_t i = 0; i < put; i += 1000) /* uneven pieces */
        ck_klog_put(big + i, put - i < 1000 ? put - i : 1000);
    CHECK(ck_klog_total() == put);
    n = ck_klog_read(out, sizeof out);
    CHECK(memcmp(out, big, CK_KLOG_HEAD) == 0);
    char line[64];
    snprintf(line, sizeof line, "\n[klog: %zu bytes dropped]\n", put - CK_KLOG_HEAD - CK_KLOG_TAIL);
    size_t ll = strlen(line);
    CHECK(memcmp(out + CK_KLOG_HEAD, line, ll) == 0);
    CHECK(n == CK_KLOG_HEAD + ll + CK_KLOG_TAIL);
    CHECK(memcmp(out + CK_KLOG_HEAD + ll, big + put - CK_KLOG_TAIL, CK_KLOG_TAIL) == 0);
    CHECK(n <= CK_KLOG_MAX);

    /* Exactly one full ring: nothing dropped, no line. */
    ck_klog_clear();
    ck_klog_put(big, CK_KLOG_HEAD + CK_KLOG_TAIL);
    n = ck_klog_read(out, sizeof out);
    CHECK(n == CK_KLOG_HEAD + CK_KLOG_TAIL && memcmp(out, big, n) == 0);
    free(big);
    return ck_t_verdict("test_klog");
}
