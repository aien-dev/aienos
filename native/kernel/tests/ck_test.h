/* ck_test.h -- tiny host test harness for the C kernel core. Each test
 * binary ends with "<name>: PASS" or "<name>: FAIL (<n> failed)". */
#ifndef CK_TEST_H
#define CK_TEST_H

#include <stdio.h>

static int ck_t_fail, ck_t_run;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ck_t_run++;                                                            \
        if (!(cond)) {                                                         \
            ck_t_fail++;                                                       \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                      \
    } while (0)

static inline int ck_t_verdict(const char *name)
{
    if (ck_t_fail)
        printf("%s: FAIL (%d of %d checks failed)\n", name, ck_t_fail, ck_t_run);
    else
        printf("%s: PASS (%d checks)\n", name, ck_t_run);
    return ck_t_fail ? 1 : 0;
}

#endif
