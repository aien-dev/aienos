/* Kernel-build stand-in, see README. */
#ifndef CK_COMPAT_STDLIB_H
#define CK_COMPAT_STDLIB_H
#include <stddef.h>
void *ck_compat_malloc(size_t n);
void *ck_compat_calloc(size_t n, size_t sz);
void ck_compat_free(void *p);
#define malloc(n) ck_compat_malloc(n)
#define calloc(n, s) ck_compat_calloc((n), (s))
#define free(p) ck_compat_free(p)
#endif
