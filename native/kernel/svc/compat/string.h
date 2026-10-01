/* Kernel-build stand-in, see README. Declares only the four memory routines
 * the stage sources use; they are defined (weak) in ../ck_compat.c. Keeps
 * the freestanding build off the host libc headers (no _FORTIFY_SOURCE
 * __memcpy_chk calls). */
#ifndef CK_COMPAT_STRING_H
#define CK_COMPAT_STRING_H
#include <stddef.h>
void *memcpy(void *restrict d, const void *restrict s, size_t n);
void *memmove(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
#endif
