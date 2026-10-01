/* Kernel-build stand-in, see README. Only "/dev/urandom" opens. */
#ifndef CK_COMPAT_STDIO_H
#define CK_COMPAT_STDIO_H
#include <stddef.h>
typedef struct ck_compat_file FILE;
FILE *ck_compat_fopen(const char *path, const char *mode);
size_t ck_compat_fread(void *buf, size_t sz, size_t n, FILE *f);
int ck_compat_fclose(FILE *f);
#define fopen(p, m) ck_compat_fopen((p), (m))
#define fread(b, s, n, f) ck_compat_fread((b), (s), (n), (f))
#define fclose(f) ck_compat_fclose(f)
#endif
