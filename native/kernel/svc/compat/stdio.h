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
/* snprintf for the TEST-ONLY continuity wiring (svc/continuity_recovery.c): the kernel's own formatter, core/fmt.c. */
#include <stdarg.h>
int ck_snprintf(char *buf, size_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
#define snprintf ck_snprintf
#endif
