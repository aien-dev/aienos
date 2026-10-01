/* ck_compat.h -- what the kernel-build compat layer reports back. */
#ifndef AIENOS_CK_COMPAT_H
#define AIENOS_CK_COMPAT_H
enum { CK_ENTROPY_NONE = 0, CK_ENTROPY_RNDR = 1, CK_ENTROPY_TIMER_WEAK = 2, CK_ENTROPY_HOST = 3 };
/* Source used for the last "/dev/urandom" read (kernel build). */
int ck_compat_entropy_source(void);
#endif
