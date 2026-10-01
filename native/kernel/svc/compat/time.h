/* Kernel-build stand-in, see README. Every clock is ck_time_us. */
#ifndef CK_COMPAT_TIME_H
#define CK_COMPAT_TIME_H
typedef long time_t;
typedef int clockid_t;
struct timespec { time_t tv_sec; long tv_nsec; };
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_BOOTTIME 7
int ck_compat_clock_gettime(clockid_t id, struct timespec *ts);
#define clock_gettime(i, t) ck_compat_clock_gettime((i), (t))
#endif
