/* Kernel-build stand-in, see README. Single core, no preemption of stage code. */
#ifndef CK_COMPAT_PTHREAD_H
#define CK_COMPAT_PTHREAD_H
typedef struct { volatile int locked; } pthread_mutex_t;
typedef int pthread_mutexattr_t;
#define PTHREAD_MUTEX_INITIALIZER { 0 }
void ck_compat_mutex_lock(pthread_mutex_t *m);
static inline int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a)
{
    (void)a;
    m->locked = 0;
    return 0;
}
static inline int pthread_mutex_destroy(pthread_mutex_t *m)
{
    (void)m;
    return 0;
}
static inline int pthread_mutex_lock(pthread_mutex_t *m)
{
    ck_compat_mutex_lock(m);
    return 0;
}
static inline int pthread_mutex_unlock(pthread_mutex_t *m)
{
    m->locked = 0;
    return 0;
}
#endif
