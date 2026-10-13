/* klog.c -- see klog.h. */
#include "klog.h"
#include "fmt.h"

static char head[CK_KLOG_HEAD];
static char tail[CK_KLOG_TAIL];
static uint32_t head_len;
static uint64_t tail_put; /* bytes put into the ring, ever */
static uint64_t total;

void ck_klog_put(const char *s, size_t n)
{
    total += n;
    for (size_t i = 0; i < n; i++) {
        if (head_len < CK_KLOG_HEAD)
            head[head_len++] = s[i];
        else
            tail[tail_put++ % CK_KLOG_TAIL] = s[i];
    }
}

size_t ck_klog_read(char *out, size_t cap)
{
    size_t w = 0;
    for (uint32_t i = 0; i < head_len && w < cap; i++)
        out[w++] = head[i];
    uint64_t kept = tail_put < CK_KLOG_TAIL ? tail_put : CK_KLOG_TAIL;
    if (tail_put > CK_KLOG_TAIL) {
        char line[64];
        int n = ck_snprintf(line, sizeof line, "\n[klog: %llu bytes dropped]\n",
                            (unsigned long long)(tail_put - CK_KLOG_TAIL));
        for (int i = 0; i < n && w < cap; i++)
            out[w++] = line[i];
    }
    for (uint64_t i = tail_put - kept; i < tail_put && w < cap; i++)
        out[w++] = tail[i % CK_KLOG_TAIL];
    return w;
}

uint64_t ck_klog_total(void) { return total; }

void ck_klog_clear(void)
{
    head_len = 0;
    tail_put = 0;
    total = 0;
}
