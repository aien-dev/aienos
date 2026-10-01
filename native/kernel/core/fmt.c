/* fmt.c -- see fmt.h. */
#include "fmt.h"

#include <stdint.h>

static void emit_n(ck_emit_fn emit, void *ctx, char c, int n, int *count)
{
    for (int i = 0; i < n; i++) {
        emit(ctx, c);
        (*count)++;
    }
}

int ck_vformat(ck_emit_fn emit, void *ctx, const char *fmt, va_list ap)
{
    int count = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            emit(ctx, *p);
            count++;
            continue;
        }
        const char *start = p++;
        int left = 0, zero = 0, width = 0, len = 0; /* len: -2 hh, -1 h, 1 l, 2 ll, 3 z */
        for (;; p++) {
            if (*p == '-')
                left = 1;
            else if (*p == '0')
                zero = 1;
            else
                break;
        }
        if (*p == '*') {
            width = va_arg(ap, int);
            if (width < 0) {
                left = 1;
                width = -width;
            }
            p++;
        } else {
            while (*p >= '0' && *p <= '9')
                width = width * 10 + (*p++ - '0');
        }
        if (*p == 'h') {
            len = -1;
            if (*++p == 'h') {
                len = -2;
                p++;
            }
        } else if (*p == 'l') {
            len = 1;
            if (*++p == 'l') {
                len = 2;
                p++;
            }
        } else if (*p == 'z') {
            len = 3;
            p++;
        }
        char c = *p;
        if (c == '\0') {
            /* Dangling '%': print what we saw and stop. */
            for (const char *q = start; *q; q++) {
                emit(ctx, *q);
                count++;
            }
            break;
        }
        char tmp[24];
        int n = 0, neg = 0;
        const char *str = tmp;
        const char *prefix = "";
        if (c == 's' || c == 'c' || c == '%') {
            if (c == 's') {
                str = va_arg(ap, const char *);
                if (!str)
                    str = "(null)";
                while (str[n])
                    n++;
            } else {
                tmp[0] = c == 'c' ? (char)va_arg(ap, int) : '%';
                n = 1;
            }
            int pad = width > n ? width - n : 0;
            if (!left)
                emit_n(emit, ctx, ' ', pad, &count);
            for (int i = 0; i < n; i++) {
                emit(ctx, str[i]);
                count++;
            }
            if (left)
                emit_n(emit, ctx, ' ', pad, &count);
            continue;
        }
        if (c != 'd' && c != 'i' && c != 'u' && c != 'x' && c != 'X' && c != 'p') {
            /* Unknown conversion: print it literally. */
            for (const char *q = start; q <= p; q++) {
                emit(ctx, *q);
                count++;
            }
            continue;
        }
        uint64_t v;
        if (c == 'p') {
            v = (uint64_t)(uintptr_t)va_arg(ap, void *);
            prefix = "0x";
        } else if (c == 'd' || c == 'i') {
            int64_t s;
            if (len == 2)
                s = va_arg(ap, long long);
            else if (len == 1)
                s = va_arg(ap, long);
            else if (len == 3)
                s = (int64_t)va_arg(ap, size_t);
            else
                s = va_arg(ap, int);
            if (len == -1)
                s = (short)s;
            else if (len == -2)
                s = (signed char)s;
            neg = s < 0;
            v = neg ? (uint64_t)0 - (uint64_t)s : (uint64_t)s;
        } else {
            if (len == 2)
                v = va_arg(ap, unsigned long long);
            else if (len == 1)
                v = va_arg(ap, unsigned long);
            else if (len == 3)
                v = va_arg(ap, size_t);
            else
                v = va_arg(ap, unsigned int);
            if (len == -1)
                v = (unsigned short)v;
            else if (len == -2)
                v = (unsigned char)v;
        }
        unsigned base = (c == 'x' || c == 'X' || c == 'p') ? 16 : 10;
        const char *digits = c == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
        do {
            tmp[n++] = digits[v % base];
            v /= base;
        } while (v);
        int plen = neg ? 1 : (prefix[0] ? 2 : 0);
        int pad = width > n + plen ? width - n - plen : 0;
        if (!left && !zero)
            emit_n(emit, ctx, ' ', pad, &count);
        if (neg) {
            emit(ctx, '-');
            count++;
        }
        for (const char *q = prefix; *q; q++) {
            emit(ctx, *q);
            count++;
        }
        if (!left && zero)
            emit_n(emit, ctx, '0', pad, &count);
        while (n)
            emit(ctx, tmp[--n]), count++;
        if (left)
            emit_n(emit, ctx, ' ', pad, &count);
    }
    return count;
}

struct sbuf {
    char *buf;
    size_t cap, len;
};

static void sbuf_emit(void *ctx, char c)
{
    struct sbuf *s = ctx;
    if (s->len + 1 < s->cap)
        s->buf[s->len] = c;
    s->len++;
}

int ck_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap)
{
    struct sbuf s = { buf, n, 0 };
    int r = ck_vformat(sbuf_emit, &s, fmt, ap);
    if (n)
        buf[s.len < n ? s.len : n - 1] = '\0';
    return r;
}

int ck_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = ck_vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}
