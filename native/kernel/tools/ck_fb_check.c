/* ck_fb_check -- host checker for the AIENOS_CK_SCREEN gate
 * (scripts/qemu_ck_screen_test.sh): does a QEMU screendump show exactly
 * what the kernel's framebuffer console (core/fbcon.c) must have drawn for
 * the serial log of the same boot? Hosted C, test tooling only, never part
 * of an image. No OCR: the expected screen is rendered by the kernel's own
 * console code from the serial bytes, and the dump is decoded cell by cell
 * against the kernel's own font.
 *
 *   ck_fb_check --serial LOG [--ppm DUMP] [--render OUT.ppm] [--expect TEXT]...
 *
 *   --render writes the screen rendered in step 2 as a PPM (evidence, and the
 *   gate's self-test input); without --ppm only steps 1-2 run.
 *
 *   1. LOG must hold exactly one line starting "screen: gop " (the first
 *      line the kernel draws, core/kmain.c screen_start); its geometry
 *      (WxH, format, scale, grid) must match DUMP (binary PPM, P6, maxval
 *      255, as QMP screendump writes it) and what ck_fbcon_setup computes.
 *   2. The serial bytes from that line to the end of LOG are fed through
 *      ck_fbcon_write into a host buffer; every visible pixel of DUMP must
 *      equal the rendered pixel (mismatched=0).
 *   3. DUMP is decoded: each cell must be a font glyph or blank with uniform
 *      scale x scale blocks and black gap rows (undecodable=0); the rows are
 *      printed as "screen_row NNN|text|".
 *   4. Each --expect TEXT must equal one decoded row (trailing blanks
 *      trimmed).
 * Exit 0 only if all four hold (or the render was written); 1 otherwise; 2
 * usage or unreadable input. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../core/fbcon.h"
#include "../core/font8x8.h"

#define MAX_EXPECT 16

static unsigned char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t cap = 1 << 16, n = 0;
    unsigned char *b = malloc(cap + 1);
    size_t r;
    while (b && (r = fread(b + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            cap *= 2;
            unsigned char *nb = realloc(b, cap + 1);
            if (!nb) {
                free(b);
                b = 0;
            }
            b = nb;
        }
    }
    fclose(f);
    if (b)
        b[n] = 0;
    *len = n;
    return b;
}

/* P6 header: "P6" ws W ws H ws 255 single-ws, no comments (QEMU writes none). */
static const unsigned char *ppm_parse(const unsigned char *b, size_t len, uint32_t *w, uint32_t *h)
{
    unsigned mv = 0;
    int off = 0;
    if (len < 16 || sscanf((const char *)b, "P6 %u %u %u%n", w, h, &mv, &off) != 3 || mv != 255)
        return 0;
    off++; /* the single whitespace byte after maxval */
    if ((uint64_t)off + (uint64_t)*w * *h * 3 > len || !*w || !*h)
        return 0;
    return b + off;
}

static uint32_t to_pixel(const unsigned char *rgb, uint32_t format)
{
    /* Memory bytes 0..2 of a 32-bit pixel: RGBX = R,G,B; BGRX = B,G,R; the
     * uint32 is read little endian like the kernel stores it. */
    if (format == 0)
        return (uint32_t)rgb[0] | (uint32_t)rgb[1] << 8 | (uint32_t)rgb[2] << 16;
    return (uint32_t)rgb[2] | (uint32_t)rgb[1] << 8 | (uint32_t)rgb[0] << 16;
}

static int usage(void)
{
    fprintf(stderr, "usage: ck_fb_check --serial LOG [--ppm DUMP] [--render OUT.ppm] [--expect TEXT]...\n");
    return 2;
}

static int write_ppm(const char *path, const uint32_t *buf, uint32_t w, uint32_t h, uint32_t format)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    fprintf(f, "P6\n%u %u\n255\n", w, h);
    for (uint64_t i = 0; i < (uint64_t)w * h; i++) {
        uint32_t v = buf[i];
        unsigned char rgb[3];
        if (format == 0) {
            rgb[0] = v & 0xff, rgb[1] = (v >> 8) & 0xff, rgb[2] = (v >> 16) & 0xff;
        } else {
            rgb[2] = v & 0xff, rgb[1] = (v >> 8) & 0xff, rgb[0] = (v >> 16) & 0xff;
        }
        fwrite(rgb, 1, 3, f);
    }
    return fclose(f) == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *serial = 0, *ppm = 0, *render = 0, *expect[MAX_EXPECT];
    int n_expect = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--serial") && i + 1 < argc)
            serial = argv[++i];
        else if (!strcmp(argv[i], "--ppm") && i + 1 < argc)
            ppm = argv[++i];
        else if (!strcmp(argv[i], "--render") && i + 1 < argc)
            render = argv[++i];
        else if (!strcmp(argv[i], "--expect") && i + 1 < argc && n_expect < MAX_EXPECT)
            expect[n_expect++] = argv[++i];
        else
            return usage();
    }
    if (!serial || (!ppm && !render))
        return usage();
    size_t slen = 0;
    unsigned char *log = slurp(serial, &slen);
    if (!log) {
        printf("fb_check: cannot read %s\n", serial);
        return 2;
    }

    /* 1. the marker line, exactly once, at a line start */
    static const char marker[] = "screen: gop ";
    const char *start = 0;
    unsigned markers = 0;
    for (size_t i = 0; i + sizeof marker - 1 <= slen; i++)
        if ((i == 0 || log[i - 1] == '\n') && !memcmp(log + i, marker, sizeof marker - 1)) {
            markers++;
            if (!start)
                start = (const char *)log + i;
        }
    if (markers != 1) {
        printf("fb_check: FAIL %u \"screen: gop\" lines in the serial log (want exactly 1)\n", markers);
        return 1;
    }
    uint32_t lw, lh, pitch, scale, cols, rows;
    char fmt[8] = {0};
    unsigned long long base, bytes;
    if (sscanf(start, "screen: gop %ux%u pitch=%u format=%4s base=0x%llx bytes=0x%llx scale=%u grid=%ux%u",
               &lw, &lh, &pitch, fmt, &base, &bytes, &scale, &cols, &rows) != 9 ||
        (strcmp(fmt, "rgbx") && strcmp(fmt, "bgrx"))) {
        printf("fb_check: FAIL malformed \"screen: gop\" line\n");
        return 1;
    }
    uint32_t format = !strcmp(fmt, "bgrx");

    /* 2. render the serial bytes from the marker on with the kernel's code */
    static struct ck_fbcon con;
    uint32_t w = lw, h = lh;
    uint32_t *buf = calloc((size_t)w * h, 4);
    if (!buf || ck_fbcon_setup(&con, buf, w, h, w, format) != 0) {
        printf("fb_check: FAIL cannot set up a %ux%u console\n", w, h);
        return 1;
    }
    if (con.scale != scale || con.cols != cols || con.rows != rows) {
        printf("fb_check: FAIL geometry: serial scale=%u grid=%ux%u, console code scale=%u grid=%ux%u\n", scale,
               cols, rows, con.scale, con.cols, con.rows);
        return 1;
    }
    ck_fbcon_write(&con, start, slen - (size_t)(start - (const char *)log));
    if (render && write_ppm(render, buf, w, h, format) != 0) {
        printf("fb_check: cannot write %s\n", render);
        return 2;
    }
    if (!ppm) {
        printf("fb_check: rendered %ux%u format=%s scale=%u grid=%ux%u scrolls=%llu to %s\n", w, h, fmt, scale,
               cols, rows, (unsigned long long)con.scrolls, render);
        return 0;
    }

    size_t plen = 0;
    unsigned char *dump = slurp(ppm, &plen);
    uint32_t dw = 0, dh = 0;
    const unsigned char *px = dump ? ppm_parse(dump, plen, &dw, &dh) : 0;
    if (!px) {
        printf("fb_check: FAIL %s is missing or not a binary P6 PPM with maxval 255\n", ppm);
        return 1;
    }
    if (dw != w || dh != h) {
        printf("fb_check: FAIL geometry: serial %ux%u, dump %ux%u\n", w, h, dw, dh);
        return 1;
    }
    uint64_t mismatched = 0;
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++) {
            uint64_t i = (uint64_t)y * w + x;
            if (to_pixel(px + 3 * i, format) != buf[i]) {
                if (mismatched < 5)
                    printf("fb_check: pixel (%u,%u) dump=0x%06x rendered=0x%06x\n", x, y,
                           to_pixel(px + 3 * i, format), buf[i]);
                mismatched++;
            }
        }

    /* 3. decode the dump against the font */
    uint64_t undecodable = 0;
    char (*text)[CK_FBCON_MAX_COLS + 1] = calloc(rows, sizeof *text);
    if (!text)
        return 2;
    uint32_t s = scale, cw = CK_FBCON_CELL_W * s, chh = CK_FBCON_CELL_H * s;
    for (uint32_t r = 0; r < rows; r++) {
        for (uint32_t k = 0; k < cols; k++) {
            uint8_t bits[CK_FBCON_CELL_H] = {0};
            int bad = 0;
            for (uint32_t cy = 0; cy < chh && !bad; cy++)
                for (uint32_t cx = 0; cx < cw; cx++) {
                    uint64_t i = ((uint64_t)r * chh + cy) * w + (uint64_t)k * cw + cx;
                    uint32_t v = to_pixel(px + 3 * i, format);
                    if (v != CK_FBCON_FG && v != CK_FBCON_BG) {
                        bad = 1;
                        break;
                    }
                    int on = v == CK_FBCON_FG;
                    uint32_t gy = cy / s, gx = cx / s;
                    if (cy % s == 0 && cx % s == 0) {
                        if (on)
                            bits[gy] |= (uint8_t)(1u << gx);
                    } else if (on != ((bits[gy] >> gx) & 1)) {
                        bad = 1; /* scale x scale block not uniform */
                        break;
                    }
                }
            if (!bad && (bits[8] || bits[9]))
                bad = 1; /* the two gap rows of a cell stay black */
            char ch = 0;
            for (int g = 0; !bad && g <= CK_FONT_LAST - CK_FONT_FIRST && !ch; g++)
                if (!memcmp(bits, ck_font8x8[g], CK_FONT_H))
                    ch = (char)(CK_FONT_FIRST + g);
            if (!ch) {
                ch = '?'; /* shown as '?', counted; a real '?' glyph is not counted */
                undecodable++;
            }
            text[r][k] = ch;
        }
        uint32_t n = cols;
        while (n && text[r][n - 1] == ' ')
            n--;
        text[r][n] = 0;
        printf("screen_row %03u|%s|\n", r, text[r]);
    }

    /* 4. expected rows */
    int found_all = 1;
    for (int e = 0; e < n_expect; e++) {
        int found = 0;
        for (uint32_t r = 0; r < rows && !found; r++)
            found = !strcmp(text[r], expect[e]);
        printf("fb_check: expect \"%s\": %s\n", expect[e], found ? "found" : "MISSING");
        found_all &= found;
    }
    int ok = mismatched == 0 && undecodable == 0 && found_all;
    printf("fb_check: %s %ux%u format=%s scale=%u grid=%ux%u scrolls=%llu pixels=%llu mismatched=%llu "
           "undecodable=%llu\n",
           ok ? "PASS" : "FAIL", w, h, fmt, scale, cols, rows, (unsigned long long)con.scrolls,
           (unsigned long long)w * h, (unsigned long long)mismatched, (unsigned long long)undecodable);
    return ok ? 0 : 1;
}
