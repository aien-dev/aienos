/* fbcon.h -- text console on a linear 32-bit framebuffer (the UEFI GOP
 * framebuffer the boot stub hands over in the CHANDOF3 record).
 *
 * Pure layout and drawing: no globals, no I/O besides the pixel stores, so
 * the kernel (core/console.c, framebuffer mapped Device-nGnRE) and the host
 * checker (tools/ck_fb_check.c, a malloc'd buffer) run the same code and
 * the checker can render the exact screen a serial log must produce.
 *
 * Layout: 8x8 glyphs (core/font8x8.h) in cells of 8 x 10 pixels times an
 * integer scale; white on black. Scrolling is "half-scroll": when the
 * bottom row is full, the screen is cleared and the newest half of the rows
 * is redrawn at the top from a text copy kept here (no read-back of device
 * memory), so the screen always shows at least half a screen of the latest
 * lines, in order, and each line is drawn about twice. A newline is applied
 * lazily, when the next character arrives, so the last line of a
 * run stays on screen. Long lines wrap. Bytes outside 0x20..0x7e (except
 * '\n', '\r', '\t') are drawn as '?'. */
#ifndef AIENOS_CK_FBCON_H
#define AIENOS_CK_FBCON_H
#include <stddef.h>
#include <stdint.h>

#define CK_FBCON_CELL_W 8  /* times scale */
#define CK_FBCON_CELL_H 10 /* 8 glyph rows + 2 blank rows, times scale */
#define CK_FBCON_FG 0x00ffffffu /* white in both RGBX and BGRX */
#define CK_FBCON_BG 0x00000000u
#define CK_FBCON_MAX_COLS 256 /* text copy; wider screens leave the right edge black */
#define CK_FBCON_MAX_ROWS 256

struct ck_fbcon {
    volatile uint32_t *px;       /* pixel (0,0) */
    uint32_t width, height;      /* visible pixels */
    uint32_t pitch;              /* pixels per scan line */
    uint32_t format;             /* 0 RGBX, 1 BGRX (EFI_GRAPHICS_PIXEL_FORMAT) */
    uint32_t scale, cols, rows;
    uint32_t col, row;
    int pending_nl;              /* a '\n' not yet applied */
    uint64_t scrolls;            /* half-scrolls so far */
    char text[CK_FBCON_MAX_ROWS][CK_FBCON_MAX_COLS]; /* what each cell shows, 0 = never written */
};

/* Scale for a screen: height / 540 clamped to 1..4, lowered until at least
 * 80 columns fit (1920x1080 -> 2, 3840x2160 -> 4, 800x600 -> 1). */
uint32_t ck_fbcon_scale_for(uint32_t width, uint32_t height);

/* Sets up c for the framebuffer and clears the visible area. Returns -1
 * (and touches no pixel) when the geometry cannot hold one cell or the
 * format is not 0/1. */
int ck_fbcon_setup(struct ck_fbcon *c, volatile uint32_t *px, uint32_t width, uint32_t height,
                   uint32_t pitch, uint32_t format);

void ck_fbcon_clear(struct ck_fbcon *c);
void ck_fbcon_write(struct ck_fbcon *c, const char *s, size_t n);

#endif
