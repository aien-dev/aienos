/* fbcon.c -- text console on a linear 32-bit framebuffer; see fbcon.h. */
#include "fbcon.h"
#include "font8x8.h"

uint32_t ck_fbcon_scale_for(uint32_t width, uint32_t height)
{
    uint32_t s = height / 540;
    if (s < 1)
        s = 1;
    if (s > 4)
        s = 4;
    while (s > 1 && width / (CK_FBCON_CELL_W * s) < 80)
        s--;
    return s;
}

int ck_fbcon_setup(struct ck_fbcon *c, volatile uint32_t *px, uint32_t width, uint32_t height,
                   uint32_t pitch, uint32_t format)
{
    if (!px || format > 1 || pitch < width)
        return -1;
    uint32_t s = ck_fbcon_scale_for(width, height);
    uint32_t cols = width / (CK_FBCON_CELL_W * s), rows = height / (CK_FBCON_CELL_H * s);
    if (!cols || !rows)
        return -1;
    if (cols > CK_FBCON_MAX_COLS)
        cols = CK_FBCON_MAX_COLS;
    if (rows > CK_FBCON_MAX_ROWS)
        rows = CK_FBCON_MAX_ROWS;
    c->px = px;
    c->width = width;
    c->height = height;
    c->pitch = pitch;
    c->format = format;
    c->scale = s;
    c->cols = cols;
    c->rows = rows;
    c->col = 0;
    c->row = 0;
    c->pending_nl = 0;
    c->scrolls = 0;
    for (uint32_t r = 0; r < CK_FBCON_MAX_ROWS; r++)
        for (uint32_t k = 0; k < CK_FBCON_MAX_COLS; k++)
            c->text[r][k] = 0;
    ck_fbcon_clear(c);
    return 0;
}

void ck_fbcon_clear(struct ck_fbcon *c)
{
    for (uint32_t y = 0; y < c->height; y++) {
        volatile uint32_t *p = c->px + (uint64_t)y * c->pitch;
        for (uint32_t x = 0; x < c->width; x++)
            p[x] = CK_FBCON_BG;
    }
}

/* One 8x8 glyph (times scale) into cell (col, row); the two gap rows of the
 * cell are left as the clear made them. */
static void glyph(struct ck_fbcon *c, uint32_t col, uint32_t row, unsigned char ch)
{
    const uint8_t *g = ck_font8x8[ch - CK_FONT_FIRST];
    uint32_t s = c->scale;
    uint64_t x0 = (uint64_t)col * CK_FBCON_CELL_W * s;
    uint64_t y0 = (uint64_t)row * CK_FBCON_CELL_H * s;
    for (uint32_t gy = 0; gy < CK_FONT_H; gy++) {
        for (uint32_t sy = 0; sy < s; sy++) {
            volatile uint32_t *p = c->px + (y0 + gy * s + sy) * c->pitch + x0;
            for (uint32_t gx = 0; gx < CK_FONT_W; gx++) {
                uint32_t v = (g[gy] >> gx) & 1 ? CK_FBCON_FG : CK_FBCON_BG;
                for (uint32_t sx = 0; sx < s; sx++)
                    *p++ = v;
            }
        }
    }
}

static void draw(struct ck_fbcon *c, unsigned char ch)
{
    if (ch < CK_FONT_FIRST || ch > CK_FONT_LAST)
        ch = '?';
    c->text[c->row][c->col] = (char)ch;
    glyph(c, c->col, c->row, ch);
}

/* Next row. Bottom row full: clear, move the newest half of the text rows
 * to the top and redraw them; writing goes on below them. */
static void advance(struct ck_fbcon *c)
{
    c->col = 0;
    if (++c->row < c->rows)
        return;
    uint32_t keep = c->rows / 2;
    ck_fbcon_clear(c);
    for (uint32_t r = 0; r < c->rows; r++)
        for (uint32_t k = 0; k < c->cols; k++)
            c->text[r][k] = r < keep ? c->text[c->rows - keep + r][k] : 0;
    for (uint32_t r = 0; r < keep; r++)
        for (uint32_t k = 0; k < c->cols; k++)
            if (c->text[r][k])
                glyph(c, k, r, (unsigned char)c->text[r][k]);
    c->row = keep;
    c->scrolls++;
}

void ck_fbcon_write(struct ck_fbcon *c, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch == '\n') {
            if (c->pending_nl)
                advance(c);
            c->pending_nl = 1;
            continue;
        }
        if (ch == '\r') {
            if (!c->pending_nl)
                c->col = 0;
            continue;
        }
        if (c->pending_nl) {
            advance(c);
            c->pending_nl = 0;
        }
        if (ch == '\t') {
            uint32_t next = (c->col / 8 + 1) * 8;
            while (c->col < next && c->col < c->cols) {
                draw(c, ' ');
                c->col++;
            }
            continue;
        }
        if (c->col >= c->cols)
            advance(c);
        draw(c, ch);
        c->col++;
    }
}
