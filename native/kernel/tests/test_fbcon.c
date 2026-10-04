/* test_fbcon.c -- host tests of core/fbcon.c (the GOP framebuffer console)
 * and core/font8x8.h: every printable glyph is distinct (the screen gate's
 * checker decodes cells by exact match), the scale rule, lazy newline, line
 * wrap, half-scroll, and the exact pixels of one glyph. */
#include <string.h>
#include "ck_test.h"
#include "fbcon.h"
#include "font8x8.h"

static uint32_t px[800 * 600];
static struct ck_fbcon con;

/* Text of row r as the text copy holds it (0 cells end it). */
static const char *row_text(uint32_t r)
{
    static char b[CK_FBCON_MAX_COLS + 1];
    uint32_t n = 0;
    while (n < con.cols && con.text[r][n])
        b[n] = con.text[r][n], n++;
    b[n] = 0;
    return b;
}

static void put(const char *s) { ck_fbcon_write(&con, s, strlen(s)); }

int main(void)
{
    /* glyphs 0x20..0x7e pairwise distinct; only the space is blank */
    int distinct = 1, blank = 0;
    for (int a = 0; a <= CK_FONT_LAST - CK_FONT_FIRST; a++) {
        uint8_t z[8] = {0};
        blank += !memcmp(ck_font8x8[a], z, 8);
        for (int b = a + 1; b <= CK_FONT_LAST - CK_FONT_FIRST; b++)
            if (!memcmp(ck_font8x8[a], ck_font8x8[b], 8))
                distinct = 0;
    }
    CHECK(distinct);
    CHECK(blank == 1);

    /* scale: 1080p -> 2, 4K -> 4, 800x600 -> 1, 1280x1024 -> 1 (80 columns) */
    CHECK(ck_fbcon_scale_for(1920, 1080) == 2);
    CHECK(ck_fbcon_scale_for(3840, 2160) == 4);
    CHECK(ck_fbcon_scale_for(800, 600) == 1);
    CHECK(ck_fbcon_scale_for(1280, 1024) == 1);
    CHECK(ck_fbcon_scale_for(640, 480) == 1);

    /* refusals: format 2, pitch < width, too small for one cell */
    CHECK(ck_fbcon_setup(&con, px, 800, 600, 800, 2) == -1);
    CHECK(ck_fbcon_setup(&con, px, 800, 600, 799, 1) == -1);
    CHECK(ck_fbcon_setup(&con, px, 7, 600, 800, 1) == -1);

    memset(px, 0x55, sizeof px);
    CHECK(ck_fbcon_setup(&con, px, 800, 600, 800, 1) == 0);
    CHECK(con.scale == 1 && con.cols == 100 && con.rows == 60);
    CHECK(px[0] == CK_FBCON_BG && px[800 * 600 - 1] == CK_FBCON_BG); /* cleared */

    /* 'A' at cell (0,0): row 0 of the glyph is 0x0C -> pixels 2 and 3 lit */
    put("A");
    CHECK(px[0] == CK_FBCON_BG && px[1] == CK_FBCON_BG && px[2] == CK_FBCON_FG && px[3] == CK_FBCON_FG &&
          px[4] == CK_FBCON_BG);
    CHECK(px[8 * 800 + 2] == CK_FBCON_BG); /* gap row 8 stays black */

    /* lazy newline: the trailing '\n' does not move to the next row yet */
    put("BC\n");
    CHECK(con.row == 0 && con.pending_nl == 1);
    CHECK(!strcmp(row_text(0), "ABC"));
    put("\r\nD"); /* "\r\n" from the UART stream behaves like one more '\n' */
    CHECK(con.row == 2 && !strcmp(row_text(2), "D"));

    /* wrap at 100 columns */
    put("\n");
    for (int i = 0; i < 105; i++)
        put("x");
    CHECK(con.row == 4 && con.col == 5);

    /* half-scroll: fill to the bottom; the newest 30 rows move to the top */
    CHECK(ck_fbcon_setup(&con, px, 800, 600, 800, 0) == 0);
    char line[16];
    for (int i = 0; i < 61; i++) {
        snprintf(line, sizeof line, "%sL%02d", i ? "\n" : "", i);
        put(line);
    }
    CHECK(con.scrolls == 1);
    CHECK(!strcmp(row_text(0), "L30"));
    CHECK(!strcmp(row_text(29), "L59"));
    CHECK(!strcmp(row_text(30), "L60"));
    CHECK(con.row == 30 && con.text[31][0] == 0);
    /* the redrawn row 0 shows "L30": 'L' row 0 is 0x0F -> pixels 0..3 lit */
    CHECK(px[0] == CK_FBCON_FG && px[3] == CK_FBCON_FG && px[4] == CK_FBCON_BG);

    /* bytes outside 0x20..0x7e are drawn as '?' */
    put("\n\x01\xff");
    CHECK(!strcmp(row_text(31), "??"));

    return ck_t_verdict("test_fbcon");
}
