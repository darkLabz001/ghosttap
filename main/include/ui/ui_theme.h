/*
 * GHOSTTAP UI — theme (palette + shared styles)
 *
 * Cyberpunk / retro-CRT look: near-black blue background, neon cyan
 * primary, hot magenta secondary, CRT scanlines and HUD corner brackets.
 */
#pragma once

#include "lvgl.h"
#include "board.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- neon palette ------------------------------------------------- */
#define CLR_BG          lv_color_hex(0x05060e)   /* void black-blue     */
#define CLR_BG_PANEL    lv_color_hex(0x0a0d1a)   /* raised panel        */
#define CLR_BG_ELEV     lv_color_hex(0x10142a)   /* selected row        */
#define CLR_BORDER      lv_color_hex(0x1e2a52)   /* dim neon edge       */
#define CLR_ACCENT      lv_color_hex(0x00f0ff)   /* neon cyan           */
#define CLR_ACCENT_DIM  lv_color_hex(0x0a8f9e)   /* cyan @ 60%          */
#define CLR_TEXT        lv_color_hex(0xe8f8ff)   /* ice white           */
#define CLR_TEXT_DIM    lv_color_hex(0x93b7d1)   /* steel — readable    */
#define CLR_ALERT       lv_color_hex(0xff2d6f)   /* hot pink-red        */
#define CLR_WARN        lv_color_hex(0xffb020)   /* amber               */
#define CLR_INFO        lv_color_hex(0xff00c8)   /* magenta             */
#define CLR_PURPLE      lv_color_hex(0x9d4edd)   /* ultraviolet         */

/* Full-screen dark background + rounded elevated panel. */
void ui_theme_apply_bg(lv_obj_t *obj);
lv_obj_t *ui_theme_panel(lv_obj_t *parent);

/* Reusable styles (must be initialized once via ui_theme_init()). */
void ui_theme_init(void);

/* Shared style handles used by the screen builders. */
extern lv_style_t ui_style_bg;
extern lv_style_t ui_style_panel;
extern lv_style_t ui_style_title;
extern lv_style_t ui_style_row;
extern lv_style_t ui_style_row_base;
extern lv_style_t ui_style_row_sel;
extern lv_style_t ui_style_val;
extern lv_style_t ui_style_footer;

/* Small helper: progress bar with terminal look. */
lv_obj_t *ui_theme_progress(lv_obj_t *parent, lv_coord_t w);

/* ---- retro effects ------------------------------------------------- */

/* CRT scanline overlay across the whole screen (place after content). */
void ui_theme_scanlines(lv_obj_t *parent);

/* HUD corner brackets: 4 L-shaped neon corners inset by `m`. */
void ui_theme_corners(lv_obj_t *parent, lv_coord_t m, lv_coord_t len,
                      lv_color_t c);

/* Neon "glow" text: draws `text` in `c` with a soft halo of `glow`.
 * Returns the main label (positioned at x,y; halo sits behind it). */
lv_obj_t *ui_theme_glow_text(lv_obj_t *parent, const char *text,
                             const lv_font_t *font, lv_color_t c,
                             lv_color_t glow, lv_coord_t x, lv_coord_t y);

#ifdef __cplusplus
}
#endif
