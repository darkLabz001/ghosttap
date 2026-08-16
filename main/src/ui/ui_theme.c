/*
 * GHOSTTAP UI — theme
 *
 * Cyberpunk / retro-CRT: neon cyan on void black, scanlines, HUD
 * brackets, glow titles.
 */
#include "ui/ui_theme.h"
#include "ui/ui.h"

lv_style_t ui_style_bg;
lv_style_t ui_style_panel;
lv_style_t ui_style_title;
lv_style_t ui_style_row;
lv_style_t ui_style_row_base;
lv_style_t ui_style_row_sel;
lv_style_t ui_style_val;
lv_style_t ui_style_footer;

void ui_theme_init(void)
{
    /* full-screen background */
    lv_style_init(&ui_style_bg);
    lv_style_set_bg_color(&ui_style_bg, CLR_BG);
    lv_style_set_bg_opa(&ui_style_bg, LV_OPA_COVER);
    lv_style_set_pad_all(&ui_style_bg, 0);
    lv_style_set_border_width(&ui_style_bg, 0);

    /* elevated panel */
    lv_style_init(&ui_style_panel);
    lv_style_set_bg_color(&ui_style_panel, CLR_BG_PANEL);
    lv_style_set_bg_opa(&ui_style_panel, LV_OPA_COVER);
    lv_style_set_border_color(&ui_style_panel, CLR_BORDER);
    lv_style_set_border_width(&ui_style_panel, 1);
    lv_style_set_radius(&ui_style_panel, 6);
    lv_style_set_pad_all(&ui_style_panel, 6);

    /* title — neon cyan, wide tracking */
    lv_style_init(&ui_style_title);
    lv_style_set_text_color(&ui_style_title, CLR_ACCENT);
    lv_style_set_text_font(&ui_style_title, &lv_font_montserrat_20);
    lv_style_set_text_letter_space(&ui_style_title, 3);

    /* menu row (text color inherited from the row object so the
       selection can recolor it) */
    lv_style_init(&ui_style_row);
    lv_style_set_text_font(&ui_style_row, &lv_font_montserrat_14);
    lv_style_set_pad_left(&ui_style_row, 8);

    /* unselected row (base). Applied once per row and never removed;
       ui_style_row_sel is added/removed on top of it to toggle
       selection — see row_render(). Using shared styles here instead of
       lv_obj_set_style_*() local overrides avoids a livelock in
       lv_timer_handler() that repeated local-style mutation of the same
       objects triggers after enough navigation cycles on this
       esp32c5 / esp_lvgl_port / LVGL 8.4 combo (confirmed empirically). */
    lv_style_init(&ui_style_row_base);
    lv_style_set_bg_opa(&ui_style_row_base, LV_OPA_TRANSP);
    lv_style_set_border_width(&ui_style_row_base, 0);
    lv_style_set_text_color(&ui_style_row_base, CLR_TEXT);

    /* selected row */
    lv_style_init(&ui_style_row_sel);
    lv_style_set_bg_color(&ui_style_row_sel, CLR_BG_ELEV);
    lv_style_set_bg_opa(&ui_style_row_sel, LV_OPA_COVER);
    lv_style_set_text_color(&ui_style_row_sel, CLR_ACCENT);
    lv_style_set_text_font(&ui_style_row_sel, &lv_font_montserrat_14);
    lv_style_set_pad_left(&ui_style_row_sel, 8);
    lv_style_set_border_color(&ui_style_row_sel, CLR_ACCENT_DIM);
    lv_style_set_border_width(&ui_style_row_sel, 1);

    /* trailing value */
    lv_style_init(&ui_style_val);
    lv_style_set_text_color(&ui_style_val, CLR_TEXT_DIM);
    lv_style_set_text_font(&ui_style_val, &lv_font_montserrat_14);

    /* footer */
    lv_style_init(&ui_style_footer);
    lv_style_set_text_color(&ui_style_footer, CLR_TEXT_DIM);
    lv_style_set_text_font(&ui_style_footer, &lv_font_montserrat_14);
    lv_style_set_text_letter_space(&ui_style_footer, 1);
}

void ui_theme_apply_bg(lv_obj_t *obj)
{
    lv_obj_remove_style_all(obj);
    lv_obj_add_style(obj, &ui_style_bg, 0);
}

lv_obj_t *ui_theme_panel(lv_obj_t *parent)
{
    lv_obj_t *p = lv_obj_create(parent);
    lv_obj_add_style(p, &ui_style_panel, 0);
    return p;
}

lv_obj_t *ui_theme_progress(lv_obj_t *parent, lv_coord_t w)
{
    lv_obj_t *bar = lv_bar_create(parent);
    lv_obj_set_size(bar, w, 8);
    lv_obj_set_style_bg_color(bar, CLR_BG_ELEV, LV_PART_MAIN);
    lv_obj_set_style_bg_color(bar, CLR_ACCENT, LV_PART_INDICATOR);
    lv_obj_set_style_border_width(bar, 0, LV_PART_MAIN);
    lv_obj_set_style_radius(bar, 0, LV_PART_MAIN);
    lv_obj_set_style_radius(bar, 0, LV_PART_INDICATOR);
    lv_bar_set_range(bar, 0, 100);
    lv_bar_set_value(bar, 0, LV_ANIM_OFF);
    return bar;
}

/* ---- retro effects -------------------------------------------------- */

static lv_obj_t *fx_rect(lv_obj_t *parent, lv_coord_t x, lv_coord_t y,
                         lv_coord_t w, lv_coord_t h, lv_color_t c,
                         lv_opa_t opa)
{
    lv_obj_t *r = lv_obj_create(parent);
    lv_obj_set_pos(r, x, y);
    lv_obj_set_size(r, w, h);
    lv_obj_set_style_bg_color(r, c, 0);
    lv_obj_set_style_bg_opa(r, opa, 0);
    lv_obj_set_style_border_width(r, 0, 0);
    lv_obj_set_style_radius(r, 0, 0);
    return r;
}

void ui_theme_scanlines(lv_obj_t *parent)
{
    /* faint CRT raster — spaced widely and kept very dim so text stays
       crisp underneath */
    for (lv_coord_t y = 4; y < UI_H; y += 8) {
        fx_rect(parent, 0, y, UI_W, 1, lv_color_hex(0x000000), LV_OPA_20);
    }
}

void ui_theme_corners(lv_obj_t *parent, lv_coord_t m, lv_coord_t len,
                      lv_color_t c)
{
    lv_coord_t t = 2;                       /* bracket thickness */
    /* top-left */ fx_rect(parent, m, m, len, t, c, LV_OPA_COVER);
                    fx_rect(parent, m, m, t, len, c, LV_OPA_COVER);
    /* top-right */ fx_rect(parent, UI_W - m - len, m, len, t, c, LV_OPA_COVER);
                    fx_rect(parent, UI_W - m - t, m, t, len, c, LV_OPA_COVER);
    /* bottom-left */ fx_rect(parent, m, UI_H - m - t, len, t, c, LV_OPA_COVER);
                      fx_rect(parent, m, UI_H - m - len, t, len, c, LV_OPA_COVER);
    /* bottom-right */ fx_rect(parent, UI_W - m - len, UI_H - m - t, len, t, c, LV_OPA_COVER);
                       fx_rect(parent, UI_W - m - t, UI_H - m - len, t, len, c, LV_OPA_COVER);
}

lv_obj_t *ui_theme_glow_text(lv_obj_t *parent, const char *text,
                             const lv_font_t *font, lv_color_t c,
                             lv_color_t glow, lv_coord_t x, lv_coord_t y)
{
    /* tight neon halo: ±1px copies behind the main glyph — enough for
       the CRT bloom feel without smearing the text */
    lv_obj_t *h1 = lv_label_create(parent);
    lv_obj_set_style_text_font(h1, font, 0);
    lv_obj_set_style_text_color(h1, glow, 0);
    lv_obj_set_style_text_opa(h1, LV_OPA_20, 0);
    lv_obj_set_pos(h1, x - 1, y - 1);
    lv_label_set_text(h1, text);

    lv_obj_t *lbl = lv_label_create(parent);
    lv_obj_set_style_text_font(lbl, font, 0);
    lv_obj_set_style_text_color(lbl, c, 0);
    lv_obj_set_pos(lbl, x, y);
    lv_label_set_text(lbl, text);
    return lbl;
}
