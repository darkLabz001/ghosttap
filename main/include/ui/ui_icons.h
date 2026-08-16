/*
 * GHOSTTAP UI — icons
 *
 * Small vector-ish glyphs built from LVGL primitives so no custom font
 * is required.  Each icon is drawn into a square container.
 */
#pragma once

#include "lvgl.h"
#include "ui/ui.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Draw the glyph for `screen` centered inside `host` at (x,y), size px. */
void ui_icon_draw(lv_obj_t *host, ui_screen_t screen, lv_color_t color,
                  lv_coord_t x, lv_coord_t y, lv_coord_t size);

#ifdef __cplusplus
}
#endif
