/*
 * GHOSTTAP UI — icons
 *
 * Small glyphs built from LVGL primitives (lines, arcs, rectangles) so
 * no custom bitmap font is required.  Icons are drawn into a `size`x`size`
 * box placed at (x, y) relative to `host`.
 *
 * NOTE: lv_line keeps a pointer to its point array, so arrays are
 * `static` and filled at runtime (LVGL 8 API).
 */
#include "ui/ui_icons.h"

/* ---- helpers ------------------------------------------------------- */
static void icon_line(lv_obj_t *host, const lv_point_t *pts, uint16_t n,
                      lv_coord_t x, lv_coord_t y, lv_color_t c)
{
    lv_obj_t *line = lv_line_create(host);
    lv_line_set_points(line, pts, n);
    lv_obj_set_pos(line, x, y);
    lv_obj_set_style_line_color(line, c, 0);
    lv_obj_set_style_line_width(line, 2, 0);
    lv_obj_set_style_line_rounded(line, true, 0);
}

static void icon_dot(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                     lv_coord_t d, lv_color_t c)
{
    lv_obj_t *dot = lv_obj_create(host);
    lv_obj_set_size(dot, d, d);
    lv_obj_set_pos(dot, x, y);
    lv_obj_set_style_bg_color(dot, c, 0);
    lv_obj_set_style_bg_opa(dot, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(dot, 0, 0);
    lv_obj_set_style_radius(dot, LV_RADIUS_CIRCLE, 0);
}

static void icon_arc(lv_obj_t *host, lv_coord_t cx, lv_coord_t cy,
                     lv_coord_t r, lv_color_t c)
{
    lv_obj_t *arc = lv_arc_create(host);
    lv_obj_set_size(arc, r * 2, r * 2);
    lv_obj_set_pos(arc, cx - r, cy - r);
    lv_obj_set_style_arc_width(arc, 2, LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(arc, c, LV_PART_INDICATOR);
    lv_obj_set_style_arc_rounded(arc, true, LV_PART_INDICATOR);
    lv_obj_set_style_arc_width(arc, 2, LV_PART_MAIN);
    lv_obj_set_style_arc_color(arc, c, LV_PART_MAIN);
    lv_obj_set_style_arc_opa(arc, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_arc_set_rotation(arc, 0);
    lv_arc_set_bg_angles(arc, 225, 315);      /* upper arc */
    lv_arc_set_start_angle(arc, 225);
    lv_arc_set_end_angle(arc, 315);
    lv_arc_set_value(arc, 100);
}

static void icon_box(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                     lv_coord_t w, lv_coord_t h, lv_color_t c)
{
    lv_obj_t *box = lv_obj_create(host);
    lv_obj_set_size(box, w, h);
    lv_obj_set_pos(box, x, y);
    lv_obj_set_style_border_color(box, c, 0);
    lv_obj_set_style_border_width(box, 2, 0);
    lv_obj_set_style_bg_opa(box, LV_OPA_TRANSP, 0);
    lv_obj_set_style_radius(box, 2, 0);
}

/* ---- per-icon glyphs ------------------------------------------------ */
static void icon_wifi(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                      lv_coord_t size, lv_color_t c)
{
    lv_coord_t cx = x + size / 2;
    lv_coord_t cy = y + size - 2;
    icon_arc(host, cx, cy, size / 2 - 2, c);
    icon_arc(host, cx, cy, size / 3, c);
    icon_arc(host, cx, cy, size / 6, c);
    icon_dot(host, cx - 2, cy - 2, 4, c);
}

static void icon_radar(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                       lv_coord_t size, lv_color_t c)
{
    static lv_point_t sweep[2];
    lv_coord_t cx = x + size / 2;
    lv_coord_t cy = y + size / 2;
    sweep[0].x = 0;  sweep[0].y = 0;
    sweep[1].x = 6;  sweep[1].y = -8;
    icon_box(host, x + 1, y + 1, size - 2, size - 2, c);
    icon_dot(host, cx - 2, cy - 2, 4, c);
    icon_line(host, sweep, 2, cx, cy, c);
    icon_dot(host, cx + 4, cy - 6, 3, c);
}

static void icon_skull(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                       lv_coord_t size, lv_color_t c)
{
    static lv_point_t jaw[4];
    lv_coord_t cx = x + size / 2;
    lv_coord_t cy = y + size / 2;
    jaw[0].x = 2;      jaw[0].y = size - 6;
    jaw[1].x = 2;      jaw[1].y = 6;
    jaw[2].x = size - 2; jaw[2].y = 6;
    jaw[3].x = size - 2; jaw[3].y = size - 6;
    icon_line(host, jaw, 4, x, y + 4, c);
    icon_dot(host, cx - size / 4 - 2, cy - 3, 4, c);
    icon_dot(host, cx + size / 4 - 2, cy - 3, 4, c);
    icon_dot(host, cx - 1, cy + size / 5, 3, c);
}

static void icon_ble(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                     lv_coord_t size, lv_color_t c)
{
    static lv_point_t spine[2];
    static lv_point_t bar_t[2];
    static lv_point_t bar_m[2];
    static lv_point_t bar_b[2];

    spine[0].x = 3; spine[0].y = 0;   spine[1].x = 3; spine[1].y = size;
    bar_t[0].x = 3; bar_t[0].y = 3;   bar_t[1].x = size - 3; bar_t[1].y = 3;
    bar_m[0].x = 3; bar_m[0].y = size / 2; bar_m[1].x = size - 1; bar_m[1].y = size / 2;
    bar_b[0].x = 3; bar_b[0].y = size - 3; bar_b[1].x = size - 4; bar_b[1].y = size - 3;

    icon_line(host, spine, 2, x, y, c);
    icon_line(host, bar_t, 2, x, y, c);
    icon_line(host, bar_m, 2, x, y, c);
    icon_line(host, bar_b, 2, x, y, c);
}

static void icon_bolt(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                      lv_coord_t size, lv_color_t c)
{
    static lv_point_t bolt[6];
    bolt[0].x = 8;  bolt[0].y = 0;
    bolt[1].x = 0;  bolt[1].y = 10;
    bolt[2].x = 5;  bolt[2].y = 10;
    bolt[3].x = 2;  bolt[3].y = size;
    bolt[4].x = 11; bolt[4].y = 5;
    bolt[5].x = 6;  bolt[5].y = 5;
    icon_line(host, bolt, 6, x, y, c);
}

static void icon_sd(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                    lv_coord_t size, lv_color_t c)
{
    static lv_point_t data[2];
    data[0].x = 4; data[0].y = 6;
    data[1].x = size - 4; data[1].y = 6;
    icon_box(host, x + 1, y, size - 2, size - 1, c);
    icon_box(host, x + size / 2, y + 2, size / 4, size / 4, c);
    icon_line(host, data, 2, x, y + size / 2 + 2, c);
}

static void icon_home(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                      lv_coord_t size, lv_color_t c)
{
    static lv_point_t roof[3];
    static lv_point_t wall[4];
    roof[0].x = 1; roof[0].y = size / 2;
    roof[1].x = size / 2; roof[1].y = 1;
    roof[2].x = size - 1; roof[2].y = size / 2;

    wall[0].x = 3; wall[0].y = size / 2;
    wall[1].x = 3; wall[1].y = size - 1;
    wall[2].x = size - 3; wall[2].y = size - 1;
    wall[3].x = size - 3; wall[3].y = size / 2;

    icon_line(host, roof, 3, x, y, c);
    icon_line(host, wall, 4, x, y + 1, c);
    icon_dot(host, x + size / 2 - 2, y + size / 2 + 2, 4, c);
}

static void icon_portal(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                       lv_coord_t size, lv_color_t c)
{
    icon_wifi(host, x, y + 2, size - 6, c);
    icon_box(host, x + size / 2 - 4, y + size - 7, 8, 6, c);
    icon_dot(host, x + size / 2 - 2, y + size - 5, 4, c);
}

static void icon_key(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                     lv_coord_t size, lv_color_t c)
{
    static lv_point_t shaft[2];
    shaft[0].x = size / 3; shaft[0].y = size / 3;
    shaft[1].x = size - 2; shaft[1].y = size - 2;
    icon_dot(host, x + size / 3 - 4, y + size / 3 - 4, size / 3, c);
    icon_line(host, shaft, 2, x, y, c);
    icon_dot(host, x + size - 6, y + size - 8, 3, c);
    icon_dot(host, x + size - 10, y + size - 4, 3, c);
}

static void icon_kbd(lv_obj_t *host, lv_coord_t x, lv_coord_t y,
                     lv_coord_t size, lv_color_t c)
{
    icon_box(host, x + 1, y + 3, size - 2, size - 7, c);
    for (int r = 0; r < 2; r++) {
        for (int k = 0; k < 4; k++) {
            icon_dot(host, x + 4 + k * 3, y + 6 + r * 3, 2, c);
        }
    }
    icon_dot(host, x + size / 2 - 3, y + size - 5, 2, c);
}

/* ---- dispatcher ----------------------------------------------------- */
void ui_icon_draw(lv_obj_t *host, ui_screen_t screen, lv_color_t color,
                  lv_coord_t x, lv_coord_t y, lv_coord_t size)
{
    switch (screen) {
    case UI_SCREEN_HOME:       icon_home(host, x, y, size, color); break;
    case UI_SCREEN_WIFI_SCAN:  icon_wifi(host, x, y, size, color); break;
    case UI_SCREEN_SNIFFER:    icon_radar(host, x, y, size, color); break;
    case UI_SCREEN_HANDSHAKE:  icon_key(host, x, y, size, color); break;
    case UI_SCREEN_ATTACK:     icon_skull(host, x, y, size, color); break;
    case UI_SCREEN_BLE_SCAN:   icon_ble(host, x, y, size, color); break;
    case UI_SCREEN_BLE_SPAM:   icon_ble(host, x, y, size, color); break;
    case UI_SCREEN_BLE_HID:    icon_kbd(host, x, y, size, color); break;
    case UI_SCREEN_ZB_SNIFF:   icon_bolt(host, x, y, size, color); break;
    case UI_SCREEN_LOGGER:     icon_sd(host, x, y, size, color); break;
    case UI_SCREEN_EVIL:       icon_portal(host, x, y, size, color); break;
    case UI_SCREEN_KARMA:      icon_portal(host, x, y, size, color); break;
    case UI_SCREEN_WIDS:       icon_skull(host, x, y, size, color); break;
    case UI_SCREEN_TRACKER:    icon_ble(host, x, y, size, color); break;
    default: break;
    }
}
