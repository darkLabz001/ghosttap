/*
 * GHOSTTAP UI — screens
 *
 * Single-button UX: SHORT = move highlight, LONG = select.
 * Every screen is a vertical menu; tool screens get a live stats header
 * and a set of action rows.  All UI runs in the ui_task (app_main.c).
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "app.h"
#include "board.h"
#include "ui/ui.h"
#include "ui/ui_theme.h"
#include "ui/ui_icons.h"
#include "ui/ui_screens.h"

#include "modules/wifi_scan.h"
#include "modules/wifi_sniff.h"
#include "modules/wifi_attack.h"
#include "modules/wifi_handshake.h"
#include "modules/wids.h"
#include "modules/ble_scan.h"
#include "modules/ble_spam.h"
#include "modules/ble_hid.h"
#include "modules/zb_sniff.h"
#include "modules/sd_log.h"
#include "modules/sys_led.h"
#include "modules/evil_portal.h"

static void scan_worker(void *arg);
static void ble_worker(void *arg);

#define TITLE_H   30
#define FOOTER_H  22
#define ROW_H     24
#define ROW_W     (UI_W - 8)
#define MAX_DYN   13

static ui_menu_t     s_menu;
static lv_obj_t     *s_stats;          /* tool-screen live header   */
static ui_screen_t   s_screen;
static uint8_t       s_base_count;     /* rows before dynamic ones  */
static bool          s_scan_running;
static bool          s_ble_running;
static bool          s_zb_running;
static bool          s_sniff_running;
static bool          s_hs_running;
static bool          s_passive;
static bool          s_picking_target;
static uint32_t      s_sniff_pps_last_total;
static uint32_t      s_sniff_pps_last_ms;
static uint8_t       s_zb_channel = 15;
static uint8_t       s_target_bssid[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static char          s_target_ssid[33] = "GHOSTTAP";
static uint8_t       s_target_channel = 6;
static lv_obj_t     *s_home_dots[APP_RADIO_COUNT];
static lv_obj_t     *s_home_dot_labels[APP_RADIO_COUNT];
static int8_t        s_home_dot_active[APP_RADIO_COUNT];

static bool          s_karma_running;
static size_t         s_karma_last_count;

static bool           s_wids_running;
static uint32_t       s_wids_last_deauth;
static uint32_t       s_wids_last_disassoc;
static bool           s_wids_last_alert;
static uint32_t       s_wids_last_text_ms;

static uint32_t       s_tracker_last_count;

/* ================================================================== */
/* Menu framework                                                     */
/* ================================================================== */

lv_obj_t *ui_menu_build(ui_menu_t *m, const char *title)
{
    memset(m, 0, sizeof(*m));
    snprintf(m->title, sizeof(m->title), "%s", title);
    m->start_y = 6;
    m->row_h = ROW_H;

    lv_obj_t *root = lv_obj_create(ui_scr());
    ui_theme_apply_bg(root);
    lv_obj_set_size(root, UI_W, UI_H);
    m->root = root;

    m->title_lbl = lv_label_create(root);
    lv_obj_add_style(m->title_lbl, &ui_style_title, 0);
    lv_obj_set_pos(m->title_lbl, 10, 4);
    lv_label_set_text(m->title_lbl, m->title);

    lv_obj_t *rule = lv_obj_create(root);
    lv_obj_set_size(rule, UI_W - 20, 1);
    lv_obj_set_pos(rule, 10, TITLE_H - 2);
    lv_obj_set_style_bg_color(rule, CLR_BORDER, 0);
    lv_obj_set_style_bg_opa(rule, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(rule, 0, 0);

    m->body = lv_obj_create(root);
    lv_obj_set_pos(m->body, 0, TITLE_H);
    lv_obj_set_size(m->body, UI_W, UI_H - TITLE_H - FOOTER_H);
    lv_obj_set_style_bg_opa(m->body, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(m->body, 0, 0);
    lv_obj_clear_flag(m->body, LV_OBJ_FLAG_SCROLLABLE);

    m->footer_lbl = lv_label_create(root);
    lv_obj_add_style(m->footer_lbl, &ui_style_footer, 0);
    lv_obj_set_pos(m->footer_lbl, 10, UI_H - FOOTER_H + 3);

    return m->body;
}

static void row_render(ui_menu_t *m, uint8_t idx)
{
    lv_obj_t *row = m->rows[idx];
    if (!row) return;

    bool sel = (idx == m->sel);
    lv_obj_set_style_bg_opa(row, sel ? LV_OPA_COVER : LV_OPA_TRANSP, 0);
    lv_obj_set_style_bg_color(row, sel ? CLR_BG_ELEV : CLR_BG_ELEV, 0);
    lv_obj_set_style_border_width(row, sel ? 1 : 0, 0);
    lv_obj_set_style_border_color(row, sel ? CLR_ACCENT_DIM : CLR_BORDER, 0);
    /* text color is inherited from the row by the label */
    lv_obj_set_style_text_color(row, sel ? CLR_ACCENT : CLR_TEXT, 0);
}

static void menu_append(ui_menu_t *m, const char *label, int icon,
                        void (*cb)(int idx))
{
    if (m->count >= 16) return;
    uint8_t idx = m->count++;

    lv_obj_t *row = lv_obj_create(m->body);
    lv_obj_set_size(row, ROW_W, m->row_h - 4);
    lv_obj_set_pos(row, 4, m->start_y + idx * m->row_h);
    lv_obj_set_style_radius(row, 4, 0);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    row_render(m, idx);

    if (icon >= 0) {
        ui_icon_draw(row, (ui_screen_t)icon, CLR_ACCENT, 5,
                     (m->row_h - 4 - 16) / 2, 16);
    }

    lv_obj_t *lbl = lv_label_create(row);
    lv_obj_add_style(lbl, &ui_style_row, 0);
    lv_obj_set_pos(lbl, (icon >= 0) ? 26 : 8, 3);
    lv_label_set_text(lbl, label);

    lv_obj_t *val = lv_label_create(row);
    lv_obj_add_style(val, &ui_style_val, 0);
    lv_obj_set_width(val, 64);
    lv_obj_set_pos(val, ROW_W - 70, 3);
    lv_label_set_long_mode(val, LV_LABEL_LONG_DOT);
    lv_obj_set_style_text_align(val, LV_TEXT_ALIGN_RIGHT, 0);

    m->items[idx].label = label;
    m->items[idx].cb = cb;
    m->items[idx].value_color = CLR_TEXT_DIM;
    m->items[idx].value[0] = 0;
    m->rows[idx] = row;
    m->vals[idx] = val;

    /* No LV_OBJ_FLAG_SCROLLABLE here: overflowing rows are windowed
       manually (see menu_relayout()), not scrolled — see its comment.
       Hide this row up front if it doesn't fit in the current window;
       menu_relayout() itself is defined further down, so just hide by
       position for now and let the first ui_menu_move() confirm it. */
    lv_coord_t body_h = lv_obj_get_height(m->body);
    uint8_t visible = (uint8_t)(body_h / m->row_h);
    if (visible == 0) visible = 1;
    if (idx >= visible) {
        lv_obj_add_flag(row, LV_OBJ_FLAG_HIDDEN);
    }
}

void ui_menu_add(ui_menu_t *m, const char *label, void (*cb)(int idx))
{
    menu_append(m, label, -1, cb);
}

void ui_menu_set_value(ui_menu_t *m, uint8_t idx, const char *fmt, ...)
{
    if (idx >= m->count || !m->vals[idx]) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(m->items[idx].value, sizeof(m->items[idx].value), fmt, args);
    va_end(args);
    lv_label_set_text(m->vals[idx], m->items[idx].value);
    lv_obj_set_style_text_color(m->vals[idx], m->items[idx].value_color, 0);
}

/* Keep the selected row in view by repositioning rows (manual "windowing")
 * rather than using LVGL's lv_obj_scroll_to_*() family. Any use of LVGL's
 * scroll machinery on this menu — even scoped to a single object with no
 * ancestor walk — reliably livelocks lv_timer_handler() within a handful
 * of navigation cycles on this esp32c5 / esp_lvgl_port / LVGL 8.4 combo
 * (confirmed empirically: zero scroll calls survives indefinitely, any
 * scroll calls eventually hang). So rows are just moved instead of scrolled.
 */
static void menu_relayout(ui_menu_t *m)
{
    lv_coord_t body_h = lv_obj_get_height(m->body);
    uint8_t visible = (uint8_t)(body_h / m->row_h);
    if (visible == 0) visible = 1;

    if (m->sel < m->win_start) {
        m->win_start = m->sel;
    } else if (m->sel >= (uint8_t)(m->win_start + visible)) {
        m->win_start = m->sel - visible + 1;
    }

    for (uint8_t i = 0; i < m->count; i++) {
        lv_obj_t *row = m->rows[i];
        if (!row) continue;
        if (i >= m->win_start && i < m->win_start + visible) {
            lv_obj_clear_flag(row, LV_OBJ_FLAG_HIDDEN);
            lv_obj_set_pos(row, 4, m->start_y + (i - m->win_start) * m->row_h);
        } else {
            lv_obj_add_flag(row, LV_OBJ_FLAG_HIDDEN);
        }
    }
}

void ui_menu_move(ui_menu_t *m, int dir)
{
    if (m->count == 0) return;
    uint8_t old = m->sel;
    m->sel = (m->sel + dir + m->count) % m->count;
    if (old != m->sel) {
        row_render(m, old);
        row_render(m, m->sel);
    }
    menu_relayout(m);
}

void ui_menu_activate(ui_menu_t *m)
{
    if (m->count == 0) return;
    int idx = m->sel;
    if (m->items[idx].cb) m->items[idx].cb(idx);
}

void ui_menu_set_footer(ui_menu_t *m, const char *fmt, ...)
{
    char buf[96];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    lv_label_set_text(m->footer_lbl, buf);
}

static void ui_menu_trim(ui_menu_t *m, uint8_t base)
{
    while (m->count > base) {
        uint8_t i = --m->count;
        if (m->rows[i]) lv_obj_del(m->rows[i]);
        m->rows[i] = NULL;
        m->vals[i] = NULL;
        m->items[i].cb = NULL;
    }
    m->sel = 0;
    m->win_start = 0;
    row_render(m, 0);
}

ui_menu_t *ui_active_menu(void)
{
    return &s_menu;
}

/* ================================================================== */
/* Screen navigation                                                  */
/* ================================================================== */

void ui_show(ui_screen_t screen)
{
    if (s_menu.root) lv_obj_del(s_menu.root);
    s_menu.root = NULL;
    s_screen = screen;
    s_stats = NULL;
    ui_screens_open(screen);
}

ui_screen_t ui_current(void)
{
    return s_screen;
}

/* ================================================================== */
/* Tool screens                                                        */
/* ================================================================== */

static void stats_header(ui_menu_t *m)
{
    s_stats = lv_label_create(m->body);
    lv_obj_add_style(s_stats, &ui_style_footer, 0);
    lv_obj_set_style_text_color(s_stats, CLR_INFO, 0);
    lv_obj_set_width(s_stats, UI_W - 20);
    lv_obj_set_pos(s_stats, 10, 3);
    lv_label_set_long_mode(s_stats, LV_LABEL_LONG_DOT);
    lv_label_set_text(s_stats, "-");
    m->start_y = 26;
}

/* ---- navigation callbacks ----------------------------------------- */
static void cb_back(int idx) { ui_show(UI_SCREEN_HOME); }

static void home_open(void);
static void home_tick(void);

static void cb_open_scan(int idx)   { ui_show(UI_SCREEN_WIFI_SCAN); }
static void cb_open_sniff(int idx)  { ui_show(UI_SCREEN_SNIFFER); }
static void cb_open_hand(int idx)   { ui_show(UI_SCREEN_HANDSHAKE); }
static void cb_open_attack(int idx) { ui_show(UI_SCREEN_ATTACK); }
static void cb_open_ble(int idx)    { ui_show(UI_SCREEN_BLE_SCAN); }
static void cb_open_spam(int idx)   { ui_show(UI_SCREEN_BLE_SPAM); }
static void cb_open_hid(int idx)    { ui_show(UI_SCREEN_BLE_HID); }
static void cb_open_zb(int idx)     { ui_show(UI_SCREEN_ZB_SNIFF); }
static void cb_open_logger(int idx) { ui_show(UI_SCREEN_LOGGER); }
static void cb_open_evil(int idx)   { ui_show(UI_SCREEN_EVIL); }
static void cb_open_karma(int idx)   { ui_show(UI_SCREEN_KARMA); }
static void cb_open_wids(int idx)    { ui_show(UI_SCREEN_WIDS); }
static void cb_open_tracker(int idx) { ui_show(UI_SCREEN_TRACKER); }

/* ================================================================== */
/* Boot + Home                                                        */
/* ================================================================== */

/* ================================================================== */
/* Boot — cyberpunk POST sequence                                      */
/* ================================================================== */

#define BOOT_LOG_LINES 5
#define BOOT_BLOCKS    24
#define BOOT_DURATION_MS 3400

static const char *const s_boot_log[BOOT_LOG_LINES] = {
    "> ghosttap bios v0.3 // cold boot",
    "[ OK ] radio .. wifi6/ble5/802.15.4",
    "[ OK ] usb bridge online",
    "[ OK ] 12 modules loaded",
    "> access: GRANTED_",
};
static lv_obj_t *s_boot_lines[BOOT_LOG_LINES];
static lv_obj_t *s_boot_blocks[BOOT_BLOCKS];
static lv_obj_t *s_boot_title_cyan;
static lv_obj_t *s_boot_title_mag;
static uint32_t   s_boot_t0;

void ui_screens_boot(void)
{
    s_screen = UI_SCREEN_BOOT;
    s_boot_t0 = (uint32_t)(esp_timer_get_time() / 1000);

    lv_obj_t *root = lv_obj_create(ui_scr());
    ui_theme_apply_bg(root);
    lv_obj_set_size(root, UI_W, UI_H);

    /* chromatic-aberration title: magenta ghost + cyan glow text */
    s_boot_title_mag = lv_label_create(root);
    lv_obj_set_style_text_font(s_boot_title_mag, &lv_font_montserrat_28, 0);
    lv_obj_set_style_text_color(s_boot_title_mag, CLR_INFO, 0);
    lv_obj_set_pos(s_boot_title_mag, 112, 12);
    lv_label_set_text(s_boot_title_mag, "GHOSTTAP");

    s_boot_title_cyan = ui_theme_glow_text(root, "GHOSTTAP",
                                           &lv_font_montserrat_28,
                                           CLR_ACCENT, CLR_ACCENT, 110, 10);

    lv_obj_t *sub = lv_label_create(root);
    lv_obj_add_style(sub, &ui_style_footer, 0);
    lv_obj_set_style_text_color(sub, CLR_INFO, 0);
    lv_obj_set_pos(sub, 91, 40);
    lv_label_set_text(sub, "// PENTEST FIELD UNIT");

    /* boot log, revealed line by line */
    for (int i = 0; i < BOOT_LOG_LINES; i++) {
        s_boot_lines[i] = lv_label_create(root);
        lv_obj_add_style(s_boot_lines[i], &ui_style_footer, 0);
        lv_obj_set_pos(s_boot_lines[i], 20, 62 + i * 14);
        lv_obj_set_style_text_color(s_boot_lines[i],
            (i == BOOT_LOG_LINES - 1) ? CLR_INFO : CLR_TEXT_DIM, 0);
        lv_label_set_text(s_boot_lines[i], "");
    }

    /* segmented load bar (centered) */
    for (int i = 0; i < BOOT_BLOCKS; i++) {
        s_boot_blocks[i] = lv_obj_create(root);
        lv_obj_set_pos(s_boot_blocks[i], 54 + i * 9, 138);
        lv_obj_set_size(s_boot_blocks[i], 6, 6);
        lv_obj_set_style_radius(s_boot_blocks[i], 0, 0);
        lv_obj_set_style_border_width(s_boot_blocks[i], 0, 0);
        lv_obj_set_style_bg_color(s_boot_blocks[i], CLR_BORDER, 0);
        lv_obj_set_style_bg_opa(s_boot_blocks[i], LV_OPA_COVER, 0);
    }

    ui_theme_corners(root, 4, 16, CLR_ACCENT_DIM);
    ui_theme_scanlines(root);

    s_menu.root = root;
}

static void boot_tick(void)
{
    uint32_t el = (uint32_t)(esp_timer_get_time() / 1000) - s_boot_t0;

    /* staged log reveal */
    uint32_t stage = el / 520;
    for (uint32_t i = 0; i < BOOT_LOG_LINES; i++) {
        if (s_boot_lines[i]) {
            lv_label_set_text(s_boot_lines[i],
                              (i < stage) ? s_boot_log[i] : "");
        }
    }

    /* load blocks fill cyan, last one runs hot magenta */
    uint32_t filled = el * BOOT_BLOCKS / BOOT_DURATION_MS;
    if (filled > BOOT_BLOCKS) filled = BOOT_BLOCKS;
    for (uint32_t i = 0; i < BOOT_BLOCKS; i++) {
        lv_obj_set_style_bg_color(s_boot_blocks[i],
            i < filled ? ((i == filled - 1) ? CLR_INFO : CLR_ACCENT)
                       : CLR_BORDER, 0);
    }

    /* occasional glitch jitter on the title while booting */
    if (stage < BOOT_LOG_LINES && (esp_random() & 15) == 0) {
        lv_coord_t dx = (lv_coord_t)(esp_random() % 5) - 2;
        lv_coord_t dy = (lv_coord_t)(esp_random() % 3) - 1;
        lv_obj_set_pos(s_boot_title_mag, 112 + dx * 2, 12 + dy);
        lv_obj_set_pos(s_boot_title_cyan, 110 - dx, 10 + dy);
    } else {
        lv_obj_set_pos(s_boot_title_mag, 112, 12);
        lv_obj_set_pos(s_boot_title_cyan, 110, 10);
    }

    if (el >= BOOT_DURATION_MS) {
        ui_show(UI_SCREEN_HOME);
    }
}

static lv_obj_t *s_home_cursor;

static void home_open(void)
{
    ui_menu_t *m = &s_menu;
    lv_obj_t *body = ui_menu_build(m, "GHOSTTAP://");
    (void)body;

    /* blinking terminal cursor after the title */
    s_home_cursor = lv_label_create(m->root);
    lv_obj_add_style(s_home_cursor, &ui_style_title, 0);
    lv_obj_set_style_text_color(s_home_cursor, CLR_INFO, 0);
    lv_obj_set_pos(s_home_cursor, 118, 4);
    lv_label_set_text(s_home_cursor, "_");

    menu_append(m, "WiFi Scan", UI_SCREEN_WIFI_SCAN, cb_open_scan);
    menu_append(m, "Sniffer",   UI_SCREEN_SNIFFER, cb_open_sniff);
    menu_append(m, "Handshakes", UI_SCREEN_HANDSHAKE, cb_open_hand);
    menu_append(m, "Attacks",   UI_SCREEN_ATTACK, cb_open_attack);
    menu_append(m, "BLE Scan",  UI_SCREEN_BLE_SCAN, cb_open_ble);
    menu_append(m, "BLE Spam",  UI_SCREEN_BLE_SPAM, cb_open_spam);
    menu_append(m, "BLE HID",   UI_SCREEN_BLE_HID, cb_open_hid);
    menu_append(m, "Zigbee",    UI_SCREEN_ZB_SNIFF, cb_open_zb);
    menu_append(m, "Logger",    UI_SCREEN_LOGGER, cb_open_logger);
    menu_append(m, "Evil Portal", UI_SCREEN_EVIL, cb_open_evil);
    menu_append(m, "Karma",     UI_SCREEN_KARMA, cb_open_karma);
    menu_append(m, "WIDS Alarm", UI_SCREEN_WIDS, cb_open_wids);
    menu_append(m, "Trackers",  UI_SCREEN_TRACKER, cb_open_tracker);

    static const char names[] = "W B Z S";
    for (int i = 0; i < APP_RADIO_COUNT; i++) {
        s_home_dots[i] = lv_obj_create(m->root);
        lv_obj_set_size(s_home_dots[i], 8, 8);
        lv_obj_set_pos(s_home_dots[i], 250 + i * 16, UI_H - FOOTER_H + 5);
        lv_obj_set_style_radius(s_home_dots[i], LV_RADIUS_CIRCLE, 0);
        lv_obj_set_style_border_width(s_home_dots[i], 0, 0);
        bool active0 = app_radio_get((app_radio_t)i) == RADIO_STATE_ACTIVE;
        lv_obj_set_style_bg_color(s_home_dots[i],
            active0 ? CLR_ACCENT : lv_color_hex(0x161c33), 0);
        lv_obj_set_style_bg_opa(s_home_dots[i], LV_OPA_COVER, 0);
        s_home_dot_active[i] = (int8_t)active0;

        s_home_dot_labels[i] = lv_label_create(m->root);
        lv_obj_add_style(s_home_dot_labels[i], &ui_style_footer, 0);
        lv_obj_set_pos(s_home_dot_labels[i], 200 + i * 26, UI_H - FOOTER_H + 2);
        lv_label_set_text(s_home_dot_labels[i], (const char[]) { names[i * 2], 0 });
    }
    ui_menu_set_footer(m, "SHORT=NEXT LONG=SELECT");
    ui_theme_corners(m->root, 2, 12, CLR_BORDER);
    home_tick();
}

static void home_tick(void)
{
    static uint32_t last_blink;
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);

    /* home_tick() runs at 20Hz. Re-applying LVGL styles unconditionally
       here — even when nothing changed — invalidates/refreshes these
       objects up to 160 times/sec forever, which reliably livelocks
       lv_timer_handler() after enough accumulated churn on this
       esp32c5 / esp_lvgl_port / LVGL 8.4 combo (confirmed empirically).
       Only touch the style when a dot's state actually changes. */
    for (int i = 0; i < APP_RADIO_COUNT; i++) {
        if (!s_home_dots[i]) continue;
        bool active = app_radio_get((app_radio_t)i) == RADIO_STATE_ACTIVE;
        if (s_home_dot_active[i] == (int8_t)active) continue;
        s_home_dot_active[i] = (int8_t)active;
        lv_obj_set_style_bg_color(s_home_dots[i],
            active ? CLR_ACCENT : lv_color_hex(0x161c33), 0);
        lv_obj_set_style_bg_opa(s_home_dots[i], LV_OPA_COVER, 0);
    }

    /* cursor blinks at ~2 Hz */
    if (s_home_cursor) {
        if (now - last_blink > 500) {
            last_blink = now;
            const char *t = lv_label_get_text(s_home_cursor);
            lv_label_set_text(s_home_cursor, t[0] ? "" : "_");
        }
    }
}

void ui_screens_home(void)
{
    if (s_screen == UI_SCREEN_HOME) home_tick();
}

/* ================================================================== */
/* WiFi scan screen                                                    */
/* ================================================================== */

static void cb_scan_start(int idx)
{
    (void)idx;
    if (s_scan_running) return;
    s_scan_running = true;
    app_radio_set(APP_RADIO_WIFI, RADIO_STATE_ACTIVE);
    sys_led_set_mode(LED_MODE_SCAN);
    ui_menu_set_value(&s_menu, 1, "%s", s_passive ? "PASSIVE" : "ACTIVE");
    ui_menu_set_footer(&s_menu, "SCANNING...");

    if (wifi_scan_start(s_passive) != ESP_OK) {
        s_scan_running = false;
        ui_menu_set_footer(&s_menu, "SCAN FAILED");
        return;
    }
    xTaskCreate(scan_worker, "scanw", 3072, NULL, 5, NULL);
}

static void cb_scan_passive(int idx)
{
    (void)idx;
    s_passive = !s_passive;
    ui_menu_set_value(&s_menu, 2, "%s", s_passive ? "PASSIVE" : "ACTIVE");
}

static void scan_worker(void *arg)
{
    wifi_ap_t tmp[16];
    size_t n = 0;
    esp_err_t e = wifi_scan_wait_results(tmp, 16, &n, 15000);
    s_scan_running = false;
    sys_led_set_mode(LED_MODE_IDLE);
    ui_post(UI_EV_SCAN_DONE, (e == ESP_OK) ? 0 : -1, NULL);
    vTaskDelete(NULL);
}

void ui_screen_scan_refresh(void)
{
    if (s_screen != UI_SCREEN_WIFI_SCAN) return;
    size_t n = 0;
    const wifi_ap_t *aps = wifi_scan_get_results(&n);

    ui_menu_trim(&s_menu, s_base_count);
    for (size_t i = 0; i < n && i < MAX_DYN; i++) {
        const wifi_ap_t *ap = &aps[i];
        char label[33];
        snprintf(label, sizeof(label), "%s", ap->ssid);
        ui_menu_add(&s_menu, label, NULL);
        ui_menu_set_value(&s_menu, s_menu.count - 1, "ch%02u %ddBm %s",
                          ap->channel, ap->rssi, ap->band == WIFI_SCAN_BAND_2G4 ? "2G" : "5G");
    }
    ui_menu_set_footer(&s_menu, "%d APS", (int)n);
    app_radio_set(APP_RADIO_WIFI, RADIO_STATE_IDLE);
}

/* ================================================================== */
/* Sniffer screen                                                      */
/* ================================================================== */

static void cb_sniff_toggle(int idx)
{
    (void)idx;
    if (s_sniff_running) {
        wifi_sniff_stop();
        s_sniff_running = false;
        app_radio_set(APP_RADIO_WIFI, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    } else {
        if (wifi_sniff_start(0, true) == ESP_OK) {
            s_sniff_running = true;
            app_radio_set(APP_RADIO_WIFI, RADIO_STATE_ACTIVE);
            sys_led_set_mode(LED_MODE_SNIFF);
        }
    }
    ui_menu_set_value(&s_menu, 1, "%s", s_sniff_running ? "STOP" : "START");
}

static void cb_sniff_ch(int idx)
{
    (void)idx;
    if (s_sniff_running) {
        wifi_sniff_stop();
        s_sniff_running = false;
    }
    wifi_sniff_set_channel(36);   /* hop off + pick a 5G channel */
    sys_led_set_mode(LED_MODE_SNIFF);
}

static void sniff_tick(void)
{
    sniff_stats_t st;
    wifi_sniff_get_stats(&st);

    uint32_t now = esp_timer_get_time() / 1000;
    uint32_t pps = 0;
    if (s_sniff_pps_last_ms && (now - s_sniff_pps_last_ms) >= 1000) {
        pps = (st.total - s_sniff_pps_last_total) * 1000 / (now - s_sniff_pps_last_ms);
        s_sniff_pps_last_total = st.total;
        s_sniff_pps_last_ms = now;
    } else if (!s_sniff_pps_last_ms) {
        s_sniff_pps_last_total = st.total;
        s_sniff_pps_last_ms = now;
    }

    if (s_stats) {
        lv_label_set_text_fmt(s_stats,
            "PKT %lu  BCON %lu  BSSID %lu  PPS %lu  CH %u  RSSI %ddBm",
            (unsigned long)st.total, (unsigned long)st.beacons,
            (unsigned long)st.unique_bssid, (unsigned long)pps,
            st.channel, st.last_rssi);
    }
}

/* ================================================================== */
/* Attack screen                                                       */
/* ================================================================== */

static void pick_target(void)
{
    size_t n = 0;
    const wifi_ap_t *aps = wifi_scan_get_results(&n);
    if (n > 0) {
        memcpy(s_target_bssid, aps[0].bssid, 6);
        snprintf(s_target_ssid, sizeof(s_target_ssid), "%s", aps[0].ssid);
        s_target_channel = aps[0].channel;
    } else {
        memset(s_target_bssid, 0xff, 6);
        snprintf(s_target_ssid, sizeof(s_target_ssid), "GHOSTTAP");
        s_target_channel = 6;
    }
}

static void cb_attack_deauth(int idx)   { (void)idx; wifi_attack_start(ATTACK_DEAUTH, s_target_bssid, NULL, NULL, s_target_channel); sys_led_set_mode(LED_MODE_ATTACK); }
static void cb_attack_deauth_all(int idx) { (void)idx; uint8_t bc[6] = { 0xff,0xff,0xff,0xff,0xff,0xff }; wifi_attack_start(ATTACK_DEAUTH_ALL, s_target_bssid, bc, NULL, s_target_channel); sys_led_set_mode(LED_MODE_ATTACK); }
static void cb_attack_beacon(int idx)   { (void)idx; wifi_attack_start(ATTACK_BEACON, s_target_bssid, NULL, s_target_ssid, s_target_channel); sys_led_set_mode(LED_MODE_ATTACK); }
static void cb_attack_probe(int idx)    { (void)idx; wifi_attack_start(ATTACK_PROBE, s_target_bssid, NULL, s_target_ssid, s_target_channel); sys_led_set_mode(LED_MODE_ATTACK); }

static void cb_attack_stop(int idx)
{
    (void)idx;
    wifi_attack_stop();
    app_radio_set(APP_RADIO_WIFI, RADIO_STATE_IDLE);
    sys_led_set_mode(LED_MODE_IDLE);
}

/* ---- target picker ------------------------------------------------- */
static void cb_target_back(int idx)
{
    (void)idx;
    s_picking_target = false;
    ui_show(UI_SCREEN_ATTACK);
}

static void cb_target_pick(int idx)
{
    int apidx = idx - 1;             /* row 0 is "< Back"          */
    size_t n = 0;
    const wifi_ap_t *aps = wifi_scan_get_results(&n);
    if (apidx >= 0 && apidx < (int)n) {
        memcpy(s_target_bssid, aps[apidx].bssid, 6);
        snprintf(s_target_ssid, sizeof(s_target_ssid), "%s", aps[apidx].ssid);
        s_target_channel = aps[apidx].channel;
    }
    s_picking_target = false;
    ui_show(UI_SCREEN_ATTACK);
}

static void cb_pick_target(int idx)
{
    (void)idx;
    s_picking_target = true;
    ui_show(UI_SCREEN_ATTACK);
}

static void attack_tick(void)
{
    attack_state_t st;
    wifi_attack_get_state(&st);
    if (s_stats) {
        lv_label_set_text_fmt(s_stats, "TX %lu  ch%u  %s",
                              (unsigned long)st.sent, st.channel,
                              st.running ? "RUNNING" : "IDLE");
    }
}

/* ================================================================== */
/* 2.4 GHz radio guard — BLE and 802.15.4 share the same radio         */
/* ================================================================== */

static void radio_zb_stop(void)
{
    if (s_zb_running) {
        zb_sniff_stop();
        s_zb_running = false;
        app_radio_set(APP_RADIO_ZB, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    }
}

static void radio_ble_stop(void)
{
    if (s_ble_running) {
        ble_scan_stop();
        s_ble_running = false;
        app_radio_set(APP_RADIO_BLE, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    }
    if (ble_spam_is_running()) {
        ble_spam_stop();
        app_radio_set(APP_RADIO_BLE, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    }
    if (ble_hid_is_running()) {
        ble_hid_stop();
        app_radio_set(APP_RADIO_BLE, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    }
}

/* ================================================================== */
/* BLE scan screen                                                     */
/* ================================================================== */

static void ble_scan_launch(uint32_t ms)
{
    if (s_ble_running) return;
    radio_zb_stop();                 /* same radio — one at a time   */
    if (ble_scan_start(ms) != ESP_OK) return;
    s_ble_running = true;
    app_radio_set(APP_RADIO_BLE, RADIO_STATE_ACTIVE);
    sys_led_set_mode(LED_MODE_BLE);
    xTaskCreate(ble_worker, "blew", 2048, NULL, 5, NULL);
}

static void cb_ble_10(int idx) { (void)idx; ble_scan_launch(10000); }
static void cb_ble_30(int idx) { (void)idx; ble_scan_launch(30000); }

static void cb_ble_stop(int idx)
{
    (void)idx;
    radio_ble_stop();
}

static void ble_worker(void *arg)
{
    ble_scan_wait_done(45000);
    if (s_ble_running) {             /* not stopped by the guard? */
        s_ble_running = false;
        app_radio_set(APP_RADIO_BLE, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
        ui_post(UI_EV_BLE_DONE, 0, NULL);
    }
    vTaskDelete(NULL);
}

void ui_screen_ble_refresh(void)
{
    if (s_screen != UI_SCREEN_BLE_SCAN) return;
    size_t n = 0;
    const ble_dev_t *devs = ble_scan_get_results(&n);

    ui_menu_trim(&s_menu, s_base_count);
    for (size_t i = 0; i < n && i < MAX_DYN; i++) {
        char label[33];
        ble_scan_addr_to_str(devs[i].addr, label);
        ui_menu_add(&s_menu, label, NULL);
        ui_menu_set_value(&s_menu, s_menu.count - 1, "%ddBm %s",
                          devs[i].rssi, devs[i].name);
    }
    app_radio_set(APP_RADIO_BLE, RADIO_STATE_IDLE);
}

static void ble_tick(void)
{
    ble_scan_stats_t st;
    ble_scan_get_stats(&st);
    if (s_stats) {
        lv_label_set_text_fmt(s_stats, "FRAMES %lu  DEV %lu  %s",
                              (unsigned long)st.total, (unsigned long)st.unique,
                              st.running ? "RUNNING" : "IDLE");
    }
}

/* ================================================================== */
/* Zigbee screen                                                       */
/* ================================================================== */

static void cb_zb_toggle(int idx)
{
    (void)idx;
    if (s_zb_running) {
        radio_zb_stop();
    } else {
        radio_ble_stop();            /* same radio — one at a time   */
        if (zb_sniff_start(s_zb_channel) == ESP_OK) {
            s_zb_running = true;
            app_radio_set(APP_RADIO_ZB, RADIO_STATE_ACTIVE);
            sys_led_set_mode(LED_MODE_ZB);
        }
    }
    ui_menu_set_value(&s_menu, 1, "%s", s_zb_running ? "STOP" : "START");
}

static void cb_zb_chp(int idx) { (void)idx; if (s_zb_channel < 26) { s_zb_channel++; zb_sniff_set_channel(s_zb_channel); } ui_menu_set_value(&s_menu, 2, "ch%u", s_zb_channel); }
static void cb_zb_chm(int idx) { (void)idx; if (s_zb_channel > 11) { s_zb_channel--; zb_sniff_set_channel(s_zb_channel); } ui_menu_set_value(&s_menu, 2, "ch%u", s_zb_channel); }

static void zb_tick(void)
{
    zb_sniff_stats_t st;
    zb_sniff_get_stats(&st);
    if (s_stats) {
        lv_label_set_text_fmt(s_stats, "TOT %lu  BC %lu  DAT %lu  ACK %lu  CMD %lu  CH %u",
                              (unsigned long)st.total, (unsigned long)st.beacons,
                              (unsigned long)st.data_frames, (unsigned long)st.acks,
                              (unsigned long)st.commands, s_zb_channel);
    }
}

/* ================================================================== */
/* Logger screen                                                       */
/* ================================================================== */

static void cb_log_toggle(int idx)
{
    (void)idx;
    bool en = !sd_log_capture_enabled();
    sd_log_capture_set(en);
    ui_menu_set_value(&s_menu, 1, "%s", en ? "ON" : "OFF");
}

static void log_tick(void)
{
    sd_log_stats_t st;
    sd_log_get_stats(&st);
    if (s_stats) {
        if (st.mounted) {
            lv_label_set_text_fmt(s_stats, "SD OK  WR %lu  B %lu  FREE %lluMB",
                                  (unsigned long)st.log_writes, (unsigned long)st.log_bytes,
                                  (unsigned long long)(st.free_bytes >> 20));
        } else {
            lv_label_set_text(s_stats, "SD: NO CARD");
        }
    }
}

/* ================================================================== */
/* Evil portal screen                                                  */
/* ================================================================== */

static const char *const s_portal_ssids[] = {
    "GHOSTTAP", "FreeWiFi", "Starbucks_WiFi", "HotelGuest", "Airport_Free",
};
#define PORTAL_SSID_COUNT (sizeof(s_portal_ssids) / sizeof(s_portal_ssids[0]))
static uint8_t s_portal_ssid_idx;

static void cb_evil_toggle(int idx)
{
    (void)idx;
    if (evil_portal_is_running()) {
        evil_portal_stop();
        app_radio_set(APP_RADIO_WIFI, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    } else {
        wifi_attack_stop();          /* portal owns the AP radio */
        if (evil_portal_start(s_portal_ssids[s_portal_ssid_idx],
                              "ghosttappass") == ESP_OK) {
            app_radio_set(APP_RADIO_WIFI, RADIO_STATE_ACTIVE);
            sys_led_set_mode(LED_MODE_IDLE);
        }
    }
    ui_menu_set_value(&s_menu, 1, "%s",
                      evil_portal_is_running() ? "STOP" : "START");
}

static void cb_evil_ssid(int idx)
{
    (void)idx;
    s_portal_ssid_idx = (s_portal_ssid_idx + 1) % PORTAL_SSID_COUNT;
    ui_menu_set_value(&s_menu, 2, "%s", s_portal_ssids[s_portal_ssid_idx]);
}

static void evil_tick(void)
{
    char last[33] = { 0 };
    uint32_t attempts = 0;
    evil_portal_get_last_creds(last, sizeof(last), NULL, 0);
    evil_portal_get_stats(&attempts);
    if (s_stats) {
        if (evil_portal_is_running()) {
            lv_label_set_text_fmt(s_stats, "PORTAL: %s  |  ATTEMPTS %lu  |  LAST %s",
                                  "ONLINE", (unsigned long)attempts, last[0] ? last : "-");
        } else {
            lv_label_set_text(s_stats, "PORTAL: OFFLINE");
        }
    }
}

/* ================================================================== */
/* Handshake capture screen                                            */
/* ================================================================== */

static void cb_hs_toggle(int idx)
{
    (void)idx;
    if (s_hs_running) {
        wifi_handshake_stop();
        s_hs_running = false;
        app_radio_set(APP_RADIO_WIFI, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    } else {
        if (s_sniff_running) {
            wifi_sniff_stop();
            s_sniff_running = false;
        }
        wifi_attack_stop();
        if (evil_portal_is_running()) evil_portal_stop();
        if (wifi_handshake_start(0, true) == ESP_OK) {
            s_hs_running = true;
            app_radio_set(APP_RADIO_WIFI, RADIO_STATE_ACTIVE);
            sys_led_set_mode(LED_MODE_SNIFF);
        }
    }
    ui_menu_set_value(&s_menu, 1, "%s", s_hs_running ? "STOP" : "START");
}

static void handshake_tick(void)
{
    hs_stats_t st;
    wifi_handshake_get_stats(&st);
    if (s_stats) {
        lv_label_set_text_fmt(s_stats,
            "AP %u  EAPOL %lu  HS %lu  PMKID %lu  %s",
            st.ap_count, (unsigned long)st.total_eapol,
            (unsigned long)st.handshakes, (unsigned long)st.pmkids,
            st.running ? "RUNNING" : "IDLE");
    }
}

/* ================================================================== */
/* BLE spam screen                                                     */
/* ================================================================== */

static void cb_spam_toggle(int idx)
{
    (void)idx;
    if (ble_spam_is_running()) {
        ble_spam_stop();
        app_radio_set(APP_RADIO_BLE, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    } else {
        radio_ble_stop();
        radio_zb_stop();
        if (ble_spam_start() == ESP_OK) {
            app_radio_set(APP_RADIO_BLE, RADIO_STATE_ACTIVE);
            sys_led_set_mode(LED_MODE_BLE);
        }
    }
    ui_menu_set_value(&s_menu, 1, "%s",
                      ble_spam_is_running() ? "STOP" : "START");
}

static void spam_tick(void)
{
    uint32_t pkts = 0, names = 0;
    char last[33] = { 0 };
    ble_spam_get_stats(&pkts, &names, last, sizeof(last));
    if (s_stats) {
        lv_label_set_text_fmt(s_stats, "PKTS %lu  NAMES %lu  LAST %s",
                              (unsigned long)pkts, (unsigned long)names,
                              last[0] ? last : "-");
    }
}

/* ================================================================== */
/* BLE HID keyboard screen                                             */
/* ================================================================== */

static void cb_hid_toggle(int idx)
{
    (void)idx;
    if (ble_hid_is_running()) {
        ble_hid_stop();
        app_radio_set(APP_RADIO_BLE, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    } else {
        radio_ble_stop();
        radio_zb_stop();
        if (ble_hid_start() == ESP_OK) {
            app_radio_set(APP_RADIO_BLE, RADIO_STATE_ACTIVE);
            sys_led_set_mode(LED_MODE_BLE);
        }
    }
    ui_menu_set_value(&s_menu, 1, "%s",
                      ble_hid_is_running() ? "STOP" : "START");
}

static void cb_hid_hello(int idx)
{
    (void)idx;
    ble_hid_type_string("Hello from GHOSTTAP!");
}

static void cb_hid_payload(int idx)
{
    (void)idx;
    ble_hid_run_script("DELAY 1000\nGUI r\nDELAY 500\n"
                       "STRING notepad\nENTER\nDELAY 800\n"
                       "STRING PWNED BY GHOSTTAP\nENTER");
}

static void hid_tick(void)
{
    uint32_t chars = 0, keys = 0;
    bool conn = false;
    ble_hid_get_stats(&chars, &keys, &conn);
    if (s_stats) {
        lv_label_set_text_fmt(s_stats, "%s  CHARS %lu  KEYS %lu",
                              conn ? "CONNECTED" : "ADVERTISING",
                              (unsigned long)chars, (unsigned long)keys);
    }
}

/* ================================================================== */
/* Karma — probed-SSID harvester + one-touch rogue AP                  */
/* ================================================================== */

static void cb_karma_pick(int idx);

static void karma_refresh_rows(void)
{
    size_t n = 0;
    const karma_ssid_t *list = wifi_sniff_get_probed_ssids(&n);
    ui_menu_trim(&s_menu, s_base_count);
    for (size_t i = 0; i < n && i < MAX_DYN; i++) {
        ui_menu_add(&s_menu, list[i].ssid, cb_karma_pick);
        ui_menu_set_value(&s_menu, s_menu.count - 1, "x%lu %ddBm",
                          (unsigned long)list[i].hits, list[i].last_rssi);
    }
    ui_menu_set_footer(&s_menu, "%d PROBED SSIDS", (int)n);
    s_karma_last_count = n;
}

static void cb_karma_toggle(int idx)
{
    (void)idx;
    if (s_karma_running) {
        wifi_sniff_stop();
        s_karma_running = false;
        app_radio_set(APP_RADIO_WIFI, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    } else if (wifi_sniff_start(0, true) == ESP_OK) {
        s_karma_running = true;
        app_radio_set(APP_RADIO_WIFI, RADIO_STATE_ACTIVE);
        sys_led_set_mode(LED_MODE_SNIFF);
    }
    ui_menu_set_value(&s_menu, 1, "%s", s_karma_running ? "STOP" : "START");
}

static void cb_karma_clear(int idx)
{
    (void)idx;
    wifi_sniff_clear_probed_ssids();
    karma_refresh_rows();
}

/* LONG-press a harvested SSID: stop harvesting and stand up a rogue AP
 * advertising that exact SSID — the client that probed for it should
 * auto-connect, thinking it's a network it already trusts. */
static void cb_karma_pick(int idx)
{
    int kidx = idx - s_base_count;
    size_t n = 0;
    const karma_ssid_t *list = wifi_sniff_get_probed_ssids(&n);
    if (kidx < 0 || kidx >= (int)n) return;

    wifi_sniff_stop();
    s_karma_running = false;
    wifi_attack_stop();
    if (evil_portal_start(list[kidx].ssid, "ghosttappass") == ESP_OK) {
        app_radio_set(APP_RADIO_WIFI, RADIO_STATE_ACTIVE);
        sys_led_set_mode(LED_MODE_IDLE);
        ui_show(UI_SCREEN_EVIL);
    }
}

static void karma_tick(void)
{
    size_t n = 0;
    wifi_sniff_get_probed_ssids(&n);
    if (n != s_karma_last_count) karma_refresh_rows();
}

/* ================================================================== */
/* WIDS — passive deauth/disassoc flood alarm                          */
/* ================================================================== */

static void cb_wids_toggle(int idx)
{
    (void)idx;
    if (wids_is_running()) {
        wids_stop();
        s_wids_running = false;
        app_radio_set(APP_RADIO_WIFI, RADIO_STATE_IDLE);
        sys_led_set_mode(LED_MODE_IDLE);
    } else if (wids_start() == ESP_OK) {
        s_wids_running = true;
        app_radio_set(APP_RADIO_WIFI, RADIO_STATE_ACTIVE);
        sys_led_set_mode(LED_MODE_SNIFF);
    }
    ui_menu_set_value(&s_menu, 1, "%s", s_wids_running ? "STOP" : "START");
    /* force an immediate, un-throttled text refresh on the next tick */
    s_wids_last_deauth = s_wids_last_disassoc = 0xFFFFFFFF;
    s_wids_last_text_ms = 0;
}

static void wids_tick(void)
{
    wids_stats_t st;
    wids_get_stats(&st);

    if (st.alert != s_wids_last_alert && st.running) {
        sys_led_set_mode(st.alert ? LED_MODE_ATTACK : LED_MODE_SNIFF);
    }

    /* Throttled to ~3Hz: a sustained flood increments deauth_total on
     * nearly every received frame, and unbounded LVGL text churn is
     * exactly the pattern that livelocks lv_timer_handler() on this
     * esp32c5/LVGL8.4 combo (see menu_relayout()'s comment) — an alarm
     * screen is the worst possible place to reintroduce that. */
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    bool changed = (st.deauth_total != s_wids_last_deauth ||
                    st.disassoc_total != s_wids_last_disassoc ||
                    st.alert != s_wids_last_alert);
    if (changed && (now - s_wids_last_text_ms) >= 300) {
        s_wids_last_text_ms = now;
        s_wids_last_deauth = st.deauth_total;
        s_wids_last_disassoc = st.disassoc_total;
        s_wids_last_alert = st.alert;

        if (s_stats) {
            if (st.alert) {
                lv_label_set_text_fmt(s_stats,
                    "ALERT! FLOOD FROM %02x:%02x:%02x:%02x:%02x:%02x  %lu/s",
                    st.alert_bssid[0], st.alert_bssid[1], st.alert_bssid[2],
                    st.alert_bssid[3], st.alert_bssid[4], st.alert_bssid[5],
                    (unsigned long)st.alert_rate);
            } else {
                lv_label_set_text_fmt(s_stats, "DEAUTH %lu  DISASSOC %lu  %s",
                    (unsigned long)st.deauth_total, (unsigned long)st.disassoc_total,
                    st.running ? "WATCHING" : "IDLE");
            }
        }
    }
}

/* ================================================================== */
/* BLE tracker detector                                                */
/* ================================================================== */

static void cb_tracker_scan(int idx) { (void)idx; ble_scan_launch(60000); }
static void cb_tracker_stop(int idx) { (void)idx; radio_ble_stop(); }

static void tracker_refresh_rows(void)
{
    size_t n = 0;
    const ble_dev_t *devs = ble_scan_get_results(&n);
    ui_menu_trim(&s_menu, s_base_count);
    uint32_t shown = 0;
    for (size_t i = 0; i < n && shown < MAX_DYN; i++) {
        if (devs[i].tracker == BLE_TRACKER_NONE) continue;
        char label[18];
        ble_scan_addr_to_str(devs[i].addr, label);
        ui_menu_add(&s_menu, label, NULL);
        ui_menu_set_value(&s_menu, s_menu.count - 1, "%s %ddBm",
                          ble_tracker_type_name(devs[i].tracker), devs[i].rssi);
        shown++;
    }
    ui_menu_set_footer(&s_menu, "%lu TRACKERS", (unsigned long)shown);
    s_tracker_last_count = shown;
}

void ui_screen_tracker_refresh(void)
{
    if (s_screen != UI_SCREEN_TRACKER) return;
    tracker_refresh_rows();
    app_radio_set(APP_RADIO_BLE, RADIO_STATE_IDLE);
}

static void tracker_tick(void)
{
    /* Only rebuild the list when the tracker count actually changes —
     * same discipline as karma_tick(), see its sibling comment above. */
    if (!s_ble_running) return;
    size_t n = 0;
    const ble_dev_t *devs = ble_scan_get_results(&n);
    uint32_t count = 0;
    for (size_t i = 0; i < n; i++) {
        if (devs[i].tracker != BLE_TRACKER_NONE) count++;
    }
    if (count != s_tracker_last_count) tracker_refresh_rows();
}

/* ================================================================== */
/* Open / tick dispatchers                                             */
/* ================================================================== */

void ui_screens_open(ui_screen_t screen)
{
    s_screen = screen;

    switch (screen) {
    case UI_SCREEN_HOME:
        home_open();
        break;

    case UI_SCREEN_WIFI_SCAN: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "WIFI SCAN");
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Start scan", cb_scan_start);
        ui_menu_add(m, "Mode", cb_scan_passive);
        s_base_count = m->count;
        ui_menu_set_value(m, 2, "%s", s_passive ? "PASSIVE" : "ACTIVE");
        ui_menu_set_footer(m, "0 APS");
        break;
    }
    case UI_SCREEN_SNIFFER: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "SNIFFER");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Start/Stop hop", cb_sniff_toggle);
        ui_menu_add(m, "5G ch36", cb_sniff_ch);
        ui_menu_set_footer(m, "SHORT=NEXT  LONG=SELECT");
        break;
    }
    case UI_SCREEN_HANDSHAKE: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "HANDSHAKES");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Capture", cb_hs_toggle);
        ui_menu_set_value(m, 1, "%s", s_hs_running ? "STOP" : "START");
        ui_menu_set_footer(m, "PCAP VIA USB TUI");
        break;
    }
    case UI_SCREEN_ATTACK: {
        pick_target();
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "ATTACKS");
        stats_header(m);
        if (s_picking_target) {
            ui_menu_add(m, "< Back", cb_target_back);
            size_t n = 0;
            const wifi_ap_t *aps = wifi_scan_get_results(&n);
            if (n == 0) {
                ui_menu_add(m, "No scan results", NULL);
            }
            for (size_t i = 0; i < n && i < MAX_DYN; i++) {
                ui_menu_add(m, aps[i].ssid, cb_target_pick);
                ui_menu_set_value(m, s_menu.count - 1, "ch%u %ddBm",
                                  aps[i].channel, aps[i].rssi);
            }
            ui_menu_set_footer(m, "PICK TARGET");
        } else {
            ui_menu_add(m, "< Back", cb_back);
            ui_menu_add(m, "Target", cb_pick_target);
            ui_menu_set_value(m, 1, "%s", s_target_ssid);
            ui_menu_add(m, "Deauth AP", cb_attack_deauth);
            ui_menu_add(m, "Deauth broadcast", cb_attack_deauth_all);
            ui_menu_add(m, "Beacon flood", cb_attack_beacon);
            ui_menu_add(m, "Probe flood", cb_attack_probe);
            ui_menu_add(m, "Stop", cb_attack_stop);
            ui_menu_set_footer(m, "AUTHORIZED USE ONLY");
        }
        break;
    }
    case UI_SCREEN_EVIL: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "EVIL PORTAL");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Start/Stop", cb_evil_toggle);
        ui_menu_add(m, "SSID", cb_evil_ssid);
        ui_menu_set_value(m, 1, "%s", evil_portal_is_running() ? "STOP" : "START");
        ui_menu_set_value(m, 2, "%s", s_portal_ssids[s_portal_ssid_idx]);
        ui_menu_set_footer(m, "PASS: ghosttappass");
        break;
    }
    case UI_SCREEN_BLE_SCAN: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "BLE SCAN");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Scan 10s", cb_ble_10);
        ui_menu_add(m, "Scan 30s", cb_ble_30);
        ui_menu_add(m, "Stop", cb_ble_stop);
        s_base_count = m->count;
        ui_menu_set_footer(m, "0 DEVICES");
        break;
    }
    case UI_SCREEN_BLE_SPAM: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "BLE SPAM");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Flood", cb_spam_toggle);
        ui_menu_set_value(m, 1, "%s",
                          ble_spam_is_running() ? "STOP" : "START");
        ui_menu_set_footer(m, "PHANTOM ADV FLOOD");
        break;
    }
    case UI_SCREEN_BLE_HID: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "BLE HID");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Advertise", cb_hid_toggle);
        ui_menu_add(m, "Type hello", cb_hid_hello);
        ui_menu_add(m, "Demo payload", cb_hid_payload);
        ui_menu_set_value(m, 1, "%s",
                          ble_hid_is_running() ? "STOP" : "START");
        ui_menu_set_footer(m, "PAIR THEN TYPE");
        break;
    }
    case UI_SCREEN_ZB_SNIFF: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "ZIGBEE 802.15.4");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Start/Stop", cb_zb_toggle);
        ui_menu_add(m, "Channel +", cb_zb_chp);
        ui_menu_add(m, "Channel -", cb_zb_chm);
        ui_menu_set_value(m, 2, "ch%u", s_zb_channel);
        ui_menu_set_value(m, 3, "ch%u", s_zb_channel);
        ui_menu_set_footer(m, "SHORT=NEXT  LONG=SELECT");
        break;
    }
    case UI_SCREEN_LOGGER: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "LOGGER");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Capture", cb_log_toggle);
        ui_menu_set_value(m, 1, "%s", sd_log_capture_enabled() ? "ON" : "OFF");
        ui_menu_set_footer(m, "SHORT=NEXT  LONG=SELECT");
        break;
    }
    case UI_SCREEN_KARMA: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "KARMA");
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Start/Stop harvest", cb_karma_toggle);
        ui_menu_add(m, "Clear list", cb_karma_clear);
        ui_menu_set_value(m, 1, "%s", s_karma_running ? "STOP" : "START");
        s_base_count = m->count;
        karma_refresh_rows();
        break;
    }
    case UI_SCREEN_WIDS: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "WIDS ALARM");
        stats_header(m);
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Start/Stop", cb_wids_toggle);
        ui_menu_set_value(m, 1, "%s", s_wids_running ? "STOP" : "START");
        ui_menu_set_footer(m, "DEAUTH/DISASSOC FLOOD WATCH");
        break;
    }
    case UI_SCREEN_TRACKER: {
        ui_menu_t *m = &s_menu;
        ui_menu_build(m, "TRACKER DETECT");
        ui_menu_add(m, "< Back", cb_back);
        ui_menu_add(m, "Scan 60s", cb_tracker_scan);
        ui_menu_add(m, "Stop", cb_tracker_stop);
        s_base_count = m->count;
        s_tracker_last_count = 0xFFFFFFFF;
        tracker_refresh_rows();
        break;
    }
    default:
        break;
    }
}

void ui_screens_tick(ui_screen_t screen)
{
    switch (screen) {
    case UI_SCREEN_BOOT:
        boot_tick();
        break;
    case UI_SCREEN_HOME:
        home_tick();
        break;
    case UI_SCREEN_SNIFFER:
        sniff_tick();
        break;
    case UI_SCREEN_HANDSHAKE:
        handshake_tick();
        break;
    case UI_SCREEN_ATTACK:
        attack_tick();
        break;
    case UI_SCREEN_BLE_SCAN:
        ble_tick();
        break;
    case UI_SCREEN_BLE_SPAM:
        spam_tick();
        break;
    case UI_SCREEN_BLE_HID:
        hid_tick();
        break;
    case UI_SCREEN_ZB_SNIFF:
        zb_tick();
        break;
    case UI_SCREEN_LOGGER:
        log_tick();
        break;
    case UI_SCREEN_EVIL:
        evil_tick();
        break;
    case UI_SCREEN_KARMA:
        karma_tick();
        break;
    case UI_SCREEN_WIDS:
        wids_tick();
        break;
    case UI_SCREEN_TRACKER:
        tracker_tick();
        break;
    default:
        break;
    }
}
