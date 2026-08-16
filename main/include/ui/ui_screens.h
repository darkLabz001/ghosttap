/*
 * GHOSTTAP UI — screens
 *
 * Single-button UX: every screen is a vertical menu.
 *   SHORT press = move highlight down
 *   LONG  press = activate highlighted row
 * The first row of every screen is "‹ Back".
 */
#pragma once

#include "lvgl.h"
#include "ui/ui.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A menu row. */
typedef struct {
    const char *label;      /* static label              */
    char        value[24];  /* dynamic trailing text     */
    lv_color_t  value_color;
    void      (*cb)(int idx);   /* called on select       */
    bool        sel;        /* per-tick selection state  */
} ui_menu_item_t;

typedef struct {
    char           title[28];
    ui_menu_item_t items[16];
    uint8_t        count;
    uint8_t        sel;
    lv_obj_t      *root;    /* full-screen container     */
    lv_obj_t      *body;    /* content area (menus)      */
    lv_obj_t      *title_lbl;
    lv_obj_t      *footer_lbl;
    lv_obj_t      *rows[16];
    lv_obj_t      *vals[16];
    lv_coord_t     start_y;  /* first row Y offset      */
    lv_coord_t     row_h;    /* row pitch               */
    bool           scroll;  /* content taller than screen */
    uint8_t        win_start; /* index of first visible row (manual windowing) */
} ui_menu_t;

/*
 * Build a full menu screen (title bar + rows + footer).
 * Returns the content container for custom widgets (stats headers).
 */
lv_obj_t *ui_menu_build(ui_menu_t *m, const char *title);

void ui_menu_add(ui_menu_t *m, const char *label, void (*cb)(int idx));
void ui_menu_set_value(ui_menu_t *m, uint8_t idx, const char *fmt, ...);
void ui_menu_move(ui_menu_t *m, int dir);        /* dir: +1 / -1        */
void ui_menu_activate(ui_menu_t *m);             /* call selected cb    */
void ui_menu_set_footer(ui_menu_t *m, const char *fmt, ...);

/* Screen lifecycle. */
void ui_screens_boot(void);
void ui_screens_home(void);
void ui_screens_open(ui_screen_t s);

/* Periodic refresh — called from the UI task for the active screen. */
void ui_screens_tick(ui_screen_t s);

/* Data refresh hooks used by ui_screens_open / tick. */
void ui_screen_scan_refresh(void);
void ui_screen_ble_refresh(void);

/* Access to the active menu (for modules that push values). */
ui_menu_t *ui_active_menu(void);

#ifdef __cplusplus
}
#endif
