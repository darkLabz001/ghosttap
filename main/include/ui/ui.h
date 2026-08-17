/*
 * GHOSTTAP UI — event bridge and screen ids
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "lvgl.h"
#include "board.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UI_W BOARD_DISPLAY_W   /* 320 */
#define UI_H BOARD_DISPLAY_H   /* 172 */

typedef enum {
    UI_SCREEN_BOOT = 0,
    UI_SCREEN_HOME,
    UI_SCREEN_WIFI_SCAN,
    UI_SCREEN_SNIFFER,
    UI_SCREEN_HANDSHAKE,
    UI_SCREEN_ATTACK,
    UI_SCREEN_BLE_SCAN,
    UI_SCREEN_BLE_SPAM,
    UI_SCREEN_BLE_HID,
    UI_SCREEN_ZB_SNIFF,
    UI_SCREEN_LOGGER,
    UI_SCREEN_EVIL,
    UI_SCREEN_KARMA,
    UI_SCREEN_WIDS,
    UI_SCREEN_TRACKER,
    UI_SCREEN_COUNT,
} ui_screen_t;

typedef enum {
    UI_EV_NONE = 0,
    UI_EV_NAV_NEXT,      /* short button press  */
    UI_EV_NAV_SELECT,    /* long button press   */
    UI_EV_RADIO_STATE,   /* app_radio_t + app_radio_state_t */
    UI_EV_SCAN_DONE,     /* wifi scan finished  */
    UI_EV_BLE_DONE,      /* ble scan finished   */
    UI_EV_SNIFF_TICK,    /* periodic sniffer refresh */
    UI_EV_ZB_TICK,       /* periodic 802.15.4 refresh */
    UI_EV_ATTACK_TICK,   /* periodic attack refresh */
    UI_EV_SD_TICK,       /* periodic storage refresh */
} ui_event_id_t;

typedef struct {
    ui_event_id_t id;
    int32_t arg;         /* secondary payload, e.g. app_radio_state_t */
    void   *data;        /* optional pointer payload */
} ui_event_t;

/* Init LVGL screens + start the UI task. Call after bsp_display_start(). */
esp_err_t ui_init(void);

/* Thread-safe: queue an event for the UI task. */
void ui_post(ui_event_id_t id, int32_t arg, void *data);

/* Switch to a screen (from the UI task context or via ui_post). */
void ui_show(ui_screen_t screen);

ui_screen_t ui_current(void);

/* LVGL 8/9 active screen helper, like the Waveshare examples. */
static inline lv_obj_t *ui_scr(void)
{
#if LVGL_VERSION_MAJOR >= 9
    return lv_screen_active();
#else
    return lv_scr_act();
#endif
}

#ifdef __cplusplus
}
#endif
