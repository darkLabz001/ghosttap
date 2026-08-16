/*
 * GHOSTTAP Pentest Field Unit — application core
 *
 * Shared app state: radio status flags, uptime clock and the UI event
 * bridge used by every module to push data to the screen.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Indices used by the home-screen status LED dots. */
typedef enum {
    APP_RADIO_WIFI = 0,
    APP_RADIO_BLE,
    APP_RADIO_ZB,
    APP_RADIO_SD,
    APP_RADIO_COUNT
} app_radio_t;

typedef enum {
    RADIO_STATE_OFF = 0,
    RADIO_STATE_IDLE,
    RADIO_STATE_ACTIVE,
    RADIO_STATE_ERROR,
} app_radio_state_t;

void    app_radio_set(app_radio_t radio, app_radio_state_t st);
app_radio_state_t app_radio_get(app_radio_t radio);

uint32_t app_uptime_seconds(void);

/* Module hook so app_main.c can be kept thin but wired. */
void app_boot(void);

/* Button driver (app_button.c). */
void app_button_init(void);

#ifdef __cplusplus
}
#endif
