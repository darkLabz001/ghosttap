/*
 * GHOSTTAP system LED — semantic WS2812 status via the Waveshare BSP.
 */
#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LED_MODE_OFF = 0,
    LED_MODE_IDLE,      /* dim blue           */
    LED_MODE_SCAN,      /* cyan pulse         */
    LED_MODE_SNIFF,     /* green pulse        */
    LED_MODE_ATTACK,    /* red fast pulse     */
    LED_MODE_BLE,       /* purple pulse       */
    LED_MODE_ZB,        /* amber pulse        */
} sys_led_mode_t;

esp_err_t sys_led_init(void);
void sys_led_set_mode(sys_led_mode_t mode);

/* Called by a periodic task to run the pulsing animations. */
void sys_led_tick(void);

#ifdef __cplusplus
}
#endif
