/*
 * GHOSTTAP system LED — WS2812 status animations.
 *
 * Uses the Waveshare BSP LED API (bsp_ws2812b_init / bsp_setledcolor).
 * Each mode maps to a semantic color; sys_led_tick() is called
 * periodically from the UI task to animate brightness.
 */
#include <string.h>

#include "esp_log.h"
#include "bsp/esp-bsp.h"

#include "app.h"
#include "modules/sys_led.h"

static const char *TAG = "sys_led";

static volatile sys_led_mode_t s_mode = LED_MODE_OFF;
static uint32_t s_frame;
static bool     s_ready;

#define RATE 20          /* ticks/sec */

static void set_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    if (s_ready) bsp_setledcolor(0, r, g, b);
}

esp_err_t sys_led_init(void)
{
    if (bsp_ws2812b_init() == ESP_OK) {
        s_ready = true;
        set_rgb(0, 0, 0);
        ESP_LOGI(TAG, "ws2812 ready");
    } else {
        ESP_LOGW(TAG, "ws2812 init failed");
    }
    return ESP_OK;
}

void sys_led_set_mode(sys_led_mode_t mode)
{
    s_mode = mode;
    s_frame = 0;
}

void sys_led_tick(void)
{
    if (!s_ready) return;
    s_frame++;

    uint8_t r = 0, g = 0, b = 0;

    switch (s_mode) {
    case LED_MODE_OFF:
        break;
    case LED_MODE_IDLE:
        b = 24;                       /* dim blue */
        break;
    case LED_MODE_SCAN:
        b = (s_frame / RATE % 2) ? 60 : 10;
        break;
    case LED_MODE_SNIFF:
        g = (s_frame / RATE % 2) ? 80 : 15;
        break;
    case LED_MODE_ATTACK:
        r = ((s_frame / 4) % 2) ? 120 : 8;   /* fast red pulse */
        break;
    case LED_MODE_BLE:
        b = 30; r = 30;
        if ((s_frame / RATE % 2)) { b = 60; r = 60; }
        break;
    case LED_MODE_ZB:
        r = 40; g = 25;
        if ((s_frame / RATE % 2)) { r = 90; g = 60; }
        break;
    }

    app_radio_state_t wifi = app_radio_get(APP_RADIO_WIFI);
    app_radio_state_t zb   = app_radio_get(APP_RADIO_ZB);
    if (s_mode == LED_MODE_OFF &&
        (wifi == RADIO_STATE_ACTIVE || zb == RADIO_STATE_ACTIVE)) {
        g = 10;                       /* auto wake on radio activity */
    }

    set_rgb(r, g, b);
}
