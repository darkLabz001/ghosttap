/*
 * GHOSTTAP Pentest Field Unit — application entry point
 *
 * Boot sequence:
 *   1. Start the Waveshare BSP display + LVGL
 *   2. Show the boot splash
 *   3. Start hardware modules (LED, button)
 *   4. Run the UI event loop (all screen updates happen here, under the
 *      BSP display lock, so modules can post events from any task)
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "bsp/esp-bsp.h"
#include "lvgl.h"

#include "app.h"
#include "board.h"
#include "cmd.h"
#include "ui/ui.h"
#include "ui/ui_theme.h"
#include "ui/ui_screens.h"
#include "modules/sys_led.h"

static const char *TAG = "ghosttap";

/* ------------------------------------------------------------------ */
/* Shared radio-status table                                          */
/* ------------------------------------------------------------------ */
static app_radio_state_t s_radio[APP_RADIO_COUNT];
static SemaphoreHandle_t s_radio_mux;

void app_radio_set(app_radio_t radio, app_radio_state_t st)
{
    if (radio >= APP_RADIO_COUNT) return;
    xSemaphoreTake(s_radio_mux, portMAX_DELAY);
    s_radio[radio] = st;
    xSemaphoreGive(s_radio_mux);
    ui_post(UI_EV_RADIO_STATE, (int32_t)radio, NULL);
}

app_radio_state_t app_radio_get(app_radio_t radio)
{
    if (radio >= APP_RADIO_COUNT) return RADIO_STATE_OFF;
    return s_radio[radio];
}

uint32_t app_uptime_seconds(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

/* ------------------------------------------------------------------ */
/* UI task / event bridge                                             */
/* ------------------------------------------------------------------ */
#define UI_EVENT_QUEUE_DEPTH 24

static QueueHandle_t s_ui_queue;

void ui_post(ui_event_id_t id, int32_t arg, void *data)
{
    if (!s_ui_queue) return;
    ui_event_t ev = { .id = id, .arg = arg, .data = data };
    xQueueSend(s_ui_queue, &ev, 0);   /* fire and forget */
}

static void ui_task(void *arg)
{
    ui_event_t ev;
    static TickType_t last_tick = 0;
    static uint32_t button_silence_ms = 0;

    while (1) {
        /* 20 Hz refresh for the active screen */
        TickType_t now = xTaskGetTickCount();
        if ((now - last_tick) >= pdMS_TO_TICKS(50)) {
            last_tick = now;
            if (bsp_display_lock(0)) {
                ui_screens_tick(ui_current());
                bsp_display_unlock();
            }
            sys_led_tick();
        }

        if (xQueueReceive(s_ui_queue, &ev, pdMS_TO_TICKS(50)) == pdTRUE) {
            /* All branches below touch LVGL objects and race with the
               esp_lvgl_port render task unless serialized on the same
               lock it uses internally. */
            if (!bsp_display_lock(0)) continue;
            switch (ev.id) {
            case UI_EV_NAV_NEXT:
                button_silence_ms = esp_timer_get_time() / 1000;
                ui_menu_move(ui_active_menu(), +1);
                break;
            case UI_EV_NAV_SELECT:
                button_silence_ms = esp_timer_get_time() / 1000;
                ui_menu_activate(ui_active_menu());
                break;
            case UI_EV_RADIO_STATE:
                if (ui_current() == UI_SCREEN_HOME) {
                    ui_screens_home();   /* refresh status dots */
                }
                break;
            case UI_EV_SCAN_DONE:
                if (ui_current() == UI_SCREEN_WIFI_SCAN) ui_screen_scan_refresh();
                break;
            case UI_EV_BLE_DONE:
                if (ui_current() == UI_SCREEN_BLE_SCAN) ui_screen_ble_refresh();
                else if (ui_current() == UI_SCREEN_TRACKER) ui_screen_tracker_refresh();
                break;
            default:
                break;
            }
            bsp_display_unlock();
        }

#if CONFIG_APP_UI_DEMO_MODE
        /* Auto-cycle after ~4s without button activity. */
        if ((esp_timer_get_time() / 1000 - button_silence_ms) > 4000) {
            button_silence_ms = esp_timer_get_time() / 1000;
            if (bsp_display_lock(0)) {
                ui_menu_move(ui_active_menu(), +1);
                bsp_display_unlock();
            }
        }
#endif
    }
}

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */

void app_boot(void)
{
    /* Board radios start OFF */
    for (int i = 0; i < APP_RADIO_COUNT; i++) s_radio[i] = RADIO_STATE_OFF;
    s_radio_mux = xSemaphoreCreateMutex();

    ESP_LOGI(TAG, "Start display");
    lv_display_t *disp = bsp_display_start();
    if (!disp) {
        ESP_LOGE(TAG, "Display init failed");
        return;
    }

    bsp_display_rotate(disp, LV_DISPLAY_ROTATION_90);
    ESP_ERROR_CHECK(bsp_display_backlight_on());
    ESP_ERROR_CHECK(bsp_display_brightness_set(70));

    ui_theme_init();

    if (bsp_display_lock(0)) {
        ui_screens_boot();
        bsp_display_unlock();
    }

    /* Hardware support */
    ESP_ERROR_CHECK(sys_led_init());
    app_button_init();

    /* USB-Serial-JTAG command bridge (host TUI control plane) */
    esp_err_t crc = cmd_init();
    if (crc != ESP_OK) {
        ESP_LOGE(TAG, "cmd bridge init failed: %s", esp_err_to_name(crc));
    }

    s_ui_queue = xQueueCreate(UI_EVENT_QUEUE_DEPTH, sizeof(ui_event_t));
    xTaskCreatePinnedToCore(ui_task, "ui", 4096, NULL, 6, NULL, 0);
}

void app_main(void)
{
    app_boot();
}
