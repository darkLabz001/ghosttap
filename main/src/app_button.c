/*
 * GHOSTTAP — button driver
 *
 * Polls the BOOT button (and an optional expansion-header button).
 * Debounced; generates UI events:
 *   SHORT press  (< 450 ms) -> UI_EV_NAV_NEXT
 *   LONG  press  (>= 450 ms)-> UI_EV_NAV_SELECT
 */
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "driver/gpio.h"

#include "board.h"
#include "ui/ui.h"

static const char *TAG = "button";

static gpio_num_t s_pins[2] = { BOARD_BTN_BOOT, BOARD_BTN_USER };
static int        s_pin_count = 1;

void app_button_init(void);
static void button_task(void *arg);

void app_button_init(void)
{
    if (BOARD_BTN_USER >= 0) s_pin_count = 2;

    for (int i = 0; i < s_pin_count; i++) {
        gpio_config_t cfg = {
            .pin_bit_mask = 1ULL << s_pins[i],
            .mode = GPIO_MODE_INPUT,
            .pull_up_en = BOARD_BTN_ACTIVE_LOW ? GPIO_PULLUP_ENABLE : GPIO_PULLDOWN_ENABLE,
            .pull_down_en = BOARD_BTN_ACTIVE_LOW ? GPIO_PULLDOWN_DISABLE : GPIO_PULLUP_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };
        ESP_ERROR_CHECK(gpio_config(&cfg));
    }

    xTaskCreate(button_task, "button", 2048, NULL, 5, NULL);
}

static void button_task(void *arg)
{
    const uint32_t DEBOUNCE_MS = 35;
    const uint32_t LONG_MS     = 450;

    bool       tracking[2] = { false, false };
    bool       fired[2]    = { false, false };
    uint32_t   press_start_ms[2] = { 0, 0 };

    while (1) {
        for (int i = 0; i < s_pin_count; i++) {
            bool raw = gpio_get_level(s_pins[i]) != 0;
            bool down = BOARD_BTN_ACTIVE_LOW ? !raw : raw;

            if (!down) {
                if (tracking[i] && !fired[i]) {
                    ESP_LOGI(TAG, "short press -> next");
                    ui_post(UI_EV_NAV_NEXT, 0, NULL);
                }
                tracking[i] = false;
                fired[i] = false;
                continue;
            }

            if (!tracking[i]) {
                vTaskDelay(pdMS_TO_TICKS(DEBOUNCE_MS));
                raw = gpio_get_level(s_pins[i]) != 0;
                bool confirm = BOARD_BTN_ACTIVE_LOW ? !raw : raw;
                if (!confirm) continue;            /* bounce */
                tracking[i] = true;
                press_start_ms[i] = (uint32_t)(esp_timer_get_time() / 1000);
                fired[i] = false;
            } else if (!fired[i]) {
                uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
                if ((now - press_start_ms[i]) >= LONG_MS) {
                    fired[i] = true;
                    ESP_LOGI(TAG, "long press -> select");
                    ui_post(UI_EV_NAV_SELECT, 0, NULL);
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
