/*
 * GHOSTTAP shared BLE core — single NimBLE host instance.
 *
 * nimble_port_init() must only run once; scanning, advertising spam and
 * the HID keyboard all share this host.  The 2.4 GHz radio itself is
 * still exclusive — the UI / command layer serializes BLE vs 802.15.4.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"

#include "modules/ble_core.h"

static const char *TAG = "ble_core";

#if CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"

static SemaphoreHandle_t s_sync;
static bool              s_inited;
static bool              s_ready;

static void on_sync(void)
{
    s_ready = true;
    if (s_sync) xSemaphoreGive(s_sync);
}

static void on_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t ble_core_init(void)
{
    if (s_inited) return ESP_OK;

    if (!s_sync) s_sync = xSemaphoreCreateBinary();

    int rc = nimble_port_init();
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %d", rc);
        return ESP_FAIL;
    }

    ble_hs_cfg.sync_cb = on_sync;
    xTaskCreate(on_host_task, "ble_host", 4096, NULL, 5, NULL);
    s_inited = true;
    ESP_LOGI(TAG, "NimBLE host started");
    return ESP_OK;
}

esp_err_t ble_core_wait_sync(uint32_t timeout_ms)
{
    if (s_ready) return ESP_OK;
    if (!s_sync) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(s_sync, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

bool ble_core_is_ready(void)
{
    return s_ready;
}

#else /* BT disabled -> stubs */

esp_err_t ble_core_init(void)               { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t ble_core_wait_sync(uint32_t t)    { return ESP_ERR_NOT_SUPPORTED; }
bool ble_core_is_ready(void)                { return false; }

#endif
