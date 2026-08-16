/*
 * GHOSTTAP WiFi scanner — dual band (2.4 + 5 GHz) AP discovery.
 *
 * Runs WiFi in STA mode with power-save off so the same radio setup can
 * also feed the promiscuous sniffer.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "modules/wifi_scan.h"

static const char *TAG = "wifi_scan";

#define SCAN_DONE_BIT BIT0
#define SCAN_MAX WIFI_SCAN_MAX_APS

static EventGroupHandle_t  s_scan_evt;
static wifi_ap_record_t    s_raw[SCAN_MAX];
static wifi_ap_t           s_results[SCAN_MAX];
static size_t              s_count;
static bool                s_inited;

static void wifi_scan_event_handler(void *arg, esp_event_base_t base,
                                    int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_SCAN_DONE) {
        xEventGroupSetBits(s_scan_evt, SCAN_DONE_BIT);
    }
}

static esp_err_t init_nvs(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    return ret;
}

esp_err_t wifi_scan_init(void)
{
    if (s_inited) return ESP_OK;

    ESP_ERROR_CHECK(init_nvs());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               wifi_scan_event_handler, NULL));

    s_scan_evt = xEventGroupCreate();
    s_inited = true;
    ESP_LOGI(TAG, "WiFi ready (STA, ps-off)");
    return ESP_OK;
}

esp_err_t wifi_scan_start(bool passive)
{
    if (!s_inited) ESP_ERROR_CHECK(wifi_scan_init());

    wifi_scan_config_t sc = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,                  /* sweep 2.4 + 5 GHz */
        .show_hidden = true,
        .scan_type = passive ? WIFI_SCAN_TYPE_PASSIVE : WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {
            .active = { .min = 60, .max = 120 },
            .passive = 200,
        },
    };

    xEventGroupClearBits(s_scan_evt, SCAN_DONE_BIT);
    esp_err_t ret = esp_wifi_scan_start(&sc, false);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "scan start failed: %s", esp_err_to_name(ret));
        return ret;
    }
    return ESP_OK;
}

esp_err_t wifi_scan_wait_results(wifi_ap_t *out, size_t max,
                                 size_t *count, uint32_t timeout_ms)
{
    EventBits_t bits = xEventGroupWaitBits(s_scan_evt, SCAN_DONE_BIT, pdTRUE, pdFALSE,
                                           pdMS_TO_TICKS(timeout_ms));
    if (!(bits & SCAN_DONE_BIT)) return ESP_ERR_TIMEOUT;

    uint16_t num = 0;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&num));
    if (num > SCAN_MAX) num = SCAN_MAX;
    if (num > 0) {
        ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&num, s_raw));
    }

    s_count = 0;
    for (uint16_t i = 0; i < num; i++) {
        wifi_ap_record_t *r = &s_raw[i];
        wifi_ap_t *ap = &s_results[s_count];
        memset(ap, 0, sizeof(*ap));
        memcpy(ap->ssid, r->ssid, sizeof(r->ssid));
        ap->ssid[32] = 0;
        if (ap->ssid[0] == 0) snprintf(ap->ssid, sizeof(ap->ssid), "<hidden>");
        memcpy(ap->bssid, r->bssid, 6);
        ap->rssi = r->rssi;
        ap->channel = r->primary;
        ap->band = (r->primary <= 14) ? WIFI_SCAN_BAND_2G4 : WIFI_SCAN_BAND_5G;
        ap->authmode = r->authmode;
        ap->is_11ax = r->phy_11ax;
        ap->hidden = (r->ssid[0] == 0);
        s_count++;
    }

    ESP_LOGI(TAG, "scan done: %d APs", (int)s_count);

    if (out && max && count) {
        size_t n = s_count < max ? s_count : max;
        memcpy(out, s_results, n * sizeof(wifi_ap_t));
        *count = n;
    }
    return ESP_OK;
}

const wifi_ap_t *wifi_scan_get_results(size_t *count)
{
    if (count) *count = s_count;
    return s_results;
}
