/*
 * GHOSTTAP BLE scanner — BLE 5 device discovery via NimBLE.
 *
 * NimBLE is part of ESP-IDF; enable it with CONFIG_BT_ENABLED=y and
 * CONFIG_BT_NIMBLE_ROLE_CENTRAL/OBSERVER=y (see sdkconfig.defaults).
 * The whole module compiles to a stub when BT is disabled so the rest
 * of the firmware stays buildable without the radio stack.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_log.h"

#include "modules/ble_core.h"
#include "modules/ble_scan.h"

static const char *TAG = "ble_scan";

#if CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED

#include "host/ble_hs.h"
#include "host/util/util.h"

#define SCAN_DONE_BIT BIT0

static EventGroupHandle_t s_evt;
static ble_dev_t          s_devs[BLE_SCAN_MAX_DEV];
static size_t             s_dev_count;
static volatile uint32_t  s_total_frames;
static volatile bool      s_running;

static ble_dev_t *find_dev(const uint8_t addr[6], uint8_t atype)
{
    for (size_t i = 0; i < s_dev_count; i++) {
        if (s_devs[i].addr_type == atype && memcmp(s_devs[i].addr, addr, 6) == 0)
            return &s_devs[i];
    }
    return NULL;
}

static void add_or_update(const uint8_t addr[6], uint8_t atype, int8_t rssi,
                          uint8_t evt_type, const uint8_t *ad, uint8_t ad_len)
{
    ble_dev_t *d = find_dev(addr, atype);
    if (!d) {
        if (s_dev_count >= BLE_SCAN_MAX_DEV) return;
        d = &s_devs[s_dev_count++];
        memset(d, 0, sizeof(*d));
        memcpy(d->addr, addr, 6);
        d->addr_type = atype;
        d->adv_type = (ble_adv_type_t)evt_type;
    }
    d->rssi = rssi;

    /* extract short/full local name from AD structures */
    uint8_t off = 0;
    while (off + 1 < ad_len) {
        uint8_t len = ad[off];
        if (len == 0) break;
        if (off + 1 + len > ad_len) break;
        uint8_t type = ad[off + 1];
        if ((type == 0x09 || type == 0x08) && len > 1) {
            uint8_t n = len - 1;
            if (n > 32) n = 32;
            memcpy(d->name, &ad[off + 2], n);
            d->name[n] = 0;
        }
        off += 1 + len;
    }
    d->fields_len = ad_len;
}

static int on_scan(struct ble_gap_event *event, void *cb_arg)
{
    (void)cb_arg;
    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        s_total_frames++;
        add_or_update(event->disc.addr.val, event->disc.addr.type,
                      event->disc.rssi, event->disc.event_type,
                      event->disc.data, event->disc.length_data);
        return 0;
    case BLE_GAP_EVENT_DISC_COMPLETE:
        s_running = false;
        if (s_evt) xEventGroupSetBits(s_evt, SCAN_DONE_BIT);
        return 0;
    default:
        return 0;
    }
}

esp_err_t ble_scan_init(void)
{
    if (s_evt) return ESP_OK;

    s_evt = xEventGroupCreate();

    ESP_ERROR_CHECK(ble_core_init());
    ESP_LOGI(TAG, "BLE scan ready");
    return ESP_OK;
}

esp_err_t ble_scan_start(uint32_t duration_ms)
{
    ESP_ERROR_CHECK(ble_scan_init());

    /* wait for host sync before scanning */
    if (ble_core_wait_sync(3000) != ESP_OK) {
        ESP_LOGW(TAG, "host not synced yet");
        return ESP_ERR_TIMEOUT;
    }

    s_dev_count = 0;
    s_total_frames = 0;
    s_running = true;
    xEventGroupClearBits(s_evt, SCAN_DONE_BIT);

    struct ble_gap_disc_params p = {
        .filter_duplicates = 0,
        .passive = 0,
        .itvl = 0,
        .window = 0,
        .filter_policy = 0,
        .limited = 0,
    };

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, duration_ms, &p, on_scan, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
        s_running = false;
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "scan started (%lu ms)", (unsigned long)duration_ms);
    return ESP_OK;
}

esp_err_t ble_scan_stop(void)
{
    if (s_running) {
        ble_gap_disc_cancel();
        s_running = false;
        xEventGroupSetBits(s_evt, SCAN_DONE_BIT);
    }
    return ESP_OK;
}

esp_err_t ble_scan_wait_done(uint32_t timeout_ms)
{
    EventBits_t bits = xEventGroupWaitBits(s_evt, SCAN_DONE_BIT, pdTRUE, pdFALSE,
                                           pdMS_TO_TICKS(timeout_ms));
    return (bits & SCAN_DONE_BIT) ? ESP_OK : ESP_ERR_TIMEOUT;
}

const ble_dev_t *ble_scan_get_results(size_t *count)
{
    if (count) *count = s_dev_count;
    return s_devs;
}

esp_err_t ble_scan_get_stats(ble_scan_stats_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    out->total = s_total_frames;
    out->unique = s_dev_count;
    out->running = s_running;
    return ESP_OK;
}

void ble_scan_addr_to_str(const uint8_t addr[6], char *buf)
{
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

#else /* BT disabled -> stubs */

esp_err_t ble_scan_init(void) { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t ble_scan_start(uint32_t d) { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t ble_scan_stop(void) { return ESP_OK; }
esp_err_t ble_scan_wait_done(uint32_t t) { return ESP_ERR_NOT_SUPPORTED; }
const ble_dev_t *ble_scan_get_results(size_t *c) { if (c) *c = 0; return NULL; }
esp_err_t ble_scan_get_stats(ble_scan_stats_t *o)
{
    if (o) { o->total = 0; o->unique = 0; o->running = false; }
    return ESP_OK;
}
void ble_scan_addr_to_str(const uint8_t addr[6], char *buf)
{
    snprintf(buf, 18, "00:00:00:00:00:00");
}

#endif
