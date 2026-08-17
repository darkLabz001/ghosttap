/*
 * GHOSTTAP WiFi sniffer — promiscuous (monitor) mode.
 *
 * Runs in STA mode (shared init with wifi_scan), sets promiscuous RX,
 * parses 802.11 headers directly from the payload bytes (the C5 has a
 * known quirk where the callback `type` hint can be wrong — see
 * esp32.com forum "ESP32-C5: Promiscuous callback reports wrong 802.11
 * frame type", so we trust the raw frame control bytes instead).
 *
 * Channel hopping list covers 2.4 GHz + common 5 GHz channels.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_wifi.h"

#include "modules/wifi_sniff.h"
#include "modules/wifi_scan.h"

static const char *TAG = "wifi_sniff";

#define HOP_LIST_LEN 22
static const uint8_t s_hop_list[HOP_LIST_LEN] = {
    1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
    36, 40, 44, 48, 52, 56, 60, 64, 100, 149, 153,
};

static sniff_stats_t    s_stats;
static sniff_frame_t    s_log[SNIFF_LOG_DEPTH];
static uint32_t         s_log_head;
static uint8_t          s_bssids[SNIFF_MAX_BSSID][6];
static uint32_t         s_bssid_count;
static sniff_frame_cb_t s_frame_cb;
static volatile bool    s_running;
static bool             s_hop;
static uint8_t          s_channel;
static TaskHandle_t     s_hop_task;
static uint32_t         s_1s_tick_pkts;

static karma_ssid_t     s_karma[KARMA_MAX_SSIDS];
static size_t           s_karma_count;

static void karma_record(const char *ssid, int8_t rssi)
{
    if (!ssid[0]) return;              /* wildcard/broadcast probe */
    for (size_t i = 0; i < s_karma_count; i++) {
        if (strcmp(s_karma[i].ssid, ssid) == 0) {
            s_karma[i].hits++;
            s_karma[i].last_rssi = rssi;
            return;
        }
    }
    if (s_karma_count >= KARMA_MAX_SSIDS) return;
    karma_ssid_t *k = &s_karma[s_karma_count++];
    snprintf(k->ssid, sizeof(k->ssid), "%s", ssid);
    k->hits = 1;
    k->last_rssi = rssi;
}

/* ---- 802.11 field accessors (byte layout) -------------------------- */
#define FC0_TYPE(fc0)      (((fc0) >> 2) & 0x03)
#define FC0_SUBTYPE(fc0)   (((fc0) >> 4) & 0x0F)

static void parse_mgmt_frame(const uint8_t *p, uint32_t len, uint8_t subtype,
                             sniff_frame_t *f)
{
    /* p = frame payload; header is 24 bytes, fixed mgmt fields 12 bytes */
    if (subtype == 0x08) {                       /* beacon */
        if (len < 36) return;
        memcpy(f->dst, &p[4], 6);
        memcpy(f->src, &p[10], 6);
        /* SSID tag: IEs start at offset 36, tag id 0x00 */
        uint32_t off = 36;
        while (off + 2 <= len) {
            uint8_t tag = p[off];
            uint8_t tlen = p[off + 1];
            if (tag == 0x00 && tlen <= 32 && off + 2 + tlen <= len) {
                memcpy(f->ssid, &p[off + 2], tlen);
                f->ssid[tlen] = 0;
            }
            off += 2 + tlen;
        }
    } else if (subtype == 0x05) {                /* probe response */
        if (len < 36) return;
        memcpy(f->dst, &p[4], 6);
        memcpy(f->src, &p[10], 6);
        uint32_t off = 36;
        while (off + 2 <= len) {
            uint8_t tag = p[off];
            uint8_t tlen = p[off + 1];
            if (tag == 0x00 && tlen <= 32 && off + 2 + tlen <= len) {
                memcpy(f->ssid, &p[off + 2], tlen);
                f->ssid[tlen] = 0;
            }
            off += 2 + tlen;
        }
    } else if (subtype == 0x04) {                /* probe request */
        if (len < 24) return;
        memcpy(f->dst, &p[4], 6);
        memcpy(f->src, &p[10], 6);
        uint32_t off = 24;
        while (off + 2 <= len) {
            uint8_t tag = p[off];
            uint8_t tlen = p[off + 1];
            if (tag == 0x00 && tlen <= 32 && off + 2 + tlen <= len) {
                memcpy(f->ssid, &p[off + 2], tlen);
                f->ssid[tlen] = 0;
            }
            off += 2 + tlen;
        }
    }
}

static bool bssid_seen(const uint8_t mac[6])
{
    if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0) return true;
    for (uint32_t i = 0; i < s_bssid_count; i++) {
        if (memcmp(s_bssids[i], mac, 6) == 0) return true;
    }
    if (s_bssid_count >= SNIFF_MAX_BSSID) return true;
    memcpy(s_bssids[s_bssid_count++], mac, 6);
    return false;
}

static void sniff_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    if (!s_running) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    uint32_t len = pkt->rx_ctrl.sig_len;

    sniff_frame_t f;
    memset(&f, 0, sizeof(f));
    f.channel = pkt->rx_ctrl.channel;
    f.rssi = pkt->rx_ctrl.rssi;
    f.raw_len = len;

    s_stats.total++;
    s_1s_tick_pkts++;

    if (len < 2) { s_stats.other++; return; }

    uint8_t fc0 = p[0];
    uint8_t ftype = FC0_TYPE(fc0);
    uint8_t subtype = FC0_SUBTYPE(fc0);
    f.ftype = ftype;
    f.subtype = subtype;

    if (ftype == 0) {   /* management */
        s_stats.ctrl += 0;
        switch (subtype) {
        case 0x08: s_stats.beacons++; break;
        case 0x04: s_stats.probe_req++; break;
        case 0x05: s_stats.probe_resp++; break;
        default:   s_stats.other++; break;
        }
        if (len >= 16) {  /* header >= 16 guarantees dst/src presence */
            memcpy(f.dst, &p[4], 6);
            memcpy(f.src, &p[10], 6);
            if (subtype == 0x08 && !bssid_seen(&p[16])) {
                s_stats.unique_bssid++;
            }
            if (subtype == 0x08 || subtype == 0x05 || subtype == 0x04) {
                parse_mgmt_frame(p, len, subtype, &f);
                if (subtype == 0x04) karma_record(f.ssid, f.rssi);
            }
        }
    } else if (ftype == 2) {   /* data */
        s_stats.data++;
        if (len >= 16) {
            memcpy(f.dst, &p[4], 6);
            memcpy(f.src, &p[10], 6);
        }
    } else if (ftype == 1) {   /* control */
        s_stats.ctrl++;
    } else {
        s_stats.other++;
    }

    /* rolling log */
    s_log[s_log_head] = f;
    s_log_head = (s_log_head + 1) % SNIFF_LOG_DEPTH;

    if (s_frame_cb) s_frame_cb(&f);
}

static void hop_task(void *arg)
{
    uint8_t idx = 0;
    while (1) {
        if (s_running && s_hop) {
            idx = (idx + 1) % HOP_LIST_LEN;
            s_channel = s_hop_list[idx];
            esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
        }
        vTaskDelay(pdMS_TO_TICKS(400));
    }
}

esp_err_t wifi_sniff_start(uint8_t channel, bool hop)
{
    ESP_ERROR_CHECK(wifi_scan_init());   /* ensures WiFi up in STA mode */

    memset(&s_stats, 0, sizeof(s_stats));
    s_bssid_count = 0;
    s_log_head = 0;
    s_hop = hop;
    s_channel = channel ? channel : 1;
    s_running = true;

    esp_wifi_set_promiscuous_rx_cb(sniff_rx_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);

    if (!s_hop_task) {
        xTaskCreate(hop_task, "wifi_hop", 2048, NULL, 4, &s_hop_task);
    }
    ESP_LOGI(TAG, "sniffer started ch=%u hop=%d", s_channel, (int)hop);
    return ESP_OK;
}

esp_err_t wifi_sniff_stop(void)
{
    s_running = false;
    esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "sniffer stopped");
    return ESP_OK;
}

esp_err_t wifi_sniff_set_channel(uint8_t channel)
{
    s_channel = channel;
    s_hop = false;
    if (s_running) esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    return ESP_OK;
}

esp_err_t wifi_sniff_get_stats(sniff_stats_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    *out = s_stats;
    out->channel = s_channel;
    out->dropped = 0;
    return ESP_OK;
}

void wifi_sniff_set_frame_cb(sniff_frame_cb_t cb)
{
    s_frame_cb = cb;
}

const sniff_frame_t *wifi_sniff_get_log(size_t *count)
{
    if (count) *count = SNIFF_LOG_DEPTH;
    return s_log;
}

const karma_ssid_t *wifi_sniff_get_probed_ssids(size_t *count)
{
    if (count) *count = s_karma_count;
    return s_karma;
}

void wifi_sniff_clear_probed_ssids(void)
{
    s_karma_count = 0;
}
