/*
 * GHOSTTAP IEEE 802.15.4 sniffer — Zigbee / Thread promiscuous capture.
 *
 * Uses the C5's native 802.15.4 radio (idf component `ieee802154`).
 * The RX-done callback receives the full PSDU including the PHR length
 * byte at data[0]; payload starts at data[1]. Frame type is bits 0..2
 * of the frame-control field (little-endian word, byte 1..2).
 *
 * NOTE: the 2.4 GHz radio is shared — this module and BLE must not run
 * at the same time.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include "esp_log.h"
#include "esp_ieee802154.h"
#include "esp_ieee802154_types.h"

#include "modules/zb_sniff.h"

static const char *TAG = "zb_sniff";

static QueueHandle_t   s_queue;
static zb_sniff_stats_t s_stats;
static volatile bool   s_running;

static void on_rx_done(uint8_t *data, esp_ieee802154_frame_info_t *info)
{
    if (!s_queue) {
        esp_ieee802154_receive_handle_done(data);
        return;
    }

    zb_frame_t f;
    memset(&f, 0, sizeof(f));
    f.len = data[0];                          /* PHR length byte     */
    if (f.len > ZB_FRAME_MAX) f.len = ZB_FRAME_MAX;
    if (f.len > 1) memcpy(f.data, &data[1], f.len - 1);   /* payload, keep room for FCS */

    if (info) {
        f.rssi = info->rssi;
        f.lqi = info->lqi;
        f.channel = info->channel;
    }

    /* frame type: bits 0..2 of first byte of frame control (LE word) */
    if (f.len >= 3) {
        uint8_t ft = f.data[0] & 0x07;
        f.frame_type = ft;
        switch (ft) {
        case 0: s_stats.beacons++; break;
        case 1: s_stats.data_frames++; break;
        case 2: s_stats.acks++; break;
        case 3: s_stats.commands++; break;
        }
    }
    s_stats.total++;

    if (xQueueSend(s_queue, &f, 0) != pdTRUE) {
        /* queue full — drop the frame but keep the radio alive */
    }
    esp_ieee802154_receive_handle_done(data);
}

static esp_ieee802154_event_cb_list_t s_cbs = {
    .rx_done_cb = on_rx_done,
};

esp_err_t zb_sniff_start(uint8_t channel)
{
    if (s_running) return ESP_ERR_INVALID_STATE;

    if (!s_queue) {
        s_queue = xQueueCreate(ZB_QUEUE_DEPTH, sizeof(zb_frame_t));
    }
    xQueueReset(s_queue);
    memset(&s_stats, 0, sizeof(s_stats));

    if (channel < 11) channel = 11;
    if (channel > 26) channel = 26;

    esp_ieee802154_set_channel(channel);
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_event_callback_list_register(s_cbs);
    esp_ieee802154_enable();
    esp_ieee802154_receive();

    s_running = true;
    ESP_LOGI(TAG, "802.15.4 sniffer started ch=%u", channel);
    return ESP_OK;
}

esp_err_t zb_sniff_stop(void)
{
    if (!s_running) return ESP_OK;
    esp_ieee802154_disable();
    s_running = false;
    ESP_LOGI(TAG, "802.15.4 sniffer stopped");
    return ESP_OK;
}

esp_err_t zb_sniff_set_channel(uint8_t channel)
{
    if (channel < 11) channel = 11;
    if (channel > 26) channel = 26;
    esp_ieee802154_set_channel(channel);
    return ESP_OK;
}

esp_err_t zb_sniff_get_stats(zb_sniff_stats_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    *out = s_stats;
    out->running = s_running;
    return ESP_OK;
}

esp_err_t zb_sniff_pop_frame(zb_frame_t *out, uint32_t timeout_ms)
{
    if (!s_queue) return ESP_ERR_INVALID_STATE;
    if (xQueueReceive(s_queue, out, pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
        return ESP_OK;
    }
    return ESP_ERR_TIMEOUT;
}
