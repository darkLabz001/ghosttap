/*
 * GHOSTTAP WIDS — passive deauth/disassoc flood alarm.
 */
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "modules/wids.h"
#include "modules/wifi_sniff.h"

static const char *TAG = "wids";

#define FLOOD_THRESHOLD   6        /* frames within WINDOW_US to alert   */
#define WINDOW_US         1000000  /* 1s counting window                 */
#define QUIET_US          3000000  /* clear alert after 3s of silence    */

static volatile bool s_running;
static uint32_t      s_deauth_total;
static uint32_t      s_disassoc_total;

static int64_t       s_window_start_us;
static uint32_t       s_window_count;
static uint8_t         s_window_bssid[6];

static volatile bool  s_alert;
static uint8_t         s_alert_bssid[6];
static uint32_t        s_alert_rate;
static int64_t         s_last_flood_us;

static void wids_frame_cb(const sniff_frame_t *f)
{
    if (f->ftype != 0) return;                 /* management frames only */
    if (f->subtype != 0x0C && f->subtype != 0x0A) return;  /* deauth/disassoc */

    if (f->subtype == 0x0C) s_deauth_total++;
    else                    s_disassoc_total++;

    int64_t now = esp_timer_get_time();
    s_last_flood_us = now;

    if (s_window_start_us == 0 || (now - s_window_start_us) > WINDOW_US ||
        memcmp(s_window_bssid, f->src, 6) != 0) {
        s_window_start_us = now;
        s_window_count = 0;
        memcpy(s_window_bssid, f->src, 6);
    }
    s_window_count++;

    if (s_window_count >= FLOOD_THRESHOLD) {
        if (!s_alert) {
            ESP_LOGW(TAG, "deauth flood detected from %02x:%02x:%02x:%02x:%02x:%02x",
                     f->src[0], f->src[1], f->src[2], f->src[3], f->src[4], f->src[5]);
        }
        s_alert = true;
        memcpy(s_alert_bssid, f->src, 6);
        s_alert_rate = s_window_count;
    }
}

esp_err_t wids_start(void)
{
    if (s_running) return ESP_OK;

    s_deauth_total = 0;
    s_disassoc_total = 0;
    s_window_start_us = 0;
    s_window_count = 0;
    s_alert = false;
    s_alert_rate = 0;
    s_last_flood_us = 0;
    memset(s_alert_bssid, 0, 6);

    esp_err_t err = wifi_sniff_start(0, true);
    if (err != ESP_OK) return err;

    wifi_sniff_set_frame_cb(wids_frame_cb);
    s_running = true;
    ESP_LOGI(TAG, "watching for deauth/disassoc floods");
    return ESP_OK;
}

esp_err_t wids_stop(void)
{
    if (!s_running) return ESP_OK;
    wifi_sniff_set_frame_cb(NULL);
    wifi_sniff_stop();
    s_running = false;
    s_alert = false;
    return ESP_OK;
}

bool wids_is_running(void)
{
    return s_running;
}

esp_err_t wids_get_stats(wids_stats_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;

    /* Clear a stale alert once the flood has been quiet for a while —
       checked here (poll time) rather than from a timer, same pattern
       the rest of the UI/stats layer already uses. */
    if (s_alert && s_last_flood_us &&
        (esp_timer_get_time() - s_last_flood_us) > QUIET_US) {
        s_alert = false;
    }

    out->deauth_total = s_deauth_total;
    out->disassoc_total = s_disassoc_total;
    out->running = s_running;
    out->alert = s_alert;
    memcpy(out->alert_bssid, s_alert_bssid, 6);
    out->alert_rate = s_alert_rate;
    return ESP_OK;
}
