/*
 * GHOSTTAP WIDS — passive deauth/disassoc flood alarm.
 *
 * Rides the existing wifi_sniff promiscuous capture (via its frame
 * callback) and watches the rate of deauth/disassoc management frames.
 * When it crosses a threshold within a 1s window, raises an alert with
 * the offending BSSID until the flood goes quiet again.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t deauth_total;
    uint32_t disassoc_total;
    bool     running;
    bool     alert;
    uint8_t  alert_bssid[6];
    uint32_t alert_rate;      /* frames/sec that tripped the alert */
} wids_stats_t;

esp_err_t wids_start(void);
esp_err_t wids_stop(void);
bool      wids_is_running(void);
esp_err_t wids_get_stats(wids_stats_t *out);

#ifdef __cplusplus
}
#endif
