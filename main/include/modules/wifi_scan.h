/*
 * GHOSTTAP WiFi scanner — dual band (2.4 + 5 GHz) AP discovery.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_wifi_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_SCAN_MAX_APS 64

typedef enum {
    WIFI_SCAN_BAND_2G4 = 0,
    WIFI_SCAN_BAND_5G,
} wifi_scan_band_t;

typedef struct {
    char              ssid[33];
    uint8_t           bssid[6];
    int8_t            rssi;
    uint8_t           channel;
    wifi_scan_band_t  band;
    wifi_auth_mode_t  authmode;
    bool              is_11ax;      /* Wi-Fi 6 */
    bool              hidden;
} wifi_ap_t;

/* Initializes WiFi in STA mode (required for both scan and sniffer). */
esp_err_t wifi_scan_init(void);

/* Trigger an async scan. Returns immediately; wait on _wait_results(). */
esp_err_t wifi_scan_start(bool passive);

/* Block until the scan completes (or timeout_ms) and copy results out. */
esp_err_t wifi_scan_wait_results(wifi_ap_t *out, size_t max,
                                 size_t *count, uint32_t timeout_ms);

/* Access the internal result cache (call after scan finished). */
const wifi_ap_t *wifi_scan_get_results(size_t *count);

#ifdef __cplusplus
}
#endif
