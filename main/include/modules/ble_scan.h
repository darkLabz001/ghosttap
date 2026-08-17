/*
 * GHOSTTAP BLE scanner — BLE 5 device discovery via NimBLE.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_SCAN_MAX_DEV 48

typedef enum {
    BLE_ADV_TYPE_ADV_IND = 0x00,
    BLE_ADV_TYPE_DIRECT_IND = 0x01,
    BLE_ADV_TYPE_SCAN_IND = 0x02,
    BLE_ADV_TYPE_NONCONN_IND = 0x03,
    BLE_ADV_TYPE_SCAN_RSP = 0x04,
} ble_adv_type_t;

/* Best-effort classification from manufacturer-data/service-UUID
 * signatures in the advertisement. Not cryptographically certain —
 * these are the well-known public identifiers each vendor's tracker
 * advertises with, not proof of the physical product. */
typedef enum {
    BLE_TRACKER_NONE = 0,
    BLE_TRACKER_FINDMY,     /* Apple Find My network (AirTag + accessories) */
    BLE_TRACKER_SMARTTAG,   /* Samsung Galaxy SmartTag                      */
    BLE_TRACKER_TILE,       /* Tile                                        */
} ble_tracker_type_t;

typedef struct {
    uint8_t      addr[6];
    uint8_t      addr_type;
    char         name[33];
    int8_t       rssi;
    ble_adv_type_t adv_type;
    uint8_t      fields_len;
    ble_tracker_type_t tracker;
} ble_dev_t;

const char *ble_tracker_type_name(ble_tracker_type_t t);

typedef struct {
    uint32_t total;     /* frames seen */
    uint32_t unique;    /* devices recorded */
    bool     running;
} ble_scan_stats_t;

esp_err_t ble_scan_init(void);
esp_err_t ble_scan_start(uint32_t duration_ms);
esp_err_t ble_scan_stop(void);

/* Block until the ongoing scan completes (or timeout_ms). */
esp_err_t ble_scan_wait_done(uint32_t timeout_ms);

const ble_dev_t *ble_scan_get_results(size_t *count);
esp_err_t ble_scan_get_stats(ble_scan_stats_t *out);

void ble_scan_addr_to_str(const uint8_t addr[6], char *buf);

#ifdef __cplusplus
}
#endif
