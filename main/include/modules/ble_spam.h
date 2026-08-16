/*
 * GHOSTTAP BLE advertising spam — Flipper-style packet flood.
 *
 * Continuously restarts advertising with a random address + random
 * device name, so scanners see a stream of phantom BLE devices.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_SPAM_MAX_NAMES 16

esp_err_t ble_spam_start(void);
esp_err_t ble_spam_stop(void);
bool     ble_spam_is_running(void);

void ble_spam_get_stats(uint32_t *packets, uint32_t *names,
                        char *last_name, size_t namelen);

#ifdef __cplusplus
}
#endif
