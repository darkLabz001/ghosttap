/*
 * GHOSTTAP shared BLE core — single NimBLE host instance.
 *
 * Every BLE tool (scan, spam, HID keyboard) boots the host through this
 * module so the radio stack is initialized exactly once.  The host is
 * brought up lazily on first use.
 */
#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Boot the NimBLE host exactly once (idempotent). */
esp_err_t ble_core_init(void);

/* Block until the host has synced with the controller (or timeout). */
esp_err_t ble_core_wait_sync(uint32_t timeout_ms);

bool ble_core_is_ready(void);

#ifdef __cplusplus
}
#endif
