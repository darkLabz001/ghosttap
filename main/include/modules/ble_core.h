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

/* Tears the NimBLE host + controller back down (~31KB). Implemented
 * per ESP-IDF's own nimble_port_stop()+nimble_port_deinit() pattern
 * (examples/bluetooth/nimble/blecent) and safe to call when not
 * initialized, BUT: reliably resets the chip with zero panic/assert
 * output when called on this esp32c5/IDF v5.5 combo, cause not fully
 * root-caused. Nothing in this codebase calls it — WiFi's driver
 * footprint is trimmed via sdkconfig instead so both radio stacks can
 * just stay resident together (see cmd.c claim_wifi_radio()). Don't
 * wire this back in without a real fix for the reset, or at least a
 * lot more investigation than "it crashed, tried once, moved on". */
esp_err_t ble_core_deinit(void);

/* Block until the host has synced with the controller (or timeout). */
esp_err_t ble_core_wait_sync(uint32_t timeout_ms);

bool ble_core_is_ready(void);

#ifdef __cplusplus
}
#endif
