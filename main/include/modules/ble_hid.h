/*
 * GHOSTTAP BLE HID keyboard — wireless "BadUSB".
 *
 * The C5 has no USB-OTG (only USB-Serial-JTAG), so physical USB HID is
 * impossible.  This module advertises as a BLE keyboard (HID over GATT)
 * and types keystrokes into whatever host pairs with it — a remote
 * rubber-ducky over Bluetooth.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_HID_SCRIPT_MAX 2048

/* Start advertising as a connectable BLE keyboard. */
esp_err_t ble_hid_start(void);
esp_err_t ble_hid_stop(void);
bool     ble_hid_is_running(void);
bool     ble_hid_is_connected(void);

/* Type a plain string (async; runs in a worker task). */
esp_err_t ble_hid_type_string(const char *text);

/* Type a DuckyScript-lite payload (lines of STRING/ENTER/GUI/...). */
esp_err_t ble_hid_run_script(const char *script);

void ble_hid_get_stats(uint32_t *chars, uint32_t *keys, bool *connected);

#ifdef __cplusplus
}
#endif
