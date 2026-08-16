# GHOSTTAP — platform research & design notes

Facts and decisions gathered before writing code, kept so future work has
the full context (hardware arrived later, so on-device verification is
pending).

## Board: Waveshare ESP32-C5-LCD-1.47

| Item | Value |
|---|---|
| SoC | ESP32-C5FH4 (RISC-V single-core, 240 MHz) |
| RAM | 384 KB HP SRAM + 16 KB LP SRAM — **no PSRAM** |
| Flash | 4 MB (QSPI) |
| Radio | Wi-Fi 6 **dual-band 2.4/5 GHz**, BLE 5, IEEE 802.15.4 (Zigbee/Thread) |
| Display | 1.47" TFT 172x320, ST7789, SPI, 260K color |
| Touch | none → **single-button UI** |
| Button | on-board BOOT (GPIO9 on the C5 reference design — **verify**) |
| LEDs | 1x WS2812 RGB (GPIO8) |
| microSD | yes, shares the LCD SPI bus |
| USB | native, USB-Serial-JTAG (GPIO13/14) |

### Verified pin map

```
LCD   CLK=7   DIN=6   CS=23  DC=24  RST=26  BL=10
SD    CS=4    MISO=5  MOSI=6 CLK=7         (shared bus)
WS2812        GPIO8
UART0         TX=11 RX=12
USB           D+=14 D-=13
```

All pins above are confirmed from the Waveshare wiki + sample code
(`/tmp/opencode/wsrefs/`). **BOOT button = GPIO9 is assumed** (reference
design); confirm with a meter when hardware is on the bench.

## Framework / build

- **ESP-IDF >= 5.3**, developed against 5.5.x (Waveshare examples use 5.5.2).
- BSP component `waveshare/esp32_c5_lcd_1_47` v1.0.0
  (pulls `espressif/esp_lvgl_port ^2`, `espressif/led_strip *`, `lvgl/lvgl >=8,<10`).
- **LVGL pinned to `^8.4.0`** so all UI code uses the LVGL 8 API; the
  few 9.x differences (e.g. `lv_screen_active()`) are behind
  `LVGL_VERSION_MAJOR` guards.
- Display rotated 90° → landscape UI 320x172.
- Custom `partitions.csv`: nvs / phy_init / factory (2M) / storage (1M spiffs).

## Pentest capability matrix (ESP32-C5)

| Capability | Status | Notes |
|---|---|---|
| Dual-band AP scan | ✅ real | `esp_wifi_scan_start`, band inferred from channel (<=14 = 2.4G) |
| Promiscuous monitor + channel hop | ✅ real | `esp_wifi_set_promiscuous`; parse FC directly from payload (C5 callback `type` hint is unreliable) |
| Raw frame injection (deauth/beacon/probe) | ✅ real (needs patch) | `esp_wifi_80211_tx` in AP mode; spoofed SA blocked by stock `libnet80211.a` → `patches/` |
| BLE 5 scanner | ✅ real | NimBLE (built into IDF); `CONFIG_BT_NIMBLE_ROLE_CENTRAL/OBSERVER` |
| 802.15.4 (Zigbee/Thread) sniffing | ✅ real | `esp_ieee802154` promiscuous RX |
| SD capture logging | ✅ real | FATFS via BSP, shared SPI bus |
| Evil portal / captive portal | 📋 future | keep SoftAP enabled in config |

### Radio-sharing rules

- **BLE and 802.15.4 share the 2.4 GHz radio** → never run both at once.
- Wi-Fi (2.4G) + BLE are concurrent-capable but sharing is fragile; the
  UI enforces one tool at a time.
- Promiscuous sniffing requires power-save off (`esp_wifi_set_ps(WIFI_PS_NONE)`).

## Verified IDF 5.5.1 APIs

- `wifi_promiscuous_pkt_t { wifi_pkt_rx_ctrl_t rx_ctrl; uint8_t payload[0]; }`
  — use `rx_ctrl.rssi/.channel/.sig_len`; never trust the callback `type`.
- `esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq)`.
- IEEE 802.15.4 (component `ieee802154` in REQUIRES):
  - `esp_ieee802154_enable()`, `esp_ieee802154_set_channel()`,
    `esp_ieee802154_set_promiscuous()`, `esp_ieee802154_receive()`,
    `esp_ieee802154_disable()`
  - callback: `esp_ieee802154_event_callback_list_register()` with
    `rx_done_cb(uint8_t *data, esp_ieee802154_frame_info_t *info)` —
    **frame length = `data[0]` (PHR byte)**, payload at `data[1]`; then
    `esp_ieee802154_receive_handle_done(data)`.
  - `CONFIG_IEEE802154_ENABLED` defaults on when the target supports it.
- NimBLE: `nimble_port_init()`, `ble_gap_disc()`, `BLE_GAP_EVENT_DISC`,
  `BLE_GAP_EVENT_DISC_COMPLETE`. In IDF 5.5 it is built-in (no manifest dep).

## Memory constraints (no PSRAM)

- Small static buffers everywhere; no heap-heavy allocations on the
  hot path. AP list = 64 records; frame logs ring-buffered.
- LVGL draw buffer height 80 (via `CONFIG_BSP_DISPLAY_LVGL_BUF_HEIGHT`).
- UI fonts: Montserrat 14/16/20/28 only.

## UX design

- No touch → **SHORT press = NEXT, LONG press = SELECT** on BOOT.
- Generic vertical-menu framework reused by every screen.
- `CONFIG_APP_UI_DEMO_MODE` auto-advances for bench demos.
- Home screen: tool list + radio status dots (WiFi / BLE / ZB / SD).
- Theme: dark field-terminal, matrix-green accent.

## Open items for hardware day

- [ ] Confirm BOOT button GPIO (default assumed GPIO9).
- [ ] Confirm SD card detection + shared-bus stability at 80 MHz.
- [ ] Verify 5 GHz `esp_wifi_80211_tx` after applying the patch.
- [ ] Verify BLE vs 802.15.4 mutual exclusion at runtime.
