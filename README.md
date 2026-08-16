# GHOSTTAP — Pentest Field Unit

<img width="1920" height="1280" alt="ghosttap_hacker_cutout" src="https://github.com/user-attachments/assets/d80ed4c8-7a17-4f00-8c15-53afa65c51c4" />


A pocket-sized Wi-Fi / BLE / Zigbee **assessment toolkit** for the
[Waveshare ESP32-C5-LCD-1.47](https://www.waveshare.com/esp32-c5-lcd-1.47.htm)
(dual-band Wi-Fi 6, BLE 5, IEEE 802.15.4, 1.47" ST7789 LCD, WS2812, microSD).

> **Authorized use only.** This firmware is for security research and
> testing on equipment you own or are explicitly permitted to assess.

## Features

- **Wi-Fi scan** — dual-band (2.4 + 5 GHz) AP discovery with signal/band/rate tags
- **Sniffer** — promiscuous monitor mode, channel hopping, beacon/BSSID tracking
- **Handshake / PMKID capture** — EAPOL M1–M4 + PMKID KDE detection; raw
  frames stream over USB to the host TUI which writes a `.pcap` and
  auto-converts it with `hcxpcapngtool` (hashcat 22000)
- **Attacks** — deauth (targeted / broadcast), beacon flood, probe flood
  via `esp_wifi_80211_tx` (needs the `libnet80211.a` patch for spoofed SA, see `patches/`)
- **Target selection** — pick any scanned AP from the last scan as the attack target
- **BLE scan** — BLE 5 device discovery via NimBLE
- **BLE spam** — Flipper-style phantom-device advertisement flood
- **BLE HID keyboard** — wireless rubber-ducky (HID-over-GATT). The C5 has
  no USB-OTG, so this replaces a physical USB BadUSB
- **Zigbee / Thread sniffing** — native 802.15.4 promiscuous capture
- **Evil portal** — WPA2 SoftAP + DNS spoof + captive login page; captured
  credentials shown on screen, logged to SD and pushed to the host TUI
- **USB command bridge** — full remote control from a host over the
  USB-Serial-JTAG port (line protocol, see `main/src/cmd.c`)
- **Host TUI** — hacker-themed curses control panel (`tui/ghosttap_tui.py`)
- **SD logging** — session capture logs to microSD
- **Status LED** — semantic WS2812 animations per tool
- **Single-button UI** — SHORT = next, LONG = select (no touch screen)

## Hardware

- Waveshare ESP32-C5-LCD-1.47
- Optional: microSD card for logging

See `docs/RESEARCH.md` for pin map, capability matrix and design notes.

## Build & flash

Requires ESP-IDF **5.5.x** (`idf.py` on PATH).

```sh
. $IDF_PATH/export.sh
cd ghosttap

idf.py set-target esp32c5
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

For full frame-injection (deauth/beacon/probe with spoofed source MAC),
apply the WiFi library patch once per IDF installation:

```sh
./patches/apply_libnet80211_patch.sh
idf.py build flash
```

See `patches/README.md` for details and rollback instructions.

## Host TUI

Control the device from this machine over USB (shows up as `/dev/ttyACM0`):

```sh
pip install pyserial          # if missing
python3 tui/ghosttap_tui.py      # or: -p /dev/ttyACM0
```

Keys: `UP/DOWN` pick tool, `ENTER` act, `s` scan, `SPACE` set target,
`1-4` launch attacks, `x` stop everything, `e` start portal, `t` type HID
payload, `p` open/close pcap, `c` ping, `q` quit.

Captured handshakes are written to `captures/*.pcap` and converted to
hashcat 22000 format automatically when `hcxpcapngtool` is installed
(`apt install hcxtools`).

## USB protocol

Line-based ASCII over the USB-Serial-JTAG port; device events are
`!`-prefixed.  Summary (full reference at the top of `main/src/cmd.c`):

```
PING / GET <STATUS|SCAN|SNIFF|HAND|CAP|BLE|BLE_SPAM|HID|ZB|SD|PORTAL>
SCAN [PASSIVE] / SNIFF ON|OFF / HANDSHAKE ON [ch]|OFF
ATTACK DEAUTH|DEAUTHALL|BEACON|PROBE <idx|bssid> [ch] / ATTACK STOP
PORTAL ON <ssid> / OFF / BLE SCAN <ms> / BLE SPAM ON|OFF
HID ON|OFF / HID TYPE ... HID END / ZB ON <ch>|OFF / LED / LOG / REBOOT
```

## Configuration

`idf.py menuconfig` → "GHOSTTAP Pentest Field Unit":

- `APP_UI_DEMO_MODE` — auto-cycle screens without buttons
- `APP_WIFI_SCAN` / `APP_WIFI_SNIFF` / `APP_WIFI_ATTACK` / `APP_BLE_SCAN` / `APP_ZB_SNIFF` / `APP_SD_LOG` / `APP_EVIL_PORTAL` — enable/disable tools

## Project layout

```
ghosttap/
├── sdkconfig.defaults      target/flash/radio defaults
├── partitions.csv          custom partition table
├── patches/                libnet80211.a injection patch + apply script
├── docs/RESEARCH.md        platform research, APIs, constraints
├── tui/ghosttap_tui.py        host-side curses control TUI
└── main/
    ├── idf_component.yml   BSP + LVGL 8 dependency pinning
    ├── include/            board.h, app.h, cmd.h, ui/, modules/
    └── src/
        ├── app_main.c      boot + UI event bridge
        ├── app_button.c    debounced single-button driver
        ├── cmd.c           USB-Serial-JTAG command bridge
        ├── ui/             theme, icons, screens
        └── modules/        wifi_scan, wifi_sniff, wifi_attack,
                            wifi_handshake, ble_core, ble_scan, ble_spam,
                            ble_hid, zb_sniff, sd_log, sys_led, evil_portal
```

## Legal

You are responsible for using this responsibly and legally. Penetration
testing without authorization is illegal in most jurisdictions.
