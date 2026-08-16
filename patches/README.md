# GHOSTTAP WiFi injection patch (ESP32-C5)

## Why

`esp_wifi_80211_tx()` is the IDF API for raw 802.11 frame injection.
On the ESP32-C5, the **stock** `libnet80211.a` refuses to transmit
management frames (beacon / deauth / probe-request) when the source
address does not belong to the interface — i.e. when the frame carries
a **spoofed SA**, which is what every deauth/beacon-flood tool needs.

Without the patch the attack engine in this project still works, but is
restricted to frames the radio believes are its own (effectively 2.4 GHz
only and with a limited effect). The patch relaxes that sanity check.

## The patch

Community-maintained prebuilt `libnet80211.a` (built against
ESP-IDF **v5.5.1**, tested on the Waveshare ESP32-C5-LCD-1.47):

- Primary: https://github.com/maxbrito500/esp32-c5-deauth
  raw: `https://raw.githubusercontent.com/maxbrito500/esp32-c5-deauth/main/esp32-c5/patched_libnet/libnet80211.a`
- Mirror: https://github.com/AnvilBrain/esp32-c5-dualband-deauther
  raw: `.../AnvilBrain/esp32-c5-dualband-deauther/main/patched_libnet/libnet80211.a`

These are same-binary/dual-band compatible builds for IDF 5.5.1.

## Install

```sh
. $IDF_PATH/export.sh
./patches/apply_libnet80211_patch.sh
idf.py build flash
```

The script:

1. locates your IDF installation,
2. verifies it is IDF 5.5.x,
3. backs the stock lib up to `libnet80211.a.orig`,
4. downloads + SHA-verifies + installs the patched lib.

Roll back with:

```sh
./patches/apply_libnet80211_patch.sh --restore
```

> Alternative for other IDF versions: build your own patched library.
> The change is one check inside `esp_wifi_80211_tx` / `wifi_auth` that
> validates the frame's source MAC against the interface MAC; patch the
> IDF source (`esp_wifi/src/net80211/`) and rebuild `libnet80211.a`.

## Legal

Use only against networks/devices you own or are authorized to test.
