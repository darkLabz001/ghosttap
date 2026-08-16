/*
 * GHOSTTAP WiFi attack engine — raw 802.11 frame injection.
 *
 * Deauthentication, beacon flood and probe flood using
 * esp_wifi_80211_tx() in AP mode (2.4 + 5 GHz).
 *
 * NOTE (C5): the stock IDF libnet80211.a rejects management frames with
 * a spoofed source address on the 5 GHz radio.  Apply the binary patch
 * shipped in patches/ (run patches/apply_libnet80211_patch.sh) or the
 * deauth/flood attacks will be limited to 2.4 GHz only.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ATTACK_MAX_SSIDS 4
#define ATTACK_FRAME_LEN 128

typedef enum {
    ATTACK_NONE = 0,
    ATTACK_DEAUTH,
    ATTACK_DEAUTH_ALL,
    ATTACK_BEACON,
    ATTACK_PROBE,
} attack_type_t;

typedef struct {
    attack_type_t type;
    uint8_t       bssid[6];           /* target AP          */
    uint8_t       client[6];          /* deauth target / ff.. */
    char          ssids[ATTACK_MAX_SSIDS][33];
    uint8_t       ssid_count;
    uint8_t       channel;
    uint32_t      sent;
    bool          running;
} attack_state_t;

/* Put WiFi into AP mode ready for injection. */
esp_err_t wifi_attack_init(void);

/* Configure a single attack and start its task. */
esp_err_t wifi_attack_start(attack_type_t type, const uint8_t *bssid,
                            const uint8_t *client, const char *ssid,
                            uint8_t channel);
esp_err_t wifi_attack_stop(void);

void wifi_attack_get_state(attack_state_t *out);

#ifdef __cplusplus
}
#endif
