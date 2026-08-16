/*
 * GHOSTTAP WPA handshake / PMKID capture.
 *
 * Runs the promiscuous sniffer and pulls 802.11 EAPOL key frames
 * (messages 1-4) plus beacon RSNE/PMKID data.  Raw interesting frames
 * are queued for streaming to the host TUI, which assembles a .pcap
 * for hcxpcapngtool / aircrack-ng.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HS_MAX_APS        16
#define HS_CAP_DEPTH      32
#define HS_CAP_FRAME_MAX  256

typedef struct {
    uint8_t  ap[6];
    uint8_t  sta[6];
    char     ssid[33];
    bool     has_m1;
    bool     has_m2;
    bool     has_m3;
    uint8_t  anonce[32];
    uint8_t  snonce[32];
    uint8_t  pmkid[16];
    bool     has_pmkid;
    bool     beacon_queued;
    uint32_t eapol_frames;
    uint32_t last_seen_ms;
} hs_ap_t;

typedef struct {
    uint32_t total_eapol;
    uint32_t total_beacons;
    uint32_t handshakes;      /* APs with M1 + M2 */
    uint32_t pmkids;
    uint8_t  ap_count;
    bool     running;
} hs_stats_t;

/* Capture-ring record (raw 802.11 frame, as received incl. FCS). */
typedef struct {
    uint16_t len;
    uint16_t seq;
    uint8_t  data[HS_CAP_FRAME_MAX];
} hs_cap_t;

/* Start capture. channel 0 + hop=true sweeps; or fix a channel. */
esp_err_t wifi_handshake_start(uint8_t channel, bool hop);
esp_err_t wifi_handshake_stop(void);
bool     wifi_handshake_is_running(void);

esp_err_t wifi_handshake_get_stats(hs_stats_t *out);
const hs_ap_t *wifi_handshake_get_aps(size_t *count);

/* Pop the next queued frame for streaming (1 = got one, 0 = none). */
int wifi_handshake_pop_capture(hs_cap_t *out);

#ifdef __cplusplus
}
#endif
