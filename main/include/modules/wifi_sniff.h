/*
 * GHOSTTAP WiFi sniffer — promiscuous (monitor) mode packet capture.
 *
 * Captures 802.11 management/data frames on 2.4 and 5 GHz, parses
 * beacons/probes, tracks unique BSSIDs and keeps a rolling frame log.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SNIFF_MAX_BSSID 48
#define SNIFF_LOG_DEPTH 24

typedef enum {
    SNIFF_FRAME_MGMT = 0,
    SNIFF_FRAME_CTRL,
    SNIFF_FRAME_DATA,
    SNIFF_FRAME_OTHER,
} sniff_frame_class_t;

/* Decoded fields for one captured frame. */
typedef struct {
    uint8_t           channel;
    int8_t            rssi;
    uint8_t           ftype;    /* 802.11 frame type   */
    uint8_t           subtype;
    uint8_t           src[6];
    uint8_t           dst[6];
    char              ssid[33]; /* valid for beacons/probe-resp */
    uint32_t          raw_len;
} sniff_frame_t;

typedef struct {
    uint32_t total;
    uint32_t beacons;
    uint32_t probe_req;
    uint32_t probe_resp;
    uint32_t data;
    uint32_t ctrl;
    uint32_t other;
    uint32_t unique_bssid;
    uint32_t dropped;
    uint32_t pkt_per_sec;
    int8_t   last_rssi;
    uint8_t  channel;
} sniff_stats_t;

typedef void (*sniff_frame_cb_t)(const sniff_frame_t *f);

/* Start sniffing. If hop, sweep the active channel list automatically. */
esp_err_t wifi_sniff_start(uint8_t channel, bool hop);
esp_err_t wifi_sniff_stop(void);
esp_err_t wifi_sniff_set_channel(uint8_t channel);

esp_err_t wifi_sniff_get_stats(sniff_stats_t *out);

/* Optional per-frame callback (called from WiFi task context). */
void wifi_sniff_set_frame_cb(sniff_frame_cb_t cb);

/* Rolling log of decoded frames (UI shows the last few). */
const sniff_frame_t *wifi_sniff_get_log(size_t *count);

/* ---- KARMA probe-request harvester ---------------------------------
 * Whenever the sniffer is running (any screen/mode — Sniffer, WIDS, or
 * Karma itself), it opportunistically dedupes SSIDs seen in probe
 * requests. This is what a client's "preferred network list" leaks
 * even when it never associates — classic KARMA recon.
 */
#define KARMA_MAX_SSIDS 16

typedef struct {
    char     ssid[33];
    uint32_t hits;
    int8_t   last_rssi;
} karma_ssid_t;

const karma_ssid_t *wifi_sniff_get_probed_ssids(size_t *count);
void wifi_sniff_clear_probed_ssids(void);

#ifdef __cplusplus
}
#endif
