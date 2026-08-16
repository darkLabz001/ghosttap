/*
 * GHOSTTAP IEEE 802.15.4 sniffer — Zigbee / Thread promiscuous capture.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZB_FRAME_MAX  127
#define ZB_QUEUE_DEPTH 16

typedef struct {
    uint16_t len;              /* PSDU length incl. FCS */
    uint8_t  data[ZB_FRAME_MAX];
    int8_t   rssi;
    uint8_t  lqi;
    uint8_t  channel;
    uint8_t  frame_type;       /* 0 beacon / 1 data / 2 ack / 3 cmd */
} zb_frame_t;

typedef struct {
    uint32_t total;
    uint32_t beacons;
    uint32_t data_frames;
    uint32_t acks;
    uint32_t commands;
    uint32_t pan_ids[8];       /* distinct PAN IDs seen */
    uint8_t  pan_count;
    bool     running;
} zb_sniff_stats_t;

/* Start promiscuous sniffing on 802.15.4 channel 11-26. */
esp_err_t zb_sniff_start(uint8_t channel);
esp_err_t zb_sniff_stop(void);
esp_err_t zb_sniff_set_channel(uint8_t channel);

esp_err_t zb_sniff_get_stats(zb_sniff_stats_t *out);

/* Pop the oldest captured frame (blocks up to timeout_ms). */
esp_err_t zb_sniff_pop_frame(zb_frame_t *out, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
