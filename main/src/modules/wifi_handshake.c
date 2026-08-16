/*
 * GHOSTTAP WPA handshake / PMKID capture.
 *
 * Sits on top of the promiscuous sniffer (wifi_sniff) and watches for:
 *   - EAPOL-Key frames (802.1X type 3): messages 1..4
 *   - Beacon RSNE (tag 0x30) that advertises a PMKID count
 *   - PMKID KDE inside EAPOL M1 key data (OUI 00-0f-ac, type 0x04)
 *
 * Interesting frames are queued (raw, incl. FCS) so the host TUI can
 * assemble a .pcap for hcxpcapngtool / aircrack-ng.  On-device stats
 * show which APs have complete handshakes.
 *
 * This firmware is for authorized security testing only.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_wifi.h"

#include "modules/wifi_handshake.h"
#include "modules/wifi_sniff.h"
#include "modules/wifi_scan.h"

static const char *TAG = "wifi_handshake";

static hs_ap_t    s_aps[HS_MAX_APS];
static uint8_t    s_ap_count;
static hs_stats_t s_stats;
static volatile bool s_running;

static hs_cap_t   s_ring[HS_CAP_DEPTH];
static uint32_t   s_ring_head;
static uint32_t   s_ring_tail;
static uint16_t   s_cap_seq;

#define HOP_LIST_LEN 11
static const uint8_t s_hop_list[HOP_LIST_LEN] = { 1,2,3,4,5,6,7,8,9,10,11 };
static bool  s_hop;
static TaskHandle_t s_hop_task;

static void hop_task(void *arg)
{
    uint8_t idx = 0;
    while (1) {
        if (s_running && s_hop) {
            idx = (idx + 1) % HOP_LIST_LEN;
            esp_wifi_set_channel(s_hop_list[idx], WIFI_SECOND_CHAN_NONE);
        }
        vTaskDelay(pdMS_TO_TICKS(300));
    }
}

/* ---- EAPOL parsing helpers ------------------------------------- */
/* Returns offset of EAPOL payload in the 802.11 frame, or 0. */
static uint16_t eapol_offset(const uint8_t *p, uint32_t len, uint8_t *subtype)
{
    if (len < 32) return 0;
    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x03) != 2) return 0;      /* data frame */
    *subtype = (fc0 >> 4) & 0x0f;

    uint16_t hdr = 24;
    if (*subtype >= 8) hdr += 2;                 /* QoS control */

    /* LLC/SNAP: aa aa 03 00 00 00 88 8e */
    const uint8_t *llc = &p[hdr];
    if (len < hdr + 8) return 0;
    if (llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03) return 0;
    if (llc[6] != 0x88 || llc[7] != 0x8e) return 0;   /* EtherType EAPOL */
    return hdr + 8;
}

/* --- frame: fields we care about --- */
static void parse_addrs(const uint8_t *p, uint8_t to_ds, uint8_t from_ds,
                        uint8_t ap[6], uint8_t sta[6])
{
    /* addr1 = p[4..10], addr2 = p[10..16] */
    if (to_ds) {
        memcpy(ap, &p[4], 6);
        memcpy(sta, &p[10], 6);
    } else {
        memcpy(ap, &p[10], 6);   /* from_ds=1 or ad-hoc: AP = transmitter */
        memcpy(sta, &p[4], 6);
    }
}

static hs_ap_t *find_ap(const uint8_t ap[6])
{
    for (uint8_t i = 0; i < s_ap_count; i++) {
        if (memcmp(s_aps[i].ap, ap, 6) == 0) return &s_aps[i];
    }
    return NULL;
}

static hs_ap_t *alloc_ap(const uint8_t ap[6])
{
    hs_ap_t *a = find_ap(ap);
    if (a) return a;
    if (s_ap_count >= HS_MAX_APS) return NULL;
    a = &s_aps[s_ap_count++];
    memset(a, 0, sizeof(*a));
    memcpy(a->ap, ap, 6);
    return a;
}

/* Scan M1 key data for a PMKID KDE: dd <len> 00 0f ac 04 <16 bytes> */
static void find_pmkid(const uint8_t *kd, uint16_t kdlen, hs_ap_t *ap)
{
    uint16_t off = 0;
    while (off + 2 <= kdlen) {
        uint8_t id = kd[off];
        uint8_t len = kd[off + 1];
        if (id == 0xdd && len >= 22 && off + 2 + len <= kdlen) {
            if (kd[off + 2] == 0x00 && kd[off + 3] == 0x0f &&
                kd[off + 4] == 0xac && kd[off + 5] == 0x04) {
                memcpy(ap->pmkid, &kd[off + 6], 16);
                ap->has_pmkid = true;
                s_stats.pmkids++;
                return;
            }
        }
        off += 2 + len;
    }
}

static void handle_eapol(const uint8_t *p, uint32_t len, uint16_t eo,
                         uint8_t fc1)
{
    if (len < eo + 4) return;
    if (p[eo + 1] != 3) return;                /* EAPOL type != key */
    uint16_t eapol_len = (uint16_t)((p[eo + 2] << 8) | p[eo + 3]);
    if (eapol_len < 99) return;                /* too short for a key msg */
    if (len < eo + 99) return;

    uint16_t key_info = (uint16_t)((p[eo + 5] << 8) | p[eo + 6]);
    bool ack    = (key_info & 0x0080) != 0;
    bool mic    = (key_info & 0x0008) != 0;
    bool secure = (key_info & 0x0020) != 0;

    const uint8_t *nonce = &p[eo + 17];
    uint16_t kdlen = (uint16_t)((p[eo + 97] << 8) | p[eo + 98]);
    const uint8_t *kd = &p[eo + 99];
    if (kdlen > len - (eo + 99)) kdlen = (uint16_t)(len - (eo + 99));

    uint8_t to_ds = fc1 & 0x01;
    uint8_t from_ds = (fc1 >> 1) & 0x01;

    uint8_t ap[6], sta[6];
    parse_addrs(p, to_ds, from_ds, ap, sta);

    s_stats.total_eapol++;

    hs_ap_t *a = alloc_ap(ap);
    if (!a) return;
    a->eapol_frames++;
    a->last_seen_ms = (uint32_t)(esp_timer_get_time() / 1000);
    if (a->sta[0] == 0 || memcmp(a->sta, "\xff\xff\xff\xff\xff\xff", 6) == 0) {
        memcpy(a->sta, sta, 6);
    }

    if (ack && !mic) {                          /* M1: AP -> STA */
        memcpy(a->anonce, nonce, 32);
        a->has_m1 = true;
        find_pmkid(kd, kdlen, a);
    } else if (!ack && mic && !secure) {        /* M2: STA -> AP */
        memcpy(a->snonce, nonce, 32);
        a->has_m2 = true;
    } else if (ack && mic) {                    /* M3 */
        a->has_m3 = true;
    }

    if (a->has_m1 && a->has_m2) {
        if (s_stats.handshakes == 0) {
            /* first complete pair this session */
            ESP_LOGI(TAG, "HANDSHAKE captured for AP " MACSTR,
                     MAC2STR(a->ap));
        }
    }
}

static hs_ap_t *handle_beacon(const uint8_t *p, uint32_t len)
{
    s_stats.total_beacons++;
    if (len < 36) return NULL;

    uint8_t ssid[33] = { 0 };
    bool have_ssid = false;
    bool pmkid_adv = false;

    uint32_t off = 36;
    while (off + 2 <= len) {
        uint8_t tag = p[off];
        uint8_t tlen = p[off + 1];
        if (off + 2 + tlen > len) break;
        if (tag == 0x00 && tlen <= 32 && tlen > 0) {
            memcpy(ssid, &p[off + 2], tlen);
            have_ssid = true;
        } else if (tag == 0x30 && tlen >= 20) {
            /* RSNE: version(2) group(4) pwcnt(2)+pwc(4n) akmcnt(2)+akm(4m)
               rsncaps(2) [pmkidcnt(2)+pmkids(16n)] */
            uint32_t i = 2 + 4;
            uint32_t pwcnt = (uint32_t)((p[off + 2 + i] << 8) | p[off + 2 + i + 1]);
            i += 2 + pwcnt * 4;
            if (i + 2 <= tlen) {
                uint32_t akmcnt = (uint32_t)((p[off + 2 + i] << 8) | p[off + 2 + i + 1]);
                i += 2 + akmcnt * 4;
                i += 2;                          /* rsn caps */
                if (i + 2 <= tlen) {
                    uint32_t pcnt = (uint32_t)((p[off + 2 + i] << 8) | p[off + 2 + i + 1]);
                    if (pcnt > 0) pmkid_adv = true;
                }
            }
        }
        off += 2 + tlen;
    }

    if (!have_ssid) return NULL;

    uint8_t ap[6], sta[6];
    memcpy(ap, &p[10], 6);       /* beacon SA */
    memcpy(sta, &p[4], 6);
    (void)sta;

    hs_ap_t *a = alloc_ap(ap);
    if (!a) return NULL;
    if (!a->ssid[0]) {
        snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    }
    if (pmkid_adv && !a->has_pmkid) {
        a->has_pmkid = true;
        s_stats.pmkids++;
    }
    return a;
}

static void raw_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    if (!s_running) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    uint32_t len = pkt->rx_ctrl.sig_len;
    if (len < 2) return;

    uint8_t fc0 = p[0], fc1 = p[1];
    uint8_t ftype = (fc0 >> 2) & 0x03;
    uint8_t subtype = (fc0 >> 4) & 0x0f;

    bool keep = false;
    if (ftype == 2) {
        uint8_t sub = 0;
        uint16_t eo = eapol_offset(p, len, &sub);
        if (eo) {
            handle_eapol(p, len, eo, fc1);
            keep = true;
        }
    } else if (ftype == 0 && subtype == 0x08) {
        hs_ap_t *a = handle_beacon(p, len);
        if (a && !a->beacon_queued) {
            a->beacon_queued = true;
            keep = true;      /* first beacon for this AP -> stream */
        }
    }

    if (!keep) return;
    if (len > HS_CAP_FRAME_MAX) len = HS_CAP_FRAME_MAX;

    uint32_t next = (s_ring_head + 1) % HS_CAP_DEPTH;
    if (next == s_ring_tail) s_ring_tail = (s_ring_tail + 1) % HS_CAP_DEPTH;
    hs_cap_t *c = &s_ring[s_ring_head];
    c->len = (uint16_t)len;
    c->seq = s_cap_seq++;
    memcpy(c->data, p, len);
    s_ring_head = next;
}

/* ---- public API ------------------------------------------------- */
esp_err_t wifi_handshake_start(uint8_t channel, bool hop)
{
    if (s_running) return ESP_ERR_INVALID_STATE;

    ESP_ERROR_CHECK(wifi_scan_init());

    memset(&s_stats, 0, sizeof(s_stats));
    s_ap_count = 0;
    s_ring_head = s_ring_tail = 0;
    s_cap_seq = 0;

    s_running = true;
    s_hop = hop;
    esp_wifi_set_promiscuous_rx_cb(raw_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel ? channel : 1, WIFI_SECOND_CHAN_NONE);
    if (hop && !s_hop_task) {
        xTaskCreate(hop_task, "hs_hop", 2048, NULL, 4, &s_hop_task);
    }
    ESP_LOGI(TAG, "handshake capture started ch=%u hop=%d", channel, (int)hop);
    return ESP_OK;
}

esp_err_t wifi_handshake_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;
    esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "handshake capture stopped");
    return ESP_OK;
}

bool wifi_handshake_is_running(void) { return s_running; }

esp_err_t wifi_handshake_get_stats(hs_stats_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    *out = s_stats;
    out->ap_count = s_ap_count;
    out->running = s_running;
    uint32_t hs = 0, pmk = 0;
    for (uint8_t i = 0; i < s_ap_count; i++) {
        if (s_aps[i].has_m1 && s_aps[i].has_m2) hs++;
        if (s_aps[i].has_pmkid) pmk++;
    }
    out->handshakes = hs;
    out->pmkids = pmk;
    return ESP_OK;
}

const hs_ap_t *wifi_handshake_get_aps(size_t *count)
{
    if (count) *count = s_ap_count;
    return s_aps;
}

int wifi_handshake_pop_capture(hs_cap_t *out)
{
    if (s_ring_tail == s_ring_head) return 0;
    if (!out) return 0;
    memcpy(out, &s_ring[s_ring_tail], sizeof(*out));
    s_ring_tail = (s_ring_tail + 1) % HS_CAP_DEPTH;
    return 1;
}
