/*
 * GHOSTTAP command bridge — USB-Serial-JTAG control protocol.
 *
 * Protocol: newline-terminated ASCII commands over the native USB port
 * (which shows up as /dev/ttyACM0 on the host).  Device responses and
 * unsolicited events are `!`-prefixed lines.  Fields within a line use
 * `|` as separator (SSIDs/names may contain spaces).
 *
 *   Host -> Device           Device -> Host
 *   ------------------       --------------------------------
 *   PING                     !PONG v0.3
 *   GET <what>               !AP / !SNIFF / !HAND / !CAP / ...
 *   SCAN [PASSIVE]           !SCAN_DONE n  then !AP lines
 *   SNIFF ON|OFF
 *   HANDSHAKE ON [ch]
 *   HANDSHAKE OFF
 *   ATTACK <type> <arg> [ch]
 *   ATTACK STOP
 *   PORTAL ON <ssid> [pass]
 *   PORTAL OFF
 *   BLE SCAN <ms>
 *   BLE SPAM ON|OFF
 *   HID ON|OFF
 *   HID TYPE ... HID END
 *   ZB ON <ch> / ZB OFF
 *   LED <mode>
 *   LOG ON|OFF
 *   REBOOT
 *
 * This firmware is for authorized security testing only.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"

#if CONFIG_ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG
#warning "Secondary USB console enabled: logs will interleave with the cmd protocol"
#endif

#include "driver/usb_serial_jtag.h"

#include "cmd.h"
#include "modules/wifi_scan.h"
#include "modules/wifi_sniff.h"
#include "modules/wifi_attack.h"
#include "modules/wifi_handshake.h"
#include "modules/ble_scan.h"
#include "modules/ble_spam.h"
#include "modules/ble_hid.h"
#include "modules/zb_sniff.h"
#include "modules/evil_portal.h"
#include "modules/sd_log.h"
#include "modules/sys_led.h"

static const char *TAG = "cmd";

#define TX_QUEUE_DEPTH  48
#define TX_LINE_MAX     768     /* CAP lines are the longest: ~530 bytes */
#define RX_LINE_MAX     1024

static QueueHandle_t s_tx_q;   /* queue of malloc'd char* lines */

static void scan_worker(void *arg);
static void ble_worker(void *arg);

static void tx_task(void *arg)
{
    (void)arg;
    char *line;
    while (1) {
        if (xQueueReceive(s_tx_q, &line, portMAX_DELAY) == pdTRUE) {
            size_t n = strlen(line);
            if (n) {
                usb_serial_jtag_write_bytes(line, n, pdMS_TO_TICKS(200));
                usb_serial_jtag_write_bytes("\n", 1, pdMS_TO_TICKS(200));
            }
            free(line);
        }
    }
}

void cmd_emit_raw(const char *line)
{
    if (!s_tx_q || !line || !*line) return;
    char *buf = malloc(TX_LINE_MAX);
    if (!buf) return;
    snprintf(buf, TX_LINE_MAX, "!%s", line);
    if (xQueueSend(s_tx_q, &buf, 0) != pdTRUE) {
        free(buf);
    }
}

void cmd_emit(const char *fmt, ...)
{
    char *buf = malloc(TX_LINE_MAX);
    if (!buf) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, TX_LINE_MAX, fmt, args);
    va_end(args);
    cmd_emit_raw(buf);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* Field helpers                                                      */
/* ------------------------------------------------------------------ */

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) *--e = 0;
    return s;
}

static int parse_bssid(const char *s, uint8_t out[6])
{
    if (!s || !*s) return 0;
    unsigned int b[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* GET handlers                                                       */
/* ------------------------------------------------------------------ */

static void emit_scan_results(void)
{
    size_t n = 0;
    const wifi_ap_t *aps = wifi_scan_get_results(&n);
    cmd_emit("SCAN_DONE %d", (int)n);
    for (size_t i = 0; i < n; i++) {
        cmd_emit("AP %d %s|%02x:%02x:%02x:%02x:%02x:%02x|%d|%u|%s|%u|%d",
                 (int)i, aps[i].ssid,
                 aps[i].bssid[0], aps[i].bssid[1], aps[i].bssid[2],
                 aps[i].bssid[3], aps[i].bssid[4], aps[i].bssid[5],
                 aps[i].rssi, aps[i].channel,
                 aps[i].band == WIFI_SCAN_BAND_2G4 ? "2G" : "5G",
                 (unsigned)aps[i].authmode, aps[i].is_11ax ? 1 : 0);
    }
}

static void emit_sniff_stats(void)
{
    sniff_stats_t st;
    wifi_sniff_get_stats(&st);
    cmd_emit("SNIFF %lu|%lu|%lu|%lu|%u|%d",
             (unsigned long)st.total, (unsigned long)st.beacons,
             (unsigned long)st.unique_bssid, (unsigned long)st.pkt_per_sec,
             st.channel, st.last_rssi);
}

static void emit_handshake_stats(void)
{
    hs_stats_t st;
    wifi_handshake_get_stats(&st);
    cmd_emit("HAND %u|%lu|%lu|%lu|%d",
             st.ap_count, (unsigned long)st.total_eapol,
             (unsigned long)st.handshakes, (unsigned long)st.pmkids,
             st.running ? 1 : 0);

    size_t n = 0;
    const hs_ap_t *aps = wifi_handshake_get_aps(&n);
    for (size_t i = 0; i < n; i++) {
        char pmk[64] = "-";
        if (aps[i].has_pmkid) {
            snprintf(pmk, sizeof(pmk),
                     "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     aps[i].pmkid[0], aps[i].pmkid[1], aps[i].pmkid[2],
                     aps[i].pmkid[3], aps[i].pmkid[4], aps[i].pmkid[5],
                     aps[i].pmkid[6], aps[i].pmkid[7], aps[i].pmkid[8],
                     aps[i].pmkid[9], aps[i].pmkid[10], aps[i].pmkid[11],
                     aps[i].pmkid[12], aps[i].pmkid[13], aps[i].pmkid[14],
                     aps[i].pmkid[15]);
        }
        cmd_emit("HAP %d %s %02x:%02x:%02x:%02x:%02x:%02x %d %d %s",
                 (int)i, aps[i].ssid,
                 aps[i].ap[0], aps[i].ap[1], aps[i].ap[2],
                 aps[i].ap[3], aps[i].ap[4], aps[i].ap[5],
                 aps[i].has_m1 ? 1 : 0, aps[i].has_m2 ? 1 : 0, pmk);
    }
}

static void emit_ble_stats(void)
{
    ble_scan_stats_t st;
    ble_scan_get_stats(&st);
    cmd_emit("BLE %lu|%lu|%d", (unsigned long)st.total,
             (unsigned long)st.unique, st.running ? 1 : 0);
}

static void emit_ble_spam_stats(void)
{
    uint32_t pkts = 0, names = 0;
    char last[33] = { 0 };
    ble_spam_get_stats(&pkts, &names, last, sizeof(last));
    cmd_emit("BLE_SPAM %lu|%lu|%s|%d", (unsigned long)pkts,
             (unsigned long)names, last, ble_spam_is_running() ? 1 : 0);
}

static void emit_hid_stats(void)
{
    uint32_t chars = 0, keys = 0;
    bool connected = false;
    ble_hid_get_stats(&chars, &keys, &connected);
    cmd_emit("HID %d|%d|%lu|%lu", ble_hid_is_running() ? 1 : 0,
             connected ? 1 : 0, (unsigned long)chars, (unsigned long)keys);
}

static void emit_zb_stats(void)
{
    zb_sniff_stats_t st;
    zb_sniff_get_stats(&st);
    cmd_emit("ZB %lu|%lu|%lu|%lu|%lu|%d",
             (unsigned long)st.total, (unsigned long)st.beacons,
             (unsigned long)st.data_frames, (unsigned long)st.acks,
             (unsigned long)st.commands, st.running ? 1 : 0);
}

static void emit_sd_stats(void)
{
    sd_log_stats_t st;
    sd_log_get_stats(&st);
    cmd_emit("SD %d|%llu|%s", st.mounted ? 1 : 0,
             (unsigned long long)(st.free_bytes >> 20),
             st.mounted ? st.card_name : "-");
}

static void emit_portal_stats(void)
{
    uint32_t attempts = 0;
    evil_portal_get_stats(&attempts);
    cmd_emit("PORTAL %d|%lu", evil_portal_is_running() ? 1 : 0,
             (unsigned long)attempts);
}

static void drain_capture(void)
{
    hs_cap_t cap;
    int emitted = 0;
    char hex[HS_CAP_FRAME_MAX * 2 + 16];
    while (wifi_handshake_pop_capture(&cap) && emitted < 12) {
        size_t o = 0;
        hex[o++] = 'C';
        hex[o++] = 'A';
        hex[o++] = 'P';
        hex[o++] = ' ';
        o += snprintf(&hex[o], sizeof(hex) - o, "%u %04x ",
                      cap.len, cap.seq);
        for (uint16_t i = 0; i < cap.len && o + 2 < sizeof(hex) - 1; i++) {
            hex[o++] = "0123456789abcdef"[cap.data[i] >> 4];
            hex[o++] = "0123456789abcdef"[cap.data[i] & 0x0f];
        }
        hex[o] = 0;
        cmd_emit_raw(hex);
        emitted++;
    }
}

static void do_get(char *arg)
{
    if (!arg) { cmd_emit("ERR GET needs an arg"); return; }

    if (strcmp(arg, "SCAN") == 0) {
        emit_scan_results();
    } else if (strcmp(arg, "SNIFF") == 0) {
        emit_sniff_stats();
    } else if (strcmp(arg, "HAND") == 0) {
        emit_handshake_stats();
    } else if (strcmp(arg, "BLE") == 0) {
        emit_ble_stats();
    } else if (strcmp(arg, "BLE_SPAM") == 0) {
        emit_ble_spam_stats();
    } else if (strcmp(arg, "HID") == 0) {
        emit_hid_stats();
    } else if (strcmp(arg, "ZB") == 0) {
        emit_zb_stats();
    } else if (strcmp(arg, "SD") == 0) {
        emit_sd_stats();
    } else if (strcmp(arg, "PORTAL") == 0) {
        emit_portal_stats();
    } else if (strcmp(arg, "CAP") == 0) {
        drain_capture();
    } else {
        cmd_emit("ERR unknown GET %s", arg);
    }
}

/* ------------------------------------------------------------------ */
/* Radio exclusivity helper                                            */
/* ------------------------------------------------------------------ */

static void stop_wifi_rx_tools(void)
{
    if (wifi_handshake_is_running()) wifi_handshake_stop();
    attack_state_t st;
    wifi_attack_get_state(&st);
    if (st.running) wifi_attack_stop();
    if (evil_portal_is_running()) evil_portal_stop();
    wifi_sniff_stop();
}

static void stop_ble_tools(void)
{
    ble_spam_stop();
    if (ble_hid_is_running()) ble_hid_stop();
    ble_scan_stop();
}

/* ------------------------------------------------------------------ */
/* Command handlers                                                    */
/* ------------------------------------------------------------------ */

static void cmd_scan(int argc, char **argv)
{
    stop_wifi_rx_tools();
    bool passive = argc > 1 && strcmp(argv[1], "PASSIVE") == 0;
    if (wifi_scan_start(passive) != ESP_OK) {
        cmd_emit("ERR scan start failed");
        return;
    }
    sys_led_set_mode(LED_MODE_SCAN);
    xTaskCreate(scan_worker, "cmd_scan", 4096, NULL, 5, NULL);
}

static void scan_worker(void *arg)
{
    (void)arg;
    wifi_ap_t tmp[WIFI_SCAN_MAX_APS];
    size_t n = 0;
    esp_err_t e = wifi_scan_wait_results(tmp, WIFI_SCAN_MAX_APS, &n, 15000);
    sys_led_set_mode(LED_MODE_IDLE);
    if (e == ESP_OK) {
        emit_scan_results();
    } else {
        cmd_emit("ERR scan timeout");
    }
    vTaskDelete(NULL);
}

static void cmd_sniff(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR SNIFF ON|OFF"); return; }
    if (strcmp(argv[1], "ON") == 0) {
        stop_wifi_rx_tools();
        if (wifi_sniff_start(0, true) != ESP_OK) {
            cmd_emit("ERR sniff start");
            return;
        }
        sys_led_set_mode(LED_MODE_SNIFF);
        cmd_emit("OK SNIFF ON");
    } else {
        wifi_sniff_stop();
        sys_led_set_mode(LED_MODE_IDLE);
        cmd_emit("OK SNIFF OFF");
    }
}

static void cmd_handshake(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR HANDSHAKE ON [ch]|OFF"); return; }
    if (strcmp(argv[1], "ON") == 0) {
        stop_wifi_rx_tools();
        uint8_t ch = (argc > 2) ? (uint8_t)atoi(argv[2]) : 0;
        if (wifi_handshake_start(ch, ch == 0) != ESP_OK) {
            cmd_emit("ERR handshake start");
            return;
        }
        sys_led_set_mode(LED_MODE_SNIFF);
        cmd_emit("OK HANDSHAKE ON");
    } else {
        wifi_handshake_stop();
        sys_led_set_mode(LED_MODE_IDLE);
        cmd_emit("OK HANDSHAKE OFF");
    }
}

static void cmd_attack(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR ATTACK <type> [arg] [ch]"); return; }

    if (strcmp(argv[1], "STOP") == 0) {
        wifi_attack_stop();
        sys_led_set_mode(LED_MODE_IDLE);
        cmd_emit("OK ATTACK STOP");
        return;
    }

    stop_wifi_rx_tools();

    uint8_t bssid[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    char    ssid[33] = "GHOSTTAP";
    uint8_t ch = 6;

    if (argc > 2) {
        if (!parse_bssid(argv[2], bssid)) {
            int idx = atoi(argv[2]);
            size_t n = 0;
            const wifi_ap_t *aps = wifi_scan_get_results(&n);
            if (idx >= 0 && idx < (int)n) {
                memcpy(bssid, aps[idx].bssid, 6);
                snprintf(ssid, sizeof(ssid), "%s", aps[idx].ssid);
                ch = aps[idx].channel;
            }
        }
        if (argc > 3) ch = (uint8_t)atoi(argv[3]);
    }

    attack_type_t type;
    if (strcmp(argv[1], "DEAUTH") == 0)          type = ATTACK_DEAUTH;
    else if (strcmp(argv[1], "DEAUTHALL") == 0)  type = ATTACK_DEAUTH_ALL;
    else if (strcmp(argv[1], "BEACON") == 0)     type = ATTACK_BEACON;
    else if (strcmp(argv[1], "PROBE") == 0)      type = ATTACK_PROBE;
    else { cmd_emit("ERR unknown attack %s", argv[1]); return; }

    if (wifi_attack_start(type, bssid, NULL, ssid, ch) != ESP_OK) {
        cmd_emit("ERR attack start");
        return;
    }
    sys_led_set_mode(LED_MODE_ATTACK);
    cmd_emit("OK ATTACK %s ch%u", argv[1], ch);
}

static void cmd_portal(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR PORTAL ON <ssid> [pass]|OFF"); return; }
    if (strcmp(argv[1], "ON") == 0) {
        stop_wifi_rx_tools();
        const char *ssid = (argc > 2) ? argv[2] : "FreeWiFi";
        const char *pass = (argc > 3) ? argv[3] : "";
        if (evil_portal_start(ssid, pass) != ESP_OK) {
            cmd_emit("ERR portal start");
            return;
        }
        cmd_emit("OK PORTAL ON %s", ssid);
    } else {
        evil_portal_stop();
        cmd_emit("OK PORTAL OFF");
    }
}

static void cmd_ble(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR BLE SCAN <ms>|SPAM ON|OFF"); return; }
    if (strcmp(argv[1], "SCAN") == 0) {
        stop_ble_tools();
        uint32_t ms = (argc > 2) ? (uint32_t)atoi(argv[2]) : 10000;
        if (ble_scan_start(ms) != ESP_OK) {
            cmd_emit("ERR ble scan start");
            return;
        }
        sys_led_set_mode(LED_MODE_BLE);
        xTaskCreate(ble_worker, "cmd_ble", 2048, NULL, 5, NULL);
    } else if (strcmp(argv[1], "SPAM") == 0) {
        if (argc > 2 && strcmp(argv[2], "ON") == 0) {
            stop_ble_tools();
            if (ble_spam_start() != ESP_OK) {
                cmd_emit("ERR ble spam start");
                return;
            }
            sys_led_set_mode(LED_MODE_BLE);
            cmd_emit("OK BLE SPAM ON");
        } else {
            ble_spam_stop();
            sys_led_set_mode(LED_MODE_IDLE);
            cmd_emit("OK BLE SPAM OFF");
        }
    } else {
        cmd_emit("ERR unknown BLE subcmd");
    }
}

static void ble_worker(void *arg)
{
    (void)arg;
    ble_scan_wait_done(45000);
    sys_led_set_mode(LED_MODE_IDLE);
    cmd_emit("LOG BLE scan complete");
    vTaskDelete(NULL);
}

static void cmd_hid(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR HID ON|OFF|TYPE"); return; }
    if (strcmp(argv[1], "ON") == 0) {
        stop_ble_tools();
        if (ble_hid_start() != ESP_OK) {
            cmd_emit("ERR hid start");
            return;
        }
        sys_led_set_mode(LED_MODE_BLE);
        cmd_emit("OK HID ON");
    } else if (strcmp(argv[1], "OFF") == 0) {
        ble_hid_stop();
        sys_led_set_mode(LED_MODE_IDLE);
        cmd_emit("OK HID OFF");
    } else {
        cmd_emit("ERR unknown HID subcmd");
    }
}

static void cmd_zb(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR ZB ON <ch>|OFF"); return; }
    if (strcmp(argv[1], "ON") == 0) {
        stop_ble_tools();
        uint8_t ch = (argc > 2) ? (uint8_t)atoi(argv[2]) : 15;
        if (zb_sniff_start(ch) != ESP_OK) {
            cmd_emit("ERR zb start");
            return;
        }
        sys_led_set_mode(LED_MODE_ZB);
        cmd_emit("OK ZB ON ch%u", ch);
    } else {
        zb_sniff_stop();
        sys_led_set_mode(LED_MODE_IDLE);
        cmd_emit("OK ZB OFF");
    }
}

static void cmd_led(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR LED <mode>"); return; }
    if (strcmp(argv[1], "OFF") == 0)          sys_led_set_mode(LED_MODE_OFF);
    else if (strcmp(argv[1], "IDLE") == 0)    sys_led_set_mode(LED_MODE_IDLE);
    else if (strcmp(argv[1], "SCAN") == 0)    sys_led_set_mode(LED_MODE_SCAN);
    else if (strcmp(argv[1], "SNIFF") == 0)   sys_led_set_mode(LED_MODE_SNIFF);
    else if (strcmp(argv[1], "ATTACK") == 0)  sys_led_set_mode(LED_MODE_ATTACK);
    else if (strcmp(argv[1], "BLE") == 0)     sys_led_set_mode(LED_MODE_BLE);
    else if (strcmp(argv[1], "ZB") == 0)      sys_led_set_mode(LED_MODE_ZB);
    else { cmd_emit("ERR LED mode"); return; }
    cmd_emit("OK LED %s", argv[1]);
}

static void cmd_log(int argc, char **argv)
{
    if (argc < 2) { cmd_emit("ERR LOG ON|OFF"); return; }
    sd_log_capture_set(strcmp(argv[1], "ON") == 0);
    cmd_emit("OK LOG %s", argv[1]);
}

/* ------------------------------------------------------------------ */
/* Line dispatcher                                                     */
/* ------------------------------------------------------------------ */

/* state for multi-line HID script capture */
static char   s_hid_script[BLE_HID_SCRIPT_MAX];
static size_t s_hid_script_len;
static bool   s_in_hid_script;

static void dispatch(char *line)
{
    char *save = NULL;
    char *argv[16];
    int argc = 0;

    if (s_in_hid_script) {
        if (strcmp(line, "HID END") == 0) {
            s_in_hid_script = false;
            if (s_hid_script_len) {
                ble_hid_run_script(s_hid_script);
                cmd_emit("OK HID SCRIPT %d bytes", (int)s_hid_script_len);
            }
        } else if (s_hid_script_len + strlen(line) + 2 < sizeof(s_hid_script)) {
            s_hid_script_len += snprintf(s_hid_script + s_hid_script_len,
                                         sizeof(s_hid_script) - s_hid_script_len,
                                         "%s\n", line);
        }
        return;
    }

    char *tok = strtok_r(line, " ", &save);
    while (tok && argc < 15) {
        argv[argc++] = tok;
        tok = strtok_r(NULL, " ", &save);
    }
    if (argc == 0) return;

    const char *cmd = argv[0];

    if (strcmp(cmd, "PING") == 0) {
        cmd_emit("PONG v0.3");
    } else if (strcmp(cmd, "GET") == 0) {
        do_get(argc > 1 ? argv[1] : NULL);
    } else if (strcmp(cmd, "SCAN") == 0) {
        cmd_scan(argc, argv);
    } else if (strcmp(cmd, "SNIFF") == 0) {
        cmd_sniff(argc, argv);
    } else if (strcmp(cmd, "HANDSHAKE") == 0) {
        cmd_handshake(argc, argv);
    } else if (strcmp(cmd, "ATTACK") == 0) {
        cmd_attack(argc, argv);
    } else if (strcmp(cmd, "PORTAL") == 0) {
        cmd_portal(argc, argv);
    } else if (strcmp(cmd, "BLE") == 0) {
        cmd_ble(argc, argv);
    } else if (strcmp(cmd, "HID") == 0) {
        if (argc > 1 && strcmp(argv[1], "TYPE") == 0) {
            s_hid_script_len = 0;
            s_in_hid_script = true;
            cmd_emit("OK HID TYPE> (end with HID END)");
        } else {
            cmd_hid(argc, argv);
        }
    } else if (strcmp(cmd, "ZB") == 0) {
        cmd_zb(argc, argv);
    } else if (strcmp(cmd, "LED") == 0) {
        cmd_led(argc, argv);
    } else if (strcmp(cmd, "LOG") == 0) {
        cmd_log(argc, argv);
    } else if (strcmp(cmd, "REBOOT") == 0) {
        cmd_emit("OK REBOOT");
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else {
        cmd_emit("ERR unknown command '%s'", cmd);
    }
}

/* ------------------------------------------------------------------ */
/* RX                                                                 */
/* ------------------------------------------------------------------ */

static void rx_task(void *arg)
{
    (void)arg;
    static char line[RX_LINE_MAX];
    size_t n = 0;

    while (1) {
        char c;
        int got = usb_serial_jtag_read_bytes(&c, 1, pdMS_TO_TICKS(10));
        if (got == 1) {
            if (c == '\n') {
                if (n > 0) {
                    line[n] = 0;
                    dispatch(trim(line));
                    n = 0;
                }
            } else if (c != '\r' && n < sizeof(line) - 1) {
                line[n++] = c;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

esp_err_t cmd_init(void)
{
    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.tx_buffer_size = 1024;
    cfg.rx_buffer_size = 1024;
    esp_err_t ret = usb_serial_jtag_driver_install(&cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "usb_serial_jtag_driver_install failed: %s",
                 esp_err_to_name(ret));
        return ret;
    }

    s_tx_q = xQueueCreate(TX_QUEUE_DEPTH, sizeof(char *));
    if (!s_tx_q) {
        usb_serial_jtag_driver_uninstall();
        return ESP_ERR_NO_MEM;
    }

    xTaskCreatePinnedToCore(tx_task, "cmd_tx", 4096, NULL, 3, NULL, 0);
    xTaskCreatePinnedToCore(rx_task, "cmd_rx", 4096, NULL, 5, NULL, 0);

    ESP_LOGI(TAG, "command bridge online (USB-Serial-JTAG)");
    cmd_emit("READY v0.3");
    return ESP_OK;
}
