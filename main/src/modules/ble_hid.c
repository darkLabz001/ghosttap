/*
 * GHOSTTAP BLE HID keyboard — HID-over-GATT keyboard emulation via NimBLE.
 *
 * Registers the standard HID service (0x1812) with a boot-keyboard
 * report characteristic, advertises as a keyboard, and types text /
 * DuckyScript-lite payloads into the connected host.
 *
 * NOTE: this module and the other 2.4 GHz tools (BLE scan/spam,
 * 802.15.4) share one radio — the caller serializes access.
 *
 * This firmware is for authorized security testing only.
 */
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"

#include "modules/ble_core.h"
#include "modules/ble_hid.h"

static const char *TAG = "ble_hid";

#if CONFIG_BT_ENABLED && CONFIG_BT_NIMBLE_ENABLED
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_hs_adv.h"
#include "host/ble_hs_mbuf.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "services/hid/ble_svc_hid.h"

#define KEYBOARD_APPEARANCE 0x03C1
#define KEY_UP_DELAY_MS     12
#define KEY_DOWN_DELAY_MS    8

static volatile bool s_running;
static volatile bool s_connected;
static uint16_t      s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static uint16_t      s_kbd_handle  = 0xffff;
static TaskHandle_t  s_type_task;
static uint32_t      s_chars_typed;
static uint32_t      s_keys_pressed;

static SemaphoreHandle_t s_type_mux;

/* ---- key report ------------------------------------------------ */
typedef struct {
    uint8_t mod;      /* bitmap: 1 ctrl 2 shift 4 alt 8 gui  */
    uint8_t res;
    uint8_t keys[6];
} kbd_report_t;

#define MOD_CTRL  0x01
#define MOD_SHIFT 0x02
#define MOD_ALT   0x04
#define MOD_GUI   0x08

static void report_clear(kbd_report_t *r)
{
    memset(r, 0, sizeof(*r));
}

static int send_report(const kbd_report_t *r)
{
    if (!s_connected || s_conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        return BLE_HS_ENOTCONN;
    }
    struct os_mbuf *om = ble_hs_mbuf_from_flat(r, sizeof(*r));
    if (!om) return BLE_HS_ENOMEM;
    int rc = ble_gatts_notify_custom(s_conn_handle, s_kbd_handle, om);
    s_keys_pressed++;
    return rc;
}

static void tap_key(uint8_t modifier, uint8_t key)
{
    kbd_report_t r;
    report_clear(&r);
    r.mod = modifier;
    r.keys[0] = key;
    send_report(&r);
    vTaskDelay(pdMS_TO_TICKS(KEY_DOWN_DELAY_MS));
    report_clear(&r);
    send_report(&r);
    vTaskDelay(pdMS_TO_TICKS(KEY_UP_DELAY_MS));
}

/* ---- ASCII -> HID ---------------------------------------------- */
static const struct { uint8_t key; uint8_t shift; } s_keymap[95] = {
    {0x2c, 0}, /* ' ' */
    {0x1e, 1}, /* '!' */
    {0x34, 1}, /* '"' */
    {0x20, 1}, /* '#' */
    {0x21, 1}, /* '$' */
    {0x22, 1}, /* '%' */
    {0x24, 1}, /* '&' */
    {0x34, 0}, /* '\'' */
    {0x26, 1}, /* '(' */
    {0x27, 1}, /* ')' */
    {0x25, 1}, /* '*' */
    {0x2e, 1}, /* '+' */
    {0x36, 0}, /* ',' */
    {0x2d, 0}, /* '-' */
    {0x37, 0}, /* '.' */
    {0x38, 0}, /* '/' */
    {0x27, 0}, /* '0' */
    {0x26, 0}, /* '1' */
    {0x25, 0}, /* '2' */
    {0x24, 0}, /* '3' */
    {0x23, 0}, /* '4' */
    {0x22, 0}, /* '5' */
    {0x21, 0}, /* '6' */
    {0x20, 0}, /* '7' */
    {0x1f, 0}, /* '8' */
    {0x1e, 0}, /* '9' */
    {0x33, 1}, /* ':' */
    {0x33, 0}, /* ';' */
    {0x36, 1}, /* '<' */
    {0x2e, 0}, /* '=' */
    {0x37, 1}, /* '>' */
    {0x38, 1}, /* '?' */
    {0x1f, 1}, /* '@' */
    {0x04, 1}, /* 'A' */
    {0x05, 1}, /* 'B' */
    {0x06, 1}, /* 'C' */
    {0x07, 1}, /* 'D' */
    {0x08, 1}, /* 'E' */
    {0x09, 1}, /* 'F' */
    {0x0a, 1}, /* 'G' */
    {0x0b, 1}, /* 'H' */
    {0x0c, 1}, /* 'I' */
    {0x0d, 1}, /* 'J' */
    {0x0e, 1}, /* 'K' */
    {0x0f, 1}, /* 'L' */
    {0x10, 1}, /* 'M' */
    {0x11, 1}, /* 'N' */
    {0x12, 1}, /* 'O' */
    {0x13, 1}, /* 'P' */
    {0x14, 1}, /* 'Q' */
    {0x15, 1}, /* 'R' */
    {0x16, 1}, /* 'S' */
    {0x17, 1}, /* 'T' */
    {0x18, 1}, /* 'U' */
    {0x19, 1}, /* 'V' */
    {0x1a, 1}, /* 'W' */
    {0x1b, 1}, /* 'X' */
    {0x1c, 1}, /* 'Y' */
    {0x1d, 1}, /* 'Z' */
    {0x2f, 0}, /* '[' */
    {0x31, 0}, /* '\' */
    {0x30, 0}, /* ']' */
    {0x23, 1}, /* '^' */
    {0x2d, 1}, /* '_' */
    {0x35, 0}, /* '`' */
    {0x04, 0}, /* 'a' */
    {0x05, 0}, /* 'b' */
    {0x06, 0}, /* 'c' */
    {0x07, 0}, /* 'd' */
    {0x08, 0}, /* 'e' */
    {0x09, 0}, /* 'f' */
    {0x0a, 0}, /* 'g' */
    {0x0b, 0}, /* 'h' */
    {0x0c, 0}, /* 'i' */
    {0x0d, 0}, /* 'j' */
    {0x0e, 0}, /* 'k' */
    {0x0f, 0}, /* 'l' */
    {0x10, 0}, /* 'm' */
    {0x11, 0}, /* 'n' */
    {0x12, 0}, /* 'o' */
    {0x13, 0}, /* 'p' */
    {0x14, 0}, /* 'q' */
    {0x15, 0}, /* 'r' */
    {0x16, 0}, /* 's' */
    {0x17, 0}, /* 't' */
    {0x18, 0}, /* 'u' */
    {0x19, 0}, /* 'v' */
    {0x1a, 0}, /* 'w' */
    {0x1b, 0}, /* 'x' */
    {0x1c, 0}, /* 'y' */
    {0x1d, 0}, /* 'z' */
    {0x2f, 1}, /* '{' */
    {0x31, 1}, /* '|' */
    {0x30, 1}, /* '}' */
    {0x35, 1}, /* '~' */
};

static void type_char(char c)
{
    if (c < 32 || c > 126) return;
    uint8_t key   = s_keymap[c - 32].key;
    uint8_t shift = s_keymap[c - 32].shift;
    tap_key(shift ? MOD_SHIFT : 0, key);
    s_chars_typed++;
}

void ble_hid_type_string_impl(const char *text)
{
    while (text && *text) {
        if (s_connected) type_char(*text);
        else break;
        text++;
    }
}

/* ---- named key lookup ------------------------------------------ */
typedef struct { const char *name; uint8_t mod; uint8_t key; } named_key_t;

static const named_key_t s_named[] = {
    { "ENTER",    0, 0x28 }, { "RETURN",   0, 0x28 },
    { "TAB",      0, 0x2b },
    { "ESC",      0, 0x29 }, { "ESCAPE",   0, 0x29 },
    { "BACKSPACE",0, 0x2a }, { "BACK",     0, 0x2a },
    { "DELETE",   0, 0x4c }, { "DEL",      0, 0x4c },
    { "SPACE",    0, 0x2c },
    { "CAPSLOCK", 0, 0x39 },
    { "HOME",     0, 0x4a }, { "END",      0, 0x4d },
    { "PAGEUP",   0, 0x4b }, { "PAGEDOWN", 0, 0x4e },
    { "UP",       0, 0x52 }, { "DOWN",     0, 0x51 },
    { "LEFT",     0, 0x50 }, { "RIGHT",    0, 0x4f },
    { "INSERT",   0, 0x49 },
    { "F1", 0, 0x3a }, { "F2", 0, 0x3b }, { "F3", 0, 0x3c },
    { "F4", 0, 0x3d }, { "F5", 0, 0x3e }, { "F6", 0, 0x3f },
    { "F7", 0, 0x40 }, { "F8", 0, 0x41 }, { "F9", 0, 0x42 },
    { "F10", 0, 0x43 }, { "F11", 0, 0x44 }, { "F12", 0, 0x45 },
};

static uint8_t named_key(const char *tok, uint8_t *mod)
{
    *mod = 0;
    for (size_t i = 0; i < sizeof(s_named) / sizeof(s_named[0]); i++) {
        if (strcasecmp(tok, s_named[i].name) == 0) {
            *mod = s_named[i].mod;
            return s_named[i].key;
        }
    }
    return 0;
}

/* modifier-aware single-char tap */
static void tap_mod_key(const char *tok, uint8_t mod)
{
    uint8_t k = named_key(tok, &mod);
    if (k) {
        tap_key(mod, k);
        return;
    }
    if (tok[0] && !tok[1]) {
        char c = tok[0];
        if (c >= 'a' && c <= 'z') { tap_key(mod, 0x04 + (c - 'a')); return; }
        if (c >= 'A' && c <= 'Z') { tap_key(mod | MOD_SHIFT, 0x04 + (c - 'A')); return; }
        type_char(c);
    }
}

/* ---- DuckyScript-lite ------------------------------------------ */
static void run_script(const char *script)
{
    char *copy = strdup(script);
    if (!copy) return;

    char *line = strtok(copy, "\n");
    while (line && s_connected) {
        /* trim leading whitespace */
        while (*line == ' ' || *line == '\t') line++;

        if (*line && strncmp(line, "REM", 3) != 0) {
            char cmd[32] = { 0 };
            const char *arg = NULL;
            char *sp = strchr(line, ' ');
            if (sp) {
                size_t n = (size_t)(sp - line);
                if (n > 31) n = 31;
                memcpy(cmd, line, n);
                arg = sp + 1;
                while (*arg == ' ') arg++;
            } else {
                snprintf(cmd, sizeof(cmd), "%s", line);
            }

            uint8_t mod;
            uint8_t k = named_key(cmd, &mod);
            if (strcmp(cmd, "STRING") == 0) {
                ble_hid_type_string_impl(arg ? arg : "");
            } else if (strcmp(cmd, "STRINGLN") == 0) {
                ble_hid_type_string_impl(arg ? arg : "");
                tap_key(0, 0x28);
            } else if (strcmp(cmd, "DELAY") == 0 && arg) {
                vTaskDelay(pdMS_TO_TICKS((uint32_t)atoi(arg)));
            } else if (strcmp(cmd, "DELAY") == 0) {
                vTaskDelay(pdMS_TO_TICKS(1000));
            } else if (strcmp(cmd, "GUI") == 0 || strcmp(cmd, "WIN") == 0) {
                tap_mod_key(arg ? arg : "r", MOD_GUI);
            } else if (strcmp(cmd, "CTRL") == 0 || strcmp(cmd, "CONTROL") == 0) {
                tap_mod_key(arg ? arg : "", MOD_CTRL);
            } else if (strcmp(cmd, "ALT") == 0) {
                tap_mod_key(arg ? arg : "", MOD_ALT);
            } else if (strcmp(cmd, "SHIFT") == 0) {
                tap_mod_key(arg ? arg : "", MOD_SHIFT);
            } else if (strcmp(cmd, "CTRL-ALT") == 0) {
                tap_mod_key(arg ? arg : "", MOD_CTRL | MOD_ALT);
            } else if (k) {
                tap_key(mod, k);              /* plain named key */
            } else {
                /* free-text line: type it + ENTER (ducky behaviour) */
                ble_hid_type_string_impl(line);
                tap_key(0, 0x28);
            }
        }
        line = strtok(NULL, "\n");
    }

    free(copy);
}

static void type_task(void *arg)
{
    const char *script = (const char *)arg;
    xSemaphoreTake(s_type_mux, portMAX_DELAY);
    if (script) {
        run_script(script);
        free((void *)script);
    }
    xSemaphoreGive(s_type_mux);
    vTaskDelete(NULL);
}

/* ---- GAP -------------------------------------------------------- */
static int gap_event(struct ble_gap_event *event, void *arg);

static void restart_advertise(void)
{
    struct ble_gap_adv_params adv = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = 48, .itvl_max = 96,   /* 30-60 ms */
        .channel_map = 0x07,
    };
    ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, 0, &adv, gap_event, NULL);
}

static int gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            s_connected = true;
            ESP_LOGI(TAG, "HID connected");
        } else {
            s_connected = false;
            restart_advertise();
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        s_connected = false;
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        ESP_LOGI(TAG, "HID disconnected");
        if (s_running) restart_advertise();
        return 0;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        if (s_running) restart_advertise();
        return 0;
    case BLE_GAP_EVENT_ENC_CHANGE:
        return 0;
    case BLE_GAP_EVENT_PASSKEY_ACTION:
        ESP_LOGI(TAG, "pairing: passkey action %d", event->passkey.params.action);
        return 0;
    case BLE_GAP_EVENT_SUBSCRIBE:
        return 0;
    default:
        return 0;
    }
}

/* ---- report map (6KRO keyboard) --------------------------------- */
static const uint8_t s_report_map[] = {
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01,
    0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01,
    0x95, 0x08, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
    0x95, 0x05, 0x75, 0x01, 0x05, 0x08,
    0x19, 0x01, 0x29, 0x05, 0x91, 0x02,
    0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00,
    0x25, 0x65, 0x05, 0x07, 0x19, 0x00,
    0x29, 0x65, 0x81, 0x00,
    0xc0,
};

static void setup_hid_service(void)
{
    struct ble_svc_hid_params hp;
    memset(&hp, 0, sizeof(hp));
    hp.proto_mode_present = 1;
    hp.proto_mode = BLE_SVC_HID_PROTO_MODE_REPORT;
    hp.kbd_inp_present = 1;
    hp.kbd_inp_write_perm = 1;
    hp.mouse_inp_present = 0;
    hp.rpts_len = 0;
    hp.report_map_len = sizeof(s_report_map);
    memcpy(hp.report_map, s_report_map, sizeof(s_report_map));
    hp.hid_info = 0x00010111;   /* bcdHID 1.11, country 0, numpad flags */

    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_hid_init();
    ble_svc_hid_add(hp);
    s_kbd_handle = hp.kbd_inp_handle;
}

/* ---- public API ------------------------------------------------- */
esp_err_t ble_hid_start(void)
{
    if (s_running) return ESP_ERR_INVALID_STATE;
    ESP_ERROR_CHECK(ble_core_init());
    if (ble_core_wait_sync(3000) != ESP_OK) {
        ESP_LOGW(TAG, "host not synced");
        return ESP_ERR_TIMEOUT;
    }

    if (!s_type_mux) s_type_mux = xSemaphoreCreateMutex();
    setup_hid_service();

    /* appearance + name in advertise data */
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.appearance = KEYBOARD_APPEARANCE;
    fields.appearance_is_present = 1;
    fields.name = (uint8_t *)"GHOSTTAP KB";
    fields.name_len = strlen("GHOSTTAP KB");
    fields.name_is_complete = 1;
    ble_gap_adv_set_fields(&fields);

    s_running = true;
    restart_advertise();
    ESP_LOGI(TAG, "BLE HID keyboard online");
    return ESP_OK;
}

esp_err_t ble_hid_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;
    if (s_connected && s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
    ble_gap_adv_stop();
    s_connected = false;
    ESP_LOGI(TAG, "BLE HID keyboard offline");
    return ESP_OK;
}

bool ble_hid_is_running(void)    { return s_running; }
bool ble_hid_is_connected(void)  { return s_connected; }

esp_err_t ble_hid_type_string(const char *text)
{
    if (!s_running) return ESP_ERR_INVALID_STATE;
    char *copy = strdup(text);
    if (!copy) return ESP_ERR_NO_MEM;
    xTaskCreate(type_task, "hid_type", 4096, copy, 5, &s_type_task);
    return ESP_OK;
}

esp_err_t ble_hid_run_script(const char *script)
{
    if (!s_running) return ESP_ERR_INVALID_STATE;
    char *copy = strdup(script);
    if (!copy) return ESP_ERR_NO_MEM;
    xTaskCreate(type_task, "hid_script", 4096, copy, 5, &s_type_task);
    return ESP_OK;
}

void ble_hid_get_stats(uint32_t *chars, uint32_t *keys, bool *connected)
{
    if (chars) *chars = s_chars_typed;
    if (keys)  *keys = s_keys_pressed;
    if (connected) *connected = s_connected;
}

#else /* BT disabled -> stubs */

esp_err_t ble_hid_start(void)                    { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t ble_hid_stop(void)                     { return ESP_OK; }
bool ble_hid_is_running(void)                    { return false; }
bool ble_hid_is_connected(void)                  { return false; }
esp_err_t ble_hid_type_string(const char *t)     { return ESP_ERR_NOT_SUPPORTED; }
esp_err_t ble_hid_run_script(const char *s)      { return ESP_ERR_NOT_SUPPORTED; }
void ble_hid_get_stats(uint32_t *c, uint32_t *k, bool *conn)
{
    if (c) *c = 0;
    if (k) *k = 0;
    if (conn) *conn = false;
}

#endif
