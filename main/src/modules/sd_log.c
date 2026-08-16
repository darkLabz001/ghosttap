/*
 * GHOSTTAP SD logging — microSD capture via the Waveshare BSP.
 *
 * Mounts the SD card and streams one session log per boot.  A shared
 * mutex serializes writers (sniffer capture, module logs).
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs_fat.h"

#include "bsp/esp-bsp.h"

#include "modules/sd_log.h"

static const char *TAG = "sd_log";

static SemaphoreHandle_t s_mux;
static FILE             *s_file;
static sd_log_stats_t    s_stats;
static volatile bool     s_capture_enabled = true;
static bool              s_inited;

#if defined(BSP_SD_MOUNT_POINT)
#define SD_MOUNT BSP_SD_MOUNT_POINT
#else
#define SD_MOUNT "/sdcard"
#endif

esp_err_t sd_log_init(void)
{
    if (s_inited) return ESP_OK;
    s_mux = xSemaphoreCreateMutex();
    memset(&s_stats, 0, sizeof(s_stats));

    esp_err_t ret = bsp_sdcard_mount();
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SD not present (%s)", esp_err_to_name(ret));
        s_stats.mounted = false;
        s_inited = true;
        return ESP_OK;   /* non-fatal: log to console only */
    }

    s_stats.mounted = true;
    uint64_t total = 0, free = 0;
    if (esp_vfs_fat_info(SD_MOUNT, &total, &free) == ESP_OK) {
        s_stats.capacity_bytes = total;
        s_stats.free_bytes = free;
    }

    char path[64];
    snprintf(path, sizeof(path), "%s/ghosttap_%u.log", SD_MOUNT,
             (unsigned)(esp_timer_get_time() / 1000000ULL));
    s_file = fopen(path, "a");
    if (!s_file) {
        ESP_LOGW(TAG, "cannot open %s", path);
    } else {
        ESP_LOGI(TAG, "logging to %s", path);
    }

    s_inited = true;
    return ESP_OK;
}

esp_err_t sd_log_write(const char *fmt, ...)
{
    if (!s_file || !s_capture_enabled) return ESP_OK;

    xSemaphoreTake(s_mux, portMAX_DELAY);

    va_list args;
    va_start(args, fmt);
    int n = vfprintf(s_file, fmt, args);
    va_end(args);

    if (n > 0) {
        s_stats.log_writes++;
        s_stats.log_bytes += n;
    }
    xSemaphoreGive(s_mux);
    return (n < 0) ? ESP_FAIL : ESP_OK;
}

esp_err_t sd_log_write_hex(const char *tag, const uint8_t *data, size_t len)
{
    if (!s_file || !s_capture_enabled) return ESP_OK;

    xSemaphoreTake(s_mux, portMAX_DELAY);

    int n = fprintf(s_file, "[%llu] %s (%d): ",
                    (unsigned long long)(esp_timer_get_time() / 1000),
                    tag ? tag : "", (int)len);
    for (size_t i = 0; i < len && i < 64; i++) {
        n += fprintf(s_file, "%02x ", data[i]);
    }
    n += fprintf(s_file, "\n");

    s_stats.log_writes++;
    s_stats.log_bytes += n;
    xSemaphoreGive(s_mux);
    return ESP_OK;
}

esp_err_t sd_log_get_stats(sd_log_stats_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    *out = s_stats;
    return ESP_OK;
}

esp_err_t sd_log_flush(void)
{
    if (!s_file) return ESP_OK;
    xSemaphoreTake(s_mux, portMAX_DELAY);
    fflush(s_file);
    xSemaphoreGive(s_mux);
    return ESP_OK;
}

bool sd_log_capture_enabled(void)
{
    return s_capture_enabled;
}

void sd_log_capture_set(bool en)
{
    s_capture_enabled = en;
}
