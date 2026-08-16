/*
 * GHOSTTAP SD logging — microSD card capture/logging.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool     mounted;
    uint64_t capacity_bytes;
    uint64_t free_bytes;
    uint32_t log_writes;
    uint32_t log_bytes;
    char     card_name[16];
} sd_log_stats_t;

esp_err_t sd_log_init(void);          /* mount + open session file */
esp_err_t sd_log_write(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
esp_err_t sd_log_write_hex(const char *tag, const uint8_t *data, size_t len);
esp_err_t sd_log_get_stats(sd_log_stats_t *out);
esp_err_t sd_log_flush(void);

/* capture control from the UI */
bool sd_log_capture_enabled(void);
void sd_log_capture_set(bool en);

#ifdef __cplusplus
}
#endif
