/*
 * GHOSTTAP command bridge — USB-Serial-JTAG control protocol.
 *
 * The host TUI (tui/) drives the device over its native USB port using
 * newline-terminated text commands; the device replies with `!`-prefixed
 * event lines.  Every module can push events via cmd_emit() from any
 * task context (queued, non-blocking).
 */
#pragma once

#include <stdarg.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Install the USB-Serial-JTAG driver + start the reader/writer tasks. */
esp_err_t cmd_init(void);

/* Queue an event line (no newline needed). Safe from any task. */
void cmd_emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Queue an already-formatted line (no newline needed). */
void cmd_emit_raw(const char *line);

#ifdef __cplusplus
}
#endif
