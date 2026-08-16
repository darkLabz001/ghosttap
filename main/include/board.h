/*
 * GHOSTTAP Pentest Field Unit — board pin map
 *
 * Source: docs.waveshare.com/ESP32-C5-LCD-1.47 (verified against official
 * Waveshare sample programs).
 */
#pragma once

#include "driver/gpio.h"

/* ---- Onboard LCD (ST7789, SPI, 172x320) ---- */
#define BOARD_LCD_CLK   GPIO_NUM_7
#define BOARD_LCD_DIN   GPIO_NUM_6
#define BOARD_LCD_CS    GPIO_NUM_23
#define BOARD_LCD_DC    GPIO_NUM_24
#define BOARD_LCD_RST   GPIO_NUM_26
#define BOARD_LCD_BL    GPIO_NUM_10

/* ---- Onboard WS2812 RGB LED ---- */
#define BOARD_WS2812    GPIO_NUM_8

/* ---- microSD / TF card (shares SPI bus with LCD: MOSI/CLK) ---- */
#define BOARD_SD_CS     GPIO_NUM_4
#define BOARD_SD_MISO   GPIO_NUM_5
#define BOARD_SD_MOSI   GPIO_NUM_6
#define BOARD_SD_CLK    GPIO_NUM_7

/* ---- UART0 (debug console) ---- */
#define BOARD_UART0_TX  GPIO_NUM_11
#define BOARD_UART0_RX  GPIO_NUM_12

/* ---- USB (native, depends on firmware config) ---- */
#define BOARD_USB_DM    GPIO_NUM_13
#define BOARD_USB_DP    GPIO_NUM_14

/*
 * ---- Buttons -------------------------------------------------------
 * BOOT is on-board.  Its exact GPIO on the Waveshare C5-LCD-1.47 is not
 * published in the wiki yet — the default below follows the ESP32-C5
 * reference design (DevKitM-1).  VERIFY with a multimeter when the board
 * arrives and adjust here if needed.
 *
 * BOARD_BTN_USER is a spare GPIO you can wire to a momentary switch on
 * the 18-pin expansion header (pins are brought out, free to use).
 */
#define BOARD_BTN_BOOT  GPIO_NUM_9
#define BOARD_BTN_USER  (-1)   /* set to a GPIO_NUM_* to enable a 2nd key */

#define BOARD_BTN_ACTIVE_LOW true

/* ---- Display geometry (after bsp_display_rotate(.., LV_DISPLAY_ROTATION_90)) */
#define BOARD_DISPLAY_W 320
#define BOARD_DISPLAY_H 172
