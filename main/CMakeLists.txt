# GHOSTTAP Pentest Field Unit — main component

set(SRCS
    "src/app_main.c"
    "src/app_button.c"
    "src/cmd.c"
    "src/ui/ui_theme.c"
    "src/ui/ui_icons.c"
    "src/ui/ui_screens.c"
    "src/modules/wifi_scan.c"
    "src/modules/wifi_sniff.c"
    "src/modules/wifi_attack.c"
    "src/modules/wifi_handshake.c"
    "src/modules/ble_core.c"
    "src/modules/ble_scan.c"
    "src/modules/ble_spam.c"
    "src/modules/ble_hid.c"
    "src/modules/zb_sniff.c"
    "src/modules/sd_log.c"
    "src/modules/sys_led.c"
    "src/modules/evil_portal.c"
)

set(REQ
    waveshare__esp32_c5_lcd_1_47
    esp_wifi
    esp_netif
    esp_event
    nvs_flash
    driver
    esp_driver_usb_serial_jtag
    vfs
    fatfs
    ieee802154
    bt
    esp_http_server
)

idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS "include"
    REQUIRES ${REQ}
    PRIV_REQUIRES log
)
