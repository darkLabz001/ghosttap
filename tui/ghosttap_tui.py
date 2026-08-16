#!/usr/bin/env python3
"""
GHOSTTAP // PENTEST FIELD UNIT — host control TUI

Drives the ESP32-C5 field unit over its USB-Serial-JTAG port using the
line protocol implemented in main/src/cmd.c.  Hacker-green on black.

Usage:  python3 tui/ghosttap_tui.py [-p /dev/ttyACM0]

For authorized security testing only.
"""

import argparse
import glob
import os
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime
from queue import Queue, Empty

try:
    import serial
except ImportError:
    print("pyserial required:  pip install pyserial")
    sys.exit(1)

import curses
import curses.ascii

APP = "GHOSTTAP // PENTEST FIELD UNIT"
PROTO_VER = "v0.3"

BANNER = r"""
  ____ _   _  ___  ____ _____ _____  _    ____
 / ___| | | |/ _ \/ ___|_   _|_   _|/ \  |  _ \
| |  _| |_| | | | \___ \ | |   | | / _ \ | |_) |
| |_| |  _  | |_| |___) || |   | |/ ___ \|  __/
 \____|_| |_|\___/|____/ |_|   |_/_/   \_\_|
"""

RADIOTAP_DUMMY = struct.pack("<BBHI", 0, 0, 8, 0x80000000)

TOOL_KEYS = [
    "WIFI_SCAN", "SNIFFER", "HANDSHAKE", "ATTACK", "PORTAL",
    "BLE_SCAN", "BLE_SPAM", "BLE_HID", "ZIGBEE", "SYSTEM",
]

TOOL_TITLES = {
    "WIFI_SCAN": "WIFI SCANNER", "SNIFFER": "WIFI SNIFFER",
    "HANDSHAKE": "HANDSHAKE CAPTURE", "ATTACK": "ATTACK SUITE",
    "PORTAL": "EVIL PORTAL", "BLE_SCAN": "BLE SCANNER",
    "BLE_SPAM": "BLE SPAM", "BLE_HID": "BLE HID KEYBOARD",
    "ZIGBEE": "802.15.4 SNIFFER", "SYSTEM": "SYSTEM",
}

AUTH_NAMES = {
    0: "OPEN", 1: "WEP", 2: "WPA", 3: "WPA2", 4: "WPA/WPA2",
    5: "ENT", 6: "WPA3", 7: "WPA2/WPA3", 8: "WAPI", 9: "OWE",
}


class PcapWriter:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        self.count = 0

    def write_frame(self, frame):
        now = time.time()
        pkt = RADIOTAP_DUMMY + frame
        self.f.write(struct.pack("<IIII", int(now), int((now % 1) * 1e6),
                                 len(pkt), len(pkt)))
        self.f.write(pkt)
        self.count += 1
        if self.count % 16 == 0:
            self.f.flush()

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass
        return self.count


class Device:
    def __init__(self, port, baud=115200):
        self.ser = None
        self.port = port
        self.baud = baud
        self.alive = False
        self.rx_q = Queue()
        self.fw_ver = None
        self.reader = None
        self.lock = threading.Lock()

    def open(self):
        # Clear DTR/RTS *before* open: on the ESP32 USB-Serial-JTAG these
        # strapping lines otherwise reset the chip into download mode.
        self.ser = serial.Serial()
        self.ser.port = self.port
        self.ser.baudrate = self.baud
        self.ser.timeout = 0.05
        self.ser.dtr = False
        self.ser.rts = False
        self.ser.open()
        self.alive = True
        self.reader = threading.Thread(target=self._rx_loop, daemon=True)
        self.reader.start()

    def close(self):
        self.alive = False
        if self.reader:
            self.reader.join(timeout=1.0)
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def _rx_loop(self):
        buf = b""
        while self.alive:
            try:
                chunk = self.ser.read(4096)
            except Exception:
                self.rx_q.put(("DISCONNECTED", ""))
                return
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode("utf-8", "replace").strip()
                if line.startswith("!"):
                    self._handle(line[1:])

    def _handle(self, line):
        parts = line.split(" ", 1)
        ev = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        self.rx_q.put((ev, rest))

    def send(self, line):
        if self.ser and self.alive:
            with self.lock:
                try:
                    self.ser.write((line + "\n").encode())
                except Exception:
                    self.rx_q.put(("DISCONNECTED", ""))


class AppState:
    def __init__(self, outdir):
        self.outdir = outdir
        self.log = []
        self.fw_ver = None
        self.aps = []
        self.target = None
        self.sniff = None
        self.hand = None
        self.haps = []
        self.ble = None
        self.ble_spam = None
        self.hid = None
        self.zb = None
        self.sd = None
        self.portal = None
        self.creds = []
        self.pcap = None
        self.pcap_path = None
        self.pcap_count = 0
        self.caps_pending = 0

    def logline(self, msg, hl=False):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.append((ts, msg, hl))
        if len(self.log) > 400:
            del self.log[:200]

    def pcap_open(self):
        if self.pcap:
            return
        os.makedirs(self.outdir, exist_ok=True)
        self.pcap_path = os.path.join(
            self.outdir, "ghosttap-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".pcap")
        self.pcap = PcapWriter(self.pcap_path)
        self.logline("pcap: " + self.pcap_path, True)

    def pcap_write(self, frame):
        self.pcap_open()
        self.pcap.write_frame(frame)
        self.pcap_count += 1

    def pcap_close(self):
        if self.pcap:
            self.pcap_count = self.pcap.close()
            self.pcap = None
            self.logline("pcap closed: %d frames" % self.pcap_count, True)
            self.hcx_convert(self.pcap_path)

    def hcx_convert(self, path):
        if not os.path.exists(path):
            return
        out = path.replace(".pcap", ".22000")
        try:
            r = subprocess.run(["hcxpcapngtool", "-o", out, path],
                               capture_output=True, timeout=60)
            if r.returncode == 0 and os.path.exists(out):
                self.logline("hashes: " + out, True)
            else:
                err = r.stderr.decode()[:200]
                self.logline("hcxpcapngtool: " + (err or "no hashes"))
        except FileNotFoundError:
            self.logline("hcxpcapngtool not installed (apt install hcxtools)")
        except Exception as e:
            self.logline("hcx error: %s" % e)


def apply_event(st, ev, rest):
    if ev == "READY":
        st.fw_ver = rest
        st.logline("device ready " + rest, True)
    elif ev == "PONG":
        st.fw_ver = rest
    elif ev == "OK" or ev == "ERR":
        st.logline(ev.lower() + ": " + rest, ev == "ERR")
    elif ev == "LOG":
        st.logline("dev: " + rest)
    elif ev == "SCAN_DONE":
        st.aps = []
    elif ev == "AP":
        f = rest.split(" ", 1)
        idx = int(f[0])
        fields = f[1].split("|") if len(f) > 1 else []
        while len(st.aps) <= idx:
            st.aps.append(None)
        ssid, bssid, rssi, ch, band, auth, ax = (fields + [""] * 7)[:7]
        st.aps[idx] = {
            "ssid": ssid or "<hidden>", "bssid": bssid,
            "rssi": int(rssi or 0), "ch": ch, "band": band,
            "auth": AUTH_NAMES.get(int(auth), auth) if auth.isdigit() else auth,
            "ax": ax == "1",
        }
    elif ev == "SNIFF":
        st.sniff = rest.split("|")
    elif ev == "HAND":
        st.hand = rest.split("|")
        st.haps = []
    elif ev == "HAP":
        f = rest.split(" ")
        while len(f) < 6:
            f.append("")
        st.haps.append({"idx": f[0], "ssid": f[1] or "<ssid?>", "ap": f[2],
                        "m1": f[3], "m2": f[4], "pmkid": f[5]})
    elif ev == "CAP":
        f = rest.split(" ")
        frame = bytes.fromhex(f[2]) if len(f) > 2 and f[2] else b""
        if frame:
            st.pcap_write(frame)
    elif ev == "BLE":
        st.ble = rest.split("|")
    elif ev == "BLE_SPAM":
        st.ble_spam = rest.split("|")
    elif ev == "HID":
        st.hid = rest.split("|")
    elif ev == "ZB":
        st.zb = rest.split("|")
    elif ev == "SD":
        st.sd = rest.split("|")
    elif ev == "PORTAL":
        st.portal = rest.split("|")
    elif ev == "CREDS":
        f = rest.split(" ")
        st.creds.append((datetime.now().strftime("%H:%M:%S"),
                         f[0] if f else "?", f[1] if len(f) > 1 else "?"))
        st.logline("CREDENTIALS CAPTURED: %s / %s" % (f[0], f[1] if len(f) > 1 else ""), True)
    elif ev == "DISCONNECTED":
        st.logline("serial disconnected", True)


class Tui:
    def __init__(self, stdscr, dev, st):
        self.scr = stdscr
        self.dev = dev
        self.st = st
        self.tool_idx = 0
        self.ap_sel = 0
        self.ap_scroll = 0
        self.hap_scroll = 0
        self.log_scroll = 0
        self.focus = "menu"          # menu | list | log
        self.modal = None            # ("input", prompt, buffer) | ("msg", lines)
        self.zb_ch = 15
        self.portal_ssid = "FreeWiFi"
        self.hid_text = "Hello from GhostTap"
        self.last_poll = 0
        self.running = True
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)      # normal
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_CYAN, -1)       # headers
        curses.init_pair(4, curses.COLOR_RED, -1)        # attacks/alerts
        curses.init_pair(5, curses.COLOR_YELLOW, -1)     # values
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_GREEN)  # selected
        curses.init_pair(7, curses.COLOR_WHITE, -1)      # dim
        self.scr.timeout(50)

    # ---------------- helpers ----------------
    def send(self, cmd):
        self.dev.send(cmd)

    def w(self, y, x, text, pair=1, bold=False, rev=False):
        try:
            attr = curses.color_pair(pair) | (curses.A_BOLD if bold else 0) \
                   | (curses.A_REVERSE if rev else 0)
            self.scr.addstr(y, x, text, attr)
        except curses.error:
            pass

    def box(self, y, x, h, w, title=None):
        try:
            self.scr.attron(curses.color_pair(1))
            self.scr.vline(y, x, curses.ACS_VLINE, h - 1)
            self.scr.vline(y, x + w - 1, curses.ACS_VLINE, h - 1)
            self.scr.hline(y, x, curses.ACS_HLINE, w)
            self.scr.hline(y + h - 1, x, curses.ACS_HLINE, w)
            self.scr.addch(y, x, curses.ACS_ULCORNER)
            self.scr.addch(y, x + w - 1, curses.ACS_URCORNER)
            self.scr.addch(y + h - 1, x, curses.ACS_LLCORNER)
            self.scr.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER)
            self.scr.attroff(curses.color_pair(1))
        except curses.error:
            pass
        if title:
            self.w(y, x + 2, " " + title + " ", 3, bold=True)

    # ---------------- drawing ----------------
    def draw(self):
        self.scr.erase()
        H, W = self.scr.getmaxyx()

        self.w(0, 1, APP, 3, bold=True)
        ver = self.st.fw_ver or "offline"
        port = self.dev.port or "-"
        self.w(0, W - len(ver) - 12, "fw:%s" % ver, 5)
        self.w(0, max(0, W - len(ver) - 12 - len(port) - 10), port, 7)

        menu_w = 22
        log_h = min(9, max(4, H // 4))
        body_h = H - 1 - log_h - 2
        self.box(1, 0, body_h + 2, menu_w, "TOOLS")
        self.box(1, menu_w + 1, body_h + 2, W - menu_w - 2,
                 TOOL_TITLES[TOOL_KEYS[self.tool_idx]])
        self.box(1 + body_h + 2, 0, log_h, W, "LOG")

        for i, key in enumerate(TOOL_KEYS):
            y = 2 + i
            mark = ">" if i == self.tool_idx else " "
            running = self._tool_running(key)
            tag = "*" if running else " "
            pair = 6 if i == self.tool_idx else (4 if running else 1)
            self.w(y, 1, "%s%s %-16s" % (mark, tag, TOOL_TITLES[key]), pair,
                   bold=(i == self.tool_idx))

        self._draw_hints(2 + len(TOOL_KEYS) + 1, 1, menu_w - 2)
        self._draw_log(2 + body_h + 2, 1, log_h - 2, W - 2)
        self._draw_context(2, menu_w + 2, body_h - 1, W - menu_w - 4)
        self._draw_status(H - 1, W)

        if self.modal:
            self._draw_modal(H, W)
        self.scr.refresh()

    def _tool_running(self, key):
        st = self.st
        try:
            if key == "SNIFFER" and st.sniff:
                return True
            if key == "HANDSHAKE" and st.hand and st.hand[4] == "1":
                return True
            if key == "BLE_SPAM" and st.ble_spam and st.ble_spam[3] == "1":
                return True
            if key == "BLE_HID" and st.hid and st.hid[0] == "1":
                return True
            if key == "ZIGBEE" and st.zb and st.zb[5] == "1":
                return True
            if key == "PORTAL" and st.portal and st.portal[0] == "1":
                return True
        except Exception:
            pass
        return False

    def _draw_hints(self, y, x, w):
        hints = [
            ("ENTER", "action"), ("s", "scan"), ("1-4", "attack"),
            ("x", "stop"), ("t/e", "input"), ("c", "connect"),
            ("p", "pcap"), ("q", "quit"),
        ]
        self.w(y, x, "- keys " + "-" * (w - 7), 7)
        yy = y + 1
        for k, v in hints:
            if yy > y + 6:
                break
            self.w(yy, x, "%-6s %s" % (k, v), 7)
            yy += 1

    def _draw_log(self, y, x, h, w):
        lines = self.st.log[-h:]
        for i, (ts, msg, hl) in enumerate(lines):
            pair = 5 if hl else 1
            self.w(y + i, x, "%s %s" % (ts, msg[:w - 10]), pair, bold=hl)

    def _draw_status(self, y, W):
        st = self.st
        seg = []
        if st.hand and len(st.hand) > 4:
            seg.append("HS:%s AP:%s EAPOL:%s" % (st.hand[2], st.hand[0], st.hand[1]))
        if st.pcap:
            seg.append("PCAP:%d" % st.pcap_count)
        if st.sniff:
            seg.append("PKT:%s" % st.sniff[0])
        if st.ble_spam:
            seg.append("SPAM:%s" % st.ble_spam[0])
        if st.sd:
            seg.append("SD:%sMB" % st.sd[1])
        txt = " [" + "] [".join(seg) + "]"
        self.w(y, 1, txt[:W - 2], 3, bold=True)

    def _row(self, y, x, w, cols, widths, pair=1, bold=False):
        out = []
        for c, wd in zip(cols, widths):
            out.append(str(c)[:wd].ljust(wd))
        self.w(y, x, " ".join(out), pair, bold=bold)

    def _draw_context(self, y0, x0, h, w):
        key = TOOL_KEYS[self.tool_idx]
        st = self.st
        y = y0

        if key == "WIFI_SCAN":
            if not st.aps:
                self.w(y, x0, "no scan yet — press [s] to scan", 7)
                return
            widths = [4, 22, 17, 5, 3, 3, 8, 2]
            hdr = ["#", "SSID", "BSSID", "RSSI", "CH", "BD", "AUTH", "AX"]
            self._row(y, x0, w, hdr, widths, 3, True)
            y += 1
            self.ap_scroll = max(0, min(self.ap_scroll, len(st.aps) - h + 1))
            for i in range(self.ap_scroll, len(st.aps)):
                if y >= y0 + h:
                    break
                ap = st.aps[i]
                if not ap:
                    continue
                sel = (i == self.ap_sel)
                pair = 6 if sel else 1
                tgt = ">>" if st.target == i else "  "
                self._row(y, x0, w,
                          [tgt + str(i), ap["ssid"], ap["bssid"], ap["rssi"],
                           ap["ch"], ap["band"], ap["auth"], "ax" if ap["ax"] else ""],
                          widths, pair, bold=sel)
                y += 1
            if st.target is not None and st.target < len(st.aps) and st.aps[st.target]:
                t = st.aps[st.target]
                self.w(y0 + h - 1, x0,
                       "TARGET: %s (%s ch%s)" % (t["ssid"], t["bssid"], t["ch"]), 4, bold=True)

        elif key == "SNIFFER":
            s = st.sniff or ["0"] * 6
            rows = [("total frames", s[0]), ("beacons", s[1]),
                    ("unique BSSIDs", s[2]), ("pkt/sec", s[3]),
                    ("channel", s[4]), ("last rssi", s[5])]
            for name, val in rows:
                self.w(y, x0, "%-16s" % name, 1)
                self.w(y, x0 + 18, str(val), 5, bold=True)
                y += 1
            self.w(y + 1, x0, "ENTER: toggle sniffer  (channel hops 1-11)", 7)

        elif key == "HANDSHAKE":
            hd = st.hand or ["0", "0", "0", "0", "0"]
            self.w(y, x0, "APs:%s  EAPOL:%s  HANDSHAKES:" % (hd[0], hd[1]), 1)
            self.w(y, x0 + 26, hd[2], 4 if hd[2] != "0" else 5, bold=True)
            self.w(y, x0 + 34, " PMKID:%s" % hd[3], 4 if hd[3] != "0" else 5, bold=True)
            y += 1
            self.w(y, x0, "capture: %s  pcap:%s frames" %
                   ("RUNNING" if hd[4] == "1" else "stopped", st.pcap_count), 3)
            y += 2
            widths = [4, 20, 17, 3, 3, 34]
            self._row(y, x0, w, ["#", "SSID", "AP", "M1", "M2", "PMKID"], widths, 3, True)
            y += 1
            for i in range(self.hap_scroll, len(st.haps)):
                if y >= y0 + h:
                    break
                a = st.haps[i]
                hs = (a["m1"] == "1" and a["m2"] == "1")
                self._row(y, x0, w, [a["idx"], a["ssid"], a["ap"],
                                     a["m1"], a["m2"], a["pmkid"]],
                          widths, 4 if hs else 1, bold=hs)
                y += 1
            self.w(y0 + h - 1, x0,
                   "ENTER: toggle   p: %s   (converts to 22000 on stop)" %
                   ("close pcap" if st.pcap else "open pcap"), 7)

        elif key == "ATTACK":
            t = None
            if st.target is not None and st.target < len(st.aps) and st.aps[st.target]:
                t = st.aps[st.target]
            self.w(y, x0, "target:", 1)
            if t:
                self.w(y, x0 + 8, "%s  %s  ch%s" % (t["ssid"], t["bssid"], t["ch"]), 5, True)
            else:
                self.w(y, x0 + 8, "none — pick one in WIFI SCAN", 4)
            y += 2
            atk = [("1", "deauth target", "ATTACK DEAUTH"),
                   ("2", "deauth broadcast", "ATTACK DEAUTHALL"),
                   ("3", "beacon flood", "ATTACK BEACON GHOSTTAP-NET"),
                   ("4", "probe flood", "ATTACK PROBE GHOSTTAP-NET")]
            for k, name, _ in atk:
                self.w(y, x0, "[%s] %s" % (k, name), 1)
                y += 1
            y += 1
            self.w(y, x0, "x: stop all attacks", 4)
            y += 2
            self.w(y, x0, "frames use the patched libnet80211 TX path", 7)
            self.w(y + 1, x0, "authorized targets only!", 4, True)

        elif key == "PORTAL":
            p = st.portal or ["0", "0"]
            self.w(y, x0, "portal: ", 1)
            self.w(y, x0 + 8, "RUNNING" if p[0] == "1" else "stopped",
                   4 if p[0] == "1" else 5, True)
            self.w(y, x0 + 20, " attempts: %s" % p[1], 5)
            y += 1
            self.w(y, x0, "ssid: %s" % self.portal_ssid, 1)
            y += 2
            self.w(y, x0, "e: start (edit ssid)   x: stop", 7)
            y += 2
            self.w(y, x0, "CAPTURED CREDENTIALS", 3, True)
            y += 1
            for ts, u, pw in st.creds[-(h - y + y0):]:
                self.w(y, x0, "%s  %-20s %s" % (ts, u, pw), 5, True)
                y += 1

        elif key == "BLE_SCAN":
            b = st.ble or ["0", "0", "0"]
            self.w(y, x0, "frames:%s devices:%s  %s" %
                   (b[0], b[1], "scanning" if b[2] == "1" else "idle"), 3)
            y += 2
            self.w(y, x0, "s: scan for 10 s", 7)

        elif key == "BLE_SPAM":
            b = st.ble_spam or ["0", "0", "-", "0"]
            rows = [("status", "RUNNING" if b[3] == "1" else "stopped"),
                    ("packets", b[0]), ("names", b[1]), ("last name", b[2])]
            for name, val in rows:
                self.w(y, x0, "%-12s" % name, 1)
                self.w(y, x0 + 14, str(val), 5, bold=True)
                y += 1
            self.w(y + 1, x0, "ENTER: toggle advertisement flood", 7)

        elif key == "BLE_HID":
            b = st.hid or ["0", "0", "0", "0"]
            conn = b[1] == "1"
            self.w(y, x0, "advertising: ", 1)
            self.w(y, x0 + 13, b[0] == "1" and "yes" or "no", 5, True)
            y += 1
            self.w(y, x0, "connected:   ", 1)
            self.w(y, x0 + 13, "YES" if conn else "no",
                   4 if conn else 5, True)
            y += 1
            self.w(y, x0, "chars typed: %s   keys: %s" % (b[2], b[3]), 1)
            y += 2
            self.w(y, x0, "ENTER: start/stop advertising", 7)
            self.w(y + 1, x0, "t: type text (DuckyScript-lite ok)", 7)
            self.w(y + 2, x0, "payload: %s" % self.hid_text[:w - 10], 7)
            if not conn:
                self.w(y + 4, x0, "pair from the target host, then send payload", 4)

        elif key == "ZIGBEE":
            z = st.zb or ["0"] * 6
            rows = [("status", "RUNNING" if z[5] == "1" else "stopped"),
                    ("frames", z[0]), ("beacons", z[1]), ("data", z[2]),
                    ("acks", z[3]), ("commands", z[4])]
            for name, val in rows:
                self.w(y, x0, "%-10s" % name, 1)
                self.w(y, x0 + 12, str(val), 5, bold=True)
                y += 1
            y += 1
            self.w(y, x0, "ENTER: start/stop on ch %d   +/-: channel" % self.zb_ch, 7)

        elif key == "SYSTEM":
            sd = st.sd or ["0", "?", "-"]
            rows = [
                ("firmware", self.st.fw_ver or "?"),
                ("sd card", "mounted %s MB free (%s)" % (sd[1], sd[2]) if sd[0] == "1" else "not mounted"),
                ("pcap file", self.st.pcap_path or "-"),
                ("pcap frames", str(self.st.pcap_count)),
                ("portal creds", str(len(self.st.creds))),
            ]
            for name, val in rows:
                self.w(y, x0, "%-14s" % name, 1)
                self.w(y, x0 + 16, str(val)[:w - 18], 5)
                y += 1
            y += 1
            self.w(y, x0, "l: toggle SD capture   R: reboot device", 7)

    def _draw_modal(self, H, W):
        if self.modal[0] == "input":
            _, prompt, buf = self.modal
            mw = max(40, len(prompt) + len(buf) + 8)
            mx, my = (W - mw) // 2, H // 2 - 2
            self.box(my, mx, 5, mw)
            self.w(my + 1, mx + 2, prompt[:mw - 4], 3, True)
            self.w(my + 2, mx + 2, (buf + "_")[:mw - 4], 5, True)
            self.w(my + 3, mx + 2, "ENTER ok  ESC cancel", 7)
        elif self.modal[0] == "msg":
            _, lines = self.modal
            mw = max(max(len(l) for l in lines) + 6, 30)
            mh = len(lines) + 4
            mx, my = (W - mw) // 2, H // 2 - mh // 2
            self.box(my, mx, mh, mw)
            for i, l in enumerate(lines):
                self.w(my + 1 + i, mx + 2, l[:mw - 4], 5 if i else 3, bold=(i == 0))

    # ---------------- polling ----------------
    def poll(self):
        now = time.time()
        if now - self.last_poll < 0.5:
            return
        self.last_poll = now
        key = TOOL_KEYS[self.tool_idx]
        st = self.st
        if key == "SNIFFER":
            self.send("GET SNIFF")
        elif key == "HANDSHAKE":
            self.send("GET HAND")
            self.send("GET CAP")
        elif key == "BLE_SCAN":
            self.send("GET BLE")
        elif key == "BLE_SPAM":
            self.send("GET BLE_SPAM")
        elif key == "BLE_HID":
            self.send("GET HID")
        elif key == "ZIGBEE":
            self.send("GET ZB")
        elif key == "PORTAL":
            self.send("GET PORTAL")
        elif key == "SYSTEM":
            self.send("GET SD")

    def drain(self):
        while True:
            try:
                ev, rest = self.dev.rx_q.get_nowait()
            except Empty:
                return
            apply_event(self.st, ev, rest)
            if ev == "DISCONNECTED":
                self.running = False

    # ---------------- input ----------------
    def input_char(self):
        c = self.scr.getch()
        if c == -1:
            return None
        if c == curses.KEY_UP:
            return "UP"
        if c == curses.KEY_DOWN:
            return "DOWN"
        if c == curses.KEY_PPAGE:
            return "PGUP"
        if c == curses.KEY_NPAGE:
            return "PGDN"
        if c == curses.KEY_ENTER or c == 10 or c == 13:
            return "ENTER"
        if c == 9:
            return "TAB"
        if c == 27:
            return "ESC"
        if c == curses.KEY_BACKSPACE or c == 8 or c == 127:
            return "BS"
        if 32 <= c < 127:
            return chr(c)
        return None

    def handle_input(self, ch):
        if self.modal:
            self._handle_modal(ch)
            return
        if ch is None:
            return
        key = TOOL_KEYS[self.tool_idx]

        if ch == "q":
            self.running = False
            return
        if ch == "TAB":
            return
        if ch == "UP":
            if self.focus == "menu":
                self.tool_idx = (self.tool_idx - 1) % len(TOOL_KEYS)
            elif key == "WIFI_SCAN" and self.st.aps:
                self.ap_sel = max(0, self.ap_sel - 1)
                self.ap_scroll = max(0, min(self.ap_scroll, self.ap_sel))
            return
        if ch == "DOWN":
            if self.focus == "menu":
                self.tool_idx = (self.tool_idx + 1) % len(TOOL_KEYS)
            elif key == "WIFI_SCAN" and self.st.aps:
                self.ap_sel = min(len(self.st.aps) - 1, self.ap_sel + 1)
                if self.ap_sel >= self.ap_scroll + 10:
                    self.ap_scroll = self.ap_sel - 9
            return

        if ch == "s":
            if key == "WIFI_SCAN":
                self.st.logline("scanning...")
                self.send("SCAN")
            elif key == "BLE_SCAN":
                self.st.logline("ble scan 10s...")
                self.send("BLE SCAN 10000")
            return
        if ch == "x":
            self._stop_all(key)
            return
        if ch == "c":
            self.st.logline("ping...")
            self.send("PING")
            return
        if ch == "p":
            if self.st.pcap:
                self.st.pcap_close()
            else:
                self.st.pcap_open()
            return

        if ch == "ENTER":
            self._enter(key)
            return

        if key == "WIFI_SCAN" and ch == " ":
            self.st.target = self.ap_sel
            return
        if key == "ATTACK" and ch in "1234":
            self._attack(ch)
            return
        if key == "PORTAL" and ch == "e":
            self.modal = ("input", "portal ssid:", self.portal_ssid)
            return
        if key == "BLE_HID" and ch == "t":
            self.modal = ("input", "type text / ducky lines:", self.hid_text)
            return
        if key == "ZIGBEE":
            if ch == "+" or ch == "=":
                self.zb_ch = min(26, self.zb_ch + 1)
            elif ch == "-":
                self.zb_ch = max(11, self.zb_ch - 1)
            return
        if key == "SYSTEM":
            if ch == "l":
                self.send("LOG ON" if not getattr(self, "_log_on", False) else "LOG OFF")
                self._log_on = not getattr(self, "_log_on", False)
            elif ch == "R":
                self.modal = ("msg", ["REBOOT DEVICE", "press ENTER to confirm, ESC to abort"])

    def _handle_modal(self, ch):
        kind = self.modal[0]
        if kind == "input":
            _, prompt, buf = self.modal
            if ch == "ESC":
                self.modal = None
            elif ch == "ENTER":
                self.modal = None
                if not buf:
                    return
                if prompt.startswith("portal"):
                    self.portal_ssid = buf
                    self.send("PORTAL ON %s" % buf)
                else:
                    self.hid_text = buf
                    self.send("HID TYPE")
                    for ln in buf.split("\\n"):
                        self.send(ln)
                    self.send("HID END")
            elif ch == "BS":
                buf = buf[:-1]
                self.modal = ("input", prompt, buf)
            elif ch and len(ch) == 1:
                self.modal = ("input", prompt, buf + ch)
        elif kind == "msg":
            if ch == "ENTER":
                self.modal = None
                self.send("REBOOT")
                self.st.logline("reboot requested")
            elif ch == "ESC":
                self.modal = None

    def _enter(self, key):
        if key == "WIFI_SCAN":
            self.st.target = self.ap_sel
        elif key == "SNIFFER":
            if self.st.sniff:
                self.send("SNIFF OFF")
            else:
                self.send("SNIFF ON")
        elif key == "HANDSHAKE":
            if self.st.hand and self.st.hand[4] == "1":
                self.send("HANDSHAKE OFF")
                if self.st.pcap:
                    self.st.pcap_close()
            else:
                self.send("HANDSHAKE ON")
        elif key == "BLE_SPAM":
            if self.st.ble_spam and self.st.ble_spam[3] == "1":
                self.send("BLE SPAM OFF")
            else:
                self.send("BLE SPAM ON")
        elif key == "BLE_HID":
            if self.st.hid and self.st.hid[0] == "1":
                self.send("HID OFF")
            else:
                self.send("HID ON")
        elif key == "ZIGBEE":
            if self.st.zb and self.st.zb[5] == "1":
                self.send("ZB OFF")
            else:
                self.send("ZB ON %d" % self.zb_ch)

    def _stop_all(self, key):
        self.send("ATTACK STOP")
        self.send("SNIFF OFF")
        if self.st.hand and self.st.hand[4] == "1":
            self.send("HANDSHAKE OFF")
        if self.st.ble_spam and self.st.ble_spam[3] == "1":
            self.send("BLE SPAM OFF")
        if key == "PORTAL":
            self.send("PORTAL OFF")
        if key == "BLE_HID":
            self.send("HID OFF")
        self.st.logline("stop sent", True)

    def _attack(self, ch):
        t = self.st.target
        tgt = str(t) if t is not None else "0"
        cmds = {"1": "ATTACK DEAUTH %s" % tgt,
                "2": "ATTACK DEAUTHALL %s" % tgt,
                "3": "ATTACK BEACON GHOSTTAP-NET",
                "4": "ATTACK PROBE GHOSTTAP-NET"}
        self.st.logline("attack: " + cmds[ch], True)
        self.send(cmds[ch])

    # ---------------- main loop ----------------
    def run(self):
        while self.running:
            self.drain()
            self.poll()
            self.draw()
            ch = self.input_char()
            self.handle_input(ch)


def autodetect_port():
    # Prefer the GhostTap board itself: match its stable by-id symlink so we
    # don't grab some other unrelated /dev/ttyACM* device plugged in at the
    # same time (e.g. another board enumerating as ttyACM0 first).
    for dev in sorted(glob.glob("/dev/serial/by-id/*")):
        if "Espressif" in dev:
            return os.path.realpath(dev)
    for pat in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        ports = sorted(glob.glob(pat))
        if ports:
            return ports[0]
    return None


def main(stdscr, port, outdir):
    if not port:
        port = autodetect_port()
    elif not port.startswith("/") and os.path.exists("/dev/" + port):
        # Forgive a bare device name like "ttyACM1" (missing /dev/) —
        # pyserial treats it as a relative path and fails silently, which
        # looks exactly like "the device isn't detected".
        port = "/dev/" + port
    st = AppState(outdir)
    st.logline("GhostTap host TUI " + PROTO_VER)
    if port:
        dev = Device(port)
        try:
            dev.open()
            st.logline("connected " + port, True)
            dev.send("PING")
        except Exception as e:
            st.logline("open %s failed: %s" % (port, e), True)
            dev = Device(None)
    else:
        st.logline("no /dev/ttyACM* found — offline mode (c to retry)", True)
        dev = Device(None)

    tui = Tui(stdscr, dev, st)
    try:
        tui.run()
    finally:
        st.pcap_close()


def cli():
    ap = argparse.ArgumentParser(description="GhostTap pentest field unit TUI")
    ap.add_argument("-p", "--port", default=None)
    ap.add_argument("-o", "--outdir", default="captures")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    try:
        curses.wrapper(main, args.port, args.outdir)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cli()
