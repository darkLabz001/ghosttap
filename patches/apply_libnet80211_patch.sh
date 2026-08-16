#!/usr/bin/env bash
# ============================================================
# ESPC5 — apply the patched libnet80211.a for the ESP32-C5
# ============================================================
#
# WHY:
#   The stock ESP-IDF libnet80211.a (>= v5.3) rejects management frames
#   whose source address does not belong to the interface.  That blocks
#   spoofed-SA injection (deauth, beacon/probe floods) over BOTH bands.
#   The community patch below relaxes that check on the C5.
#
# WHAT IT DOES:
#   1. Locates your IDF installation (IDF_PATH or idf.py).
#   2. Backs up the original library to libnet80211.a.orig.
#   3. Downloads a patched binary built against IDF v5.5.1.
#   4. Verifies the SHA-256 before installing.
#
# USAGE:
#   . $IDF_PATH/export.sh
#   ./patches/apply_libnet80211_patch.sh
#
# WARNINGS:
#   * Only installs on ESP-IDF 5.5.x (the prebuilt patch target).
#   * This modifies your IDF installation.  Re-run the script's reverse
#     mode (`--restore`) or reinstall IDF to go back to stock.
#   * Use only on equipment you are authorized to test.
# ============================================================

set -euo pipefail

# --- resolve IDF path -----------------------------------------------
IDF_PATH="${IDF_PATH:-}"
if [[ -z "$IDF_PATH" ]]; then
    if command -v idf.py >/dev/null 2>&1; then
        IDF_PATH="$(python3 -c 'import idf_py_commands; print(idf_py_commands.IDF_PY_PATH)' 2>/dev/null | xargs dirname 2>/dev/null || true)"
    fi
fi
if [[ -z "$IDF_PATH" || ! -f "$IDF_PATH/tools/cmake/version.cmake" ]]; then
    echo "ERROR: could not locate ESP-IDF. Source it first:" >&2
    echo "  . \$IDF_PATH/export.sh" >&2
    exit 1
fi
echo "IDF at: $IDF_PATH"

# --- version gate ----------------------------------------------------
idf_ver="$(grep -oE 'IDF_VER VERSION [0-9]+\.[0-9]+' "$IDF_PATH/tools/cmake/version.cmake" | grep -oE '[0-9]+\.[0-9]+' || echo 'unknown')"
if [[ "$idf_ver" != 5.5* ]]; then
    echo "ERROR: patch is prebuilt for IDF 5.5.x, you have $idf_ver" >&2
    echo "       (tested on 5.5.1; build from source for other versions)" >&2
    exit 1
fi

DEST="$IDF_PATH/components/esp_wifi/lib/esp32c5/libnet80211.a"
if [[ ! -f "$DEST" ]]; then
    echo "ERROR: stock library not found at $DEST" >&2
    exit 1
fi

URL="https://raw.githubusercontent.com/maxbrito500/esp32-c5-deauth/main/esp32-c5/patched_libnet/libnet80211.a"
SHA_EXPECTED="$(curl -fsSL "$URL.sha256" 2>/dev/null || true)"

# --- restore mode ----------------------------------------------------
if [[ "${1:-}" == "--restore" ]]; then
    if [[ -f "$DEST.orig" ]]; then
        cp "$DEST.orig" "$DEST"
        echo "Restored original libnet80211.a"
    else
        echo "No backup found ($DEST.orig) — nothing to do"
    fi
    exit 0
fi

echo "Downloading patched libnet80211.a ..."
curl -fL "$URL" -o "$DEST.new"

if [[ -n "$SHA_EXPECTED" ]]; then
    actual="$(sha256sum "$DEST.new" | awk '{print $1}')"
    if [[ "$actual" != "$SHA_EXPECTED" ]]; then
        echo "ERROR: SHA mismatch" >&2
        echo "  expected: $SHA_EXPECTED" >&2
        echo "  actual:   $actual" >&2
        rm -f "$DEST.new"
        exit 1
    fi
    echo "SHA256 OK"
fi

cp "$DEST" "$DEST.orig"
mv "$DEST.new" "$DEST"
echo "Patched. Backup kept at $DEST.orig"
echo "Rebuild with:  idf.py build flash"
