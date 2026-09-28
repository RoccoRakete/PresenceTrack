#!/usr/bin/env bash
# Flashes the firmware and/or filesystem image (data/) onto the PresenceTrack ESP8266.
# Usage: ./flash.sh [serial-port] [device-ip]
#   serial-port: default /dev/ttyUSB0
#   device-ip:   IP/hostname of the running device on the Wi-Fi network, e.g. 192.168.1.42
#                (required for the configuration backup, see below)
#
# Without a USB cable: web UI -> tab "Firmware" (OTA). Build the files for it with
#   pio run              -> .pio/build/d1_mini/firmware.bin
#   pio run -t buildfs   -> .pio/build/d1_mini/littlefs.bin   (web UI from data/)
# The web UI downloads a configuration backup before every update and restores
# it automatically after an image update (like this script does).
set -euo pipefail

PORT="${1:-/dev/ttyUSB0}"
DEVICE_IP="${2:-}"
BACKUP_DIR="$(dirname "$0")/.config-backups"
BACKUP_FILE=""

if [ ! -e "$PORT" ]; then
    echo "Serial port $PORT not found. Is the D1 Mini connected?" >&2
    exit 1
fi

cd "$(dirname "$0")"

PIO="pio"
command -v pio >/dev/null 2>&1 || PIO="nix shell nixpkgs#platformio -c pio"

echo "What should be flashed?"
echo "  1) Firmware only      (settings are safely kept, but web UI changes are missing)"
echo "  2) Filesystem only    (data/: update the web UI - erases the settings otherwise!)"
echo "  3) Both               (default - required after changes to data/*)"
read -rp "Choice [1/2/3, Enter=3]: " CHOICE
CHOICE="${CHOICE:-3}"

DO_FIRMWARE=false
DO_FS=false
case "$CHOICE" in
    1) DO_FIRMWARE=true ;;
    2) DO_FS=true ;;
    3) DO_FIRMWARE=true; DO_FS=true ;;
    *) echo "Invalid choice." >&2; exit 1 ;;
esac

# --- Back up config -----------------------------------------------------
# uploadfs replaces the entire LittleFS partition with a new image built from
# data/ and thereby erases /config.json (zones, objects, MQTT, pins, ...), because
# this file is not part of data/ but is only written at runtime. A plain
# firmware upload, on the other hand, does not touch the partition.
if [ "$DO_FS" = true ]; then
    if [ -z "$DEVICE_IP" ]; then
        echo "WARNING: No device IP given - cannot back up the settings." >&2
        echo "         Usage: ./flash.sh $PORT <device-ip>, otherwise zones/MQTT/objects/pins are lost." >&2
        read -rp "Continue without a backup anyway? [y/N] " CONFIRM
        [[ "$CONFIRM" =~ ^[yY] ]] || exit 1
    else
        mkdir -p "$BACKUP_DIR"
        BACKUP_FILE="$BACKUP_DIR/config-$(date +%Y%m%d-%H%M%S).json"
        echo "==> Backing up current configuration from $DEVICE_IP"
        if curl -sf --max-time 10 "http://$DEVICE_IP/api/config/backup" -o "$BACKUP_FILE"; then
            echo "    Saved to $BACKUP_FILE"
        else
            echo "WARNING: Backup failed (device not reachable?)." >&2
            rm -f "$BACKUP_FILE"
            BACKUP_FILE=""
            read -rp "Continue anyway? The settings will be lost. [y/N] " CONFIRM
            [[ "$CONFIRM" =~ ^[yY] ]] || exit 1
        fi
    fi
fi

# --- Flash ----------------------------------------------------------------
if [ "$DO_FIRMWARE" = true ]; then
    echo "==> Firmware upload ($PORT)"
    $PIO run -t upload --upload-port "$PORT"
fi

if [ "$DO_FS" = true ]; then
    echo "==> Filesystem upload ($PORT)"
    $PIO run -t uploadfs --upload-port "$PORT"
fi

echo "==> Flashing finished."

# --- Restore config -------------------------------------------------------
if [ -n "$BACKUP_FILE" ]; then
    echo "==> Waiting for reboot and Wi-Fi connection of $DEVICE_IP..."
    READY=false
    for _ in $(seq 1 30); do
        sleep 2
        if curl -sf --max-time 3 "http://$DEVICE_IP/api/system" >/dev/null 2>&1; then
            READY=true
            break
        fi
    done
    if [ "$READY" = true ]; then
        echo "==> Restoring configuration"
        if curl -sf --max-time 10 -X POST -H "Content-Type: application/json" \
            --data-binary "@$BACKUP_FILE" "http://$DEVICE_IP/api/config/restore" >/dev/null; then
            echo "    Configuration restored."
        else
            echo "WARNING: Restore failed. The backup is still at $BACKUP_FILE" >&2
        fi
    else
        echo "WARNING: Device not reachable after 60s. The backup is at $BACKUP_FILE," >&2
        echo "         restore it manually with:" >&2
        echo "         curl -X POST -H 'Content-Type: application/json' --data-binary @$BACKUP_FILE http://$DEVICE_IP/api/config/restore" >&2
    fi
fi

echo "==> Done."
