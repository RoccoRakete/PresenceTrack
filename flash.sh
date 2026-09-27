#!/usr/bin/env bash
# Flasht Firmware und/oder Filesystem-Image (data/) auf den PresenceTrack ESP8266.
# Nutzung: ./flash.sh [seriell-port] [geraete-ip]
#   seriell-port: Standard /dev/ttyUSB0
#   geraete-ip:   IP/Hostname des laufenden Geraets im WLAN, z.B. 192.168.1.42
#                 (fuer die Konfigurations-Sicherung noetig, siehe unten)
#
# Ohne USB-Kabel: Web-UI -> Tab "Firmware" (OTA). Dateien dafuer bauen mit
#   pio run              -> .pio/build/d1_mini/firmware.bin
#   pio run -t buildfs   -> .pio/build/d1_mini/littlefs.bin   (Web-UI aus data/)
# Das Web-UI laedt vor jedem Update ein Konfigurations-Backup herunter und stellt
# es nach einem Image-Update automatisch wieder her (wie dieses Skript).
set -euo pipefail

PORT="${1:-/dev/ttyUSB0}"
DEVICE_IP="${2:-}"
BACKUP_DIR="$(dirname "$0")/.config-backups"
BACKUP_FILE=""

if [ ! -e "$PORT" ]; then
    echo "Serieller Port $PORT nicht gefunden. Ist der D1 Mini angeschlossen?" >&2
    exit 1
fi

cd "$(dirname "$0")"

PIO="pio"
command -v pio >/dev/null 2>&1 || PIO="nix shell nixpkgs#platformio -c pio"

echo "Was soll geflasht werden?"
echo "  1) Nur Firmware       (Einstellungen bleiben sicher erhalten, aber Web-UI-Aenderungen fehlen)"
echo "  2) Nur Dateisystem    (data/: Web-UI aktualisieren - loescht sonst die Einstellungen!)"
echo "  3) Beides             (Standard - noetig nach Aenderungen an data/*)"
read -rp "Auswahl [1/2/3, Enter=3]: " CHOICE
CHOICE="${CHOICE:-3}"

DO_FIRMWARE=false
DO_FS=false
case "$CHOICE" in
    1) DO_FIRMWARE=true ;;
    2) DO_FS=true ;;
    3) DO_FIRMWARE=true; DO_FS=true ;;
    *) echo "Ungueltige Auswahl." >&2; exit 1 ;;
esac

# --- Config sichern -----------------------------------------------------
# uploadfs ersetzt die komplette LittleFS-Partition durch ein neues Abbild aus
# data/ und loescht dabei /config.json (Zonen, Objekte, MQTT, Pins, ...), weil
# diese Datei nicht Teil von data/ ist, sondern erst zur Laufzeit geschrieben
# wird. Ein reines Firmware-Upload ruehrt die Partition dagegen nicht an.
if [ "$DO_FS" = true ]; then
    if [ -z "$DEVICE_IP" ]; then
        echo "WARNUNG: Keine Geraete-IP angegeben - kann die Einstellungen nicht sichern." >&2
        echo "         Nutzung: ./flash.sh $PORT <geraete-ip>, sonst gehen Zonen/MQTT/Objekte/Pins verloren." >&2
        read -rp "Trotzdem ohne Sicherung fortfahren? [j/N] " CONFIRM
        [[ "$CONFIRM" =~ ^[jJ] ]] || exit 1
    else
        mkdir -p "$BACKUP_DIR"
        BACKUP_FILE="$BACKUP_DIR/config-$(date +%Y%m%d-%H%M%S).json"
        echo "==> Sichere aktuelle Konfiguration von $DEVICE_IP"
        if curl -sf --max-time 10 "http://$DEVICE_IP/api/config/backup" -o "$BACKUP_FILE"; then
            echo "    Gesichert nach $BACKUP_FILE"
        else
            echo "WARNUNG: Sicherung fehlgeschlagen (Geraet nicht erreichbar?)." >&2
            rm -f "$BACKUP_FILE"
            BACKUP_FILE=""
            read -rp "Trotzdem fortfahren? Einstellungen gehen dann verloren. [j/N] " CONFIRM
            [[ "$CONFIRM" =~ ^[jJ] ]] || exit 1
        fi
    fi
fi

# --- Flashen --------------------------------------------------------------
if [ "$DO_FIRMWARE" = true ]; then
    echo "==> Firmware-Upload ($PORT)"
    $PIO run -t upload --upload-port "$PORT"
fi

if [ "$DO_FS" = true ]; then
    echo "==> Filesystem-Upload ($PORT)"
    $PIO run -t uploadfs --upload-port "$PORT"
fi

echo "==> Flash-Vorgang fertig."

# --- Config wiederherstellen ----------------------------------------------
if [ -n "$BACKUP_FILE" ]; then
    echo "==> Warte auf Neustart und WLAN-Verbindung von $DEVICE_IP..."
    READY=false
    for _ in $(seq 1 30); do
        sleep 2
        if curl -sf --max-time 3 "http://$DEVICE_IP/api/system" >/dev/null 2>&1; then
            READY=true
            break
        fi
    done
    if [ "$READY" = true ]; then
        echo "==> Stelle Konfiguration wieder her"
        if curl -sf --max-time 10 -X POST -H "Content-Type: application/json" \
            --data-binary "@$BACKUP_FILE" "http://$DEVICE_IP/api/config/restore" >/dev/null; then
            echo "    Konfiguration wiederhergestellt."
        else
            echo "WARNUNG: Wiederherstellung fehlgeschlagen. Backup liegt weiter unter $BACKUP_FILE" >&2
        fi
    else
        echo "WARNUNG: Geraet nach 60s nicht erreichbar. Backup liegt unter $BACKUP_FILE," >&2
        echo "         manuell wiederherstellen mit:" >&2
        echo "         curl -X POST -H 'Content-Type: application/json' --data-binary @$BACKUP_FILE http://$DEVICE_IP/api/config/restore" >&2
    fi
fi

echo "==> Fertig."
