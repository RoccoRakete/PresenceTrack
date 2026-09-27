# PresenceTrack

ESP8266-Firmware fuer einen Anwesenheits- und Helligkeitssensor: LD2410C
(mmWave-Praesenzradar) + BH1750FVI (Helligkeit), angebunden an Home Assistant
per MQTT-Discovery. Konfiguration, Status und Firmware-Updates laufen ueber
eine Web-Oberflaeche, die das Geraet selbst ausliefert.

## Hardware

- ESP8266 D1 Mini (4 MB Flash, Board-Layout `d1_mini`)
- LD2410C (UART, Praesenz-/Bewegungserkennung)
- BH1750FVI (I2C, Helligkeit)

## Verzeichnisstruktur

```
include/        Header der Firmware-Module
src/            Implementierung (Sensorik, WLAN, MQTT/HA, Webserver, OTA)
data/           Web-Oberflaeche (wird als LittleFS-Image mitgeflasht)
platformio.ini  Board- und Build-Konfiguration
flash.sh        Interaktives Flash-Skript (USB, mit Config-Backup/Restore)
.github/        CI-Workflow und Release-Skripte
```

## Lokaler Build

PlatformIO wird per Nix bereitgestellt (`flake.nix`/`.envrc`, direnv aktiviert
die Shell automatisch; ohne direnv manuell mit `nix shell nixpkgs#platformio`):

```
pio run                # Firmware  -> .pio/build/d1_mini/firmware.bin
pio run -t buildfs     # Dateisystem -> .pio/build/d1_mini/littlefs.bin (aus data/)
```

## Flashen

**Per USB:** `./flash.sh [seriell-port] [geraete-ip]` fragt interaktiv ab, ob
Firmware, Dateisystem oder beides geflasht werden soll, sichert bei einem
Dateisystem-Update vorher die laufende Konfiguration ueber die Geraete-API und
stellt sie danach automatisch wieder her.

**Ueber die Web-Oberflaeche (OTA, kein PC noetig):** Tab "Firmware" bietet
zwei Wege:
- Datei-Upload von `firmware.bin`/`littlefs.bin` aus einem lokalen Build.
- "Update von GitHub": das Geraet prueft das neueste Release dieses Repos
  selbst (`manifest.json`) und installiert es direkt per HTTPS.

## Release-Ablauf

1. `FIRMWARE_VERSION` in `include/firmware.h` auf die neue Version setzen und
   committen.
2. Annotierten Tag pushen: `git tag -a v<x.y.z> -m "..."` und `git push origin v<x.y.z>`.
3. Die CI (`.github/workflows/firmware.yml`) baut Firmware und Dateisystem,
   prueft, dass der Tag exakt `v<FIRMWARE_VERSION>` entspricht, und
   veroeffentlicht bei Erfolg ein GitHub-Release mit `firmware.bin`,
   `littlefs.bin`, `manifest.json` und `checksums.txt`. Ein Geraet im Feld holt
   sich darueber automatisch die neue Version (Tab "Firmware" -> "Update von
   GitHub").

Push auf `main` und Pull Requests bauen nur (Artefakt-Upload zur
Nachvollziehbarkeit), ohne ein Release zu erzeugen.
