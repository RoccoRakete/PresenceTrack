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
.github/        CI workflow (build and release)
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

**Ueber die Web-Oberflaeche (OTA, kein USB-Kabel noetig):** Tab "Firmware" ->
"Upload Update" nimmt `firmware.bin` und optional `littlefs.bin` an, aus einem
lokalen Build oder aus einem Release (siehe unten).

## Update auf eine neue Version

1. Im GitHub-Release die beiden Images herunterladen:
   `presencetrack-<x.y.z>-firmware.bin` und `presencetrack-<x.y.z>-littlefs.bin`
   (optional gegen `presencetrack-<x.y.z>-checksums.txt` pruefen:
   `sha256sum -c presencetrack-<x.y.z>-checksums.txt`).
2. Web-Oberflaeche -> Tab "Firmware" -> "Upload Update": beide Dateien
   auswaehlen und "Start update".
3. Das Dateisystem-Image ersetzt die ganze LittleFS-Partition und loescht dabei
   die Einstellungen (`/config.json`). Die Seite laedt deshalb vor dem Upload
   ein Konfigurations-Backup in den Download-Ordner des Browsers und spielt es
   nach dem Neustart automatisch wieder ein. Schlaegt das fehl: Karte
   "Restore Backup" mit genau dieser Datei.

Alternativ per USB: `./flash.sh [seriell-port] [geraete-ip]`, Auswahl 3
(beides); mit Geraete-IP sichert und restauriert das Skript die Konfiguration
genauso.

## Release process

1. Set `FIRMWARE_VERSION` in `include/firmware.h` to the new version and
   commit it.
2. Push an annotated tag: `git tag -a v<x.y.z> -m "..."` and `git push origin v<x.y.z>`.
3. CI (`.github/workflows/firmware.yml`) builds the firmware and filesystem,
   checks that the tag matches `v<FIRMWARE_VERSION>` exactly and, on success,
   publishes a GitHub release with
   `presencetrack-<x.y.z>-firmware.bin`, `presencetrack-<x.y.z>-littlefs.bin`
   and `presencetrack-<x.y.z>-checksums.txt`. Installing it on the device is
   described under "Update auf eine neue Version".

Pushes to `main` and pull requests only build (artifacts are uploaded for
traceability) without creating a release.
