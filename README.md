# PresenceTrack

ESP8266 firmware for a presence and illuminance sensor: LD2410C
(mmWave presence radar) + BH1750FVI (illuminance), connected to Home Assistant
via MQTT discovery. Configuration, status and firmware updates run through
a web interface served by the device itself.

## Hardware

- ESP8266 D1 Mini (4 MB flash, board layout `d1_mini`)
- LD2410C (UART, presence/motion detection)
- BH1750FVI (I2C, illuminance)

## Directory layout

```
include/        Headers of the firmware modules
src/            Implementation (sensors, Wi-Fi, MQTT/HA, web server, OTA)
data/           Web interface (flashed as a LittleFS image)
platformio.ini  Board and build configuration
flash.sh        Interactive flash script (USB, with config backup/restore)
.github/        CI workflow (build and release)
```

## Local build

PlatformIO is provided via Nix (`flake.nix`/`.envrc`; direnv activates the
shell automatically, without direnv run `nix shell nixpkgs#platformio` manually):

```
pio run                # firmware   -> .pio/build/d1_mini/firmware.bin
pio run -t buildfs     # filesystem -> .pio/build/d1_mini/littlefs.bin (from data/)
```

## Flashing

**Via USB:** `./flash.sh [serial-port] [device-ip]` asks interactively whether
to flash the firmware, the filesystem or both, backs up the running
configuration through the device API before a filesystem update and restores
it automatically afterwards.

**Via the web interface (OTA, no USB cable needed):** tab "Firmware" ->
"Upload Update" accepts `firmware.bin` and optionally `littlefs.bin`, either
from a local build or from a release (see below).

## Updating to a new version

1. Download both images from the GitHub release:
   `presencetrack-<x.y.z>-firmware.bin` and `presencetrack-<x.y.z>-littlefs.bin`
   (optionally verify them against `presencetrack-<x.y.z>-checksums.txt`:
   `sha256sum -c presencetrack-<x.y.z>-checksums.txt`).
2. Web interface -> tab "Firmware" -> "Upload Update": select both files
   and click "Start update".
3. The filesystem image replaces the whole LittleFS partition and thereby
   erases the settings (`/config.json`). The page therefore downloads a
   configuration backup into the browser's download folder before the upload
   and restores it automatically after the reboot. If that fails: use the
   "Restore Backup" card with exactly that file.

Alternatively via USB: `./flash.sh [serial-port] [device-ip]`, option 3
(both); with a device IP the script backs up and restores the configuration
the same way.

## Release process

1. Set `FIRMWARE_VERSION` in `include/firmware.h` to the new version and
   commit it.
2. Push an annotated tag: `git tag -a v<x.y.z> -m "..."` and `git push origin v<x.y.z>`.
3. CI (`.github/workflows/firmware.yml`) builds the firmware and filesystem,
   checks that the tag matches `v<FIRMWARE_VERSION>` exactly and, on success,
   publishes a GitHub release with
   `presencetrack-<x.y.z>-firmware.bin`, `presencetrack-<x.y.z>-littlefs.bin`
   and `presencetrack-<x.y.z>-checksums.txt`. Installing it on the device is
   described under "Updating to a new version".

Pushes to `main` and pull requests only build (artifacts are uploaded for
traceability) without creating a release.
