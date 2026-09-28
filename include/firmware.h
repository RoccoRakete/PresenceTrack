#pragma once

// Single source of truth for the firmware release version: reported as
// sw_version in the Home Assistant discovery payloads (mqtt_ha.cpp) and as
// fw_version by /api/system, so the web UI can show which build an OTA update
// actually brought up. Bump it with every release.
//
// Deliberately independent of CONFIG_SCHEMA_VERSION (app_config.cpp): the
// config layout only changes with some releases, and a firmware that keeps the
// layout must not look like a schema change in /config.json backups.
//
// Muss exakt zum GitHub-Release-Tag v<FIRMWARE_VERSION> passen: die CI
// (.github/workflows/firmware.yml) prüft das bei jedem Tag-Build und
// veröffentlicht bei Abweichung kein Release - sonst trügen die Release-Assets
// eine andere Fassung im Namen, als das Gerät nach dem Upload unter /api/system
// meldet.
//
// 0.4.0: Das Update direkt vom Gerät aus GitHub ist entfernt. Updates laufen nur
// noch über den Datei-Upload der Weboberfläche (/api/firmware, /api/filesystem)
// oder per USB (flash.sh). Das Konfigurationsformat ist unverändert
// (CONFIG_SCHEMA_VERSION bleibt).
#define FIRMWARE_VERSION "0.4.0"
