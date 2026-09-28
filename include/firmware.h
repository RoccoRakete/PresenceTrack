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
// Muss exakt zum GitHub-Release-Tag v<FIRMWARE_VERSION> passen: die CI prüft
// das beim Release, und das Update von GitHub (firmware_update.cpp) vergleicht
// diese Version mit "version" aus manifest.json - weicht sie ab, bietet das
// Gerät ein Release entweder endlos erneut an oder nie. Nur Ziffern und Punkte,
// höchstens drei Segmente (firmwareUpdateVersionValid).
//
// 0.3.1: Patch für das Update von GitHub in 0.3.0 (veröffentlicht und defekt). Der
// check blockierte den Webserver-Request bis zum Manifest, DNS/TCP/TLS-Fehler kamen
// als nichtssagendes "BearSSL error 0" an, und der Empfangspuffer hing vom Host ab.
// Siehe Kopfkommentar in firmware_update.cpp. Das Konfigurationsformat ist
// unverändert (CONFIG_SCHEMA_VERSION bleibt).
//
// 0.3.2: 0.3.1 wurde nie veröffentlicht (nur auf main). Der check läuft jetzt auf
// dem echten Gerät über beide github.com-Hops und das CDN durch, das Manifest wird
// geparst, und der Speicherbedarf liegt bei 17781 B (check) bzw. 18049 B (install)
// gegenüber ~22000 B freiem Heap - vorher zu knapp. Erstes Release, von dem ein
// Gerät auf dem defekten 0.3.0 aus tatsächlich aktualisieren kann.
#define FIRMWARE_VERSION "0.3.2"
