#pragma once

#include "app_config.h"

// Async web server (port 80) with a REST API under /api/... and the SPA from
// LittleFS (data/). The REST handlers mutate the given config directly,
// persist it and pass it on to the MQTT/HA layer.
//
// Deliberately without the ESPAsyncWebServer include: its HTTP_GET/HTTP_POST
// enums collide with ESP8266WebServer (used by WiFiManager in main.cpp).
void webServerBegin(AppConfig &cfg);

// Must be called regularly from loop() (delayed restart after /api/reboot or
// /api/factory-reset; gibt Plätze des HTTP-Verbindungslimits wieder frei;
// taktet das Update von GitHub, firmware_update.h).
void webServerLoop();

// Neustart REBOOT_DELAY_MS (300 ms) später aus webServerLoop(), damit die
// laufende HTTP-Antwort noch hinausgeht; loggt Reboot bzw. FactoryReset.
// Öffentlich für firmware_update.cpp (Neustart nach einem Update von GitHub).
void webServerScheduleReboot(bool factoryReset);
