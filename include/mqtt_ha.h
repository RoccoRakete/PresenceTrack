#pragma once

#include "app_config.h"

// MQTT discovery following the Home Assistant convention (homeassistant/<component>/...).
// The device thus shows up in HA automatically with all its entities as soon
// as the MQTT broker is configured in the web UI - no YAML required.
void mqttHaBegin(const AppConfig &cfg);
void mqttHaApplyConfig(const AppConfig &cfg);
void mqttHaLoop();
bool mqttHaIsConnected();

// Längstes Zustands-PUBLISH auf der Leitung (publishStates): Kopf 1 + Restlänge 1 +
// Topic-Länge 2 + Topic <= 66 (Präfix 31 + "/" + Geräte-Id 20 + "/" + "zone_5_motion")
// + Wert <= 15 (valueBuf). Während eines Updates von GitHub ist höchstens eines davon
// unbestätigt - die Heap-Rechnung dort (RESERVE_MQTT, firmware_update.cpp) baut darauf.
static const uint16_t MQTT_STATE_PACKET_MAX = 85;
