#pragma once

#include "app_config.h"

// MQTT discovery following the Home Assistant convention (homeassistant/<component>/...).
// The device thus shows up in HA automatically with all its entities as soon
// as the MQTT broker is configured in the web UI - no YAML required.
void mqttHaBegin(const AppConfig &cfg);
void mqttHaApplyConfig(const AppConfig &cfg);
void mqttHaLoop();
bool mqttHaIsConnected();
