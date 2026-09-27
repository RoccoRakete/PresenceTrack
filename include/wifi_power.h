#pragma once

#include "app_config.h"

// WiFi power-save settings. Modem sleep powers the radio down between DTIM
// beacons, which delays replies and can make PubSubClient run into
// MQTT_CONNECTION_TIMEOUT ("state -3"). Can be switched at runtime, no reconnect needed.
void wifiPowerApplyConfig(const WifiConfig &cfg);
