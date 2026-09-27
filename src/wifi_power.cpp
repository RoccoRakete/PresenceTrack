#include "wifi_power.h"
#include <ESP8266WiFi.h>

void wifiPowerApplyConfig(const WifiConfig &cfg) {
    WiFi.setSleepMode(cfg.noModemSleep ? WIFI_NONE_SLEEP : WIFI_MODEM_SLEEP);
}
