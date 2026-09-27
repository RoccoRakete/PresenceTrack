#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <LittleFS.h>
#include <WiFiManager.h>

#include "app_config.h"
#include "sensor_data.h"
#include "mqtt_ha.h"
#include "web_server.h"
#include "event_log.h"
#include "wifi_power.h"

static const char *AP_SSID = "PresenceTrack-Setup";
static const char *AP_PASSWORD = "presence1234";
static const unsigned long CONFIG_PORTAL_TIMEOUT_S = 300;

// Single global config instance; the web server mutates it by reference.
AppConfig g_appConfig;

void setup()
{
    Serial.begin(115200);
    Serial.println();
    Serial.println("PresenceTrack starting...");
    eventLogPush(EventType::Reboot, "Boot (%s)", ESP.getResetReason().c_str());

    if (!LittleFS.begin())
    {
        Serial.println("LittleFS mount failed - formatting");
        LittleFS.format();
        if (!LittleFS.begin())
        {
            Serial.println("LittleFS unavailable");
        }
    }

    // Loads /config.json or defaults - keep running in either case
    if (!loadConfig(g_appConfig))
    {
        Serial.println("No valid config found - using defaults");
    }

    // Blocking: avoids a port 80 collision between the WiFiManager portal
    // and ESPAsyncWebServer (the device is permanently powered).
    WiFiManager wm;
    wm.setConfigPortalTimeout(CONFIG_PORTAL_TIMEOUT_S);
    bool connected = wm.autoConnect(AP_SSID, AP_PASSWORD);
    if (!connected)
    {
        Serial.println("Wi-Fi connection failed - restarting");
        ESP.restart();
    }

    wifiPowerApplyConfig(g_appConfig.wifi);
    sensorsBegin(g_appConfig);
    mqttHaBegin(g_appConfig);
    webServerBegin(g_appConfig);

    Serial.print("IP: ");
    Serial.println(WiFi.localIP());
}

void loop()
{
    sensorsLoop(g_appConfig);
    mqttHaLoop();
    webServerLoop();
}
