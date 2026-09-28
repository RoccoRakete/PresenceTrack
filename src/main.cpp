#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <LittleFS.h>
#include <WiFiManager.h>
#include <lwip/etharp.h>
#include <lwip/netif.h>

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

// ---------------------------------------------------------------------------
// Static IP fallback
//
// A wrong static IP would leave the device unreachable with no way back but a
// serial flash. Failed boots with the static IP are therefore counted in RTC
// memory (survives ESP.restart() and resets, not a power loss); after
// STATIC_IP_MAX_FAILS the device boots with DHCP until the static settings
// change (configHash) or the power is cycled.
// A wrong IP still "connects" (WL_CONNECTED only means associated), so a boot
// also counts as failed if the gateway does not answer ARP.
// RTC user blocks 64-66 (4-B blocks): 0-31 hold eboot_command.
// ---------------------------------------------------------------------------

static const uint8_t STATIC_IP_MAX_FAILS = 3;
static const uint32_t RTC_WIFI_BLOCK = 64;
static const uint32_t RTC_WIFI_MAGIC = 0x50545743; // "PTWC"
static const unsigned long GATEWAY_ARP_TIMEOUT_MS = 3000;

struct RtcWifiState {
    uint32_t magic;      // anything else after a power loss: no failures recorded
    uint32_t configHash; // staticIpConfigHash() of the settings the failures belong to
    uint32_t staticIpFails;
};

// FNV-1a over the address fields
static uint32_t staticIpConfigHash(const WifiConfig &c) {
    uint32_t h = 2166136261u;
    for (const char *s : {c.staticIp, c.gateway, c.subnet, c.dns}) {
        for (; *s; s++) h = (h ^ (uint8_t)*s) * 16777619u;
        h = (h ^ '|') * 16777619u;
    }
    return h;
}

static uint32_t rtcReadStaticIpFails(uint32_t configHash) {
    RtcWifiState s;
    if (!ESP.rtcUserMemoryRead(RTC_WIFI_BLOCK, reinterpret_cast<uint32_t *>(&s), sizeof(s))) return 0;
    return (s.magic == RTC_WIFI_MAGIC && s.configHash == configHash) ? s.staticIpFails : 0;
}

static void rtcWriteStaticIpFails(uint32_t configHash, uint32_t fails) {
    RtcWifiState s{RTC_WIFI_MAGIC, configHash, fails};
    ESP.rtcUserMemoryWrite(RTC_WIFI_BLOCK, reinterpret_cast<uint32_t *>(&s), sizeof(s));
}

// true once the gateway's MAC is in the ARP table (no ICMP ping in the core).
static bool gatewayAnswersArp(const IPAddress &gateway) {
    struct netif *nif = nullptr;
    for (struct netif *n = netif_list; n; n = n->next) {
        if (ip4_addr_get_u32(netif_ip4_addr(n)) == WiFi.localIP().v4()) nif = n;
    }
    if (!nif) return false;

    ip4_addr_t gw;
    ip4_addr_set_u32(&gw, gateway.v4());
    unsigned long start = millis(), lastRequest = 0;
    bool first = true;
    while (millis() - start < GATEWAY_ARP_TIMEOUT_MS) {
        if (first || millis() - lastRequest >= 500) {
            etharp_request(nif, &gw);
            lastRequest = millis();
            first = false;
        }
        struct eth_addr *eth;
        const ip4_addr_t *ip;
        if (etharp_find_addr(nif, &gw, &eth, &ip) >= 0) return true;
        delay(20);
    }
    return false;
}

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

    const WifiConfig &wc = g_appConfig.wifi;
    const uint32_t staticIpHash = staticIpConfigHash(wc);
    const uint32_t staticIpFails = wc.useStaticIp ? rtcReadStaticIpFails(staticIpHash) : 0;
    const bool applyStaticIp = wc.useStaticIp && staticIpFails < STATIC_IP_MAX_FAILS;
    if (wc.useStaticIp && !applyStaticIp)
    {
        Serial.println("Static IP failed repeatedly - using DHCP");
        eventLogPush(EventType::Network, "Static IP failed %ux, using DHCP", STATIC_IP_MAX_FAILS);
    }

    // Blocking: avoids a port 80 collision between the WiFiManager portal
    // and ESPAsyncWebServer (the device is permanently powered).
    WiFiManager wm;
    wm.setConfigPortalTimeout(CONFIG_PORTAL_TIMEOUT_S);
    wm.setHostname(wc.hostname); // applied by autoConnect() before the station connects
    IPAddress gateway;
    if (applyStaticIp)
    {
        // Validated by POST /api/config/wifi; an empty DNS falls back to the gateway,
        // without any DNS server the MQTT broker name would not resolve
        IPAddress ip, subnet, dns;
        ip.fromString(wc.staticIp);
        gateway.fromString(wc.gateway);
        subnet.fromString(wc.subnet);
        if (!*wc.dns || !dns.fromString(wc.dns)) dns = gateway;
        wm.setSTAStaticIPConfig(ip, gateway, subnet, dns);
    }

    bool connected = wm.autoConnect(AP_SSID, AP_PASSWORD);
    if (connected && applyStaticIp && !gatewayAnswersArp(gateway))
    {
        Serial.println("Gateway not reachable with the static IP");
        connected = false;
    }
    if (!connected)
    {
        if (applyStaticIp) rtcWriteStaticIpFails(staticIpHash, staticIpFails + 1);
        Serial.println("Wi-Fi connection failed - restarting");
        ESP.restart();
    }
    if (applyStaticIp && staticIpFails) rtcWriteStaticIpFails(staticIpHash, 0);

    wifiPowerApplyConfig(g_appConfig.wifi);
    mqttHaBegin(g_appConfig);
    webServerBegin(g_appConfig);

    Serial.print("IP: ");
    Serial.println(WiFi.localIP());
    // Last: with the LD2450 on D7/D8 this swaps UART0 away from USB, so all
    // boot output has to be written before.
    sensorsBegin(g_appConfig);
}

void loop()
{
    sensorsLoop(g_appConfig);
    mqttHaLoop();
    webServerLoop();
}
