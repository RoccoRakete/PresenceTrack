#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

// A logical zone is an axis-aligned rectangle in the LD2450 coordinate
// system (mm, sensor at the origin, X = left/right, Y = distance in front
// of the sensor), modeled after the Aqara FP2 zone UI.
struct ZoneConfig {
    uint8_t id = 0;
    char name[24] = "Zone";
    bool present = false; // slot in use (shown in the UI); enabled is forced false otherwise
    bool enabled = false; // evaluated and reported to Home Assistant
    int16_t x1 = 0;
    int16_t y1 = 0;
    int16_t x2 = 0;
    int16_t y2 = 0;
    // Firmware-side counterpart of the LD2410 per-gate thresholds (the LD2450
    // has no gates): +2 B per zone.
    uint16_t minResolution = 0; // 0 = off; targets below this signal quality do not count for this zone
};

static const uint8_t MAX_ZONES = 6;

// Furniture / room objects drawn on the zone map for orientation only: no
// presence evaluation, not exported to Home Assistant.
enum ObjectType : uint8_t {
    OBJECT_CABINET = 0,
    OBJECT_SOFA,
    OBJECT_DOOR,
    OBJECT_TABLE,
    OBJECT_OTHER,
    OBJECT_TYPE_COUNT
};

// Same coordinate system as ZoneConfig. x1..y2 is always the axis-aligned
// footprint; rotationDeg (0/90/180/270) is the facing direction.
struct RoomObjectConfig {
    uint8_t id = 0;
    char name[24] = "Object";
    bool present = false; // slot in use (shown in the UI)
    uint8_t type = OBJECT_OTHER;
    int16_t x1 = 0;
    int16_t y1 = 0;
    int16_t x2 = 0;
    int16_t y2 = 0;
    int16_t rotationDeg = 0;
};

static const uint8_t MAX_OBJECTS = 12;

// JSON names of ObjectType ("cabinet", "sofa", ...).
const char *objectTypeToString(uint8_t type);
// Returns -1 for unknown or missing names.
int objectTypeFromString(const char *s);

// Region filter inside the LD2450 itself (command 0x00C2): targets in these
// rectangles are never reported by the sensor. Unrelated to ZoneConfig, which
// only evaluates presence in firmware. Sent to the sensor once at boot.
static const uint8_t LD2450_REGION_COUNT = 3; // fixed by the sensor protocol

enum Ld2450RegionFilterMode : uint8_t {
    REGION_FILTER_OFF = 0,
    // 1 = "detect only inside the regions" exists in the sensor but is deliberately not offered
    REGION_FILTER_EXCLUDE = 2,
};

// Same coordinate system as ZoneConfig (mm, x1 < x2, y1 < y2 for present slots).
struct Ld2450RegionFilterConfig {
    uint8_t mode = REGION_FILTER_OFF;
    int16_t x1[LD2450_REGION_COUNT] = {0};
    int16_t y1[LD2450_REGION_COUNT] = {0};
    int16_t x2[LD2450_REGION_COUNT] = {0};
    int16_t y2[LD2450_REGION_COUNT] = {0};
    bool present[LD2450_REGION_COUNT] = {false}; // slot in use; unused slots are sent as all zeros
};

struct Ld2450Config {
    bool enabled = true;
    bool multiTarget = true;        // native sensor mode preference (for later real UART command)
    uint16_t maxRangeMm = 6000;      // map scale / plausibility bound for simulated X/Y
    uint16_t occupancyTimeoutS = 5;  // hold-off before presence goes false after last target loss (firmware-side, no sensor equivalent)
    bool simEnabled = true;          // simulated targets instead of the UART frames
    uint16_t movingThresholdCmS = 10; // |speed| >= threshold -> target counts as moving (0..1000)
    bool ghostFilterEnabled = true;   // debounce + jump-distance check against short-lived multipath ghost targets
    uint16_t ghostMinExistMs = 500;   // min. time a target must stay active in its slot before it counts (0 = off)
    uint16_t ghostMaxJumpCmS = 300;   // max plausible target speed between evaluation ticks; larger jumps are rejected
    // GPIO numbers, read at boot: 13/15 = hardware UART0 swapped to D7/D8, else SoftwareSerial
    uint8_t rxPin = 13; // D7
    uint8_t txPin = 15; // D8
    Ld2450RegionFilterConfig regionFilter; // read at boot, like the pins
};

struct Bh1750Config {
    bool enabled = true;
    uint8_t i2cAddress = 0x23;
    // 0 = Continuous High Res, 1 = Continuous High Res Mode2, 2 = Continuous Low Res
    uint8_t mode = 0;
    uint32_t intervalMs = 5000;
    bool simEnabled = true;
    // GPIO numbers of the I2C bus, read at boot (address and mode apply at the next reading)
    uint8_t sdaPin = 4; // D2
    uint8_t sclPin = 5; // D1
};

struct MqttConfig {
    bool enabled = false;
    char host[64] = "";
    uint16_t port = 1883;
    char user[32] = "";
    char pass[64] = "";
    char topicPrefix[32] = "presencetrack";
    char deviceName[32] = "PresenceTrack";
    uint16_t keepAliveS = 60;    // PubSubClient::setKeepAlive()
    uint16_t socketTimeoutS = 4; // PubSubClient::setSocketTimeout(), must stay < keepAliveS
};

// Which Home Assistant entities are announced via MQTT discovery. Zone
// occupancy entities (zone_<i>) follow the zone's own enabled flag instead.
struct HaExposeConfig {
    bool presence = true;
    bool targetCount = true;
    bool illuminance = true;
    bool motion = true;
    bool zoneMotion = true; // zone_<i>_motion for every enabled zone
};

// Hostname and IP settings are applied once at boot (main.cpp, before
// WiFiManager::autoConnect()); SSID/password stay with the WiFiManager portal.
struct WifiConfig {
    bool noModemSleep = true; // true -> WIFI_NONE_SLEEP instead of modem sleep
    char hostname[32] = "presencetrack"; // [A-Za-z0-9-], no leading/trailing '-'
    bool useStaticIp = false;
    char staticIp[16] = "";
    char gateway[16] = "";
    char subnet[16] = "255.255.255.0";
    char dns[16] = ""; // empty -> the gateway is used as DNS server
};

struct AppConfig {
    Ld2450Config ld2450;
    Bh1750Config bh1750;
    MqttConfig mqtt;
    HaExposeConfig haExpose;
    WifiConfig wifi;
    ZoneConfig zones[MAX_ZONES];
    RoomObjectConfig objects[MAX_OBJECTS];

    void toJson(JsonDocument &doc) const;
    void fromJson(const JsonDocument &doc);
};

bool loadConfig(AppConfig &cfg);
bool saveConfig(const AppConfig &cfg);
void resetConfigToDefaults(AppConfig &cfg);
