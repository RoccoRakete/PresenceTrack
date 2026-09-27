#include "app_config.h"
#include <LittleFS.h>

static const char *CONFIG_PATH = "/config.json";
static const char *CONFIG_TMP_PATH = "/config.json.tmp";
static const uint8_t CONFIG_SCHEMA_VERSION = 7; // informational only, not evaluated on load

// Indexed by ObjectType
static const char *const OBJECT_TYPE_NAMES[OBJECT_TYPE_COUNT] = {
    "cabinet", "sofa", "door", "table", "other",
};

const char *objectTypeToString(uint8_t type) {
    return OBJECT_TYPE_NAMES[type < OBJECT_TYPE_COUNT ? type : OBJECT_OTHER];
}

int objectTypeFromString(const char *s) {
    if (!s) return -1;
    for (uint8_t i = 0; i < OBJECT_TYPE_COUNT; i++) {
        if (strcmp(s, OBJECT_TYPE_NAMES[i]) == 0) return i;
    }
    return -1;
}

// Default object footprints: 400 x 400 mm cells of a 4 x 3 grid around the
// map center, so that newly added objects do not stack on top of each other.
// All object slots are unused after a factory reset.
static const int16_t DEFAULT_OBJECT_SIZE_MM = 400;
static const int16_t DEFAULT_OBJECT_PITCH_MM = 600;

// Default zone rectangles {x1, y1, x2, y2} in mm: a 3x2 grid of 2 m x 2 m
// cells covering the sensor's field of view (near row / far row). Only the
// first DEFAULT_PRESENT_ZONES slots are in use after a factory reset.
static const int16_t DEFAULT_ZONE_RECTS[MAX_ZONES][4] = {
    {-3000,  500, -1000, 2500},
    {-1000,  500,  1000, 2500},
    { 1000,  500,  3000, 2500},
    {-3000, 3000, -1000, 5000},
    {-1000, 3000,  1000, 5000},
    { 1000, 3000,  3000, 5000},
};
static const uint8_t DEFAULT_PRESENT_ZONES = 2;

void resetConfigToDefaults(AppConfig &cfg) {
    cfg = AppConfig{};
    for (uint8_t i = 0; i < MAX_ZONES; i++) {
        cfg.zones[i].id = i;
        snprintf(cfg.zones[i].name, sizeof(cfg.zones[i].name), "Zone %u", i + 1);
        cfg.zones[i].present = i < DEFAULT_PRESENT_ZONES;
        cfg.zones[i].enabled = false;
        cfg.zones[i].x1 = DEFAULT_ZONE_RECTS[i][0];
        cfg.zones[i].y1 = DEFAULT_ZONE_RECTS[i][1];
        cfg.zones[i].x2 = DEFAULT_ZONE_RECTS[i][2];
        cfg.zones[i].y2 = DEFAULT_ZONE_RECTS[i][3];
    }
    for (uint8_t i = 0; i < MAX_OBJECTS; i++) {
        RoomObjectConfig &o = cfg.objects[i];
        o.id = i;
        snprintf(o.name, sizeof(o.name), "Object %u", i + 1);
        o.present = false;
        o.type = OBJECT_OTHER;
        o.x1 = -1100 + (i % 4) * DEFAULT_OBJECT_PITCH_MM;
        o.y1 = 2400 + (i / 4) * DEFAULT_OBJECT_PITCH_MM;
        o.x2 = o.x1 + DEFAULT_OBJECT_SIZE_MM;
        o.y2 = o.y1 + DEFAULT_OBJECT_SIZE_MM;
        o.rotationDeg = 0;
    }
}

void AppConfig::toJson(JsonDocument &doc) const {
    doc["schema"] = CONFIG_SCHEMA_VERSION;

    JsonObject ld = doc["ld2450"].to<JsonObject>();
    ld["enabled"] = ld2450.enabled;
    ld["multi_target"] = ld2450.multiTarget;
    ld["max_range_mm"] = ld2450.maxRangeMm;
    ld["occupancy_timeout_s"] = ld2450.occupancyTimeoutS;
    ld["sim_enabled"] = ld2450.simEnabled;
    ld["moving_threshold_cm_s"] = ld2450.movingThresholdCmS;
    ld["rx_pin"] = ld2450.rxPin;
    ld["tx_pin"] = ld2450.txPin;

    JsonObject bh = doc["bh1750"].to<JsonObject>();
    bh["enabled"] = bh1750.enabled;
    bh["i2c_address"] = bh1750.i2cAddress;
    bh["mode"] = bh1750.mode;
    bh["interval_ms"] = bh1750.intervalMs;
    bh["sim_enabled"] = bh1750.simEnabled;
    bh["sda_pin"] = bh1750.sdaPin;
    bh["scl_pin"] = bh1750.sclPin;

    JsonObject mq = doc["mqtt"].to<JsonObject>();
    mq["enabled"] = mqtt.enabled;
    mq["host"] = mqtt.host;
    mq["port"] = mqtt.port;
    mq["user"] = mqtt.user;
    mq["pass"] = mqtt.pass;
    mq["topic_prefix"] = mqtt.topicPrefix;
    mq["device_name"] = mqtt.deviceName;
    mq["keepalive_s"] = mqtt.keepAliveS;
    mq["socket_timeout_s"] = mqtt.socketTimeoutS;

    JsonObject ha = doc["ha_expose"].to<JsonObject>();
    ha["presence"] = haExpose.presence;
    ha["target_count"] = haExpose.targetCount;
    ha["illuminance"] = haExpose.illuminance;
    ha["motion"] = haExpose.motion;
    ha["zone_motion"] = haExpose.zoneMotion;

    JsonObject wf = doc["wifi"].to<JsonObject>();
    wf["no_modem_sleep"] = wifi.noModemSleep;

    JsonArray zonesArr = doc["zones"].to<JsonArray>();
    for (uint8_t i = 0; i < MAX_ZONES; i++) {
        JsonObject z = zonesArr.add<JsonObject>();
        z["id"] = zones[i].id;
        z["name"] = zones[i].name;
        z["present"] = zones[i].present;
        z["enabled"] = zones[i].enabled;
        z["x1"] = zones[i].x1;
        z["y1"] = zones[i].y1;
        z["x2"] = zones[i].x2;
        z["y2"] = zones[i].y2;
        z["min_resolution"] = zones[i].minResolution;
    }

    JsonArray objectsArr = doc["objects"].to<JsonArray>();
    for (uint8_t i = 0; i < MAX_OBJECTS; i++) {
        JsonObject o = objectsArr.add<JsonObject>();
        o["id"] = objects[i].id;
        o["name"] = objects[i].name;
        o["present"] = objects[i].present;
        o["type"] = objectTypeToString(objects[i].type);
        o["x1"] = objects[i].x1;
        o["y1"] = objects[i].y1;
        o["x2"] = objects[i].x2;
        o["y2"] = objects[i].y2;
        o["rotation_deg"] = objects[i].rotationDeg;
    }
}

// Old (e.g. LD2410-era) keys simply do not match here and fall back to the
// defaults set by resetConfigToDefaults() - no explicit migration needed.
void AppConfig::fromJson(const JsonDocument &doc) {
    if (doc["ld2450"].is<JsonObjectConst>()) {
        JsonObjectConst ld = doc["ld2450"];
        ld2450.enabled = ld["enabled"] | ld2450.enabled;
        ld2450.multiTarget = ld["multi_target"] | ld2450.multiTarget;
        ld2450.maxRangeMm = ld["max_range_mm"] | ld2450.maxRangeMm;
        ld2450.occupancyTimeoutS = ld["occupancy_timeout_s"] | ld2450.occupancyTimeoutS;
        ld2450.simEnabled = ld["sim_enabled"] | ld2450.simEnabled;
        ld2450.movingThresholdCmS = ld["moving_threshold_cm_s"] | ld2450.movingThresholdCmS;
        ld2450.rxPin = ld["rx_pin"] | ld2450.rxPin;
        ld2450.txPin = ld["tx_pin"] | ld2450.txPin;
    }

    if (doc["bh1750"].is<JsonObjectConst>()) {
        JsonObjectConst bh = doc["bh1750"];
        bh1750.enabled = bh["enabled"] | bh1750.enabled;
        bh1750.i2cAddress = bh["i2c_address"] | bh1750.i2cAddress;
        bh1750.mode = bh["mode"] | bh1750.mode;
        bh1750.intervalMs = bh["interval_ms"] | bh1750.intervalMs;
        bh1750.simEnabled = bh["sim_enabled"] | bh1750.simEnabled;
        bh1750.sdaPin = bh["sda_pin"] | bh1750.sdaPin;
        bh1750.sclPin = bh["scl_pin"] | bh1750.sclPin;
    }

    if (doc["mqtt"].is<JsonObjectConst>()) {
        JsonObjectConst mq = doc["mqtt"];
        mqtt.enabled = mq["enabled"] | mqtt.enabled;
        strlcpy(mqtt.host, mq["host"] | mqtt.host, sizeof(mqtt.host));
        mqtt.port = mq["port"] | mqtt.port;
        strlcpy(mqtt.user, mq["user"] | mqtt.user, sizeof(mqtt.user));
        strlcpy(mqtt.pass, mq["pass"] | mqtt.pass, sizeof(mqtt.pass));
        strlcpy(mqtt.topicPrefix, mq["topic_prefix"] | mqtt.topicPrefix, sizeof(mqtt.topicPrefix));
        strlcpy(mqtt.deviceName, mq["device_name"] | mqtt.deviceName, sizeof(mqtt.deviceName));
        // Missing in schema <= 5: keep the defaults
        mqtt.keepAliveS = mq["keepalive_s"] | mqtt.keepAliveS;
        mqtt.socketTimeoutS = mq["socket_timeout_s"] | mqtt.socketTimeoutS;
    }

    // Missing in schema <= 4: all entities stay exposed (defaults), as before
    if (doc["ha_expose"].is<JsonObjectConst>()) {
        JsonObjectConst ha = doc["ha_expose"];
        haExpose.presence = ha["presence"] | haExpose.presence;
        haExpose.targetCount = ha["target_count"] | haExpose.targetCount;
        haExpose.illuminance = ha["illuminance"] | haExpose.illuminance;
        haExpose.motion = ha["motion"] | haExpose.motion;
        haExpose.zoneMotion = ha["zone_motion"] | haExpose.zoneMotion;
    }

    // Missing in schema <= 5: modem sleep stays disabled (default)
    if (doc["wifi"].is<JsonObjectConst>()) {
        JsonObjectConst wf = doc["wifi"];
        wifi.noModemSleep = wf["no_modem_sleep"] | wifi.noModemSleep;
    }

    if (doc["zones"].is<JsonArrayConst>()) {
        JsonArrayConst zonesArr = doc["zones"];
        uint8_t i = 0;
        for (JsonObjectConst z : zonesArr) {
            if (i >= MAX_ZONES) break;
            zones[i].id = z["id"] | i;
            strlcpy(zones[i].name, z["name"] | zones[i].name, sizeof(zones[i].name));
            // Configs without "present" (schema <= 2) showed all slots, so keep them visible
            zones[i].present = z["present"] | true;
            zones[i].enabled = zones[i].present && (z["enabled"] | zones[i].enabled);
            zones[i].x1 = z["x1"] | zones[i].x1;
            zones[i].y1 = z["y1"] | zones[i].y1;
            zones[i].x2 = z["x2"] | zones[i].x2;
            zones[i].y2 = z["y2"] | zones[i].y2;
            // Missing in schema <= 6: no per-zone signal filter (0)
            zones[i].minResolution = z["min_resolution"] | zones[i].minResolution;
            i++;
        }
    }

    // Missing in schema <= 3: the unused default slots from resetConfigToDefaults() stay
    if (doc["objects"].is<JsonArrayConst>()) {
        JsonArrayConst objectsArr = doc["objects"];
        uint8_t i = 0;
        for (JsonObjectConst o : objectsArr) {
            if (i >= MAX_OBJECTS) break;
            RoomObjectConfig &obj = objects[i];
            obj.id = o["id"] | i;
            strlcpy(obj.name, o["name"] | obj.name, sizeof(obj.name));
            obj.present = o["present"] | obj.present;
            // Missing "type" keeps the stored value (same merge rule as every other field here);
            // only a present-but-unrecognized string falls back to "other".
            if (o["type"].is<const char *>()) {
                int type = objectTypeFromString(o["type"].as<const char *>());
                obj.type = type < 0 ? OBJECT_OTHER : (uint8_t)type;
            }
            obj.x1 = o["x1"] | obj.x1;
            obj.y1 = o["y1"] | obj.y1;
            obj.x2 = o["x2"] | obj.x2;
            obj.y2 = o["y2"] | obj.y2;
            int16_t rot = o["rotation_deg"] | obj.rotationDeg;
            obj.rotationDeg = (rot == 90 || rot == 180 || rot == 270) ? rot : 0;
            i++;
        }
    }
}

bool loadConfig(AppConfig &cfg) {
    resetConfigToDefaults(cfg);

    if (!LittleFS.exists(CONFIG_PATH)) {
        return false;
    }

    File f = LittleFS.open(CONFIG_PATH, "r");
    if (!f) {
        return false;
    }

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, f);
    f.close();

    if (err) {
        return false;
    }

    cfg.fromJson(doc);
    return true;
}

bool saveConfig(const AppConfig &cfg) {
    JsonDocument doc;
    cfg.toJson(doc);

    // Write to a temp file first and only replace the real config once the
    // write succeeded, so a full filesystem never leaves a truncated config.
    File f = LittleFS.open(CONFIG_TMP_PATH, "w");
    if (!f) {
        Serial.println("Config save failed: cannot open temp file");
        return false;
    }

    size_t expected = measureJson(doc);
    size_t written = serializeJson(doc, f);
    bool ok = written == expected && !f.getWriteError();
    f.close();

    if (!ok) {
        Serial.println("Config save failed: incomplete write");
        LittleFS.remove(CONFIG_TMP_PATH);
        return false;
    }

    // lfs_rename replaces an existing destination atomically.
    if (!LittleFS.rename(CONFIG_TMP_PATH, CONFIG_PATH)) {
        Serial.println("Config save failed: cannot replace config file");
        LittleFS.remove(CONFIG_TMP_PATH);
        return false;
    }
    return true;
}
