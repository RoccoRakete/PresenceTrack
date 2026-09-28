#include "mqtt_ha.h"
#include "sensor_data.h"
#include "event_log.h"
#include "firmware.h"
#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <lwip/tcp.h> // TCP_SND_BUF
#include "firmware_update.h"

static WiFiClient s_wifiClient;
static PubSubClient s_mqtt(s_wifiClient);
// Only the parts used here (a full AppConfig copy would also hold the room objects)
struct MqttLayerConfig {
    MqttConfig mqtt;
    HaExposeConfig haExpose;
    ZoneConfig zones[MAX_ZONES];
};
static MqttLayerConfig s_cfg;
static bool s_discoveryPublished = false;
static unsigned long s_lastPublish = 0;
static unsigned long s_lastReconnectAttempt = 0;
static bool s_wasConnected = false; // for logging a connection loss once

static void copyConfig(const AppConfig &cfg) {
    s_cfg.mqtt = cfg.mqtt;
    s_cfg.haExpose = cfg.haExpose;
    memcpy(s_cfg.zones, cfg.zones, sizeof(s_cfg.zones));
    // Take effect with the next CONNECT (mqttHaApplyConfig drops the connection)
    s_mqtt.setKeepAlive(s_cfg.mqtt.keepAliveS);
    s_mqtt.setSocketTimeout(s_cfg.mqtt.socketTimeoutS);
}

static const char *deviceId() {
    static char id[24] = {0};
    if (id[0] == '\0') {
        snprintf(id, sizeof(id), "presencetrack_%06x", ESP.getChipId());
    }
    return id;
}

// Buffer sized for the longest topic actually built: prefix (32) + "/" +
// deviceId (up to 23) + "/" + longest suffix ("zone_<N>_motion", well under 24).
static const size_t TOPIC_BUF_LEN = 32 + 1 + 23 + 1 + 24;

static const char *topic(const char *suffix, char *out, size_t outLen) {
    snprintf(out, outLen, "%s/%s/%s", s_cfg.mqtt.topicPrefix, deviceId(), suffix);
    return out;
}

static const char *availabilityTopic(char *out, size_t outLen) {
    return topic("status", out, outLen);
}

static void publishDeviceDiscovery(const char *objectId, const char *component,
                                    const char *name, const char *deviceClass,
                                    const char *stateTopicSuffix, const char *unit,
                                    const char *icon = nullptr, const char *stateClass = nullptr) {
    JsonDocument doc;
    String uniqueId = String(deviceId()) + "_" + objectId;
    char topicBuf[TOPIC_BUF_LEN];
    char availBuf[TOPIC_BUF_LEN];

    doc["name"] = name;
    doc["unique_id"] = uniqueId;
    doc["state_topic"] = topic(stateTopicSuffix, topicBuf, sizeof(topicBuf));
    doc["availability_topic"] = availabilityTopic(availBuf, sizeof(availBuf));
    doc["payload_available"] = "online";
    doc["payload_not_available"] = "offline";
    if (deviceClass) doc["device_class"] = deviceClass;
    if (unit) doc["unit_of_measurement"] = unit;
    if (icon) doc["icon"] = icon;
    if (stateClass) doc["state_class"] = stateClass;
    if (strcmp(component, "binary_sensor") == 0) {
        doc["payload_on"] = "ON";
        doc["payload_off"] = "OFF";
    }

    JsonObject dev = doc["device"].to<JsonObject>();
    dev["identifiers"][0] = deviceId();
    dev["name"] = s_cfg.mqtt.deviceName;
    dev["manufacturer"] = "PresenceTrack";
    dev["model"] = "ESP8266 LD2450 + BH1750";
    dev["sw_version"] = FIRMWARE_VERSION;

    String configTopic = String("homeassistant/") + component + "/" + deviceId() + "/" + objectId + "/config";

    String payload;
    serializeJson(doc, payload);
    s_mqtt.publish(configTopic.c_str(), payload.c_str(), true);
}

static void clearDiscovery(const char *component, const char *objectId) {
    String configTopic = String("homeassistant/") + component + "/" + deviceId() + "/" + objectId + "/config";
    // An empty retained payload removes the discovery entry from Home Assistant.
    s_mqtt.publish(configTopic.c_str(), "", true);
}

static void clearState(const char *stateTopicSuffix) {
    // An empty retained payload removes the last retained state from the broker.
    char topicBuf[TOPIC_BUF_LEN];
    s_mqtt.publish(topic(stateTopicSuffix, topicBuf, sizeof(topicBuf)), "", true);
}

// Entities of firmware <= 0.1.0 (LD2410C) that no longer exist; clearing
// them keeps stale retained discovery entries from lingering in HA.
static void clearLegacyDiscovery() {
    static const char *const LEGACY[][2] = {
        {"binary_sensor", "moving_target"},
        {"binary_sensor", "static_target"},
        {"sensor", "moving_distance"},
        {"sensor", "static_distance"},
    };
    for (const auto &e : LEGACY) {
        clearDiscovery(e[0], e[1]);
    }
}

static void publishDiscovery() {
    const HaExposeConfig &ha = s_cfg.haExpose;
    // Entities turned off in the web UI clear their retained discovery config
    // and state. Done here rather than in publishStates() so it only happens
    // once per (re)connect / config change, not on every publish tick.
    if (ha.presence) {
        publishDeviceDiscovery("presence", "binary_sensor", "Presence", "occupancy", "presence", nullptr);
    } else {
        clearDiscovery("binary_sensor", "presence");
        clearState("presence");
    }
    if (ha.motion) {
        publishDeviceDiscovery("motion", "binary_sensor", "Motion", "motion", "motion", nullptr);
    } else {
        clearDiscovery("binary_sensor", "motion");
        clearState("motion");
    }
    if (ha.targetCount) {
        publishDeviceDiscovery("target_count", "sensor", "Target Count", nullptr, "target_count", nullptr,
                               "mdi:motion-sensor", "measurement");
    } else {
        clearDiscovery("sensor", "target_count");
        clearState("target_count");
    }
    if (ha.illuminance) {
        publishDeviceDiscovery("illuminance", "sensor", "Illuminance", "illuminance", "illuminance", "lx");
    } else {
        clearDiscovery("sensor", "illuminance");
        clearState("illuminance");
    }
    clearLegacyDiscovery();

    for (uint8_t i = 0; i < MAX_ZONES; i++) {
        const ZoneConfig &z = s_cfg.zones[i];
        // Object id doubles as the state topic suffix
        char objId[24];
        snprintf(objId, sizeof(objId), "zone_%u", i);
        char motionObjId[24];
        snprintf(motionObjId, sizeof(motionObjId), "zone_%u_motion", i);

        // Deleted (present=false) and disabled slots clear their retained discovery config and state
        bool active = z.present && z.enabled;
        if (active) {
            publishDeviceDiscovery(objId, "binary_sensor", z.name, "occupancy", objId, nullptr);
        } else {
            clearDiscovery("binary_sensor", objId);
            clearState(objId);
        }
        if (active && ha.zoneMotion) {
            char name[sizeof(z.name) + 8];
            snprintf(name, sizeof(name), "%s Motion", z.name);
            publishDeviceDiscovery(motionObjId, "binary_sensor", name, "motion", motionObjId, nullptr);
        } else {
            clearDiscovery("binary_sensor", motionObjId);
            clearState(motionObjId);
        }
    }

    s_discoveryPublished = true;
}

// Zustandswerte in der Reihenfolge, in der publishStates() sie schickt: presence, motion,
// target_count, illuminance, dann je Zone zone_<i> und zone_<i>_motion.
static const uint8_t STATE_ITEM_COUNT = 4 + 2 * MAX_ZONES;
static const unsigned long PUBLISH_INTERVAL_MS = 2000;

// Schickt Zustandswert idx; false, wenn er nicht gemeldet wird (Entität aus, Zone leer
// oder aus, BH1750 ohne gültigen Wert).
static bool publishStateItem(uint8_t idx) {
    const Ld2450State &ld = g_sensorState.ld2450;
    const Bh1750State &bh = g_sensorState.bh1750;
    const HaExposeConfig &ha = s_cfg.haExpose;

    char topicBuf[TOPIC_BUF_LEN];
    char valueBuf[16];

    switch (idx) {
        case 0:
            if (!ha.presence) return false;
            s_mqtt.publish(topic("presence", topicBuf, sizeof(topicBuf)), ld.presence ? "ON" : "OFF", true);
            return true;
        case 1:
            if (!ha.motion) return false;
            s_mqtt.publish(topic("motion", topicBuf, sizeof(topicBuf)), ld.motion ? "ON" : "OFF", true);
            return true;
        case 2:
            if (!ha.targetCount) return false;
            snprintf(valueBuf, sizeof(valueBuf), "%d", ld.targetCount);
            s_mqtt.publish(topic("target_count", topicBuf, sizeof(topicBuf)), valueBuf, true);
            return true;
        case 3:
            if (!ha.illuminance || !bh.valid) return false;
            snprintf(valueBuf, sizeof(valueBuf), "%.1f", bh.lux);
            s_mqtt.publish(topic("illuminance", topicBuf, sizeof(topicBuf)), valueBuf, true);
            return true;
    }

    const uint8_t i = (idx - 4) / 2;
    if (i >= MAX_ZONES || !s_cfg.zones[i].present || !s_cfg.zones[i].enabled) return false;
    char suffix[24];
    if ((idx - 4) % 2 == 0) {
        snprintf(suffix, sizeof(suffix), "zone_%u", i);
        s_mqtt.publish(topic(suffix, topicBuf, sizeof(topicBuf)), ld.zonePresence[i] ? "ON" : "OFF", true);
        return true;
    }
    if (!ha.zoneMotion) return false;
    snprintf(suffix, sizeof(suffix), "zone_%u_motion", i);
    s_mqtt.publish(topic(suffix, topicBuf, sizeof(topicBuf)), ld.zoneMoving[i] ? "ON" : "OFF", true);
    return true;
}

static void publishStates() {
    for (uint8_t i = 0; i < STATE_ITEM_COUNT; i++) publishStateItem(i);
}

// ---------------------------------------------------------------------------
// Während eines Updates von GitHub (firmwareUpdateBusy())
//
// Die TLS-Verbindung des Updates braucht fast den ganzen Heap (firmware_update.cpp,
// Kopfkommentar Speicher). Die Verbindung zum Broker bleibt, und die Zustände gehen
// weiter hinaus, nur sparsamer:
//   - PubSubClient-Puffer 256 statt 1024 B (+768 B frei). Reicht für jedes Zustands-PUBLISH
//     und für ein CONNECT (Reconnect), nicht für Discovery - die wartet bis nach dem Lauf,
//     Home Assistant hat sie retained vom Broker.
//   - Gepaced: derselbe Durchgang wie publishStates() alle 2 s, aber ein Wert pro loop()
//     und nur, wenn der vorige bestätigt ist (tcp_sndbuf == TCP_SND_BUF). So ist höchstens
//     ein PUBLISH unbestätigt statt bis zu 16 (bis TCP_SND_BUF = 1072 B).
//   - TCP_NODELAY: lwIP legt jedes Segment genau passend an statt MSS-groß (TCP_OVERSIZE,
//     lwipopts.h:1432) - auch das PINGREQ, das PubSubClient::loop() selbst schickt.
// Die Anwesenheitsmeldungen kostet das nur die Pacing-Latenz: 16 Werte brauchen 16 ACKs,
// im LAN Millisekunden; während eines TLS-Handshakes (bis 15 s) ruht loop() ohnehin.
// ---------------------------------------------------------------------------

static const uint16_t MQTT_BUFFER_LEN = 1024;
static const uint16_t MQTT_RUN_BUFFER_LEN = 256;
// Geräte-Id "presencetrack_" + 6 Hex-Ziffern (deviceId(), ESP.getChipId() hat 24 Bit)
static const size_t DEVICE_ID_LEN = 14 + 6;
static const size_t TOPIC_MAX_LEN = (sizeof(MqttConfig::topicPrefix) - 1) + 1 + DEVICE_ID_LEN + 1 + strlen("zone_5_motion");
static_assert(MAX_ZONES <= 10, "längster Zustands-Suffix ist zone_<eine Ziffer>_motion");
static_assert(1 + 1 + 2 + TOPIC_MAX_LEN + 15 <= MQTT_STATE_PACKET_MAX && MQTT_STATE_PACKET_MAX < 128,
              "MQTT_STATE_PACKET_MAX (mqtt_ha.h) nachführen");
// PubSubClient::publish() braucht MQTT_MAX_HEADER_SIZE (5) + 2 + Topic + Wert im Puffer;
// connect() 5 + 10 (Protokoll, Flags, Keepalive) + Client-Id, Will-Topic ("status"),
// Will-Nachricht ("offline"), User und Passwort mit je 2 B Länge (PubSubClient.cpp:220-251).
static_assert(5 + 2 + TOPIC_MAX_LEN + 15 <= MQTT_RUN_BUFFER_LEN &&
                  5 + 10 + (2 + DEVICE_ID_LEN) +
                          (2 + (sizeof(MqttConfig::topicPrefix) - 1) + 1 + DEVICE_ID_LEN + 1 + strlen("status")) +
                          (2 + strlen("offline")) + (2 + sizeof(MqttConfig::user) - 1) +
                          (2 + sizeof(MqttConfig::pass) - 1) <=
                      MQTT_RUN_BUFFER_LEN,
              "MQTT_RUN_BUFFER_LEN fasst ein Zustands-PUBLISH bzw. CONNECT nicht");

static bool s_runMode = false;
static uint8_t s_runItem = STATE_ITEM_COUNT; // nächster Wert des Durchgangs, COUNT = keiner offen

static void syncRunMode() {
    const bool busy = firmwareUpdateBusy();
    if (busy == s_runMode) return;
    if (busy) {
        // Verkleinern: umm_realloc() teilt den Block an Ort und Stelle
        s_mqtt.setBufferSize(MQTT_RUN_BUFFER_LEN);
        s_runItem = STATE_ITEM_COUNT;
        s_runMode = true;
        return;
    }
    // Vergrößern kann an einem zerstückelten Heap scheitern; PubSubClient behält dann den
    // kleinen Puffer (PubSubClient.cpp:740-755), der Lauf-Modus gilt weiter bis zum nächsten Versuch
    if (!s_mqtt.setBufferSize(MQTT_BUFFER_LEN)) return;
    s_wifiClient.setNoDelay(false);
    s_runMode = false;
}

static void publishStatesPaced() {
    if (s_runItem >= STATE_ITEM_COUNT) {
        const unsigned long now = millis();
        if (now - s_lastPublish <= PUBLISH_INTERVAL_MS) return;
        s_lastPublish = now;
        s_runItem = 0;
    }
    // Voriges PUBLISH (oder das PINGREQ) noch unbestätigt: nächster loop()
    if (s_wifiClient.availableForWrite() != TCP_SND_BUF) return;
    while (s_runItem < STATE_ITEM_COUNT && !publishStateItem(s_runItem++)) {
    }
}
static bool reconnect() {
    if (!s_cfg.mqtt.enabled || strlen(s_cfg.mqtt.host) == 0) {
        return false;
    }

    s_mqtt.setServer(s_cfg.mqtt.host, s_cfg.mqtt.port);

    char availBuf[TOPIC_BUF_LEN];
    bool ok;
    if (strlen(s_cfg.mqtt.user) > 0) {
        ok = s_mqtt.connect(deviceId(), s_cfg.mqtt.user, s_cfg.mqtt.pass,
                             availabilityTopic(availBuf, sizeof(availBuf)), 0, true, "offline");
    } else {
        ok = s_mqtt.connect(deviceId(), availabilityTopic(availBuf, sizeof(availBuf)), 0, true, "offline");
    }

    if (ok) {
        s_mqtt.publish(availabilityTopic(availBuf, sizeof(availBuf)), "online", true);
        s_discoveryPublished = false; // re-send discovery after (re)connect
        s_wasConnected = true;
        eventLogPush(EventType::MqttConnected, "Connected to %s:%u", s_cfg.mqtt.host, s_cfg.mqtt.port);
    }
    return ok;
}

void mqttHaBegin(const AppConfig &cfg) {
    copyConfig(cfg);
    s_mqtt.setBufferSize(MQTT_BUFFER_LEN);
}

void mqttHaApplyConfig(const AppConfig &cfg) {
    copyConfig(cfg);
    s_discoveryPublished = false;
    if (s_mqtt.connected()) {
        s_mqtt.disconnect();
        s_wasConnected = false; // deliberate disconnect, not a connection loss
        eventLogPush(EventType::MqttDisconnected, "Disconnected (config changed)");
    }
}

void mqttHaLoop() {
    // Vor dem enabled-Check: der Puffer ist auch ohne Broker belegt (mqttHaBegin)
    syncRunMode();
    if (!s_cfg.mqtt.enabled || strlen(s_cfg.mqtt.host) == 0) {
        return;
    }

    if (!s_mqtt.connected()) {
        if (s_wasConnected) {
            s_wasConnected = false;
            eventLogPush(EventType::MqttDisconnected, "Connection lost (state %d)", s_mqtt.state());
        }
        unsigned long now = millis();
        if (now - s_lastReconnectAttempt > 5000) {
            s_lastReconnectAttempt = now;
            reconnect();
        }
        return;
    }

    // Nach einem Reconnect ist es ein neuer ClientContext (Default: Nagle an); vor loop(),
    // damit auch dessen PINGREQ genau passend angelegt wird
    if (s_runMode) s_wifiClient.setNoDelay(true);
    s_mqtt.loop();

    if (s_runMode) {
        publishStatesPaced();
        return;
    }

    if (!s_discoveryPublished) {
        publishDiscovery();
    }

    unsigned long now = millis();
    if (now - s_lastPublish > PUBLISH_INTERVAL_MS) {
        s_lastPublish = now;
        publishStates();
    }
}

bool mqttHaIsConnected() {
    return s_mqtt.connected();
}
