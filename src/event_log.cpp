#include "event_log.h"
#include <stdarg.h>

static LogEvent s_events[EVENT_LOG_SIZE];
static uint8_t s_head = 0;  // next slot to write
static uint8_t s_count = 0; // valid entries (<= EVENT_LOG_SIZE)
static uint32_t s_nextId = 1;

// Indexed by EventType
static const char *const EVENT_TYPE_NAMES[] = {
    "presence_changed", "zone_enter", "zone_exit", "mqtt_connected",
    "mqtt_disconnected", "config_changed", "reboot", "factory_reset", "ota_update",
};

static const char *eventTypeToString(EventType type) {
    uint8_t i = static_cast<uint8_t>(type);
    return i < sizeof(EVENT_TYPE_NAMES) / sizeof(EVENT_TYPE_NAMES[0]) ? EVENT_TYPE_NAMES[i] : "unknown";
}

void eventLogPush(EventType type, const char *fmt, ...) {
    LogEvent &e = s_events[s_head];
    e.id = s_nextId++;
    e.uptimeMs = millis();
    e.type = type;

    va_list args;
    va_start(args, fmt);
    vsnprintf(e.message, sizeof(e.message), fmt, args);
    va_end(args);

    s_head = (s_head + 1) % EVENT_LOG_SIZE;
    if (s_count < EVENT_LOG_SIZE) s_count++;
}

uint32_t eventLogNewestId() {
    return s_nextId - 1;
}

uint32_t eventLogOldestId() {
    return s_nextId - s_count;
}

size_t eventLogEventToJson(uint32_t id, char *buf, size_t size) {
    if (id < eventLogOldestId() || id > eventLogNewestId()) return 0;
    // Id 1 liegt in Slot 0 und jede Id belegt den nächsten Slot
    const LogEvent &e = s_events[(id - 1) % EVENT_LOG_SIZE];
    // Nur ein kleines Dokument pro Event: Schlüssel und Typ sind Literale (werden
    // nicht kopiert), nur die Meldung wird kopiert - gut 100 Byte Heap.
    JsonDocument doc;
    doc["id"] = e.id;
    doc["uptime_ms"] = e.uptimeMs;
    doc["type"] = eventTypeToString(e.type);
    doc["message"] = e.message;
    if (measureJson(doc) >= size) return 0;
    return serializeJson(doc, buf, size);
}
