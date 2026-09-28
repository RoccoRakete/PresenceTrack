#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

// In-RAM ring buffer of the most recent device events for the status page.
// Not persisted: the buffer starts empty (ids restart at 1) after each boot.
enum class EventType : uint8_t {
    PresenceChanged,
    ZoneEnter,
    ZoneExit,
    MqttConnected,
    MqttDisconnected,
    ConfigChanged,
    Reboot,
    FactoryReset,
    OtaUpdate, // firmware or filesystem image received via /api/firmware, /api/filesystem
    Network,   // boot-time network setup, e.g. the static IP fallback to DHCP (main.cpp)
    Sensor,    // boot-time sensor configuration, e.g. the LD2450 region filter (sensor_data.cpp)
};

struct LogEvent {
    uint32_t id;            // monotonically increasing, starts at 1
    unsigned long uptimeMs; // millis() when the event was pushed
    EventType type;
    char message[48];
};

static const uint8_t EVENT_LOG_SIZE = 64;

// printf-style; overwrites the oldest entry once the buffer is full.
void eventLogPush(EventType type, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

// Newest id (0 while empty) and oldest id still buffered (1 while empty).
// The ids have no gaps, so a client with ?since=<id> needs exactly the ids
// (max(since, oldest - 1), newest].
uint32_t eventLogNewestId();
uint32_t eventLogOldestId();

// Serializes event `id` as a JSON object into buf. Returns the length, or
// 0 if the id is not (or no longer) buffered or does not fit into `size`.
//
// Deliberately one event at a time instead of a JsonDocument for the whole
// list: with a full buffer that is 5-9 kB of JSON plus a JsonDocument of about
// the same size, which alone exceeds the free heap - /api/events?since=0
// crashed the device that way. web_server.cpp therefore streams the events
// one by one.
size_t eventLogEventToJson(uint32_t id, char *buf, size_t size);
