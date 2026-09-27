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

// Neueste Id (0 solange leer) und älteste noch gepufferte Id (1 solange leer).
// Die Ids sind lückenlos, ein Client mit ?since=<id> braucht also genau die Ids
// (max(since, älteste - 1), neueste].
uint32_t eventLogNewestId();
uint32_t eventLogOldestId();

// Serialisiert das Event `id` als JSON-Objekt nach buf. Liefert die Länge, oder
// 0, wenn die Id nicht (mehr) gepuffert ist oder nicht in `size` passt.
//
// Bewusst ein Event nach dem anderen statt eines JsonDocument für die ganze
// Liste: bei vollem Puffer sind das 5-9 kB JSON plus ein etwa gleich großes
// JsonDocument, was allein schon den freien Heap sprengt - /api/events?since=0
// hat das Gerät so zum Absturz gebracht. web_server.cpp streamt die Events
// deshalb einzeln.
size_t eventLogEventToJson(uint32_t id, char *buf, size_t size);
