#include "web_server.h"
#include "sensor_data.h"
#include "mqtt_ha.h"
#include "event_log.h"
#include "wifi_power.h"
#include "firmware.h"
#include "ota_image.h"

#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <Updater.h>
#include <flash_hal.h>
#include <umm_malloc/umm_malloc.h>
#include <functional>

static const size_t MAX_BODY_LEN = 2048;
// 12 objects with 23-byte names (worst case JSON-escaped) exceed MAX_BODY_LEN
static const size_t MAX_OBJECTS_BODY_LEN = 4096;
static const unsigned long REBOOT_DELAY_MS = 300;

static const uint16_t HTTP_PORT = 80;

// Upper bound of concurrent HTTP connections. lwIP silently drops further
// SYNs and the client retries them after ~1 s (TCP retransmit) - excess
// connections therefore wait instead of failing. Without a limit the heap
// does not suffice for arbitrarily many parallel requests (each connection
// costs a pcb, AsyncClient, request object, request headers and send buffer),
// and the first failed `new` inside a library is a reboot. Chrome opens up to
// 6 connections, but the UI loads sequentially, so 4 is enough for a page load
// without waiting. An OTA upload occupies one slot while it runs (the UI
// pauses its polling meanwhile).
static const uint8_t MAX_HTTP_CONNECTIONS = 4;

static tcp_pcb_listen *s_httpListener = nullptr;

// Sets the listen backlog so that lwIP only accepts as many handshakes as
// there are free slots (lwIP itself counts handshakes in SYN_RCVD against the
// backlog; at 0 all SYNs are dropped).
//
// Only connections that still have an AsyncClient are counted (tcp_arg set;
// ESPAsyncTCP clears it on close). The pcbs themselves live on after closing,
// in FIN_WAIT_2 for up to 20 s if the peer never sends its FIN - e.g. Chrome's
// unused preconnects, which the server closes after 3 s of idle time.
// Measured: four such connections blocked the server for 20 s with lwIP's own
// counting (tcp_backlog_delayed), even though they hardly use any heap anymore.
static void updateConnectionLimit() {
    if (!s_httpListener) return;
    uint8_t open = 0;
    for (tcp_pcb *pcb = tcp_active_pcbs; pcb; pcb = pcb->next) {
        if (pcb->local_port == HTTP_PORT && pcb->state != SYN_RCVD && pcb->callback_arg) open++;
    }
    s_httpListener->backlog = open >= MAX_HTTP_CONNECTIONS ? 0 : MAX_HTTP_CONNECTIONS - open;
}

// AsyncWebServer that updates the limit on every new connection; on close
// webServerLoop() does that.
class LimitedWebServer : public AsyncWebServer {
  public:
    explicit LimitedWebServer(uint16_t port) : AsyncWebServer(port) {
        // Replaces AsyncWebServer's onClient handler: same body, plus the
        // limit and nothrow (a plain `new` would panic on OOM)
        _server.onClient([](void *s, AsyncClient *c) {
            if (c == NULL) return;
            updateConnectionLimit();
            c->setRxTimeout(3);
            AsyncWebServerRequest *r = new (std::nothrow) AsyncWebServerRequest((AsyncWebServer *)s, c);
            if (r == NULL) {
                c->close(true);
                c->free();
                delete c;
            }
        }, this);
    }
};

static LimitedWebServer server(HTTP_PORT);
static AppConfig *s_cfg = nullptr;

static bool s_rebootPending = false;
static unsigned long s_rebootRequestedAt = 0;
static bool s_wifiResetPending = false; // erase the Wi-Fi credentials right before the restart

using JsonPostHandler = std::function<void(JsonDocument &, JsonDocument &, AsyncWebServerRequest *)>;

// ---------------------------------------------------------------------------
// Response helpers
//
// Why custom response classes instead of request->send(code, type, String): the
// free heap has to suffice for all simultaneously open connections, and a
// shortage does not end in an error but in a reboot - the libraries allocate
// with `new`, and that panics on the ESP8266 on OOM ("Unhandled C++ exception:
// OOM", in lwIP context, so it cannot be caught).
// AsyncBasicResponse holds the body three times per request (copy in the
// response object, copy with the header prepended, copy in the lwIP send
// buffer) plus a list of header objects; beginResponseStream() additionally
// costs a 1460-byte cbuf. The classes here write header and body directly into
// the TCP send buffer (lwIP copies anyway) and only keep what did not fit yet.
// ---------------------------------------------------------------------------

// Sends the status line/headers and then the body in pieces returned by
// nextPiece(). If the send buffer is full or lwIP gets no pbufs right now, it
// continues on the next ACK or poll (every 500 ms).
class PiecewiseResponse : public AsyncWebServerResponse {
  public:
    explicit PiecewiseResponse(int code) { _code = code; }
    bool _sourceValid() const override { return true; }

    void _respond(AsyncWebServerRequest *request) override {
        _pieceLen = snprintf(_head, sizeof(_head),
                             "HTTP/1.%d %d %s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
                             "Connection: close\r\n\r\n",
                             request->version(), _code, _responseCodeToString(_code), (unsigned)bodyLength());
        _piece = _head;
        _state = RESPONSE_CONTENT;
        pump(request);
    }

    size_t _ack(AsyncWebServerRequest *request, size_t len, uint32_t time) override {
        (void)time;
        _ackedLength += len;
        if (_state == RESPONSE_CONTENT) pump(request);
        if (_state == RESPONSE_WAIT_ACK && _ackedLength >= _writtenLength) _state = RESPONSE_END;
        return 0;
    }

  protected:
    // Content-Length; queried once before the first nextPiece().
    virtual size_t bodyLength() const = 0;
    // Next piece of the body, false at the end. The pointer must stay valid
    // until nextPiece() is called the next time.
    virtual bool nextPiece(const char *&data, size_t &len) = 0;

    // Set by nextPiece() when the body can no longer be completed as announced
    // by Content-Length: the connection is then closed instead of letting the
    // client wait for bytes that never arrive.
    bool _truncated = false;

  private:
    void pump(AsyncWebServerRequest *request) {
        AsyncClient *client = request->client();
        while (_state == RESPONSE_CONTENT) {
            if (_pieceLen == 0) {
                if (!nextPiece(_piece, _pieceLen)) {
                    _state = RESPONSE_WAIT_ACK;
                    // close(false) only takes effect on the next poll: closing right away
                    // would delete the request along with this response mid-call
                    if (_truncated) client->close(false);
                    break;
                }
                continue;
            }
            size_t n = client->add(_piece, _pieceLen);
            if (n == 0) break; // send buffer full or no memory for pbufs
            _piece += n;
            _pieceLen -= n;
            _writtenLength += n;
        }
        client->send();
    }

    char _head[112];
    const char *_piece = nullptr;
    size_t _pieceLen = 0;
};

// Fully serialized JSON. The string is released as soon as lwIP has taken
// everything - for most responses already in _respond().
class JsonBufferResponse : public PiecewiseResponse {
  public:
    JsonBufferResponse(int code, String &&body) : PiecewiseResponse(code), _body(std::move(body)) {}

  protected:
    size_t bodyLength() const override { return _body.length(); }

    bool nextPiece(const char *&data, size_t &len) override {
        if (_handedOut) {
            _body = String();
            return false;
        }
        _handedOut = true;
        data = _body.c_str();
        len = _body.length();
        return true;
    }

  private:
    String _body;
    bool _handedOut = false;
};

// /api/events: {"uptime_ms":..,"last_id":..,"events":[...]} with the events
// (since, newest], rendered one after another directly from the ring buffer
// (see eventLogEventToJson). The Content-Length comes from a dry run. If an
// event not yet sent is overwritten during the transfer (only conceivable with
// a full buffer and more new events than already sent ones), the response is
// aborted; the UI keeps its list and asks again on the next poll.
class EventsResponse : public PiecewiseResponse {
  public:
    explicit EventsResponse(uint32_t sinceId) : PiecewiseResponse(200) {
        _last = eventLogNewestId();
        _first = sinceId >= _last ? _last + 1 : std::max(sinceId + 1, eventLogOldestId());
        _next = _first;
        _length = 2; // "]}"
        for (uint32_t id = _first; id <= _last; id++) {
            _length += eventLogEventToJson(id, _line, sizeof(_line)) + (id > _first ? 1 : 0);
        }
        _prefixLen = snprintf(_line, sizeof(_line), "{\"uptime_ms\":%lu,\"last_id\":%u,\"events\":[",
                              millis(), (unsigned)_last);
        _length += _prefixLen;
    }

  protected:
    size_t bodyLength() const override { return _length; }

    bool nextPiece(const char *&data, size_t &len) override {
        data = _line;
        if (_prefixLen) {
            len = _prefixLen;
            _prefixLen = 0;
            return true;
        }
        if (_next <= _last) {
            size_t comma = _next > _first ? 1 : 0;
            _line[0] = ',';
            len = eventLogEventToJson(_next, _line + comma, sizeof(_line) - comma);
            if (len == 0) {
                _truncated = true;
                return false;
            }
            len += comma;
            _next++;
            return true;
        }
        if (_next == _last + 1) {
            _next++;
            data = "]}";
            len = 2;
            return true;
        }
        return false;
    }

  private:
    // Largest event: ~90 bytes of framing + 47 message characters, in the worst
    // case each escaped as \u00XX (6 bytes)
    char _line[384];
    uint32_t _first;
    uint32_t _next;
    uint32_t _last;
    size_t _prefixLen;
    size_t _length;
};

// response == nullptr means: not even the response object fit into the heap
// anymore. Then close without a response (the client sees a dropped
// connection) instead of panicking with a plain `new`.
static void sendResponse(AsyncWebServerRequest *request, AsyncWebServerResponse *response) {
    if (response) {
        request->send(response);
    } else {
        request->client()->close(false);
    }
}

// Heap that has to stay free after allocating a body: the remaining up to
// MAX_HTTP_CONNECTIONS - 1 connections still allocate request headers,
// response objects and send buffers (measured ~2 kB per connection). Only large
// responses like /api/config/backup (2.7 kB) hit this under parallel load.
static const uint32_t RESPONSE_HEAP_RESERVE = 6144;

static void sendJsonDoc(AsyncWebServerRequest *request, int code, const JsonDocument &doc);
static void sendJsonError(AsyncWebServerRequest *request, int code, const String &message);

static void sendJsonDoc(AsyncWebServerRequest *request, int code, const JsonDocument &doc) {
    size_t len = measureJson(doc);
    String body;
    // overflowed(): the document is missing values because the heap was already
    // tight while filling it - better a 503 than e.g. an incomplete config backup.
    // reserve() exactly: growing step by step, the string would briefly need the
    // old and the new buffer at the same time.
    if (doc.overflowed() || ESP.getFreeHeap() < len + RESPONSE_HEAP_RESERVE || !body.reserve(len)) {
        sendResponse(request, new (std::nothrow) JsonBufferResponse(503, String(F("{\"error\":\"device busy, retry\"}"))));
        return;
    }
    serializeJson(doc, body);
    sendResponse(request, new (std::nothrow) JsonBufferResponse(code, std::move(body)));
}

static void sendJsonError(AsyncWebServerRequest *request, int code, const String &message) {
    JsonDocument doc;
    doc["error"] = message;
    sendJsonDoc(request, code, doc);
}

// Generic JSON POST handler (instead of AsyncCallbackJsonWebHandler, which does
// not work reliably with ArduinoJson v7 in the esphome fork).
// Convention for `handler`: on success fill `resp` (the helper sends 200),
// on errors call `request->send(...)` itself and leave `resp` empty.
static void registerJsonPost(AsyncWebServer &srv, const char *path, size_t maxLen, JsonPostHandler handler) {
    srv.on(path, HTTP_POST,
        [maxLen](AsyncWebServerRequest *request) {
            // Called after the complete body. Regular responses are already sent
            // in onBody - only the cases without body processing are handled here.
            if (request->contentLength() > maxLen) {
                sendJsonError(request, 413, "payload too large");
            } else if (request->contentLength() == 0) {
                sendJsonError(request, 400, "empty body");
            }
        },
        nullptr,
        [maxLen, handler](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
            if (total == 0 || total > maxLen) {
                return; // 413 is sent in onRequest, do not accumulate anything
            }
            if (index == 0) {
                // _tempObject is released via free() by the request destructor
                request->_tempObject = malloc(total);
            }
            char *buf = static_cast<char *>(request->_tempObject);
            if (buf && index + len <= total) {
                memcpy(buf + index, data, len);
            }
            if (index + len != total) {
                return;
            }
            if (!buf) {
                sendJsonError(request, 500, "out of memory");
                return;
            }

            JsonDocument body;
            DeserializationError err = deserializeJson(body, buf, total);
            if (err) {
                sendJsonError(request, 400, String("invalid json: ") + err.c_str());
                return;
            }

            JsonDocument resp;
            handler(body, resp, request);
            if (!resp.isNull()) {
                sendJsonDoc(request, 200, resp);
            }
        });
}

// ---------------------------------------------------------------------------
// Validation helpers: missing fields are allowed (partial update),
// present fields must match type and value range.
// ---------------------------------------------------------------------------

static bool validateInt(JsonObjectConst obj, const char *key, long minVal, long maxVal, String &err) {
    JsonVariantConst v = obj[key];
    if (v.isNull()) return true;
    if (!v.is<long>() || v.as<long>() < minVal || v.as<long>() > maxVal) {
        err = String(key) + " must be an integer between " + minVal + " and " + maxVal;
        return false;
    }
    return true;
}

static bool validateBool(JsonObjectConst obj, const char *key, String &err) {
    JsonVariantConst v = obj[key];
    if (v.isNull() || v.is<bool>()) return true;
    err = String(key) + " must be a boolean";
    return false;
}

// No silent truncation via strlcpy: strings that are too long are rejected.
static bool validateString(JsonObjectConst obj, const char *key, size_t minLen, size_t maxLen, String &err) {
    JsonVariantConst v = obj[key];
    if (v.isNull()) return true;
    if (!v.is<const char *>()) {
        err = String(key) + " must be a string";
        return false;
    }
    size_t n = strlen(v.as<const char *>());
    if (n < minLen || n > maxLen) {
        err = String(key) + " length must be between " + minLen + " and " + maxLen;
        return false;
    }
    return true;
}

// DHCP/DNS host label: 1-31 of [A-Za-z0-9-], no leading or trailing '-'.
static bool validateHostname(JsonObjectConst obj, const char *key, String &err) {
    JsonVariantConst v = obj[key];
    if (v.isNull()) return true;
    const char *s = v.is<const char *>() ? v.as<const char *>() : nullptr;
    size_t n = s ? strlen(s) : 0;
    bool ok = n >= 1 && n <= 31 && s[0] != '-' && s[n - 1] != '-';
    for (size_t i = 0; ok && i < n; i++) {
        ok = isalnum((unsigned char)s[i]) || s[i] == '-';
    }
    if (!ok) {
        err = String(key) + " must be 1-31 characters of A-Z, a-z, 0-9 and '-', not starting or ending with '-'";
    }
    return ok;
}

// Dotted IPv4 address; "" is allowed (field unused with DHCP / optional DNS).
static bool validateIp(JsonObjectConst obj, const char *key, String &err) {
    JsonVariantConst v = obj[key];
    if (v.isNull()) return true;
    IPAddress ip;
    if (!v.is<const char *>() || strlen(v.as<const char *>()) > 15 ||
        (*v.as<const char *>() && !ip.fromString(v.as<const char *>()))) {
        err = String(key) + " must be an IPv4 address like 192.168.1.50 or empty";
        return false;
    }
    return true;
}

static bool requireObject(JsonDocument &body, AsyncWebServerRequest *request) {
    if (body.is<JsonObjectConst>()) return true;
    sendJsonError(request, 400, "body must be a JSON object");
    return false;
}

// GPIOs broken out on the D1 Mini, with their board labels.
struct BoardPin {
    uint8_t gpio;
    const char *label;
};
static const BoardPin BOARD_PINS[] = {
    {16, "D0"}, {5, "D1"}, {4, "D2"}, {0, "D3"}, {2, "D4"}, {14, "D5"},
    {12, "D6"}, {13, "D7"}, {15, "D8"}, {3, "RX"}, {1, "TX"},
};

static const char *boardPinLabel(uint8_t gpio) {
    for (const BoardPin &p : BOARD_PINS) {
        if (p.gpio == gpio) return p.label;
    }
    return nullptr;
}

static bool validatePin(JsonObjectConst obj, const char *key, String &err) {
    JsonVariantConst v = obj[key];
    if (v.isNull()) return true;
    if (!v.is<long>() || v.as<long>() < 0 || v.as<long>() > 255 || !boardPinLabel(v.as<uint8_t>())) {
        err = String(key) + " must be one of the D1 Mini GPIOs 0, 1, 2, 3, 4, 5, 12, 13, 14, 15, 16";
        return false;
    }
    return true;
}

// All sensor pins must be distinct; checked on the merged values of both sections.
static bool checkPinConflicts(const Ld2450Config &ld, const Bh1750Config &bh, String &err) {
    const struct {
        const char *name;
        uint8_t gpio;
    } pins[] = {
        {"ld2450.rx_pin", ld.rxPin}, {"ld2450.tx_pin", ld.txPin},
        {"bh1750.sda_pin", bh.sdaPin}, {"bh1750.scl_pin", bh.sclPin},
    };
    const size_t n = sizeof(pins) / sizeof(pins[0]);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (pins[i].gpio == pins[j].gpio) {
                err = String(pins[i].name) + " and " + pins[j].name + " must not both use GPIO" + pins[i].gpio;
                return false;
            }
        }
    }
    return true;
}

// Boot-sensitive or special-purpose GPIOs are allowed, but reported as a hint.
static void addPinWarning(JsonArray warnings, const char *field, uint8_t gpio) {
    const char *hint;
    switch (gpio) {
        case 0: hint = "must be HIGH at boot (LOW enters flash mode) – avoid external pull-downs"; break;
        case 2: hint = "must be HIGH at boot and drives the on-board LED – avoid external pull-downs"; break;
        case 15: hint = "must be LOW at boot – avoid external pull-ups"; break;
        case 1:
        case 3: hint = "is shared with the USB serial console (debug output, flashing)"; break;
        case 16: hint = "has no interrupt / open-drain support – unsuitable for UART RX or I²C"; break;
        default: return;
    }
    JsonObject w = warnings.add<JsonObject>();
    w["field"] = field;
    w["message"] = String("GPIO") + gpio + " (" + boardPinLabel(gpio) + ") " + hint;
}

// Pins as the firmware booted with them: sensorsBegin() only reads the pins
// once, so any difference means the change takes effect after a restart.
static uint8_t s_bootPins[4] = {0}; // ld2450 rx, tx, bh1750 sda, scl

struct PinField {
    const char *key;
    uint8_t gpio;
    uint8_t bootGpio;
};

// Adds pin_warnings (per field) and restart_required to a section response.
static void addPinStatus(JsonDocument &doc, const PinField *fields, size_t n) {
    JsonArray warnings = doc["pin_warnings"].to<JsonArray>();
    bool restart = false;
    for (size_t i = 0; i < n; i++) {
        addPinWarning(warnings, fields[i].key, fields[i].gpio);
        restart = restart || fields[i].gpio != fields[i].bootGpio;
    }
    doc["restart_required"] = restart;
}

// ---------------------------------------------------------------------------
// Serialization of the individual config sections (field names identical to
// AppConfig::toJson/fromJson)
// ---------------------------------------------------------------------------

static void ld2450ToJson(const Ld2450Config &c, JsonDocument &doc) {
    doc["enabled"] = c.enabled;
    doc["multi_target"] = c.multiTarget;
    doc["max_range_mm"] = c.maxRangeMm;
    doc["occupancy_timeout_s"] = c.occupancyTimeoutS;
    doc["sim_enabled"] = c.simEnabled;
    doc["moving_threshold_cm_s"] = c.movingThresholdCmS;
    doc["ghost_filter_enabled"] = c.ghostFilterEnabled;
    doc["ghost_min_exist_ms"] = c.ghostMinExistMs;
    doc["ghost_max_jump_cm_s"] = c.ghostMaxJumpCmS;
    doc["rx_pin"] = c.rxPin;
    doc["tx_pin"] = c.txPin;
    const PinField pins[] = {{"rx_pin", c.rxPin, s_bootPins[0]}, {"tx_pin", c.txPin, s_bootPins[1]}};
    addPinStatus(doc, pins, 2);
}

static void bh1750ToJson(const Bh1750Config &c, JsonDocument &doc) {
    doc["enabled"] = c.enabled;
    doc["i2c_address"] = c.i2cAddress;
    doc["mode"] = c.mode;
    doc["interval_ms"] = c.intervalMs;
    doc["sim_enabled"] = c.simEnabled;
    doc["sda_pin"] = c.sdaPin;
    doc["scl_pin"] = c.sclPin;
    const PinField pins[] = {{"sda_pin", c.sdaPin, s_bootPins[2]}, {"scl_pin", c.sclPin, s_bootPins[3]}};
    addPinStatus(doc, pins, 2);
}

static void mqttToJson(const MqttConfig &c, JsonDocument &doc) {
    doc["enabled"] = c.enabled;
    doc["host"] = c.host;
    doc["port"] = c.port;
    doc["user"] = c.user;
    // Password deliberately in plain text: LAN-only device, no TLS/auth intended.
    doc["pass"] = c.pass;
    doc["topic_prefix"] = c.topicPrefix;
    doc["device_name"] = c.deviceName;
    doc["keepalive_s"] = c.keepAliveS;
    doc["socket_timeout_s"] = c.socketTimeoutS;
}

static void haExposeToJson(const HaExposeConfig &c, JsonDocument &doc) {
    doc["presence"] = c.presence;
    doc["target_count"] = c.targetCount;
    doc["illuminance"] = c.illuminance;
    doc["motion"] = c.motion;
    doc["zone_motion"] = c.zoneMotion;
}

// Network settings as the firmware booted with them: main.cpp applies them only
// before autoConnect(), so any difference means the change takes effect after a restart.
static WifiConfig s_bootWifi;
// Static IP configured, but the device booted with DHCP (fallback in main.cpp).
static bool s_staticIpFallback = false;

static bool wifiNetworkChanged(const WifiConfig &a, const WifiConfig &b) {
    return strcmp(a.hostname, b.hostname) != 0 || a.useStaticIp != b.useStaticIp ||
           strcmp(a.staticIp, b.staticIp) != 0 || strcmp(a.gateway, b.gateway) != 0 ||
           strcmp(a.subnet, b.subnet) != 0 || strcmp(a.dns, b.dns) != 0;
}

static void wifiToJson(const WifiConfig &c, JsonDocument &doc) {
    doc["no_modem_sleep"] = c.noModemSleep;
    doc["hostname"] = c.hostname;
    doc["use_static_ip"] = c.useStaticIp;
    doc["static_ip"] = c.staticIp;
    doc["gateway"] = c.gateway;
    doc["subnet"] = c.subnet;
    doc["dns"] = c.dns;
    // Same key as the pin sections; no_modem_sleep switches live and never needs it
    doc["restart_required"] = wifiNetworkChanged(c, s_bootWifi);
    doc["static_ip_fallback"] = s_staticIpFallback;
}

static void zonesToJson(const ZoneConfig *zones, JsonDocument &doc) {
    JsonArray arr = doc.to<JsonArray>();
    for (uint8_t i = 0; i < MAX_ZONES; i++) {
        JsonObject z = arr.add<JsonObject>();
        z["id"] = i;
        z["name"] = zones[i].name;
        z["present"] = zones[i].present;
        z["enabled"] = zones[i].enabled;
        z["x1"] = zones[i].x1;
        z["y1"] = zones[i].y1;
        z["x2"] = zones[i].x2;
        z["y2"] = zones[i].y2;
        z["min_resolution"] = zones[i].minResolution;
    }
}

// Region filter as the firmware booted with it: it is only sent to the sensor in
// sensorsBegin(), so any difference means the change reaches the sensor after a restart.
static Ld2450RegionFilterConfig s_bootRegionFilter;

// Geometry of unused slots is ignored (it is kept as stored, but never sent).
static bool regionFilterChanged(const Ld2450RegionFilterConfig &a, const Ld2450RegionFilterConfig &b) {
    if (a.mode != b.mode) return true;
    for (uint8_t i = 0; i < LD2450_REGION_COUNT; i++) {
        if (a.present[i] != b.present[i]) return true;
        if (a.present[i] && (a.x1[i] != b.x1[i] || a.y1[i] != b.y1[i] ||
                             a.x2[i] != b.x2[i] || a.y2[i] != b.y2[i])) {
            return true;
        }
    }
    return false;
}

static void regionFilterToJson(const Ld2450RegionFilterConfig &rf, JsonDocument &doc) {
    doc["mode"] = rf.mode;
    JsonArray arr = doc["regions"].to<JsonArray>();
    for (uint8_t i = 0; i < LD2450_REGION_COUNT; i++) {
        JsonObject r = arr.add<JsonObject>();
        r["id"] = i;
        r["present"] = rf.present[i];
        r["x1"] = rf.x1[i];
        r["y1"] = rf.y1[i];
        r["x2"] = rf.x2[i];
        r["y2"] = rf.y2[i];
    }
    // Only while the real sensor is in use (the simulation applies the filter live) and it
    // does not hold this config yet: changed since boot, or not sent at boot at all
    // (simulation switched off at runtime). Never with unusable boot pins: a restart cannot help there.
    const Ld2450Config &ld = s_cfg->ld2450;
    doc["restart_required"] = ld.enabled && !ld.simEnabled && !ld2450PinError(s_bootPins[0], s_bootPins[1]) &&
                              (!g_sensorState.ld2450RegionFilterSent || regionFilterChanged(rf, s_bootRegionFilter));
    // Outcome of the boot-time upload (not sent: simulation, sensor disabled or invalid pins)
    doc["sensor_sent"] = g_sensorState.ld2450RegionFilterSent;
    doc["sensor_acked"] = g_sensorState.ld2450RegionFilterAcked;
}

static void objectsToJson(const RoomObjectConfig *objects, JsonDocument &doc) {
    JsonArray arr = doc.to<JsonArray>();
    for (uint8_t i = 0; i < MAX_OBJECTS; i++) {
        JsonObject o = arr.add<JsonObject>();
        o["id"] = i;
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

// Persists the config, logs the change and syncs the MQTT layer (which drops
// the connection for a re-discovery; skipped for sections without HA
// entities). Returns false (and has already sent 500 in that case) if saving fails.
static bool persistAndApply(AsyncWebServerRequest *request, const char *section, bool applyMqtt = true) {
    if (!saveConfig(*s_cfg)) {
        sendJsonError(request, 500, "failed to persist config");
        return false;
    }
    eventLogPush(EventType::ConfigChanged, "Config saved: %s", section);
    if (applyMqtt) {
        mqttHaApplyConfig(*s_cfg);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

static void registerLd2450Routes() {
    server.on("/api/config/ld2450", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        ld2450ToJson(s_cfg->ld2450, doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/config/ld2450", MAX_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!requireObject(body, request)) return;
            JsonObjectConst o = body.as<JsonObjectConst>();

            String err;
            if (!validateBool(o, "enabled", err) ||
                !validateBool(o, "multi_target", err) ||
                !validateInt(o, "max_range_mm", 1000, 6000, err) ||
                !validateInt(o, "occupancy_timeout_s", 0, 3600, err) ||
                !validateBool(o, "sim_enabled", err) ||
                !validateInt(o, "moving_threshold_cm_s", 0, 1000, err) ||
                !validateBool(o, "ghost_filter_enabled", err) ||
                !validateInt(o, "ghost_min_exist_ms", 0, 5000, err) ||
                !validateInt(o, "ghost_max_jump_cm_s", 100, 2000, err) ||
                !validatePin(o, "rx_pin", err) ||
                !validatePin(o, "tx_pin", err)) {
                sendJsonError(request, 400, err);
                return;
            }

            Ld2450Config next = s_cfg->ld2450;
            next.enabled = o["enabled"] | next.enabled;
            next.multiTarget = o["multi_target"] | next.multiTarget;
            next.maxRangeMm = o["max_range_mm"] | next.maxRangeMm;
            next.occupancyTimeoutS = o["occupancy_timeout_s"] | next.occupancyTimeoutS;
            next.simEnabled = o["sim_enabled"] | next.simEnabled;
            next.movingThresholdCmS = o["moving_threshold_cm_s"] | next.movingThresholdCmS;
            next.ghostFilterEnabled = o["ghost_filter_enabled"] | next.ghostFilterEnabled;
            next.ghostMinExistMs = o["ghost_min_exist_ms"] | next.ghostMinExistMs;
            next.ghostMaxJumpCmS = o["ghost_max_jump_cm_s"] | next.ghostMaxJumpCmS;
            next.rxPin = o["rx_pin"] | next.rxPin;
            next.txPin = o["tx_pin"] | next.txPin;
            if (const char *pinErr = ld2450PinError(next.rxPin, next.txPin)) {
                sendJsonError(request, 400, pinErr);
                return;
            }
            if (!checkPinConflicts(next, s_cfg->bh1750, err)) {
                sendJsonError(request, 400, err);
                return;
            }

            Ld2450Config previous = s_cfg->ld2450;
            Ld2450Config &c = s_cfg->ld2450;
            c = next;

            if (!persistAndApply(request, "radar")) {
                s_cfg->ld2450 = previous;
                return;
            }
            ld2450ToJson(c, resp);
        });
}

static void registerBh1750Routes() {
    server.on("/api/config/bh1750", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        bh1750ToJson(s_cfg->bh1750, doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/config/bh1750", MAX_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!requireObject(body, request)) return;
            JsonObjectConst o = body.as<JsonObjectConst>();

            String err;
            if (!validateBool(o, "enabled", err) ||
                !validateInt(o, "i2c_address", 35, 92, err) ||
                !validateInt(o, "mode", 0, 2, err) ||
                !validateInt(o, "interval_ms", 1000, 3600000, err) ||
                !validateBool(o, "sim_enabled", err) ||
                !validatePin(o, "sda_pin", err) ||
                !validatePin(o, "scl_pin", err)) {
                sendJsonError(request, 400, err);
                return;
            }
            if (!o["i2c_address"].isNull()) {
                long addr = o["i2c_address"].as<long>();
                if (addr != 0x23 && addr != 0x5C) {
                    sendJsonError(request, 400, "i2c_address must be 35 (0x23) or 92 (0x5C)");
                    return;
                }
            }

            Bh1750Config next = s_cfg->bh1750;
            next.enabled = o["enabled"] | next.enabled;
            next.i2cAddress = o["i2c_address"] | next.i2cAddress;
            next.mode = o["mode"] | next.mode;
            next.intervalMs = o["interval_ms"] | next.intervalMs;
            next.simEnabled = o["sim_enabled"] | next.simEnabled;
            next.sdaPin = o["sda_pin"] | next.sdaPin;
            next.sclPin = o["scl_pin"] | next.sclPin;
            if (!checkPinConflicts(s_cfg->ld2450, next, err)) {
                sendJsonError(request, 400, err);
                return;
            }

            Bh1750Config previous = s_cfg->bh1750;
            Bh1750Config &c = s_cfg->bh1750;
            c = next;

            if (!persistAndApply(request, "light")) {
                s_cfg->bh1750 = previous;
                return;
            }
            bh1750ToJson(c, resp);
        });
}

static void registerMqttRoutes() {
    server.on("/api/config/mqtt", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        mqttToJson(s_cfg->mqtt, doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/config/mqtt", MAX_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!requireObject(body, request)) return;
            JsonObjectConst o = body.as<JsonObjectConst>();

            MqttConfig &c = s_cfg->mqtt;
            String err;
            if (!validateBool(o, "enabled", err) ||
                !validateString(o, "host", 0, sizeof(c.host) - 1, err) ||
                !validateInt(o, "port", 1, 65535, err) ||
                !validateString(o, "user", 0, sizeof(c.user) - 1, err) ||
                !validateString(o, "pass", 0, sizeof(c.pass) - 1, err) ||
                !validateString(o, "topic_prefix", 1, sizeof(c.topicPrefix) - 1, err) ||
                !validateString(o, "device_name", 1, sizeof(c.deviceName) - 1, err) ||
                !validateInt(o, "keepalive_s", 5, 120, err) ||
                !validateInt(o, "socket_timeout_s", 1, 30, err)) {
                sendJsonError(request, 400, err);
                return;
            }

            MqttConfig previous = c;
            c.enabled = o["enabled"] | c.enabled;
            c.port = o["port"] | c.port;
            if (!o["host"].isNull()) strlcpy(c.host, o["host"].as<const char *>(), sizeof(c.host));
            if (!o["user"].isNull()) strlcpy(c.user, o["user"].as<const char *>(), sizeof(c.user));
            if (!o["pass"].isNull()) strlcpy(c.pass, o["pass"].as<const char *>(), sizeof(c.pass));
            if (!o["topic_prefix"].isNull()) strlcpy(c.topicPrefix, o["topic_prefix"].as<const char *>(), sizeof(c.topicPrefix));
            if (!o["device_name"].isNull()) strlcpy(c.deviceName, o["device_name"].as<const char *>(), sizeof(c.deviceName));
            c.keepAliveS = o["keepalive_s"] | c.keepAliveS;
            c.socketTimeoutS = o["socket_timeout_s"] | c.socketTimeoutS;
            // Checked on the merged values, so partial updates stay consistent. A timeout
            // >= the keepalive interval only delays detecting a dead connection.
            if (c.socketTimeoutS >= c.keepAliveS) {
                s_cfg->mqtt = previous;
                sendJsonError(request, 400, "socket_timeout_s must be < keepalive_s");
                return;
            }

            // mqttHaApplyConfig drops the connection -> reconnect + re-discovery
            if (!persistAndApply(request, "mqtt")) {
                s_cfg->mqtt = previous;
                return;
            }
            mqttToJson(c, resp);
        });
}

static void registerHaExposeRoutes() {
    server.on("/api/config/ha-expose", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        haExposeToJson(s_cfg->haExpose, doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/config/ha-expose", MAX_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!requireObject(body, request)) return;
            JsonObjectConst o = body.as<JsonObjectConst>();

            String err;
            if (!validateBool(o, "presence", err) ||
                !validateBool(o, "target_count", err) ||
                !validateBool(o, "illuminance", err) ||
                !validateBool(o, "motion", err) ||
                !validateBool(o, "zone_motion", err)) {
                sendJsonError(request, 400, err);
                return;
            }

            HaExposeConfig &c = s_cfg->haExpose;
            HaExposeConfig previous = c;
            c.presence = o["presence"] | c.presence;
            c.targetCount = o["target_count"] | c.targetCount;
            c.illuminance = o["illuminance"] | c.illuminance;
            c.motion = o["motion"] | c.motion;
            c.zoneMotion = o["zone_motion"] | c.zoneMotion;

            // Changes the set of discovery entities -> reconnect + re-discovery
            if (!persistAndApply(request, "home assistant")) {
                s_cfg->haExpose = previous;
                return;
            }
            haExposeToJson(c, resp);
        });
}

static void registerWifiRoutes() {
    server.on("/api/config/wifi", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        wifiToJson(s_cfg->wifi, doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/config/wifi", MAX_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!requireObject(body, request)) return;
            JsonObjectConst o = body.as<JsonObjectConst>();

            String err;
            if (!validateBool(o, "no_modem_sleep", err) ||
                !validateHostname(o, "hostname", err) ||
                !validateBool(o, "use_static_ip", err) ||
                !validateIp(o, "static_ip", err) ||
                !validateIp(o, "gateway", err) ||
                !validateIp(o, "subnet", err) ||
                !validateIp(o, "dns", err)) {
                sendJsonError(request, 400, err);
                return;
            }

            WifiConfig next = s_cfg->wifi;
            next.noModemSleep = o["no_modem_sleep"] | next.noModemSleep;
            strlcpy(next.hostname, o["hostname"] | next.hostname, sizeof(next.hostname));
            next.useStaticIp = o["use_static_ip"] | next.useStaticIp;
            strlcpy(next.staticIp, o["static_ip"] | next.staticIp, sizeof(next.staticIp));
            strlcpy(next.gateway, o["gateway"] | next.gateway, sizeof(next.gateway));
            strlcpy(next.subnet, o["subnet"] | next.subnet, sizeof(next.subnet));
            strlcpy(next.dns, o["dns"] | next.dns, sizeof(next.dns));
            // Checked on the merged values: a partial update may leave a required field empty
            if (next.useStaticIp && (!*next.staticIp || !*next.gateway || !*next.subnet)) {
                sendJsonError(request, 400, "static_ip, gateway and subnet are required when use_static_ip is true");
                return;
            }
            if (next.useStaticIp) {
                IPAddress ip, gw, sn;
                ip.fromString(next.staticIp);
                gw.fromString(next.gateway);
                sn.fromString(next.subnet);
                // IPAddress holds the octets in network order; ntohl for the bit tests
                uint32_t mask = ntohl((uint32_t)sn);
                if (mask == 0 || (~mask & (~mask + 1)) != 0) {
                    sendJsonError(request, 400, "subnet must be a netmask like 255.255.255.0");
                    return;
                }
                if (((uint32_t)ip & (uint32_t)sn) != ((uint32_t)gw & (uint32_t)sn) || ip == gw) {
                    sendJsonError(request, 400, "static_ip and gateway must be different addresses in the same subnet");
                    return;
                }
            }

            WifiConfig &c = s_cfg->wifi;
            WifiConfig previous = c;
            c = next;

            // No HA entities involved; the sleep mode switches at runtime without a reconnect,
            // hostname/IP settings are applied on the next boot (restart_required)
            if (!persistAndApply(request, "wifi", false)) {
                s_cfg->wifi = previous;
                return;
            }
            wifiPowerApplyConfig(c);
            wifiToJson(c, resp);
        });
}

static void registerZoneRoutes() {
    server.on("/api/zones", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        zonesToJson(s_cfg->zones, doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/zones", MAX_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!body.is<JsonArrayConst>() || body.as<JsonArrayConst>().size() != MAX_ZONES) {
                sendJsonError(request, 400, "zones array must contain exactly 6 entries");
                return;
            }

            // Validate everything first, then apply atomically. Overlapping zones
            // are deliberately allowed (each zone is evaluated independently).
            ZoneConfig next[MAX_ZONES];
            memcpy(next, s_cfg->zones, sizeof(next));
            uint8_t i = 0;
            for (JsonVariantConst v : body.as<JsonArrayConst>()) {
                String prefix = String("zones[") + i + "].";
                if (!v.is<JsonObjectConst>()) {
                    sendJsonError(request, 400, prefix.substring(0, prefix.length() - 1) + " must be an object");
                    return;
                }
                JsonObjectConst o = v.as<JsonObjectConst>();
                String err;
                if (!validateBool(o, "present", err) || !validateBool(o, "enabled", err)) {
                    sendJsonError(request, 400, prefix + err);
                    return;
                }

                ZoneConfig &z = next[i];
                z.id = i; // id from the request is ignored (index-based)
                z.present = o["present"] | z.present;
                if (!z.present) {
                    // Deleted slot: name/geometry are ignored and kept as stored
                    z.enabled = false;
                    i++;
                    continue;
                }

                if (!validateString(o, "name", 1, sizeof(z.name) - 1, err) ||
                    !validateInt(o, "x1", -6000, 6000, err) ||
                    !validateInt(o, "y1", 0, 6000, err) ||
                    !validateInt(o, "x2", -6000, 6000, err) ||
                    !validateInt(o, "y2", 0, 6000, err) ||
                    !validateInt(o, "min_resolution", 0, 65535, err)) {
                    sendJsonError(request, 400, prefix + err);
                    return;
                }
                if (!o["name"].isNull()) strlcpy(z.name, o["name"].as<const char *>(), sizeof(z.name));
                z.enabled = o["enabled"] | z.enabled;
                z.x1 = o["x1"] | z.x1;
                z.y1 = o["y1"] | z.y1;
                z.x2 = o["x2"] | z.x2;
                z.y2 = o["y2"] | z.y2;
                z.minResolution = o["min_resolution"] | z.minResolution;
                // Checked on the merged values, so partial updates stay consistent
                if (z.x1 >= z.x2 || z.y1 >= z.y2) {
                    sendJsonError(request, 400, prefix + "x1 must be < x2 and y1 must be < y2");
                    return;
                }
                i++;
            }

            ZoneConfig previous[MAX_ZONES];
            memcpy(previous, s_cfg->zones, sizeof(previous));
            memcpy(s_cfg->zones, next, sizeof(next));

            // Zone names/present/enabled affect the discovery entities zone_<i>
            if (!persistAndApply(request, "zones")) {
                memcpy(s_cfg->zones, previous, sizeof(previous));
                return;
            }
            zonesToJson(s_cfg->zones, resp);
        });
}

static void registerRegionFilterRoutes() {
    server.on("/api/region-filter", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        regionFilterToJson(s_cfg->ld2450.regionFilter, doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/region-filter", MAX_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!requireObject(body, request)) return;
            JsonObjectConst o = body.as<JsonObjectConst>();

            String err;
            if (!validateInt(o, "mode", REGION_FILTER_OFF, REGION_FILTER_EXCLUDE, err)) {
                sendJsonError(request, 400, err);
                return;
            }
            // The sensor's "detect only inside the regions" mode (1) is deliberately not supported
            if (!o["mode"].isNull() && o["mode"].as<long>() == 1) {
                sendJsonError(request, 400, "mode must be 0 (off) or 2 (exclusion)");
                return;
            }

            // Validate everything first, then apply atomically (same rules as zones)
            Ld2450RegionFilterConfig next = s_cfg->ld2450.regionFilter;
            next.mode = o["mode"] | next.mode;
            if (!o["regions"].isNull()) {
                if (!o["regions"].is<JsonArrayConst>() || o["regions"].size() != LD2450_REGION_COUNT) {
                    sendJsonError(request, 400, "regions array must contain exactly 3 entries");
                    return;
                }
                uint8_t i = 0;
                for (JsonVariantConst v : o["regions"].as<JsonArrayConst>()) {
                    String prefix = String("regions[") + i + "].";
                    if (!v.is<JsonObjectConst>()) {
                        sendJsonError(request, 400, prefix.substring(0, prefix.length() - 1) + " must be an object");
                        return;
                    }
                    JsonObjectConst r = v.as<JsonObjectConst>();
                    if (!validateBool(r, "present", err)) {
                        sendJsonError(request, 400, prefix + err);
                        return;
                    }
                    next.present[i] = r["present"] | next.present[i];
                    if (!next.present[i]) {
                        // Deleted slot: geometry is ignored and kept as stored
                        i++;
                        continue;
                    }
                    if (!validateInt(r, "x1", -6000, 6000, err) ||
                        !validateInt(r, "y1", 0, 6000, err) ||
                        !validateInt(r, "x2", -6000, 6000, err) ||
                        !validateInt(r, "y2", 0, 6000, err)) {
                        sendJsonError(request, 400, prefix + err);
                        return;
                    }
                    next.x1[i] = r["x1"] | next.x1[i];
                    next.y1[i] = r["y1"] | next.y1[i];
                    next.x2[i] = r["x2"] | next.x2[i];
                    next.y2[i] = r["y2"] | next.y2[i];
                    // Checked on the merged values, so partial updates stay consistent
                    if (next.x1[i] >= next.x2[i] || next.y1[i] >= next.y2[i]) {
                        sendJsonError(request, 400, prefix + "x1 must be < x2 and y1 must be < y2");
                        return;
                    }
                    i++;
                }
            }

            Ld2450RegionFilterConfig previous = s_cfg->ld2450.regionFilter;
            s_cfg->ld2450.regionFilter = next;

            // No HA entities; the simulation applies it right away, the sensor after a restart
            if (!persistAndApply(request, "exclusion zones", false)) {
                s_cfg->ld2450.regionFilter = previous;
                return;
            }
            regionFilterToJson(s_cfg->ld2450.regionFilter, resp);
        });
}

static void registerObjectRoutes() {
    server.on("/api/objects", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        objectsToJson(s_cfg->objects, doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/objects", MAX_OBJECTS_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!body.is<JsonArrayConst>() || body.as<JsonArrayConst>().size() != MAX_OBJECTS) {
                sendJsonError(request, 400, "objects array must contain exactly 12 entries");
                return;
            }

            // Validate everything first, then apply atomically (same rules as zones).
            RoomObjectConfig next[MAX_OBJECTS];
            memcpy(next, s_cfg->objects, sizeof(next));
            uint8_t i = 0;
            for (JsonVariantConst v : body.as<JsonArrayConst>()) {
                String prefix = String("objects[") + i + "].";
                if (!v.is<JsonObjectConst>()) {
                    sendJsonError(request, 400, prefix.substring(0, prefix.length() - 1) + " must be an object");
                    return;
                }
                JsonObjectConst o = v.as<JsonObjectConst>();
                String err;
                if (!validateBool(o, "present", err)) {
                    sendJsonError(request, 400, prefix + err);
                    return;
                }

                RoomObjectConfig &obj = next[i];
                obj.id = i; // id from the request is ignored (index-based)
                obj.present = o["present"] | obj.present;
                if (!obj.present) {
                    // Deleted slot: the remaining fields are ignored and kept as stored
                    i++;
                    continue;
                }

                if (!validateString(o, "name", 1, sizeof(obj.name) - 1, err) ||
                    !validateString(o, "type", 1, 16, err) ||
                    !validateInt(o, "x1", -6000, 6000, err) ||
                    !validateInt(o, "y1", 0, 6000, err) ||
                    !validateInt(o, "x2", -6000, 6000, err) ||
                    !validateInt(o, "y2", 0, 6000, err) ||
                    !validateInt(o, "rotation_deg", 0, 270, err)) {
                    sendJsonError(request, 400, prefix + err);
                    return;
                }
                if (!o["type"].isNull()) {
                    int type = objectTypeFromString(o["type"].as<const char *>());
                    if (type < 0) {
                        sendJsonError(request, 400, prefix + "type must be one of cabinet, sofa, door, table, other");
                        return;
                    }
                    obj.type = (uint8_t)type;
                }
                if (!o["rotation_deg"].isNull()) {
                    int16_t rot = o["rotation_deg"].as<int16_t>();
                    if (rot % 90 != 0) {
                        sendJsonError(request, 400, prefix + "rotation_deg must be 0, 90, 180 or 270");
                        return;
                    }
                    obj.rotationDeg = rot;
                }
                if (!o["name"].isNull()) strlcpy(obj.name, o["name"].as<const char *>(), sizeof(obj.name));
                obj.x1 = o["x1"] | obj.x1;
                obj.y1 = o["y1"] | obj.y1;
                obj.x2 = o["x2"] | obj.x2;
                obj.y2 = o["y2"] | obj.y2;
                if (obj.x1 >= obj.x2 || obj.y1 >= obj.y2) {
                    sendJsonError(request, 400, prefix + "x1 must be < x2 and y1 must be < y2");
                    return;
                }
                i++;
            }

            RoomObjectConfig previous[MAX_OBJECTS];
            memcpy(previous, s_cfg->objects, sizeof(previous));
            memcpy(s_cfg->objects, next, sizeof(next));

            // Objects have no Home Assistant entities: no MQTT re-discovery needed
            if (!persistAndApply(request, "objects", false)) {
                memcpy(s_cfg->objects, previous, sizeof(previous));
                return;
            }
            objectsToJson(s_cfg->objects, resp);
        });
}

static void registerStateRoute() {
    server.on("/api/state", HTTP_GET, [](AsyncWebServerRequest *request) {
        const Ld2450State &ld = g_sensorState.ld2450;
        const Bh1750State &bh = g_sensorState.bh1750;
        const unsigned long now = millis();
        JsonDocument doc;

        JsonObject l = doc["ld2450"].to<JsonObject>();
        l["sim_mode"] = g_sensorState.ld2450SimMode;
        l["sim_enabled"] = s_cfg->ld2450.simEnabled; // configured; sim_mode is the actual data source
        l["presence"] = ld.presence;
        l["motion"] = ld.motion;
        l["target_count"] = ld.targetCount;
        // Always all slots; inactive ones are reported with active=false
        JsonArray targets = l["targets"].to<JsonArray>();
        for (uint8_t i = 0; i < LD2450_MAX_TARGETS; i++) {
            JsonObject t = targets.add<JsonObject>();
            t["active"] = ld.targets[i].active;
            t["x_mm"] = ld.targets[i].xMm;
            t["y_mm"] = ld.targets[i].yMm;
            t["speed_cm_s"] = ld.targets[i].speedCmS;
            t["resolution"] = ld.targets[i].resolution;
            t["moving"] = ld.targets[i].moving;
            t["plausible"] = ld.targets[i].plausible;
        }
        JsonArray zp = l["zone_presence"].to<JsonArray>();
        for (uint8_t i = 0; i < MAX_ZONES; i++) {
            zp.add(ld.zonePresence[i]);
        }
        JsonArray zm = l["zone_motion"].to<JsonArray>();
        for (uint8_t i = 0; i < MAX_ZONES; i++) {
            zm.add(ld.zoneMoving[i]);
        }
        // Age of the last data update (not an absolute timestamp)
        l["last_update_ms"] = now - g_sensorState.ld2450LastUpdateMs;

        JsonObject b = doc["bh1750"].to<JsonObject>();
        // One decimal place, otherwise float->double serializes e.g. 123.4000015
        b["illuminance_lx"] = serialized(String(bh.lux, 1));
        b["valid"] = bh.valid;
        b["sim_mode"] = g_sensorState.bh1750SimMode;
        b["sim_enabled"] = s_cfg->bh1750.simEnabled;
        b["last_update_ms"] = now - g_sensorState.bh1750LastUpdateMs;

        JsonObject w = doc["wifi"].to<JsonObject>();
        w["connected"] = WiFi.status() == WL_CONNECTED;
        w["ip"] = WiFi.localIP().toString();
        w["rssi"] = WiFi.RSSI();
        w["ssid"] = WiFi.SSID();
        w["mac"] = WiFi.macAddress();

        JsonObject sys = doc["system"].to<JsonObject>();
        sys["free_heap"] = ESP.getFreeHeap();
        sys["heap_fragmentation"] = ESP.getHeapFragmentation();
        sys["mqtt_host"] = s_cfg->mqtt.host;

        doc["mqtt_connected"] = mqttHaIsConnected();
        doc["uptime_s"] = millis() / 1000;

        sendJsonDoc(request, 200, doc);
    });
}

static void registerEventRoutes() {
    // ?since=<id> returns only newer events (the UI polls incrementally)
    server.on("/api/events", HTTP_GET, [](AsyncWebServerRequest *request) {
        uint32_t since = 0;
        if (request->hasParam("since")) {
            since = strtoul(request->getParam("since")->value().c_str(), nullptr, 10);
        }
        sendResponse(request, new (std::nothrow) EventsResponse(since));
    });
}

// Restarts REBOOT_DELAY_MS (300 ms) later from webServerLoop(), so that the
// running HTTP response still goes out; logs Reboot or FactoryReset.
// The log entry is lost with the restart; the next boot logs its reset reason.
static void webServerScheduleReboot(bool factoryReset) {
    eventLogPush(factoryReset ? EventType::FactoryReset : EventType::Reboot,
                 factoryReset ? "Factory reset, rebooting" : "Reboot requested");
    s_rebootPending = true;
    s_rebootRequestedAt = millis();
}

// `pio run -t uploadfs` (needed for every data/ change, e.g. this release) replaces the whole
// LittleFS partition with a fresh image built from data/ - unlike a firmware-only upload, it
// wipes /config.json along with it. These two routes let flash.sh save/restore the config
// across such a filesystem reflash; the backup is the same shape as toJson()/fromJson() use
// for persistence, so it survives schema changes exactly like the on-disk file does.
static const size_t MAX_BACKUP_BODY_LEN = 8192; // full config: zones + objects + sensors + mqtt

static void registerConfigBackupRoutes() {
    server.on("/api/config/backup", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;
        s_cfg->toJson(doc);
        sendJsonDoc(request, 200, doc);
    });

    registerJsonPost(server, "/api/config/restore", MAX_BACKUP_BODY_LEN,
        [](JsonDocument &body, JsonDocument &resp, AsyncWebServerRequest *request) {
            if (!requireObject(body, request)) return;
            // Full replace (not merge): starts from a clean default so a slot present in the
            // backup but now unused (e.g. a shrunk zone/object array) does not keep stale data.
            resetConfigToDefaults(*s_cfg);
            s_cfg->fromJson(body);
            if (!persistAndApply(request, "restore")) return;
            wifiPowerApplyConfig(s_cfg->wifi);
            s_cfg->toJson(resp);
        });
}

// ---------------------------------------------------------------------------
// OTA updates: firmware (/api/firmware) and LittleFS image (/api/filesystem)
//
// Both endpoints take a multipart/form-data upload with exactly one file part
// and stream it chunk by chunk (AsyncWebServer hands the file over in pieces of
// at most 1460 bytes) straight into the core's Updater, which buffers at most
// one flash sector (4 KB) itself. The image is never held in RAM as a whole: a
// 670 KB firmware or a 1000 KB filesystem image is far beyond the ~40 KB heap
// that MQTT, the sensors and the web server share.
//
// Optional query parameters:
//   ?size=<bytes>  exact file size (the web UI always sends it); enables the
//                  exact size guard before the first flash write. Without it
//                  the firmware endpoint falls back to Content-Length as an
//                  upper bound (curl -F, recovery page without JS).
//   ?reboot=0      do not restart after a successful update. The UI uses it for
//                  the firmware step of a combined update, so firmware and
//                  filesystem go live together with a single reboot.
//
// Flash layout (board d1_mini, eagle.flash.4m1m.ld, see platformio.ini):
//   0x000000  running sketch
//      ...    OTA slot: a new firmware is staged directly below FS_start and
//             copied over the running sketch by the bootloader (eboot) on the
//             next boot, so a failed firmware upload never touches the running one
//   0x300000  LittleFS (FS_PHYS_SIZE = 0xFA000 = 1000 KB), incl. /config.json
//
// Authentication: none, consistent with the rest of /api (LAN-only device, see
// mqttToJson). The web UI asks for an explicit confirmation instead.
// ---------------------------------------------------------------------------

// Flash layout values, size limits and the image checks (LD_IROM0_SEG_LEN,
// FIRMWARE_BIN_MAX_BYTES, otaFirmwareMaxBytes(), otaCheckLittleFsImage(), ...)
// live in ota_image.h/.cpp.

// Framing that browsers/curl add around the file part (boundary lines + part
// headers, typically ~200 bytes). Only used to judge Content-Length when the
// exact size was not sent. Secondary since FIRMWARE_BIN_MAX_BYTES: the hard
// cap is what keeps oversized images out, this margin only avoids rejecting a
// file right at that cap because of its multipart framing.
static const size_t MULTIPART_OVERHEAD_MAX = 1024;

enum class OtaKind : uint8_t { Firmware, Filesystem };

// Per-request upload state in request->_tempObject. Plain data only, because
// the request destructor releases _tempObject with free() (same mechanism as
// registerJsonPost's body buffer).
struct OtaUploadState {
    bool fileSeen;    // a file part arrived (a second one is rejected)
    bool exactSize;   // Update.begin() got the exact image size -> strict end()
    bool started;     // Update.begin() succeeded, flash is being written
    bool finished;    // Update.end() succeeded
    bool fsTouched;   // LittleFS was unmounted and (partially) overwritten
    uint16_t httpCode;
    uint32_t written;
    char error[128];
};

// Incremented with every Update.begin(). The disconnect callback of an upload
// only aborts the update if it is still its own (a new upload may already have
// started between Update.end() and the old connection closing).
static uint32_t s_otaSession = 0;

static const char *otaKindName(OtaKind kind) {
    return kind == OtaKind::Firmware ? "Firmware" : "Filesystem";
}

// Records the first error only: later chunks of a failed upload are ignored,
// and the root cause is what the user needs to see.
static void otaSetError(OtaUploadState &st, uint16_t httpCode, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void otaSetError(OtaUploadState &st, uint16_t httpCode, const char *fmt, ...) {
    if (st.error[0]) return;
    st.httpCode = httpCode;
    va_list args;
    va_start(args, fmt);
    vsnprintf(st.error, sizeof(st.error), fmt, args);
    va_end(args);
}

// Aborts a running update without a reboot. For the filesystem the partition
// is left partially overwritten; it is deliberately not remounted (it may hold
// half an image), the next upload simply starts over.
static void otaAbort() {
    if (Update.isRunning()) {
        Update.end(); // with remaining data this only resets the updater
    }
    // Update.begin() forces WIFI_NONE_SLEEP; restore the configured mode.
    wifiPowerApplyConfig(s_cfg->wifi);
}

// Validates the first chunk and starts the update. Everything that can reject
// the file runs before Update.begin(), i.e. before the first flash erase.
static void otaBegin(AsyncWebServerRequest *request, OtaKind kind, OtaUploadState &st, const uint8_t *data, size_t len) {
    if (Update.isRunning()) {
        otaSetError(st, 409, "another update is already in progress");
        return;
    }
    if (s_rebootPending) {
        otaSetError(st, 409, "device is rebooting");
        return;
    }
    // declared == 0 means "not sent"; a size that is sent must be usable, so
    // "?size=", "?size=0" or "?size=12abc" are rejected instead of silently
    // falling back to the weaker Content-Length bound.
    size_t declared = 0;
    if (request->hasParam("size")) {
        const char *s = request->getParam("size")->value().c_str();
        char *end = nullptr;
        unsigned long v = strtoul(s, &end, 10);
        if (!isdigit((unsigned char)s[0]) || *end != '\0' || v == 0) {
            otaSetError(st, 400, "size must be a positive integer (file size in bytes)");
            return;
        }
        declared = v;
    }

    size_t size = 0;
    if (kind == OtaKind::Firmware) {
        // Magic byte check: see otaHasFirmwareMagic() in ota_image.h.
        if (!otaHasFirmwareMagic(data, len)) {
            otaSetError(st, 400, "not an ESP8266 firmware image (magic byte 0xE9 missing) - use firmware.bin");
            return;
        }
        uint32_t maxBytes = otaFirmwareMaxBytes();
        if (declared > 0) {
            if (declared > maxBytes) {
                otaSetError(st, 413, "firmware too large: %u bytes, limit is %u bytes (%s)",
                            declared, maxBytes, otaFirmwareLimitName());
                return;
            }
            size = declared;
            st.exactSize = true;
        } else {
            // Without the exact size, Content-Length (file + framing) is the
            // best bound available. Staging goes to the unused OTA slot and
            // Update.begin(maxBytes) makes Update.write() refuse anything
            // beyond the cap, so a file that only turns out too large while
            // writing is harmless.
            if (request->contentLength() > maxBytes + MULTIPART_OVERHEAD_MAX) {
                otaSetError(st, 413, "firmware too large: upload is %u bytes, limit is %u bytes (%s)",
                            request->contentLength(), maxBytes, otaFirmwareLimitName());
                return;
            }
            size = maxBytes;
        }
    } else {
        uint32_t imageSize = 0;
        char err[sizeof(st.error)];
        if (!otaCheckLittleFsImage(data, len, imageSize, err, sizeof(err))) {
            otaSetError(st, 400, "%s", err);
            return;
        }
        if (declared > 0 && declared != imageSize) {
            otaSetError(st, 400, "file size %u does not match the image size %u in its superblock", declared, imageSize);
            return;
        }
        // The partition is overwritten in place, so a body that cannot even
        // contain the whole image is rejected here rather than after erasing.
        if (request->contentLength() < imageSize) {
            otaSetError(st, 400, "upload is shorter than the image (%u of %u bytes)", request->contentLength(), imageSize);
            return;
        }
        size = imageSize;
        st.exactSize = true;
    }

    // Upload callbacks run in the lwIP (SYS) context, where yield() panics;
    // async mode stops the Updater from yielding between sector writes.
    Update.runAsync(true);
    if (kind == OtaKind::Filesystem) {
        // Same as the core's ESP8266HTTPUpdateServer before Update.begin(U_FS):
        // unmount so no open file or LittleFS cache writes into the region
        // being replaced. From here on static files and saveConfig() fail
        // until the reboot (the config itself stays in RAM).
        close_all_fs();
        st.fsTouched = true;
    }
    if (!Update.begin(size, kind == OtaKind::Firmware ? U_FLASH : U_FS)) {
        otaSetError(st, 500, "Update.begin failed: %s", Update.getErrorString().c_str());
        if (kind == OtaKind::Filesystem) {
            // Nothing was written yet: the old filesystem is intact, so remount it.
            LittleFS.begin();
            st.fsTouched = false;
        }
        wifiPowerApplyConfig(s_cfg->wifi);
        return;
    }
    st.started = true;

    // A dropped connection never reaches the final chunk or onRequest; without
    // this the Updater would stay "running" and block every later upload.
    uint32_t session = ++s_otaSession;
    request->onDisconnect([session, kind]() {
        if (session == s_otaSession && Update.isRunning()) {
            otaAbort();
            eventLogPush(EventType::OtaUpdate, "%s upload aborted", otaKindName(kind));
        }
    });
}

static void otaHandleUpload(AsyncWebServerRequest *request, OtaKind kind, size_t index, uint8_t *data, size_t len, bool final) {
    OtaUploadState *st = static_cast<OtaUploadState *>(request->_tempObject);
    if (index == 0) {
        if (!st) {
            st = static_cast<OtaUploadState *>(calloc(1, sizeof(OtaUploadState)));
            if (!st) return; // onRequest reports "no file received"
            request->_tempObject = st;
        } else if (st->fileSeen) {
            otaSetError(*st, 400, "only one file per upload");
            return;
        }
        st->fileSeen = true;
        otaBegin(request, kind, *st, data, len);
    }
    if (!st || !st->started || st->finished || st->error[0]) return;

    if (len > 0 && Update.write(data, len) != len) {
        otaSetError(*st, 500, "flash write failed at %u bytes: %s", st->written, Update.getErrorString().c_str());
        otaAbort();
        return;
    }
    st->written += len;

    if (final) {
        // Exact size known: strict end() also rejects a truncated upload.
        // Firmware without ?size=: end(true) takes the bytes received as the
        // image size, like the core's ESP8266HTTPUpdateServer; the magic byte
        // is re-checked on flash by Updater::_verifyEnd().
        if (!Update.end(!st->exactSize)) {
            otaSetError(*st, 500, "update verification failed: %s", Update.getErrorString().c_str());
            otaAbort();
            return;
        }
        st->finished = true;
    }
}

// Runs once the whole request body has been received, i.e. after the final
// chunk and Update.end(). The response deliberately waits for Update.end():
// only then is the image verified and (for firmware) the eboot copy command
// written, so "200" really means "staged". Answering earlier would let the UI
// report success for an image that still fails verification.
static void otaHandleRequest(AsyncWebServerRequest *request, OtaKind kind) {
    OtaUploadState *st = static_cast<OtaUploadState *>(request->_tempObject);
    if (!st) {
        sendJsonError(request, 400, "no file received (multipart/form-data with one file part expected)");
        return;
    }
    // An error can also follow a finished image: a second file part in the same
    // request is rejected after the first one was already staged.
    if (!st->finished || st->error[0]) {
        if (st->started) otaAbort(); // e.g. body ended without a final chunk
        if (!st->error[0]) otaSetError(*st, 400, "upload incomplete");
        eventLogPush(EventType::OtaUpdate, "%s update failed", otaKindName(kind));
        JsonDocument doc;
        doc["error"] = st->error;
        // Tells the UI that the web files are gone until a successful retry
        // (not the case if the image itself was completely written).
        doc["filesystem_damaged"] = st->fsTouched && !st->finished;
        // A finished firmware is staged anyway and goes live with the next reboot.
        doc["staged"] = st->finished;
        sendJsonDoc(request, st->httpCode ? st->httpCode : 500, doc);
        return;
    }

    bool reboot = !(request->hasParam("reboot") && request->getParam("reboot")->value() == "0");
    eventLogPush(EventType::OtaUpdate, "%s update staged (%u B)", otaKindName(kind), st->written);
    JsonDocument doc;
    doc["status"] = reboot ? "rebooting" : "staged";
    doc["bytes"] = st->written;
    sendJsonDoc(request, 200, doc);
    if (reboot) {
        webServerScheduleReboot(false);
    } else {
        wifiPowerApplyConfig(s_cfg->wifi);
    }
}

static void registerOtaRoutes() {
    server.on("/api/firmware", HTTP_POST,
        [](AsyncWebServerRequest *request) { otaHandleRequest(request, OtaKind::Firmware); },
        [](AsyncWebServerRequest *request, const String &, size_t index, uint8_t *data, size_t len, bool final) {
            otaHandleUpload(request, OtaKind::Firmware, index, data, len, final);
        });

    server.on("/api/filesystem", HTTP_POST,
        [](AsyncWebServerRequest *request) { otaHandleRequest(request, OtaKind::Filesystem); },
        [](AsyncWebServerRequest *request, const String &, size_t index, uint8_t *data, size_t len, bool final) {
            otaHandleUpload(request, OtaKind::Filesystem, index, data, len, final);
        });
}

// Served instead of index.html when the filesystem holds no web UI - after an
// interrupted filesystem update (main.cpp formats the unmountable partition
// on the next boot) or while an image is being written. Without it the device
// would only answer "Not found" and could be recovered via serial flash only.
static const char RECOVERY_HTML[] PROGMEM = R"html(<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PresenceTrack - Recovery</title></head>
<body style="font-family:sans-serif;max-width:560px;margin:2em auto;padding:0 1em">
<h1>PresenceTrack</h1>
<p>The web UI is missing from the filesystem, e.g. after an interrupted filesystem update.
Upload the filesystem image (<code>littlefs.bin</code>) again.</p>
<p><a href="/api/config/backup" download="presencetrack-backup.json">Download backup</a></p>
<p><label>Firmware (.bin, optional): <input type="file" id="fw" accept=".bin"></label></p>
<p><label>Filesystem image: <input type="file" id="fs" accept=".bin,.fs"></label></p>
<p><button onclick="go()">Upload</button> <span id="m"></span></p>
<script>
function up(f,u,r){return new Promise(function(ok,no){var x=new XMLHttpRequest(),d=new FormData();d.append('file',f);
x.open('POST',u+'?size='+f.size+(r?'':'&reboot=0'));x.upload.onprogress=function(e){m.textContent=f.name+': '+Math.round(e.loaded*100/e.total)+' %'};
x.onload=function(){x.status==200?ok():no(x.responseText)};x.onerror=function(){no('connection lost')};x.send(d)})}
async function go(){var a=fw.files[0],b=fs.files[0];if(!a&&!b){m.textContent='No file selected';return}
try{if(a)await up(a,'/api/firmware',!b);if(b)await up(b,'/api/filesystem',1);m.textContent='Done - restarting, reload the page in 30 s.'}
catch(e){m.textContent='Error: '+e}}
</script></body></html>)html";

static void registerSystemRoutes() {
    // Static device info, loaded once by the UI (dynamic values are in /api/state)
    server.on("/api/system", HTTP_GET, [](AsyncWebServerRequest *request) {
        char chipId[16];
        snprintf(chipId, sizeof(chipId), "%06x", ESP.getChipId()); // same format as the MQTT device id
        JsonDocument doc;
        doc["fw_version"] = FIRMWARE_VERSION;
        doc["chip_id"] = chipId;
        doc["flash_size_bytes"] = ESP.getFlashChipSize();
        doc["sketch_size_bytes"] = ESP.getSketchSize();
        doc["free_sketch_space_bytes"] = ESP.getFreeSketchSpace();
        // Upload limits enforced by /api/firmware and /api/filesystem, so the UI
        // can warn before a doomed upload instead of after transferring it.
        doc["ota_max_firmware_bytes"] = otaFirmwareMaxBytes();
        doc["fs_size_bytes"] = FS_PHYS_SIZE;
        doc["core_version"] = ESP.getCoreVersion();
        doc["sdk_version"] = ESP.getSdkVersion();
        doc["reset_reason"] = ESP.getResetReason();
        // Low-water mark of the allocator itself (UMM_STATS_FULL, platformio.ini):
        // updated in every malloc, so it also captures the peak in the middle of
        // parallel requests that sampling from loop() never sees. Reset at the end
        // of webServerBegin(), so WiFiManager's boot peak does not count.
        doc["min_free_heap"] = umm_free_heap_size_min();
        sendJsonDoc(request, 200, doc);
    });

    // Both refuse while an OTA upload is running: ESP.restart() would cut it off,
    // and during a filesystem upload the partition is already unmounted and
    // partially overwritten - the reboot would come up with a broken or freshly
    // formatted filesystem. Checked before any mutation (factory reset too).
    server.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (Update.isRunning()) {
            sendJsonError(request, 409, "OTA update in progress");
            return;
        }
        JsonDocument doc;
        doc["status"] = "rebooting";
        sendJsonDoc(request, 200, doc);
        webServerScheduleReboot(false);
    });

    server.on("/api/factory-reset", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (Update.isRunning()) {
            sendJsonError(request, 409, "OTA update in progress");
            return;
        }
        resetConfigToDefaults(*s_cfg);
        if (!persistAndApply(request, "factory defaults")) {
            return;
        }
        JsonDocument doc;
        doc["status"] = "resetting";
        sendJsonDoc(request, 200, doc);
        webServerScheduleReboot(true);
    });

    // Erases the stored SSID/password, so the next boot opens the WiFiManager
    // portal (AP_SSID in main.cpp). The erase itself runs in webServerLoop():
    // it disconnects the station, which would cut off this response, and
    // WiFiManager::resetSettings() delay()s, which is not allowed in an async
    // callback (WiFiManager.h also cannot be included here, see web_server.h).
    server.on("/api/wifi/reset", HTTP_POST, [](AsyncWebServerRequest *request) {
        if (Update.isRunning()) {
            sendJsonError(request, 409, "OTA update in progress");
            return;
        }
        JsonDocument doc;
        doc["status"] = "resetting";
        sendJsonDoc(request, 200, doc);
        s_wifiResetPending = true;
        webServerScheduleReboot(false);
    });
}

static void registerStaticRoutes() {
    // Specific handlers first: the first matching handler wins.
    // no-cache (not a long max-age) on all three: index.html/app.js/style.css are one release
    // unit uploaded together via uploadfs. A cached app.js surviving against a freshly reloaded
    // index.html after such an update mismatches on renamed classes/ids and throws in the UI.
    server.serveStatic("/style.css", LittleFS, "/style.css").setCacheControl("no-cache");
    server.serveStatic("/app.js", LittleFS, "/app.js").setCacheControl("no-cache");
    server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html").setCacheControl("no-cache");

    server.onNotFound([](AsyncWebServerRequest *request) {
        const String &url = request->url();
        if (url.startsWith("/api/")) {
            sendJsonError(request, 404, "not found");
        } else if ((url == "/" || url == "/index.html") && !LittleFS.exists("/index.html")) {
            // serveStatic("/") declines when index.html is missing (or LittleFS is
            // unmounted during a filesystem update), so the request ends up here.
            request->send_P(200, "text/html", RECOVERY_HTML);
        } else {
            request->send(404, "text/plain", "Not found");
        }
    });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void webServerBegin(AppConfig &cfg) {
    s_cfg = &cfg;
    s_bootPins[0] = cfg.ld2450.rxPin;
    s_bootPins[1] = cfg.ld2450.txPin;
    s_bootPins[2] = cfg.bh1750.sdaPin;
    s_bootPins[3] = cfg.bh1750.sclPin;
    s_bootWifi = cfg.wifi;
    s_bootRegionFilter = cfg.ld2450.regionFilter;
    IPAddress bootStaticIp;
    s_staticIpFallback = cfg.wifi.useStaticIp &&
                         (!bootStaticIp.fromString(cfg.wifi.staticIp) || WiFi.localIP() != bootStaticIp);

    registerLd2450Routes();
    registerBh1750Routes();
    registerMqttRoutes();
    registerHaExposeRoutes();
    registerWifiRoutes();
    registerZoneRoutes();
    registerRegionFilterRoutes();
    registerObjectRoutes();
    registerStateRoute();
    registerEventRoutes();
    registerConfigBackupRoutes();
    registerOtaRoutes();
    registerSystemRoutes();
    registerStaticRoutes();

    server.begin();
    // The listen pcb is only created in begin(); AsyncServer does not expose it
    for (tcp_pcb_listen *l = tcp_listen_pcbs.listen_pcbs; l; l = l->next) {
        if (l->local_port == HTTP_PORT) s_httpListener = l;
    }
    updateConnectionLimit();
    umm_free_heap_size_min_reset();
}

void webServerLoop() {
    updateConnectionLimit();

    if (s_rebootPending && millis() - s_rebootRequestedAt >= REBOOT_DELAY_MS) {
        if (s_wifiResetPending) {
            // What WiFiManager::resetSettings() does on the ESP8266: clear the SDK-stored credentials
            WiFi.persistent(true);
            WiFi.disconnect(true);
            WiFi.persistent(false);
        }
        ESP.restart();
    }
}
