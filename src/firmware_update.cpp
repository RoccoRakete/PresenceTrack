#include "firmware_update.h"
#include "ota_image.h"
#include "web_server.h"
#include "wifi_power.h"
#include "event_log.h"
#include "firmware.h"

#include <ESP8266WiFi.h>
#include <WiFiClientSecureBearSSL.h>
#include <bearssl/bearssl.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <Updater.h>
#include <flash_hal.h>
#include <stdarg.h>

// ---------------------------------------------------------------------------
// Update direkt von GitHub
//
// Ablauf eines Installs (ein Schritt pro firmwareUpdateLoop()-Takt):
//   1. Manifest   GET MANIFEST_URL, 2 Redirects (latest -> v<version> -> Asset-CDN),
//                 Body (~500 B) in den Chunk-Puffer, mit ArduinoJson prüfen
//   2. Firmware   GET firmware.url, Redirect aufs CDN, dort in Range-Requests à
//                 RANGE_LEN über eine Keep-Alive-Verbindung (siehe Speicher), Body in
//                 1460-B-Chunks direkt in Update.write(); SHA-256 läuft mit,
//                 Update.end() erst nach dem Vergleich
//   3. Image      (nur "both") dasselbe für littlefs.bin mit U_FS
//   4. Neustart   webServerScheduleReboot(), eboot kopiert die Firmware beim Booten
// Ein check macht nur Schritt 1 und endet wieder in Idle.
//
// Warum ein eigener HTTP-Client statt ESP8266HTTPClient: dessen Redirect-Support
// verbindet den übergebenen secure client neu, ohne den Host für SNI zu
// wechseln - das CDN (release-assets.githubusercontent.com) bekäme den
// Handshake für github.com und antwortet mit dem falschen Zertifikat bzw. gar
// nicht. Hier entsteht pro Hop ein neuer WiFiClientSecure; connect(host, port)
// reicht den Hostnamen an br_ssl_client_reset(ctx, hostName, ...) weiter
// (WiFiClientSecureBearSSL.cpp:1188), der ihn als SNI sendet.
//
// Zertifikats-Policy: setInsecure(), d.h. die Zertifikatskette wird nicht
// geprüft. Der ESP8266 hat keine RTC; ohne verlässliche Uhrzeit ist die
// X.509-Gültigkeitsprüfung (notBefore/notAfter) nicht belastbar, und eine
// hinterlegte CA bzw. ein Fingerprint veraltet mit jedem Zertifikatswechsel bei
// GitHub/Fastly, ohne dass das Gerät es mitbekäme. Die Alternative - Uhrzeit
// per NTP (configTime) holen und gegen einen BearSSL::CertStore mit den
// Root-CAs prüfen - ist bewusst nicht Teil dieses Changes. Was bleibt: TLS
// verschlüsselt, und der SHA-256 aus dem Manifest schützt gegen abgeschnittene
// oder verfälschte Downloads auf dem Weg vom CDN. Gegen einen aktiven Angreifer
// im Netz, der auch das Manifest austauscht, schützt er NICHT.
//
// Nur HTTPS: ein Redirect auf http:// wird abgelehnt, es gibt keinen Fallback.
//
// Speicher (gemessen ~26 kB freier Heap im Leerlauf, ~14 kB bei 4 parallelen
// HTTP-Verbindungen; geteilt mit MQTT, Sensoren und Webserver):
//   RunContext   3296 B (sizeof im Build), nur während eines Laufs (calloc/free)
//   TLS          pro Verbindung: BearSSL-Stack (StackThunk, 6200 B) +
//                br_ssl_client_context + Empfangs-/Sendepuffer. BearSSL muss
//                jeden TLS-Record komplett im Empfangspuffer haben.
//                Gemessen am 2026-09-27 (openssl s_client -maxfraglen 512 / -msg):
//                - github.com bestätigt die Max-Fragment-Length-Extension (MFLN):
//                  setBufferSizes(512, 512) genügt für die Redirect-Hops.
//                - Das Asset-CDN release-assets.githubusercontent.com (Fastly)
//                  kennt KEIN MFLN. Ein voller Download kommt dort in
//                  16400-B-Records - dafür bräuchte es 16 kB + 325 B am Stück,
//                  und das gibt der Heap nicht her. Bei Range-Requests ist ein
//                  Record dagegen nie größer als der Body einer Range + 16 B
//                  (Details bei RANGE_LEN). Größter Handshake-Record: das
//                  Zertifikat mit 4145 B.
//                Deshalb: zuerst (512, 512); scheitert der Handshake mit einem
//                BearSSL-Fehler (Record passt nicht), einmal mit
//                (TLS_RX_NO_MFLN, 512), und die Assets werden immer in Ranges à
//                RANGE_LEN geholt. Der Host ohne MFLN wird für den Rest des Laufs
//                gemerkt (kein zweiter Fehlversuch pro Asset). Das Verhalten des
//                CDN ist beobachtet, nicht zugesichert: schickt es doch einen
//                größeren Record, scheitert der Download mit einer Fehlermeldung,
//                der Flash bleibt dabei unangetastet bzw. der Updater wird
//                zurückgesetzt.
//   Images       nie am Stück im RAM: max. ein Chunk (1460 B) hier, max. ein
//                Flash-Sektor (4 kB) im Updater.
//
// Blockieren: connect() blockiert - DNS (Core-Default bis 10 s), TCP-Aufbau und
// TLS-Handshake (bis 15 s, Default des Kontexts; Stream::setTimeout() des
// Wrappers erreicht den Kontext nicht). Der Core ruft dabei optimistic_yield()
// auf (_run_until), der Watchdog wird also bedient und der AsyncWebServer
// (lwIP-Kontext) beantwortet /api/update/status weiter; nur sensorsLoop() und
// mqttHaLoop() pausieren für die Dauer eines Handshakes (ECDHE auf 80 MHz,
// typisch 1-2 s, auf diesem Gerät nicht gemessen). Alles andere ist
// nicht-blockierend: read() liefert nur, was schon da ist, höchstens
// TICK_BUDGET_MS pro Takt.
// ---------------------------------------------------------------------------

// Stabile URL, zeigt immer auf das neueste Release; GitHub antwortet mit 302 auf
// .../releases/download/v<version>/manifest.json und das wiederum mit 302 aufs CDN.
static const char MANIFEST_URL[] PROGMEM = "https://github.com/RoccoRakete/PresenceTrack/releases/latest/download/manifest.json";

// latest -> v<version> -> CDN sind 2 Hops, 3 lassen einen Zwischenschritt Luft.
static const uint8_t MAX_REDIRECTS = 3;
// Größe von Update.write()-Stücken und Lesepuffer; dieselbe Stückelung wie beim
// Datei-Upload (AsyncWebServer liefert max. 1460 B, eine TCP-MSS).
static const size_t CHUNK_LEN = 1460;
// Location des CDN-Redirects gemessen am 2026-09-27: 930 Zeichen, davon 892
// Pfad + signierte Query (sp/sv/se/sig/jwt). Reserve für längere Tokens.
static const size_t URL_PATH_MAX_LEN = 1152;
// "release-assets.githubusercontent.com" = 36 Zeichen
static const size_t HOST_MAX_LEN = 48;
// firmware.url/filesystem.url laut Vertrag ".../releases/download/v0.3.0/littlefs.bin", ~85 Zeichen
static const size_t ASSET_URL_MAX_LEN = 128;
static const size_t SHA256_LEN = 32;
// Range-Größe für Assets. Gemessen am 2026-09-27 mit 40 Ranges hintereinander
// auf einer Keep-Alive-Verbindung: die Antwort-Header kommen immer in einem
// eigenen Record (~946 B), der Body anfangs in Records <= 1395 B, nach einigen
// zehn kB aber am Stück - Range-Länge + 16 B (4096 -> 4112, 8192 -> 8208). Der
// Body einer Range muss also in den Empfangspuffer (TLS_RX_NO_MFLN = 4608 B
// Klartext) passen; 8 kB scheiterten im Test nach 56 kB. 1 MB littlefs.bin =
// 250 Requests auf einer Verbindung, je ein RTT (~30 ms) extra.
static const uint32_t RANGE_LEN = 4096;

// Taktbudget: danach kommen sensorsLoop()/mqttHaLoop() wieder dran. Ein
// Flash-Sektor (Erase + Write) kostet ~30-50 ms, das Budget lässt also etwa
// einen Sektor pro Takt zu.
static const unsigned long TICK_BUDGET_MS = 40;
// Vom gesendeten Request bis zum Ende der Header; GitHub/CDN antworten in <1 s.
static const unsigned long HEADER_TIMEOUT_MS = 15000;
// Keine Body-Bytes mehr: Verbindung gilt als tot.
static const unsigned long BODY_IDLE_TIMEOUT_MS = 15000;

// TLS-Puffer (siehe oben). Die Overheads stammen aus WiFiClientSecureCtx::
// setBufferSizes() (bearssl ssl_engine.c, dort nicht exportiert).
static const int TLS_RX_MFLN = 512;
// Zertifikats-Record des CDN 4145 B + 463 B Luft; der Body einer Range
// (RANGE_LEN = 4096 B, ein Record) passt ebenfalls. Mehr Luft gibt der Heap nicht her:
// Bilanz am CDN-Hop 6200 (StackThunk) + 3408 (br_ssl_client_context, sizeof
// im Build) + 4608+325 + 512+85 = 15138 B, dazu RunContext 3296 B, bei ~26 kB
// freiem Heap im Leerlauf. Wird die Zertifikatskette des CDN länger, scheitert
// der Handshake mit einer Fehlermeldung - dann hier erhöhen, falls der Heap es
// zulässt.
static const int TLS_RX_NO_MFLN = 4608;
static const int TLS_TX = 512;
static const uint32_t TLS_IN_OVERHEAD = 325;
static const uint32_t TLS_OUT_OVERHEAD = 85;
// StackThunk.cpp: _stackSize = 6200/4 Worte, wird mit dem letzten Client wieder freigegeben
static const uint32_t TLS_STACK_THUNK_BYTES = 6200;
// Muss nach dem TLS-Aufbau frei bleiben: der Webserver beantwortet währenddessen
// /api/update/status (~2 kB pro Verbindung; während eines Laufs lässt er nur
// FW_UPDATE_HTTP_CONNECTIONS = 2 Verbindungen zu, daher weniger als
// RESPONSE_HEAP_RESERVE = 6144 in web_server.cpp für 4 Verbindungen), MQTT
// publiziert weiter. Ein fehlgeschlagenes `new` in BearSSL/lwIP ist auf dem
// ESP8266 ein Neustart, kein Fehlercode.
static const uint32_t TLS_HEAP_RESERVE = 4096;

enum class Job : uint8_t { Check, Install };
enum class Fetch : uint8_t { Manifest, Firmware, Filesystem };
enum class Phase : uint8_t { Connect, Headers, Body };
enum class Step : uint8_t { Continue, Failed, Finished };
enum class HdrState : uint8_t { StatusLine, Name, ValueStart, Value, Done };
enum class HdrField : uint8_t { Other, Location, ContentLength, ContentRange, TransferEncoding, Connection };

struct Asset {
    uint32_t size;
    uint8_t sha256[SHA256_LEN];
    char url[ASSET_URL_MAX_LEN];
};

// Antwortkopf, Zeichen für Zeichen geparst: GitHubs 302 bringt u.a. eine
// 3,7 kB lange Content-Security-Policy mit (gemessen 2026-09-27), die nirgends
// hin kopiert, sondern nur überlesen wird. Nur Location wird vollständig
// aufgehoben (direkt in RunContext::path), alles andere passt in value[].
struct HeaderParser {
    HdrState state;
    HdrField field;
    bool nameOverflow;
    bool locationSeen;
    bool locationTooLong;
    bool chunked;
    bool connectionClose; // "Connection: close": für die nächste Range neu verbinden
    bool rangeSeen;
    uint8_t nameLen;
    uint8_t valueLen;
    uint16_t pathLen;
    int status;
    int32_t contentLength; // -1 = nicht gesendet
    uint32_t rangeFirst;   // Content-Range: bytes <first>-<last>/<total>
    uint32_t rangeLast;
    uint32_t rangeTotal;
    char name[20];         // "transfer-encoding" = 17 Zeichen, längere Namen interessieren nicht
    char value[40];        // Statuszeile ("HTTP/1.1 302 Found") bzw. Wert eines bekannten Headers
};

// Alles, was ein Lauf braucht, in einem Block: wird beim Start mit calloc()
// angelegt und am Ende freigegeben, kostet im Leerlauf also keinen Heap. Nur
// Plain Data (calloc/free, keine Konstruktoren).
struct RunContext {
    WiFiClientSecure *client;
    Job job;
    Fetch fetch;
    Phase phase;
    uint8_t hops;
    bool keepAlive;      // die Verbindung darf die nächste Range tragen
    bool updateStarted;  // Update.begin() für das aktuelle Asset ist durch
    bool fsTouched;      // LittleFS ist ausgehängt (close_all_fs)
    bool fsWritten;      // Update.begin(U_FS) ist durch: die Partition ist (teilweise) überschrieben
    bool firmwareStaged; // Firmware-Update.end() war erfolgreich, eboot kopiert beim nächsten Boot
    uint16_t port;
    unsigned long phaseStartMs;
    unsigned long lastDataMs;
    uint32_t received; // verarbeitete Body-Bytes des aktuellen Fetches (= Offset im Asset)
    uint32_t bodyEnd;  // Offset hinter dem Body der aktuellen Antwort (Ende der Range)
    size_t fill;       // Bytes in chunk, noch nicht verarbeitet
    HeaderParser hdr;
    br_sha256_context sha;
    char expectedVersion[FW_VERSION_MAX_LEN];
    char host[HOST_MAX_LEN];
    char noMflnHost[HOST_MAX_LEN]; // Host ohne MFLN: gleich mit dem 16-kB-Puffer verbinden
    char path[URL_PATH_MAX_LEN];   // Pfad + Query des aktuellen Requests, danach Ziel der Location
    uint8_t chunk[CHUNK_LEN];      // Manifest-Body bzw. aktueller Asset-Chunk
    Asset firmware;
    Asset filesystem;
};

static AppConfig *s_cfg = nullptr;
static RunContext *s_run = nullptr;
static FwUpdateState s_state = FwUpdateState::Idle;
static FwUpdateTarget s_target = FwUpdateTarget::None;
static char s_version[FW_VERSION_MAX_LEN] = "";
static uint32_t s_bytesDone = 0;  // über beide Assets eines "both"-Laufs summiert
static uint32_t s_bytesTotal = 0; // firmware.size (+ filesystem.size)
static char s_error[176] = ""; // längste Meldung mit beiden Hinweisen aus failRun() ~170 Zeichen
static FwManifestOutcome s_outcome = FwManifestOutcome::Pending;
static FwManifestInfo s_manifest = {};
static bool s_abortRequested = false;

// Hält nur die erste Meldung fest: Folgefehler (z.B. beim Aufräumen) würden die
// eigentliche Ursache verdecken - gleiches Prinzip wie otaSetError() im Webserver.
//
// Formatstrings per PSTR im Flash: als normale Literale lagen die Meldungen
// dieses Moduls im DRAM (.rodata, im Build gemessen ~2,7 kB) und fehlten dem
// Heap, der fürs TLS ohnehin knapp ist. Das snprintf im toten Zweig behält die
// printf-Formatprüfung des Compilers (für PSTR kann er sie nicht).
#define setError(fmt, ...)                                  \
    do {                                                    \
        if (false) snprintf(nullptr, 0, fmt, ##__VA_ARGS__); \
        setErrorP(PSTR(fmt), ##__VA_ARGS__);                \
    } while (0)

static void setErrorP(PGM_P fmt, ...) {
    if (s_error[0]) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf_P(s_error, sizeof(s_error), fmt, args);
    va_end(args);
}

// Hängt einen Hinweis an die schon gesetzte Meldung an (gekürzt, wenn voll).
static void appendErrorP(PGM_P text) {
    const size_t len = strlen(s_error);
    strncpy_P(s_error + len, text, sizeof(s_error) - len - 1);
    s_error[sizeof(s_error) - 1] = '\0';
}

static const char *fetchName(Fetch f) {
    return f == Fetch::Manifest ? "manifest.json" : f == Fetch::Firmware ? "firmware.bin" : "littlefs.bin";
}

// ---------------------------------------------------------------------------
// Versionen: gepunktet numerisch, optionales führendes "v", fehlende Segmente = 0
// ("1.2" == "1.2.0"). Drei Segmente genügen; ein viertes oder Suffixe wie
// "-rc1" machen die Version ungültig, statt stillschweigend falsch zu vergleichen.
// ---------------------------------------------------------------------------

static const uint8_t VERSION_SEGMENTS = 3;

static bool parseVersion(const char *s, uint32_t seg[VERSION_SEGMENTS]) {
    if (!s) return false;
    if (*s == 'v' || *s == 'V') s++;
    for (uint8_t i = 0; i < VERSION_SEGMENTS; i++) seg[i] = 0;
    for (uint8_t n = 0; n < VERSION_SEGMENTS; n++) {
        if (!isdigit((unsigned char)*s)) return false;
        uint32_t v = 0;
        for (uint8_t digits = 0; isdigit((unsigned char)*s); digits++, s++) {
            if (digits == 5) return false; // > 99999: kein ernst gemeintes Segment
            v = v * 10 + (*s - '0');
        }
        seg[n] = v;
        if (*s == '\0') return true;
        if (*s != '.') return false;
        s++;
    }
    return false; // mehr als VERSION_SEGMENTS Segmente
}

// <0, 0, >0 wie strcmp. Beide Versionen müssen parseVersion() bestehen.
static int compareVersions(const char *a, const char *b) {
    uint32_t sa[VERSION_SEGMENTS], sb[VERSION_SEGMENTS];
    parseVersion(a, sa);
    parseVersion(b, sb);
    for (uint8_t i = 0; i < VERSION_SEGMENTS; i++) {
        if (sa[i] != sb[i]) return sa[i] < sb[i] ? -1 : 1;
    }
    return 0;
}

bool firmwareUpdateVersionValid(const char *s) {
    uint32_t seg[VERSION_SEGMENTS];
    return s && strlen(s) < FW_VERSION_MAX_LEN && parseVersion(s, seg);
}

// ---------------------------------------------------------------------------
// HTTPS-GET mit Redirects
// ---------------------------------------------------------------------------

static void closeClient(RunContext &r) {
    if (!r.client) return;
    r.client->stop();
    delete r.client;
    r.client = nullptr;
}

// Setzt host/port/path aus einer absoluten https-URL oder einem absoluten Pfad
// ("/..." = gleicher Host). url darf auf r.path selbst zeigen (Location wird
// dorthin geparst): der Host wird zuerst herauskopiert, der Pfad dann mit
// memmove() an den Anfang geschoben.
static bool setUrl(RunContext &r, const char *url) {
    if (url[0] == '/') {
        if (url != r.path && strlcpy(r.path, url, sizeof(r.path)) >= sizeof(r.path)) {
            setError("URL path longer than %u bytes", (unsigned)sizeof(r.path) - 1);
            return false;
        }
        return true;
    }
    if (strncasecmp(url, "https://", 8) != 0) {
        if (strncasecmp(url, "http://", 7) == 0) {
            setError("refusing plain-HTTP URL %.60s", url);
        } else {
            setError("unsupported URL %.60s", url);
        }
        return false;
    }
    const char *hostStart = url + 8;
    size_t hostLen = strcspn(hostStart, ":/?#");
    if (hostLen == 0 || hostLen >= sizeof(r.host)) {
        setError("invalid host in URL %.60s", url);
        return false;
    }
    memcpy(r.host, hostStart, hostLen);
    r.host[hostLen] = '\0';
    const char *p = hostStart + hostLen;
    r.port = 443;
    if (*p == ':') {
        char *end = nullptr;
        unsigned long port = strtoul(p + 1, &end, 10);
        if (end == p + 1 || port == 0 || port > 65535) {
            setError("invalid port in URL %.60s", url);
            return false;
        }
        r.port = port;
        p = end;
    }
    if (*p == '\0') {
        strcpy(r.path, "/");
        return true;
    }
    // "?query" ohne Pfad bekommt ein "/" davor
    size_t lead = *p == '/' ? 0 : 1;
    size_t len = strlen(p);
    if (len + lead >= sizeof(r.path)) {
        setError("URL longer than %u bytes", (unsigned)sizeof(r.path) - 1);
        return false;
    }
    memmove(r.path + lead, p, len + 1);
    if (lead) r.path[0] = '/';
    return true;
}

static bool sendRequest(RunContext &r) {
    // In einem Stück in den (gerade leeren: vor dem Request liegt nie Body darin)
    // Chunk-Puffer: jeder write() schickt beim Core einen eigenen TLS-Record samt
    // flush(). Längster Request: Pfad 1151 + Host 47 + ~200 B Rest < CHUNK_LEN.
    char port[8] = "";
    if (r.port != 443) snprintf(port, sizeof(port), ":%u", r.port);
    // Assets immer als Range ab dem aktuellen Offset (Begründung: Kopfkommentar,
    // Speicher). github.com ignoriert sie bei seinem 302, das CDN antwortet mit 206.
    char range[48] = "";
    if (r.fetch != Fetch::Manifest) {
        const Asset &a = r.fetch == Fetch::Firmware ? r.firmware : r.filesystem;
        snprintf_P(range, sizeof(range), PSTR("Range: bytes=%u-%u\r\n"), r.received,
                   std::min(r.received + RANGE_LEN, a.size) - 1);
    }
    char *req = reinterpret_cast<char *>(r.chunk);
    // identity: das Gerät streamt die Bytes 1:1 in den Flash, gzip/chunked kann es nicht
    int n = snprintf_P(req, sizeof(r.chunk),
                       PSTR("GET %s HTTP/1.1\r\nHost: %s%s\r\nUser-Agent: PresenceTrack/" FIRMWARE_VERSION
                            "\r\nAccept: */*\r\nAccept-Encoding: identity\r\n%sConnection: %s\r\n\r\n"),
                       r.path, r.host, port, range, r.fetch == Fetch::Manifest ? "close" : "keep-alive");
    // Kein setError() hier: auf einer Keep-Alive-Verbindung ist ein Fehlschlag
    // nur ein Grund zum Neuverbinden (nextRange)
    if (n < 0 || (size_t)n >= sizeof(r.chunk)) return false;
    return r.client->write(r.chunk, n) == (size_t)n;
}

static bool isRedirect(int status) {
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

static void resetHeaderParser(HeaderParser &h) {
    memset(&h, 0, sizeof(h));
    h.state = HdrState::StatusLine;
    h.contentLength = -1;
}

static HdrField classifyHeader(const HeaderParser &h) {
    if (h.nameOverflow) return HdrField::Other;
    // Location nur bei Redirects: in einer 206-Antwort darf sie den Pfad nicht
    // überschreiben, der Pfad trägt die nächste Range bzw. den Reconnect.
    if (strcmp(h.name, "location") == 0) return isRedirect(h.status) ? HdrField::Location : HdrField::Other;
    if (strcmp(h.name, "content-length") == 0) return HdrField::ContentLength;
    if (strcmp(h.name, "content-range") == 0) return HdrField::ContentRange;
    if (strcmp(h.name, "transfer-encoding") == 0) return HdrField::TransferEncoding;
    if (strcmp(h.name, "connection") == 0) return HdrField::Connection;
    return HdrField::Other;
}

// "bytes 0-8191/1024000" -> first/last/total. Andere Formen ("bytes */1024000") -> false.
static bool parseContentRange(HeaderParser &h) {
    if (strncmp(h.value, "bytes ", 6) != 0) return false;
    char *p = h.value + 6;
    uint32_t v[3];
    const char seps[3] = {'-', '/', '\0'};
    for (uint8_t i = 0; i < 3; i++) {
        if (!isdigit((unsigned char)*p)) return false;
        char *end = nullptr;
        v[i] = strtoul(p, &end, 10);
        if (*end != seps[i]) return false;
        p = end + 1;
    }
    h.rangeFirst = v[0];
    h.rangeLast = v[1];
    h.rangeTotal = v[2];
    return true;
}

static void finishHeaderValue(RunContext &r) {
    HeaderParser &h = r.hdr;
    if (h.field == HdrField::Location) {
        while (h.pathLen > 0 && (r.path[h.pathLen - 1] == ' ' || r.path[h.pathLen - 1] == '\t')) h.pathLen--;
        r.path[h.pathLen] = '\0';
        h.locationSeen = true;
        return;
    }
    while (h.valueLen > 0 && (h.value[h.valueLen - 1] == ' ' || h.value[h.valueLen - 1] == '\t')) h.valueLen--;
    h.value[h.valueLen] = '\0';
    if (h.field == HdrField::ContentLength) {
        char *end = nullptr;
        unsigned long v = strtoul(h.value, &end, 10);
        // Größer als jedes zulässige Asset ist ohnehin ein Fehler; so passt es in int32_t
        if (isdigit((unsigned char)h.value[0]) && *end == '\0' && v <= 0x7fffffffUL) h.contentLength = v;
    } else if (h.field == HdrField::ContentRange) {
        h.rangeSeen = parseContentRange(h);
    } else if (h.field == HdrField::TransferEncoding || h.field == HdrField::Connection) {
        for (uint8_t i = 0; i < h.valueLen; i++) h.value[i] = tolower((unsigned char)h.value[i]);
        if (h.field == HdrField::TransferEncoding && strstr(h.value, "chunked")) h.chunked = true;
        if (h.field == HdrField::Connection && strstr(h.value, "close")) h.connectionClose = true;
    }
}

// Ein Byte des Antwortkopfs. false bei einer unbrauchbaren Statuszeile.
static bool feedHeader(RunContext &r, char c) {
    HeaderParser &h = r.hdr;
    if (c == '\r') return true;
    switch (h.state) {
        case HdrState::StatusLine:
            if (c != '\n') {
                if (h.valueLen < sizeof(h.value) - 1) h.value[h.valueLen++] = c;
                return true;
            }
            h.value[h.valueLen] = '\0';
            // "HTTP/1.1 302 Found" - auch HTTP/1.0 wird akzeptiert
            if (strncmp(h.value, "HTTP/1.", 7) != 0 || h.valueLen < 12 || h.value[8] != ' ' ||
                !isdigit((unsigned char)h.value[9]) || !isdigit((unsigned char)h.value[10]) ||
                !isdigit((unsigned char)h.value[11])) {
                setError("invalid HTTP status line from %s", r.host);
                return false;
            }
            h.status = (h.value[9] - '0') * 100 + (h.value[10] - '0') * 10 + (h.value[11] - '0');
            h.state = HdrState::Name;
            return true;
        case HdrState::Name:
            if (c == '\n') {
                // Leerzeile = Ende der Header; eine Zeile ohne ':' wird ignoriert
                if (h.nameLen == 0 && !h.nameOverflow) h.state = HdrState::Done;
                h.nameLen = 0;
                h.nameOverflow = false;
                return true;
            }
            if (c == ':') {
                h.name[h.nameLen] = '\0';
                h.field = classifyHeader(h);
                h.valueLen = 0;
                if (h.field == HdrField::Location) {
                    h.pathLen = 0;
                    h.locationTooLong = false;
                }
                h.state = HdrState::ValueStart;
                return true;
            }
            if (h.nameLen < sizeof(h.name) - 1) {
                h.name[h.nameLen++] = tolower((unsigned char)c);
            } else {
                h.nameOverflow = true;
            }
            return true;
        case HdrState::ValueStart:
            if (c == ' ' || c == '\t') return true;
            h.state = HdrState::Value;
            [[fallthrough]];
        case HdrState::Value:
            if (c == '\n') {
                finishHeaderValue(r);
                h.state = HdrState::Name;
                h.nameLen = 0;
                h.nameOverflow = false;
                return true;
            }
            if (h.field == HdrField::Location) {
                if (h.pathLen < sizeof(r.path) - 1) {
                    r.path[h.pathLen++] = c;
                } else {
                    h.locationTooLong = true;
                }
            } else if (h.field != HdrField::Other && h.valueLen < sizeof(h.value) - 1) {
                h.value[h.valueLen++] = c;
            }
            return true;
        case HdrState::Done:
            return true;
    }
    return true;
}

static bool startFetch(RunContext &r, Fetch fetch) {
    r.fetch = fetch;
    r.hops = 0;
    r.keepAlive = false;
    r.received = 0;
    r.bodyEnd = 0;
    r.fill = 0;
    r.updateStarted = false;
    br_sha256_init(&r.sha);
    r.phase = Phase::Connect;
    if (fetch == Fetch::Manifest) {
        // MANIFEST_URL liegt im Flash; setUrl() darf auf r.path selbst arbeiten
        strncpy_P(r.path, MANIFEST_URL, sizeof(r.path) - 1);
        return setUrl(r, r.path);
    }
    s_state = FwUpdateState::Downloading;
    return setUrl(r, fetch == Fetch::Firmware ? r.firmware.url : r.filesystem.url);
}

static Step stepConnect(RunContext &r) {
    if (WiFi.status() != WL_CONNECTED) {
        setError("Wi-Fi not connected");
        return Step::Failed;
    }
    const bool full = strcmp(r.host, r.noMflnHost) == 0;
    const int rx = full ? TLS_RX_NO_MFLN : TLS_RX_MFLN;
    // Vorab prüfen statt es auf BearSSL ankommen zu lassen: der Core legt den
    // Client-Kontext mit make_shared (normales `new`) an, und das panict bei OOM.
    const uint32_t need = TLS_STACK_THUNK_BYTES + sizeof(br_ssl_client_context) + rx + TLS_IN_OVERHEAD +
                          TLS_TX + TLS_OUT_OVERHEAD + TLS_HEAP_RESERVE;
    const uint32_t freeHeap = ESP.getFreeHeap();
    if (freeHeap < need || ESP.getMaxFreeBlockSize() < rx + TLS_IN_OVERHEAD) {
        setError("not enough heap for TLS to %s: %u B free (largest block %u B), %u B needed",
                 r.host, freeHeap, ESP.getMaxFreeBlockSize(), need);
        return Step::Failed;
    }
    r.client = new (std::nothrow) WiFiClientSecure();
    if (!r.client) {
        setError("out of memory");
        return Step::Failed;
    }
    r.client->setInsecure(); // Begründung siehe Kopfkommentar
    r.client->setBufferSizes(rx, TLS_TX);
    if (!r.client->connect(r.host, r.port)) {
        // > 0: BearSSL-Protokollfehler (TCP stand also); 0: DNS/TCP; -1000: OOM
        int sslError = r.client->getLastSSLError();
        closeClient(r);
        if (!full && sslError > 0) {
            // Typisch für einen Server ohne MFLN: sein 4-kB-Zertifikats-Record passt
            // nicht in den 512-B-Puffer. Nächster Takt, gleicher Hop, größerer Puffer.
            strlcpy(r.noMflnHost, r.host, sizeof(r.noMflnHost));
            return Step::Continue;
        }
        setError("connection to %s:%u failed (BearSSL error %d)", r.host, r.port, sslError);
        return Step::Failed;
    }
    if (!sendRequest(r)) {
        setError("sending the request to %s failed", r.host);
        return Step::Failed;
    }
    resetHeaderParser(r.hdr);
    r.fill = 0;
    r.phase = Phase::Headers;
    r.phaseStartMs = millis();
    return Step::Continue;
}

static Step onHeadersDone(RunContext &r) {
    HeaderParser &h = r.hdr;
    if (isRedirect(h.status)) {
        if (h.locationTooLong) {
            setError("redirect URL from %s longer than %u bytes", r.host, (unsigned)sizeof(r.path) - 1);
            return Step::Failed;
        }
        if (!h.locationSeen) {
            setError("HTTP %d from %s without Location", h.status, r.host);
            return Step::Failed;
        }
        if (++r.hops > MAX_REDIRECTS) {
            setError("%s: more than %u redirects", fetchName(r.fetch), MAX_REDIRECTS);
            return Step::Failed;
        }
        closeClient(r);
        if (!setUrl(r, r.path)) return Step::Failed;
        r.phase = Phase::Connect;
        return Step::Continue;
    }
    // Die exakte Länge muss vorab feststehen (Update.begin(size) bzw. Manifest-Puffer)
    if (h.chunked) {
        setError("%s: chunked response from %s not supported", fetchName(r.fetch), r.host);
        return Step::Failed;
    }
    if (r.fetch == Fetch::Manifest) {
        if (h.status != 200) {
            setError("manifest.json: HTTP %d from %s", h.status, r.host);
            return Step::Failed;
        }
        if (h.contentLength <= 0 || (size_t)h.contentLength > sizeof(r.chunk)) {
            setError("manifest.json: Content-Length %d, expected 1..%u B", h.contentLength, (unsigned)sizeof(r.chunk));
            return Step::Failed;
        }
        r.bodyEnd = h.contentLength;
    } else {
        const Asset &a = r.fetch == Fetch::Firmware ? r.firmware : r.filesystem;
        if (h.status == 206) {
            // Genau ab dem angefragten Offset, und die Gesamtgröße muss die aus dem
            // Manifest sein - sonst liegt auf dem CDN ein anderes Asset.
            if (!h.rangeSeen || h.rangeFirst != r.received || h.rangeLast < h.rangeFirst ||
                h.rangeLast >= a.size || h.rangeTotal != a.size ||
                (h.contentLength >= 0 && (uint32_t)h.contentLength != h.rangeLast - h.rangeFirst + 1)) {
                setError("%s: unexpected Content-Range from %s at offset %u (manifest size %u B)",
                         fetchName(r.fetch), r.host, r.received, a.size);
                return Step::Failed;
            }
            r.bodyEnd = h.rangeLast + 1;
        } else if (h.status == 200 && r.received == 0) {
            // Server ohne Range-Support: dann eben am Stück (klappt nur, wenn seine
            // Records in den Empfangspuffer passen, z.B. mit MFLN)
            if (h.contentLength < 0 || (uint32_t)h.contentLength != a.size) {
                setError("%s is %d B, the manifest says %u B", fetchName(r.fetch), h.contentLength, a.size);
                return Step::Failed;
            }
            r.bodyEnd = a.size;
        } else {
            setError("%s: HTTP %d from %s at offset %u", fetchName(r.fetch), h.status, r.host, r.received);
            return Step::Failed;
        }
    }
    r.keepAlive = !h.connectionClose;
    // Was schon hinter den Headern im Puffer lag, ist Body; mehr als angekündigt wird verworfen
    if (r.fill > r.bodyEnd - r.received) r.fill = r.bodyEnd - r.received;
    r.phase = Phase::Body;
    r.lastDataMs = millis();
    return Step::Continue;
}

// Nächste Range auf derselben Verbindung, oder neu verbinden, wenn der Server
// sie geschlossen hat (Pfad und Host bleiben: die signierte CDN-URL gilt weiter).
// Ohne Obergrenze für Reconnects: hierher kommt ein Lauf nur nach einer
// vollständig gelieferten Range, jede Verbindung bringt also Fortschritt, und
// mehr als size / RANGE_LEN (125 für littlefs.bin) können es nicht werden. Ein
// Server, der jede Antwort mit "Connection: close" beendet, kostet dann einen
// Handshake pro Range - langsam, aber korrekt. Bricht die Verbindung mitten in
// einer Range ab, scheitert der Download (fillChunk).
static Step nextRange(RunContext &r) {
    if (r.keepAlive && r.client && r.client->connected()) {
        if (sendRequest(r)) {
            resetHeaderParser(r.hdr);
            r.phase = Phase::Headers;
            r.phaseStartMs = millis();
            return Step::Continue;
        }
        // Senden gescheitert: wie eine vom Server geschlossene Verbindung behandeln
    }
    closeClient(r);
    r.phase = Phase::Connect;
    return Step::Continue;
}

static Step stepHeaders(RunContext &r) {
    if (millis() - r.phaseStartMs > HEADER_TIMEOUT_MS) {
        setError("%s: no complete HTTP response from %s within %lu s", fetchName(r.fetch), r.host, HEADER_TIMEOUT_MS / 1000);
        return Step::Failed;
    }
    const unsigned long start = millis();
    while (millis() - start < TICK_BUDGET_MS) {
        int n = r.client->read(r.chunk, sizeof(r.chunk));
        if (n == 0) return Step::Continue;
        if (n < 0) {
            setError("%s: %s closed the connection during the headers", fetchName(r.fetch), r.host);
            return Step::Failed;
        }
        for (int i = 0; i < n; i++) {
            if (!feedHeader(r, (char)r.chunk[i])) return Step::Failed;
            if (r.hdr.state == HdrState::Done) {
                r.fill = n - i - 1;
                memmove(r.chunk, r.chunk + i + 1, r.fill);
                return onHeadersDone(r);
            }
        }
    }
    return Step::Continue;
}

// Liest in r.chunk bis `want` Bytes darin liegen. Continue = noch nicht voll
// (später weiter), Finished = voll, Failed = Verbindung weg/abgelaufen.
static Step fillChunk(RunContext &r, size_t want, uint32_t total) {
    while (r.fill < want) {
        int n = r.client->read(r.chunk + r.fill, want - r.fill);
        if (n == 0) {
            if (millis() - r.lastDataMs > BODY_IDLE_TIMEOUT_MS) {
                setError("%s: download stalled at %u of %u bytes", fetchName(r.fetch), (unsigned)(r.received + r.fill), total);
                return Step::Failed;
            }
            return Step::Continue;
        }
        if (n < 0) {
            setError("%s: connection closed at %u of %u bytes", fetchName(r.fetch), (unsigned)(r.received + r.fill), total);
            return Step::Failed;
        }
        r.fill += n;
        r.lastDataMs = millis();
    }
    return Step::Finished;
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

static int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower((unsigned char)c);
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

// Vertrag: 64 Hex-Ziffern, klein; Großbuchstaben werden trotzdem akzeptiert.
static bool parseSha256(const char *s, uint8_t out[SHA256_LEN]) {
    if (!s || strlen(s) != SHA256_LEN * 2) return false;
    for (size_t i = 0; i < SHA256_LEN; i++) {
        int hi = hexValue(s[2 * i]), lo = hexValue(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return true;
}

// Pflichtfelder eines Assets: file, size, url, sha256.
static bool parseAsset(JsonObjectConst root, const char *key, Asset &a) {
    JsonObjectConst o = root[key].as<JsonObjectConst>();
    if (o.isNull()) {
        setError("manifest: %s missing or not an object", key);
        return false;
    }
    const char *file = o["file"].as<const char *>();
    const char *url = o["url"].as<const char *>();
    JsonVariantConst size = o["size"];
    if (!file || !file[0]) {
        setError("manifest: %s.file missing", key);
        return false;
    }
    // Pflicht, kein Fallback auf "unbekannt": ohne exakte Größe könnte ein
    // abgeschnittener Download nicht am strikten Update.end() scheitern.
    if (!size.is<uint32_t>() || size.as<uint32_t>() == 0) {
        setError("manifest: %s.size missing or not a positive integer", key);
        return false;
    }
    if (!url || strncmp(url, "https://", 8) != 0) {
        setError("manifest: %s.url must be an https:// URL", key);
        return false;
    }
    if (strlcpy(a.url, url, sizeof(a.url)) >= sizeof(a.url)) {
        setError("manifest: %s.url longer than %u bytes", key, (unsigned)sizeof(a.url) - 1);
        return false;
    }
    if (!parseSha256(o["sha256"].as<const char *>(), a.sha256)) {
        setError("manifest: %s.sha256 must be 64 hex digits", key);
        return false;
    }
    a.size = size.as<uint32_t>();
    return true;
}

// Liest das Manifest aus r.chunk (r.fill Bytes). Unbekannte Keys (tag, board,
// commit, built_at, künftige) überliest der Filter, ohne dafür Speicher zu belegen.
static bool parseManifest(RunContext &r) {
    JsonDocument filter;
    filter["version"] = true;
    for (const char *key : {"firmware", "filesystem"}) {
        JsonObject f = filter[key].to<JsonObject>();
        f["file"] = true;
        f["size"] = true;
        f["url"] = true;
        f["sha256"] = true;
    }
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, reinterpret_cast<const char *>(r.chunk), r.fill,
                                               DeserializationOption::Filter(filter));
    if (err) {
        setError("manifest: invalid JSON (%s)", err.c_str());
        return false;
    }
    if (!doc.is<JsonObjectConst>()) {
        setError("manifest: not a JSON object");
        return false;
    }
    JsonObjectConst root = doc.as<JsonObjectConst>();
    const char *version = root["version"].as<const char *>();
    if (!firmwareUpdateVersionValid(version)) {
        setError("manifest: version missing or not numeric (e.g. \"0.3.1\")");
        return false;
    }
    if (!parseAsset(root, "firmware", r.firmware) || !parseAsset(root, "filesystem", r.filesystem)) return false;
    // Größen gegen dieselben Grenzen wie beim Datei-Upload, bevor irgendetwas geladen wird
    const uint32_t maxFw = otaFirmwareMaxBytes();
    if (r.firmware.size > maxFw) {
        setError("firmware.bin too large: %u bytes, limit is %u bytes (%s)", r.firmware.size, maxFw, otaFirmwareLimitName());
        return false;
    }
    if (r.filesystem.size != FS_PHYS_SIZE) {
        setError("littlefs.bin is %u bytes, this partition takes exactly %u bytes - different flash layout?",
                 r.filesystem.size, (unsigned)FS_PHYS_SIZE);
        return false;
    }
    strlcpy(s_manifest.version, version, sizeof(s_manifest.version));
    s_manifest.firmwareSize = r.firmware.size;
    s_manifest.filesystemSize = r.filesystem.size;
    return true;
}

// ---------------------------------------------------------------------------
// Laufende Läufe beenden
// ---------------------------------------------------------------------------

// Idle heißt "kein Lauf": target/version/bytes eines beendeten Laufs gehören
// dann nicht mehr in den Status (bei error bleiben sie, sie beschreiben den Fehler).
static void setState(FwUpdateState state) {
    s_state = state;
    if (state != FwUpdateState::Idle) return;
    s_target = FwUpdateTarget::None;
    s_version[0] = '\0';
    s_bytesDone = 0;
    s_bytesTotal = 0;
}

static void endRun(FwUpdateState state) {
    if (s_run) {
        closeClient(*s_run);
        free(s_run);
        s_run = nullptr;
    }
    setState(state);
    s_abortRequested = false;
}

// Räumt nach einem Fehler oder Abbruch auf. Der Updater wird immer freigegeben:
// ein halb beschriebener Flash darf keinen weiteren Versuch bis zum nächsten
// Boot blockieren.
static void failRun() {
    RunContext &r = *s_run;
    const bool aborted = s_abortRequested;
    if (aborted) setError("aborted");
    closeClient(r);
    if (r.updateStarted && Update.isRunning()) {
        // Mit Restdaten setzt Update.end() den Updater nur zurück: kein
        // eboot-Kommando, das Firmware-Slot-Image bleibt wirkungslos.
        Update.end();
    }
    wifiPowerApplyConfig(s_cfg->wifi);
    if (r.fsTouched && !r.fsWritten) {
        // Noch nichts geschrieben: das alte Dateisystem ist intakt
        LittleFS.begin();
    } else if (r.fsWritten) {
        // Bewusst nicht wieder eingehängt (halbes Image). Die Recovery-Seite des
        // Webservers bleibt erreichbar und kann den Install erneut starten.
        appendErrorP(PSTR(" - filesystem half written, retry, do not reboot"));
    }
    if (r.firmwareStaged) appendErrorP(PSTR("; firmware staged for next boot"));
    if (s_outcome == FwManifestOutcome::Pending) {
        s_outcome = aborted ? FwManifestOutcome::Aborted : FwManifestOutcome::Failed;
    }
    Serial.printf("[update] %s\n", s_error);
    if (r.job == Job::Install) {
        eventLogPush(EventType::OtaUpdate, "GitHub update %s", aborted ? "aborted" : "failed");
    }
    // Ein gescheiterter check ist kein Gerätefehler: der Zustand geht wie im
    // Vertrag auf idle zurück, die Meldung steht in der check-Antwort.
    endRun(r.job == Job::Check ? FwUpdateState::Idle : FwUpdateState::Error);
}

static Step onManifest(RunContext &r) {
    closeClient(r);
    if (!parseManifest(r)) return Step::Failed;
    const int cmp = compareVersions(s_manifest.version, FIRMWARE_VERSION);
    if (r.job == Job::Check) {
        s_outcome = cmp > 0 ? FwManifestOutcome::UpdateAvailable : FwManifestOutcome::NoUpdate;
        endRun(FwUpdateState::Idle);
        return Step::Finished;
    }
    // Kein TOCTOU: installiert wird nur die Version, die der Client gesehen hat
    if (r.expectedVersion[0] && compareVersions(r.expectedVersion, s_manifest.version) != 0) {
        s_outcome = FwManifestOutcome::VersionMismatch;
        endRun(FwUpdateState::Idle);
        return Step::Finished;
    }
    if (cmp <= 0) {
        s_outcome = FwManifestOutcome::NoUpdate;
        endRun(FwUpdateState::Idle);
        return Step::Finished;
    }
    s_outcome = FwManifestOutcome::UpdateAvailable;
    strlcpy(s_version, s_manifest.version, sizeof(s_version));
    s_bytesDone = 0;
    s_bytesTotal = r.firmware.size + (s_target == FwUpdateTarget::Both ? r.filesystem.size : 0);
    eventLogPush(EventType::OtaUpdate, "GitHub update %s started", s_version);
    return startFetch(r, Fetch::Firmware) ? Step::Continue : Step::Failed;
}

static Step onAssetDone(RunContext &r) {
    closeClient(r);
    wifiPowerApplyConfig(s_cfg->wifi); // Update.begin() hat WIFI_NONE_SLEEP erzwungen
    if (r.fetch == Fetch::Firmware) {
        r.firmwareStaged = true;
        eventLogPush(EventType::OtaUpdate, "GitHub %s: firmware staged", s_version);
        if (s_target == FwUpdateTarget::Both) {
            return startFetch(r, Fetch::Filesystem) ? Step::Continue : Step::Failed;
        }
    } else {
        // littlefs.bin bringt nur data/ mit, keine /config.json: die Konfiguration
        // liegt noch vollständig im RAM und wird ins frische Image geschrieben.
        // Ohne das stünde das Gerät nach dem Neustart mit Werkseinstellungen da
        // (MQTT weg) - beim Datei-Upload übernimmt das Web-UI Backup/Restore.
        r.fsTouched = false;
        r.fsWritten = false;
        if (!LittleFS.begin() || !saveConfig(*s_cfg)) {
            // Kein Neustart: sonst ginge die Konfiguration verloren. Das Image ist
            // geschrieben, die Firmware vorgemerkt; der Nutzer kann jetzt noch
            // /api/config/backup sichern und dann selbst neu starten.
            setError("web UI updated, but the config could not be saved - download a backup, then reboot");
            return Step::Failed;
        }
        eventLogPush(EventType::OtaUpdate, "GitHub %s: web UI updated", s_version);
    }
    endRun(FwUpdateState::Rebooting);
    webServerScheduleReboot(false);
    return Step::Finished;
}

// Erster Chunk eines Assets: alles, was das Image ablehnen kann, läuft vor
// Update.begin(), also vor dem ersten Flash-Erase (für littlefs.bin auch vor
// dem Aushängen des Dateisystems).
static bool beginFlash(RunContext &r, const Asset &a) {
    if (Update.isRunning()) {
        setError("another update is already in progress");
        return false;
    }
    const bool fs = r.fetch == Fetch::Filesystem;
    if (!fs) {
        if (!otaHasFirmwareMagic(r.chunk, r.fill)) {
            setError("firmware.bin is not an ESP8266 firmware image (magic byte 0xE9 missing)");
            return false;
        }
    } else {
        uint32_t imageSize = 0;
        char err[128];
        if (!otaCheckLittleFsImage(r.chunk, r.fill, imageSize, err, sizeof(err))) {
            setError("littlefs.bin: %s", err);
            return false;
        }
        if (imageSize != a.size) {
            setError("littlefs.bin: superblock says %u bytes, the manifest %u bytes", imageSize, a.size);
            return false;
        }
    }
    // Anders als beim Datei-Upload (lwIP-Kontext) läuft das hier in loop():
    // yield() ist erlaubt und hält während der Sektor-Erases den Webserver am Laufen.
    Update.runAsync(false);
    if (fs) {
        // Wie beim Datei-Upload: aushängen, damit kein offener File-Handle oder
        // LittleFS-Cache in den Bereich schreibt, der gerade ersetzt wird.
        close_all_fs();
        r.fsTouched = true;
    }
    // Exakte Größe aus dem Manifest: ein abgeschnittener Download scheitert am
    // strikten Update.end(), statt ein halbes Image vorzumerken.
    if (!Update.begin(a.size, fs ? U_FS : U_FLASH)) {
        setError("Update.begin failed: %s", Update.getErrorString().c_str());
        return false;
    }
    r.updateStarted = true;
    if (fs) r.fsWritten = true;
    s_state = FwUpdateState::Flashing;
    return true;
}

// Verarbeitet einen vollen Chunk. Der SHA-256 wird geprüft, BEVOR der letzte
// Chunk geschrieben wird: solange noch Bytes fehlen, setzt Update.end() den
// Updater nur zurück. Wäre alles geschrieben, würde end() das Image bei einem
// Mismatch trotzdem vormerken (eboot-Kommando) - daher dieser Rückhalt.
static Step processChunk(RunContext &r, const Asset &a) {
    if (!r.updateStarted && !beginFlash(r, a)) return Step::Failed;
    br_sha256_update(&r.sha, r.chunk, r.fill);
    const bool last = r.received + r.fill == a.size;
    if (last) {
        uint8_t digest[SHA256_LEN];
        br_sha256_out(&r.sha, digest);
        if (memcmp(digest, a.sha256, SHA256_LEN) != 0) {
            setError("%s: SHA-256 mismatch, update discarded", fetchName(r.fetch));
            return Step::Failed;
        }
    }
    if (Update.write(r.chunk, r.fill) != r.fill) {
        setError("%s: flash write failed at %u bytes: %s", fetchName(r.fetch), r.received, Update.getErrorString().c_str());
        return Step::Failed;
    }
    r.received += r.fill;
    s_bytesDone += r.fill;
    r.fill = 0;
    if (!last) return Step::Continue;
    if (!Update.end(false)) {
        setError("%s: update verification failed: %s", fetchName(r.fetch), Update.getErrorString().c_str());
        return Step::Failed;
    }
    r.updateStarted = false;
    return onAssetDone(r);
}

static Step stepBody(RunContext &r) {
    if (r.fetch == Fetch::Manifest) {
        Step s = fillChunk(r, r.bodyEnd, r.bodyEnd);
        return s == Step::Finished ? onManifest(r) : s;
    }
    const Asset &a = r.fetch == Fetch::Firmware ? r.firmware : r.filesystem;
    const unsigned long start = millis();
    while (millis() - start < TICK_BUDGET_MS) {
        if (r.received == r.bodyEnd) return nextRange(r);
        // Chunks enden an Range-Grenzen (8192 ist kein Vielfaches von 1460);
        // Update.write() nimmt jede Länge, nur der erste Chunk muss >= 32 B sein.
        const size_t want = std::min<uint32_t>(CHUNK_LEN, r.bodyEnd - r.received);
        Step s = fillChunk(r, want, a.size);
        if (s != Step::Finished) return s;
        s = processChunk(r, a);
        // Asset fertig (nächster Fetch, Neustart) oder Fehler: nicht weiterlesen
        if (s != Step::Continue || r.phase != Phase::Body) return s;
    }
    return Step::Continue;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

static const char *stateName(FwUpdateState s) {
    switch (s) {
        case FwUpdateState::Idle: return "idle";
        case FwUpdateState::Checking: return "checking";
        case FwUpdateState::Downloading: return "downloading";
        case FwUpdateState::Flashing: return "flashing";
        case FwUpdateState::Rebooting: return "rebooting";
        case FwUpdateState::Error: return "error";
    }
    return "error";
}

static const char *targetName(FwUpdateTarget t) {
    return t == FwUpdateTarget::Firmware ? "firmware" : t == FwUpdateTarget::Both ? "both" : "";
}

bool firmwareUpdateParseTarget(const char *s, FwUpdateTarget &target) {
    if (!s) return false;
    if (strcmp(s, "firmware") == 0) {
        target = FwUpdateTarget::Firmware;
    } else if (strcmp(s, "both") == 0) {
        target = FwUpdateTarget::Both;
    } else {
        return false;
    }
    return true;
}

void firmwareUpdateBegin(AppConfig &cfg) {
    s_cfg = &cfg;
}

FwUpdateState firmwareUpdateState() {
    return s_state;
}

bool firmwareUpdateBusy() {
    return s_state == FwUpdateState::Checking || s_state == FwUpdateState::Downloading ||
           s_state == FwUpdateState::Flashing || s_state == FwUpdateState::Rebooting;
}

static bool startRun(Job job, FwUpdateTarget target, const char *expectedVersion) {
    if (s_run || firmwareUpdateBusy() || !s_cfg) return false;
    RunContext *r = static_cast<RunContext *>(calloc(1, sizeof(RunContext)));
    if (!r) return false;
    s_run = r;
    r->job = job;
    if (expectedVersion) strlcpy(r->expectedVersion, expectedVersion, sizeof(r->expectedVersion));
    s_error[0] = '\0';
    s_outcome = FwManifestOutcome::Pending;
    s_manifest = {};
    s_abortRequested = false;
    s_target = target;
    strlcpy(s_version, expectedVersion ? expectedVersion : "", sizeof(s_version));
    s_bytesDone = 0;
    s_bytesTotal = 0;
    s_state = FwUpdateState::Checking;
    startFetch(*r, Fetch::Manifest); // MANIFEST_URL ist gültig, kann nicht scheitern
    return true;
}

bool firmwareUpdateStartCheck() {
    return startRun(Job::Check, FwUpdateTarget::None, nullptr);
}

bool firmwareUpdateStartInstall(FwUpdateTarget target, const char *expectedVersion) {
    return startRun(Job::Install, target, expectedVersion);
}

FwManifestOutcome firmwareUpdateManifestOutcome(FwManifestInfo &info, const char *&error) {
    info = s_manifest;
    error = s_error;
    return s_outcome;
}

bool firmwareUpdateRequestAbort() {
    if (s_run) {
        s_abortRequested = true;
        return true;
    }
    if (s_state == FwUpdateState::Error) {
        setState(FwUpdateState::Idle);
        s_error[0] = '\0';
    }
    return false;
}

void firmwareUpdateLoop() {
    RunContext *r = s_run;
    if (!r) return;
    Step s;
    if (s_abortRequested) {
        s = Step::Failed;
    } else {
        switch (r->phase) {
            case Phase::Connect: s = stepConnect(*r); break;
            case Phase::Headers: s = stepHeaders(*r); break;
            default: s = stepBody(*r); break;
        }
    }
    // Finished hat den Lauf schon beendet (s_run ist dann frei)
    if (s == Step::Failed) failRun();
}

size_t firmwareUpdateStatusToJson(char *buf, size_t size) {
    int n = snprintf(buf, size,
                     "{\"state\":\"%s\",\"target\":\"%s\",\"version\":\"%s\",\"bytes_done\":%u,\"bytes_total\":%u,\"error\":\"",
                     stateName(s_state), targetName(s_target), s_version, s_bytesDone, s_bytesTotal);
    if (n < 0 || (size_t)n + 3 > size) return 0;
    size_t len = n;
    // Die Meldung gehört zum Zustand error; nach einem gescheiterten check
    // (Zustand idle) steht sie nur in dessen Antwort.
    const char *err = s_state == FwUpdateState::Error ? s_error : "";
    for (const char *p = err; *p; p++) {
        char esc[8];
        const unsigned char c = *p;
        size_t el;
        if (c == '"' || c == '\\') {
            esc[0] = '\\';
            esc[1] = c;
            el = 2;
        } else if (c < 0x20) {
            el = snprintf(esc, sizeof(esc), "\\u%04x", c);
        } else {
            esc[0] = c;
            el = 1;
        }
        if (len + el + 3 > size) break; // kürzen, "}" muss noch passen
        memcpy(buf + len, esc, el);
        len += el;
    }
    memcpy(buf + len, "\"}", 3);
    return len + 2;
}
