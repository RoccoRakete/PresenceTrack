#pragma once

#include "app_config.h"

// Update direkt vom Gerät aus: holt manifest.json des neuesten GitHub-Releases
// (RoccoRakete/PresenceTrack), lädt firmware.bin und optional littlefs.bin per
// HTTPS und schreibt beides streamend in den Flash - kein PC, kein Datei-Upload.
//
// Zustandsautomat ohne eigenen Task (kein RAM für einen zweiten Stack), getaktet
// aus webServerLoop(). Die HTTP-Endpunkte (/api/update/...) liegen in
// web_server.cpp; dieses Modul kennt bewusst keine ESPAsyncWebServer-Typen
// (siehe web_server.h, HTTP_GET/HTTP_POST-Kollision).

// Öffentlicher Zustand, 1:1 als "state" in /api/update/status:
//   Checking     Manifest wird geholt (GET /api/update/check oder Vorlauf eines Installs);
//                ein check endet danach in Idle, sein Ergebnis steht in "check"
//   Downloading  Verbindung/Redirects/Header eines Assets, erster Record wird geprüft
//   Flashing     Update.begin() ist durch, die Bytes laufen in den Flash
//   Rebooting    alles geschrieben und verifiziert, Neustart ist angesetzt
enum class FwUpdateState : uint8_t { Idle, Checking, Downloading, Flashing, Rebooting, Error };

// "firmware": nur firmware.bin. "both": firmware.bin mit verzögertem Reboot, dann
// littlefs.bin, dann ein einziger Neustart (wie "?reboot=0" beim Datei-Upload).
enum class FwUpdateTarget : uint8_t { None, Firmware, Both };

// Ergebnis der Manifest-Abfrage, auf das ein wartender check-/install-Request antwortet.
enum class FwManifestOutcome : uint8_t {
    Pending,         // läuft noch
    UpdateAvailable, // Manifest-Version > installierte; beim Install läuft der Download jetzt
    NoUpdate,        // Manifest-Version <= installierte
    VersionMismatch, // Install mit "version": das Manifest nennt inzwischen eine andere
    Failed,          // Netz/TLS/HTTP/Manifest ungültig, Text siehe firmwareUpdateManifestOutcome()
    Aborted,         // per Abbruch beendet
};

// Versionsstrings wie "0.3.10" oder "v12.345.6789" - 15 Zeichen reichen für drei
// Segmente mit je bis zu 4 Ziffern.
static const size_t FW_VERSION_MAX_LEN = 16;

struct FwManifestInfo {
    char version[FW_VERSION_MAX_LEN];
    uint32_t firmwareSize;
    uint32_t filesystemSize;
};

// Konfiguration per Referenz wie im Webserver: der Automat braucht sie für
// wifiPowerApplyConfig() (Update.begin() erzwingt WIFI_NONE_SLEEP) und um sie
// nach dem Dateisystem-Image neu zu speichern (littlefs.bin enthält keine /config.json).
void firmwareUpdateBegin(AppConfig &cfg);

// Ein Takt des Automaten; aus webServerLoop(). Blockiert nur beim TCP-Aufbau (bis 10 s)
// und beim TLS-Handshake (bis 15 s, siehe firmware_update.cpp), sonst höchstens ~50 ms.
void firmwareUpdateLoop();

FwUpdateState firmwareUpdateState();

// Checking, Downloading, Flashing oder Rebooting: ein Lauf hält den Updater bzw.
// wird ihn gleich halten. Manuelle Uploads, Reboot und Factory Reset werden dann abgelehnt.
bool firmwareUpdateBusy();

// Startet einen Lauf. false, wenn schon einer läuft oder der Arbeitsspeicher für
// den Lauf nicht reicht (~1,8 kB, siehe RunContext). expectedVersion darf
// nullptr/"" sein; sonst bricht der Install mit VersionMismatch ab, wenn das
// Manifest inzwischen eine andere Version nennt.
bool firmwareUpdateStartCheck();
bool firmwareUpdateStartInstall(FwUpdateTarget target, const char *expectedVersion);

// Pending, solange die Manifest-Abfrage des aktuellen Laufs läuft. error zeigt
// bei Failed auf die Meldung (gültig bis zum nächsten Lauf). Für den wartenden
// install-Request; ein check liest sein Ergebnis über firmwareUpdateStatusToJson().
FwManifestOutcome firmwareUpdateManifestOutcome(FwManifestInfo &info, const char *&error);

// Abbruch aus dem Request-Kontext: setzt nur ein Flag, der nächste Takt räumt auf
// (ein Update.end() mitten aus einem yield() im Flash-Schreiben heraus wäre nicht
// sicher). true, wenn ein Lauf abgebrochen wird; false, wenn keiner lief - ein
// Fehlerzustand wird dabei auf Idle zurückgesetzt.
bool firmwareUpdateRequestAbort();

// "firmware" / "both" -> Target; false bei allem anderen.
bool firmwareUpdateParseTarget(const char *s, FwUpdateTarget &target);

// Gepunktet numerisch mit optionalem "v", höchstens 3 Segmente und kürzer als
// FW_VERSION_MAX_LEN ("0.3.1", "v1.2"); so vergleicht das Gerät Versionen.
bool firmwareUpdateVersionValid(const char *s);

// Während eines Laufs nimmt der Webserver nur so viele Verbindungen an (statt
// MAX_HTTP_CONNECTIONS), den wartenden install-Request nicht mitgezählt: eine
// TLS-Verbindung belegt ~13,7 kB Heap, die Reserve daneben rechnet genau einen Poll
// ein (RESERVE_WEB, 2692 B, firmware_update.cpp), und jede weitere parallele
// Verbindung kann ein `new` in der Library scheitern lassen - ein Neustart mitten im
// Flash-Schreiben. 1 = Status-Poll oder Abbruch; kommen beide zugleich, wartet einer
// (lwIP verwirft das SYN, der Browser wiederholt es nach ~1 s).
static const uint8_t FW_UPDATE_HTTP_CONNECTIONS = 1;

// Aktuelles Limit während eines Laufs, für das Listen-Backlog in web_server.cpp: 0,
// solange eine TLS-Verbindung aufgebaut wird oder ihr Request unterwegs ist
// (Webserver-Pause, firmware_update.cpp), sonst FW_UPDATE_HTTP_CONNECTIONS.
uint8_t firmwareUpdateHttpConnections();

// /api/update/status als JSON nach buf, ohne Heap (der Status muss auch dann
// antworten, wenn der TLS-Download den Heap fast aufbraucht). Liefert die Länge,
// 0 wenn buf zu klein ist:
//   {state, target, version, bytes_done, bytes_total,
//    check: ""|"running"|"available"|"none"|"failed"|"aborted", current_version,
//    [available_version, firmware_size, filesystem_size  nur bei check "available"],
//    error  bei state "error" und check "failed"/"aborted", sonst ""}
// "check" beschreibt den letzten Lauf, wenn er ein check war; nach einem Install "".
// FW_STATUS_JSON_MAX reicht immer: ~160 Zeichen Rahmen im Fehlerfall plus die
// Meldung (bis 255 Zeichen), die notfalls gekürzt wird.
static const size_t FW_STATUS_JSON_MAX = 416;
size_t firmwareUpdateStatusToJson(char *buf, size_t size);
