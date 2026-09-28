#include "firmware_update.h"
#include "ota_image.h"
#include "web_server.h"
#include "wifi_power.h"
#include "event_log.h"
#include "firmware.h"
#include "sensor_data.h"
#include "mqtt_ha.h"

#include <ESP8266WiFi.h>
#include <WiFiClientSecureBearSSL.h>
#include <bearssl/bearssl.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <Updater.h>
#include <flash_hal.h>
#include <StackThunk.h>
#include <lwip/dns.h>
#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h> // struct tcp_seg, nur für sizeof (RESERVE_TLS_TX_REQUEST)
#include <lwip/prot/ip4.h>
#include <umm_malloc/umm_malloc.h>
#include <stdarg.h>

// ---------------------------------------------------------------------------
// Update direkt von GitHub
//
// Ablauf eines Installs (ein Schritt pro firmwareUpdateLoop()-Takt):
//   1. Manifest   GET MANIFEST_URL, 2 Redirects (latest -> v<version> -> Asset-CDN),
//                 Body (~650 B) in den Pfad-Puffer, mit ArduinoJson prüfen
//   2. Firmware   GET firmware.url, Redirect aufs CDN, dort in Range-Requests à
//                 RANGE_LEN über eine Keep-Alive-Verbindung (siehe Speicher), Body ohne
//                 Kopie aus dem TLS-Empfangspuffer in Update.write(); SHA-256 läuft mit,
//                 Update.end() erst nach dem Vergleich
//   3. Image      (nur "both") dasselbe für littlefs.bin mit U_FS
//   4. Neustart   webServerScheduleReboot(), eboot kopiert die Firmware beim Booten
// Ein check macht nur Schritt 1 und endet wieder in Idle; sein Ergebnis steht danach
// im Status ("check", firmwareUpdateStatusToJson), GET /api/update/check wartet nicht.
//
// Jede Verbindung (pro Hop bzw. Reconnect) durchläuft eigene Phasen, je eine pro Takt:
//   Resolve  DNS, nicht blockierend (stepResolve)
//   Tcp      TCP-Aufbau zur aufgelösten IP (stepTcp)
//   Tls      Handshake mit SNI (stepTls), danach der Request
//   Headers  Antwortkopf, Body: Nutzdaten
//   Request  nächste Range auf derselben Verbindung (Keep-Alive, stepRequest)
// So lässt sich jeder Fehler seiner Phase zuordnen - siehe Diagnose.
//
// Warum ein eigener HTTP-Client statt ESP8266HTTPClient: dessen Redirect-Support
// verbindet den übergebenen secure client neu, ohne den Host für SNI zu
// wechseln - das CDN (release-assets.githubusercontent.com) bekäme den
// Handshake für github.com und antwortet mit dem falschen Zertifikat bzw. gar
// nicht. Hier entsteht pro Hop ein neuer TlsClient; _connectSSL(host) reicht den
// Hostnamen an br_ssl_client_reset(ctx, hostName, ...) weiter
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
// Speicher (gemessen am Gerät 10.7.2.152 mit 0.3.1-Vorversion: im Betrieb 19936-22648 B
// frei, zur Heap-Prüfung im schlechtesten Fall 19024 B, größter Block 13328 B - RunContext
// (damals 3264 B) und MQTT-Puffer (1024 B) schon abgezogen; geteilt mit MQTT, Sensoren
// und Webserver):
//   RunContext   1840 B (sizeof im Build), nur während eines Laufs (calloc/free). Ohne den
//                Chunk-Puffer (1460 B): der Body wird direkt aus dem TLS-Empfangspuffer
//                gelesen (peekBuffer), das Manifest landet im Pfad-Puffer, der Request wird
//                auf dem Stack gebaut (sendRequest).
//   MQTT         während eines Laufs schrumpft der PubSubClient-Puffer von 1024 auf 256 B
//                (mqtt_ha.cpp, MQTT_RUN_BUFFER_LEN): +768 B frei, bevor die erste Verbindung
//                geprüft wird. Zusammen mit dem RunContext stehen in derselben Lage also
//                1424 + 768 = 2192 B mehr zur Verfügung als bei der Messung oben (umm-Blöcke:
//                3272 -> 1848 B bzw. 1032 -> 264 B).
//   TLS          pro Verbindung, Empfangspuffer TLS_RX 1024 B für jeden Fetch:
//                  check/Manifest  Verbindung 13662 B + Reserve 4119 B            = 17781 B
//                  Asset-Download  Verbindung 13662 B + Flash-Puffer 268 B
//                                  + Reserve 4119 B                               = 18049 B
//                Verbindung und Reserve: tlsNeedBytes(), die Reserve getrennt für
//                Handshake, Request und Transfer, denn die Verbraucher sind nicht alle
//                zugleich da. Geprüft vor jedem Aufbau (tlsHeapAvailable); reicht es nach
//                HEAP_WAIT_MS noch nicht, endet der Lauf mit allen Zahlen, bevor etwas belegt
//                ist. Erwarteter Tiefstwert bei 19024 + 2192 = 21216 B zur Prüfung, wenn alle
//                Verbraucher zugleich ihr Maximum brauchen: 3435 B (check) bzw. 3167 B (Asset).
//                Bis zur 0.3.1-Vorversion: Empfangspuffer 1536/2048 B, eine Reserve von
//                6674 B für jeden Zeitpunkt ohne das TLS-Senden, bis zu zwei Webverbindungen
//                und ungedrosseltes MQTT - Bedarf 20848/21628 B, und im check fiel der Heap am
//                Gerät trotzdem auf 800 B (min_free_heap).
//   Webserver    pausiert, solange eine Verbindung aufgebaut wird oder ihr Request unterwegs
//                ist (waitWebIdle, firmwareUpdateHttpConnections), sonst eine Verbindung.
//   Images       nie am Stück im RAM: max. ein TLS-Record (1024 B) im Empfangspuffer, 256 B
//                im Updater (beginUpdater: ohne Eingriff nähme er hier 4 kB, siehe dort).
//
// Empfangspuffer, belegt am Core 3.1.2 (BearSSL-Quellen unter tools/sdk/ssl/bearssl/src):
//   - Komplett in den Puffer muss nur ein VERSCHLÜSSELTER Record (ssl/ssl_engine.c:679-696:
//     BR_ERR_TOO_LARGE nur bei incrypt, wenn Länge > Puffer - 5; unverschlüsselte Records
//     bis 16384 B stückweise). Der Handshake bis ChangeCipherSpec, also auch die
//     Zertifikatskette (am CDN 4145 B), braucht deshalb keinen großen Puffer - wohl aber
//     jede Antwort danach. setBufferSizes() rechnet 325 B für Kopf, IV, MAC und Padding
//     drauf (WiFiClientSecureBearSSL.cpp:180-190), TLS_RX ist also reiner Klartext.
//   - Die Max-Fragment-Length-Extension (MFLN) fordert BearSSL von sich aus an:
//     br_ssl_engine_set_buffers_bidi() wählt die größte Zweierpotenz, die in Empfangs- UND
//     Sendepuffer passt (ssl/ssl_engine.c:422-447), mit 512 + 85 B Sendepuffer immer 512,
//     und der ClientHello bittet um 512-B-Records (ssl/ssl_hs_client.t0:380, 516-519) -
//     unabhängig von TLS_RX.
//   - Ob der Server sich daran hält, entscheidet er: github.com ja, das CDN
//     release-assets.githubusercontent.com (Fastly) nein (gemessen 2026-09-27). Auch der
//     check landet dort: manifest.json liegt wie die Images auf dem CDN (3. Hop, siehe
//     MANIFEST_URL). Gemessen am 2026-09-28 mit openssl s_client -tls1_2 -maxfraglen 512
//     -msg (AES-128-GCM, Record auf der Leitung = Klartext + 24 B):
//       manifest.json (653 B)  Header-Record 873 B, Body-Record 653 B (3 Läufe, gleich)
//       Range 2048 B, 260x     Header-Record 948-957 B, Body-Record genau 2048 B
//                              (die ersten Ranges in 1371 + 677 B)
//       Range 4096 B, 40x      Header-Record 953-955 B, Body-Record genau 4096 B
//     Kopf und Body kamen nie im selben Record.
// Der Puffer steht also fest, BEVOR die Verbindung aufgebaut wird, und zwar nach dem, was
// sie holen soll (tlsRxFor). 1024 B fassen den größten gemessenen Record (Header 957 B), das
// Manifest und mit RANGE_LEN = 1024 den Body jeder Range. Bis 0.3.0 kam der große Puffer
// erst als Rückfall nach einem gescheiterten Handshake - an der falschen Stelle, denn ein
// zu großer Record kommt erst NACH dem Handshake, beim Lesen der Antwort, und daran
// scheiterte der Lauf ohne zweiten Versuch. Ist ein Record doch einmal größer, meldet der
// Lauf BearSSL-Fehler 6 (BR_ERR_TOO_LARGE) mit Text; kein Absturz, nichts geflasht.
//
// Nicht zu verkleinern, belegt am Core 3.1.2:
//   - StackThunk 6200 B, der größte Posten: fest im Core (StackThunk.cpp:45), malloc() für
//     den ersten BearSSL-Client (Zeile 59). Jede TLS-Verbindung braucht ihn, auch eine kurze
//     fürs Manifest, und github.com wie das CDN liefern nur über HTTPS (ein Klartext-Umweg
//     schiede auch an "Nur HTTPS" oben). Statisch vorgehalten fehlte er dauerhaft statt nur
//     im Lauf. Er muss am Stück frei sein; der größte Block (13328 B im schlechtesten
//     gemessenen Moment) reicht dafür.
//   - X.509-Kontext von setInsecure() 1480 B, nur im Handshake: den Validator wählt die
//     private _installClientX509Validator() (WiFiClientSecureBearSSL.h:234, .cpp:1056-1058);
//     setFingerprint() nutzt denselben Kontext, setKnownKey() pinnte den Serverschlüssel und
//     bräche beim nächsten Zertifikatswechsel. Er zählt deshalb nur im Handshake (tlsNeedBytes).
//   - br_ssl_client_context 3408 B und der Sendepuffer 512 + 85 B (Minimum, setBufferSizes).
//
// Blockieren: der Automat läuft aus webServerLoop(), also in loop() - nicht im
// lwIP-Kontext der Request-Handler, die nur einen Lauf anstoßen. Pro Verbindung:
//   Resolve  blockiert nicht: dns_gethostbyname() mit Callback, der Takt prüft nur
//            (WiFi.hostByName() würde bis zu 10 s in esp_delay() warten,
//            ESP8266WiFiGeneric.cpp:645)
//   Tcp      bis TCP_CONNECT_TIMEOUT_MS: ClientContext::connect() wartet in
//            esp_delay() auf das SYN-ACK (include/ClientContext.h:147)
//   Tls      bis zu 15 s: _connectSSL() setzt den Timeout über _freeSSL() fest auf
//            15000 ms (WiFiClientSecureBearSSL.cpp:249), von außen nicht zu kürzen.
//            ECDHE auf 80 MHz, typisch 1-2 s, auf diesem Gerät nicht gemessen
//            (Serial zeigt die Dauer, siehe Diagnose).
// Dabei laufen esp_delay() bzw. optimistic_yield() (_run_until), der Watchdog wird
// bedient und lwIP arbeitet weiter; sensorsLoop() und mqttHaLoop() pausieren, im
// schlimmsten Fall 10 + 15 s am Stück - unter dem MQTT-Keepalive von 60 s (der Broker
// trennt erst nach 1,5 x Keepalive). Neue HTTP-Verbindungen nimmt der Webserver in dieser
// Zeit nicht an (Webserver-Pause, siehe waitWebIdle): lwIP verwirft das SYN, der Browser
// wiederholt es nach ~1 s, 3 s, 7 s, und der Status-Poll kommt danach durch.
// BearSSL selbst rechnet auf dem eigenen 6200-B-Stack des StackThunk
// (make_stack_thunk, BearSSLHelpers.cpp:977ff.), nicht auf dem 4-kB-Stack von loop().
// Alles andere ist nicht-blockierend: available()/peekBuffer() liefern nur, was schon
// da ist, höchstens TICK_BUDGET_MS pro Takt. Nur sendRequest() wartet, bis lwIP den
// Request angenommen hat (TCP_SND_BUF, siehe TlsClient::writeNoAckWait).
//
// Diagnose: getLastSSLError() allein unterscheidet die Fälle nicht. Es liefert 0,
// solange der Core keinen BearSSL-Kontext hat (_sc entsteht erst in _connectSSL(),
// WiFiClientSecureBearSSL.cpp:1135, 1353), also nach jedem DNS- oder TCP-Fehler -
// und ebenso, wenn die Verbindung im Handshake ohne Protokollfehler stirbt oder
// _run_until() in den Timeout läuft (Zeile 492, 503). Der Text des Cores zu 0 wäre
// "Unknown error code." (die switch ab Zeile 1368 kennt BR_ERR_OK nicht). Deshalb
// trennt TlsClient TCP und TLS, die DNS-Antwort wird selbst geholt, und jede Meldung
// nennt Phase, Host, IP und - wenn BearSSL lief - Code und Text.
// Serial, 115200 Baud, Präfix "[update]": Zustände, Phasen, aufgelöste IP, Heap vor
// und nach dem TLS-Aufbau, Dauer, BearSSL-Code mit Text, Ergebnis. Dazu eine Marke im
// RTC-Speicher, die einen Absturz überlebt (siehe RtcMark).
// ---------------------------------------------------------------------------

// Stabile URL, zeigt immer auf das neueste Release; GitHub antwortet mit 302 auf
// .../releases/download/v<version>/manifest.json und das wiederum mit 302 aufs CDN.
static const char MANIFEST_URL[] PROGMEM = "https://github.com/RoccoRakete/PresenceTrack/releases/latest/download/manifest.json";

// latest -> v<version> -> CDN sind 2 Hops, 3 lassen einen Zwischenschritt Luft.
static const uint8_t MAX_REDIRECTS = 3;
// Location des CDN-Redirects gemessen am 2026-09-27: 930 Zeichen, davon 892
// Pfad + signierte Query (sp/sv/se/sig/jwt). Reserve für längere Tokens.
static const size_t URL_PATH_MAX_LEN = 1152;
// "release-assets.githubusercontent.com" = 36 Zeichen
static const size_t HOST_MAX_LEN = 48;
// firmware.url/filesystem.url laut Vertrag ".../releases/download/v0.3.0/littlefs.bin", ~85 Zeichen
static const size_t ASSET_URL_MAX_LEN = 128;
static const size_t SHA256_LEN = 32;
// Range-Größe für Assets. Der CDN schickt den Body einer Range als einen Record mit
// genau RANGE_LEN B Klartext (Messung im Kopfkommentar), der muss in den Empfangspuffer:
// TLS_RX_ASSET = RANGE_LEN, und der Puffer ist der einzige Posten der Verbindung, der
// mit der Range wächst. Abwägung für "both", littlefs.bin (1024000 B) + firmware.bin
// (607072 B in v0.3.0); ein Request ist ~1080 B (signierte URL 892 Zeichen + ~190 B Kopf),
// also drei Records à TLS_TX:
//   RANGE_LEN  Requests           Bedarf Asset  RTT gesamt (2 je Range)
//   2048        297 + 500 =  797     19073 B    1594
//   1536        396 + 667 = 1063     18561 B    2126
//   1024        593 + 1000 = 1593    18049 B    3186
// 2 RTT je Range: die drei Records gehen ohne Warten hinaus (TlsClient::writeNoAckWait),
// nur die ~1170 B auf der Leitung übersteigen TCP_SND_BUF (1072 B) und warten auf ein ACK,
// dazu die Antwort. Bis zur 0.3.1-Vorversion wartete der Core nach jedem Record aufs ACK
// (WiFiClientSecureBearSSL.cpp:326 flush() -> WiFiClient.cpp:313 wait_until_acked(),
// ClientContext.h:316-360): 3 RTT, mit 2048 also 2391 RTT. RTT am PC gemessen (2026-09-28,
// curl time_connect): CDN 7 ms, github.com 11 ms; am Gerät nicht gemessen. Bei angenommenen
// 15 ms reine Wartezeit: 1024 ~48 s, 1536 ~32 s, 2048 ~24 s, Vorversion ~36 s; dazu je
// Range ein Header-Record von ~980 B (1593 x = 1,6 MB statt 0,8 MB bei 2048).
// 2048 passt nicht (19073 > 19000 B), 1536 ließe nur 2655 B als Tiefstwert (Kopfkommentar,
// Speicher: 21216 - 18561), knapp über den 2500 B. 1024 lässt 3167 B und kostet gegenüber
// der Vorversion geschätzt ~12 s.
static const uint32_t RANGE_LEN = 1024;

// Taktbudget: danach kommen sensorsLoop()/mqttHaLoop() wieder dran. Ein
// Flash-Sektor (Erase + Write) kostet ~30-50 ms, das Budget lässt also etwa
// einen Sektor pro Takt zu.
static const unsigned long TICK_BUDGET_MS = 40;
// Vom gesendeten Request bis zum Ende der Header; GitHub/CDN antworten in <1 s.
static const unsigned long HEADER_TIMEOUT_MS = 15000;
// Keine Body-Bytes mehr: Verbindung gilt als tot.
static const unsigned long BODY_IDLE_TIMEOUT_MS = 15000;

// DNS: dieselbe Grenze wie WiFi.hostByName() (DNSDefaultTimeoutMs = 10000,
// ESP8266WiFiGeneric.h:57), nur ohne dabei zu blockieren.
static const unsigned long DNS_TIMEOUT_MS = 10000;
// TCP-Aufbau. Ohne setTimeout() wären es die 15 s aus WiFiClientSecureCtx::_clear()
// (WiFiClientSecureBearSSL.cpp:73). GitHub/Fastly antworten aufs SYN nach einem RTT
// (~30 ms). 10 s wie beim DNS: bei den 35-50 % Paketverlust dieses Geräts (ICMP
// gemessen) muss mindestens eine SYN-Wiederholung hineinpassen (lwIP wiederholt nach
// seinem RTO, laut lwIP-Doku anfangs 3 s; im Core liegt lwIP nur binär vor).
static const unsigned long TCP_CONNECT_TIMEOUT_MS = 10000;

// TLS-Empfangspuffer (Klartext) je Fetch, gewählt vor dem Aufbau (tlsRxFor; Messung und
// Begründung im Kopfkommentar). Manifest: der größte Record ist der Header-Record des CDN
// (873 B); das Manifest selbst (653 B) kommt als ein Record, parseManifest nimmt deshalb
// höchstens TLS_RX_MANIFEST B an (MANIFEST_MAX_LEN). Assets: genau der Body-Record einer
// Range. Die Header-Records (<= 957 B, 67 B Luft) und die 302 von github.com (MFLN, 512 B)
// passen in beide. Die Overheads stammen aus WiFiClientSecureCtx::setBufferSizes()
// (WiFiClientSecureBearSSL.cpp:180-188, dort aus ssl_engine.c:282-283 übernommen).
static const int TLS_RX_MANIFEST = 1024;
static const int TLS_RX_ASSET = RANGE_LEN;
static const uint32_t CDN_HEADER_RECORD_MAX = 957; // gemessen, siehe Kopfkommentar
static const size_t MANIFEST_MAX_LEN = TLS_RX_MANIFEST;
static_assert(TLS_RX_MANIFEST >= (int)CDN_HEADER_RECORD_MAX && TLS_RX_ASSET >= (int)CDN_HEADER_RECORD_MAX,
              "Empfangspuffer fassen die gemessenen Records nicht mehr");
static_assert(MANIFEST_MAX_LEN <= URL_PATH_MAX_LEN, "das Manifest wird im Pfad-Puffer gelesen (stepBody)");
static const int TLS_TX = 512; // Minimum des Cores (setBufferSizes klemmt auf >= 512)
static const uint32_t TLS_IN_OVERHEAD = 325;
static const uint32_t TLS_OUT_OVERHEAD = 85;
// StackThunk.cpp:45: _stackSize = 6200/4 Worte, malloc() im Konstruktor des ersten
// BearSSL-Clients (stack_thunk_add_ref, StackThunk.cpp:59), mit dem letzten wieder frei.
// Schlägt das malloc fehl, ruft der Core abort() auf (StackThunk.cpp:60-64).
static const uint32_t TLS_STACK_THUNK_BYTES = 6200;
// ClientContext (Socket-Wrapper des Cores, include/ClientContext.h) ist privat;
// sizeof im Build gemessen (Core 3.1.2).
static const uint32_t TLS_CLIENT_CONTEXT_BYTES = 52;
// shared_ptr-Kontrollblöcke: make_shared legt Objekt und Block zusammen an,
// shared_ptr<unsigned char>(new[], deleter) in _alloc_iobuf() einen eigenen Block
// (WiFiClientSecureBearSSL.cpp:1113). sizeof im Build gemessen (_Sp_counted_ptr_inplace
// abzüglich Objekt bzw. _Sp_counted_deleter, je 16 B).
static const uint32_t TLS_SHARED_INPLACE_BYTES = 16;
static const uint32_t TLS_SHARED_DELETER_BYTES = 16;
// umm_malloc: 8-B-Blöcke, 4 B Kopf pro Allokation -> bis zu 11 B Verschnitt
// (umm_block, umm_malloc.cpp:109-117, Blockzahl Zeile 332-358; kein Poisoning
// ohne DEBUG_ESP_PORT, umm_malloc_cfg.h:600-606).
static const uint32_t UMM_ALLOC_SLACK = 12;

// Updater::begin() nimmt einen 4096-B-Sektorpuffer nur, wenn mehr als 2 x FLASH_SECTOR_SIZE
// frei sind, sonst 256 B (Updater.cpp:172-177, nothrow); beginUpdater() sorgt für die 256 B,
// wenn 4096 die Reserve verletzen würden. Gezählt für einen Asset-Fetch, bis begin() lief.
static const uint32_t UPDATER_SMALL_BUFFER = 256;
static const uint32_t UPDATER_BUFFER_BYTES = UPDATER_SMALL_BUFFER + UMM_ALLOC_SLACK;

// Reserve: was neben einer offenen Verbindung zusätzlich Heap belegen kann. Die Verbraucher
// kommen nicht alle zugleich, deshalb drei Zeitpunkte je Verbindung, in der Reihenfolge des
// Codes (stepTcp -> stepTls -> sendRequest -> stepHeaders/stepBody -> beginFlash):
//   Handshake  _connectSSL(): der X.509-Kontext ist belegt, der Client sendet seine Flights;
//              der Webserver ist pausiert (waitWebIdle vor dem TCP-Aufbau)
//   Request    X.509 wieder frei (_x509_insecure = nullptr, WiFiClientSecureBearSSL.cpp:1206),
//              der Request geht hinaus; Webserver pausiert, bis lwIP ihn bestätigt hat (webMayRun)
//   Transfer   Antwort und Body; der Webserver bedient eine Verbindung, beim ersten Request
//              eines Assets kommt mit dem ersten Record der Flash-Puffer dazu (beginFlash)
// Innerhalb eines Zeitpunkts zählen alle seine Verbraucher gleichzeitig: zwischen zwei Takten
// liest der Automat nicht, die Antwort läuft in lwIP auf, mqttHaLoop publiziert, und der
// Webserver beantwortet einen Poll.
// lwIP-Zahlen: lwipopts.h, Variante lwip2-536-feat (TCP_MSS 536, IPv4, lwIP 2.1.3), jede
// Allokation im umm-Heap (MEMP_MEM_MALLOC, lwipopts.h:279).
//   TLS-Empfang   2472 B  in allen drei: lwIP puffert bis TCP_WND = 4 x 536 B (lwipopts.h:1251),
//                         bis BearSSL abholt: die Antwort einer Range (~2,0 kB auf der Leitung),
//                         die 302 von github.com (~5 kB, 3,7 kB davon CSP-Header), die
//                         Zertifikate im Handshake. Je Segment ein pbuf für den ganzen Frame
//                         (esp2glue_alloc_for_recv, glue.h:103): 16 + 14 + 20 + 20 + 536 + 12.
//   TLS-Senden    1035 B  Handshake: ein Client-Flight, ClientHello (ein Record <= 512 + 85 B,
//                         zwei Segmente) bzw. ClientKeyExchange + ChangeCipherSpec + Finished
//                         (drei Records, ~130 B mit ECDHE); den nächsten Flight schickt BearSSL
//                         erst auf die Antwort des Servers, die den vorigen bestätigt: 597 + 3 x 146.
//                 1510 B  Request: lwIP hält höchstens TCP_SND_BUF = 1072 B (lwipopts.h:1326)
//                         unbestätigt, mit TCP_NODELAY (stepTcp) in genau passenden Segmenten,
//                         höchstens drei: 1072 + 3 x 146. Ohne NODELAY legt lwIP ab dem zweiten
//                         unbestätigten Segment MSS-große pbufs an (TCP_OVERSIZE = TCP_MSS,
//                         lwipopts.h:1432; tcp_pbuf_prealloc() in lwIP 2.1.3): bis 3 x 682 B.
//                         Bis zur 0.3.1-Vorversion fehlte dieser Posten ganz.
//   MQTT           463 B  in allen drei. Während eines Laufs (mqtt_ha.cpp) höchstens ein PUBLISH
//                         (<= MQTT_STATE_PACKET_MAX = 85 B) und ein PINGREQ (2 B) unbestätigt,
//                         beide mit TCP_NODELAY in genau passenden Segmenten, dazu das PINGRESP
//                         (ein Frame, 82 + 2 B), bis PubSubClient::loop() es liest:
//                         146 + 85 + 146 + 2 + 84. Ohne Drosselung schickt publishStates() alle
//                         2 s bis zu 16 Nachrichten, mit Nagle + TCP_OVERSIZE bis 3 x 682 = 2046 B
//                         (die Vorversion rechnete 1510 B).
//   Webserver     2692 B  nur im Transfer, eine Verbindung (FW_UPDATE_HTTP_CONNECTIONS; der
//                         wartende install-Request zählt nicht, sein Heap ist bei der Prüfung
//                         schon belegt): ein Status-Poll, die UI fragt während eines Laufs nur
//                         /api/update/status ab, alle GH_POLL_MS = 1000 ms (data/app.js).
//                         tcp_pcb 184 + AsyncClient 220 + AsyncWebServerRequest 324 +
//                         FixedJsonResponse 616 (sizeof im Build) + 4 x 12, der Request als
//                         ein RX-Segment (618) und die Antwort (<= 95 B Kopf + 416 B) als
//                         ein TX-Segment (682). Die Request-Header (~7 à ~60 B) sind vor der
//                         Antwort wieder frei und kleiner als Response + TX-Segment.
//   Sensoren         0 B  sensorsLoop() arbeitet nur auf statischen Puffern.
// Damit neben der Verbindung: Handshake 3970 B, Request 4445 B, Transfer 5627 B. Der
// X.509-Kontext (1508 B) ist nur im Handshake belegt, deshalb bindet der Transfer
// (tlsNeedBytes): 5627 - 1508 = 4119 B Reserve über der Verbindung, beim Asset + 268 B.
// Unterhalb der Reserve wird es nicht sofort kritisch: pbufs, AsyncClient, Request- und
// Response-Objekte scheitern mit Fehlerwert (Paket verworfen, Verbindung geschlossen, TCP
// wiederholt). Einen Neustart (OOM-Panic) lösen nur `new` ohne nothrow aus: beim
// Header-Parsen je AsyncWebHeader 24 B + Listenknoten (WebRequest.cpp:348), beim
// MQTT-Reconnect der ClientContext 52 B, im Handshake die Objekte des Cores.
// Nicht abgedeckt, nur durch den Abstand zum Tiefstwert (Kopfkommentar, Speicher): ein
// MQTT-Reconnect mitten im Lauf (~0,7 kB: tcp_pcb 184 + ClientContext 52 + CONNECT <= 205 B
// in einem Segment + CONNACK; Discovery wartet bis nach dem Lauf), statt des Polls der
// Abbruch-POST (JSON-Body und zwei JsonDocuments, einige hundert Byte mehr), ein Neuladen der
// Seite während eines Laufs (Dateien aus LittleFS, mehr als ein Poll) und was das WLAN-SDK
// selbst braucht (nicht messbar, nur der Tiefstwert).
// Gegen die Messung: 0.3.0 fiel im Lauf auf min_free_heap 4712 B und lief weiter, die
// 0.3.1-Vorversion im check auf 800 B. Beides ist mit den fehlenden Posten vereinbar (in der
// Vorversion nach dem Aufbau 6674 B eingeplant, möglich waren TLS-Empfang 2472 + TLS-Senden
// bis 2046 + MQTT bis 2046 + zwei Webverbindungen 5384 B), welcher davon die 800 B verursachte,
// ist nicht einzeln belegt.
static const uint32_t RX_FRAME_OVERHEAD = sizeof(pbuf) + PBUF_LINK_HLEN + IP_HLEN + TCP_HLEN + UMM_ALLOC_SLACK;
static const uint32_t RX_SEGMENT_BYTES = RX_FRAME_OVERHEAD + TCP_MSS;
static const uint32_t TX_SEGMENT_OVERHEAD = sizeof(pbuf) + PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN +
                                            PBUF_IP_HLEN + PBUF_TRANSPORT_HLEN + UMM_ALLOC_SLACK +
                                            sizeof(tcp_seg) + UMM_ALLOC_SLACK;
// sizeof im Build (Core 3.1.2, ESPAsyncTCP-esphome 2.0, ESPAsyncWebServer-esphome 3.2):
// dieses Modul kennt die Webserver-Typen bewusst nicht (firmware_update.h)
static const uint32_t WEB_ASYNC_CLIENT_BYTES = 220;
static const uint32_t WEB_REQUEST_BYTES = 324;
static const uint32_t WEB_STATUS_RESPONSE_BYTES = 616; // FixedJsonResponse, web_server.cpp
static const uint32_t MQTT_PINGREQ_LEN = 2;
static const uint32_t MQTT_PINGRESP_LEN = 2;
static const uint32_t RESERVE_TLS_RX = TCP_WND / TCP_MSS * RX_SEGMENT_BYTES;
static const uint32_t RESERVE_TLS_TX_HANDSHAKE = TLS_TX + TLS_OUT_OVERHEAD + 3 * TX_SEGMENT_OVERHEAD;
static const uint32_t RESERVE_TLS_TX_REQUEST = TCP_SND_BUF + (TCP_SND_BUF / TCP_MSS + 1) * TX_SEGMENT_OVERHEAD;
static const uint32_t RESERVE_MQTT = TX_SEGMENT_OVERHEAD + MQTT_STATE_PACKET_MAX + TX_SEGMENT_OVERHEAD +
                                     MQTT_PINGREQ_LEN + RX_FRAME_OVERHEAD + MQTT_PINGRESP_LEN;
static const uint32_t RESERVE_WEB = sizeof(tcp_pcb) + WEB_ASYNC_CLIENT_BYTES + WEB_REQUEST_BYTES +
                                    WEB_STATUS_RESPONSE_BYTES + 4 * UMM_ALLOC_SLACK + RX_SEGMENT_BYTES +
                                    TX_SEGMENT_OVERHEAD + TCP_MSS;
static const uint32_t RESERVE_HANDSHAKE = RESERVE_TLS_RX + RESERVE_TLS_TX_HANDSHAKE + RESERVE_MQTT;
static const uint32_t RESERVE_REQUEST = RESERVE_TLS_RX + RESERVE_TLS_TX_REQUEST + RESERVE_MQTT;
static const uint32_t RESERVE_TRANSFER = RESERVE_TLS_RX + RESERVE_MQTT + RESERVE_WEB;
// Direkt nach dem Handshake können TLS-Empfang und MQTT ihren Teil schon belegen (dann ist er
// bereits abgezogen); dazukommen können noch der Request bzw. danach ein Poll und beim ersten
// Asset-Request der Flash-Puffer. Nach Update.begin() (im Transfer) kann der Poll schon
// laufen. Beide Prüfungen fangen nur grobe Fehlschätzungen ab; die volle Rechnung hat die
// Prüfung vor dem Aufbau verlangt.
static const uint32_t TLS_HEAP_RESERVE_AFTER = std::max(RESERVE_TLS_TX_REQUEST, RESERVE_WEB);
static const uint32_t UPDATER_HEAP_RESERVE_AFTER = RESERVE_TRANSFER - RESERVE_WEB;

// Reicht der Heap vor einem Aufbau nicht, wartet der Automat bis zu so lange, bevor er
// ablehnt: zur Prüfzeit ist der Webserver schon still (waitWebIdle), aber MQTT kann gerade
// ein Segment unterwegs haben, und die Verbindung des vorigen Hops ist eben erst zu
// (closeClient). 3 s kosten nichts: nichts ist belegt, blockiert wird nicht.
static const unsigned long HEAP_WAIT_MS = 3000;

// Nachbau von br_x509_insecure_context (privat, WiFiClientSecureBearSSL.cpp:671-680)
// nur für sizeof: setInsecure() legt ihn pro Handshake mit make_shared an
// (_installClientX509Validator, Zeile 1058). Die Feldtypen kommen aus den
// BearSSL-Headern, der Nachbau wächst also mit ihnen. Nach dem Handshake gibt der Core
// ihn wieder frei (_x509_insecure = nullptr, Zeile 1206); gezählt wird er deshalb nur
// im Handshake (tlsNeedBytes).
struct X509InsecureSizeMirror {
    const br_x509_class *vtable;
    bool done_cert;
    const uint8_t *match_fingerprint;
    br_sha1_context sha1_cert;
    bool allow_self_signed;
    br_sha256_context sha256_subject;
    br_sha256_context sha256_issuer;
    br_x509_decoder_context ctx;
};

// TCP und TLS getrennt: WiFiClientSecureCtx::connect(name, port) macht DNS, TCP und
// Handshake in einem Aufruf (WiFiClientSecureBearSSL.cpp:218-229) und hinterlässt bei
// jedem Fehler davor getLastSSLError() == 0. Hier dieselben Schritte einzeln:
// WiFiClient::connect(ip, port) und _connectSSL(host) (protected,
// WiFiClientSecureBearSSL.h:150-151).
// Direkt der Kontext statt des WiFiClientSecure-Wrappers: nur so erreicht
// setTimeout() den TCP-Aufbau, und das spart dessen shared_ptr.
class TlsClient : public BearSSL::WiFiClientSecureCtx {
  public:
    using BearSSL::WiFiClientSecureCtx::flush;

    bool connectTcp(const IPAddress &ip, uint16_t port) { return WiFiClient::connect(ip, port); }
    bool handshake(const char *host) { return _connectSSL(host); }
    bool tcpEstablished() { return WiFiClient::status() == ESTABLISHED; }

    // lwIP hat alles Gesendete bestätigt bekommen, die TX-Segmente sind frei (tcp_sndbuf,
    // ClientContext.h:161-164). Auf einer geschlossenen Verbindung ist nichts mehr belegt.
    bool tcpAcked() { return !tcpEstablished() || WiFiClient::availableForWrite() == TCP_SND_BUF; }

    // read() ohne Kopie: zeigt auf den entschlüsselten Rest des aktuellen Records im
    // Empfangspuffer (available() -> _pollRecvBuffer(), peekBuffer(),
    // WiFiClientSecureBearSSL.cpp:398-444), gültig bis peekConsume(). >0 Bytes, 0 = noch
    // nichts da, -1 = Verbindung weg - dieselben Fälle wie read() (Zeile 355-393).
    int peekRecord(const uint8_t *&data) {
        const int n = available();
        if (n > 0) {
            data = reinterpret_cast<const uint8_t *>(peekBuffer());
            return n;
        }
        return connected() ? 0 : -1;
    }

    // write(), ohne nach jedem Record aufs ACK zu warten: _write() ruft nach jedem Record
    // das virtuelle flush() (WiFiClientSecureBearSSL.cpp:326), das bis zu 300 ms auf die
    // Bestätigung wartet (WiFiClient.cpp:313, ClientContext.h:316-360) - pro Request drei RTT.
    // Hier schiebt flush() den Record nur an lwIP weiter: availableForWrite() läuft
    // _run_until(BR_SSL_SENDAPP) (Zeile 276-294) und schreibt dabei, was BearSSL zu senden
    // hat. Mehr als TCP_SND_BUF unbestätigt lässt lwIP nicht zu; dann wartet
    // ClientContext::write() wie bisher (_write_from_source), also höchstens
    // RESERVE_TLS_TX_REQUEST im Heap.
    size_t writeNoAckWait(const uint8_t *buf, size_t len) {
        _noAckWait = true;
        const size_t n = write(buf, len);
        _noAckWait = false;
        return n;
    }

    void flush() override {
        if (_noAckWait) {
            (void)BearSSL::WiFiClientSecureCtx::availableForWrite();
            return;
        }
        BearSSL::WiFiClientSecureCtx::flush();
    }

  private:
    // Statisch statt Member: es gibt nur einen TlsClient, und sizeof(TlsClient) bleibt 208 B
    static bool _noAckWait;
};

bool TlsClient::_noAckWait = false;

enum class Job : uint8_t { Check, Install };
enum class Fetch : uint8_t { Manifest, Firmware, Filesystem };
// Request hinten angehängt: die Absturzmarke (RtcMark) speichert die Nummer
enum class Phase : uint8_t { Resolve, Tcp, Tls, Headers, Body, Request };
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
// Liegt während des ganzen Laufs, also nur, was über Takte hinweg gebraucht wird. Kein
// Chunk-Puffer mehr (bis zur 0.3.1-Vorversion 1460 B): Header und Body kommen per
// peekRecord() direkt aus dem TLS-Empfangspuffer, das Manifest in path (nach dem 200 ist der
// Pfad frei), der Request entsteht auf dem Stack (sendRequest). Geprüft und verworfen, weil
// es je nur wenige Byte bringt und Felder doppelt belegen würde: hdr und head in einer
// union (32 B; hdr lebt bis onHeadersDone, head erst danach), firmware.url in path statt
// im Asset (128 B; der Pfad trägt beim Parsen noch das Manifest).
struct RunContext {
    TlsClient *client;
    Job job;
    Fetch fetch;
    Phase phase;
    uint8_t hops;
    bool keepAlive;      // die Verbindung darf die nächste Range tragen
    bool updateStarted;  // Update.begin() für das aktuelle Asset ist durch
    bool fsTouched;      // LittleFS ist ausgehängt (close_all_fs)
    bool fsWritten;      // Update.begin(U_FS) ist durch: die Partition ist (teilweise) überschrieben
    bool firmwareStaged; // Firmware-Update.end() war erfolgreich, eboot kopiert beim nächsten Boot
    bool sleepForced;    // Update.begin() lief: es erzwingt WIFI_NONE_SLEEP (Updater.cpp:112)
    bool dnsPending;     // dns_gethostbyname() wartet auf den Callback (s_dns)
    bool heapWaiting;    // diese Phase wartet auf Heap (HEAP_WAIT_MS), schon protokolliert
    bool webHold;        // Webserver pausiert (firmwareUpdateHttpConnections() == 0)
    bool webWaiting;     // wartet darauf, dass die offenen HTTP-Verbindungen zugehen
    uint16_t port;
    uint32_t ip;         // aufgelöste IPv4-Adresse des Hosts (IPAddress ist kein Plain Data)
    uint32_t minHeap;    // kleinster freier Heap in diesem Lauf, an den Messpunkten (noteHeap)
    uint32_t nextLogAt;  // Body-Offset der nächsten Fortschrittszeile auf Serial
    unsigned long phaseStartMs;
    unsigned long heapWaitStartMs;
    unsigned long webWaitStartMs;
    unsigned long lastDataMs;
    uint32_t received; // verarbeitete Body-Bytes des aktuellen Fetches (= Offset im Asset)
    uint32_t bodyEnd;  // Offset hinter dem Body der aktuellen Antwort (Ende der Range)
    size_t fill;       // Manifest: Bytes in path; Asset: Bytes in head vor Update.begin()
    HeaderParser hdr;
    br_sha256_context sha;
    char expectedVersion[FW_VERSION_MAX_LEN];
    char host[HOST_MAX_LEN];
    char path[URL_PATH_MAX_LEN];   // Pfad + Query des aktuellen Requests, danach Ziel der Location;
                                   // nach dem 200 fürs Manifest dessen Body (MANIFEST_MAX_LEN)
    // Anfang eines Assets für die Bildprüfung (beginFlash), die LFS_SUPERBLOCK_MIN_LEN B am
    // Stück braucht - der erste Record einer Range könnte kürzer sein
    uint8_t head[LFS_SUPERBLOCK_MIN_LEN];
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
// Längste Meldungen: der Heap-Fehler mit allen Zahlen (bis 226 Zeichen, mit dem CDN-Host)
// bzw. TLS-Fehler mit Host, IP und dem längsten Text aus getLastSSLError(); dazu die
// Hinweise aus failRun() (" - filesystem half written, ..." 48 Zeichen beim Reconnect).
static char s_error[256] = "";
static FwManifestOutcome s_outcome = FwManifestOutcome::Pending;
static FwManifestInfo s_manifest = {};
static bool s_abortRequested = false;
// Art des letzten Laufs: das Ergebnis eines check steht nach dessen Ende im Status
// ("check"), das eines Installs nicht (dessen Antwort gibt answerUpdateRequest).
static Job s_job = Job::Install;
static bool s_jobStarted = false; // seit dem Boot lief ein Lauf (sonst kein "check"-Ergebnis)

static const char *stateName(FwUpdateState s);
static void setState(FwUpdateState state);

// Serial-Protokoll (115200 Baud, main.cpp), Formatstrings wie bei setError im Flash.
// Nur Phasenwechsel und Ergebnisse, nie pro Record: der UART-FIFO hat 128 B, jede
// Zeile darüber hinaus wartet ~87 us pro Zeichen im Takt. Stumm, sobald UART0 auf
// den LD2450 getauscht ist (serialLogEnabled()), sonst landete das Protokoll auf dessen RX.
#define logLine(fmt, ...)                                                   \
    do {                                                                    \
        if (false) snprintf(nullptr, 0, fmt, ##__VA_ARGS__);                \
        if (serialLogEnabled())                                             \
            Serial.printf_P(PSTR("[update] " fmt "\n"), ##__VA_ARGS__);     \
    } while (0)

static const char *phaseName(Phase p) {
    switch (p) {
        case Phase::Resolve: return "DNS";
        case Phase::Tcp: return "TCP";
        case Phase::Tls: return "TLS";
        case Phase::Headers: return "HTTP-Header";
        case Phase::Body: return "Body";
        case Phase::Request: return "Request";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Absturzmarke im RTC-Speicher
//
// Übersteht Exception, Watchdog-Reset und ESP.restart(), nur Stromausfall nicht.
// Jeder Phasenwechsel schreibt sie, jedes geordnete Ende eines Laufs (endRun)
// löscht sie. Steht sie beim nächsten Boot noch da, endete der Lauf mitten in
// dieser Phase - zusammen mit dem Reset-Grund die Antwort auf "OOM-Panic,
// Watchdog oder Stack?", auch wenn beim Absturz niemand am Serial mitlas.
// Block 96 von 128 (4-B-Blöcke, Esp.cpp:177): 0-31 belegt eboot_command (128 B ab
// 0x60001200, cores/esp8266/eboot_command.h:10 und 20-25), sonst nutzt im Core, in den Libraries
// und im Projekt niemand den User-Bereich (rtcUserMemory/RTC_MEM gesucht).
// ---------------------------------------------------------------------------

static const uint32_t RTC_MARK_BLOCK = 96;
static const uint32_t RTC_MARK_MAGIC = 0x55504454; // "UPDT"

struct RtcMark {
    uint32_t magic;
    uint8_t job, fetch, phase, hops;
    uint32_t freeHeap; // beim Eintritt in die Phase
    uint32_t check;    // nach einem Stromausfall steht Zufall im RTC-Speicher
};

static uint32_t rtcMarkCheck(const RtcMark &m) {
    uint32_t packed;
    memcpy(&packed, &m.job, sizeof(packed));
    return ~(m.magic ^ packed ^ m.freeHeap);
}

static void writeRtcMark(const RunContext &r) {
    RtcMark m = {RTC_MARK_MAGIC, (uint8_t)r.job, (uint8_t)r.fetch, (uint8_t)r.phase, r.hops, ESP.getFreeHeap(), 0};
    m.check = rtcMarkCheck(m);
    ESP.rtcUserMemoryWrite(RTC_MARK_BLOCK, reinterpret_cast<uint32_t *>(&m), sizeof(m));
}

static void clearRtcMark() {
    RtcMark m = {};
    ESP.rtcUserMemoryWrite(RTC_MARK_BLOCK, reinterpret_cast<uint32_t *>(&m), sizeof(m));
}

// Beim Boot: Marke eines abgebrochenen Laufs melden (Serial + Ereignisprotokoll) und löschen.
static void reportRtcMark() {
    RtcMark m;
    if (!ESP.rtcUserMemoryRead(RTC_MARK_BLOCK, reinterpret_cast<uint32_t *>(&m), sizeof(m))) return;
    if (m.magic != RTC_MARK_MAGIC || m.check != rtcMarkCheck(m)) return;
    static const char *const FETCH_NAMES[] = {"manifest.json", "firmware.bin", "littlefs.bin"};
    const char *fetch = m.fetch < 3 ? FETCH_NAMES[m.fetch] : "?";
    const char *phase = m.phase <= (uint8_t)Phase::Request ? phaseName((Phase)m.phase) : "?";
    const String reason = ESP.getResetReason();
    logLine("ABSTURZ im letzten Lauf: %s, %s, Phase %s, Hop %u, Heap beim Eintritt %u B, Reset-Grund: %s",
            m.job == (uint8_t)Job::Check ? "check" : "install", fetch, phase, m.hops, m.freeHeap, reason.c_str());
    // Ereignistext max. 47 Zeichen (LogEvent::message); den Reset-Grund nennt schon der Boot-Eintrag
    eventLogPush(EventType::OtaUpdate, "GitHub %s crashed: phase %s, heap %u B",
                 m.job == (uint8_t)Job::Check ? "check" : "update", phase, m.freeHeap);
    clearRtcMark();
}

static void enterPhase(RunContext &r, Phase p) {
    r.phase = p;
    r.phaseStartMs = millis();
    r.heapWaiting = false;
    r.webWaiting = false;
    writeRtcMark(r);
}

// ---------------------------------------------------------------------------
// DNS ohne Blockieren
//
// Die Antwort kommt im lwIP-Callback. Statisch statt im RunContext: lwIP ruft den
// Callback auch nach unserem Timeout oder einem Abbruch noch auf, dann ist der
// RunContext womöglich schon frei. Die Nummer der Anfrage (callback_arg)
// verwirft solche Nachzügler.
// ---------------------------------------------------------------------------

static struct {
    uint8_t id;    // Nummer der offenen Anfrage
    bool done;
    uint32_t addr; // 0 = nicht aufgelöst
} s_dns;

static void onDnsFound(const char *, const ip_addr_t *addr, void *arg) {
    if ((uint8_t)(uintptr_t)arg != s_dns.id) return;
    s_dns.addr = addr ? (uint32_t)IPAddress(addr) : 0;
    s_dns.done = true;
}

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

// Sammelt den Request auf dem Stack in Stücken zu TLS_TX B: jeder write() wird beim Core
// mindestens ein eigener TLS-Record (WiFiClientSecureBearSSL.cpp:315-329), volle Stücke
// ergeben also genau so viele Records wie ein Request am Stück (~1080 B: drei).
struct RequestWriter {
    TlsClient *client;
    size_t len;
    bool ok;
    uint8_t buf[TLS_TX];

    void add(const char *s, size_t n) {
        while (ok && n) {
            const size_t take = std::min(n, sizeof(buf) - len);
            memcpy(buf + len, s, take);
            len += take;
            s += take;
            n -= take;
            if (len == sizeof(buf)) send();
        }
    }

    void send() {
        if (ok && len) ok = client->writeNoAckWait(buf, len) == len;
        len = 0;
    }
};

static bool sendRequest(RunContext &r) {
    // Stack statt RunContext: der Puffer wird nur hier gebraucht (~0,8 kB mit Kopf und Range;
    // der Stack von loop() hat 4 kB, BearSSL rechnet auf dem StackThunk). Längster Request:
    // Pfad 1151 + Host 47 + ~220 B Rest.
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
    // identity: das Gerät streamt die Bytes 1:1 in den Flash, gzip/chunked kann es nicht
    char tail[256];
    const int n = snprintf_P(tail, sizeof(tail),
                             PSTR(" HTTP/1.1\r\nHost: %s%s\r\nUser-Agent: PresenceTrack/" FIRMWARE_VERSION
                                  "\r\nAccept: */*\r\nAccept-Encoding: identity\r\n%sConnection: %s\r\n\r\n"),
                             r.host, port, range, r.fetch == Fetch::Manifest ? "close" : "keep-alive");
    // Kein setError() hier: auf einer Keep-Alive-Verbindung ist ein Fehlschlag
    // nur ein Grund zum Neuverbinden (stepRequest)
    if (n < 0 || (size_t)n >= sizeof(tail)) return false;
    RequestWriter w;
    w.client = r.client;
    w.len = 0;
    w.ok = true;
    w.add("GET ", 4);
    w.add(r.path, strlen(r.path));
    w.add(tail, n);
    w.send();
    return w.ok;
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
    r.nextLogAt = 0;
    r.updateStarted = false;
    br_sha256_init(&r.sha);
    enterPhase(r, Phase::Resolve);
    bool ok;
    if (fetch == Fetch::Manifest) {
        // MANIFEST_URL liegt im Flash; setUrl() darf auf r.path selbst arbeiten
        strncpy_P(r.path, MANIFEST_URL, sizeof(r.path) - 1);
        ok = setUrl(r, r.path);
    } else {
        setState(FwUpdateState::Downloading);
        ok = setUrl(r, fetch == Fetch::Firmware ? r.firmware.url : r.filesystem.url);
    }
    if (ok) logLine("%s: https://%s:%u%.60s", fetchName(fetch), r.host, r.port, r.path);
    return ok;
}

// "a.b.c.d" ohne String/Heap. lwIP hält die Adresse in Netz-Byte-Reihenfolge, auf
// dem (little-endian) ESP8266 steht das erste Oktett also im untersten Byte.
struct IpText {
    char s[16];
};

static IpText ipText(uint32_t ip) {
    IpText t;
    snprintf(t.s, sizeof(t.s), "%u.%u.%u.%u", ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, ip >> 24);
    return t;
}

// BearSSL-Code mit dem Text des Cores (getLastSSLError, WiFiClientSecureBearSSL.cpp:1348).
// Für 0 steht hier eine eigene Erklärung: der Core schriebe "Unknown error code.".
static int sslErrorText(RunContext &r, char *text, size_t len) {
    const int code = r.client ? r.client->getLastSSLError(text, len) : 0;
    if (code == 0) strlcpy(text, "no BearSSL error, closed by the server or the network", len);
    return code;
}

// Heap einer Verbindung, in der Reihenfolge, in der der Core ihn belegt (jede Zeile
// eine Allokation mit bis zu UMM_ALLOC_SLACK Verschnitt):
//   Socket   TlsClient (hier, new (std::nothrow)); StackThunk im Konstruktor, nur für
//            den ersten BearSSL-Client (stack_thunk_get_refcnt() == 0); tcp_pcb und
//            ClientContext in WiFiClient::connect() (WiFiClient.cpp:153, 161)
//   Sitzung  br_ssl_client_context (make_shared, WiFiClientSecureBearSSL.cpp:1135),
//            Empfangs- und Sendepuffer mit je eigenem Kontrollblock (_alloc_iobuf,
//            Zeile 1137-1138), X509InsecureSizeMirror (make_shared, Zeile 1058; nach dem
//            Handshake wieder frei, Zeile 1206)
// sizeof im Build (Core 3.1.2): TlsClient 208, tcp_pcb 184, ClientContext 52,
// br_ssl_client_context 3408, X509InsecureSizeMirror 1480 (zum Vergleich: der Wrapper
// BearSSL::WiFiClientSecure kostete 40 B + shared_ptr auf denselben Kontext zusätzlich).
// Damit Socket 6692 B (mit StackThunk), Sitzung 5946 B + Empfangspuffer 1024 B = 6970 B,
// zusammen 13662 B; ohne den X.509-Kontext (1508 B) 12154 B.
static constexpr uint32_t tlsSocketBytes(bool withStackThunk) {
    return sizeof(TlsClient) + (withStackThunk ? TLS_STACK_THUNK_BYTES + UMM_ALLOC_SLACK : 0) + sizeof(tcp_pcb) +
           TLS_CLIENT_CONTEXT_BYTES + 3 * UMM_ALLOC_SLACK;
}

static constexpr uint32_t tlsSessionBytes(int rx) {
    return sizeof(br_ssl_client_context) + TLS_SHARED_INPLACE_BYTES + rx + TLS_IN_OVERHEAD +
           TLS_SHARED_DELETER_BYTES + TLS_TX + TLS_OUT_OVERHEAD + TLS_SHARED_DELETER_BYTES +
           sizeof(X509InsecureSizeMirror) + TLS_SHARED_INPLACE_BYTES + 6 * UMM_ALLOC_SLACK;
}

static const uint32_t TLS_X509_BYTES = sizeof(X509InsecureSizeMirror) + TLS_SHARED_INPLACE_BYTES + UMM_ALLOC_SLACK;

// Bedarf vor einem Aufbauschritt: was von der Verbindung noch fehlt (socket = 0, wenn der
// Socket schon steht) plus die Reserve des Zeitpunkts, der am meisten braucht (Kommentar bei
// RESERVE_WEB): Handshake mit, Request und Transfer ohne X.509-Kontext, der noch ausstehende
// Flash-Puffer (flash) erst im Transfer.
static constexpr uint32_t tlsNeedBytes(int rx, uint32_t socket, uint32_t flash) {
    return std::max(socket + tlsSessionBytes(rx) + RESERVE_HANDSHAKE,
                    std::max(socket + tlsSessionBytes(rx) - TLS_X509_BYTES + RESERVE_REQUEST,
                             socket + tlsSessionBytes(rx) - TLS_X509_BYTES + flash + RESERVE_TRANSFER));
}

static int tlsRxFor(Fetch f) {
    return f == Fetch::Manifest ? TLS_RX_MANIFEST : TLS_RX_ASSET;
}

// Der Updater-Puffer eines Asset-Fetches kommt erst mit dem ersten Record (beginFlash),
// nach dem Handshake; bis dahin zählt er zum Bedarf. Bei einem Reconnect ist er schon belegt.
static uint32_t pendingFlashBufferBytes(const RunContext &r) {
    return r.fetch != Fetch::Manifest && !r.updateStarted ? UPDATER_BUFFER_BYTES : 0;
}

// Die Zahlen der Kommentare (Kopf, Speicher und oben) gegen den Build: ändert ein
// Core- oder Library-Update eine Größe, bricht der Build hier, statt dass die
// Heap-Rechnung still von der Beschreibung abweicht.
static_assert(sizeof(RunContext) == 1840, "RunContext: Kopfkommentar (Speicher) nachführen");
static_assert(sizeof(TlsClient) == 208 && sizeof(tcp_pcb) == 184 && sizeof(br_ssl_client_context) == 3408 &&
                  sizeof(X509InsecureSizeMirror) == 1480,
              "sizeof-Liste bei tlsSocketBytes nachführen");
static_assert(tlsSocketBytes(true) == 6692 && tlsSessionBytes(TLS_RX_MANIFEST) == 6970 &&
                  tlsSessionBytes(TLS_RX_ASSET) == 6970 && TLS_X509_BYTES == 1508,
              "Bedarf pro Verbindung nachführen");
static_assert(sizeof(pbuf) == 16 && sizeof(tcp_seg) == 16 && RX_FRAME_OVERHEAD == 82 && RX_SEGMENT_BYTES == 618 &&
                  TX_SEGMENT_OVERHEAD == 146,
              "lwIP-Größen bei RESERVE_WEB nachführen");
static_assert(RESERVE_TLS_RX == 2472 && RESERVE_TLS_TX_HANDSHAKE == 1035 && RESERVE_TLS_TX_REQUEST == 1510 &&
                  RESERVE_MQTT == 463 && RESERVE_WEB == 2692,
              "Posten im Kommentar bei RESERVE_WEB nachführen");
static_assert(RESERVE_HANDSHAKE == 3970 && RESERVE_REQUEST == 4445 && RESERVE_TRANSFER == 5627,
              "Reserve je Zeitpunkt im Kommentar bei RESERVE_WEB nachführen");
static_assert(tlsNeedBytes(TLS_RX_MANIFEST, tlsSocketBytes(true), 0) == 17781 &&
                  tlsNeedBytes(TLS_RX_ASSET, tlsSocketBytes(true), UPDATER_BUFFER_BYTES) == 18049,
              "Bedarf check/Asset im Kopfkommentar (Speicher) nachführen");
// Zielvorgabe für dieses Gerät (im schlechtesten Moment 19024 B frei, siehe Kopfkommentar)
static_assert(tlsNeedBytes(TLS_RX_MANIFEST, tlsSocketBytes(true), 0) <= 18000 &&
                  tlsNeedBytes(TLS_RX_ASSET, tlsSocketBytes(true), UPDATER_BUFFER_BYTES) <= 19000,
              "Bedarf über der Zielvorgabe");
// beginUpdater() verlässt sich darauf: 4096 B nimmt der Updater erst ab 8193 B frei, danach
// wären noch >= 4084 B frei - weniger als die Transfer-Reserve, also muss er klein bleiben.
static_assert(2 * FLASH_SECTOR_SIZE - FLASH_SECTOR_SIZE - UMM_ALLOC_SLACK < RESERVE_TRANSFER,
              "beginUpdater: Blockade ist nicht mehr nötig");

// Passt die Verbindung samt Reserve (und beim Asset dem Updater-Puffer) in den Heap?
// Vorab statt es darauf ankommen zu lassen: bis auf TlsClient und die beiden Puffer
// belegt der Core alles mit normalem `new` bzw. malloc()+abort() (StackThunk) - OOM ist
// dort ein Neustart, kein Fehlercode. Die Summe allein genügt nicht, StackThunk (6200 B),
// Sitzung (3424 B), X.509-Kontext (1496 B) und Empfangspuffer (1349 B) brauchen je einen
// zusammenhängenden Block. Deshalb werden die großen Blöcke in der Reihenfolge des Cores
// einmal testweise belegt und sofort wieder freigegeben; danach ist der Heap wie vorher
// (umm_malloc vereinigt freie Nachbarblöcke, Best-Fit, umm_malloc_cfg.h:136).
// withSocket: vor dem TCP-Aufbau (alles), sonst nur noch der Sitzungsteil.
// report: sonst nur prüfen (Wartezeit, HEAP_WAIT_MS); mit report die Meldung mit allen Zahlen.
static bool tlsHeapAvailable(RunContext &r, bool withSocket, bool report) {
    const bool withStack = withSocket && stack_thunk_get_refcnt() == 0;
    const int rx = tlsRxFor(r.fetch);
    const uint32_t socket = withSocket ? tlsSocketBytes(withStack) : 0;
    const uint32_t conn = socket + tlsSessionBytes(rx);
    const uint32_t flashBuf = pendingFlashBufferBytes(r);
    const uint32_t need = tlsNeedBytes(rx, socket, flashBuf);
    const uint32_t reserve = need - conn - flashBuf;
    const uint32_t freeHeap = ESP.getFreeHeap();
    const size_t blocks[] = {withStack ? TLS_STACK_THUNK_BYTES : 0,
                             sizeof(br_ssl_client_context) + TLS_SHARED_INPLACE_BYTES,
                             rx + TLS_IN_OVERHEAD, TLS_TX + TLS_OUT_OVERHEAD,
                             sizeof(X509InsecureSizeMirror) + TLS_SHARED_INPLACE_BYTES};
    const size_t count = sizeof(blocks) / sizeof(blocks[0]);
    void *probe[count] = {};
    bool fits = freeHeap >= need;
    for (size_t i = 0; fits && i < count; i++) {
        if (blocks[i] && !(probe[i] = malloc(blocks[i]))) fits = false;
    }
    for (size_t i = count; i-- > 0;) free(probe[i]);
    const uint32_t largest = ESP.getMaxFreeBlockSize();
    if (fits) {
        if (r.heapWaiting) {
            logLine("%s %s: Heap reicht nach %lu ms, %u B frei, nötig %u B", phaseName(r.phase), r.host,
                    millis() - r.heapWaitStartMs, freeHeap, need);
        }
        return true;
    }
    if (!report) {
        if (!r.heapWaiting) {
            r.heapWaiting = true;
            logLine("%s %s: Heap reicht noch nicht (%u B frei, größter Block %u B, nötig %u B), warte bis %lu s",
                    phaseName(r.phase), r.host, freeHeap, largest, need, HEAP_WAIT_MS / 1000);
        }
        return false;
    }
    const unsigned block = withStack ? TLS_STACK_THUNK_BYTES : blocks[1];
    const unsigned long waited = (millis() - r.heapWaitStartMs) / 1000;
    if (flashBuf) {
        setError("not enough heap for TLS to %s: %u B free, largest block %u B; needed %u B "
                 "(connection %u + flash buffer %u + reserve %u) in blocks up to %u B after %lu s - "
                 "nothing was attempted",
                 r.host, freeHeap, largest, need, conn, flashBuf, reserve, block, waited);
    } else {
        setError("not enough heap for TLS to %s: %u B free, largest block %u B; needed %u B "
                 "(connection %u + reserve %u) in blocks up to %u B after %lu s - nothing was attempted",
                 r.host, freeHeap, largest, need, conn, reserve, block, waited);
    }
    logLine("%s %s: Heap reicht nicht, %u B frei, größter Block %u B, nötig %u B (Verbindung %u + Flash-Puffer %u "
            "+ Reserve %u)",
            phaseName(r.phase), r.host, freeHeap, largest, need, conn, flashBuf, reserve);
    return false;
}

// Heap-Prüfung vor einem Aufbauschritt, mit Wartezeit: Continue = später noch einmal.
static Step checkTlsHeap(RunContext &r, bool withSocket) {
    if (!r.heapWaiting) r.heapWaitStartMs = millis();
    const bool last = millis() - r.heapWaitStartMs >= HEAP_WAIT_MS;
    if (tlsHeapAvailable(r, withSocket, last)) return Step::Finished;
    return last ? Step::Failed : Step::Continue;
}

// Tiefstwert des Laufs an den Stellen, an denen der Heap am knappsten ist (Takt-Beginn, nach
// Handshake, Request und Update.begin, nach jedem Record). Spitzen mitten in lwIP-Callbacks
// sieht nur umm_free_heap_size_min() (seit Boot, endRun nennt beides).
static void noteHeap(RunContext &r) {
    const uint32_t heap = ESP.getFreeHeap();
    if (heap < r.minHeap) r.minHeap = heap;
}

// ---------------------------------------------------------------------------
// Webserver-Pause
//
// Solange eine Verbindung aufgebaut wird (Tcp, Tls) oder ihr Request unterwegs ist,
// nimmt der Webserver keine Verbindung an (firmwareUpdateHttpConnections() == 0,
// umgesetzt über das Listen-Backlog in web_server.cpp), und der Aufbau beginnt erst, wenn
// keine mehr offen ist. So braucht ein Status-Poll (RESERVE_WEB, 2692 B) nie zugleich mit
// dem X.509-Kontext (1508 B) bzw. dem TLS-Senden (1510 B) Platz. Ein SYN in dieser Zeit
// verwirft lwIP, der Browser wiederholt es (~1 s, 3 s, 7 s): der Poll kommt später durch,
// scheitert aber nicht. Der wartende install-Request zählt nicht mit (web_server.cpp).
// ---------------------------------------------------------------------------

// Obergrenze fürs Warten auf offene HTTP-Verbindungen. ESPAsyncTCP schließt eine Verbindung
// ohne empfangene Daten nach 3 s (setRxTimeout(3), LimitedWebServer in web_server.cpp) und
// eine ohne ACK nach 5 s (ASYNC_MAX_ACK_TIME, ESPAsyncTCP.h:40); ein Status-Poll dauert
// Millisekunden. 30 s lassen auch eine langsame Antwort (Seite neu geladen) zu Ende laufen.
static const unsigned long WEB_IDLE_WAIT_MS = 30000;

static void holdWeb(RunContext &r, bool hold) {
    if (r.webHold == hold) return;
    r.webHold = hold;
    webServerApplyConnectionLimit();
}

uint8_t firmwareUpdateHttpConnections() {
    return s_run && s_run->webHold ? 0 : FW_UPDATE_HTTP_CONNECTIONS;
}

// Pausiert den Webserver und wartet, bis keine Verbindung mehr offen ist: Finished = frei,
// Continue = später noch einmal, Failed nach WEB_IDLE_WAIT_MS (Meldung gesetzt).
static Step waitWebIdle(RunContext &r) {
    holdWeb(r, true);
    const uint8_t open = webServerOpenConnections();
    const unsigned long now = millis();
    if (open == 0) {
        if (r.webWaiting && now - r.webWaitStartMs >= 1000) {
            logLine("%s %s: Webserver nach %lu ms frei", phaseName(r.phase), r.host, now - r.webWaitStartMs);
        }
        r.webWaiting = false;
        return Step::Finished;
    }
    if (!r.webWaiting) {
        r.webWaiting = true;
        r.webWaitStartMs = now;
    }
    if (now - r.webWaitStartMs < WEB_IDLE_WAIT_MS) return Step::Continue;
    setError("%u HTTP connection(s) still open after %lu s, the connection to %s was not attempted", open,
             WEB_IDLE_WAIT_MS / 1000, r.host);
    return Step::Failed;
}

// Webserver wieder offen: zwischen zwei Hops (keine TLS-Verbindung) und sobald der Request
// bestätigt ist - danach kommt nur noch der Transfer (RESERVE_TRANSFER rechnet den Poll ein).
static bool webMayRun(RunContext &r) {
    if (r.phase == Phase::Resolve) return true;
    return (r.phase == Phase::Headers || r.phase == Phase::Body) && r.client && r.client->tcpAcked();
}

// DNS ohne Blockieren: erster Takt stellt die Anfrage, die folgenden prüfen nur.
static Step stepResolve(RunContext &r) {
    if (!r.dnsPending) {
        if (WiFi.status() != WL_CONNECTED) {
            setError("Wi-Fi not connected (DNS lookup for %s not attempted)", r.host);
            logLine("DNS %s: WLAN nicht verbunden", r.host);
            return Step::Failed;
        }
        s_dns.id++;
        s_dns.done = false;
        s_dns.addr = 0;
        ip_addr_t addr;
        const err_t err = dns_gethostbyname(r.host, &addr, onDnsFound, (void *)(uintptr_t)s_dns.id);
        if (err == ERR_OK) {
            // Aus dem DNS-Cache von lwIP (Reconnect, zweiter Hop zum selben Host): kein Callback
            s_dns.addr = (uint32_t)IPAddress(&addr);
            s_dns.done = true;
        } else if (err == ERR_INPROGRESS) {
            r.dnsPending = true;
            return Step::Continue;
        } else {
            setError("DNS lookup for %s failed: lwIP error %d, no query sent", r.host, (int)err);
            logLine("DNS %s: fehlgeschlagen, lwIP-Fehler %d, keine Anfrage gesendet", r.host, (int)err);
            return Step::Failed;
        }
    }
    const unsigned long ms = millis() - r.phaseStartMs;
    if (!s_dns.done) {
        if (ms < DNS_TIMEOUT_MS) return Step::Continue;
        s_dns.id++; // eine späte Antwort gehört nicht mehr zu diesem Hop
        r.dnsPending = false;
        setError("DNS lookup for %s failed: no answer within %lu s", r.host, DNS_TIMEOUT_MS / 1000);
        logLine("DNS %s: fehlgeschlagen, keine Antwort in %lu s", r.host, DNS_TIMEOUT_MS / 1000);
        return Step::Failed;
    }
    r.dnsPending = false;
    if (!s_dns.addr) {
        setError("DNS lookup for %s failed after %lu ms: name unknown or DNS server unreachable", r.host, ms);
        logLine("DNS %s: fehlgeschlagen nach %lu ms (Name unbekannt/Server nicht erreichbar)", r.host, ms);
        return Step::Failed;
    }
    r.ip = s_dns.addr;
    logLine("DNS %s -> %s (%lu ms)", r.host, ipText(r.ip).s, ms);
    enterPhase(r, Phase::Tcp);
    return Step::Continue;
}

// TCP zur aufgelösten IP. Blockiert bis TCP_CONNECT_TIMEOUT_MS (Kopfkommentar). Vorher
// wird der Webserver pausiert und der Heap erst gemessen, wenn keine HTTP-Verbindung mehr
// offen ist - deren Heap zählt die Reserve dieses Zeitpunkts nicht (Webserver-Pause).
static Step stepTcp(RunContext &r) {
    const Step web = waitWebIdle(r);
    if (web != Step::Finished) return web;
    const Step heap = checkTlsHeap(r, true);
    if (heap != Step::Finished) return heap;
    r.client = new (std::nothrow) TlsClient();
    if (!r.client) {
        setError("out of memory for the TLS client to %s", r.host);
        return Step::Failed;
    }
    r.client->setInsecure(); // Begründung siehe Kopfkommentar
    // Puffer nach dem, was diese Verbindung holt - fest ab hier, kein Rückfall (Kopfkommentar)
    r.client->setBufferSizes(tlsRxFor(r.fetch), TLS_TX);
    r.client->setTimeout(TCP_CONNECT_TIMEOUT_MS); // erreicht WiFiClient::connect(), WiFiClient.cpp:163
    const unsigned long start = millis();
    const bool ok = r.client->connectTcp(IPAddress(r.ip), r.port);
    const unsigned long ms = millis() - start;
    const IpText ip = ipText(r.ip);
    if (!ok) {
        // Vor Ablauf des Timeouts: RST/ICMP (abgewiesen) oder kein pcb; sonst keine Antwort
        const bool timeout = ms >= TCP_CONNECT_TIMEOUT_MS;
        closeClient(r);
        setError("TCP connection to %s (%s:%u) failed after %lu ms (%s) - TLS/BearSSL was not started",
                 r.host, ip.s, r.port, ms, timeout ? "no answer" : "refused or reset");
        logLine("TCP %s:%u fehlgeschlagen nach %lu ms (%s), BearSSL lief nicht", ip.s, r.port, ms,
                timeout ? "keine Antwort" : "abgewiesen");
        return Step::Failed;
    }
    // Request und Handshake in genau passenden Segmenten statt MSS-großer pbufs
    // (RESERVE_TLS_TX_REQUEST, TCP_OVERSIZE); geht an tcp_nagle_disable (ClientContext.h:166-175)
    r.client->setNoDelay(true);
    logLine("TCP %s:%u verbunden (%lu ms)", ip.s, r.port, ms);
    enterPhase(r, Phase::Tls);
    return Step::Continue;
}

// Handshake mit SNI, danach der Request. Blockiert bis zu 15 s (Kopfkommentar).
static Step stepTls(RunContext &r) {
    const IpText ip = ipText(r.ip);
    if (!r.client->tcpEstablished()) {
        setError("TCP connection to %s (%s:%u) closed before the TLS handshake - BearSSL was not started",
                 r.host, ip.s, r.port);
        logLine("TLS %s: TCP schon wieder zu, BearSSL lief nicht", r.host);
        return Step::Failed;
    }
    // Zwischen den Takten kann der Heap geschrumpft sein (MQTT, fremde Pakete)
    const Step heap = checkTlsHeap(r, false);
    if (heap != Step::Finished) return heap;
    const uint32_t heapBefore = ESP.getFreeHeap();
    logLine("TLS %s: Handshake, Heap %u B, größter Block %u B, Empfangspuffer %d B", r.host, heapBefore,
            ESP.getMaxFreeBlockSize(), tlsRxFor(r.fetch));
    const unsigned long start = millis();
    const bool ok = r.client->handshake(r.host);
    const unsigned long ms = millis() - start;
    if (!ok) {
        char text[112];
        const int code = r.client->getLastSSLError(text, sizeof(text));
        if (code != 0) {
            setError("TLS handshake with %s (%s) failed after %lu ms: BearSSL %d - %s", r.host, ip.s, ms, code, text);
            logLine("TLS %s: fehlgeschlagen nach %lu ms, BearSSL %d - %s", r.host, ms, code, text);
        } else {
            // BearSSL lief, meldet aber nichts: _run_until() gab wegen Timeout oder
            // geschlossener Verbindung auf (Kopfkommentar, Diagnose)
            const bool tcpUp = r.client->tcpEstablished();
            setError("TLS handshake with %s (%s) failed after %lu ms without a BearSSL error (code 0): %s",
                     r.host, ip.s, ms, tcpUp ? "the server did not answer in time" : "the connection was closed");
            logLine("TLS %s: fehlgeschlagen nach %lu ms, BearSSL 0 (kein Protokollfehler), TCP %s", r.host, ms,
                    tcpUp ? "noch offen -> Timeout" : "geschlossen");
        }
        closeClient(r);
        return Step::Failed;
    }
    const uint32_t heapAfter = ESP.getFreeHeap();
    noteHeap(r);
    logLine("TLS %s: ok nach %lu ms, Heap %u -> %u B (%d B belegt), größter Block %u B", r.host, ms, heapBefore,
            heapAfter, (int)(heapBefore - heapAfter), ESP.getMaxFreeBlockSize());
    const uint32_t needAfter = TLS_HEAP_RESERVE_AFTER + pendingFlashBufferBytes(r);
    if (heapAfter < needAfter) {
        // Die Prüfung vorab hat sich verschätzt: lieber hier abbrechen als in einem `new` später
        setError("only %u B heap left after the TLS setup to %s, needed %u B (request or web %u + flash buffer %u)"
                 " - aborted",
                 heapAfter, r.host, needAfter, TLS_HEAP_RESERVE_AFTER, pendingFlashBufferBytes(r));
        logLine("TLS %s: Reserve unterschritten (%u < %u B), Abbruch", r.host, heapAfter, needAfter);
        return Step::Failed;
    }
    // Der Webserver bleibt pausiert, bis lwIP den Request bestätigt hat (webMayRun)
    if (!sendRequest(r)) {
        char text[112];
        const int code = sslErrorText(r, text, sizeof(text));
        setError("sending the request to %s failed (BearSSL %d - %s)", r.host, code, text);
        return Step::Failed;
    }
    noteHeap(r);
    resetHeaderParser(r.hdr);
    r.fill = 0;
    enterPhase(r, Phase::Headers);
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
        logLine("HTTP %d von %s, Weiterleitung %u", h.status, r.host, r.hops);
        if (!setUrl(r, r.path)) return Step::Failed;
        logLine("%s: weiter zu https://%s:%u%.60s", fetchName(r.fetch), r.host, r.port, r.path);
        enterPhase(r, Phase::Resolve);
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
        // Der Body kommt als ein Record, der muss in den Empfangspuffer (TLS_RX_MANIFEST)
        if (h.contentLength <= 0 || (size_t)h.contentLength > MANIFEST_MAX_LEN) {
            setError("manifest.json: Content-Length %d, expected 1..%u B", h.contentLength, (unsigned)MANIFEST_MAX_LEN);
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
    // Pro Range eine Zeile wären 250 für littlefs.bin: nur die erste Antwort
    if (r.received == 0) {
        logLine("HTTP %d von %s, %s %u B, Keep-Alive %s", h.status, r.host, fetchName(r.fetch),
                r.fetch == Fetch::Manifest ? r.bodyEnd : (r.fetch == Fetch::Firmware ? r.firmware.size : r.filesystem.size),
                r.keepAlive ? "ja" : "nein");
    }
    // Der Body liegt noch im Empfangspuffer (stepHeaders hat genau bis zur Leerzeile verbraucht)
    r.fill = 0;
    enterPhase(r, Phase::Body);
    r.lastDataMs = millis();
    return Step::Continue;
}

// Nächste Range auf derselben Verbindung, oder neu verbinden, wenn der Server
// sie geschlossen hat (Pfad und Host bleiben: die signierte CDN-URL gilt weiter).
// Ohne Obergrenze für Reconnects: hierher kommt ein Lauf nur nach einer
// vollständig gelieferten Range, jede Verbindung bringt also Fortschritt, und
// mehr als size / RANGE_LEN (1000 für littlefs.bin) können es nicht werden. Ein
// Server, der jede Antwort mit "Connection: close" beendet, kostet dann einen
// Handshake pro Range - langsam, aber korrekt. Bricht die Verbindung mitten in
// einer Range ab, scheitert der Download (peekBody).
static Step nextRange(RunContext &r) {
    if (r.keepAlive && r.client && r.client->connected()) {
        enterPhase(r, Phase::Request);
        return Step::Continue;
    }
    closeClient(r);
    enterPhase(r, Phase::Resolve);
    return Step::Continue;
}

// Request der nächsten Range, sobald der Webserver still ist: das TLS-Senden (bis
// RESERVE_TLS_TX_REQUEST) soll nie mit einem Poll zusammenfallen (Webserver-Pause).
// Ein laufender Poll dauert Millisekunden, die Range wartet so lange.
static Step stepRequest(RunContext &r) {
    const Step web = waitWebIdle(r);
    if (web != Step::Finished) return web;
    if (r.client->connected() && sendRequest(r)) {
        noteHeap(r);
        resetHeaderParser(r.hdr);
        enterPhase(r, Phase::Headers);
        return Step::Continue;
    }
    // Inzwischen geschlossen oder Senden gescheitert: neu verbinden
    closeClient(r);
    enterPhase(r, Phase::Resolve);
    return Step::Continue;
}

// Antwortkopf direkt aus dem Empfangspuffer: verbraucht wird genau bis zur Leerzeile,
// der Rest des Records ist Body und bleibt für stepBody liegen.
static Step stepHeaders(RunContext &r) {
    if (millis() - r.phaseStartMs > HEADER_TIMEOUT_MS) {
        setError("%s: no complete HTTP response from %s within %lu s", fetchName(r.fetch), r.host, HEADER_TIMEOUT_MS / 1000);
        return Step::Failed;
    }
    const unsigned long start = millis();
    while (millis() - start < TICK_BUDGET_MS) {
        const uint8_t *data;
        const int n = r.client->peekRecord(data);
        if (n == 0) return Step::Continue;
        if (n < 0) {
            char text[112];
            const int code = sslErrorText(r, text, sizeof(text));
            setError("%s: connection to %s lost during the headers (BearSSL %d - %s)", fetchName(r.fetch), r.host, code, text);
            return Step::Failed;
        }
        for (int i = 0; i < n; i++) {
            if (!feedHeader(r, (char)data[i])) return Step::Failed;
            if (r.hdr.state == HdrState::Done) {
                r.client->peekConsume(i + 1);
                return onHeadersDone(r);
            }
        }
        r.client->peekConsume(n);
    }
    return Step::Continue;
}

// Nächstes Stück Body aus dem Empfangspuffer, höchstens want Bytes, gültig bis
// peekConsume(). >0 Bytes, 0 = noch nichts da (später weiter), -1 = Verbindung
// weg/abgelaufen (Meldung gesetzt).
static int peekBody(RunContext &r, const uint8_t *&data, size_t want, uint32_t total) {
    const int n = r.client->peekRecord(data);
    if (n == 0) {
        if (millis() - r.lastDataMs > BODY_IDLE_TIMEOUT_MS) {
            setError("%s: download stalled at %u of %u bytes", fetchName(r.fetch), (unsigned)(r.received + r.fill), total);
            return -1;
        }
        return 0;
    }
    if (n < 0) {
        char text[112];
        const int code = sslErrorText(r, text, sizeof(text));
        setError("%s: connection lost at %u of %u bytes (BearSSL %d - %s)", fetchName(r.fetch),
                 (unsigned)(r.received + r.fill), total, code, text);
        return -1;
    }
    r.lastDataMs = millis();
    return (int)std::min<size_t>(n, want);
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

// Liest das Manifest aus r.path (r.fill Bytes, stepBody). Unbekannte Keys (tag, board,
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
    DeserializationError err = deserializeJson(doc, static_cast<const char *>(r.path), r.fill,
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
    if (state != s_state) logLine("Zustand %s -> %s", stateName(s_state), stateName(state));
    s_state = state;
    if (state != FwUpdateState::Idle) return;
    s_target = FwUpdateTarget::None;
    s_version[0] = '\0';
    s_bytesDone = 0;
    s_bytesTotal = 0;
}

// Einziger Weg aus einem Lauf (Erfolg, Fehler über failRun, Abbruch): TlsClient und
// RunContext werden hier immer freigegeben, die Absturzmarke gelöscht.
static void endRun(FwUpdateState state) {
    if (s_run) {
        closeClient(*s_run);
        const uint32_t minHeap = s_run->minHeap;
        const bool check = s_run->job == Job::Check;
        free(s_run);
        s_run = nullptr;
        // Webserver-Pause aufheben, ohne auf den nächsten webServerLoop() zu warten
        webServerApplyConnectionLimit();
        const unsigned bootMin = umm_free_heap_size_min();
        const unsigned stackFree = ESP.getFreeContStack(); // Tiefstwert seit Boot (bemalter Stack)
        // Tiefstwert "seit Boot" ist exakt (UMM_STATS_FULL) und erfasst auch Spitzen
        // mitten im Handshake, die die Messpunkte (noteHeap) nicht sehen
        logLine("Lauf beendet (%s): Heap jetzt %u B, Tiefstwert im Lauf %u B (Messpunkte), seit Boot %u B, "
                "Stack von loop() min. %u B frei",
                check ? "check" : "install", ESP.getFreeHeap(), minHeap, bootMin, stackFree);
        // Auch ins Ereignisprotokoll (/api/events): mit dem LD2450 an D7/D8 ist Serial nach dem
        // Boot stumm (serialLogEnabled). "heap <Lauf>/<seit Boot>", max. 47 Zeichen
        // (LogEvent::message); formatiert aus dem Flash, eventLogPush() nähme den Text aus dem DRAM.
        char msg[48];
        snprintf_P(msg, sizeof(msg), PSTR("GitHub %s: heap %u/%u, stack %u B"), check ? "check" : "update", minHeap,
                   bootMin, stackFree);
        eventLogPush(EventType::OtaUpdate, "%s", msg);
    }
    clearRtcMark();
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
    // Nur wenn Update.begin() lief: ein check oder ein Install, der vor dem ersten
    // Record scheitert, hat den Schlafmodus nie angefasst
    if (r.sleepForced) wifiPowerApplyConfig(s_cfg->wifi);
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
    logLine("%s in Phase %s (%s): %s", aborted ? "Abbruch" : "Fehler", phaseName(r.phase), fetchName(r.fetch), s_error);
    if (r.job == Job::Install) {
        eventLogPush(EventType::OtaUpdate, "GitHub update %s", aborted ? "aborted" : "failed");
    }
    // Ein gescheiterter check ist kein Gerätefehler: der Zustand geht auf idle
    // zurück, Ergebnis und Meldung stehen im Status ("check": "failed").
    endRun(r.job == Job::Check ? FwUpdateState::Idle : FwUpdateState::Error);
}

static Step onManifest(RunContext &r) {
    closeClient(r);
    if (!parseManifest(r)) return Step::Failed;
    const int cmp = compareVersions(s_manifest.version, FIRMWARE_VERSION);
    logLine("Manifest: Version %s, installiert %s -> %s", s_manifest.version, FIRMWARE_VERSION,
            cmp > 0 ? "Update verfügbar" : "aktuell");
    if (r.job == Job::Check) {
        s_outcome = cmp > 0 ? FwManifestOutcome::UpdateAvailable : FwManifestOutcome::NoUpdate;
        endRun(FwUpdateState::Idle);
        return Step::Finished;
    }
    // Kein TOCTOU: installiert wird nur die Version, die der Client gesehen hat
    if (r.expectedVersion[0] && compareVersions(r.expectedVersion, s_manifest.version) != 0) {
        s_outcome = FwManifestOutcome::VersionMismatch;
        logLine("install: erwartet %s, Manifest nennt %s - nichts installiert", r.expectedVersion, s_manifest.version);
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
    logLine("%s: %u B geschrieben, SHA-256 und Update.end() ok", fetchName(r.fetch), r.received);
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

// Update.begin() mit dem kleinen Puffer, wenn der große die Reserve verletzen würde.
// Updater.cpp:172-177: mehr als 2 x FLASH_SECTOR_SIZE (8192 B) frei -> 4096 B, sonst 256 B.
// Hier, mit offener CDN-Verbindung (X.509 ist nach dem Handshake wieder frei), sind bei
// 21216 B vor dem Aufbau 21216 - 12154 = 9062 B frei - der Updater nähme 4108 B und ließe
// 4954 B, 673 B unter der Transfer-Reserve (5627 B). Deshalb wird der Heap für den Aufruf
// kurz unter 8193 B gedrückt: bis zu UPDATER_HOLD_BLOCKS Blöcke (einer genügt, wenn der
// größte Block reicht) und sofort wieder frei. Dazwischen läuft nichts anderes: begin() ruft
// weder yield() noch delay() (Updater.cpp bis Zeile 185), lwIP und der Webserver kommen erst
// danach wieder dran. Der kleine Puffer ist der Weg, den der Core selbst bei knappem Heap
// geht: je 256 B ein Flash-Write, Erase weiterhin pro Sektor (Updater.cpp:380-382).
static const uint8_t UPDATER_HOLD_BLOCKS = 4;

static bool beginUpdater(RunContext &r, uint32_t size, int command) {
    void *hold[UPDATER_HOLD_BLOCKS] = {};
    const uint32_t before = ESP.getFreeHeap();
    if (before < RESERVE_TRANSFER + FLASH_SECTOR_SIZE + UMM_ALLOC_SLACK) {
        for (uint8_t i = 0; i < UPDATER_HOLD_BLOCKS; i++) {
            const uint32_t freeHeap = ESP.getFreeHeap();
            // getMaxFreeBlockSize() zählt den 4-B-Kopf mit (umm_info.c:197-198)
            const uint32_t largest = ESP.getMaxFreeBlockSize();
            if (freeHeap <= 2 * FLASH_SECTOR_SIZE || largest < 16) break;
            hold[i] = malloc(std::min<size_t>(freeHeap - 2 * FLASH_SECTOR_SIZE, largest - 8));
            if (!hold[i]) break;
        }
    }
    const uint32_t held = ESP.getFreeHeap();
    const bool ok = Update.begin(size, command);
    const uint32_t taken = held - ESP.getFreeHeap();
    for (uint8_t i = UPDATER_HOLD_BLOCKS; i-- > 0;) free(hold[i]);
    const uint32_t after = ESP.getFreeHeap();
    noteHeap(r);
    logLine("%s: Update.begin(%u B), Heap %u -> %u B, Flash-Puffer %s", fetchName(r.fetch), size, before, after,
            !ok ? "-" : taken >= FLASH_SECTOR_SIZE ? "4096 B" : "256 B");
    if (!ok) {
        setError("Update.begin failed: %s", Update.getErrorString().c_str());
        return false;
    }
    if (after < UPDATER_HEAP_RESERVE_AFTER) {
        // Nur möglich, wenn der Heap so zerstückelt war, dass die Blöcke ihn nicht unter
        // 8193 B drücken konnten, und der Updater doch 4 kB nahm
        setError("only %u B heap left after Update.begin (%u B flash buffer), needed %u B - aborted", after,
                 taken >= FLASH_SECTOR_SIZE ? FLASH_SECTOR_SIZE : UPDATER_SMALL_BUFFER, UPDATER_HEAP_RESERVE_AFTER);
        return false;
    }
    return true;
}

// Erste Bytes eines Assets (data/len, mindestens LFS_SUPERBLOCK_MIN_LEN, außer das Asset ist
// kürzer): alles, was das Image ablehnen kann, läuft vor Update.begin(), also vor dem ersten
// Flash-Erase (für littlefs.bin auch vor dem Aushängen des Dateisystems).
static bool beginFlash(RunContext &r, const Asset &a, const uint8_t *data, size_t len) {
    if (Update.isRunning()) {
        setError("another update is already in progress");
        return false;
    }
    const bool fs = r.fetch == Fetch::Filesystem;
    if (!fs) {
        if (!otaHasFirmwareMagic(data, len)) {
            setError("firmware.bin is not an ESP8266 firmware image (magic byte 0xE9 missing)");
            return false;
        }
    } else {
        uint32_t imageSize = 0;
        char err[128];
        if (!otaCheckLittleFsImage(data, len, imageSize, err, sizeof(err))) {
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
        // LittleFS-Cache in den Bereich schreibt, der gerade ersetzt wird. Gibt die Caches von
        // lfs_mount() frei (3 x 64 B, LittleFS.h:73-74, lfs.c:3937-3966, ~216 B mit Verschnitt) -
        // erst nach dem Handshake dieses Fetches, und der Firmware-Fetch davor braucht dasselbe
        // bei eingehängtem Dateisystem. Früher aushängen verschöbe den kritischen Punkt also
        // nicht; es nähme nur der Web-UI und saveConfig() das Dateisystem.
        close_all_fs();
        r.fsTouched = true;
    }
    // Vor dem Aufruf: begin() schaltet auf NONE_SLEEP (Updater.cpp:112) und kann danach
    // noch scheitern (UPDATE_ERROR_SPACE ab Zeile 135) - failRun() stellt dann zurück
    r.sleepForced = true;
    // Exakte Größe aus dem Manifest: ein abgeschnittener Download scheitert am
    // strikten Update.end(), statt ein halbes Image vorzumerken.
    const bool begun = beginUpdater(r, a.size, fs ? U_FS : U_FLASH);
    // Auch wenn danach die Reserve fehlt: der Updater läuft, failRun() muss ihn zurücksetzen
    r.updateStarted = Update.isRunning();
    if (!begun) return false;
    if (fs) r.fsWritten = true;
    setState(FwUpdateState::Flashing);
    return true;
}

// Verarbeitet ein Stück Body (direkt aus dem Empfangspuffer bzw. head). Der SHA-256 wird
// geprüft, BEVOR das letzte Stück geschrieben wird: solange noch Bytes fehlen, setzt
// Update.end() den Updater nur zurück. Wäre alles geschrieben, würde end() das Image bei einem
// Mismatch trotzdem vormerken (eboot-Kommando) - daher dieser Rückhalt.
// Finished = Asset vollständig und verifiziert; onAssetDone() ruft der Aufrufer, nachdem er
// den Record freigegeben hat (onAssetDone schließt die Verbindung).
static Step processSpan(RunContext &r, const Asset &a, const uint8_t *data, size_t len) {
    if (!r.updateStarted && !beginFlash(r, a, data, len)) return Step::Failed;
    br_sha256_update(&r.sha, data, len);
    const bool last = r.received + len == a.size;
    if (last) {
        uint8_t digest[SHA256_LEN];
        br_sha256_out(&r.sha, digest);
        if (memcmp(digest, a.sha256, SHA256_LEN) != 0) {
            setError("%s: SHA-256 mismatch, update discarded", fetchName(r.fetch));
            return Step::Failed;
        }
    }
    // write() liest data nur (memcpy in den eigenen Puffer, Updater.cpp:436-466)
    if (Update.write(const_cast<uint8_t *>(data), len) != len) {
        setError("%s: flash write failed at %u bytes: %s", fetchName(r.fetch), r.received, Update.getErrorString().c_str());
        return Step::Failed;
    }
    r.received += len;
    s_bytesDone += len;
    if (r.received >= r.nextLogAt) {
        // Alle 64 kB eine Zeile: Fortschritt und Heap während Flash-Schreiben und TLS
        logLine("%s: %u/%u B, Heap %u B", fetchName(r.fetch), r.received, a.size, ESP.getFreeHeap());
        r.nextLogAt = r.received + 65536;
    }
    if (!last) return Step::Continue;
    if (!Update.end(false)) {
        setError("%s: update verification failed: %s", fetchName(r.fetch), Update.getErrorString().c_str());
        return Step::Failed;
    }
    r.updateStarted = false;
    return Step::Finished;
}

// Manifest: Body in den Pfad-Puffer (nach dem 200 frei, MANIFEST_MAX_LEN passt hinein).
static Step readManifestBody(RunContext &r) {
    while (r.fill < r.bodyEnd) {
        const uint8_t *data;
        const int n = peekBody(r, data, r.bodyEnd - r.fill, r.bodyEnd);
        if (n <= 0) return n < 0 ? Step::Failed : Step::Continue;
        memcpy(r.path + r.fill, data, n);
        r.fill += n;
        r.client->peekConsume(n);
    }
    return onManifest(r);
}

static Step stepBody(RunContext &r) {
    if (r.fetch == Fetch::Manifest) return readManifestBody(r);
    const Asset &a = r.fetch == Fetch::Firmware ? r.firmware : r.filesystem;
    const unsigned long start = millis();
    while (millis() - start < TICK_BUDGET_MS) {
        if (r.received == r.bodyEnd) return nextRange(r);
        const uint8_t *data;
        // r.fill: schon in head gesammelt, noch nicht in received
        const int n = peekBody(r, data, r.bodyEnd - r.received - r.fill, a.size);
        if (n <= 0) return n < 0 ? Step::Failed : Step::Continue;
        Step s;
        if (!r.updateStarted) {
            // Anfang des Assets erst sammeln: die Bildprüfung braucht LFS_SUPERBLOCK_MIN_LEN B
            // am Stück, ein Record kann kürzer sein
            const size_t take = std::min<size_t>(n, sizeof(r.head) - r.fill);
            memcpy(r.head + r.fill, data, take);
            r.fill += take;
            r.client->peekConsume(take);
            if (r.fill < sizeof(r.head) && r.received + r.fill < r.bodyEnd) continue;
            s = processSpan(r, a, r.head, r.fill);
            r.fill = 0;
        } else {
            s = processSpan(r, a, data, n);
            r.client->peekConsume(n);
        }
        noteHeap(r);
        if (s == Step::Finished) return onAssetDone(r);
        if (s != Step::Continue) return s;
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
    reportRtcMark();
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
    if (!r) {
        logLine("%s: kein Heap für den RunContext (%u B), frei %u B", job == Job::Check ? "check" : "install",
                (unsigned)sizeof(RunContext), ESP.getFreeHeap());
        return false;
    }
    s_run = r;
    r->job = job;
    r->minHeap = ESP.getFreeHeap();
    if (expectedVersion) strlcpy(r->expectedVersion, expectedVersion, sizeof(r->expectedVersion));
    s_error[0] = '\0';
    s_outcome = FwManifestOutcome::Pending;
    s_manifest = {};
    s_abortRequested = false;
    s_job = job;
    s_jobStarted = true;
    s_target = target;
    strlcpy(s_version, expectedVersion ? expectedVersion : "", sizeof(s_version));
    s_bytesDone = 0;
    s_bytesTotal = 0;
    const uint32_t socket = tlsSocketBytes(stack_thunk_get_refcnt() == 0);
    const uint32_t manifestConn = socket + tlsSessionBytes(TLS_RX_MANIFEST);
    const uint32_t manifestNeed = tlsNeedBytes(TLS_RX_MANIFEST, socket, 0);
    const uint32_t assetConn = socket + tlsSessionBytes(TLS_RX_ASSET);
    const uint32_t assetNeed = tlsNeedBytes(TLS_RX_ASSET, socket, UPDATER_BUFFER_BYTES);
    logLine("Start %s (v%s), Heap %u B, größter Block %u B; Bedarf Manifest %u B (Verbindung %u + Reserve %u), "
            "Asset %u B (Verbindung %u + Flash-Puffer %u + Reserve %u)",
            job == Job::Check ? "check" : "install", FIRMWARE_VERSION, r->minHeap, ESP.getMaxFreeBlockSize(),
            manifestNeed, manifestConn, manifestNeed - manifestConn, assetNeed, assetConn, UPDATER_BUFFER_BYTES,
            assetNeed - assetConn - UPDATER_BUFFER_BYTES);
    setState(FwUpdateState::Checking);
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
        logLine("Abbruch angefordert (Phase %s)", phaseName(s_run->phase));
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
    noteHeap(*r);
    if (r->webHold && webMayRun(*r)) holdWeb(*r, false);
    Step s;
    if (s_abortRequested) {
        s = Step::Failed;
    } else {
        switch (r->phase) {
            case Phase::Resolve: s = stepResolve(*r); break;
            case Phase::Tcp: s = stepTcp(*r); break;
            case Phase::Tls: s = stepTls(*r); break;
            case Phase::Headers: s = stepHeaders(*r); break;
            case Phase::Request: s = stepRequest(*r); break;
            default: s = stepBody(*r); break;
        }
    }
    // Finished hat den Lauf schon beendet (s_run ist dann frei)
    if (s == Step::Failed) failRun();
}

// Ergebnis des letzten check für den Status; "" wenn der letzte Lauf ein Install
// war (dessen Ergebnis beantwortet answerUpdateRequest) oder seit dem Boot keiner lief.
static const char *checkName() {
    if (!s_jobStarted || s_job != Job::Check) return "";
    switch (s_outcome) {
        case FwManifestOutcome::Pending: return "running";
        case FwManifestOutcome::UpdateAvailable: return "available";
        case FwManifestOutcome::NoUpdate: return "none";
        case FwManifestOutcome::Aborted: return "aborted";
        default: return "failed";
    }
}

size_t firmwareUpdateStatusToJson(char *buf, size_t size) {
    const char *check = checkName();
    const bool available = strcmp(check, "available") == 0;
    int n = snprintf(buf, size,
                     "{\"state\":\"%s\",\"target\":\"%s\",\"version\":\"%s\",\"bytes_done\":%u,\"bytes_total\":%u,"
                     "\"check\":\"%s\",\"current_version\":\"" FIRMWARE_VERSION "\"",
                     stateName(s_state), targetName(s_target), s_version, s_bytesDone, s_bytesTotal, check);
    if (n < 0 || (size_t)n >= size) return 0;
    size_t len = n;
    if (available) {
        n = snprintf(buf + len, size - len, ",\"available_version\":\"%s\",\"firmware_size\":%u,\"filesystem_size\":%u",
                     s_manifest.version, s_manifest.firmwareSize, s_manifest.filesystemSize);
        if (n < 0 || len + n >= size) return 0;
        len += n;
    }
    static const char ERROR_KEY[] = ",\"error\":\"";
    if (len + sizeof(ERROR_KEY) - 1 + 3 > size) return 0;
    memcpy(buf + len, ERROR_KEY, sizeof(ERROR_KEY) - 1);
    len += sizeof(ERROR_KEY) - 1;
    // Die Meldung gehört zum Zustand error bzw. zu einem gescheiterten oder
    // abgebrochenen check (Zustand dann idle)
    const bool checkError = strcmp(check, "failed") == 0 || strcmp(check, "aborted") == 0;
    const char *err = s_state == FwUpdateState::Error || checkError ? s_error : "";
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
