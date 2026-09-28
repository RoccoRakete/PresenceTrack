#include "sensor_data.h"
#include "event_log.h"
#include <SoftwareSerial.h>

SensorState g_sensorState;

// LD2450 UART: fixed 256000 baud 8N1, a report frame roughly every 100 ms.
static const uint32_t LD2450_BAUD = 256000;
static const size_t LD2450_RX_BUFFER = 256;           // ~8 frames of slack for a busy loop()
static const unsigned long LD2450_STALE_MS = 1000;    // no valid frame for this long -> targets cleared
// Normal report frame: header, 3 x 8 target bytes, footer (30 bytes in total).
static const uint8_t LD2450_HEADER[] = {0xAA, 0xFF, 0x03, 0x00};
static const uint8_t LD2450_FOOTER[] = {0x55, 0xCC};
static const uint8_t LD2450_TARGET_BYTES = 8;
static const uint8_t LD2450_BODY_BYTES = LD2450_MAX_TARGETS * LD2450_TARGET_BYTES;

enum class Ld2450RxState : uint8_t { WaitHeader, ReadBody, WaitFooter };

static Stream *s_ld2450Uart = nullptr; // Serial (swapped) or a SoftwareSerial, nullptr until sensorsBegin() / on invalid pins
static Ld2450RxState s_ld2450RxState = Ld2450RxState::WaitHeader;
static uint8_t s_ld2450RxPos = 0; // matched header/footer bytes or collected body bytes
static uint8_t s_ld2450Body[LD2450_BODY_BYTES];
static unsigned long s_ld2450LastFrameMs = 0;

// Simulation tick, independent of the 2 s web UI poll so that targets move smoothly.
static const unsigned long LD2450_TICK_MS = 300;
static const float SIM_MAX_DT_S = 1.0f;             // clamp for the first / delayed tick
static const float SIM_SPEED_MIN_MM_S = 200.0f;     // slow stroll
static const float SIM_SPEED_MAX_MM_S = 1200.0f;    // brisk walk
static const float SIM_NOISE_MM = 15.0f;            // per-tick position jitter
static const long SIM_DROP_PER_MILLE = 5;           // per tick: target lost (~every 60 s on average)
static const long SIM_TURN_PER_MILLE = 20;          // per tick: pick a new heading
static const unsigned long SIM_PAUSE_MIN_MS = 3000; // pause before a lost target reappears
static const unsigned long SIM_PAUSE_MAX_MS = 15000;
// Simulated signal quality (resolution field), falling linearly with distance.
// The scale of the real sensor field is not verified yet and has to be
// recalibrated against real sensor frames.
static const float SIM_RES_NEAR = 30000.0f;         // at the sensor
static const float SIM_RES_FAR = 2000.0f;           // at maxRangeMm and beyond
static const float SIM_RES_NOISE = 1500.0f;         // per-tick jitter

// Internal state of one simulated target slot (float for smooth movement).
struct SimTarget {
    bool active = false;
    float x = 0.0f;
    float y = 0.0f;
    float vx = 0.0f;
    float vy = 0.0f;
    unsigned long respawnAtMs = 0;
};

static SimTarget s_simTargets[LD2450_MAX_TARGETS];

// Debounce state for the occupancy timeout (per zone and aggregated).
static bool s_zoneSeen[MAX_ZONES] = {false};
static unsigned long s_zoneLastSeenMs[MAX_ZONES] = {0};
static bool s_presenceSeen = false;
static unsigned long s_presenceLastSeenMs = 0;

// Hold-off before a target counts as still again, so that short speed dips
// (turning, radial speed near zero while walking sideways) do not flicker.
// Zone and global motion are derived from this debounced per-target state.
static const unsigned long MOTION_HOLDOFF_MS = 1200;
static bool s_targetMovingSeen[LD2450_MAX_TARGETS] = {false};
static unsigned long s_targetMovingLastSeenMs[LD2450_MAX_TARGETS] = {0};

static unsigned long s_lastLd2450Update = 0;
static unsigned long s_lastBh1750Update = 0;
static bool s_ld2450Cleared = false;

static float randomFloat(float minVal, float maxVal) {
    return minVal + (maxVal - minVal) * (float)random(0, 10001) / 10000.0f;
}

static unsigned long randomPauseMs() {
    return (unsigned long)random(SIM_PAUSE_MIN_MS, SIM_PAUSE_MAX_MS + 1);
}

const char *ld2450PinError(uint8_t rxPin, uint8_t txPin) {
    if (rxPin == 13 && txPin == 15) return nullptr;
    if (rxPin == 1 || rxPin == 3 || txPin == 1 || txPin == 3) {
        return "GPIO1/GPIO3 (TX/RX) belong to the USB serial console - use D7/D8 (RX 13, TX 15) for the hardware UART";
    }
    if (rxPin == 16) return "GPIO16 (D0) has no pin-change interrupt and cannot receive UART data";
    return nullptr;
}

bool serialLogEnabled() {
    return s_ld2450Uart != &Serial;
}

// Opens the LD2450 UART on cfg.ld2450.rxPin / txPin. The pins are only read
// here at boot (the web UI asks for a restart after a pin change).
static void ld2450UartBegin(const AppConfig &cfg) {
    const uint8_t rx = cfg.ld2450.rxPin;
    const uint8_t tx = cfg.ld2450.txPin;
    if (rx == 13 && tx == 15) {
        // Default D7/D8: hardware UART0 swapped onto GPIO13/15 (FIFO, reliable at
        // 256000 baud). From here on every Serial.print() goes to the sensor's RX
        // instead of USB - the boot log ends with this line. Plain text cannot
        // form a sensor command (those start with FD FC FB FA).
        Serial.println("LD2450 on UART0 (D7/D8) - USB serial log ends here");
        Serial.flush();
        Serial.setRxBufferSize(LD2450_RX_BUFFER);
        Serial.begin(LD2450_BAUD);
        Serial.swap();
        s_ld2450Uart = &Serial;
    } else if (const char *err = ld2450PinError(rx, tx)) {
        // Normally rejected by the web UI; guards against an old or hand-edited
        // config. The LD2450 stays without data instead of a pin collision.
        Serial.printf("LD2450 disabled: %s\n", err);
    } else {
        // Only allocated when needed.
        SoftwareSerial *sw = new SoftwareSerial();
        sw->begin(LD2450_BAUD, SWSERIAL_8N1, rx, tx, false, LD2450_RX_BUFFER);
        s_ld2450Uart = sw;
        Serial.printf("LD2450 on SoftwareSerial RX=%u TX=%u%s\n", rx, tx,
                      *sw ? "" : " - invalid pins, no data");
    }
}

void sensorsBegin(const AppConfig &cfg) {
    ld2450UartBegin(cfg);
    // TODO: once the hardware is connected, initialize I2C (BH1750) via
    // Wire.begin(cfg.bh1750.sdaPin, cfg.bh1750.sclPin).
    randomSeed(micros());

    unsigned long now = millis();
    for (uint8_t i = 0; i < LD2450_MAX_TARGETS; i++) {
        s_simTargets[i].active = false;
        s_simTargets[i].respawnAtMs = now + (unsigned long)random(500, 5000);
    }
}

// Heads the target towards a random point in the inner area of the map.
static void aimAtRandomPoint(SimTarget &t, float maxRange) {
    float dx = randomFloat(-maxRange * 0.5f, maxRange * 0.5f) - t.x;
    float dy = randomFloat(maxRange * 0.2f, maxRange * 0.8f) - t.y;
    float len = sqrtf(dx * dx + dy * dy);
    if (len < 1.0f) {
        dx = 0.0f;
        dy = 1.0f;
        len = 1.0f;
    }
    float speed = randomFloat(SIM_SPEED_MIN_MM_S, SIM_SPEED_MAX_MM_S);
    t.vx = dx / len * speed;
    t.vy = dy / len * speed;
}

// Lets the target enter the map at a random position on the left, right or far edge.
static void spawnAtEdge(SimTarget &t, float maxRange) {
    switch (random(0, 3)) {
        case 0:
            t.x = -maxRange;
            t.y = randomFloat(0.0f, maxRange);
            break;
        case 1:
            t.x = maxRange;
            t.y = randomFloat(0.0f, maxRange);
            break;
        default:
            t.x = randomFloat(-maxRange, maxRange);
            t.y = maxRange;
            break;
    }
    aimAtRandomPoint(t, maxRange);
    t.active = true;
}

static void moveTarget(SimTarget &t, float maxRange, float dtS) {
    if (random(0, 1000) < SIM_TURN_PER_MILLE) {
        aimAtRandomPoint(t, maxRange);
    }
    t.x += t.vx * dtS + randomFloat(-SIM_NOISE_MM, SIM_NOISE_MM);
    t.y += t.vy * dtS + randomFloat(-SIM_NOISE_MM, SIM_NOISE_MM);

    // Reflect at the map bounds (also clamps after max_range_mm was reduced)
    if (t.x < -maxRange) {
        t.x = -maxRange;
        t.vx = fabsf(t.vx);
    } else if (t.x > maxRange) {
        t.x = maxRange;
        t.vx = -fabsf(t.vx);
    }
    if (t.y < 0.0f) {
        t.y = 0.0f;
        t.vy = fabsf(t.vy);
    } else if (t.y > maxRange) {
        t.y = maxRange;
        t.vy = -fabsf(t.vy);
    }
}

// Stateful simulation of up to three moving targets, so that the zone map in
// the web UI and the Home Assistant entities can be tested without hardware.
// The real driver (pollLd2450Uart) fills the same state.targets[].
static void simulateLd2450Targets(const AppConfig &cfg, unsigned long now, float dtS) {
    Ld2450State &s = g_sensorState.ld2450;
    const float maxRange = (float)cfg.ld2450.maxRangeMm;

    for (uint8_t i = 0; i < LD2450_MAX_TARGETS; i++) {
        SimTarget &t = s_simTargets[i];
        bool allowed = cfg.ld2450.multiTarget || i == 0;

        if (t.active && (!allowed || random(0, 1000) < SIM_DROP_PER_MILLE)) {
            t.active = false;
            t.respawnAtMs = now + randomPauseMs();
        } else if (t.active) {
            moveTarget(t, maxRange, dtS);
        } else if (allowed && (long)(now - t.respawnAtMs) >= 0) {
            spawnAtEdge(t, maxRange);
        }

        Ld2450Target &out = s.targets[i];
        if (!t.active) {
            out = Ld2450Target{};
            continue;
        }
        out.active = true;
        out.xMm = (int16_t)lroundf(t.x);
        out.yMm = (int16_t)lroundf(t.y);
        // Radial speed like the sensor reports it (positive = moving away)
        float r = sqrtf(t.x * t.x + t.y * t.y);
        float radialMmS = r > 1.0f ? (t.x * t.vx + t.y * t.vy) / r : 0.0f;
        out.speedCmS = (int16_t)lroundf(radialMmS / 10.0f);
        float rangeFrac = maxRange > 0.0f ? constrain(r / maxRange, 0.0f, 1.0f) : 1.0f;
        float res = SIM_RES_NEAR - (SIM_RES_NEAR - SIM_RES_FAR) * rangeFrac +
                    randomFloat(-SIM_RES_NOISE, SIM_RES_NOISE);
        out.resolution = (uint16_t)lroundf(constrain(res, 0.0f, 65535.0f));
    }
}

// x / y / speed are sign-magnitude, not two's complement: bit 15 set means
// positive, clear means negative, the lower 15 bits are the magnitude.
static int16_t decodeLd2450Signed(const uint8_t *p) {
    uint16_t raw = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    int16_t magnitude = (int16_t)(raw & 0x7FFF);
    return (raw & 0x8000) ? magnitude : (int16_t)-magnitude;
}

// Copies a complete frame body into state.targets[]. An empty slot is sent as
// all zeros; `moving` is left to classifyTargetMotion().
static void applyLd2450Frame(unsigned long now) {
    Ld2450State &s = g_sensorState.ld2450;
    for (uint8_t i = 0; i < LD2450_MAX_TARGETS; i++) {
        const uint8_t *p = s_ld2450Body + i * LD2450_TARGET_BYTES;
        Ld2450Target &out = s.targets[i];
        int16_t x = decodeLd2450Signed(p);
        int16_t y = decodeLd2450Signed(p + 2);
        if (x == 0 && y == 0) {
            out = Ld2450Target{};
            continue;
        }
        out.active = true;
        out.xMm = x;
        out.yMm = y;
        out.speedCmS = decodeLd2450Signed(p + 4);
        out.resolution = (uint16_t)p[6] | ((uint16_t)p[7] << 8);
    }
    s_ld2450LastFrameMs = now;
    g_sensorState.ld2450LastUpdateMs = now;
}

// Header matching; a mismatching byte is checked again as a possible header
// start, so a frame directly after garbage is not lost.
static void matchLd2450Header(uint8_t b) {
    if (b == LD2450_HEADER[s_ld2450RxPos]) {
        s_ld2450RxPos++;
    } else {
        s_ld2450RxPos = b == LD2450_HEADER[0] ? 1 : 0;
    }
    if (s_ld2450RxPos == sizeof(LD2450_HEADER)) {
        s_ld2450RxState = Ld2450RxState::ReadBody;
        s_ld2450RxPos = 0;
    }
}

// Non-blocking frame parser, fed with every waiting byte on each loop() so the
// UART buffer cannot overflow. Frames are only applied without simulation;
// with simulation on, the bytes are still drained so no stale backlog remains.
static void pollLd2450Uart(bool apply, unsigned long now) {
    if (!s_ld2450Uart) return;
    while (s_ld2450Uart->available() > 0) {
        uint8_t b = (uint8_t)s_ld2450Uart->read();
        switch (s_ld2450RxState) {
            case Ld2450RxState::WaitHeader:
                matchLd2450Header(b);
                break;
            case Ld2450RxState::ReadBody:
                s_ld2450Body[s_ld2450RxPos++] = b;
                if (s_ld2450RxPos == LD2450_BODY_BYTES) {
                    s_ld2450RxState = Ld2450RxState::WaitFooter;
                    s_ld2450RxPos = 0;
                }
                break;
            case Ld2450RxState::WaitFooter:
                if (b != LD2450_FOOTER[s_ld2450RxPos]) {
                    s_ld2450RxState = Ld2450RxState::WaitHeader;
                    s_ld2450RxPos = 0;
                    matchLd2450Header(b);
                    break;
                }
                if (++s_ld2450RxPos == sizeof(LD2450_FOOTER)) {
                    if (apply) applyLd2450Frame(now);
                    s_ld2450RxState = Ld2450RxState::WaitHeader;
                    s_ld2450RxPos = 0;
                }
                break;
        }
    }
}

// Sensor unplugged or silent: drop the last targets instead of freezing them,
// the occupancy timeout then clears presence as usual.
static void expireLd2450Targets(unsigned long now) {
    if (now - s_ld2450LastFrameMs < LD2450_STALE_MS) return;
    for (uint8_t i = 0; i < LD2450_MAX_TARGETS; i++) {
        if (g_sensorState.ld2450.targets[i].active) {
            g_sensorState.ld2450.targets[i] = Ld2450Target{};
        }
    }
}

// Keeps presence true until holdMs after the last detection.
static bool debouncePresence(bool detected, unsigned long now, unsigned long holdMs,
                             bool &seen, unsigned long &lastSeenMs) {
    if (detected) {
        seen = true;
        lastSeenMs = now;
        return true;
    }
    if (seen && now - lastSeenMs < holdMs) {
        return true;
    }
    seen = false;
    return false;
}

static bool targetInZone(const Ld2450Target &t, const ZoneConfig &z) {
    int16_t minX = min(z.x1, z.x2);
    int16_t maxX = max(z.x1, z.x2);
    int16_t minY = min(z.y1, z.y2);
    int16_t maxY = max(z.y1, z.y2);
    return t.xMm >= minX && t.xMm <= maxX && t.yMm >= minY && t.yMm <= maxY;
}

// Moving/still per target slot. An inactive slot drops its hold-off, so a
// target that (re)appears in the same slot does not inherit the old state.
static void classifyTargetMotion(const AppConfig &cfg, unsigned long now) {
    Ld2450State &s = g_sensorState.ld2450;
    const int threshold = cfg.ld2450.movingThresholdCmS;

    for (uint8_t t = 0; t < LD2450_MAX_TARGETS; t++) {
        Ld2450Target &target = s.targets[t];
        if (!target.active) {
            target.moving = false;
            s_targetMovingSeen[t] = false;
            continue;
        }
        bool detected = abs((int)target.speedCmS) >= threshold;
        target.moving = debouncePresence(detected, now, MOTION_HOLDOFF_MS,
                                         s_targetMovingSeen[t], s_targetMovingLastSeenMs[t]);
    }
}

// Firmware-side evaluation (independent of simulated vs. real targets):
// target count, per-zone point-in-rectangle check, occupancy timeout and
// moving/still (derived from the debounced target state, no extra hold-off).
static void evaluateLd2450Presence(const AppConfig &cfg, unsigned long now) {
    Ld2450State &s = g_sensorState.ld2450;
    const unsigned long holdMs = (unsigned long)cfg.ld2450.occupancyTimeoutS * 1000UL;

    uint8_t count = 0;
    for (uint8_t t = 0; t < LD2450_MAX_TARGETS; t++) {
        if (s.targets[t].active) count++;
    }
    s.targetCount = count;

    classifyTargetMotion(cfg, now);
    bool anyMoving = false;
    for (uint8_t t = 0; t < LD2450_MAX_TARGETS; t++) {
        anyMoving = anyMoving || (s.targets[t].active && s.targets[t].moving);
    }

    for (uint8_t i = 0; i < MAX_ZONES; i++) {
        const ZoneConfig &z = cfg.zones[i];
        if (!z.present || !z.enabled) {
            if (s.zonePresence[i]) {
                eventLogPush(EventType::ZoneExit, "Left: %s (zone disabled)", z.name);
            }
            s_zoneSeen[i] = false;
            s.zonePresence[i] = false;
            s.zoneMoving[i] = false;
            continue;
        }
        bool hit = false;
        bool movingHit = false;
        for (uint8_t t = 0; t < LD2450_MAX_TARGETS; t++) {
            const Ld2450Target &target = s.targets[t];
            // Per-zone signal filter only; target count / global presence stay unfiltered
            if (!target.active || target.resolution < z.minResolution || !targetInZone(target, z)) continue;
            hit = true;
            movingHit = movingHit || target.moving;
        }
        bool wasPresent = s.zonePresence[i];
        s.zonePresence[i] = debouncePresence(hit, now, holdMs, s_zoneSeen[i], s_zoneLastSeenMs[i]);
        s.zoneMoving[i] = s.zonePresence[i] && movingHit;
        if (s.zonePresence[i] != wasPresent) {
            eventLogPush(s.zonePresence[i] ? EventType::ZoneEnter : EventType::ZoneExit,
                         "%s: %s", s.zonePresence[i] ? "Entered" : "Left", z.name);
        }
    }

    bool wasPresent = s.presence;
    s.presence = debouncePresence(count > 0, now, holdMs, s_presenceSeen, s_presenceLastSeenMs);
    s.motion = s.presence && anyMoving;
    if (s.presence != wasPresent) {
        eventLogPush(EventType::PresenceChanged, s.presence ? "Presence detected" : "Presence cleared");
    }
}

static void simulateBh1750() {
    Bh1750State &s = g_sensorState.bh1750;
    s.lux = 50.0f + (float)random(0, 5000) / 10.0f;
    s.valid = true;
}

// Drops all LD2450 targets and presence (incl. debounce), e.g. when the data source changes.
static void clearLd2450State() {
    g_sensorState.ld2450 = Ld2450State{};
    s_presenceSeen = false;
    for (uint8_t i = 0; i < MAX_ZONES; i++) s_zoneSeen[i] = false;
    for (uint8_t t = 0; t < LD2450_MAX_TARGETS; t++) s_targetMovingSeen[t] = false;
}

// Applies a changed sim_enabled setting. The values of the previous data
// source (simulation or UART) are cleared.
static void syncSimMode(const AppConfig &cfg, unsigned long now) {
    if (cfg.ld2450.simEnabled != g_sensorState.ld2450SimMode) {
        g_sensorState.ld2450SimMode = cfg.ld2450.simEnabled;
        clearLd2450State();
        for (uint8_t i = 0; i < LD2450_MAX_TARGETS; i++) {
            s_simTargets[i].active = false;
            s_simTargets[i].respawnAtMs = now + randomPauseMs();
        }
    }
    if (cfg.bh1750.simEnabled != g_sensorState.bh1750SimMode) {
        g_sensorState.bh1750SimMode = cfg.bh1750.simEnabled;
        g_sensorState.bh1750 = Bh1750State{};
        s_lastBh1750Update = now - cfg.bh1750.intervalMs - 1; // next reading right away
    }
}

void sensorsLoop(const AppConfig &cfg) {
    unsigned long now = millis();

    syncSimMode(cfg, now);

    if (cfg.ld2450.enabled) {
        s_ld2450Cleared = false;
        // Every loop(), not only on the tick, so the UART buffer cannot overflow
        pollLd2450Uart(!cfg.ld2450.simEnabled, now);
        if (now - s_lastLd2450Update >= LD2450_TICK_MS) {
            float dtS = (float)(now - s_lastLd2450Update) / 1000.0f;
            if (dtS > SIM_MAX_DT_S) dtS = SIM_MAX_DT_S;
            s_lastLd2450Update = now;
            if (cfg.ld2450.simEnabled) {
                simulateLd2450Targets(cfg, now, dtS);
                g_sensorState.ld2450LastUpdateMs = now;
            } else {
                expireLd2450Targets(now);
            }
            evaluateLd2450Presence(cfg, now);
        }
    } else if (!s_ld2450Cleared) {
        // Disabled sensor must not keep reporting stale presence
        clearLd2450State();
        s_ld2450Cleared = true;
    }

    if (cfg.bh1750.enabled && now - s_lastBh1750Update > cfg.bh1750.intervalMs) {
        s_lastBh1750Update = now;
        if (cfg.bh1750.simEnabled) {
            simulateBh1750();
            g_sensorState.bh1750LastUpdateMs = now;
        }
        // TODO: read the real BH1750 driver via I2C
    }
}
