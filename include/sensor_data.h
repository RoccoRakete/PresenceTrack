#pragma once

#include <Arduino.h>
#include "app_config.h"

// Shared runtime state, filled by the (currently simulated) drivers and
// read by the web server / MQTT / HA layer. Once the real hardware is
// connected, an LD2450 / BH1750 driver only replaces the update()
// implementation - the data structure stays the same.
static const uint8_t LD2450_MAX_TARGETS = 3;

struct Ld2450Target {
    bool active = false;
    int16_t xMm = 0;
    int16_t yMm = 0;
    int16_t speedCmS = 0;
    uint16_t resolution = 0; // raw value from the target frame (0 until a real driver exists)
    bool moving = false; // |speedCmS| >= movingThresholdCmS, debounced per slot
};

struct Ld2450State {
    Ld2450Target targets[LD2450_MAX_TARGETS];
    uint8_t targetCount = 0;
    bool zonePresence[MAX_ZONES] = {false};
    bool zoneMoving[MAX_ZONES] = {false}; // zonePresence && a moving target inside the zone
    bool presence = false; // aggregated, debounced via occupancyTimeoutS
    bool motion = false;   // presence && any active target moving
};

struct Bh1750State {
    float lux = 0.0f;
    bool valid = false;
};

struct SensorState {
    Ld2450State ld2450;
    Bh1750State bh1750;
    bool ld2450SimMode = true; // simulated data is delivered (sim_enabled, no real sensor detected)
    bool bh1750SimMode = true;
    unsigned long ld2450LastUpdateMs = 0; // millis() of the last actual data update
    unsigned long bh1750LastUpdateMs = 0;
};

extern SensorState g_sensorState;

// Initializes the (simulated) sensor drivers based on the current config.
void sensorsBegin(const AppConfig &cfg);

// Must be called regularly from loop().
void sensorsLoop(const AppConfig &cfg);
