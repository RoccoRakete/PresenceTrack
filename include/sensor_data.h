#pragma once

#include <Arduino.h>
#include "app_config.h"

// Shared runtime state, filled by the drivers (LD2450 via UART, BH1750 via I2C,
// each optionally simulated) and read by the web server / MQTT / HA layer.
static const uint8_t LD2450_MAX_TARGETS = 3;

struct Ld2450Target {
    bool active = false;
    int16_t xMm = 0;
    int16_t yMm = 0;
    int16_t speedCmS = 0;
    uint16_t resolution = 0; // raw value from the target frame (simulated with sim_enabled)
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

// Checks the LD2450 UART pins; nullptr if usable, otherwise the reason. RX 13 /
// TX 15 swaps the hardware UART0 there; any other pair runs a SoftwareSerial,
// which must not touch GPIO1/3 (UART0, USB serial) and cannot receive on GPIO16
// (no pin-change interrupt).
const char *ld2450PinError(uint8_t rxPin, uint8_t txPin);

// Initializes the sensor drivers (LD2450 UART, BH1750 I2C bus on the configured pins) based on the current config.
void sensorsBegin(const AppConfig &cfg);

// False once sensorsBegin() has swapped UART0 onto the LD2450 (RX 13 / TX 15):
// Serial then no longer reaches USB, and log output would go to the sensor's RX.
bool serialLogEnabled();

// Must be called regularly from loop().
void sensorsLoop(const AppConfig &cfg);
