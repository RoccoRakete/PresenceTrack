#pragma once

// Single source of truth for the firmware release version: reported as
// sw_version in the Home Assistant discovery payloads (mqtt_ha.cpp) and as
// fw_version by /api/system, so the web UI can show which build an OTA update
// actually brought up. Bump it with every release.
//
// Deliberately independent of CONFIG_SCHEMA_VERSION (app_config.cpp): the
// config layout only changes with some releases, and a firmware that keeps the
// layout must not look like a schema change in /config.json backups.
//
// Must match the GitHub release tag v<FIRMWARE_VERSION> exactly: the CI
// (.github/workflows/firmware.yml) checks this on every tag build and
// publishes no release on a mismatch - otherwise the release assets would
// carry a different version in their names than the device reports under
// /api/system after the upload.
//
// 0.4.0: Updating directly from GitHub on the device has been removed. Updates
// now only run through the web interface's file upload (/api/firmware,
// /api/filesystem) or via USB (flash.sh). The config format is unchanged
// (CONFIG_SCHEMA_VERSION stays the same).
//
// 0.4.1: The Network/static-IP card moved from the MQTT tab to the System tab
// in the web UI. Remaining German UI text has been translated to English. No
// functional or config changes (CONFIG_SCHEMA_VERSION stays the same).
//
// 0.4.2: The BH1750 light sensor is now read over I2C instead of only being
// simulated. No config changes (CONFIG_SCHEMA_VERSION stays the same).
//
// 0.4.3: The LD2450 can now be given up to three hardware exclusion regions,
// uploaded to the sensor itself over UART at boot. CONFIG_SCHEMA_VERSION
// bumped to 9 for the new region_filter block (old backups still load: it
// defaults to off, all slots unused).
#define FIRMWARE_VERSION "0.4.3"
