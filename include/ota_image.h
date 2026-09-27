#pragma once

#include <Arduino.h>
#include <flash_hal.h>

// Bildprüfungen und Größengrenzen für OTA-Images, gemeinsam genutzt vom
// Datei-Upload im Web-UI (web_server.cpp, /api/firmware + /api/filesystem) und
// vom Update direkt von GitHub (firmware_update.cpp). Beide Wege schreiben in
// dieselben Flash-Bereiche und müssen deshalb exakt dieselben Grenzen ziehen.

// Flash layout values, kept in one place. FS_PHYS_SIZE / FS_PHYS_BLOCK (the
// LittleFS partition) come from the core (flash_hal.h, via the linker symbols
// of the ldscript); the sketch limit has no such symbol and is copied here:
//
// Length of irom0_0_seg in eagle.flash.4m1m.ld (org = 0x40201010, len = 0xfeff0,
// i.e. the 1 MB flash window mapped for code ends at 0x40300000, well before
// _FS_start = 0x40500000). It is the "Flash ... from 1044464 bytes" limit that
// pio run checks, so no build for this board can produce more. MUST be updated
// together with board_build.ldscript in platformio.ini.
static const uint32_t LD_IROM0_SEG_LEN = 0xFEFF0;
// firmware.bin carries more than pio run counts against LD_IROM0_SEG_LEN: the
// eboot bootloader padded to one 4 KB sector, plus the image header, segment
// headers and checksum padding (well below 256 bytes). Measured for this
// build: 678128 B firmware.bin vs. 673977 B counted by pio run = +4151 B.
static const uint32_t FIRMWARE_BIN_OVERHEAD = FLASH_SECTOR_SIZE + 0x100;
// Hard cap for an uploaded firmware.bin (1048816 B). The free OTA space alone
// (~2.3 MB on this layout) would accept images built for another board or
// ldscript: they only carry the generic 0xE9 magic byte, Update.end() does not
// check their size, and eboot would copy them over the running sketch.
static const uint32_t FIRMWARE_BIN_MAX_BYTES = LD_IROM0_SEG_LEN + FIRMWARE_BIN_OVERHEAD;

// LittleFS superblock (littlefs SPEC.md, "superblock" + "inline struct" tags),
// as mklittlefs writes it at the start of block 0 of a fresh image:
//   0x00 revision count (LE)
//   0x04 tag (BE, XOR 0xffffffff): type 0x0ff SUPERBLOCK, size 8
//   0x08 "littlefs" magic
//   0x10 tag (BE, XOR previous tag): type 0x201 INLINESTRUCT, size 24
//   0x14 disk version (LE), 0x18 block size (LE), 0x1c block count (LE), ...
// Tag types and the disk version come from lfs.h (via LittleFS.h), i.e. from
// the very littlefs build that mounts the image after the reboot.
static const size_t LFS_SUPERBLOCK_MIN_LEN = 0x20;

// Free OTA staging space: between the running sketch and the filesystem, minus
// one sector of headroom, sector-aligned - the same formula the core's
// ESP8266HTTPUpdateServer uses. Update.begin() checks the same bound, but only
// after the upload has started.
uint32_t otaFirmwareSlotBytes();

// Largest firmware accepted: the smaller of the free staging space and the hard
// sketch cap of this flash layout. Checking it before the first flash write
// turns "does not fit" into a clear error instead of an abort mid-flash.
uint32_t otaFirmwareMaxBytes();

// Names the bound that otaFirmwareMaxBytes() returned, for the error message.
const char *otaFirmwareLimitName();

// 0xE9 = ESP8266 image header; 0x1f = gzip-compressed image (eboot
// unpacks it). Same check as the core's Updater::_verifyHeader, which
// only runs for writeStream(), not for the write() calls used here.
bool otaHasFirmwareMagic(const uint8_t *data, size_t len);

// The core cannot validate a filesystem image (Updater::_verifyHeader accepts
// any first byte for U_FS) and, without ATOMIC_FS_UPDATE, writes it directly
// over the live partition. A wrong file (e.g. firmware.bin picked by mistake)
// would therefore destroy the web UI and config with no way back. Validating
// the superblock in the first chunk catches that before the first erase.
//
// Liefert bei Erfolg die Image-Größe laut Superblock (= FS_PHYS_SIZE), sonst
// false und eine Meldung in error (immer nullterminiert, wird abgeschnitten,
// wenn errorLen nicht reicht; 128 B reichen für jede Meldung).
bool otaCheckLittleFsImage(const uint8_t *data, size_t len, uint32_t &imageSize, char *error, size_t errorLen);
