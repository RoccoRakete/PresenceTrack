#include "ota_image.h"

#include <LittleFS.h>

uint32_t otaFirmwareSlotBytes() {
    uint32_t free = ESP.getFreeSketchSpace();
    return free > FLASH_SECTOR_SIZE ? (free - FLASH_SECTOR_SIZE) & ~(FLASH_SECTOR_SIZE - 1) : 0;
}

uint32_t otaFirmwareMaxBytes() {
    return std::min(otaFirmwareSlotBytes(), FIRMWARE_BIN_MAX_BYTES);
}

const char *otaFirmwareLimitName() {
    return otaFirmwareSlotBytes() < FIRMWARE_BIN_MAX_BYTES ? "free OTA space" : "sketch limit of eagle.flash.4m1m.ld";
}

bool otaHasFirmwareMagic(const uint8_t *data, size_t len) {
    return len > 0 && (data[0] == 0xE9 || data[0] == 0x1F);
}

static uint32_t readLe32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t readBe32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

bool otaCheckLittleFsImage(const uint8_t *data, size_t len, uint32_t &imageSize, char *error, size_t errorLen) {
    // The first chunk is min(file size, 1460) bytes, so this only trips for
    // files that are too short to be an image at all.
    if (len < LFS_SUPERBLOCK_MIN_LEN) {
        snprintf(error, errorLen, "file too short for a LittleFS image");
        return false;
    }
    uint32_t tag1 = readBe32(data + 0x04) ^ 0xffffffff;
    uint32_t tag2 = readBe32(data + 0x10) ^ tag1;
    if (((tag1 >> 20) & 0x7ff) != LFS_TYPE_SUPERBLOCK || (tag1 & 0x3ff) != 8 ||
        memcmp(data + 0x08, "littlefs", 8) != 0 ||
        ((tag2 >> 20) & 0x7ff) != LFS_TYPE_INLINESTRUCT || (tag2 & 0x3ff) < 12) {
        snprintf(error, errorLen, "not a LittleFS image (superblock missing) - use littlefs.bin from 'pio run -t buildfs'");
        return false;
    }
    uint32_t version = readLe32(data + 0x14);
    uint32_t blockSize = readLe32(data + 0x18);
    uint32_t blockCount = readLe32(data + 0x1c);
    if ((version >> 16) != LFS_DISK_VERSION_MAJOR) {
        snprintf(error, errorLen, "unsupported LittleFS disk version %u.%u", version >> 16, version & 0xffff);
        return false;
    }
    // Block size and count must match this partition exactly: LittleFS refuses
    // to mount an image with a different geometry, and main.cpp then formats
    // the partition - i.e. a mismatched image ends as an empty filesystem.
    if (blockSize != FS_PHYS_BLOCK || (uint64_t)blockSize * blockCount != FS_PHYS_SIZE) {
        snprintf(error, errorLen, "image geometry %u x %u B does not match this partition (%u x %u B) - different flash layout?",
                 blockCount, blockSize, FS_PHYS_SIZE / FS_PHYS_BLOCK, FS_PHYS_BLOCK);
        return false;
    }
    imageSize = blockSize * blockCount;
    return true;
}
