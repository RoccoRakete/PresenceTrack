#!/usr/bin/env python3
"""Prueft ein manifest.json gegen den Vertrag der Geraeteseite
(src/firmware_update.cpp, Puffergroessen und Parser).

Nutzung:
    check_manifest.py manifest.json [--firmware firmware.bin] [--filesystem littlefs.bin]
                                     [--repo OWNER/REPO]

Ohne --firmware/--filesystem wird nur die Struktur des Manifests geprueft
(Feldnamen, Groessen, URL-Form); mit den Pfaden zusaetzlich Groesse und
sha256 gegen die echten Dateien. Bricht mit Exit-Code 1 und einer Liste
lesbarer Fehler ab, wenn irgendetwas dem Vertrag widerspricht.
"""
import argparse
import hashlib
import json
import re
import sys

# Puffer in RunContext (firmware_update.cpp): Chunk-Puffer fuer den
# Manifest-Body ist CHUNK_LEN = 1460 Bytes; Content-Length muss reinpassen.
MANIFEST_MAX_BYTES = 1460

# ota_image.h: FIRMWARE_BIN_MAX_BYTES = LD_IROM0_SEG_LEN + FIRMWARE_BIN_OVERHEAD
#            = 0xFEFF0 + (FLASH_SECTOR_SIZE + 0x100) = 1044464 + 4352
FIRMWARE_MAX_BYTES = 1048816

# flash_hal.h (Core) fuer dieses Board: FS_PHYS_SIZE = 0xFA000
FILESYSTEM_EXACT_BYTES = 1024000

# ASSET_URL_MAX_LEN = 128 in firmware_update.cpp: Puffer inkl. Nullbyte
ASSET_URL_MAX_LEN = 128

VERSION_RE = re.compile(r"^\d{1,5}(\.\d{1,5}){0,2}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def asset_url_re(repo: str) -> re.Pattern:
    # Direkt die github.com/releases/download-URL, kein Redirector: das
    # Geraet erlaubt 3 Redirects und braucht 2 davon schon fuer den
    # Manifest-Abruf selbst (latest/download -> v-Tag -> Asset-CDN).
    return re.compile(r"^https://github\.com/" + re.escape(repo) + r"/releases/download/[^/\s]+/[^/\s]+$")


def check_asset(errors: list, name: str, obj, repo: str, expected_size: int, size_label: str, file_path: str | None):
    if not isinstance(obj, dict):
        errors.append(f"{name}: fehlt oder ist kein Objekt")
        return
    for field in ("file", "size", "url", "sha256"):
        if field not in obj:
            errors.append(f"{name}.{field}: Pflichtfeld fehlt")
    if "size" in obj:
        size = obj["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            errors.append(f"{name}.size: muss eine positive Ganzzahl sein, ist {size!r}")
        elif expected_size == "max":
            if size > FIRMWARE_MAX_BYTES:
                errors.append(f"{name}.size: {size} B ueberschreitet das Limit von {FIRMWARE_MAX_BYTES} B")
        elif size != expected_size:
            errors.append(f"{name}.size: muss exakt {expected_size} B sein ({size_label}), ist {size} B")
    if "url" in obj:
        url = obj["url"]
        if not isinstance(url, str):
            errors.append(f"{name}.url: muss ein String sein")
        else:
            if len(url) > ASSET_URL_MAX_LEN - 1:
                errors.append(f"{name}.url: {len(url)} Zeichen, Puffer im Geraet ist {ASSET_URL_MAX_LEN - 1} Zeichen (+ Nullbyte)")
            if not url.startswith("https://"):
                errors.append(f"{name}.url: muss mit https:// beginnen, ist {url!r}")
            elif not asset_url_re(repo).match(url):
                errors.append(
                    f"{name}.url: keine direkte Release-Asset-URL (erwartet https://github.com/{repo}/releases/download/<tag>/<datei>, "
                    f"kein Redirector dazwischen), ist {url!r}"
                )
    if "sha256" in obj:
        sha = obj["sha256"]
        if not isinstance(sha, str) or not SHA256_RE.match(sha):
            errors.append(f"{name}.sha256: muss aus genau 64 kleinen Hex-Ziffern bestehen, ist {sha!r}")
        elif file_path:
            actual = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
            if actual != sha:
                errors.append(f"{name}.sha256: Manifest nennt {sha}, tatsaechliche Datei {file_path} hat {actual}")
    if file_path and "size" in obj and isinstance(obj["size"], int):
        import os
        actual_size = os.path.getsize(file_path)
        if actual_size != obj["size"]:
            errors.append(f"{name}.size: Manifest nennt {obj['size']} B, tatsaechliche Datei {file_path} hat {actual_size} B")


def check_manifest(raw: bytes, repo: str, firmware_path: str | None, filesystem_path: str | None) -> list:
    errors = []

    if len(raw) < 1 or len(raw) > MANIFEST_MAX_BYTES:
        errors.append(f"manifest.json: {len(raw)} Bytes, der Geraetepuffer erlaubt 1..{MANIFEST_MAX_BYTES} Bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        errors.append("manifest.json: enthaelt ein UTF-8-BOM, das Geraet erwartet reines JSON ohne BOM")

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        errors.append(f"manifest.json: kein gueltiges JSON ({e})")
        return errors

    if not isinstance(data, dict):
        errors.append("manifest.json: oberste Ebene muss ein JSON-Objekt sein")
        return errors

    version = data.get("version")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        errors.append(
            f"version: muss rein numerisch mit 1-3 durch Punkte getrennten Segmenten sein, ohne 'v'-Praefix "
            f"oder Suffix wie '-rc1' (das Geraet lehnt beides ab), ist {version!r}"
        )

    check_asset(errors, "firmware", data.get("firmware"), repo, "max", "", firmware_path)
    check_asset(errors, "filesystem", data.get("filesystem"), repo, FILESYSTEM_EXACT_BYTES,
                "das Geraet weist jede andere Groesse als fremdes Flash-Layout zurueck", filesystem_path)

    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest", help="Pfad zu manifest.json")
    ap.add_argument("--firmware", help="Pfad zur echten firmware.bin, fuer Groessen-/sha256-Abgleich")
    ap.add_argument("--filesystem", help="Pfad zur echten littlefs.bin, fuer Groessen-/sha256-Abgleich")
    ap.add_argument("--repo", default="RoccoRakete/PresenceTrack", help="owner/repo fuer die URL-Pruefung")
    args = ap.parse_args()

    with open(args.manifest, "rb") as f:
        raw = f.read()

    errors = check_manifest(raw, args.repo, args.firmware, args.filesystem)

    if errors:
        print(f"manifest.json ({args.manifest}) verletzt den Geraete-Vertrag:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    print(f"manifest.json ist gueltig ({len(raw)} Bytes).")


if __name__ == "__main__":
    main()
