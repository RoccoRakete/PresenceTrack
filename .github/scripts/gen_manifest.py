#!/usr/bin/env python3
"""Erzeugt manifest.json fuer ein PresenceTrack-Release nach dem Schema, das
das Geraet erwartet (src/firmware_update.cpp). Laeuft lokal wie in der CI:

    .github/scripts/gen_manifest.py \\
        --version 0.3.0 --tag v0.3.0 --board d1_mini \\
        --commit $(git rev-parse HEAD) \\
        --firmware .pio/build/d1_mini/firmware.bin --firmware-name presencetrack-0.3.0-firmware.bin \\
        --filesystem .pio/build/d1_mini/littlefs.bin --filesystem-name presencetrack-0.3.0-littlefs.bin \\
        --out manifest.json

Bricht ab (Exit-Code 1), wenn das Ergebnis den Geraete-Vertrag verletzt
(siehe check_manifest.py) oder den 1460-Byte-Puffer des Geraets ueberschreitet.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_manifest import check_manifest, MANIFEST_MAX_BYTES  # noqa: E402


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def asset_entry(path: str, name: str, repo: str, tag: str) -> dict:
    return {
        "file": name,
        "size": os.path.getsize(path),
        "sha256": sha256_of(path),
        "url": f"https://github.com/{repo}/releases/download/{tag}/{name}",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", required=True, help="FIRMWARE_VERSION, z.B. 0.3.0 (ohne 'v')")
    ap.add_argument("--tag", required=True, help="Git-Tag des Release, z.B. v0.3.0")
    ap.add_argument("--board", required=True, help="PlatformIO-Board-ID, z.B. d1_mini")
    ap.add_argument("--commit", required=True, help="voller Commit-Hash (40 Hex-Zeichen)")
    ap.add_argument("--repo", default="RoccoRakete/PresenceTrack", help="owner/repo fuer die Asset-URLs")
    ap.add_argument("--firmware", required=True, help="Pfad zur gebauten firmware.bin")
    ap.add_argument("--firmware-name", required=True, help="Asset-Name der firmware.bin im Release")
    ap.add_argument("--filesystem", required=True, help="Pfad zur gebauten littlefs.bin")
    ap.add_argument("--filesystem-name", required=True, help="Asset-Name der littlefs.bin im Release")
    ap.add_argument("--out", default="manifest.json", help="Zieldatei")
    args = ap.parse_args()

    manifest = {
        "version": args.version,
        "tag": args.tag,
        "board": args.board,
        "commit": args.commit,
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "firmware": asset_entry(args.firmware, args.firmware_name, args.repo, args.tag),
        "filesystem": asset_entry(args.filesystem, args.filesystem_name, args.repo, args.tag),
    }

    # Kompakt (keine Leerzeichen): jedes Byte zaehlt gegen den 1460-B-Puffer.
    raw = json.dumps(manifest, separators=(",", ":")).encode("utf-8")

    if len(raw) > MANIFEST_MAX_BYTES:
        print(
            f"manifest.json waere {len(raw)} Bytes gross, der Geraetepuffer erlaubt nur {MANIFEST_MAX_BYTES} Bytes. "
            "Asset-Namen kuerzen oder Feld weglassen.",
            file=sys.stderr,
        )
        sys.exit(1)

    errors = check_manifest(raw, args.repo, args.firmware, args.filesystem)
    if errors:
        print("Generiertes manifest.json verletzt den Geraete-Vertrag:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    Path(args.out).write_bytes(raw)
    print(f"{args.out} geschrieben ({len(raw)} Bytes).")


if __name__ == "__main__":
    main()
