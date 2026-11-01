#!/usr/bin/env python3
"""Verify an unsigned SFI IPA on Linux/macOS without Xcode tools.

Checks:
  * zip layout: Payload/*.app
  * CFBundleIdentifier (default io.nekohasekai.sfa.application)
  * main executable + embedded appex are arm64 Mach-O
  * IPA size is plausible (> 40 MiB)
  * MITM overlay strings are present in the app binaries
"""

import argparse
import os
import plistlib
import struct
import sys
import tempfile
import zipfile

EXPECTED_BUNDLE_ID = "io.nekohasekai.sfa.application"
MIN_IPA_BYTES = 40 * 1024 * 1024
MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_MAGIC_32 = 0xFEEDFACE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C
MITM_MARKERS = [b"sfi-adblock MITM CA", b"mitm: CA is not installed"]


def macho_archs(path: str) -> list[str]:
    try:
        with open(path, "rb") as handle:
            header = handle.read(8)
    except OSError:
        return []
    if len(header) < 8:
        return []
    big_magic, = struct.unpack(">I", header[:4])
    little_magic, = struct.unpack("<I", header[:4])
    if big_magic in (FAT_MAGIC, FAT_MAGIC_64):
        count, = struct.unpack(">I", header[4:8])
        archs = []
        with open(path, "rb") as handle:
            for index in range(min(count, 32)):
                handle.seek(8 + index * 20)
                entry = handle.read(20)
                if len(entry) < 20:
                    break
                cpu, _sub, _offset, _size, _align = struct.unpack(">IIIII", entry)
                archs.append("arm64" if cpu == CPU_TYPE_ARM64 else hex(cpu))
        return archs
    if little_magic in (MACHO_MAGIC_64, MACHO_MAGIC_32):
        cpu, = struct.unpack("<I", header[4:8])
        return ["arm64" if cpu == CPU_TYPE_ARM64 else hex(cpu)]
    if big_magic in (MACHO_MAGIC_64, MACHO_MAGIC_32):
        cpu, = struct.unpack(">I", header[4:8])
        return ["arm64" if cpu == CPU_TYPE_ARM64 else hex(cpu)]
    return []


def contains_markers(path: str) -> list[str]:
    found = []
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return found
    for marker in MITM_MARKERS:
        if marker in data:
            found.append(marker.decode())
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ipa")
    parser.add_argument("--expected-bundle-id", default=EXPECTED_BUNDLE_ID)
    parser.add_argument("--min-bytes", type=int, default=MIN_IPA_BYTES)
    args = parser.parse_args()

    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        print(("PASS  " if condition else "FAIL  ") + message)
        if not condition:
            failures.append(message)

    size = os.path.getsize(args.ipa)
    check(size >= args.min_bytes, f"IPA size {size / 1024 / 1024:.1f} MiB >= {args.min_bytes / 1024 / 1024:.0f} MiB")

    work = tempfile.mkdtemp(prefix="verify-ipa-")
    with zipfile.ZipFile(args.ipa) as archive:
        names = archive.namelist()
        archive.extractall(work)

    payload_apps = [name for name in names if name.startswith("Payload/") and name.endswith(".app/")]
    check(bool(payload_apps), f"Payload/*.app present ({payload_apps[0] if payload_apps else 'missing'})")
    if not payload_apps:
        return 1

    app_dir = os.path.join(work, payload_apps[0].rstrip("/"))
    with open(os.path.join(app_dir, "Info.plist"), "rb") as handle:
        info = plistlib.load(handle)
    bundle_id = info.get("CFBundleIdentifier", "")
    executable = info.get("CFBundleExecutable", "")
    print(f"      bundle id: {bundle_id}")
    print(f"      executable: {executable}")
    check(bundle_id == args.expected_bundle_id, f"CFBundleIdentifier == {args.expected_bundle_id}")

    exec_path = os.path.join(app_dir, executable)
    archs = macho_archs(exec_path)
    check("arm64" in archs, f"main executable architecture {archs}")

    appex_dirs = [
        name for name in names
        if name.startswith(payload_apps[0]) and "/PlugIns/" in name and name.endswith(".appex/")
    ]
    check(bool(appex_dirs), f"embedded appex present ({len(appex_dirs)} found)")

    binaries: list[tuple[str, list[str]]] = [(executable, archs)]
    for appex in appex_dirs:
        appex_path = os.path.join(work, appex.rstrip("/"))
        appex_info = os.path.join(appex_path, "Info.plist")
        if not os.path.exists(appex_info):
            continue
        with open(appex_info, "rb") as handle:
            appex_plist = plistlib.load(handle)
        appex_exec = os.path.join(appex_path, appex_plist.get("CFBundleExecutable", ""))
        if os.path.exists(appex_exec):
            appex_archs = macho_archs(appex_exec)
            check("arm64" in appex_archs, f"{os.path.basename(appex.rstrip('/'))} architecture {appex_archs}")
            binaries.append((os.path.basename(appex.rstrip("/")), appex_archs))

    # Any other Mach-O files bundled in the app (frameworks, dylibs).
    for root, _dirs, files in os.walk(app_dir):
        for file_name in files:
            path = os.path.join(root, file_name)
            if path == exec_path:
                continue
            other_archs = macho_archs(path)
            if other_archs:
                binaries.append((os.path.relpath(path, app_dir), other_archs))

    print(f"      Mach-O files: {len(binaries)}")
    for name, item_archs in binaries:
        print(f"        - {name}: {item_archs}")

    marker_hits = []
    for name, _item_archs in binaries:
        if name == executable:
            path = exec_path
        else:
            path = os.path.join(app_dir, name)
        hits = contains_markers(path)
        if hits:
            marker_hits.append((name, hits))
    check(bool(marker_hits), f"MITM overlay strings found in {len(marker_hits)} binary/binaries")
    for name, hits in marker_hits:
        print(f"        - {name}: {', '.join(hits)}")

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall IPA checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
