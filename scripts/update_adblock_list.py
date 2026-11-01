#!/usr/bin/env python3
"""Regenerate the embedded ad domain list from AdGuard filter sections.

The output is a committed snapshot; CI never runs this script.
Source: https://github.com/AdguardTeam/AdguardFilters (GPL-3.0)
"""
import ipaddress
import os
import re
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "overlay/sing-box/common/adblock/adblock_domains.txt")
BASE = "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/"
SECTIONS = [
    "BaseFilter/sections/adservers.txt",
    "MobileFilter/sections/adservers.txt",
    "SpywareFilter/sections/tracking_servers.txt",
    "SpywareFilter/sections/mobile.txt",
    "BaseFilter/sections/adservers_firstparty.txt",
    "SpywareFilter/sections/tracking_servers_firstparty.txt",
    "ChineseFilter/sections/adservers.txt",
]
DOMAIN_RE = re.compile(r"^\|\|([a-z0-9]([a-z0-9.-]*[a-z0-9])?)\^?(\$.*)?$")
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9.-]*[a-z0-9])?)\s*$")
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
BAD_NAMES = {"localhost", "localhost.localdomain", "local", "broadcasthost",
             "ip6-localhost", "ip6-loopback", "0.0.0.0"}


def valid(domain: str) -> bool:
    if domain in BAD_NAMES or len(domain) < 6 or len(domain) > 253 or "." not in domain:
        return False
    if any(ch in domain for ch in "/*:_ "):
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    labels = domain.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(label) for label in labels):
        return False
    return not labels[-1].isdigit()


def main() -> None:
    block, allow = set(), set()
    for section in SECTIONS:
        url = BASE + section
        print("fetch", url)
        text = urllib.request.urlopen(url, timeout=60).read().decode("utf-8", "ignore")
        for line in text.splitlines():
            line = line.strip().lower()
            if not line or line.startswith("!") or line.startswith("#"):
                continue
            if line.startswith("@@"):
                match = DOMAIN_RE.match(line[2:])
                if match and valid(match.group(1)):
                    allow.add(match.group(1))
                continue
            match = DOMAIN_RE.match(line)
            if match and valid(match.group(1)):
                block.add(match.group(1))
                continue
            match = HOSTS_RE.match(line)
            if match and valid(match.group(1)):
                block.add(match.group(1))

    for domain in allow:
        parts = domain.split(".")
        for index in range(len(parts) - 1):
            block.discard(".".join(parts[index:]))

    final = set()
    for domain in block:
        parts = domain.split(".")
        if any(".".join(parts[index:]) in block for index in range(1, len(parts) - 1)):
            continue
        final.add(domain)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as file:
        file.write("# Built-in ad / tracker domain suffixes for sfi-adblock M1.\n")
        file.write("# Generated from AdGuard filters (GPL-3.0): "
                   "https://github.com/AdguardTeam/AdguardFilters\n")
        file.write("# Sources: Base/Mobile/Spyware/Chinese ad-server & tracking sections.\n")
        file.write("# Format: one domain suffix per line; route action `reject` "
                   "matches it and subdomains.\n")
        for domain in sorted(final):
            file.write(domain + "\n")
    print(f"wrote {len(final)} domains to {OUT}")


if __name__ == "__main__":
    main()
