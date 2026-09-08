# -*- coding: utf-8 -*-
"""Rebuild oui.dat.gz from the IEEE registry.

Why this exists:
    The first table shipped here was an old copy of Wireshark's manuf file.
    Every prefix assigned after 2020 was missing from it, so common gear on
    site - Hikvision CC-13-F3, Cisco 84-5A-3E - came up as "Unknown".
    8,611 of the 39,505 MA-L blocks (22%) were absent.

Usage:
    python tools/build_oui.py            # download, build, overwrite oui.dat.gz

File format:
    prefix (lower-case hex, no separators)\tvendor name
    Prefixes come in three widths: 6 (MA-L), 7 (MA-M) and 9 (MA-S) digits.
    IPFixStudio.vendor_of() tries 9, then 7, then 6 - narrowest first.
"""
import csv, gzip, io, os, re, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "oui.dat.gz")

SOURCES = [
    ("https://standards-oui.ieee.org/oui/oui.csv", 6),
    ("https://standards-oui.ieee.org/oui28/mam.csv", 7),
    ("https://standards-oui.ieee.org/oui36/oui36.csv", 9),
]

# Vendors seen constantly on site get a short fixed name. The column is narrow,
# and nobody reads "Hangzhou Hikvision Digital Technology Co.,Ltd.".
BRANDS = [
    (r"hikvision", "Hikvision"),
    (r"\bdahua\b", "Dahua"),
    (r"hanwha|samsung techwin", "Hanwha"),
    (r"\buniview\b|zhejiang uniview", "Uniview"),
    (r"\baxis communication", "Axis"),
    (r"\bvivotek\b", "Vivotek"),
    (r"\bcisco\b", "Cisco"),
    (r"\bhuawei\b", "Huawei"),
    (r"\btp-?link\b", "TP-Link"),
    (r"\bd-?link\b", "D-Link"),
    (r"\bnetgear\b", "Netgear"),
    (r"\bubiquiti\b", "Ubiquiti"),
    (r"\bmikrotik\b|mikrotikls", "MikroTik"),
    (r"\bruijie\b", "Ruijie"),
    (r"\bhewlett[- ]packard\b|^hp inc|hewlett packard enterprise", "HP"),
    (r"\bdell\b", "Dell"),
    (r"\blenovo\b", "Lenovo"),
    (r"\basustek\b|\basus\b", "ASUS"),
    (r"\bapple\b", "Apple"),
    (r"\bintel\b", "Intel"),
    (r"\brealtek\b", "Realtek"),
    (r"\bsynology\b", "Synology"),
    (r"\bqnap\b", "QNAP"),
    (r"\bextron\b", "Extron"),
    (r"\bcrestron\b", "Crestron"),
    (r"\bkramer\b", "Kramer"),
    (r"\bbiamp\b", "Biamp"),
    (r"\bshure\b", "Shure"),
    (r"\bbarco\b", "Barco"),
    (r"\bepson\b|seiko epson", "Epson"),
    (r"\bcanon\b", "Canon"),
    (r"\bricoh\b", "Ricoh"),
    (r"\bbrother\b", "Brother"),
    (r"\bsamsung\b", "Samsung"),
    (r"\blg electronics\b|^lg innotek", "LG"),
    (r"\bxiaomi\b", "Xiaomi"),
    (r"\bsonos\b", "Sonos"),
    (r"\braspberry pi\b", "Raspberry Pi"),
    (r"\bvmware\b", "VMware"),
    (r"\bmicrosoft\b", "Microsoft"),
    (r"\bgoogle\b", "Google"),
    (r"\bamazon\b", "Amazon"),
]

# Corporate suffixes. They add nothing to recognising a name.
SUFFIX = re.compile(
    r"[,\s]*(?:"
    r"co\.?|corp\.?|corporation|company|inc\.?|incorporated|ltd\.?|limited|"
    r"llc|l\.l\.c\.?|plc|gmbh|mbh|ag|a\.?g\.?|s\.?a\.?|s\.?a\.?s\.?|sarl|"
    r"s\.?p\.?a\.?|b\.?v\.?|n\.?v\.?|a/s|ab|oy|oyj|as|pty|pte|kg|kk|k\.k\.?|"
    r"llp|lp|jsc|ooo|zao|pjsc"
    r")\.?$", re.I)


def short(name):
    """Shorten a long legal name into something that fits the column."""
    text = re.sub(r"\s+", " ", (name or "").replace('"', " ")).strip()
    low = text.lower()
    for pattern, brand in BRANDS:
        if re.search(pattern, low):
            return brand
    text = text.split(",")[0].strip()          # what follows a comma is usually the legal suffix
    for _ in range(3):                          # they stack up, as in "Co., Ltd."
        stripped = SUFFIX.sub("", text).strip(" .,")
        if stripped == text:
            break
        text = stripped
    text = text.strip(" .,")
    return (text[:28].rstrip() if len(text) > 28 else text) or (name or "").strip()[:28]


def fetch(url):
    # Without a user agent the IEEE server answers 418 and cuts the transfer.
    request = urllib.request.Request(url, headers={"User-Agent": "QuietScanner-oui-build/1.0"})
    with urllib.request.urlopen(request, timeout=120) as fh:
        return fh.read().decode("utf-8", "replace")


def main():
    table = {}
    # Lay down the old table first, to keep the hand-tidied names and the
    # special addresses (multicast and friends). New IEEE entries only fill gaps.
    if os.path.isfile(OUT):
        with gzip.open(OUT, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                key, _, value = line.rstrip("\n").partition("\t")
                if key and value:
                    table[key.strip().lower()] = value.strip()
    before = len(table)

    added = 0
    for url, width in SOURCES:
        rows = csv.DictReader(io.StringIO(fetch(url)))
        for row in rows:
            key = re.sub(r"[^0-9a-f]", "", (row.get("Assignment") or "").lower())
            name = (row.get("Organization Name") or "").strip()
            if len(key) != width or not name:
                continue
            if name.lower() in ("private", "ieee registration authority"):
                continue
            if key in table:
                continue
            table[key] = short(name)
            added += 1
        print(f"{url.rsplit('/', 1)[-1]}: done")

    with gzip.open(OUT, "wt", encoding="utf-8", newline="\n") as fh:
        for key in sorted(table):
            fh.write(f"{key}\t{table[key]}\n")
    print(f"{before:,} -> {len(table):,} ({added:,} new)  {OUT}")


if __name__ == "__main__":
    sys.exit(main())
