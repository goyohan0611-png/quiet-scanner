# -*- coding: utf-8 -*-
"""Rebuild oui.dat.gz from the IEEE registry.

Why this exists:
    The first table shipped here was an old copy of Wireshark's manuf file.
    Every prefix assigned after 2020 was missing from it, so common gear on
    site - Hikvision CC-13-F3, Cisco 84-5A-3E - came up as "Unknown".
    8,611 of the 39,505 MA-L blocks (22%) were absent.

Usage:
    python tools/build_oui.py            # refresh src/oui.dat.gz and the default book

File format:
    prefix (lower-case hex, no separators)\tvendor name
    Prefixes come in three widths: 6 (MA-L), 7 (MA-M) and 9 (MA-S) digits.
    The Rust book resolver tries the longest matching prefix first.
"""
import csv, gzip, io, os, re, sys, urllib.request
import hashlib, json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "src", "oui.dat.gz")
BOOK = os.path.join(ROOT, "src", "device-book.json")
PROVENANCE = os.path.join(ROOT, "docs", "vendor-data.json")

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
        return fh.read().decode("utf-8-sig")


def parse_registry(text, width):
    rows = csv.DictReader(io.StringIO(text))
    required = {"Assignment", "Organization Name", "Registry"}
    if not required.issubset(rows.fieldnames or []):
        raise ValueError("Unexpected IEEE CSV columns")
    entries = {}
    for row in rows:
        key = (row.get("Assignment") or "").strip().lower()
        name = (row.get("Organization Name") or "").strip()
        if not re.fullmatch(r"[0-9a-f]{%d}" % width, key) or not name:
            raise ValueError("Invalid IEEE registry row")
        if name.lower() not in ("private", "ieee registration authority"):
            entries[key] = name
    if not entries:
        raise ValueError("Empty IEEE registry")
    return entries


def expand_book(book, registry):
    # Only expand exact organization matches already represented in this book.
    # A MAC registrant cannot establish the product type: new rules leave it blank.
    owners = defaultdict(set)
    known = set()
    for entry in book["entries"]:
        entry["prefixes"] = [p for p in entry["prefixes"] if re.fullmatch(r"[0-9a-f]{6,12}", p)]
        for prefix in entry["prefixes"]:
            known.add(prefix)
            if prefix in registry:
                owners[registry[prefix].casefold()].add(entry["vendor"])
    additions = defaultdict(list)
    for prefix, organization in registry.items():
        candidates = owners[organization.casefold()]
        if prefix not in known and len(candidates) == 1:
            additions[next(iter(candidates))].append(prefix)
    for vendor in sorted(additions):
        book["entries"].append({
            "vendor": vendor, "kind": "",
            "note": "IEEE 등록 제조사 기준. 장비 종류는 확인하지 않았습니다.",
            "prefixes": sorted(additions[vendor]),
        })
    return sum(map(len, additions.values()))


def main():
    table = {}
    # Preserve special/legacy assignments; current IEEE registrations win.
    if os.path.isfile(OUT):
        with gzip.open(OUT, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                key, _, value = line.rstrip("\n").partition("\t")
                if key and value:
                    table[key.strip().lower()] = value.strip()
    before = len(table)

    registry = {}
    sources = []
    for url, width in SOURCES:
        text = fetch(url)
        entries = parse_registry(text, width)
        registry.update(entries)
        sources.append({"url": url, "entries": len(entries),
                        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
        print(f"{url.rsplit('/', 1)[-1]}: {len(entries):,}", flush=True)

    book = json.loads(Path(BOOK).read_text(encoding="utf-8"))
    book_added = expand_book(book, registry)
    added = len(set(registry) - set(table))
    updated = sum(key in table and table[key] != short(name) for key, name in registry.items())
    table.update({key: short(name) for key, name in registry.items()})

    payload = "".join(f"{key}\t{table[key]}\n" for key in sorted(table)).encode("utf-8")
    # No files change until all three downloads and the book have been validated.
    Path(OUT).write_bytes(gzip.compress(payload, mtime=0))
    Path(BOOK).write_text(json.dumps(book, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    provenance = {"retrieved_at": datetime.now(timezone.utc).isoformat(),
                  "sources": sources, "vendor_prefixes": len(table),
                  "device_book_prefixes": sum(len(e["prefixes"]) for e in book["entries"]),
                  "added_vendor_prefixes": added, "updated_vendor_names": updated,
                  "added_book_prefixes": book_added,
                  "oui_sha256": hashlib.sha256(Path(OUT).read_bytes()).hexdigest()}
    Path(PROVENANCE).write_text(json.dumps(provenance, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{before:,} -> {len(table):,} ({added:,} new, {updated:,} refreshed); book +{book_added:,}")


if __name__ == "__main__":
    sys.exit(main())
