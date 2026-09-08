#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Quiet Scanner — field IP conflict cleanup tool
# Copyright (C) 2026 고요한
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version. This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details. You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.
"""
Quiet Scanner - field IP conflict cleanup app

For when a pile of devices that all shipped with the same factory IP sit on one
switch, and you want to sort them out from a browser window instead of unplugging and replugging each one.

  1) Sweep the subnet and find every conflicting IP     (ARP replies caught directly, not via the OS)
  2) Dig out what device is behind each IP              (MAC isolation -> port/web/ONVIF lookup)
  3) Change IPs one device at a time, isolated, and track the progress
  4) Leave the result behind as a CSV / HTML report

What you need (Windows):
    1) Install Npcap   https://npcap.com   (tick "WinPcap API-compatible mode")
    2) pip install scapy
    3) Run as administrator

Run:
    python IPFixStudio.py            # the window comes up
    python IPFixStudio.py --demo     # walk through the UI with no devices present

    To build an exe, run build_exe.bat
"""

import argparse
import concurrent.futures as futures
import csv
import html
import ipaddress
import gzip
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime

_T_START = time.time()

APP_NAME = "Quiet Scanner"
APP_VER = "3.0"

# ---------------------------------------------------------------------------
# scapy (demo mode runs fine without it)
# ---------------------------------------------------------------------------
# Just importing scapy opens the Npcap DLL and walks every interface, which
# costs several seconds on Windows. Put the window up first, load it in the background.
SCAPY_OK = None      # None = not tried yet / True / False
SCAPY_ERR = ""
ARP = Ether = srp = conf = None
IP = TCP = sr1 = None


def ensure_scapy():
    """Actually load scapy. Returns immediately if it is already loaded."""
    global SCAPY_OK, SCAPY_ERR, ARP, Ether, srp, conf, IP, TCP, sr1
    if SCAPY_OK is not None:
        return SCAPY_OK
    try:
        from scapy.all import ARP as _ARP, Ether as _Ether
        from scapy.all import conf as _conf, srp as _srp
        from scapy.all import IP as _IP, TCP as _TCP, sr1 as _sr1
        ARP, Ether, srp, conf = _ARP, _Ether, _srp, _conf
        IP, TCP, sr1 = _IP, _TCP, _sr1
        SCAPY_OK = True
    except Exception as e:
        SCAPY_ERR = str(e)
        SCAPY_OK = False
    return SCAPY_OK


# ---------------------------------------------------------------------------
# Minimal table used when the registry file cannot be read
# ---------------------------------------------------------------------------
OUI_FALLBACK = {
    "4447cc": "Hikvision", "bcad28": "Hikvision", "c056e3": "Hikvision",
    "4cbd8f": "Hikvision", "2857be": "Hikvision", "5803fb": "Hikvision",
    "a41437": "Hikvision", "e0ca3c": "Hikvision", "54c415": "Hikvision",
    "9002a9": "Dahua", "3cef8c": "Dahua", "4c11bf": "Dahua",
    "e0508b": "Dahua", "08eded": "Dahua", "14a78b": "Dahua",
    "24526a": "Dahua", "bc325f": "Dahua",
    "000918": "Hanwha", "e43022": "Hanwha", "00166c": "Hanwha",
    "34e6d7": "Hanwha",
    "0003c5": "IDIS",
    "00408c": "Axis", "accc8e": "Axis", "b8a44f": "Axis",
    "48ea63": "Uniview", "6cf17e": "Uniview",
    "00075f": "Bosch", "001c44": "Bosch",
    "008045": "Panasonic", "080023": "Panasonic",
    "30f9ed": "Sony", "544249": "Sony",
    "0005a6": "Extron", "00107f": "Crestron", "00609f": "AMX",
    "001d56": "Kramer", "7c2e0d": "Blackmagic", "0004a5": "Barco",
    "000b78": "ATEN", "001644": "Lite-On",
    "24a43c": "Ubiquiti", "788a20": "Ubiquiti", "74acb9": "Ubiquiti",
    "fcecda": "Ubiquiti", "68d79a": "Ubiquiti",
    "50c7bf": "TP-Link", "ec086b": "TP-Link", "a42bb0": "TP-Link",
    "60a4b7": "TP-Link",
    "001bd4": "Cisco", "002304": "Cisco", "6c416a": "Cisco",
    "204e7f": "Netgear", "a040a0": "Netgear",
    "24dec6": "Aruba", "6cf37f": "Aruba",
    "00e04c": "Realtek(범용)", "001a4b": "HP",
    "005056": "VMware", "000c29": "VMware", "00155d": "Hyper-V",
}


# ---------------------------------------------------------------------------
# Vendor lookup — two layers
#
#   Layer 1. The official IEEE registry (oui.dat.gz, some 58,000 entries)
#            From the MAC prefix it tells you only "which company built it".
#
#   Layer 2. The device book (device-book.json)
#            A table the operator fills in by hand. Not just the vendor —
#            device type, default credentials, even the RTSP path. Overrides layer 1.
#
#            Register a device you have never seen before once on site and from
#            then on its name shows up the moment you scan. The file can be passed
#            around, so a team — and eventually the wider user base — fills it in together.
# ---------------------------------------------------------------------------

OUI_FILE = "oui.dat.gz"
BOOK_FILE = "device-book.json"
# Entries registered on site go in a separate file.
#
# Put it all in one book and the shipped book gets mixed in the same file with
# company business like "our site's recorder". The moment that file goes up to a
# public repo the procurement details go with it. Not something a person should
# have to remember to avoid every time — split the files instead.
BOOK_MINE_FILE = "device-book.local.json"

_OUI_CACHE = None


# The Korean file names used up through v3.0. Renamed to English for the public release.
OLD_NAMES = {
    "장비사전.내것.json": "device-book.local.json",
    "스캔기록.json": "scan-history.json",
    "포트기록.json": "port-history.json",
    "격리기록.json": "isolation.json",
}


def migrate_old_names():
    """Move records piled up under the old names over to the new names, once.

    Rename and stop there and everything already accumulated goes unread. Losing
    the scan history and the port speed history is a waste, but the real danger is
    the isolation record — that is the only clue for undoing the static ARP entries
    pinned into the PC. If it cannot be read, that IP stays bound to the wrong MAC,
    forgotten, until a reboot.

    If the new name already exists, leave it alone. A failed move must not stop the
    program — a record must never be the reason a scan cannot run.
    """
    moved = []
    for old, new in OLD_NAMES.items():
        try:
            here = os.path.join(app_dir(), old)
            there = os.path.join(app_dir(), new)
            if os.path.isfile(here) and not os.path.exists(there):
                os.replace(here, there)
                moved.append("%s -> %s" % (old, new))
        except OSError:
            continue
    return moved


def app_dir():
    """Where settings and books live. Next to the exe when frozen, next to the source otherwise."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def bundle_dir():
    """Where PyInstaller unpacks the files bundled with a frozen build."""
    return getattr(sys, "_MEIPASS", "") or app_dir()


def _oui_table():
    """Read the IEEE registry once, the first time it is needed.

    Rebuild it with tools/build_oui.py. The old table was missing every
    assignment made after 2020, so common devices came up as "unknown".
    """
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE
    table = {}
    # Look next to the exe first. The IEEE registry keeps growing, so dropping a
    # newer file beside the exe updates it without a rebuild.
    for base in (app_dir(), bundle_dir()):
        path = os.path.join(base, OUI_FILE)
        if not os.path.isfile(path):
            continue
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    key, _, name = line.rstrip("\n").partition("\t")
                    if key and name:
                        table[key] = name
            break
        except (OSError, EOFError, UnicodeDecodeError):
            table = {}
    _OUI_CACHE = table
    return table


def hex_mac(mac):
    return re.sub(r"[^0-9a-f]", "", (mac or "").lower())


def vendor_of(mac):
    """Find the vendor from the MAC prefix. Narrow assignments (36/28-bit) come first."""
    digits = hex_mac(mac)
    # Hand back nothing rather than a word — the screen and the report each say
    # "unknown" in the reader's own language.
    if len(digits) < 6:
        return ""
    table = _oui_table()
    for width in (9, 7, 6):
        name = table.get(digits[:width])
        if name:
            return name
    # Minimal table for when the registry could not be read
    return OUI_FALLBACK.get(digits[:6], "")


class DeviceBook:
    """The device book. Works out vendor and device type from the MAC prefix.

    One entry can carry several prefixes (prefixes). An entry a person adds by
    hand can name just one prefix (prefix). Write all 12 MAC digits and it points
    at that one device — and that wins over a vendor prefix.

    It holds vendor and device type, nothing else. No credentials, no stream URLs.
    Those vary by firmware, and a wrong value is worse than none; there is also no
    reason to write credentials into a file meant to be passed around.
    """

    FIELDS = ("vendor", "kind", "note")

    def __init__(self):
        self.entries = []       # [{vendor, kind, note, prefixes:[...]}]
        self.index = {}         # prefix -> entry
        self.loaded_from = ""

    @property
    def path(self):
        return os.path.join(app_dir(), BOOK_FILE)

    @property
    def mine_path(self):
        """Where entries registered on site pile up. This one does not go to a public repo."""
        return os.path.join(app_dir(), BOOK_MINE_FILE)

    # -- read and write ---------------------------------------------------

    def _reindex(self):
        self.index = {}
        for item in self.entries:
            for prefix in item.get("prefixes", []):
                if prefix:
                    self.index[prefix] = item

    @staticmethod
    def _clean(item):
        out = {key: str(item.get(key) or "").strip() for key in DeviceBook.FIELDS}
        prefixes = item.get("prefixes")
        if prefixes is None:
            prefixes = [item.get("prefix", "")]
        seen, keep = set(), []
        for value in prefixes:
            digits = hex_mac(value)
            if len(digits) >= 6 and digits not in seen:
                seen.add(digits)
                keep.append(digits)
        out["prefixes"] = keep
        return out

    def load(self):
        """Look in this order: my book -> the default book beside it -> the bundled default book.

        My book comes first, so overwriting the shipped book does not wipe out what was registered on site.
        """
        for path in (self.mine_path, self.path,
                     os.path.join(bundle_dir(), BOOK_FILE)):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                items = [self._clean(x) for x in data.get("entries", [])]
                self.entries = [x for x in items if x["prefixes"]]
                self._reindex()
                self.loaded_from = path
                return True
            except (OSError, ValueError):
                continue
        self.entries = []
        self._reindex()
        return False

    def _payload(self):
        return {
            "note": ("Quiet Scanner device book. Vendor and device type are worked out "
                     "from the MAC prefix. Write prefixes without separators; a full "
                     "12-digit MAC matches that one device only."),
            "version": 1,
            "entries": self.entries,
        }

    def save(self):
        """Always write to my book. The shipped book (device-book.json) is never touched.

        Overwrite the shipped book and what was registered on site rides along the
        next time that file goes up to the repo. Keep the file the program writes
        apart from the file that gets distributed.
        """
        where = self.mine_path
        tmp = where + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._payload(), fh, ensure_ascii=False, indent=2)
        os.replace(tmp, where)
        self.loaded_from = where

    def export_to(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._payload(), fh, ensure_ascii=False, indent=2)

    def import_from(self, path, replace=False):
        """Merge in a book someone sent. A prefix already present is overwritten by the new one."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        incoming = [self._clean(x) for x in data.get("entries", [])]
        incoming = [x for x in incoming if x["prefixes"]]
        if replace:
            self.entries = incoming
            self._reindex()
            return len(incoming), 0

        added = updated = 0
        for item in incoming:
            hit = None
            for prefix in item["prefixes"]:
                hit = self.index.get(prefix)
                if hit is not None:
                    break
            if hit is None:
                self.entries.append(item)
                added += 1
            else:
                hit.update({k: item[k] for k in self.FIELDS if item[k]})
                merged = list(dict.fromkeys(hit["prefixes"] + item["prefixes"]))
                hit["prefixes"] = merged
                updated += 1
            self._reindex()
        return added, updated

    # -- lookup -----------------------------------------------------------

    def match(self, mac):
        """Try the most specific first. A full-MAC entry wins over a vendor prefix."""
        digits = hex_mac(mac)
        if len(digits) < 6:
            return None
        for width in range(len(digits), 5, -1):
            hit = self.index.get(digits[:width])
            if hit is not None:
                return hit
        return None

    def matched_prefix(self, mac):
        digits = hex_mac(mac)
        for width in range(len(digits), 5, -1):
            if digits[:width] in self.index:
                return digits[:width]
        return ""

    # -- editing ----------------------------------------------------------

    def upsert(self, prefix, vendor="", kind="", note=""):
        """Register or edit a single prefix.

        One thing to watch when editing a prefix that already exists. The default
        book groups prefixes per brand — the Hikvision entry alone holds 37 of them.
        Edit that entry in place and every Hikvision device gets renamed. So when
        an entry bundling several prefixes turns up, split this one prefix out into
        a new entry. The other 36 stay as they were.
        """
        digits = hex_mac(prefix)
        if len(digits) < 6:
            raise ValueError(T("MAC 앞자리는 최소 6자리(제조사 코드)여야 합니다.",
                             "A MAC prefix needs at least 6 hex digits (the vendor code)."))

        hit = self.index.get(digits)
        if hit is not None and len(hit["prefixes"]) == 1:
            hit["vendor"], hit["kind"], hit["note"] = vendor, kind, note
            return False

        if hit is not None:
            hit["prefixes"] = [p for p in hit["prefixes"] if p != digits]

        self.entries.append({"vendor": vendor, "kind": kind, "note": note,
                             "prefixes": [digits]})
        self._reindex()
        return hit is None      # was this prefix absent from the book entirely?

    def lookup(self, prefix):
        """Whether that prefix is already in the book, and if so what it says."""
        digits = hex_mac(prefix)
        hit = self.index.get(digits)
        if hit is None:
            return None
        return {"vendor": hit.get("vendor", ""), "kind": hit.get("kind", ""),
                "note": hit.get("note", ""), "shared": len(hit["prefixes"])}

    def remove(self, prefix):
        digits = hex_mac(prefix)
        hit = self.index.get(digits)
        if hit is None:
            return False
        hit["prefixes"] = [p for p in hit["prefixes"] if p != digits]
        if not hit["prefixes"]:
            self.entries.remove(hit)
        self._reindex()
        return True

    def rows(self):
        """A flat list for the screen: (prefix, vendor, kind, note)."""
        out = []
        for item in self.entries:
            for prefix in item["prefixes"]:
                out.append((prefix, item["vendor"], item["kind"], item["note"]))
        out.sort(key=lambda r: (r[1].lower(), r[0]))
        return out


BOOK = DeviceBook()


def describe(mac):
    """What a single MAC tells you. The book overrides the IEEE registry."""
    info = {"vendor": vendor_of(mac), "kind": "", "note": "",
            "from_book": False, "exact": False}
    hit = BOOK.match(mac)
    if hit:
        info["from_book"] = True
        # Registered by full MAC (12 digits) means a person pinned that exact device.
        info["exact"] = len(BOOK.matched_prefix(mac)) >= 12
        if hit.get("vendor"):
            info["vendor"] = hit["vendor"]
        info["kind"] = hit.get("kind", "")
        info["note"] = hit.get("note", "")
    return info


SCAN_PORTS = [80, 443, 8080, 8000, 8443, 554, 8554, 37777, 34567,
              22, 23, 161, 4352, 41794, 1319, 9100, 5000, 3389]

PORT_LABEL = {
    80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8000: "HTTP/HIK", 8443: "HTTPS",
    554: "RTSP", 8554: "RTSP", 37777: "Dahua", 34567: "XM DVR",
    22: "SSH", 23: "Telnet", 161: "SNMP", 4352: "PJLink",
    41794: "Crestron", 1319: "AMX", 9100: "프린터", 5000: "UPnP", 3389: "RDP",
}

SSLCTX = ssl.create_default_context()
SSLCTX.check_hostname = False
SSLCTX.verify_mode = ssl.CERT_NONE

CREATE_NO_WINDOW = 0x08000000


def now():
    return datetime.now().strftime("%H:%M:%S")


def norm_mac(mac):
    return mac.lower().replace("-", ":")


def dash_mac(mac):
    """Into AA-BB-CC-DD-EE-FF form. A bare 12-digit string with no separators gets split too."""
    digits = hex_mac(mac)
    if len(digits) == 12 and ":" not in mac and "-" not in mac:
        return "-".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()
    return mac.upper().replace(":", "-")


# ---------------------------------------------------------------------------
# Wording
#
# The UI strings live in electron/renderer/i18n.js; what is here is the wording
# the engine builds itself and throws into the log pane. When the language is
# switched on screen, set_lang tells this side about it too.
#
# The comments were kept in Korean for a long time — they are written for us to
# read later, and translating them buries "why it was built this way" too easily.
# ---------------------------------------------------------------------------

LANG = "ko"


def set_lang(code):
    global LANG
    LANG = "en" if str(code or "").lower().startswith("en") else "ko"
    return LANG


def T(ko, en):
    """One human-readable string. Korean goes first — that is the original."""
    return en if LANG == "en" else ko


# Device kind labels. Translates what the book file and guess_kind emit in Korean.
KIND_EN = {
    "AV 장비": "AV equipment",
    "IP 카메라": "IP camera",
    "IP 카메라 (ONVIF)": "IP camera (ONVIF)",
    "IP 카메라 / NVR": "IP camera / NVR",
    "LED 컨트롤러": "LED controller",
    "NAS": "NAS",
    "NAS / 공유기": "NAS / router",
    "NAS / 저장장치": "NAS / storage",
    "NVR": "NVR",
    "NVR / 녹화기": "NVR / recorder",
    "DVR": "DVR",
    "DVR / NVR": "DVR / NVR",
    "VoIP / 네트워크 장비": "VoIP / network gear",
    "VoIP / 화상회의": "VoIP / video conferencing",
    "VoIP 전화": "VoIP phone",
    "AMX 제어기": "AMX controller",
    "Crestron 제어기": "Crestron controller",
    "가상 머신": "Virtual machine",
    "공유기": "Router",
    "공유기 / 라우터": "Router",
    "네트워크 스위치": "Network switch",
    "네트워크 장비": "Network equipment",
    "네트워크 장비 (스위치/AP 추정)": "Network equipment (switch/AP, likely)",
    "디스플레이": "Display",
    "디코더": "Decoder",
    "인코더": "Encoder",
    "라벨 프린터": "Label printer",
    "매트릭스 스위처": "Matrix switcher",
    "무선 AP": "Wireless AP",
    "무선 장비": "Wireless equipment",
    "무정전 전원장치": "UPS",
    "미디어 플레이어": "Media player",
    "방송 장비": "Broadcast equipment",
    "방화벽": "Firewall",
    "사이니지 플레이어": "Signage player",
    "산업 / 전원 장비": "Industrial / power equipment",
    "산업 장비": "Industrial equipment",
    "산업 제어기": "Industrial controller",
    "산업용 네트워크": "Industrial network",
    "산업용 컴퓨터": "Industrial PC",
    "소형 컴퓨터": "Single-board computer",
    "스피커": "Speaker",
    "영상 녹화 장비": "Video recorder",
    "영상 장비": "Video equipment",
    "영상 장비 (카메라 계열)": "Video equipment (camera family)",
    "음향 장비": "Audio equipment",
    "음향 장비 (Dante)": "Audio equipment (Dante)",
    "인터폰": "Intercom",
    "전원 분배장치": "PDU",
    "전원 장비": "Power equipment",
    "제어기": "Controller",
    "출입통제": "Access control",
    "프로젝터": "Projector",
    "프로젝터 (PJLink)": "Projector (PJLink)",
    "프린터": "Printer",
    "프린터 / 복합기": "Printer / MFP",
    "프린터 / 프로젝터": "Printer / projector",
    "웹 관리 장비": "Web-managed device",
    "Windows 웹 서버": "Windows web server",
    "미확인": "Unidentified",
    "리눅스 / 임베디드": "Linux / embedded",
    "윈도우": "Windows",
    "네트워크 장비 ": "Network equipment",
}


def kind_en(text):
    """Device kind into English. A kind someone typed in by hand is left alone."""
    return KIND_EN.get(text or "", text or "")


def kind_show(text):
    """The device kind as it should show in the current language."""
    return kind_en(text) if LANG == "en" else (text or "")


# ---------------------------------------------------------------------------
# State store
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, demo=False):
        self.lock = threading.RLock()
        self.demo = demo
        self.iface = None
        self.ifindex = None
        self.cidr = ""
        self.busy = False
        self.cancel = threading.Event()   # request to stop the running job
        self.progress = {"phase": "대기", "pct": 0, "msg": "", "cur": 0, "total": 0}
        self.devices = {}          # "ip|mac" -> dict
        self.order = []            # keeps display order
        self.isolated = None       # key currently isolated
        self.mymac = ""            # MAC of the first NIC (old name kept)
        self.mymacs = set()        # MACs of every selected NIC — stops you shutting your own port
        self.logs = []
        self.last_scan = ""
        self.scanned = []          # only addresses that went through **all three checks**
        # Did the scan run to the end? Stays False if it blew up or was stopped.
        # A list of free IPs means nothing without this flag — an address never
        # swept and an address swept but silent look identical on screen.
        self.scan_done = False
        self.cred = None           # camera credentials (kept in memory only)

    # -- log ---------------------------------------------------------------
    def log(self, msg, level="info"):
        with self.lock:
            self.logs.append({"t": now(), "msg": msg, "level": level})
            if len(self.logs) > 400:
                self.logs = self.logs[-400:]

    def set_progress(self, phase, cur=0, total=0, msg=""):
        with self.lock:
            pct = int(cur / total * 100) if total else 0
            self.progress = {"phase": phase, "pct": pct, "msg": msg,
                             "cur": cur, "total": total}

    # -- devices -----------------------------------------------------------
    def key(self, ip, mac):
        return "%s|%s" % (ip, norm_mac(mac))

    def upsert(self, ip, mac):
        k = self.key(ip, mac)
        with self.lock:
            if k not in self.devices:
                seen = describe(mac)
                self.devices[k] = {
                    "key": k, "ip": ip, "mac": norm_mac(mac),
                    "vendor": seen["vendor"], "kind": seen["kind"],
                    # A vendor prefix (OUI) only says "same company's product line", not
                    # what this one box is. Mark it confirmed only when registered by full MAC.
                    "kind_confidence": "confirmed" if seen["kind"] and seen["exact"]
                                       else ("estimated" if seen["kind"] else ""),
                    "book": seen["from_book"], "book_exact": seen["exact"],
                    "book_note": seen["note"], "model": "",
                    "title": "", "server": "", "realm": "", "onvif": "",
                    "ports": [], "status": "pending",
                    "host": "", "ms": None, "ttl": None, "os": "",
                    "nbname": "", "nbgroup": "", "mdns": "", "ssdp": "",
                    "swport": "", "swname": "", "swvlan": None, "serial": "",
                    "swspeed": 0, "swalias": "", "swslow": False, "swshared": 0,
                    "swduplex": 0,
                    "swhost": "",
                    "poeIndex": "", "poeStatus": 0, "poeWatt": 0.0,
                    "note": "", "identified": False,
                    # Which NIC picked it up. With two or more NICs selected for the
                    # sweep, doing isolation or probing on the wrong one just fails.
                    "ifname": self.iface or "", "ifindex": self.ifindex,
                    "seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                self.order.append(k)
            return self.devices[k]

    def by_ip(self):
        """Return grouped by IP. Conflicts (2 or more devices) sort first."""
        with self.lock:
            groups = {}
            for k in self.order:
                d = self.devices.get(k)
                if not d:
                    continue
                groups.setdefault(d["ip"], []).append(d)

            def sort_key(item):
                ip, devs = item
                try:
                    ip_i = int(ipaddress.IPv4Address(ip))
                except Exception:
                    ip_i = 0
                return (0 if len(devs) > 1 else 1, ip_i)

            out = []
            for ip, devs in sorted(groups.items(), key=sort_key):
                out.append({
                    "ip": ip,
                    "count": len(devs),
                    "conflict": len(devs) > 1,
                    "devices": devs,
                })
            return out

    def snapshot(self):
        with self.lock:
            groups = self.by_ip()
            total_dev = len(self.devices)
            conflict_ips = [g for g in groups if g["conflict"]]
            conflict_dev = sum(g["count"] for g in conflict_ips)
            done = sum(1 for d in self.devices.values() if d["status"] == "done")
            return {
                "app": APP_NAME, "ver": APP_VER,
                "demo": self.demo,
                "admin": is_admin(),
                "scapy": bool(SCAPY_OK),
                "scapyLoading": SCAPY_OK is None,
                "scapyErr": SCAPY_ERR,
                "iface": self.iface, "ifindex": self.ifindex,
                "cidr": self.cidr,
                "busy": self.busy, "canceling": self.cancel.is_set(),
                "progress": self.progress,
                "isolated": self.isolated,
                "lastScan": self.last_scan,
                "groups": groups,
                "scanned": len(self.scanned),
                "summary": {
                    "ips": len(groups),
                    "conflictIps": len(conflict_ips),
                    "devices": total_dev,
                    "conflictDevices": conflict_dev,
                    "done": done,
                },
                "logs": self.logs[-120:],
            }


STORE = None


# ---------------------------------------------------------------------------
# System utilities
# ---------------------------------------------------------------------------
def is_admin():
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def run_cmd(cmd, timeout=20):
    kw = {"capture_output": True, "text": True, "timeout": timeout}
    if os.name == "nt":
        kw["creationflags"] = CREATE_NO_WINDOW
    try:
        r = subprocess.run(cmd, **kw)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as e:
        return -1, "", str(e)


def run_ps(script, timeout=20):
    return run_cmd(["powershell", "-NoProfile", "-NonInteractive",
                    "-Command", script], timeout=timeout)


def ipv4_prefixes():
    """Read the prefix length (a value like /24) Windows knows for each IPv4 address."""
    script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -notlike '127.*' } | "
        "Select-Object IPAddress,PrefixLength | ConvertTo-Json -Compress"
    )
    rc, out, _ = run_ps(script, timeout=8)
    if rc != 0 or not out.strip():
        return {}
    try:
        rows = json.loads(out)
    except (TypeError, ValueError):
        return {}
    if isinstance(rows, dict):
        rows = [rows]
    result = {}
    for row in rows if isinstance(rows, list) else []:
        try:
            ip = str(row.get("IPAddress", ""))
            prefix = int(row.get("PrefixLength"))
            if 0 <= prefix <= 32:
                result[ip] = prefix
        except (AttributeError, TypeError, ValueError):
            continue
    return result


def ip_cidr(ip, prefix):
    """Build the real network notation (e.g. 192.168.0.0/23) from one address and a prefix."""
    try:
        return str(ipaddress.ip_network("%s/%d" % (ip, prefix), strict=False))
    except (TypeError, ValueError):
        return ""


def list_ifaces():
    """List of usable network interfaces. (Can be slow — call it from a thread.)"""
    out = []
    if not ensure_scapy():
        return out
    try:
        # Npcap/Scapy caches interfaces and IPs. Re-read the Windows data every time
        # so the refresh button shows current values even after an IP change in Control Panel.
        conf.ifaces.reload()
        prefixes = ipv4_prefixes()
        for _, nif in conf.ifaces.data.items():
            ips = []
            try:
                ips = [x for x in nif.ips.get(4, []) if not x.startswith("127.")]
            except Exception:
                pass
            mac = ""
            try:
                mac = nif.mac or ""
            except Exception:
                pass
            if mac in ("", "00:00:00:00:00:00") and not ips:
                continue
            ipv4 = []
            for ip in ips:
                prefix = prefixes.get(ip)
                ipv4.append({
                    "ip": ip,
                    "prefix": prefix,
                    "cidr": ip_cidr(ip, prefix) if prefix is not None else "",
                })
            out.append({
                "name": nif.name,
                # The Control Panel display name can come out mangled depending on the code page.
                # The Npcap GUID is ASCII, and it is what Scapy actually wants when sending packets.
                "scapyName": getattr(nif, "network_name", nif.name),
                "desc": getattr(nif, "description", nif.name) or nif.name,
                "ips": ips,
                "ipv4": ipv4,
                "index": getattr(nif, "index", None),
                "mac": mac,
            })
    except Exception:
        pass
    out.sort(key=lambda x: (0 if x["ips"] else 1, x["desc"]))
    return out


def iface_info(name):
    for i in list_ifaces():
        if i["name"] == name or i["desc"] == name:
            return i
    return None


# ---------------------------------------------------------------------------
# ARP pin / unpin
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Saving results and comparing scans
#
# The comparison is for handover inspection. Take one snapshot before you go in,
# scan again when the work is done, and "what I added and what disappeared" falls out.
# Devices are keyed by MAC, not IP — an IP changes, a MAC does not.
# ---------------------------------------------------------------------------

HISTORY_FILE = "scan-history.json"
HISTORY_LIMIT = 30


def export_rows(path, rows, fmt="json", target="", columns=None):
    """Write the scan result out to a file."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fmt = (fmt or "json").lower()

    if fmt == "json":
        payload = {"tool": "%s v%s" % (APP_NAME, APP_VER), "scannedAt": stamp,
                   "target": target, "count": len(rows), "devices": rows}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        return path

    if fmt == "xml":
        def esc_(v):
            return html.escape("" if v is None else str(v), quote=True)

        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<scan tool="%s" version="%s" at="%s" target="%s" count="%d">'
                 % (esc_(APP_NAME), esc_(APP_VER), esc_(stamp), esc_(target), len(rows))]
        for row in rows:
            lines.append("  <device>")
            for key, value in row.items():
                if key == "ports":
                    lines.append("    <ports>%s</ports>"
                                 % esc_(",".join(str(p) for p in value)))
                else:
                    lines.append("    <%s>%s</%s>" % (key, esc_(value), key))
            lines.append("  </device>")
        lines.append("</scan>")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path

    if fmt == "csv":
        # The CSV carries only the columns picked on screen. Laying out identification-only
        # fields — NetBIOS, mDNS, UPnP, serial, TTL, status — in Excel makes it a poor handover sheet.
        labels = {
            "ip": "IP", "mac": "MAC",
            "vendor": T("제조사", "Vendor"), "kind": T("장비 종류", "Device type"),
            "model": T("모델", "Model"), "name": T("이름", "Name"),
            "ms": T("응답(ms)", "Reply (ms)"), "os": "OS",
            "ports": T("열린 포트", "Open ports"), "swport": T("스위치 포트", "Switch port"),
            "vlan": "VLAN", "seen": T("확인 시각", "Seen at"),
        }
        chosen = [key for key in (columns or ["ip", "vendor", "kind", "model", "name", "ms", "os", "ports"])
                  if key in labels]
        # On screen IP and MAC look like one cell, but in Excel each has to be sortable
        # and filterable on its own, so always write them as two side-by-side columns.
        cols = []
        for key in chosen:
            if key == "ip":
                cols.extend(["ip", "mac"])
            elif key != "mac":
                cols.append(key)
        if "ip" not in chosen:
            cols = ["ip", "mac"] + cols
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow([labels[key] for key in cols])
            for row in rows:
                writer.writerow([
                    ",".join(str(p) for p in row.get("ports", [])) if key == "ports"
                    else ("" if row.get(key) is None else row.get(key, ""))
                    for key in cols])
        return path

    raise ValueError(T("모르는 형식입니다: %s", "Unknown format: %s") % fmt)


def _history_path():
    return os.path.join(app_dir(), HISTORY_FILE)


def load_scan_history():
    """Read finished scan records, newest first. A corrupt record starts empty, safely."""
    try:
        with open(_history_path(), "r", encoding="utf-8") as fh:
            rows = json.load(fh).get("records", [])
        return [row for row in rows if isinstance(row, dict) and row.get("id")]
    except (OSError, ValueError, AttributeError):
        return []


def save_scan_history(devices, target="", iface=""):
    """Keep the current device list for comparison. Only the last 30 runs are held."""
    record = {
        "id": datetime.now().strftime("%Y%m%d%H%M%S%f"),
        "savedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "iface": iface,
        "devices": devices,
    }
    records = load_scan_history()
    records.insert(0, record)
    tmp = _history_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"records": records[:HISTORY_LIMIT]}, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, _history_path())
    return record


def find_scan_history(record_id):
    for record in load_scan_history():
        if record.get("id") == record_id:
            return record
    return None


def compare_device_maps(base, now):
    """Compare two scans by MAC. An IP change is not treated as a device swap."""
    added = [{"mac": key, **value} for key, value in now.items() if key not in base]
    gone = [{"mac": key, **value} for key, value in base.items() if key not in now]
    moved = [{"mac": key, "from": base[key].get("ip", ""), "to": value.get("ip", "")}
             for key, value in now.items()
             if key in base and base[key].get("ip") != value.get("ip")]
    return added, gone, moved


# ---------------------------------------------------------------------------
# Port speed history — "this used to be 1G, now it is 100M"
# ---------------------------------------------------------------------------
# A gigabit link uses all 8 conductors in the cable. Let one of them go loose at
# the end and the link does not drop — it quietly falls back to 100M. Nothing
# shows on screen. The complaint that a camera cuts out now and then arrives months later.
#
# So write the port speed down every time, and if it is slower than it used to be,
# say so before anyone has to go looking.

PORT_HISTORY_FILE = "port-history.json"
# Port lookups now run each in their own thread. Read two switches at once and both
# rewrite this file at once, and one switch's history is wiped out whole.
PORT_HISTORY_LOCK = threading.RLock()
PORT_HISTORY_SWITCHES = 40        # how many switches to remember
PORT_HISTORY_PORTS = 512          # how many ports per switch


def _port_history_path():
    return os.path.join(app_dir(), PORT_HISTORY_FILE)


def load_port_history():
    """Per-switch port history. Corrupt means start empty — a record must never kill the tool."""
    try:
        with open(_port_history_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        switches = data.get("switches") if isinstance(data, dict) else None
        if not isinstance(switches, dict):
            return {}
        # One row whose value is not a dict (hand-edited, or a write cut short) blows up
        # later during cleanup. Filter it out here.
        return {key: row for key, row in switches.items() if isinstance(row, dict)}
    except (OSError, ValueError, AttributeError, TypeError):
        return {}


def _save_port_history(switches):
    tmp = _port_history_path() + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"switches": switches}, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, _port_history_path())
    except OSError:
        # Failing to write the record is survivable. Taking the scan down with it is not.
        try:
            os.remove(tmp)
        except OSError:
            pass


def port_key(info):
    """The name that identifies a port. The name if it has one, otherwise the number.

    The name comes first because rebooting the switch or pulling and reseating a module
    can shift every ifIndex. GigabitEthernet1/0/12 does not shift.
    """
    return (info.get("name") or "").strip() or "#%s" % info.get("index", "")


def port_number(info):
    """Pull the number people actually say out of the port name. GigabitEthernet1/0/12 -> 12."""
    name = (info.get("name") or "").strip()
    if name:
        bits = re.findall(r"\d+", name)
        if bits:
            return int(bits[-1])
    try:
        return int(info.get("index", 0))
    except (TypeError, ValueError):
        return 0


def compare_port_speeds(host, ports, remember=True, name=""):   # noqa: C901
    """Record port speeds and hand back the ports that got slower than they used to be.

    The baseline is not "last time" but **the fastest speed ever seen**. Compare against
    last time and you get one warning as a 1G port drops to 100M, and after that 100M is
    the new baseline and it goes quiet. The bad cable stays bad until fixed, so hold the max.

    If the attached device changed entirely, reset the baseline. Pulling a 1G camera and
    plugging in a 100M one must not be called a fault.
    """
    with PORT_HISTORY_LOCK:
        return _compare_port_speeds(host, ports, remember, name)


def _compare_port_speeds(host, ports, remember, name):
    store = load_port_history()
    slot = store.get(host)
    if not isinstance(slot, dict):
        slot = {}
    old = slot.get("ports")
    if not isinstance(old, dict):
        old = {}
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fresh, slow = {}, []

    for info in sorted(ports.values(), key=port_number):
        key = port_key(info)
        speed = int(info.get("speed") or 0)
        up = int(info.get("oper") or 0) == 1
        macs = sorted(info.get("macs") or [])
        was = old.get(key) if isinstance(old.get(key), dict) else {}
        best = int(was.get("best") or 0)
        best_at = was.get("bestAt") or ""
        okay = int(was.get("okSpeed") or 0)     # the value a person declared "this speed is normal"
        was_macs = [m for m in (was.get("macs") or []) if isinstance(m, str)]

        # If the device changed entirely, do not hold the old speed against it. Clear the
        # "normal" a person marked too — that judgement was about the device attached then.
        #
        # A live link with not one MAC visible does not mean "nothing there", it means
        # "could not read the MAC table". Count that as a swap and a healthy port loses
        # its baseline; overwrite the old list with the empty one and the next round
        # misses a real swap. If it could not be read, keep what was there before.
        swapped = bool(macs and was_macs) and not (set(macs) & set(was_macs))
        if swapped:
            best, best_at, okay = 0, "", 0
        keep_macs = macs[:16] if macs else was_macs[:16]

        # If the port has since run faster than the speed a person called "normal",
        # it has proven it can do more. Withdraw the pass.
        if speed > okay > 0:
            okay = 0

        if up and speed > 0:
            if speed > best:
                best, best_at = speed, now
            elif speed < best:
                slow.append({
                    "key": key, "index": info.get("index", ""),
                    "name": info.get("name", ""), "alias": info.get("alias", ""),
                    "no": port_number(info), "speed": speed,
                    "best": best, "bestAt": best_at,
                    "swhost": host, "swname": name or slot.get("name", ""),
                })

        fresh[key] = {
            "index": info.get("index", ""), "no": port_number(info),
            "speed": speed, "oper": 1 if up else 0,
            "poeWatt": round(float(info.get("poeWatt") or 0), 1),
            "best": best, "bestAt": best_at, "okSpeed": okay,
            "firstAt": was.get("firstAt") or now, "seenAt": now,
            "macs": keep_macs,          # no reason to write down all several hundred behind an uplink
        }

    if remember:
        # Do not keep only the ports seen this round and drop the rest. One round where
        # the name walk got cut off and ten ports came back nameless wipes out those
        # ports' 1G baseline entirely. After that the broken port stays quiet forever.
        # Only trim what has not been seen for a long time.
        merged = dict(old)
        merged.update(fresh)
        if len(merged) > PORT_HISTORY_PORTS:
            aged = sorted(merged.items(), key=lambda kv: kv[1].get("seenAt", ""))
            for dead, _ in aged[:len(merged) - PORT_HISTORY_PORTS]:
                merged.pop(dead, None)
        slot["name"] = name or slot.get("name", "")
        slot["seenAt"] = now
        slot["ports"] = merged
        store[host] = slot
        if len(store) > PORT_HISTORY_SWITCHES:
            oldest = sorted(store.items(),
                            key=lambda kv: (kv[1] or {}).get("seenAt", ""))
            for dead, _ in oldest[:len(store) - PORT_HISTORY_SWITCHES]:
                store.pop(dead, None)
        _save_port_history(store)

    slow.sort(key=lambda row: row["no"])
    return slow


def accept_port_speed(host, key):
    """Nail down that this speed is normal. Drops the baseline to the current speed.

    Leave a port with a deliberately attached 100M device red forever and people soon
    start ignoring every red. A warning that gets ignored is worse than no warning.
    """
    with PORT_HISTORY_LOCK:
        store = load_port_history()
        slot = store.get(host)
        if not isinstance(slot, dict) or not isinstance(slot.get("ports"), dict):
            return False
        return _accept(store, slot, key)


def _accept(store, slot, key):
    row = slot["ports"].get(key)
    if not isinstance(row, dict):
        return False
    # A recorded speed of 0 means "read while the link was down". Nail that down as
    # normal and the baseline (best) drops to 0 while the pass is not even stored.
    # And the screen says "recorded" — the fault goes quiet forever.
    speed = int(row.get("speed") or 0)
    if speed <= 0:
        return False
    row["best"] = speed
    row["okSpeed"] = speed
    row["bestAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_port_history(store)
    return True


# ---------------------------------------------------------------------------
# Isolation record — cleaning up after an abnormal exit
#
# Isolating means nailing "this IP is this MAC" into the Windows ARP table. On a clean exit
# the nail comes back out, but kill it from Task Manager or let the program crash and it stays in.
# That PC then only ever reaches that one device on that IP, and whoever uses it has no idea why.
#
# So write every nail to a file, and pull whatever is left over on the next run.
# Only touch what we wrote — a static ARP entry the company put there on purpose is left alone.
#
# (The nail lives in memory only, so a reboot clears it. Nobody knows that, though.)
# ---------------------------------------------------------------------------

PIN_FILE = "isolation.json"
_pin_lock = threading.Lock()


def _pin_path():
    return os.path.join(app_dir(), PIN_FILE)


def _pin_read():
    try:
        with open(_pin_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return [x for x in data.get("pins", []) if x.get("ip")]
    except (OSError, ValueError):
        return []


def _pin_write(pins):
    try:
        tmp = _pin_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"note": "격리 중인 항목. 프로그램이 정상 종료되면 비워집니다.",
                       "pins": pins}, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, _pin_path())
    except OSError:
        pass


def pin_remember(ip, mac, ifindex, ifname):
    with _pin_lock:
        pins = [x for x in _pin_read() if x.get("ip") != ip]
        pins.append({"ip": ip, "mac": mac, "ifindex": ifindex, "ifname": ifname,
                     "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        _pin_write(pins)


def pin_forget(ip):
    with _pin_lock:
        pins = [x for x in _pin_read() if x.get("ip") != ip]
        _pin_write(pins)


def pin_sweep(log=None):
    """Clear out isolations left over from last time. Called once at startup.

    Do not empty the record first. Started without administrator rights, the entry cannot
    be removed — and with the record already gone, the next run does not even try. That IP
    stays pinned to the wrong MAC until a reboot. Drop from the record only what really went.
    """
    with _pin_lock:
        pins = _pin_read()
    if not pins:
        return 0

    cleared, left = 0, []
    for item in pins:
        try:
            ok, why = arp_unpin(item["ip"], item.get("ifindex"),
                                item.get("ifname"), remember=False)
        except Exception as err:
            ok, why = False, str(err)
        if ok:
            cleared += 1
            if log:
                log("남아 있던 격리를 풀었습니다 — %s (%s)" % (
                    item["ip"], item.get("at", "")), "warn")
        else:
            left.append(item)
            if log:
                log("남아 있던 격리를 풀지 못했습니다 — %s. 관리자 권한으로 다시 "
                    "켜거나, 안 되면 PC 를 재부팅해야 그 IP 가 정상으로 "
                    "돌아옵니다. (%s)" % (item["ip"], why or "이유 모름"), "error")

    with _pin_lock:
        _pin_write(left)
    return cleared


def arp_pin(ip, mac, ifindex, ifname):
    """Bind that IP to the one device with the given MAC, and nothing else."""
    if STORE.demo:
        return True, "demo"

    if os.name == "nt":
        if not ifindex:
            return False, "인터페이스 인덱스를 알 수 없습니다"

        # First choice: netsh. Same result as PowerShell but far faster — powershell.exe
        # takes 0.5~1.5s just to start up, and one probe calls it twice, pin and unpin.
        # That was a big share of the time a tech spends waiting after clicking a device.
        run_cmd(["netsh", "interface", "ipv4", "delete", "neighbors",
                 str(ifindex), ip])
        rc, out, err = run_cmd(["netsh", "interface", "ipv4", "add",
                                "neighbors", str(ifindex), ip, dash_mac(mac)])
        if rc == 0:
            pin_remember(ip, mac, ifindex, ifname)
            return True, ""

        # Second choice: PowerShell. There are boxes where the netsh syntax does not take.
        # (New-NetNeighbor has no -Store option. It stores to memory by default, so it
        #  disappears on its own at reboot.)
        ps = (
            "Remove-NetNeighbor -InterfaceIndex {i} -IPAddress {ip} "
            "-Confirm:$false -ErrorAction SilentlyContinue; "
            "New-NetNeighbor -InterfaceIndex {i} -IPAddress {ip} "
            "-LinkLayerAddress {m} -State Permanent -ErrorAction Stop"
        ).format(i=ifindex, ip=ip, m=dash_mac(mac))
        rc2, out2, err2 = run_ps(ps)
        if rc2 == 0 and not err2.strip():
            pin_remember(ip, mac, ifindex, ifname)
            return True, "PowerShell 방식으로 처리"
        detail = (err.strip() or out.strip() or "")[:200]
        detail2 = (err2.strip() or out2.strip() or "")[:200]
        return False, "netsh: %s / PowerShell: %s" % (detail, detail2)

    rc, out, err = run_cmd(["ip", "neigh", "replace", ip, "lladdr",
                            norm_mac(mac), "dev", ifname, "nud", "permanent"])
    return (rc == 0), (err.strip() or out.strip())


def arp_unpin(ip, ifindex, ifname, remember=True):
    """Release the isolation. Clears it for certain, whichever way it was set.

    Do not just answer "success" regardless. Without administrator rights both commands
    fail silently, and this PC keeps sending that IP only to the fixed MAC — move or swap
    the device and traffic still goes to the wrong place. It takes a reboot to clear.
    Write "released" for that and nobody will ever think to go looking.
    """
    if remember:
        pin_forget(ip)
    if STORE.demo:
        return True, "demo"
    if os.name == "nt":
        # netsh first. PowerShell takes over a second just to start.
        rc = -1
        if ifindex:
            rc, out, err = run_cmd(["netsh", "interface", "ipv4", "delete",
                                    "neighbors", str(ifindex), ip])
            if rc == 0 and not _still_pinned(ip, ifindex):
                return True, ""
        ps = ("Remove-NetNeighbor -InterfaceIndex {i} -IPAddress {ip} "
              "-Confirm:$false -ErrorAction Stop").format(i=ifindex or 0, ip=ip)
        rc2, out2, err2 = run_ps(ps)
        if rc2 == 0 and not err2.strip():
            return True, ""
        if not _still_pinned(ip, ifindex):
            return True, ""       # both complained, but it is actually gone
        return False, (err2.strip() or out2.strip() or "지우지 못했습니다")[:200]
    rc, out, err = run_cmd(["ip", "neigh", "del", ip, "dev", ifname])
    return (rc == 0), (err.strip() or out.strip())


def _still_pinned(ip, ifindex):
    """Check whether that IP is still pinned (Permanent). False if it cannot be read."""
    if os.name != "nt" or not ifindex:
        return False
    rc, out, _err = run_cmd(["netsh", "interface", "ipv4", "show", "neighbors",
                             str(ifindex)])
    if rc != 0:
        return False
    for line in out.splitlines():
        bits = line.split()
        if len(bits) >= 3 and bits[0] == ip:
            return "permanent" in line.lower() or "정적" in line
    return False


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\s*-\s*(\d{1,3})$")
MAX_TARGETS = 4096


def parse_target(text):
    """Expand '192.168.0.1-254' / '192.168.0.0/24' / '192.168.0.13' into a list of IPs.

    scapy does not expand the dash range notation, so do it here.
    """
    t = (text or "").strip()
    if not t:
        return []

    if "," in t:
        out = []
        for part in t.split(","):
            out.extend(parse_target(part))
        return out

    m = RANGE_RE.match(t)
    if m:
        base, a, b = m.group(1), int(m.group(2)), int(m.group(3))
        if a > b:
            a, b = b, a
        a, b = max(0, min(255, a)), max(0, min(255, b))
        ipaddress.IPv4Address("%s.%d" % (base, a))   # format check
        return ["%s.%d" % (base, i) for i in range(a, b + 1)]

    if "/" in t:
        net = ipaddress.ip_network(t, strict=False)
        if net.prefixlen >= 31:
            return [str(h) for h in net]
        return [str(h) for h in net.hosts()]

    ipaddress.IPv4Address(t)
    return [t]


def arp_sweep(target, iface, timeout=1.5, retry=1, chunk=64,
              on_progress=None, on_found=None):
    """Spray ARP at the targets and collect every (IP, MAC) that answers.

    Send it all at once and there is no way to show progress, so it goes out in chunks.
    Each finished chunk hands over what it found right away, so the screen fills live.
    """
    if not ensure_scapy():
        raise RuntimeError(T("scapy를 불러오지 못했습니다: %s",
                             "Could not load scapy: %s") % SCAPY_ERR)
    targets = parse_target(target)
    if not targets:
        raise ValueError(T("스캔할 대상이 없습니다: %s", "Nothing to scan: %s") % target)
    if len(targets) > MAX_TARGETS:
        raise ValueError(T("대상이 너무 많습니다 (%d개). 범위를 좁혀 주십시오.",
                           "Too many targets (%d). Narrow the range.") % len(targets))

    res = {}
    scanned = []
    total = len(targets)
    for i in range(0, total, chunk):
        if STORE.cancel.is_set():
            break
        part = targets[i:i + chunk]
        scanned.extend(part)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=part)
        ans, _ = srp(pkt, timeout=timeout, retry=retry, iface=iface,
                     multi=True, verbose=0)
        found = {}
        for _, rcv in ans:
            ip = rcv.psrc
            mac = norm_mac(rcv.hwsrc)
            res.setdefault(ip, [])
            if mac not in res[ip]:
                res[ip].append(mac)
                found.setdefault(ip, []).append(mac)
        if on_found and found:
            on_found(found)
        if on_progress:
            on_progress(min(i + chunk, total), total)
    return res, scanned


def parse_ports(text):
    """Turn input like "80,443,8000-8010" into a port list."""
    if not text or not str(text).strip():
        return list(SCAN_PORTS)
    out = []
    for piece in re.split(r"[,\s]+", str(text).strip()):
        if not piece:
            continue
        if "-" in piece:
            lo, _, hi = piece.partition("-")
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            out.extend(range(max(1, lo), min(65535, hi) + 1))
        else:
            try:
                out.append(int(piece))
            except ValueError:
                continue
    out = [p for p in dict.fromkeys(out) if 1 <= p <= 65535]
    if len(out) > 400:
        raise ValueError(T("포트를 400개 넘게 지정하면 너무 오래 걸립니다.",
                           "More than 400 ports takes too long."))
    return out or list(SCAN_PORTS)


def scan_ports(ip, ports=None, timeout=0.6):
    ports = ports or SCAN_PORTS
    found = []

    def probe(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                return p
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None

    with futures.ThreadPoolExecutor(max_workers=24) as ex:
        for r in ex.map(probe, ports):
            if r:
                found.append(r)
    return sorted(found)


TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
REALM_RE = re.compile(r'realm="([^"]+)"', re.I)


def _decode(b):
    for enc in ("utf-8", "cp949", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return ""


def clean_title(text):
    """Turn a web page title back into characters a person can read.

    Titles often come with HTML entities left in raw. Synology hands over
    "RackStation&nbsp;-&nbsp;Synology". Leave that unescaped and the list shows
    a literal &nbsp;. Line breaks and runs of spaces get tidied here too.
    """
    if not text:
        return ""
    # unescaped &nbsp; is not an ordinary space (U+00A0), so swap it out separately
    out = html.unescape(text).replace("\u00a0", " ")
    return re.sub(r"\s+", " ", out).strip()


def http_probe(ip, port, timeout=3.0):
    scheme = "https" if port in (443, 8443) else "http"
    url = "%s://%s:%d/" % (scheme, ip, port)
    info = {"title": "", "server": "", "realm": ""}
    req = urllib.request.Request(url, headers={"User-Agent": "IPFixStudio/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSLCTX) as r:
            info["server"] = r.headers.get("Server", "") or ""
            body = r.read(16384)
            m = TITLE_RE.search(body)
            if m:
                info["title"] = clean_title(_decode(m.group(1)))[:80]
    except urllib.error.HTTPError as e:
        # 401/403 carry plenty too (the realm often has the model name in it)
        try:
            info["server"] = e.headers.get("Server", "") or ""
            auth = e.headers.get("WWW-Authenticate", "") or ""
            rm = REALM_RE.search(auth)
            if rm:
                info["realm"] = clean_title(rm.group(1))[:80]
            body = e.read(8192)
            m = TITLE_RE.search(body)
            if m:
                info["title"] = clean_title(_decode(m.group(1)))[:80]
        except Exception:
            pass
    except Exception:
        pass
    return info


ONVIF_MSG = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    '<e:Header><w:MessageID>uuid:1f5c2e10-4b3a-4d55-9f2b-000000000001</w:MessageID>'
    '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
    '<w:Action e:mustUnderstand="true">'
    'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
    '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>'
    '</e:Envelope>'
)

SCOPE_RE = re.compile(r"onvif://www\.onvif\.org/(\w+)/([^\s<]+)")


def onvif_probe(ip, timeout=2.0):
    """Unicast WS-Discovery. An answer all but confirms it is in the camera family."""
    out = {}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(ONVIF_MSG.encode("utf-8"), (ip, 3702))
        data, _ = s.recvfrom(65535)
        text = _decode(data)
        for kind, val in SCOPE_RE.findall(text):
            val = urllib.request.unquote(val)
            if kind in ("name", "hardware", "location", "type"):
                out.setdefault(kind, val)
    except Exception:
        pass
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# Other channels for identifying a device
#
# Besides knocking on ports, there are a few ways a device will tell you its own
# name. A device that answers gives you accurate information for free, so ask first
# and only knock on ports for the ones that stay silent.
#
#   reverse DNS  IP -> name          when the network has a DNS server
#   NetBIOS      137/UDP             Windows PCs, NVRs, shared devices
#   mDNS         224.0.0.251:5353    Apple, printers, AV gear (Bonjour)
#   SSDP         239.255.255.250     routers, cameras, media devices (UPnP)
#   ping         round-trip and TTL  guesses distance and OS
# ---------------------------------------------------------------------------

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900


def reverse_name(ip, timeout=1.0):
    """Reverse DNS. If the network has a DNS server, an IP gets you a name."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name
    except (OSError, socket.herror, socket.gaierror):
        return ""
    finally:
        socket.setdefaulttimeout(old)


def _tcp_time(ip, ports, timeout=1.0):
    """Time (ms) to connect to an open port. Used where ICMP is blocked."""
    for port in (ports or [80, 443, 554]):
        start = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return round((time.time() - start) * 1000, 1)
        except OSError:
            continue
    return None


def os_from_ttl(ttl):
    """TTL is the hops remaining. Work back to the starting value and you can guess the OS."""
    if ttl is None:
        return ""
    start = 64 if ttl <= 64 else (128 if ttl <= 128 else 255)
    return {64: "리눅스 / 임베디드", 128: "윈도우", 255: "네트워크 장비"}[start]


def ping_once(ip, timeout_ms=800, ports=None):
    """Get the round-trip time (ms) and the TTL.

    TTL is the hops remaining, so the starting value can be guessed. Starting at 128
    usually means Windows, 64 Linux/embedded (most cameras), 255 network gear.

    If ping is blocked (some cameras have ICMP switched off) or the ping command is
    missing, measure the connect time to an open port instead. No TTL that way.
    """
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        rc, out, _ = run_cmd(cmd, timeout=max(2, timeout_ms / 1000 + 1))
    except Exception:
        rc, out = 1, ""
    if rc != 0 or not out.strip():
        return {"ms": _tcp_time(ip, ports), "ttl": None, "os": ""}

    ms = ttl = None
    m = re.search(r"(?:time|시간)[=<]\s*([\d.]+)\s*ms", out, re.I)
    if m:
        ms = float(m.group(1))
    m = re.search(r"TTL[=:]\s*(\d+)", out, re.I)
    if m:
        ttl = int(m.group(1))

    if ms is None:
        ms = _tcp_time(ip, ports)

    return {"ms": ms, "ttl": ttl, "os": os_from_ttl(ttl)}


def tcp_ttl(ip, ports, timeout=1.2):
    """Throw one SYN at an open port and read the TTL off the reply packet.

    Windows PCs block ping by default at the firewall. So ping yields no TTL, while
    the web port is often wide open. Send a SYN there and read the TTL off the
    SYN-ACK that comes back and you get the same value.

    Needs scapy (= Npcap). Without it, give up quietly.
    """
    if not ports or not ensure_scapy():
        return {"ttl": None, "os": ""}
    for port in list(ports)[:3]:
        try:
            reply = sr1(IP(dst=ip) / TCP(dport=int(port), flags="S"),
                        timeout=timeout, verbose=0)
        except Exception:
            return {"ttl": None, "os": ""}
        if reply is not None and hasattr(reply, "ttl"):
            return {"ttl": int(reply.ttl), "os": os_from_ttl(int(reply.ttl))}
    return {"ttl": None, "os": ""}


def netbios_name(ip, timeout=0.8):
    """NetBIOS name lookup (137/UDP). Windows PCs and NVRs answer this readily."""
    query = (b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return {"name": "", "group": ""}
    finally:
        sock.close()

    if len(data) < 57:
        return {"name": "", "group": ""}
    count = data[56]
    names = []
    pos = 57
    for _ in range(count):
        if pos + 18 > len(data):
            break
        raw = data[pos:pos + 15].decode("cp949", "ignore").strip()
        kind = data[pos + 15]
        flags = int.from_bytes(data[pos + 16:pos + 18], "big")
        names.append((raw, kind, bool(flags & 0x8000)))   # 0x8000 = group name
        pos += 18

    name = next((n for n, k, g in names if not g and k == 0x00), "")
    group = next((n for n, k, g in names if g and k == 0x00), "")
    return {"name": name, "group": group}


def _mdns_query(name, qtype=12):
    """Build one mDNS query. qtype 12 = PTR."""
    header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    body = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + body + qtype.to_bytes(2, "big") + b"\x00\x01"


def _dns_names(data):
    """Scrape out the name fragments sitting inside a response.

    Following compression pointers properly would mean writing a whole parser, and all
    we need is "what does this device call itself", so just pick up the readable names.
    """
    out, pos = [], 12
    while pos < len(data):
        length = data[pos]
        if length == 0 or length >= 0xC0:
            pos += 1
            continue
        piece = data[pos + 1:pos + 1 + length]
        if len(piece) == length and all(32 <= b < 127 for b in piece):
            out.append(piece.decode("ascii"))
        pos += 1 + length
    return out


# Decides whether a string is worth treating as a device name.
# mDNS responses carry TXT records mixed in with the names — things like "mac_address=00:11:32:..".
# Our fragment scraper picks those up too, so they have to be filtered here.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$")


def looks_like_hostname(text):
    name = (text or "").strip()
    if not HOSTNAME_RE.match(name):
        return False
    if name.lower() in ("local", "_tcp", "_udp", "arpa", "in-addr", "ip6"):
        return False
    if name.startswith("_"):
        return False              # a service type, not a device name
    if "=" in name or "|" in name:
        return False              # fragment of a TXT record
    if re.fullmatch(r"[0-9a-fA-F]{2}([-:][0-9a-fA-F]{2}){5}", name):
        return False              # some devices hand out their MAC as the name
    if re.fullmatch(r"[0-9.]+", name):
        return False              # an IP address
    return True


def mdns_sweep(timeout=2.0):
    """Ask the whole network once. IP -> name for every device that answers.

    It shouts once over multicast rather than visiting each device, so one call
    covers the lot no matter how many devices there are.
    """
    found = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.4)
        for service in ("_services._dns-sd._udp.local",
                        "_http._tcp.local", "_workstation._tcp.local",
                        "_printer._tcp.local", "_ipp._tcp.local",
                        "_rtsp._tcp.local", "_axis-video._tcp.local",
                        "_netaudio-arc._udp.local"):
            try:
                sock.sendto(_mdns_query(service), (MDNS_GROUP, MDNS_PORT))
            except OSError:
                pass

        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            names = [n for n in _dns_names(data) if looks_like_hostname(n)]
            if names:
                found.setdefault(addr[0], names[0])
    finally:
        sock.close()
    return found


def ssdp_sweep(timeout=2.5):
    """Shout once over UPnP. IP -> {name, vendor, model, serial} for whoever answers."""
    request = ("M-SEARCH * HTTP/1.1\r\n"
               "HOST: {0}:{1}\r\n"
               'MAN: "ssdp:discover"\r\n'
               "MX: 2\r\n"
               "ST: ssdp:all\r\n\r\n").format(SSDP_GROUP, SSDP_PORT).encode()

    replies = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.4)
        for _ in range(2):                      # it is UDP, one datagram can just be dropped
            try:
                sock.sendto(request, (SSDP_GROUP, SSDP_PORT))
            except OSError:
                pass

        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode("utf-8", "ignore")
            m = re.search(r"^LOCATION:\s*(\S+)", text, re.I | re.M)
            if m:
                replies.setdefault(addr[0], m.group(1))
    finally:
        sock.close()

    # Open the URL the device handed over and it holds the name, model and serial.
    out = {}
    for ip, url in replies.items():
        info = {"name": "", "vendor": "", "model": "", "serial": ""}
        try:
            with urllib.request.urlopen(url, timeout=2.0) as res:
                body = res.read(20000).decode("utf-8", "ignore")
            for key, tag in (("name", "friendlyName"), ("vendor", "manufacturer"),
                             ("model", "modelName"), ("serial", "serialNumber")):
                m = re.search(r"<%s>\s*([^<]{1,80})</%s>" % (tag, tag), body, re.I)
                if m:
                    info[key] = html.unescape(m.group(1).strip())
            if not info["model"]:
                m = re.search(r"<modelNumber>\s*([^<]{1,80})</modelNumber>", body, re.I)
                if m:
                    info["model"] = html.unescape(m.group(1).strip())
        except Exception:
            pass                                 # even if it will not open, we still got the IP
        if any(info.values()):
            out[ip] = info
    return out


# The values below are names given "because there was nothing better to call it".
# They are lumped together from ports or vendor alone, so if the device book knows a
# name, that one is always better. Example: a Synology NAS has 80, 443 and 5000 open
# and gets lumped in as "web-managed device" — the book already knows it is a "NAS".
WEAK_KINDS = {
    "웹 관리 장비", "네트워크 장비", "네트워크 장비 (스위치/AP 추정)",
    "영상 장비 (카메라 계열)", "AV 장비", "미확인", "",
}


def guess_kind(vendor, ports, title, server, realm, onvif):
    blob = " ".join([title or "", server or "", realm or "",
                     onvif.get("name", ""), onvif.get("hardware", "")]).lower()
    ps = set(ports or [])

    if onvif:
        if "nvr" in blob or "recorder" in blob:
            return "NVR / 녹화기"
        return "IP 카메라 (ONVIF)"
    if "microsoft-iis" in blob or re.search(r"\biis\b", blob):
        return "Windows 웹 서버"
    if 37777 in ps or 34567 in ps:
        return "DVR / NVR"
    if 554 in ps or 8554 in ps:
        if 8000 in ps:
            return "IP 카메라 / NVR"
        return "IP 카메라"
    if 4352 in ps:
        return "프로젝터 (PJLink)"
    if 41794 in ps:
        return "Crestron 제어기"
    if 1319 in ps:
        return "AMX 제어기"
    if 9100 in ps:
        return "프린터"
    for kw, label in [("camera", "IP 카메라"), ("nvr", "NVR / 녹화기"),
                      ("dvr", "DVR"), ("switch", "네트워크 스위치"),
                      ("router", "공유기 / 라우터"), ("access point", "무선 AP"),
                      ("encoder", "인코더"), ("decoder", "디코더"),
                      ("projector", "프로젝터"), ("matrix", "매트릭스 스위처"),
                      ("printer", "프린터")]:
        if kw in blob:
            return label
    if 161 in ps and (23 in ps or 22 in ps) and 80 in ps:
        return "네트워크 장비 (스위치/AP 추정)"
    if vendor in ("Ubiquiti", "TP-Link", "Cisco", "Netgear", "Aruba"):
        return "네트워크 장비"
    if vendor in ("Extron", "Crestron", "AMX", "Kramer", "Barco", "ATEN"):
        return "AV 장비"
    if vendor in ("Hikvision", "Dahua", "Hanwha", "IDIS", "Axis", "Uniview",
                  "Bosch", "Panasonic", "Sony"):
        return "영상 장비 (카메라 계열)"
    if ps:
        return "웹 관리 장비"
    return "미확인"


def pick_model(title, realm, server, onvif):
    for cand in [onvif.get("hardware", ""), onvif.get("name", ""),
                 realm or "", title or "", server or ""]:
        c = clean_title(cand)
        if c and c.lower() not in ("index", "login", "web", "document",
                                   "untitled", "home", "webserver"):
            return c[:60]
    return ""


def generic_model_name(value):
    """Decide whether this is a broad phrase naming the device's role rather than a model."""
    text = clean_title(value).lower()
    if not text:
        return True
    # With a type number like AX6000M in it, it is a model name even if a role word (router) is there too.
    if re.search(r"\d", text):
        return False
    return any(word in text for word in (
        "router", "gateway", "camera", "network camera", "nvr", "dvr",
        "switch", "web server", "webserver", "network device",
    ))


def preferred_model(current, candidate):
    """Stop a generic name like a web page title from overwriting a specific model already held."""
    current = clean_title(current)
    candidate = clean_title(candidate)
    if not candidate:
        return current
    if not current:
        return candidate
    # Example: SSDP's 'ipTIME AX6000M' beats 'ipTIME Router' from the HTTP auth realm.
    if generic_model_name(candidate) and not generic_model_name(current):
        return current
    if generic_model_name(current) and not generic_model_name(candidate):
        return candidate
    # Same class either way: keep what came first. A probe never degrades the scan result.
    return current


def kind_family(kind):
    """Treat different wordings for the same device category as one group."""
    value = (kind or "").lower()
    if "공유기" in value or "라우터" in value or "router" in value:
        return "router"
    return value


def identify_device(dev, ifindex, ifname, isolate=True, ports_text=""):
    """Dig out what one device is. Probes it isolated by ARP when that is needed."""
    ip, mac = dev["ip"], dev["mac"]
    pinned = False
    if isolate and not STORE.demo:
        ok, msg = arp_pin(ip, mac, ifindex, ifname)
        pinned = ok
        if not ok:
            STORE.log(T("ARP 격리 실패 %s / %s : %s",
                        "ARP isolation failed %s / %s : %s") % (ip, mac, msg), "warn")
        else:
            time.sleep(0.4)
    try:
        http = {"title": "", "server": "", "realm": ""}
        ov = {}

        if STORE.demo:
            # in demo mode nothing goes out on the real network
            time.sleep(0.35)
            ports = dev.get("ports") or []
            http["title"] = dev.get("title") or ""
        else:
            ports = scan_ports(ip, parse_ports(ports_text))
            if STORE.cancel.is_set():
                return dev

            # From here on it is all "wait for an answer" work. None of it has any reason
            # to wait on the rest, and yet it used to be queued up — web up to 15s, then
            # ONVIF 2s, then the name batch. On anything that is not a camera those ONVIF
            # 2s were pure waste. Fire them all at once and wait only for the slowest.
            def web():
                # Only the first two open web ports. Whichever answers first is the one we use.
                live = [p for p in (80, 8080, 8000, 443, 8443) if p in ports][:2]
                best = {"title": "", "server": "", "realm": ""}
                if not live:
                    return best
                with futures.ThreadPoolExecutor(max_workers=len(live)) as web_pool:
                    for got_one in web_pool.map(lambda p: http_probe(ip, p), live):
                        if got_one.get("title") or got_one.get("server") or got_one.get("realm"):
                            return got_one
                return best

            with futures.ThreadPoolExecutor(max_workers=5) as pool:
                jobs = {
                    "web": pool.submit(web),
                    "onvif": pool.submit(onvif_probe, ip),
                    "rdns": pool.submit(reverse_name, ip),
                    "ping": pool.submit(ping_once, ip, 800, ports),
                    "nbt": pool.submit(netbios_name, ip),
                }
                got = {}
                for key, job in jobs.items():
                    try:
                        got[key] = job.result(timeout=6)
                    except Exception:
                        got[key] = None
            http = got.get("web") or {"title": "", "server": "", "realm": ""}
            ov = got.get("onvif") or {}
            if STORE.cancel.is_set():
                return dev
            extra = {
                "host": got.get("rdns") or "",
                "ms": (got.get("ping") or {}).get("ms"),
                "ttl": (got.get("ping") or {}).get("ttl"),
                "os": (got.get("ping") or {}).get("os", ""),
                "nbname": (got.get("nbt") or {}).get("name", ""),
                "nbgroup": (got.get("nbt") or {}).get("group", ""),
            }
            # Ping blocked so no TTL, but there are open ports: measure again with a SYN.
            # A Windows PC's default firewall commonly blocks only ping and leaves web ports open.
            if extra["ttl"] is None and ports:
                extra.update(tcp_ttl(ip, ports))
                if extra["ttl"] is not None:
                    STORE.log(T("%s 핑이 막혀 있어 TCP 응답으로 TTL 을 읽었습니다 (%d)",
                                "%s blocks ping — read TTL from the TCP reply instead (%d)")
                              % (ip, extra["ttl"]), "info")

        with STORE.lock:
            if not STORE.demo:
                dev.update(extra)
            dev["ports"] = ports
            dev["title"] = http.get("title", "")
            dev["server"] = http.get("server", "")
            dev["realm"] = http.get("realm", "")
            dev["onvif"] = ov.get("hardware", "") or ov.get("name", "")
            if STORE.demo and dev.get("model"):
                pass  # keep the demo seed's model name
            else:
                scanned_model = pick_model(dev["title"], dev["realm"],
                                           dev["server"], ov)
                dev["model"] = preferred_model(dev.get("model", ""), scanned_model)
            found = guess_kind(dev["vendor"], ports, dev["title"],
                               dev["server"], dev["realm"], ov)
            if dev.get("book_exact") and dev.get("kind"):
                pass                      # registered by full MAC, pinned to this box — the person wins
            elif dev.get("kind") and kind_family(dev["kind"]) == kind_family(found):
                pass                      # same meaning, like "Router" vs "Router / gateway" — keep the existing wording
            elif found not in WEAK_KINDS:
                dev["kind"] = found
                dev["kind_confidence"] = "estimated"
            elif dev.get("book") and dev.get("kind"):
                pass                      # a name the book knows beats a lumped-together guess
            elif found and found != "미확인":
                dev["kind"] = found
                dev["kind_confidence"] = "estimated"
            elif not dev.get("kind"):
                dev["kind"] = found
                dev["kind_confidence"] = "estimated" if found and found != "미확인" else ""
            dev["identified"] = True
    finally:
        if pinned and isolate:
            arp_unpin(ip, ifindex, ifname)
    return dev


# ---------------------------------------------------------------------------
# Camera preview (ONVIF snapshot)
# ---------------------------------------------------------------------------
SNAP_PATHS = {
    "Hikvision": ["/ISAPI/Streaming/channels/101/picture",
                  "/Streaming/channels/1/picture"],
    "Dahua":     ["/cgi-bin/snapshot.cgi?channel=1", "/cgi-bin/snapshot.cgi"],
    "Hanwha":    ["/stw-cgi/video.cgi?msubmenu=snapshot&action=view",
                  "/cgi-bin/video.cgi?msubmenu=snapshot&action=view"],
    "Axis":      ["/axis-cgi/jpg/image.cgi"],
    "Uniview":   ["/images/snapshot.jpg", "/cgi-bin/snapshot.cgi"],
    "IDIS":      ["/cgi-bin/snapshot.cgi"],
    "Bosch":     ["/snap.jpg"],
    "Panasonic": ["/cgi-bin/camera?resolution=640"],
    "Sony":      ["/oneshotimage.jpg"],
}
GENERIC_SNAP = ["/onvif-http/snapshot?Profile_1", "/snapshot.jpg", "/snap.jpg",
                "/image.jpg", "/cgi-bin/snapshot.cgi", "/jpg/image.jpg"]

ONVIF_NS = (
    'xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:t="http://www.onvif.org/ver10/schema" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
    'xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
)
WSSE = ("http://docs.oasis-open.org/wss/2004/01/"
        "oasis-200401-wss-wssecurity-secext-1.0.xsd")
WSU = ("http://docs.oasis-open.org/wss/2004/01/"
       "oasis-200401-wss-wssecurity-utility-1.0.xsd")
PW_DIGEST = ("http://docs.oasis-open.org/wss/2004/01/"
             "oasis-200401-wss-username-token-profile-1.0#PasswordDigest")
B64_ENC = ("http://docs.oasis-open.org/wss/2004/01/"
           "oasis-200401-wss-soap-message-security-1.0#Base64Binary")


def _wsse_header(user, pw):
    """ONVIF auth header (UsernameToken Digest)."""
    import base64
    import hashlib
    nonce = os.urandom(16)
    created = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = hashlib.sha1(nonce + created.encode() + pw.encode()).digest()
    return (
        '<s:Header><Security s:mustUnderstand="1" xmlns="%s">'
        '<UsernameToken><Username>%s</Username>'
        '<Password Type="%s">%s</Password>'
        '<Nonce EncodingType="%s">%s</Nonce>'
        '<Created xmlns="%s">%s</Created>'
        '</UsernameToken></Security></s:Header>'
    ) % (WSSE, _xml_esc(user), PW_DIGEST,
         base64.b64encode(digest).decode(), B64_ENC,
         base64.b64encode(nonce).decode(), WSU, created)


def _xml_esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _soap_url(url, body, user, pw, timeout=6):
    """Send a SOAP request to the given ONVIF service URL."""
    env = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<s:Envelope %s>%s<s:Body>%s</s:Body></s:Envelope>'
           % (ONVIF_NS, _wsse_header(user, pw) if user else "", body))
    req = urllib.request.Request(
        url, data=env.encode("utf-8"),
        headers={"Content-Type": "application/soap+xml; charset=utf-8"})
    with urllib.request.urlopen(req, timeout=timeout, context=SSLCTX) as r:
        return _decode(r.read())


PROFILE_RE = re.compile(r'token="([^"]+)"')
URI_RE = re.compile(r"<[^>]*Uri[^>]*>([^<]+)</[^>]*Uri>", re.I)
MEDIA_XADDR_RE = re.compile(
    r"<(?:\w+:)?Media[^>]*>.*?<(?:\w+:)?XAddr[^>]*>([^<]+)</(?:\w+:)?XAddr>",
    re.I | re.S)


def onvif_snapshot_uri(ip, user, pw, bases=None, log=None):
    """Find the Media service address via the ONVIF Device service and get the snapshot URI."""
    def say(msg):
        if log:
            log(msg)

    bases = bases or ["http://%s" % ip]
    services = []
    seen = set()

    def add(url):
        if url and url not in seen:
            seen.add(url)
            services.append(url)

    for base in bases:
        device_url = base.rstrip("/") + "/onvif/device_service"
        try:
            caps = _soap_url(device_url, "<tds:GetCapabilities><tds:Category>Media</tds:Category>"
                             "</tds:GetCapabilities>", user, pw)
            xaddrs = MEDIA_XADDR_RE.findall(caps)
            for xaddr in xaddrs:
                add(xaddr.strip())
            if xaddrs:
                say(T("ONVIF Media 서비스 확인", "Found the ONVIF Media service"))
        except Exception:
            pass
        # Non-standard, but some devices take Media requests on the Device service too.
        add(device_url)
        # Some older devices offer no Capabilities at all, only the fixed paths below.
        for path in ("/onvif/media_service", "/onvif/Media", "/onvif/services"):
            add(base.rstrip("/") + path)

    for service_url in services:
        try:
            xml = _soap_url(service_url, "<trt:GetProfiles/>", user, pw)
        except Exception:
            continue
        tokens = PROFILE_RE.findall(xml)
        for tok in tokens[:3]:
            try:
                xml2 = _soap_url(
                    service_url,
                    "<trt:GetSnapshotUri><trt:ProfileToken>%s"
                    "</trt:ProfileToken></trt:GetSnapshotUri>" % _xml_esc(tok),
                    user, pw)
                m = URI_RE.search(xml2)
                if m:
                    return m.group(1).strip()
            except Exception:
                continue
    return ""


def http_get_auth(url, user, pw, timeout=8):
    """Fetch it with whichever works, Digest or Basic."""
    pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pm.add_password(None, url, user or "", pw or "")
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(pm),
        urllib.request.HTTPBasicAuthHandler(pm),
        urllib.request.HTTPSHandler(context=SSLCTX))
    req = urllib.request.Request(url, headers={"User-Agent": "IPFixStudio/1.0"})
    with opener.open(req, timeout=timeout) as r:
        return r.read()


def looks_like_image(b):
    return bool(b) and (b[:2] == b"\xff\xd8" or b[:8] == b"\x89PNG\r\n\x1a\n")


def camera_bases(dev):
    """The HTTP/HTTPS addresses to try a snapshot on. SDK ports (8000, for instance) are excluded."""
    ports = set(dev.get("ports") or [])
    candidates = []
    for port, scheme in ((80, "http"), (443, "https"), (8080, "http"),
                         (8443, "https")):
        # The port scan result comes first, but 80/443 are such common defaults they always get one try.
        if port in ports or port in (80, 443):
            host = dev["ip"] if port in (80, 443) else "%s:%d" % (dev["ip"], port)
            candidates.append("%s://%s" % (scheme, host))
    # Do not miss the ordinary web ports the device answered on. 8000 is the Hikvision SDK port, so it is out.
    for port in sorted(ports - {80, 443, 8000, 554, 8554, 37777, 34567}):
        if port <= 0 or port > 65535:
            continue
        candidates.append("http://%s:%d" % (dev["ip"], port))
        candidates.append("https://%s:%d" % (dev["ip"], port))
    return list(dict.fromkeys(candidates))


def grab_snapshot(dev, user, pw, log=None):
    """Grab one frame from the camera. Returns (bytes, how it was fetched)."""
    ip = dev["ip"]

    def say(m):
        if log:
            log(m)

    bases = camera_bases(dev)
    errors = []

    # First choice: the ONVIF standard
    try:
        uri = onvif_snapshot_uri(ip, user, pw, bases, say)
        if uri:
            say(T("ONVIF 스냅샷 주소 확인", "Found the ONVIF snapshot URL"))
            try:
                data = http_get_auth(uri, user, pw)
                if looks_like_image(data):
                    return data, "ONVIF"
            except Exception as e:
                errors.append(T("ONVIF 주소 응답 실패: %s", "ONVIF URL did not answer: %s") % e)
    except Exception as e:
        errors.append(T("ONVIF 조회 실패: %s", "ONVIF query failed: %s") % e)

    # Second choice: the known per-vendor paths
    paths = list(SNAP_PATHS.get(dev.get("vendor"), [])) + GENERIC_SNAP
    for base in bases:
        for path in paths:
            url = base + path
            try:
                data = http_get_auth(url, user, pw, timeout=5)
                if looks_like_image(data):
                    return data, urllib.parse.urlsplit(url).path or path
            except Exception as e:
                errors.append("%s: %s" % (urllib.parse.urlsplit(url).netloc, e))
                continue
    detail = errors[-1] if errors else T("스냅샷 주소를 찾지 못했습니다", "No snapshot URL found")
    return None, detail[:180]


# ---------------------------------------------------------------------------
# Background jobs
# ---------------------------------------------------------------------------
DEMO_SEED = [
    ("192.168.0.13", [("bc:ad:28:11:22:33", [80, 554, 8000], "IP CAMERA", "DS-2CD2143G0-I"),
                      ("bc:ad:28:44:55:66", [80, 554, 8000], "IP CAMERA", "DS-2CD2043G2-I"),
                      ("90:02:a9:aa:bb:cc", [80, 554, 37777], "WEB SERVICE", "IPC-HDW2431T"),
                      ("e4:30:22:de:ad:01", [80, 554], "Hanwha Vision", "XNV-6081")]),
    ("192.168.0.64", [("90:02:a9:12:34:56", [80, 554, 37777], "WEB SERVICE", "DH-IPC-HFW1230"),
                      ("90:02:a9:65:43:21", [80, 554, 37777], "WEB SERVICE", "DH-IPC-HFW1230"),
                      ("48:ea:63:0a:0b:0c", [80, 554], "Uniview", "IPC2122LR3")]),
    ("192.168.0.100", [("00:05:a6:00:11:22", [23, 80], "Extron Electronics", "IN1804"),
                       ("00:10:7f:33:44:55", [80, 41794], "Crestron", "DM-MD8X8")]),
    ("192.168.0.1", [("24:a4:3c:99:88:77", [22, 80, 443, 161], "UniFi Switch", "USW-24-PoE")]),
    ("192.168.0.200", [("7c:2e:0d:ab:cd:ef", [80], "Blackmagic", "ATEM Mini")]),
]


# ---------------------------------------------------------------------------
# Finding the switch port (SNMP)
#
# The longest job on site is "which port in the rack is this camera on".
# A switch will hand over the MAC table it learned (which MAC came in on which
# port) over SNMP. Read that table, match it against the MACs in our list, and
# "this camera = switch 3, port 12" falls straight out.
#
# No library. SNMP v2c is one UDP datagram and all it needs is a few lines of
# BER encoding, so there is no reason to add an external dependency.
# ---------------------------------------------------------------------------

SNMP_PORT = 161

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"          # dot1dTpFdbPort
OID_Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"    # dot1qTpFdbPort (per VLAN)
OID_BASE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"      # dot1dBasePortIfIndex

# When not a single MAC-table row could be read, this list checks how far the switch will go.
# All zeroes means the switch does not serve the bridge MIB at all (common on cheap gear).
# A number on ifName only means SNMP works and just the MAC table is missing.
SNMP_PROBE = [
    ("dot1qTpFdbPort", "1.3.6.1.2.1.17.7.1.2.2.1.2"),
    ("dot1qTpFdbStatus", "1.3.6.1.2.1.17.7.1.2.2.1.3"),
    ("dot1dTpFdbPort", "1.3.6.1.2.1.17.4.3.1.2"),
    ("dot1dTpFdbStatus", "1.3.6.1.2.1.17.4.3.1.3"),
    ("dot1dBasePortIfIndex", "1.3.6.1.2.1.17.1.4.1.2"),
    ("ifName", "1.3.6.1.2.1.31.1.1.1.1"),
]
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"           # ifName
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"             # ifDescr
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"    # ifHighSpeed (Mbps)
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"             # ifSpeed (bps, for older gear)
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"         # ifAlias (the description written on the port)

# --- PoE (POWER-ETHERNET-MIB, RFC 3621) ------------------------------------
# How much power each port is pushing out, and the ability to power-cycle it.
# The table index is two parts (group.port). On a non-stacked switch the group is nearly always 1.
OID_POE_ADMIN  = "1.3.6.1.2.1.105.1.1.1.3"       # pethPsePortAdminEnable (1 on / 2 off)
OID_POE_STATUS = "1.3.6.1.2.1.105.1.1.1.6"       # pethPsePortDetectionStatus
OID_POE_CLASS  = "1.3.6.1.2.1.105.1.1.1.10"      # pethPsePortPowerClassifications
OID_POE_MAIN_CAP = "1.3.6.1.2.1.105.1.3.1.1.2"   # pethMainPsePower (total capacity, W)
OID_POE_MAIN_USE = "1.3.6.1.2.1.105.1.3.1.1.4"   # pethMainPseConsumptionPower (W drawn right now)
# Per-port actual power draw is not in the standard. Cisco serves it separately (mW).
OID_POE_CISCO_W = "1.3.6.1.4.1.9.9.402.1.2.1.7"  # cpeExtPsePortPwrConsumption

# --- Port management (IF-MIB) ----------------------------------------------
OID_IF_TYPE  = "1.3.6.1.2.1.2.2.1.3"             # ifType (6 = ethernet)
OID_IF_PHYS  = "1.3.6.1.2.1.2.2.1.6"             # ifPhysAddress (the switch's own MAC)
OID_IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"             # ifAdminStatus (1 up / 2 locked)
OID_IF_OPER  = "1.3.6.1.2.1.2.2.1.8"             # ifOperStatus (1 link up / 2 no link)
IF_TYPE_ETHERNET = 6

# --- Duplex (EtherLike-MIB) ------------------------------------------------
# This is the hardest fault on site to catch. The speed reads 1G, and moving one
# file takes minutes. The link is up, ping goes through, nothing on screen is red.
# The cause is a duplex mismatch between the two ends.
#
# Hard-set one end to "100M full" and the far end, with nobody to negotiate with,
# barely works out the speed and falls back to 'half' the way the rules say. Then
# the half side gets late collisions and the full side sees corrupted frames.
# Neither drops the link. So to a person it just looks like "it's slow".
#
# Values are 1 unknown / 2 half / 3 full. We use 0 to mean 'could not read' —
# plenty of switches do not serve this MIB at all, and filling that in as 'full'
# would have this tool claim it confirmed something it never checked.
OID_DUPLEX     = "1.3.6.1.2.1.10.7.2.1.19"       # dot3StatsDuplexStatus
OID_LATE_COLL  = "1.3.6.1.2.1.10.7.2.1.8"        # dot3StatsLateCollisions
DUPLEX_UNKNOWN, DUPLEX_HALF, DUPLEX_FULL = 1, 2, 3

POE_STATUS = {1: ("꺼짐", "disabled"), 2: ("장비 찾는 중", "searching"),
              3: ("급전 중", "delivering"), 4: ("고장", "fault"),
              5: ("시험", "test"), 6: ("고장(기타)", "otherFault")}

# Max power per class. Used to estimate when the real draw cannot be read.
POE_CLASS_WATT = {1: 15.4, 2: 4.0, 3: 7.0, 4: 15.4, 5: 30.0}


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_int(value):
    if value == 0:
        return _tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(0x02, body)


def _ber_oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _read_tlv(buf, i):
    """Returns (tag, value, next position)."""
    tag = buf[i]
    length = buf[i + 1]
    i += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(buf[i:i + count], "big")
        i += count
    return tag, buf[i:i + length], i + length


def _oid_str(body):
    first = body[0]
    out = [first // 40, first % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            out.append(value)
            value = 0
    return ".".join(str(x) for x in out)


def _int_of(body):
    return int.from_bytes(body, "big", signed=False) if body else 0


def _snmp_message(community, pdu_tag, request_id, oid, non_repeaters=0):
    varbind = _tlv(0x30, _ber_oid(oid) + _tlv(0x05, b""))
    pdu = _tlv(pdu_tag,
               _ber_int(request_id) + _ber_int(0) + _ber_int(0)
               + _tlv(0x30, varbind))
    return _tlv(0x30, _ber_int(1)                       # version 1 = v2c
                + _tlv(0x04, community.encode("utf-8"))
                + pdu)


def _snmp_ask(sock, addr, community, pdu_tag, oid, request_id, timeout):
    sock.settimeout(timeout)
    sock.sendto(_snmp_message(community, pdu_tag, request_id, oid), addr)
    deadline = time.time() + timeout
    while time.time() < deadline:
        data, _ = sock.recvfrom(8192)
        _, body, _ = _read_tlv(data, 0)
        _, _, i = _read_tlv(body, 0)                    # version
        _, _, i = _read_tlv(body, i)                    # community
        tag, pdu, _ = _read_tlv(body, i)
        if tag != 0xA2:                                 # only GetResponse is accepted
            continue
        _, rid, j = _read_tlv(pdu, 0)
        if _int_of(rid) != request_id:
            continue
        _, err, j = _read_tlv(pdu, j)
        _, _, j = _read_tlv(pdu, j)                     # error index
        _, binds, _ = _read_tlv(pdu, j)
        if _int_of(err):
            return None, None, _int_of(err)
        _, bind, _ = _read_tlv(binds, 0)
        _, oid_body, k = _read_tlv(bind, 0)
        vtag, value, _ = _read_tlv(bind, k)
        return _oid_str(oid_body), (vtag, value), 0
    raise socket.timeout()


def snmp_get(ip, community, oid, timeout=1.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Wrong community and the switch says nothing back. Take that as 'none' too.
        try:
            _, value, err = _snmp_ask(sock, (ip, SNMP_PORT), community, 0xA0, oid,
                                      random.randint(1, 0x7FFFFFFF), timeout)
        except (socket.timeout, OSError):
            return None
        if err or value is None:
            return None
        tag, body = value
        if tag == 0x04:
            return body.decode("utf-8", "replace").strip()
        # Numbers arrive as more than just 0x02 INTEGER. ifHighSpeed is a Gauge32
        # (0x42) — miss that and the speed comes back as a byte blob and turns into 0 somewhere.
        if tag in (0x02, 0x41, 0x42, 0x43, 0x46):   # INTEGER, Counter32, Gauge32, TimeTicks, Counter64
            return _int_of(body)
        return body
    finally:
        sock.close()


SNMP_WALK_TRUNCATED = set()


def snmp_walk(ip, community, root, timeout=1.5, limit=8000):
    """Repeat GETNEXT to read every entry below root. {OID: (tag, value)}.

    If it gets cut off at limit, record that in SNMP_WALK_TRUNCATED. A truncated MAC
    table drops the MACs behind an uplink, so that port looks like "one device only" —
    lock it in that state and everything below goes down. This must not pass silently.
    """
    SNMP_WALK_TRUNCATED.discard(root)
    out = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    current = root
    try:
        while True:
            if len(out) >= limit:
                SNMP_WALK_TRUNCATED.add(root)
                break
            try:
                oid, value, err = _snmp_ask(
                    sock, (ip, SNMP_PORT), community, 0xA1, current,
                    random.randint(1, 0x7FFFFFFF), timeout)
            except (socket.timeout, OSError):
                # Windows answers a closed UDP port with ICMP unreachable, and that
                # surfaces as ConnectionResetError. No reason to blow the whole thing up.
                break
            except (IndexError, ValueError):
                # A short packet from somewhere else. Ignore it and use what was read so far.
                break
            # Stop at the end of the table. There are three reasons to stop.
            #  - an error came back / we walked past our table
            #  - a 'not there' marker came back, like endOfMibView or noSuchObject (tags 0x80~0x82)
            #  - the OID did not move forward (some devices hand back the same spot)
            if err or oid is None or not oid.startswith(root + "."):
                break
            if value is None or value[0] in (0x80, 0x81, 0x82):
                break
            if oid in out:
                break
            out[oid] = value
            current = oid
    finally:
        sock.close()
    return out


def _mac_from_oid_tail(tail):
    """Six decimal parts off the tail of an OID into a MAC string."""
    parts = [int(x) for x in tail.split(".") if x != ""]
    if len(parts) != 6 or any(p > 255 for p in parts):
        return ""
    return "".join("%02x" % p for p in parts)


def snmp_port_map(ip, community="public", timeout=1.5, log=None):
    """Read the MAC -> port table off the switch.

    What comes back: {"name": switch name, "ports": {mac: {...}}, "count": n}
    """
    say = log or (lambda *a, **k: None)
    name = snmp_get(ip, community, OID_SYS_NAME, timeout)
    if name is None:
        descr = snmp_get(ip, community, OID_SYS_DESCR, timeout)
        if descr is None:
            raise RuntimeError(T(
                "스위치가 SNMP 로 답하지 않습니다 (%s). IP·커뮤니티 문자열을 "
                "확인하고, 스위치에서 SNMP v2c 읽기를 켰는지 보십시오.",
                "The switch is not answering SNMP (%s). Check the IP and community "
                "string, and make sure SNMP v2c read is enabled on the switch.") % ip)
        name = descr.splitlines()[0][:40]

    # bridge port number -> interface index -> the port name a person reads
    base = {k.rsplit(".", 1)[-1]: _int_of(v[1])
            for k, v in snmp_walk(ip, community, OID_BASE_PORT_IF, timeout).items()}
    names = {}
    for oid_root in (OID_IF_NAME, OID_IF_DESCR):
        for k, v in snmp_walk(ip, community, oid_root, timeout).items():
            index = k.rsplit(".", 1)[-1]
            if index not in names and v[0] == 0x04:
                names[index] = v[1].decode("utf-8", "replace").strip()
        if names:
            break

    # Port speed. The point is to find devices sitting at 100M on a gigabit port.
    # Lose one of the cable's four pairs and the link does not drop, it quietly falls to 100M.
    # You will never find that by eye, but the switch knows.
    speeds = {}
    for k, v in snmp_walk(ip, community, OID_IF_HIGH_SPEED, timeout).items():
        speeds[k.rsplit(".", 1)[-1]] = _int_of(v[1])          # already in Mbps
    if not speeds:                                            # older gear only serves ifSpeed
        for k, v in snmp_walk(ip, community, OID_IF_SPEED, timeout).items():
            speeds[k.rsplit(".", 1)[-1]] = _int_of(v[1]) // 1000000

    # Read duplex here as well. This value has to ride along into the device list, so that
    # one line for a camera is enough to spot "1G speed but half duplex". If it only shows
    # after opening the port management window, that fault never gets caught.
    duplexes = {}
    try:
        for k, v in snmp_walk(ip, community, OID_DUPLEX, timeout).items():
            duplexes[k.rsplit(".", 1)[-1]] = _int_of(v[1])
    except Exception:
        duplexes = {}

    aliases = {}
    for k, v in snmp_walk(ip, community, OID_IF_ALIAS, timeout).items():
        if v[0] == 0x04:
            text = v[1].decode("utf-8", "replace").strip()
            if text:
                aliases[k.rsplit(".", 1)[-1]] = text

    ports = {}

    def remember(mac, bridge_port, vlan=None):
        if not mac or not bridge_port:
            return
        ifindex = base.get(str(bridge_port), bridge_port)
        label = names.get(str(ifindex)) or (T("포트 %s", "Port %s") % bridge_port)
        ports[mac] = {"port": label, "portNo": bridge_port,
                      "ifIndex": ifindex, "vlan": vlan,
                      "speed": speeds.get(str(ifindex)) or 0,
                      "duplex": duplexes.get(str(ifindex)) or 0,
                      "alias": aliases.get(str(ifindex), "")}

    # Modern switches serve the per-VLAN table (dot1q), older ones the combined table (dot1d).
    #
    # Do not hard-code the tail shape as 7 parts (VLAN 1 + MAC 6). Some vendors prepend
    # extra parts, and then the table reads fine but not one row survives.
    # The MAC is always **the last six parts**. Everything before it is treated as VLAN.
    q_table = snmp_walk(ip, community, OID_Q_FDB_PORT, timeout)
    raw_sample = []
    for oid, value in q_table.items():
        tail = oid[len(OID_Q_FDB_PORT) + 1:]
        bits = [b for b in tail.split(".") if b != ""]
        if len(raw_sample) < 3:
            raw_sample.append("%s=%d" % (tail, _int_of(value[1])))
        if len(bits) < 7:
            continue
        vlan = None
        try:
            vlan = int(bits[-7])
        except ValueError:
            vlan = None
        remember(_mac_from_oid_tail(".".join(bits[-6:])), _int_of(value[1]), vlan=vlan)

    if not ports:
        for oid, value in snmp_walk(ip, community, OID_FDB_PORT, timeout).items():
            remember(_mac_from_oid_tail(oid[len(OID_FDB_PORT) + 1:]),
                     _int_of(value[1]))

    # If nothing at all came back, count how far the switch will go and log it.
    # A wrong community and "this switch does not serve its MAC table over SNMP" have
    # to be told apart. The first is fixable, the second is not.
    probe_line = ""
    if not ports:
        counts = []
        for label, oid_root in SNMP_PROBE:
            try:
                counts.append("%s %d" % (label, len(snmp_walk(ip, community, oid_root, timeout))))
            except Exception:
                counts.append("%s ?" % label)
        probe_line = T("진단 — {rows}", "Probe — {rows}").format(rows=" · ".join(counts))
        if raw_sample:
            probe_line += T("  |  본 그대로: ", "  |  raw: ") + ", ".join(raw_sample)

    # One judgement, shared with the port window. Keeping a second copy of this rule
    # here is what let the log and the faceplate disagree about the same switch.
    mark_slow_ports(ports.values())
    top = common_speed([info["speed"] for info in ports.values()])

    # The two languages order the words differently, so use named fields, not positional (%s).
    # PoE — which ports the switch is powering. If it cannot be read, just move on.
    poe_main = {"used": 0.0, "capacity": 0.0}
    try:
        poe = read_poe(ip, community, timeout)
        poe_main = poe["main"]
        for info in ports.values():
            index = poe_index_for(info["portNo"], poe["ports"])
            if not index:
                continue
            row = poe["ports"][index]
            info["poeIndex"] = index
            info["poeStatus"] = row["status"]
            info["poeWatt"] = row["watt"] if row["status"] == 3 else 0.0
            info["poeEstimated"] = row["estimated"]
    except Exception:
        pass

    say(T("스위치 '{name}' 에서 MAC {n}개를 읽었습니다.",
          "Read {n} MACs from switch '{name}'.").format(name=name, n=len(ports)))
    powered = [i for i in ports.values() if i.get("poeStatus") == 3]
    if powered:
        watt = sum(i.get("poeWatt") or 0 for i in powered)
        say(T("PoE — {n}개 포트에 전원을 주고 있습니다 (약 {w:.0f}W).",
              "PoE — powering {n} ports (about {w:.0f}W).")
            .format(n=len(powered), w=poe_main.get("used") or watt))
    if probe_line:
        say(probe_line)
        say(T("MAC 표가 비어 있습니다. 위 줄에서 dot1q·dot1d 가 전부 0 이면 이 스위치는 "
              "MAC 표를 SNMP 로 내주지 않는 것이라 고칠 수 없습니다.",
              "The MAC table is empty. If every dot1q/dot1d count above is 0, this switch "
              "does not expose its MAC table over SNMP and there is nothing to fix."))
    return {"name": name, "ip": ip, "ports": ports, "count": len(ports),
            "top": top, "poe": poe_main}


# ---------------------------------------------------------------------------
# PoE — viewing port power and cycling it
#
# One of the most common jobs on site is "unplug the dead camera and plug it back in".
# If it is on PoE, the switch is the one supplying that power, so telling the switch to
# cycle it saves climbing the ladder.
#
# It is a dangerous operation, so there are three rules.
#   1. No off-only function. It is always one action: off, then back on.
#   2. Whatever happens in between, it comes back on at the end (finally).
#   3. Read back to confirm it went off. If it did not, there is no write access — stop right there.
# Which ports must not be touched (my own PC, the uplink) is the caller's job to block.
# ---------------------------------------------------------------------------


def _snmp_set_int(ip, community, oid, value, timeout=1.5):
    """Write one integer. Hands back whatever value the switch returned."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        varbind = _tlv(0x30, _ber_oid(oid) + _ber_int(value))
        request_id = random.randint(1, 0x7FFFFFFF)
        pdu = _tlv(0xA3, _ber_int(request_id) + _ber_int(0) + _ber_int(0)
                   + _tlv(0x30, varbind))
        message = _tlv(0x30, _ber_int(1)
                       + _tlv(0x04, community.encode("utf-8")) + pdu)
        sock.settimeout(timeout)
        for _ in range(2):
            sock.sendto(message, (ip, SNMP_PORT))
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            _, body, _ = _read_tlv(data, 0)
            _, _, i = _read_tlv(body, 0)
            _, _, i = _read_tlv(body, i)
            _, pdu_body, _ = _read_tlv(body, i)
            _, rid, j = _read_tlv(pdu_body, 0)
            if _int_of(rid) != request_id:
                continue
            _, err, j = _read_tlv(pdu_body, j)
            _, _, j = _read_tlv(pdu_body, j)
            if _int_of(err):
                # 3 = badValue, 4 = readOnly, 6 = noAccess, 16/17 = not authorized
                raise RuntimeError(T("스위치가 쓰기를 거부했습니다 (오류 %d). "
                                     "읽기 전용 커뮤니티일 수 있습니다.",
                                     "The switch refused the write (error %d). "
                                     "The community may be read-only.")
                                   % _int_of(err))
            _, binds, _ = _read_tlv(pdu_body, j)
            _, bind, _ = _read_tlv(binds, 0)
            _, _, k = _read_tlv(bind, 0)
            _, got, _ = _read_tlv(bind, k)
            return _int_of(got)
        raise RuntimeError(T("스위치가 쓰기에 답하지 않습니다 (%s).",
                             "The switch is not answering the write (%s).") % ip)
    finally:
        sock.close()


def read_poe(ip, community="public", timeout=1.5):
    """Read PoE state per port. {port number: {...}} plus the switch's total draw."""
    def tail(oid, root):
        return oid[len(root) + 1:]

    ports = {}

    def slot(index):
        return ports.setdefault(index, {"admin": None, "status": 0, "class": 0,
                                        "watt": 0.0, "estimated": True})

    for oid, value in snmp_walk(ip, community, OID_POE_STATUS, timeout).items():
        slot(tail(oid, OID_POE_STATUS))["status"] = _int_of(value[1])
    for oid, value in snmp_walk(ip, community, OID_POE_ADMIN, timeout).items():
        slot(tail(oid, OID_POE_ADMIN))["admin"] = _int_of(value[1])
    for oid, value in snmp_walk(ip, community, OID_POE_CLASS, timeout).items():
        info = slot(tail(oid, OID_POE_CLASS))
        info["class"] = _int_of(value[1])
        info["watt"] = POE_CLASS_WATT.get(info["class"], 0.0)

    # Cisco serves real per-port draw in mW. Where present, it overrides the estimate.
    for oid, value in snmp_walk(ip, community, OID_POE_CISCO_W, timeout).items():
        index = tail(oid, OID_POE_CISCO_W)
        if index in ports:
            ports[index]["watt"] = round(_int_of(value[1]) / 1000.0, 1)
            ports[index]["estimated"] = False

    main = {"used": 0.0, "capacity": 0.0}
    for oid, value in snmp_walk(ip, community, OID_POE_MAIN_USE, timeout).items():
        main["used"] += _int_of(value[1])
    for oid, value in snmp_walk(ip, community, OID_POE_MAIN_CAP, timeout).items():
        main["capacity"] += _int_of(value[1])

    return {"ports": ports, "main": main}


def poe_index_for(port_no, poe_ports):
    """Find the PoE table index (group.port) matching the port number we know."""
    want = str(port_no)
    if want in poe_ports:                     # switches whose index is a single part
        return want
    for index in poe_ports:
        if index.rsplit(".", 1)[-1] == want:  # usually the group is prepended, like "1.12"
            return index
    return ""


def poe_restart(ip, community, poe_index, wait=6.0, timeout=1.5, log=None):
    """Cycle PoE on one port. Same as unplugging the camera's power and plugging it back in."""
    say = log or (lambda _m: None)
    admin_oid = "%s.%s" % (OID_POE_ADMIN, poe_index)

    # "Enabled" (admin) and "actually delivering power" (status 3) are not the same thing.
    # Cycling a port with nothing on it is pointless and means you picked the wrong one.
    if snmp_get(ip, community, "%s.%s" % (OID_POE_STATUS, poe_index), timeout) != 3:
        raise RuntimeError(T("이 포트는 지금 PoE 로 전원을 주고 있지 않습니다.",
                             "This port is not delivering PoE right now."))
    if snmp_get(ip, community, admin_oid, timeout) != 1:
        raise RuntimeError(T("이 포트의 PoE 가 이미 꺼져 있습니다.",
                             "PoE on this port is already switched off."))

    # From the moment it is sent, treat it as "might be off". Raise this flag only after
    # confirmation and a lost confirmation reply skips the restore — the camera stays off
    # and the screen says "could not switch off". The tech never thinks to go looking.
    turned_off = True
    restore_failed = False
    try:
        got = _snmp_set_int(ip, community, admin_oid, 2, timeout)
        # Read the written value back. Some devices answer and change nothing.
        if got != 2 or snmp_get(ip, community, admin_oid, timeout) != 2:
            raise RuntimeError(T("전원을 끄지 못했습니다. 쓰기 권한이 있는 "
                                 "커뮤니티인지 확인하십시오.",
                                 "Could not switch the power off. Check that the "
                                 "community has write access."))
        say(T("포트 %s 전원 끊음 — %.0f초 기다립니다.",
              "Port %s powered off — waiting %.0f seconds.") % (poe_index, wait))
        time.sleep(max(1.0, wait))
    finally:
        # Whatever happens, switch it back on. Fail here and somebody has to go there.
        if turned_off:
            for attempt in range(3):
                try:
                    _snmp_set_int(ip, community, admin_oid, 1, timeout)
                    if snmp_get(ip, community, admin_oid, timeout) == 1:
                        break
                except Exception:
                    pass
                time.sleep(1.0)
            else:
                # Getting here means somebody has to go there. Report success and the
                # tech only finds out the device is dead after waiting a minute.
                restore_failed = True

    if restore_failed:
        raise RuntimeError(
            T("포트 %s 전원을 다시 켜지 못했습니다. 스위치 화면에서 직접 켜야 합니다 "
              "— 그 포트에 물린 장비는 지금 꺼져 있습니다.",
              "Could not power port %s back on. Switch it on manually in the switch UI "
              "— whatever is on that port is powered down right now.") % poe_index)

    say(T("포트 %s 전원 다시 넣음. 장비가 올라오는 데 30초에서 1분쯤 걸립니다.",
          "Port %s powered back on. The device needs 30-60 seconds to boot.")
        % poe_index)
    return True


# ---------------------------------------------------------------------------
# Port management — see every physical port on the switch and lock the unused ones
#
# "Are the unused ports locked?" is a handover checklist item, because one patch cable
# into the rack lets anyone onto the network. Clicking each port off one at a time in
# the switch's web UI is what this does in one go.
#
# Locking is a different animal from a PoE cycle. A cycle comes back on its own after a
# few seconds; locking is meant to stay locked, so there is no automatic restore.
# Lock the port the management path runs through and SNMP itself stops reaching — that
# is a site visit. So which ports must not be locked is strictly the caller's job to block.
# ---------------------------------------------------------------------------


# Last-read total PoE power for the switch. {switch IP: {"used":..,"capacity":..}}
LAST_POE_MAIN = {}


def switch_name(ip, community="public", timeout=1.5):
    """The switch name (sysName). Falls back to the first line of the description, then the IP."""
    name = snmp_get(ip, community, OID_SYS_NAME, timeout)
    if name is None:
        descr = snmp_get(ip, community, OID_SYS_DESCR, timeout)
        name = descr.splitlines()[0][:40] if descr else ""
    return (name or "").strip() or ip


def _blank_port(index):
    """Defaults for one port row. What an unread field is left as gets decided here.

    duplex 0 means 'could not read'. 1 (unknown), 2 (half), 3 (full) are what the switch
    said; 0 is the switch saying nothing at all. Mix the two and every switch that does
    not serve EtherLike-MIB looks perfectly healthy.
    """
    return {"index": index, "name": "", "alias": "", "speed": 0,
            "admin": 0, "oper": 0, "poeIndex": "", "poeStatus": 0,
            "poeAdmin": 0, "poeWatt": 0.0, "poeClass": 0,
            "poeEstimated": True, "macs": [], "duplex": 0, "lateColl": None}


def read_switch_ports(ip, community="public", timeout=1.5):
    """Read every physical port on the switch. {ifIndex: {...}}."""
    def by_index(root):
        return {oid.rsplit(".", 1)[-1]: value
                for oid, value in snmp_walk(ip, community, root, timeout).items()}

    types = by_index(OID_IF_TYPE)
    ports = {}
    for index, value in types.items():
        if _int_of(value[1]) == IF_TYPE_ETHERNET:      # VLAN and loopback are excluded
            ports[index] = _blank_port(index)
    if not ports:                                      # some gear does not serve ifType
        for index in by_index(OID_IF_ADMIN):
            ports[index] = _blank_port(index)

    for root, field in ((OID_IF_ADMIN, "admin"), (OID_IF_OPER, "oper")):
        for index, value in by_index(root).items():
            if index in ports:
                ports[index][field] = _int_of(value[1])
    for root in (OID_IF_NAME, OID_IF_DESCR):
        for index, value in by_index(root).items():
            if index in ports and not ports[index]["name"] and value[0] == 0x04:
                ports[index]["name"] = value[1].decode("utf-8", "replace").strip()
    for index, value in by_index(OID_IF_ALIAS).items():
        if index in ports and value[0] == 0x04:
            ports[index]["alias"] = value[1].decode("utf-8", "replace").strip()
    for index, value in by_index(OID_IF_HIGH_SPEED).items():
        if index in ports:
            ports[index]["speed"] = _int_of(value[1])
    if not any(p["speed"] for p in ports.values()):
        for index, value in by_index(OID_IF_SPEED).items():
            if index in ports:
                ports[index]["speed"] = _int_of(value[1]) // 1000000

    # Duplex. dot3StatsIndex uses the same numbering as ifIndex.
    #
    # Plenty of switches do not serve this table at all. Then everything stays 0, and the
    # screen and the report never bring duplex up. That is so "could not check" never
    # gets written down as "nothing wrong".
    try:
        for index, value in by_index(OID_DUPLEX).items():
            if index in ports:
                ports[index]["duplex"] = _int_of(value[1])
    except Exception:
        pass

    # Late collisions. Only asked about on ports that settled at half duplex.
    #
    # Walking the whole table costs 48 extra round trips on a 48-port switch. Late
    # collisions on a port that is not half duplex are of no interest anyway, so ask
    # one at a time only for the ports that are. A number above 0 here is evidence, not
    # a guess — the duplex really is mismatched and frames are being corrupted right now.
    half = [i for i, p in ports.items() if p["duplex"] == DUPLEX_HALF]
    for index in half[:24]:
        try:
            got = snmp_get(ip, community, "%s.%s" % (OID_LATE_COLL, index), timeout)
        except Exception:
            got = None
        if isinstance(got, int) and not isinstance(got, bool):
            ports[index]["lateColl"] = got

    # Which MACs come in on each port. This is what tells uplinks (several MACs) and my own port apart.
    #
    # The numbers may not line up. If the switch does not serve dot1dBasePortIfIndex, the
    # MAC table's "bridge port number" and the ifIndex here can be different numbering
    # schemes. So match twice — once by number, once by port name.
    fdb = {}
    try:
        fdb = read_fdb(ip, community, timeout)
    except Exception:
        fdb = {}
    if fdb:
        by_name = {}
        for index, info in ports.items():
            if info.get("name"):
                by_name[info["name"]] = index
        names_seen = {}
        for oid_root in (OID_IF_NAME, OID_IF_DESCR):
            for k, v in snmp_walk(ip, community, oid_root, timeout).items():
                idx = k.rsplit(".", 1)[-1]
                if idx not in names_seen and v[0] == 0x04:
                    names_seen[idx] = v[1].decode("utf-8", "replace").strip()
            if names_seen:
                break
        for index, macs in fdb.items():
            # Do not trust a number just because it exists. If bridge port number and
            # ifIndex are different schemes that happen to collide, the uplink's MAC list
            # lands on the wrong port. Then the real uplink looks empty and becomes lockable.
            named = names_seen.get(index, "")
            target = ""
            if index in ports and (not named or ports[index].get("name") in ("", named)):
                target = index
            elif named and named in by_name:
                target = by_name[named]
            if target:
                ports[target]["macs"] = sorted(set(ports[target].get("macs") or []) | set(macs))

    try:
        poe = read_poe(ip, community, timeout)
        # Switch-wide supply/draw. If the report goes and reads this again, a switch with no
        # PoE MIB stalls the whole thing a second time. Keep what was read here.
        LAST_POE_MAIN[ip] = dict(poe.get("main") or {}, at=time.time())
        for index, info in ports.items():
            found = poe_index_for(index, poe["ports"])
            if found:
                info["poeIndex"] = found
                info["poeStatus"] = poe["ports"][found]["status"]
                info["poeWatt"] = poe["ports"][found]["watt"]
                info["poeAdmin"] = poe["ports"][found]["admin"] or 0
                # So the report can write "estimated 15.4W" and "measured 4.2W" differently.
                # When the customer asks about power, those two are completely different answers.
                info["poeClass"] = poe["ports"][found]["class"]
                info["poeEstimated"] = poe["ports"][found]["estimated"]
    except Exception:
        # Could not read it this time: do not leave last time's value sitting there. The
        # report would print the old number as the current draw. Clear it to 'unknown'.
        LAST_POE_MAIN.pop(ip, None)

    return ports


def set_poe_admin(ip, community, poe_index, on, timeout=1.5):
    """Switch PoE on or off and leave it there. Unlike a cycle (poe_restart), it stays."""
    oid = "%s.%s" % (OID_POE_ADMIN, poe_index)
    want = 1 if on else 2
    _snmp_set_int(ip, community, oid, want, timeout)
    if snmp_get(ip, community, oid, timeout) != want:
        raise RuntimeError(T("PoE 상태가 바뀌지 않았습니다. 쓰기 권한이 있는 "
                             "커뮤니티인지 확인하십시오.",
                             "The PoE state did not change. Check that the "
                             "community has write access."))
    return True


def set_port_admin(ip, community, ifindex, up, timeout=1.5):
    """Lock (up=False) or unlock (up=True) a port. Reads the written value back to confirm."""
    oid = "%s.%s" % (OID_IF_ADMIN, ifindex)
    want = 1 if up else 2
    _snmp_set_int(ip, community, oid, want, timeout)
    got = snmp_get(ip, community, oid, timeout)
    if got == want:
        return True
    # This is the fork. No answer at all (None) may mean the lock took and cut our own
    # path. Say "it did not change" and the tech clicks again and keeps working, never
    # realising the link is already gone — the worst accident buried under the quietest wording.
    if got is None and not up:
        raise RuntimeError(
            T("포트 %s 를 잠근 뒤 스위치가 답하지 않습니다. 잠금이 먹혀서 관리 "
              "경로가 끊겼을 수 있습니다 — 다시 누르지 마시고 스위치 화면으로 "
              "확인하십시오.",
              "The switch stopped answering after locking port %s. The lock may have "
              "taken and cut the management path — do not retry; check the switch UI.")
            % ifindex)
    raise RuntimeError(T("포트 상태가 바뀌지 않았습니다. 쓰기 권한이 있는 "
                         "커뮤니티인지 확인하십시오.",
                         "The port state did not change. Check that the "
                         "community has write access."))


def read_port_link(ip, community, ifindex, timeout=1.5):
    """Cheaply read just the current state of one port. Used while waiting for a link to come up.

    Unlocking a port does not bring traffic back straight away. The two ends take 2~3s to
    settle on a speed again (autonegotiation), and then, while the switch checks for a loop
    (STP), the port passes no data even with the link up — 30 seconds on default settings.
    If the screen says "unlocked" and stops there in the meantime, the tech starts poking
    a perfectly good port because the camera has not come back.
    """
    # Leave unread values as None, never 0 — ifOperStatus has no 0, so the UI reads it as
    # "no link", that port becomes an "unused port", and "lock every unused port" takes it.
    # That is how a port with a camera on it gets locked.
    out = {"admin": None, "oper": None, "speed": None, "duplex": None,
           "read": False}
    for field, root in (("admin", OID_IF_ADMIN), ("oper", OID_IF_OPER),
                        ("speed", OID_IF_HIGH_SPEED), ("duplex", OID_DUPLEX)):
        try:
            got = snmp_get(ip, community, "%s.%s" % (root, ifindex), timeout)
        except Exception:
            got = None
        if isinstance(got, int) and not isinstance(got, bool):
            out[field] = got
    if out["speed"] is None:                 # older gear only serves ifSpeed (bps)
        try:
            slow = snmp_get(ip, community, "%s.%s" % (OID_IF_SPEED, ifindex), timeout)
        except Exception:
            slow = None
        if isinstance(slow, int):
            out["speed"] = slow // 1000000
    out["read"] = out["oper"] is not None
    return out


def read_own_macs(ip, community="public", timeout=1.5):
    """The switch's own MACs. A port where these show up is the management path — hands off."""
    out = set()
    for _, value in snmp_walk(ip, community, OID_IF_PHYS, timeout).items():
        if value[0] == 0x04 and len(value[1]) == 6:
            out.add("".join("%02x" % b for b in value[1]))
    out.discard("000000000000")
    return out


def read_fdb(ip, community="public", timeout=1.5):
    """Read just the switch's MAC table. {ifIndex string: [mac, ...]}.

    For the port management screen to work out "may I lock this port" on its own, it has
    to look at what the switch knows, not at our device list — it has to recognise the
    uplink and my own port even when no scan has been run.
    """
    base = {k.rsplit(".", 1)[-1]: _int_of(v[1])
            for k, v in snmp_walk(ip, community, OID_BASE_PORT_IF, timeout).items()}
    out = {}

    def put(mac, bridge_port):
        if not mac or not bridge_port:
            return
        index = str(base.get(str(bridge_port), bridge_port))
        out.setdefault(index, [])
        if mac not in out[index]:
            out[index].append(mac)

    table = snmp_walk(ip, community, OID_Q_FDB_PORT, timeout)
    for oid, value in table.items():
        bits = [b for b in oid[len(OID_Q_FDB_PORT) + 1:].split(".") if b != ""]
        if len(bits) < 7:
            continue
        put(_mac_from_oid_tail(".".join(bits[-6:])), _int_of(value[1]))
    if not out:
        for oid, value in snmp_walk(ip, community, OID_FDB_PORT, timeout).items():
            put(_mac_from_oid_tail(oid[len(OID_FDB_PORT) + 1:]), _int_of(value[1]))
    return out


def common_speed(speeds):
    """This switch's 'native' speed. The most frequent value; on a tie, the faster one.

    Two reasons the top speed must not be the reference.
      - One 10G SFP uplink flags every healthy 1G port as slow.
      - On plenty of CCTV sites the cameras are 100M by design. On such a switch 100M is
        normal and must not raise a warning.
    The speed most of them sit at is that site's baseline.
    """
    counts = {}
    for value in speeds:
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return 0
    return max(counts, key=lambda v: (counts[v], v))


# Interface names, fastest first. "TenGigabitEthernet" also contains "Gigabit", so a
# slower pattern tried first would file a 10G port as 1G. The name must be preceded by a
# non-letter, or "Gate 1" reads as a 10G port on the "te" in the middle of it.
PORT_NAME_SPEED = (
    (re.compile(r"(?:^|[^a-z])(?:hu|hundredgig)", re.I), 100000),
    (re.compile(r"(?:^|[^a-z])(?:fo|fortygig)", re.I), 40000),
    (re.compile(r"(?:^|[^a-z])(?:twe|twentyfivegig)", re.I), 25000),
    (re.compile(r"(?:^|[^a-z])(?:te|xe|tengig)", re.I), 10000),
    (re.compile(r"(?:^|[^a-z])(?:gi|ge|gigabit)", re.I), 1000),
    (re.compile(r"(?:^|[^a-z])(?:fa|fe|fastethernet)", re.I), 100),
)


def port_capable_speed(name):
    """The speed the switch's own name for a port claims it can carry. 0 if it says nothing.

    A switch calling a port GigabitEthernet6 has told us it is a gigabit port, and that
    beats asking the neighbours. Asking the neighbours is exactly backwards in the case
    that matters most: one installer terminating a whole rack badly in one afternoon makes
    the broken ports the majority, and a majority then declares itself normal.

    Names carrying no speed ("Port 3", "eth1", a bare "Ethernet1/1") return 0, and the
    caller falls back to what the rest of the switch is doing.
    """
    text = (name or "").strip()
    if not text:
        return 0
    for pattern, mbps in PORT_NAME_SPEED:
        if pattern.search(text):
            return mbps
    return 0


def mark_slow_ports(infos):
    """The one place that decides whether a port is running below what it should.

    Both screens used to answer this separately and disagreed three ways: the log counted
    one vote per MAC (an uplink carrying thirty MACs voted thirty times) while the
    faceplate counted one per port; ties went to the faster speed in one and the slower in
    the other; and only the faceplate had a rule that gave up entirely once more than a
    third of the ports were slow — so the more ports were broken, the quieter it got.

    Reference, in order:
      1. the port's own name (see port_capable_speed)
      2. failing that, the speed most of this switch's ports run at

    Sets on each row:
      slow    - linked at or under a quarter of the reference
      slowRef - the reference used, so the screen can say what it was measured against

    Takes rows from either shape: the per-port table (name/index) or the MAC table
    (port/ifIndex), which holds one entry per MAC and so has to be deduplicated first.
    """
    rows = list(infos)
    seen, uniq = set(), []
    for row in rows:
        key = str(row.get("ifIndex") or row.get("index")
                  or row.get("portNo") or row.get("name") or row.get("port") or id(row))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(row)
    peers = common_speed([int(r.get("speed") or 0) for r in uniq])
    for info in rows:
        speed = int(info.get("speed") or 0)
        reference = port_capable_speed(info.get("name") or info.get("port")) or peers
        info["slowRef"] = reference
        info["slow"] = bool(reference >= 1000 and 0 < speed <= reference // 4)
    return [r for r in rows if r.get("slow")]


def apply_port_map(result):
    """Attach the table just read to the current list. Returns (devices matched, slow ports).

    One thing to watch on a site with several switches. A camera hanging off the 3rd-floor
    switch also shows up in the 1st-floor switch's MAC table — it arrives over the uplink.
    So a switch queried later overwrites the real position found earlier with an uplink port.

    One MAC visible on a port means that is where the device is actually plugged in. Several
    means it is an uplink with another switch below it. So if the position already recorded
    is the more 'alone' one, leave it be.
    """
    crowd = {}
    for info in result["ports"].values():
        crowd[info["portNo"]] = crowd.get(info["portNo"], 0) + 1

    hit, slow = 0, []
    with STORE.lock:
        for dev in STORE.devices.values():
            info = result["ports"].get(hex_mac(dev["mac"]))
            if not info:
                continue
            shared = crowd.get(info["portNo"], 1)
            # Re-reading the same switch: the new value is always right (the device may
            # have moved). Only for a different switch, keep the known position if it is
            # narrower. Switches are told apart by IP — sysName collides at factory defaults.
            same_switch = dev.get("swhost") == result.get("ip", "")
            if dev.get("swport") and not same_switch:
                if (dev.get("swshared") or 1) <= shared:
                    continue          # we already know a narrower position
            dev["swshared"] = shared
            dev["swport"] = info["port"]
            dev["swname"] = result["name"]
            # At factory defaults two switches share the same name (sysName). Remember the IP too.
            dev["swhost"] = result.get("ip", "")
            dev["swvlan"] = info.get("vlan")
            dev["swspeed"] = info.get("speed") or 0
            dev["swalias"] = info.get("alias", "")
            dev["swslow"] = info.get("slow", False)
            dev["swduplex"] = info.get("duplex") or 0
            dev["poeIndex"] = info.get("poeIndex", "")
            dev["poeStatus"] = info.get("poeStatus", 0)
            dev["poeWatt"] = info.get("poeWatt", 0.0)
            if info.get("slow"):
                slow.append({"ip": dev["ip"], "port": info["port"],
                             "speed": info.get("speed") or 0,
                             "ref": info.get("slowRef") or 0})
            hit += 1
    slow.sort(key=lambda row: row["ip"])
    return hit, slow


# ---------------------------------------------------------------------------
# Free IPs
#
# Once the subnet is swept, the "IPs in use" are in the list. What is left is free.
# What goes where is a person's call — the tool only reports which addresses stayed silent.
# ---------------------------------------------------------------------------

def free_ips():
    with STORE.lock:
        used = {d["ip"] for d in STORE.devices.values()}
        scanned = list(STORE.scanned)
        done = bool(getattr(STORE, "scan_done", False))
    free = [ip for ip in scanned if ip not in used]

    def as_int(ip):
        try:
            return int(ipaddress.IPv4Address(ip))
        except Exception:
            return 0

    free.sort(key=as_int)
    # Show consecutive addresses as one range. One line of "13-72" beats 200 lines.
    blocks = []
    for ip in free:
        n = as_int(ip)
        if blocks and n == blocks[-1]["end_n"] + 1:
            blocks[-1]["end"], blocks[-1]["end_n"] = ip, n
            blocks[-1]["count"] += 1
        else:
            blocks.append({"start": ip, "end": ip, "start_n": n, "end_n": n,
                           "count": 1})
    for block in blocks:
        block.pop("start_n"), block.pop("end_n")
    # complete False means this list must not be used for assignment. Pass it along
    # so the screen and the CSV say so.
    return {"scanned": len(scanned), "used": len(used), "free": free,
            "blocks": blocks, "complete": done}


def export_candidate_ips(path):
    """Write candidate IPs one per row so the assignment plan can be filled in directly in Excel.

    If the scan did not run to the end, say so at the top of the file. This CSV gets used
    on site as the assignment sheet as-is — if the file alone does not say where the list
    came from, nobody remembers a few days later.
    """
    info = free_ips()
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        if not info.get("complete"):
            writer.writerow([T("경고 — 스캔이 끝까지 가지 않았습니다. 이 목록을 "
                               "배정에 쓰지 마십시오. 다시 스캔한 뒤 뽑으십시오.",
                               "WARNING — the scan did not finish. Do not assign from "
                               "this list; re-scan and export again.")])
            writer.writerow([])
        writer.writerow([T("후보 IP", "Candidate IP"), T("배정 대상", "Assign to"),
                         T("위치 / 메모", "Location / note"), T("확인 상태", "Checked")])
        for ip in info["free"]:
            writer.writerow([ip, "", "", T("미확인", "unchecked")])
    return len(info["free"])


def export_html(path, site="", note=""):
    """A one-page site report. Open it in a browser and print it, or save it as PDF.

    What you need on site is not a data dump, it is one page saying "what conflicted and
    what got touched". So conflicts go at the top and the free IPs get tacked on the end.
    """
    groups = STORE.by_ip()
    conflicts = [g for g in groups if g["conflict"]]
    devices = sum(g["count"] for g in groups)
    empty = free_ips()
    esc = lambda value: html.escape("" if value is None else str(value))
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    def cell(value, fallback="-"):
        text = esc(value) if value not in (None, "", []) else fallback
        return text

    def rows_of(group_list):
        out = []
        for g in group_list:
            for n, d in enumerate(g["devices"]):
                names = [x for x in (d.get("host"), d.get("mdns"), d.get("nbname"),
                                     d.get("ssdp")) if x]
                seen = []
                for x in names:
                    if x.lower() not in [y.lower() for y in seen]:
                        seen.append(x)
                facts = []
                if d.get("ms") is not None:
                    facts.append("%s ms" % d["ms"])
                if d.get("os"):
                    facts.append(kind_show(d["os"]))   # the TTL number is already folded into OS
                # If a name got pulled into the model column, do not repeat it below
                shown_model = d.get("model") or (seen[0] if seen else "")
                rest = [x for x in seen if x != shown_model]
                sub = " · ".join(rest[:2] + facts)
                out.append(
                    "<tr class='%s'>"
                    "<td class='ip'>%s</td>"
                    "<td><code>%s</code></td>"
                    "<td>%s</td><td>%s</td>"
                    "<td>%s%s</td>"
                    "<td>%s</td><td>%s</td></tr>" % (
                        "conf" if g["conflict"] else "",
                        esc(g["ip"]) if n == 0 else "",
                        esc(dash_mac(d["mac"])),
                        cell(d.get("vendor")),
                        cell(kind_show(d.get("kind")), T("미확인", "unidentified")),
                        cell(shown_model),
                        "<i>%s</i>" % esc(sub) if sub else "",
                        ", ".join(str(p) for p in (d.get("ports") or [])) or "-",
                        cell(d.get("swport"))))
        return "\n".join(out)

    head = (T("기존 IP", "Current IP"), "MAC", T("제조사", "Vendor"),
            T("장비 종류", "Device type"), T("모델 · 이름", "Model · name"),
            T("열린 포트", "Open ports"), T("스위치 포트", "Switch port"))
    thead = "<tr>%s</tr>" % "".join("<th>%s</th>" % h for h in head)

    parts = ["""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>%s — %s</title><style>
*{box-sizing:border-box}
body{font-family:'Malgun Gothic','Apple SD Gothic Neo',sans-serif;margin:0;
     padding:36px 40px 60px;color:#16181d;background:#fff;line-height:1.5}
h1{font-size:21px;margin:0 0 2px;letter-spacing:-.3px}
h2{font-size:14px;margin:30px 0 8px;padding-bottom:6px;border-bottom:1px solid #e5e7eb;
   color:#374151;letter-spacing:-.2px}
.meta{color:#6b7280;font-size:12.5px}
.cards{display:flex;gap:10px;margin:20px 0 4px;flex-wrap:wrap}
.card{border:1px solid #e5e7eb;border-radius:8px;padding:10px 14px;min-width:104px}
.card span{display:block;font-size:11.5px;color:#6b7280}
.card strong{font-size:19px;font-weight:600}
.card.red strong{color:#dc2626}.card.amber strong{color:#b45309}
table{border-collapse:collapse;width:100%%;font-size:12.5px}
th,td{border-bottom:1px solid #eceef1;padding:7px 9px;text-align:left;vertical-align:top}
th{background:#f7f8fa;font-weight:600;color:#4b5563;border-bottom:1px solid #e5e7eb;
   white-space:nowrap}
td.ip{font-weight:600;white-space:nowrap}
tr.conf td.ip{color:#b45309}
tr.conf td:first-child{border-left:3px solid #f59e0b}
code{font-family:Consolas,monospace;font-size:12px;color:#374151}
td i{display:block;font-style:normal;color:#8b93a1;font-size:11.5px;margin-top:2px}
.free{display:flex;flex-wrap:wrap;gap:6px;font-size:12.5px}
.free b{font-weight:600;border:1px solid #e5e7eb;border-radius:6px;padding:3px 9px;
        background:#fafbfc}
.none{color:#9ca3af;font-size:12.5px}
footer{margin-top:34px;padding-top:12px;border-top:1px solid #eceef1;
       color:#9ca3af;font-size:11.5px}
@media print{body{padding:0}h2{page-break-after:avoid}tr{page-break-inside:avoid}}
</style></head><body>""" % (esc(T("현장 리포트", "Site report")),
                             esc(site or STORE.cidr or "IP"))]

    parts.append("<h1>%s%s</h1>" % (esc(T("현장 리포트", "Site report")),
                                    " — " + esc(site) if site else ""))
    parts.append('<div class="meta">%s &nbsp;·&nbsp; %s %s &nbsp;·&nbsp; %s</div>'
                 % (stamp, esc(T("대역", "Range")), esc(STORE.cidr or "-"),
                    esc(STORE.iface or "-")))
    if note:
        parts.append('<div class="meta">%s</div>' % esc(note))

    parts.append('<div class="cards">'
                 + '<div class="card"><span>%s</span><strong>%d</strong></div>'
                   % (esc(T("사용 중인 IP", "IPs in use")), len(groups))
                 + '<div class="card red"><span>%s</span><strong>%d</strong></div>'
                   % (esc(T("충돌난 IP", "Conflicting IPs")), len(conflicts))
                 + '<div class="card"><span>%s</span><strong>%d</strong></div>'
                   % (esc(T("발견 장비", "Devices found")), devices)
                 + '<div class="card amber"><span>%s</span><strong>%d</strong></div>'
                   % (esc(T("충돌 장비", "Devices in conflict")), sum(g["count"] for g in conflicts))
                 + '<div class="card"><span>%s</span><strong>%d</strong></div>'
                   % (esc(T("응답 없는 IP", "No reply")), len(empty["free"]))
                 + "</div>")

    parts.append("<h2>%s</h2>" % esc(T("충돌", "Conflicts")))
    if conflicts:
        parts.append("<table>%s%s</table>" % (thead, rows_of(conflicts)))
    else:
        parts.append('<p class="none">%s</p>'
                     % esc(T("충돌한 IP가 없습니다.", "No IP conflicts.")))

    parts.append("<h2>%s</h2>" % esc(T("발견한 장비 전체 (%d대)",
                                          "All devices found (%d)") % devices))
    parts.append("<table>%s%s</table>" % (thead, rows_of(groups))
                 if groups else '<p class="none">%s</p>'
                 % esc(T("발견된 장비가 없습니다.", "No devices found.")))

    # The actual assignment plan for candidate IPs lives in a separate CSV, not the HTML report.
    # The CSV takes a purpose and a note per IP row, which works well opened in Excel.

    parts.append("<footer>%s v%s &nbsp;·&nbsp; %s</footer>"
                 % (esc(APP_NAME), esc(APP_VER),
                    esc(T("훑은 주소 %d개", "%d addresses scanned") % empty["scanned"])))
    parts.append("</body></html>")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))
    return path


# ---------------------------------------------------------------------------
# Handover / inspection report (Excel)
# ---------------------------------------------------------------------------
# No openpyxl. Using it means whoever builds has to pip install one more thing, and
# forgetting that while cutting the exe kills just the report button out on site. An xlsx
# is a few XML sheets in a zip, so write only what is needed. Same reason SNMP is hand-rolled.

# The control characters XML 1.0 forbids. A NUL riding in on a switch description (ifAlias),
# or a vertical tab in a comment pasted from Word, and the whole file will not open. You get
# to see "the file is corrupted" in front of the customer, with no way to fix it then.
_XL_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_XL_CELL_MAX = 32000        # Excel's per-cell limit is 32767 characters


def _xl_text(value):
    """Trim it down to characters that are safe to put in an Excel cell."""
    text = _XL_BAD.sub("", str(value))
    if len(text) > _XL_CELL_MAX:
        text = text[:_XL_CELL_MAX - 1] + "…"
    return text


def _xl_col(n):
    """0 -> A, 25 -> Z, 26 -> AA"""
    out, n = "", n + 1
    while n:
        n, rest = divmod(n - 1, 26)
        out = chr(65 + rest) + out
    return out


_XL_FONTS = [
    {},                                     # 0 normal
    {"b": 1},                               # 1 bold
    {"b": 1, "sz": 16},                     # 2 title
    {"sz": 10, "color": "6B7280"},          # 3 muted caption
    {"b": 1, "color": "FFFFFF"},            # 4 table header
    {"b": 1, "color": "B42318"},            # 5 bold red
    {"sz": 9, "color": "98A2B3"},           # 6 footnote
    {"b": 1, "sz": 12},                     # 7 subheading
    {"sz": 9},                              # 8 small text
]
_XL_FILLS = [None, None,                    # 0 and 1 are slots Excel reserves
             "44546A", "FEF0C7", "FEE4E2", "E7F1FB", "F2F4F7", "D1FADF"]
# name -> (font, fill, border, horizontal, wrap, vertical)
_XL_XF = [
    ("",       0, 0, 0, "",       0, ""),
    ("title",  2, 0, 0, "",       0, ""),
    ("sub",    3, 0, 0, "",       0, ""),
    ("sect",   7, 0, 2, "",       0, ""),
    ("small",  6, 0, 0, "",       0, ""),
    ("h",      4, 2, 1, "center", 0, "center"),
    ("hl",     4, 2, 1, "left",   0, "center"),
    ("c",      0, 0, 1, "",       0, "top"),
    ("cb",     1, 0, 1, "",       0, "top"),
    ("cc",     0, 0, 1, "center", 0, "center"),
    ("cn",     0, 0, 1, "right",  0, "top"),
    ("cs",     8, 0, 1, "",       0, "top"),
    ("warn",   0, 3, 1, "",       0, "top"),
    ("bad",    5, 4, 1, "",       0, "top"),
    ("good",   0, 7, 1, "",       0, "top"),
    ("note",   0, 0, 1, "",       1, "top"),
    ("big",    1, 0, 1, "center", 0, "center"),
    ("pIdle",  8, 0, 1, "center", 0, "center"),
    ("pLive",  1, 5, 1, "center", 0, "center"),
    ("pSlow",  5, 4, 1, "center", 0, "center"),
    ("pPoe",   1, 3, 1, "center", 0, "center"),
    ("pDown",  8, 6, 1, "center", 0, "center"),
]
_XL_STYLE = {name: i for i, (name, _f, _l, _b, _h, _w, _v) in enumerate(_XL_XF)}


def _xl_styles():
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
           '<fonts count="%d">' % len(_XL_FONTS)]
    for font in _XL_FONTS:
        bits = []
        if font.get("b"):
            bits.append("<b/>")
        bits.append('<sz val="%s"/>' % font.get("sz", 11))
        if font.get("color"):
            bits.append('<color rgb="FF%s"/>' % font["color"])
        bits.append('<name val="맑은 고딕"/>')
        out.append("<font>%s</font>" % "".join(bits))
    out.append('</fonts><fills count="%d">' % len(_XL_FILLS))
    out.append('<fill><patternFill patternType="none"/></fill>')
    out.append('<fill><patternFill patternType="gray125"/></fill>')
    for color in _XL_FILLS[2:]:
        out.append('<fill><patternFill patternType="solid"><fgColor rgb="FF%s"/>'
                   '<bgColor indexed="64"/></patternFill></fill>' % color)
    out.append('</fills><borders count="3">')
    out.append("<border><left/><right/><top/><bottom/><diagonal/></border>")
    out.append("<border>%s<diagonal/></border>" % "".join(
        '<%s style="thin"><color rgb="FFD0D5DD"/></%s>' % (side, side)
        for side in ("left", "right", "top", "bottom")))
    out.append('<border><left/><right/><top/><bottom style="medium">'
               '<color rgb="FF98A2B3"/></bottom><diagonal/></border>')
    out.append('</borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" '
               'fillId="0" borderId="0"/></cellStyleXfs>')
    out.append('<cellXfs count="%d">' % len(_XL_XF))
    for _name, font, fill, border, halign, wrap, valign in _XL_XF:
        head = ('numFmtId="0" fontId="%d" fillId="%d" borderId="%d" applyFont="1" '
                'applyFill="1" applyBorder="1"' % (font, fill, border))
        bits = []
        if halign:
            bits.append('horizontal="%s"' % halign)
        if valign:
            bits.append('vertical="%s"' % valign)
        if wrap:
            bits.append('wrapText="1"')
        out.append('<xf %s applyAlignment="1"><alignment %s/></xf>' % (head, " ".join(bits))
                   if bits else "<xf %s/>" % head)
    out.append('</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" '
               'builtinId="0"/></cellStyles></styleSheet>')
    return "".join(out)


class XlSheet(object):
    """One Excel sheet. A cell is either a value or (value, style name)."""

    def __init__(self, name):
        clean = _xl_text(name)[:31]
        for bad in "[]:*?/\\":
            clean = clean.replace(bad, " ")
        self.name = clean.strip().strip("'") or "Sheet"
        self.rows = []
        self.widths = {}
        self.heights = {}
        self.merges = []
        self.freeze = ""
        self.filter = ""

    def row(self, *cells):
        self.rows.append(list(cells))
        return len(self.rows)          # 1-based, same as Excel's row numbers.

    def blank(self, count=1):
        for _ in range(count):
            self.rows.append([])
        return len(self.rows)

    def width(self, *pairs):
        for col, value in pairs:
            self.widths[col] = value

    def merge(self, row1, col1, row2, col2):
        self.merges.append("%s%d:%s%d" % (_xl_col(col1), row1, _xl_col(col2), row2))

    def xml(self):
        out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/'
               '2006/main"><sheetViews><sheetView showGridLines="0" workbookViewId="0">']
        if self.freeze:
            top = int(self.freeze[1:])
            out.append('<pane ySplit="%d" topLeftCell="%s" activePane="bottomLeft" '
                       'state="frozen"/><selection pane="bottomLeft"/>'
                       % (top - 1, self.freeze))
        out.append('</sheetView></sheetViews><sheetFormatPr defaultRowHeight="16.5"/>')
        if self.widths:
            out.append("<cols>")
            for col in sorted(self.widths):
                out.append('<col min="%d" max="%d" width="%s" customWidth="1"/>'
                           % (col + 1, col + 1, self.widths[col]))
            out.append("</cols>")
        out.append("<sheetData>")
        for number, cells in enumerate(self.rows, 1):
            height = self.heights.get(number)
            out.append('<row r="%d"%s>' % (
                number, ' ht="%s" customHeight="1"' % height if height else ""))
            for col, cell in enumerate(cells):
                if cell is None:
                    continue
                value, style = cell if isinstance(cell, tuple) else (cell, "")
                sid = _XL_STYLE.get(style, 0)
                ref = "%s%d" % (_xl_col(col), number)
                if value is None or value == "":
                    if sid:
                        out.append('<c r="%s" s="%d"/>' % (ref, sid))
                    continue
                if isinstance(value, bool):
                    value = str(value)
                if isinstance(value, (int, float)):
                    out.append('<c r="%s" s="%d"><v>%s</v></c>' % (ref, sid, value))
                else:
                    out.append('<c r="%s" s="%d" t="inlineStr"><is>'
                               '<t xml:space="preserve">%s</t></is></c>'
                               % (ref, sid,
                                  html.escape(_xl_text(value), quote=True)))
            out.append("</row>")
        out.append("</sheetData>")
        if self.filter:
            out.append('<autoFilter ref="%s"/>' % self.filter)
        if self.merges:
            out.append('<mergeCells count="%d">%s</mergeCells>' % (
                len(self.merges),
                "".join('<mergeCell ref="%s"/>' % m for m in self.merges)))
        out.append('<pageMargins left="0.4" right="0.4" top="0.6" bottom="0.6"'
                   ' header="0.3" footer="0.3"/></worksheet>')
        return "".join(out)


def write_xlsx(path, sheets):
    """Bundle a list of sheets into one xlsx file."""
    if not sheets:
        raise ValueError(T("내보낼 내용이 없습니다.", "Nothing to export."))
    names, used = [], set()
    for sheet in sheets:                       # duplicate sheet names and Excel will not open it
        name, count = sheet.name, 2
        while name.lower() in used:
            name = "%s(%d)" % (sheet.name[:27], count)
            count += 1
        used.add(name.lower())
        names.append(name)

    esc = lambda value: html.escape(str(value), quote=True)
    rels = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        types = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types '
                 'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                 '<Default Extension="rels" ContentType="application/vnd.'
                 'openxmlformats-package.relationships+xml"/><Default Extension="xml" '
                 'ContentType="application/xml"/><Override PartName="/xl/workbook.xml" '
                 'ContentType="application/vnd.openxmlformats-officedocument.'
                 'spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" '
                 'ContentType="application/vnd.openxmlformats-officedocument.'
                 'spreadsheetml.styles+xml"/>']
        for i in range(len(sheets)):
            types.append('<Override PartName="/xl/worksheets/sheet%d.xml" '
                         'ContentType="application/vnd.openxmlformats-officedocument.'
                         'spreadsheetml.worksheet+xml"/>' % (i + 1))
        z.writestr("[Content_Types].xml", "".join(types) + "</Types>")
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
                   '2006/relationships"><Relationship Id="rId1" Type="%s/officeDocument"'
                   ' Target="xl/workbook.xml"/></Relationships>' % rels)
        book = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook '
                'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="%s"><sheets>' % rels]
        link = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships '
                'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
        for i, name in enumerate(names, 1):
            book.append('<sheet name="%s" sheetId="%d" r:id="rId%d"/>'
                        % (esc(_xl_text(name)), i, i))
            link.append('<Relationship Id="rId%d" Type="%s/worksheet" '
                        'Target="worksheets/sheet%d.xml"/>' % (i, rels, i))
        link.append('<Relationship Id="rId900" Type="%s/styles" Target="styles.xml"/>'
                    "</Relationships>" % rels)
        z.writestr("xl/workbook.xml", "".join(book) + "</sheets></workbook>")
        z.writestr("xl/_rels/workbook.xml.rels", "".join(link))
        z.writestr("xl/styles.xml", _xl_styles())
        for i, sheet in enumerate(sheets, 1):
            z.writestr("xl/worksheets/sheet%d.xml" % i, sheet.xml())
    return path


def duplex_label(value):
    """Duplex in plain words. Empty string if it could not be read — say nothing at all.

    There is a temptation here to fill 0 in as 'full'. Modern gear is mostly full duplex,
    so the odds are good. Still no. What this tool says goes straight into the handover
    document. Put a likely guess and a confirmed fact in the same column and the next
    genuinely confirmed value becomes untrustworthy along with it.
    """
    got = int(value or 0)
    if got == DUPLEX_HALF:
        return T("반이중", "half")
    if got == DUPLEX_FULL:
        return T("전이중", "full")
    if got == DUPLEX_UNKNOWN:
        return T("모름", "unknown")
    return ""


def is_half_duplex(info):
    """Is this a port with a live link that settled at half duplex?

    Duplex on a port with no link means nothing. Put a warning on a port with nothing
    plugged into it and every empty port goes red.
    """
    return (int(info.get("duplex") or 0) == DUPLEX_HALF
            and int(info.get("oper") or 0) == 1)


def speed_label(mbps):
    """Port speed in plain words. 0 means there is no link."""
    value = int(mbps or 0)
    if value <= 0:
        return "-"
    if value >= 1000 and value % 1000 == 0:
        return "%dG" % (value // 1000)
    return "%dM" % value


def _plate_layout(ports, slow_keys):
    """A picture of the switch front. Odd on the top row, even on the bottom — the real layout.

    Gear whose numbering is not clean (no number can be pulled out of the name) just gets
    laid out across two rows in order. A simple picture beats a wrong one.
    """
    listed = sorted(ports.values(), key=port_number)
    numbers = [port_number(p) for p in listed]
    # Place by number, but if the numbers are absurdly large (VLAN/loopback mixed in, or
    # ifIndex in the millions) drawing blanks across that range blows the document up.
    tidy = (bool(numbers) and len(set(numbers)) == len(numbers)
            and min(numbers) >= 1 and max(numbers) <= len(numbers) * 2 + 8)

    slots = {}                      # (top row 0 / bottom row 1, column) -> port
    if tidy:
        for info in listed:
            no = port_number(info)
            slots[((no + 1) % 2, (no + 1) // 2 - 1)] = info
    else:
        for i, info in enumerate(listed):
            slots[(i % 2, i // 2)] = info

    columns = max([c for _r, c in slots] or [0]) + 1
    return slots, columns


def _plate_cell(info, slow_keys):
    """The text and colour of one port cell."""
    no = port_number(info)
    text = str(no) if no else (info.get("name") or "")[-4:]
    if int(info.get("admin") or 1) != 1:
        return ("%s ✕" % text, "pDown")          # a port somebody locked
    if int(info.get("oper") or 0) != 1:
        return (text, "pIdle")                   # nothing plugged in — outline only
    if is_half_duplex(info):
        # Ranked ahead of the speed drop. When both show, this is usually the cause.
        return ("%s½" % text, "pSlow")       # half duplex — the two ends do not agree
    if port_key(info) in slow_keys:
        return (text, "pSlow")                   # slower than it used to be
    if float(info.get("poeWatt") or 0) > 0:
        return (text, "pPoe")
    return (text, "pLive")


def export_xlsx(path, site="", note="", author="", switches=None, missed=None):
    """One handover/inspection report. Five sheets.

    People type this into Excel by hand on site. One scan has all of it already.
    """
    switches = switches or []
    missed = missed or []          # switches that could not be read [(IP, reason)]
    groups = STORE.by_ip()
    conflicts = [g for g in groups if g["conflict"]]
    devices = [d for g in groups for d in g["devices"]]
    empty = free_ips()
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Which device hangs off which port. Keyed by switch IP + port name
    # (key on the name alone and the same-numbered port on two switches merges).
    by_port = {}
    for dev in devices:
        if dev.get("swport"):
            by_port.setdefault((dev.get("swhost", ""), dev["swport"]), []).append(dev)

    def who(host, name, limit=3):
        found = by_port.get((host, name)) or []
        shown = [d.get("ip") or dash_mac(d["mac"]) for d in found[:limit]]
        if len(found) > limit:
            shown.append(T("외 %d대", "+%d more") % (len(found) - limit))
        return ", ".join(shown)

    # ---- 1. Findings -------------------------------------------------------
    view = XlSheet(T("점검 소견", "Findings"))
    view.width((0, 13), (1, 22), (2, 46), (3, 26), (4, 14), (5, 14))
    view.row((T("준공 · 점검 리포트", "Commissioning · inspection report"), "title"))
    view.merge(1, 0, 1, 5)
    view.heights[1] = 26
    view.row((T("현장", "Site"), "sub"), site or "-", None,
             (T("작성", "By"), "sub"), author or "-")
    view.row((T("작성일", "Date"), "sub"), stamp, None,
             (T("대역", "Range"), "sub"), STORE.cidr or "-")
    view.row((T("랜카드", "Adapter"), "sub"), STORE.iface or "-", None,
             (T("도구", "Tool"), "sub"), "%s v%s" % (APP_NAME, APP_VER))
    view.blank()

    # Adding the draw from a switch that will not report its capacity pushes usage past 100%%.
    # Count only the switches that reported both.
    poe_used = sum(float(s.get("poeMain", {}).get("used") or 0) for s in switches
                   if float(s.get("poeMain", {}).get("capacity") or 0) > 0)
    poe_cap = sum(float(s.get("poeMain", {}).get("capacity") or 0) for s in switches)
    live_ports = sum(1 for s in switches for p in s.get("ports", {}).values()
                     if int(p.get("oper") or 0) == 1)
    all_slow = [dict(row, swname=s.get("name", ""), swhost=s.get("ip", ""))
                for s in switches for row in (s.get("slow") or [])]

    view.row((T("한눈에", "At a glance"), "sect"))
    view.merge(len(view.rows), 0, len(view.rows), 5)
    view.row((T("사용 중인 IP", "IPs in use"), "h"), (T("충돌 IP", "Conflicts"), "h"),
             (T("발견 장비", "Devices"), "h"), (T("스위치", "Switches"), "h"),
             (T("연결된 포트", "Live ports"), "h"), (T("남은 IP", "Free IPs"), "h"))
    view.row((len(groups), "big"), (len(conflicts), "bad" if conflicts else "big"),
             (len(devices), "big"), (len(switches), "big"),
             (live_ports, "big"), (len(empty["free"]), "big"))
    view.blank()

    view.row((T("손봐야 할 것", "Needs attention"), "sect"))
    view.merge(len(view.rows), 0, len(view.rows), 5)
    view.row((T("구분", "Type"), "h"), (T("위치", "Where"), "hl"),
             (T("내용", "What"), "hl"), (T("권장 조치", "Suggested action"), "hl"),
             (T("확인", "Checked"), "h"), (T("담당", "Owner"), "h"))
    found_any = False
    for host, why in missed:
        # Quietly leaving out what could not be read makes this document lie: it reads as
        # "that switch was fine". Write "could not be read" at the top instead.
        found_any = True
        view.row((T("확인 못 함", "Not checked"), "bad"), (host, "c"),
                 (T("이 스위치를 읽지 못했습니다 — %s", "Could not read this switch — %s")
                  % why, "bad"),
                 (T("SNMP 커뮤니티와 IP 를 확인한 뒤 리포트를 다시 뽑으십시오. "
                    "이 스위치의 포트는 아래 어디에도 없습니다.",
                    "Check the SNMP community and IP, then re-run the report. "
                    "This switch's ports appear nowhere below."), "c"),
                 ("", "cc"), ("", "cc"))
    for row in all_slow:
        found_any = True
        view.row((T("속도 저하", "Speed drop"), "bad"),
                 ("%s %s" % (row.get("swname") or row.get("swhost", ""),
                             T("%s번", "port %s") % row.get("no", "")), "c"),
                 (T("%s 였는데 지금 %s (%s 에 %s 확인)",
                     "was %s, now %s (%s seen on %s)")
                  % (speed_label(row.get("best")), speed_label(row.get("speed")),
                     row.get("bestAt", "")[:10] or "-",
                     speed_label(row.get("best"))), "bad"),
                 (T("랜선 양끝 다시 성단. 기가는 8가닥을 다 쓴다 — 한 가닥만 "
                    "헐거워도 조용히 100M 로 내려앉는다.",
                    "Re-terminate both ends. Gigabit needs all 8 wires; one loose "
                    "wire silently drops the link to 100M."), "c"),
                 ("", "cc"), ("", "cc"))
    # Half duplex. A harder fault to find than a speed drop, so it gets its own entry.
    #
    # A report of "it says 1G but it's slow" is usually this. Glance at the speed column,
    # call it fine, and you really do end up driving back out to replace a camera.
    for switch in switches:
        for info in sorted(switch.get("ports", {}).values(), key=port_number):
            if not is_half_duplex(info):
                continue
            found_any = True
            hits = info.get("lateColl")
            proof = (T(" 늦은 충돌 %d회가 실제로 쌓여 있습니다.",
                       " %d late collisions have actually accumulated.") % hits
                     if isinstance(hits, int) and hits > 0 else "")
            view.row((T("반이중", "Half duplex"), "bad"),
                     ("%s %s" % (switch.get("name") or switch.get("ip", ""),
                                 T("%s번", "port %s") % port_number(info)), "c"),
                     (T("링크는 %s 로 붙어 있지만 반이중입니다 — 속도 칸만 보면 "
                        "정상으로 보입니다.%s",
                        "Link is up at %s but running half duplex — the speed column "
                        "alone looks fine.%s")
                      % (speed_label(info.get("speed")) or "-", proof), "bad"),
                     (T("양끝의 속도·듀플렉스 설정을 맞추십시오. 한쪽만 손으로 박아 "
                        "두면 반대쪽은 협상할 상대가 없어 반이중으로 내려앉습니다 — "
                        "양쪽 다 자동(auto)이 정답입니다.",
                        "Match the speed/duplex setting on both ends. If only one side "
                        "is hard-coded, the other has nothing to negotiate with and "
                        "falls back to half duplex — set both ends to auto."), "c"),
                     ("", "cc"), ("", "cc"))

    for group in conflicts:
        found_any = True
        view.row((T("IP 충돌", "IP conflict"), "warn"), (group["ip"], "c"),
                 (T("%d대가 같은 IP를 씁니다: ", "%d devices share this IP: ")
                  % group["count"]
                  + ", ".join(dash_mac(d["mac"]) for d in group["devices"][:4]), "warn"),
                 (T("한 대만 남기고 나머지를 빈 IP로 옮기십시오.",
                    "Move all but one onto a free IP."), "c"), ("", "cc"), ("", "cc"))
    for switch in switches:
        shut = [p for p in switch.get("ports", {}).values()
                if int(p.get("admin") or 1) != 1]
        if shut:
            found_any = True
            view.row((T("잠긴 포트", "Disabled port"), "warn"),
                     (switch.get("name") or switch.get("ip", ""), "c"),
                     (", ".join(str(port_number(p)) + T("번", "") for p in shut[:12]), "warn"),
                     (T("의도한 것인지 확인하십시오. 준공 전에는 풀어 두는 것이 "
                        "보통입니다.", "Confirm this is intentional; usually released "
                        "before handover."), "c"), ("", "cc"), ("", "cc"))
    if poe_cap and poe_used / poe_cap > 0.8:
        found_any = True
        view.row((T("PoE 여유", "PoE headroom"), "warn"), (T("스위치 전체", "All switches"), "c"),
                 ("%.1fW / %.1fW (%.0f%%)" % (poe_used, poe_cap, poe_used / poe_cap * 100), "warn"),
                 (T("장비를 더 달려면 전원을 보강해야 합니다.",
                    "Add power capacity before installing more devices."), "c"),
                 ("", "cc"), ("", "cc"))
    # A site visited for the first time has no earlier record to compare against. There
    # is no speed drop 'absent', only 'not known yet'. Leave that out and this document
    # claims to have confirmed something it never checked.
    first_time = [sw for sw in switches if not sw.get("hadHistory")]
    if first_time:
        view.row((T("첫 기록", "First record"), "warn"),
                 (", ".join((sw.get("name") or sw.get("ip", "")) for sw in first_time[:6]), "c"),
                 (T("이 스위치는 이번이 첫 기록입니다. 비교할 지난 속도가 없으므로 "
                    "'속도 저하 없음' 은 확인한 결과가 아닙니다.",
                    "First time this switch was recorded. With no earlier reading, "
                    "'no speed drop' is not a checked result."), "warn"),
                 (T("다음 방문 때 다시 뽑으면 그때부터 비교합니다.",
                    "Re-run on the next visit to start comparing."), "c"),
                 ("", "cc"), ("", "cc"))
    # If duplex could not be read on a single port, say so. Leave it out and people read
    # the absence of a 'half duplex' entry in this document as "checked, nothing wrong".
    # Plenty of switches do not serve EtherLike-MIB at all.
    blind = [sw for sw in switches
             if not any(int(p.get("duplex") or 0) for p in sw.get("ports", {}).values())]
    if blind:
        view.row((T("이중 미확인", "Duplex not read"), "warn"),
                 (", ".join((sw.get("name") or sw.get("ip", "")) for sw in blind[:6]), "c"),
                 (T("이 스위치는 듀플렉스를 알려주지 않습니다. 이 문서에 반이중 "
                    "항목이 없는 것은 확인한 결과가 아닙니다.",
                    "This switch does not report duplex. The absence of a half-duplex "
                    "finding here is not a checked result."), "warn"),
                 (T("속도는 정상인데 느리다는 신고가 있으면 스위치 화면에서 포트 "
                    "듀플렉스를 직접 보십시오.",
                    "If something is slow while the speed looks right, check the port "
                    "duplex in the switch UI."), "c"),
                 ("", "cc"), ("", "cc"))

    if not empty.get("complete") and empty["scanned"]:
        view.row((T("스캔 미완", "Scan unfinished"), "bad"), ("", "c"),
                 (T("스캔이 끝까지 가지 않았습니다. '남은 IP' 시트를 배정에 쓰지 "
                    "마십시오.",
                    "The scan did not finish. Do not assign from the 'Free IPs' sheet."),
                  "bad"),
                 (T("대역을 다시 스캔한 뒤 리포트를 다시 뽑으십시오.",
                    "Re-scan the range and re-run the report."), "c"),
                 ("", "cc"), ("", "cc"))
        found_any = True
    if not groups:
        view.row((T("스캔 안 함", "No scan"), "bad"), ("", "c"),
                 (T("장비 스캔을 돌리지 않았습니다. IP 충돌·빈 IP 는 이 문서로 "
                    "판단할 수 없습니다.",
                    "No device scan was run. Do not judge IP conflicts or free "
                    "addresses from this document."), "bad"),
                 (T("대역을 스캔한 뒤 다시 뽑으십시오.",
                    "Scan the range, then re-run."), "c"), ("", "cc"), ("", "cc"))
        found_any = True

    if not found_any and switches and groups and not first_time and not blind:
        view.row((T("특이사항 없음", "All clear"), "good"), ("", "c"),
                 (T("속도 저하·반이중·IP 충돌·잠긴 포트 없습니다.",
                    "No speed drops, half-duplex links, IP conflicts or disabled ports."),
                  "good"),
                 ("", "c"), ("", "cc"), ("", "cc"))
    elif not found_any:
        view.row((T("스위치 미확인", "No switch data"), "warn"), ("", "c"),
                 (T("스위치를 한 대도 읽지 않았습니다. IP 충돌만 확인한 리포트입니다 "
                    "— 포트 속도·PoE 는 이 문서로 판단하지 마십시오.",
                    "No switch was read. This report covers IP conflicts only — do not "
                    "judge port speed or PoE from it."), "warn"),
                 (T("포트 관리 창에서 스위치를 한 번 읽은 뒤 다시 뽑으십시오.",
                    "Read the switch once in Port management, then re-run."), "c"),
                 ("", "cc"), ("", "cc"))
    view.blank()

    view.row((T("현장 소견", "Engineer's notes"), "sect"))
    view.merge(len(view.rows), 0, len(view.rows), 5)
    top = view.row((note or "", "note"))
    view.merge(top, 0, top + 5, 5)
    for extra in range(5):
        view.row(("", "note"), ("", "note"), ("", "note"),
                 ("", "note"), ("", "note"), ("", "note"))
        view.heights[top + extra + 1] = 18
    view.heights[top] = 18
    view.blank()
    sign = view.row((T("점검자", "Inspected by"), "h"), ("", "c"),
                    (T("입회자", "Witness"), "h"), ("", "c"),
                    (T("일자", "Date"), "h"), ("", "c"))
    view.heights[sign] = 30
    view.blank()
    view.row((T("%s v%s — 스캔 %d개 주소",
                "%s v%s — %d addresses scanned")
              % (APP_NAME, APP_VER, empty["scanned"]), "small"))

    # ---- 2. Device list ----------------------------------------------------
    book = XlSheet(T("장비 목록", "Devices"))
    book.width((0, 15), (1, 19), (2, 18), (3, 17), (4, 22), (5, 18), (6, 22),
               (7, 8), (8, 9), (9, 16), (10, 9), (11, 20))
    head = (T("IP", "IP"), "MAC", T("제조사", "Vendor"), T("장비 종류", "Type"),
            T("모델 · 이름", "Model · name"), T("스위치", "Switch"),
            T("포트", "Port"), T("속도", "Speed"), T("PoE(W)", "PoE(W)"),
            T("열린 포트", "Open ports"), T("응답(ms)", "Reply(ms)"),
            T("비고", "Note"))
    book.row(*[(text, "h") for text in head])
    book.freeze = "A2"
    for group in groups:
        for dev in group["devices"]:
            names = [x for x in (dev.get("model"), dev.get("host"), dev.get("mdns"),
                                 dev.get("nbname"), dev.get("ssdp")) if x]
            seen = []
            for x in names:
                if x.lower() not in [y.lower() for y in seen]:
                    seen.append(x)
            marks = []
            if group["conflict"]:
                marks.append(T("IP 충돌", "IP conflict"))
            if dev.get("swslow"):
                marks.append(T("속도 저하", "speed drop"))
            if int(dev.get("swduplex") or 0) == DUPLEX_HALF:
                marks.append(T("반이중", "half duplex"))
            base = "warn" if group["conflict"] else "c"
            book.row((group["ip"], "bad" if group["conflict"] else "cb"),
                     (dash_mac(dev["mac"]), base),
                     (dev.get("vendor") or T("미상", "unknown"), base),
                     (kind_show(dev.get("kind")) or "", base),
                     (" · ".join(seen[:2]), base),
                     (dev.get("swname") or "", base),
                     (dev.get("swport") or "", base),
                     (speed_label(dev.get("swspeed")), "bad" if dev.get("swslow") else "cc"),
                     (round(float(dev.get("poeWatt") or 0), 1) or "", "cn"),
                     (", ".join(str(p) for p in (dev.get("ports") or [])), base),
                     (dev.get("ms") if dev.get("ms") is not None else "", "cn"),
                     (" · ".join(marks), "bad" if marks else "c"))
    book.filter = "A1:%s%d" % (_xl_col(len(head) - 1), max(len(book.rows), 1))

    # ---- 3. Switch port layout ---------------------------------------------
    plate = XlSheet(T("스위치 포트 배치", "Switch layout"))
    plate.width(*[(i, 5.4) for i in range(26)])
    if not switches:
        plate.row((T("스위치를 읽지 못했습니다. 포트 관리 창에서 SNMP 커뮤니티를 "
                     "확인하십시오.",
                     "No switch data. Check the SNMP community in Port management."),
                   "sub"))
    for switch in switches:
        ports = switch.get("ports", {})
        slow_keys = {row.get("key") for row in (switch.get("slow") or [])}
        title = plate.row(("%s  (%s)" % (switch.get("name") or T("스위치", "Switch"),
                                         switch.get("ip", "")), "sect"))
        plate.merge(title, 0, title, 11)
        legend = plate.row((T("사용 중", "in use"), "pLive"), None,
                           (T("빈 포트", "empty"), "pIdle"), None,
                           (T("속도 저하", "slow"), "pSlow"), None,
                           (T("½ 반이중", "½ half duplex"), "pSlow"), None,
                           (T("PoE 급전", "PoE on"), "pPoe"), None,
                           (T("잠김", "locked"), "pDown"))
        for col in (0, 2, 4, 6, 8, 10):
            plate.merge(legend, col, legend, col + 1)
        plate.blank()
        slots, columns = _plate_layout(ports, slow_keys)
        for start in range(0, columns, 24):       # past 48 ports, wrap to a new block
            stop = min(start + 24, columns)
            for line in (0, 1):
                cells = []
                for col in range(start, stop):
                    info = slots.get((line, col))
                    cells.append(_plate_cell(info, slow_keys) if info else None)
                number = plate.row(*cells)
                plate.heights[number] = 22
            plate.blank()
        # port by port
        plate.row(*[(text, "h") for text in
                    (T("포트", "Port"), T("이름", "Name"), T("설명", "Label"),
                     T("속도", "Speed"), T("이중", "Duplex"), T("링크", "Link"),
                     T("관리", "Admin"), T("PoE(W)", "PoE(W)"),
                     T("물린 장비", "Devices behind"))])
        for info in sorted(ports.values(), key=port_number):
            key = port_key(info)
            up = int(info.get("oper") or 0) == 1
            locked = int(info.get("admin") or 1) != 1
            behind = who(switch.get("ip", ""), info.get("name", ""))
            macs = info.get("macs") or []
            if not behind and len(macs) > 1:
                behind = T("아래 스위치·허브 (MAC %d개)", "downstream switch (%d MACs)") % len(macs)
            style = "bad" if key in slow_keys else ("c" if up else "cs")
            half = is_half_duplex(info)
            plate.row((port_number(info) or info.get("index", ""), "cc"),
                      (info.get("name", ""), style),
                      (info.get("alias", ""), style),
                      (speed_label(info.get("speed")) if up else "-",
                       "bad" if key in slow_keys else "cc"),
                      # Could not read it: leave the cell empty. An empty cell reads as
                      # "not looked at"; writing 'full' reads as "looked at, and fine".
                      (duplex_label(info.get("duplex")) if up else "",
                       "bad" if half else "cc"),
                      (T("연결", "up") if up else T("없음", "down"), "cc"),
                      (T("잠김", "locked") if locked else T("열림", "open"),
                       "warn" if locked else "cc"),
                      (round(float(info.get("poeWatt") or 0), 1) or "", "cn"),
                      (behind, style))
        plate.blank(2)

    # ---- 4. PoE power ------------------------------------------------------
    power = XlSheet(T("PoE 전력", "PoE power"))
    power.width((0, 24), (1, 16), (2, 16), (3, 14), (4, 12), (5, 14), (6, 26))
    power.row((T("스위치별 전력", "Per switch"), "sect"))
    power.merge(1, 0, 1, 6)
    power.row(*[(text, "h") for text in
                (T("스위치", "Switch"), T("공급 가능(W)", "Capacity(W)"),
                 T("현재 소비(W)", "In use(W)"), T("여유(W)", "Headroom(W)"),
                 T("사용률", "Load"), T("급전 포트", "Powered ports"),
                 T("비고", "Note"))])
    for switch in switches:
        main = switch.get("poeMain") or {}
        cap = float(main.get("capacity") or 0)
        used = float(main.get("used") or 0)
        live = sum(1 for p in switch.get("ports", {}).values()
                   if float(p.get("poeWatt") or 0) > 0)
        rate = (used / cap) if cap else 0
        power.row(("%s (%s)" % (switch.get("name") or "-", switch.get("ip", "")), "c"),
                  (round(cap, 1) or T("안 알려줌", "not reported"), "cn"),
                  (round(used, 1), "cn"), (round(cap - used, 1) if cap else "", "cn"),
                  ("%.0f%%" % (rate * 100) if cap else "-",
                   "bad" if rate > 0.8 else "cc"),
                  (live, "cn"),
                  (T("여유가 20% 미만입니다.", "Under 20% headroom.") if cap and rate > 0.8
                   else "", "warn" if cap and rate > 0.8 else "c"))
    power.blank(2)
    power.row((T("급전 중인 포트", "Powered ports"), "sect"))
    power.merge(len(power.rows), 0, len(power.rows), 6)
    power.row(*[(text, "h") for text in
                (T("스위치", "Switch"), T("포트", "Port"), T("이름", "Name"),
                 T("등급", "Class"), T("소비(W)", "Watts"), T("측정", "Source"),
                 T("물린 장비", "Device"))])
    for switch in switches:
        for info in sorted(switch.get("ports", {}).values(), key=port_number):
            watt = float(info.get("poeWatt") or 0)
            if watt <= 0:
                continue
            power.row((switch.get("name") or switch.get("ip", ""), "c"),
                      (port_number(info), "cc"), (info.get("name", ""), "c"),
                      (info.get("poeClass") or "", "cc"), (round(watt, 1), "cn"),
                      (T("어림", "class est.") if info.get("poeEstimated", True)
                       else T("실측", "measured"), "cs"),
                      (who(switch.get("ip", ""), info.get("name", "")), "c"))
    power.blank(2)
    power.row((T("PoE 등급별 최대 전력 — IEEE 802.3af 15.4W / at 30W / bt 60~90W. "
                 "'어림' 은 등급으로 계산한 값이고, '실측' 은 스위치가 재서 알려준 "
                 "값입니다.",
                 "PoE class limits — 802.3af 15.4W / at 30W / bt 60-90W. "
                 "'class est.' is computed from the class; 'measured' comes from "
                 "the switch."), "small"))

    # ---- 5. Free IPs -------------------------------------------------------
    spare = XlSheet(T("남은 IP", "Free IPs"))
    spare.width((0, 18), (1, 18), (2, 10), (3, 22), (4, 30))
    spare.row((T("응답 없는 주소 — 배정에 쓸 수 있습니다", "Addresses with no reply"),
               "sect"))
    spare.merge(1, 0, 1, 4)
    if not empty.get("complete"):
        # Whatever the handover document calls a "free IP" is what the customer assigns from.
        # Addresses that were never swept mixed in makes it not a document but an accident.
        spare.row((T("스캔이 끝까지 가지 않았습니다 — 이 목록을 배정에 쓰지 마십시오. "
                     "안 훑은 주소와 조용한 주소가 섞여 있습니다.",
                     "The scan did not finish — do not assign from this list. Addresses "
                     "never swept are mixed in with genuinely silent ones."), "bad"))
        spare.merge(len(spare.rows), 0, len(spare.rows), 4)
    spare.row((T("훑은 주소 %d개 중 %d개가 조용합니다. 조용하다고 반드시 비어 있는 "
                 "것은 아닙니다 — 꺼져 있는 장비도 조용합니다.",
                 "%d of %d scanned addresses were silent. Silent does not always "
                 "mean free — a powered-off device is also silent.")
               % (empty["scanned"], len(empty["free"])), "sub"))
    spare.blank()
    spare.row(*[(text, "h") for text in
                (T("시작", "From"), T("끝", "To"), T("개수", "Count"),
                 T("배정 용도", "Planned use"), T("메모", "Note"))])
    for block in empty["blocks"]:
        spare.row((block["start"], "c"), (block["end"], "c"),
                  (block["count"], "cn"), ("", "c"), ("", "c"))
    if not empty["blocks"]:
        spare.row((T("남은 주소가 없습니다.", "No free addresses."), "c"))

    return write_xlsx(path, [view, book, plate, power, spare])


# ---------------------------------------------------------------------------
# Standalone run
#
# Electron (electron/) draws the UI. This file is the engine running behind it.
# A tkinter UI used to live in here too, but after the move to Electron nobody used it
# while it went on calling functions that had already been deleted, so it was ripped out.
# ---------------------------------------------------------------------------


def main():
    """For checking the engine. The real UI comes up from electron/."""
    parser = argparse.ArgumentParser(description="%s engine" % APP_NAME)
    parser.add_argument("mac", nargs="?", help="pass one MAC to see what the device is")
    args = parser.parse_args()

    print("%s v%s - engine" % (APP_NAME, APP_VER))
    table = _oui_table()
    print("  vendor registry : %s" % ("{:,} prefixes".format(len(table)) if table else "could not be read"))
    loaded = BOOK.load()
    print("  device book     : %s" % (
        "%d prefixes (%s)" % (len(BOOK.index), os.path.basename(BOOK.loaded_from))
        if loaded else "not found"))

    if args.mac:
        info = describe(args.mac)
        print()
        print("  %s" % dash_mac(args.mac))
        print("    vendor : %s" % (info["vendor"] or "unknown"))
        print("    type   : %s" % (info["kind"] or "(decided by port scan)"))
        if info["note"]:
            print("    note   : %s" % info["note"])
        return

    print()
    print("  The window comes up from Electron:  cd electron && npm start")


if __name__ == "__main__":
    main()
