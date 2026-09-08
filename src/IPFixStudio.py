#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Quiet Scanner — 현장 IP 충돌 정리 도구
# Copyright (C) 2026 고요한
#
# 이 프로그램은 자유 소프트웨어입니다. 자유 소프트웨어 재단이 공표한 GNU 일반
# 공중 사용 허가서 제2판 또는 그 이후 판의 조건에 따라 재배포하거나 수정할 수
# 있습니다. 아무런 보증도 하지 않습니다. 자세한 것은 같은 폴더의 LICENSE 를
# 보십시오.
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
Quiet Scanner - 현장 IP 충돌 정리 앱

같은 초기 IP로 출고된 장비들이 한 스위치에 물려 있을 때,
장비를 뽑았다 꽂지 않고 브라우저 화면에서 전부 정리하기 위한 도구.

  1) 대역을 훑어 충돌난 IP를 전부 찾아낸다        (ARP 응답을 OS 거치지 않고 직접 수신)
  2) 각 IP에 어떤 장비가 붙어 있는지 정체를 파낸다 (MAC 격리 -> 포트/웹/ONVIF 조회)
  3) 한 대씩 격리한 채로 IP를 바꾸고 진행 상황을 추적한다
  4) 결과를 CSV / HTML 리포트로 남긴다

필요한 것 (Windows):
    1) Npcap 설치      https://npcap.com   ("WinPcap API-compatible mode" 체크)
    2) pip install scapy
    3) 관리자 권한으로 실행

실행:
    python IPFixStudio.py            # 창이 뜬다
    python IPFixStudio.py --demo     # 장비 없이 화면만 둘러보기

    exe 로 뽑으려면 build_exe.bat 실행
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
# scapy (데모 모드에서는 없어도 실행됨)
# ---------------------------------------------------------------------------
# scapy 는 임포트만으로도 Npcap DLL 을 열고 인터페이스를 훑기 때문에
# Windows 에서 수 초가 걸린다. 창부터 띄우고 백그라운드에서 불러온다.
SCAPY_OK = None      # None = 아직 안 불러봄 / True / False
SCAPY_ERR = ""
ARP = Ether = srp = conf = None
IP = TCP = sr1 = None


def ensure_scapy():
    """scapy 를 실제로 불러온다. 이미 불렀으면 즉시 반환."""
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
# 등록부 파일을 못 읽었을 때 쓰는 최소 표
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
# 제조사 조회 — 두 겹으로 본다
#
#   1겹. IEEE 공식 등록부 (oui.dat.gz, 58,000여 개)
#        MAC 앞자리로 "어느 회사가 만들었나" 까지만 알려준다.
#
#   2겹. 장비 사전 (장비사전.json)
#        쓰는 사람이 직접 채우는 표다. 제조사뿐 아니라 장비 종류, 기본 계정,
#        RTSP 경로까지 적어둘 수 있다. 1겹을 덮어쓴다.
#
#        현장에서 처음 보는 장비를 한 번 등록해두면 다음부터는 스캔하자마자
#        이름이 뜬다. 파일로 주고받을 수 있어 팀끼리, 나아가 쓰는 사람들끼리
#        같이 채워 나갈 수 있다.
# ---------------------------------------------------------------------------

OUI_FILE = "oui.dat.gz"
BOOK_FILE = "device-book.json"
# 현장에서 직접 등록한 것은 따로 담는다.
#
# 사전 하나에 다 담으면, 배포본 사전과 "우리 현장 녹화기" 같은 회사 사정이
# 같은 파일에 섞인다. 그 파일을 공개 저장소에 올리는 순간 조달 정보가 같이
# 나간다. 사람이 매번 조심해서 막을 일이 아니다 — 파일을 갈라 둔다.
BOOK_MINE_FILE = "device-book.local.json"

_OUI_CACHE = None


# v3.0 까지 쓰던 한국어 파일 이름. 공개하면서 영어로 바꿨다.
OLD_NAMES = {
    "장비사전.내것.json": "device-book.local.json",
    "스캔기록.json": "scan-history.json",
    "포트기록.json": "port-history.json",
    "격리기록.json": "isolation.json",
}


def migrate_old_names():
    """옛 이름으로 쌓여 있던 기록을 새 이름으로 한 번 옮긴다.

    이름만 바꾸고 말면 이미 쌓인 것이 통째로 안 읽힌다. 스캔 기록과 포트
    속도 이력이 날아가는 것도 아깝지만, 진짜 위험한 것은 격리 기록이다 —
    그건 PC 에 박아둔 정적 ARP 를 되돌리는 유일한 단서다. 못 읽으면 그 IP 는
    재부팅할 때까지 엉뚱한 MAC 에 묶인 채로 잊힌다.

    새 이름이 이미 있으면 건드리지 않는다. 옮기다 실패해도 프로그램은
    그냥 돌아야 한다 — 기록 때문에 스캔이 못 도는 일은 없어야 한다.
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
    """설정과 사전을 두는 자리. exe 로 묶였으면 exe 옆, 아니면 소스 옆."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def bundle_dir():
    """PyInstaller 로 묶였을 때 딸려온 파일이 풀리는 자리."""
    return getattr(sys, "_MEIPASS", "") or app_dir()


def _oui_table():
    """IEEE 등록부를 처음 쓸 때 한 번만 읽어 들인다.

    tools/build_oui.py 로 다시 만든다. 옛 표는 2020년 이후 배정분이
    통째로 빠져 있어 흔한 장비가 "미상" 으로 떴다.
    """
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE
    table = {}
    # exe 옆을 먼저 본다. IEEE 등록부는 계속 늘어나므로, 새 파일을 exe 옆에
    # 떨궈 넣기만 하면 다시 빌드하지 않고도 갱신되게 한다.
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
    """MAC 앞자리로 제조사를 찾는다. 좁은 등록(36·28비트)을 먼저 본다."""
    digits = hex_mac(mac)
    if len(digits) < 6:
        return "미상"
    table = _oui_table()
    for width in (9, 7, 6):
        name = table.get(digits[:width])
        if name:
            return name
    # 등록부를 못 읽었을 때를 대비한 최소 표
    return OUI_FALLBACK.get(digits[:6], "미상")


class DeviceBook:
    """장비 사전. MAC 앞자리로 제조사와 장비 종류를 알아본다.

    한 항목이 앞자리 여러 개를 거느릴 수 있다(prefixes). 사람이 직접 넣는
    항목은 앞자리 하나(prefix)만 적어도 된다. 전체 MAC 12자리를 적으면
    그 장비 한 대만 가리킨다 — 이건 제조사 앞자리보다 우선한다.

    담는 것은 제조사와 장비 종류뿐이다. 계정이나 스트림 주소는 넣지 않는다.
    펌웨어마다 달라서 틀린 값은 없느니만 못하고, 남과 주고받을 파일에
    계정을 적을 이유도 없다.
    """

    FIELDS = ("vendor", "kind", "note")

    def __init__(self):
        self.entries = []       # [{vendor, kind, note, prefixes:[...]}]
        self.index = {}         # 앞자리 -> 항목
        self.loaded_from = ""

    @property
    def path(self):
        return os.path.join(app_dir(), BOOK_FILE)

    @property
    def mine_path(self):
        """현장에서 등록한 것이 쌓이는 자리. 공개 저장소에는 올리지 않는다."""
        return os.path.join(app_dir(), BOOK_MINE_FILE)

    # -- 읽고 쓰기 --------------------------------------------------------

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
        """내 사전 -> 옆에 놓인 기본 사전 -> 프로그램에 딸려온 기본 사전 순으로 찾는다.

        내 사전이 앞이라 배포본을 새로 덮어써도 현장에서 등록한 것은 안 날아간다.
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
            "note": ("Quiet Scanner 장비 사전. MAC 앞자리로 제조사와 장비 종류를 알아봅니다. "
                     "prefixes 에 MAC 앞자리를 콜론 없이 적습니다. "
                     "전체 MAC 12자리를 적으면 그 장비 한 대만 가리킵니다."),
            "version": 1,
            "entries": self.entries,
        }

    def save(self):
        """언제나 내 사전에 쓴다. 배포본(장비사전.json)은 건드리지 않는다.

        배포본에 덮어쓰면 다음에 그 파일을 저장소에 올릴 때 현장에서 등록한
        것이 딸려 올라간다. 프로그램이 쓰는 파일과 배포하는 파일을 갈라 둔다.
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
        """받은 사전을 합친다. 같은 앞자리는 새 것으로 덮어쓴다."""
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

    # -- 조회 -------------------------------------------------------------

    def match(self, mac):
        """가장 정확한 것부터 찾는다. 전체 MAC 등록이 제조사 앞자리보다 우선."""
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

    # -- 편집 -------------------------------------------------------------

    def upsert(self, prefix, vendor="", kind="", note=""):
        """앞자리 하나를 등록하거나 고친다.

        이미 있는 앞자리를 고칠 때 조심할 게 하나 있다. 기본 사전은 브랜드마다
        앞자리를 묶어서 담는다 — 예를 들어 Hikvision 항목 하나에 앞자리 37개가
        들어 있다. 그 항목을 그대로 고치면 하이크비전 장비 전부의 이름이 바뀐다.
        그래서 여러 앞자리를 묶은 항목을 만나면 이 앞자리만 떼어내 새 항목으로
        만든다. 나머지 36개는 원래대로 둔다.
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
        return hit is None      # 사전에 아예 없던 앞자리였는가

    def lookup(self, prefix):
        """그 앞자리가 사전에 이미 있는지, 있다면 뭐라고 적혀 있는지."""
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
        """화면에 뿌릴 평평한 목록: (앞자리, 제조사, 종류, 메모)."""
        out = []
        for item in self.entries:
            for prefix in item["prefixes"]:
                out.append((prefix, item["vendor"], item["kind"], item["note"]))
        out.sort(key=lambda r: (r[1].lower(), r[0]))
        return out


BOOK = DeviceBook()


def describe(mac):
    """MAC 하나로 알 수 있는 것. 사전이 IEEE 등록부를 덮어쓴다."""
    info = {"vendor": vendor_of(mac), "kind": "", "note": "",
            "from_book": False, "exact": False}
    hit = BOOK.match(mac)
    if hit:
        info["from_book"] = True
        # 전체 MAC(12자리)으로 등록했다면 사람이 그 장비를 콕 집은 것이다.
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
    """AA-BB-CC-DD-EE-FF 꼴로. 구분자가 아예 없는 12자리도 끊어 준다."""
    digits = hex_mac(mac)
    if len(digits) == 12 and ":" not in mac and "-" not in mac:
        return "-".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()
    return mac.upper().replace(":", "-")


# ---------------------------------------------------------------------------
# 말
#
# 화면 문구는 electron/renderer/i18n.js 가 가지고 있고, 여기 있는 것은
# 엔진이 직접 만들어 로그창에 띄우는 문구다. 화면에서 언어를 바꾸면
# set_lang 으로 이쪽에도 알려준다.
#
# 주석은 한국어로 둔다. 주석은 우리가 나중에 읽으려고 쓴 것이고,
# 옮기면 "왜 이렇게 만들었는지" 가 묻히기 쉽다.
# ---------------------------------------------------------------------------

LANG = "ko"


def set_lang(code):
    global LANG
    LANG = "en" if str(code or "").lower().startswith("en") else "ko"
    return LANG


def T(ko, en):
    """사람이 읽는 문구 하나. 한국어를 먼저 적는다 — 우리가 원본이다."""
    return en if LANG == "en" else ko


# 장비 종류 이름표. 사전 파일과 guess_kind 가 한국어로 뱉는 것을 옮긴다.
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
    """장비 종류를 영어로. 사람이 직접 적어 넣은 종류는 그대로 둔다."""
    return KIND_EN.get(text or "", text or "")


def kind_show(text):
    """지금 언어로 보여줄 장비 종류."""
    return kind_en(text) if LANG == "en" else (text or "")


# ---------------------------------------------------------------------------
# 상태 저장소
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, demo=False):
        self.lock = threading.RLock()
        self.demo = demo
        self.iface = None
        self.ifindex = None
        self.cidr = ""
        self.busy = False
        self.cancel = threading.Event()   # 작업 중지 요청
        self.progress = {"phase": "대기", "pct": 0, "msg": "", "cur": 0, "total": 0}
        self.devices = {}          # "ip|mac" -> dict
        self.order = []            # 표시 순서 유지
        self.isolated = None       # 현재 격리된 key
        self.mymac = ""            # 첫 랜카드 MAC (옛 이름 유지)
        self.mymacs = set()        # 고른 랜카드 전부의 MAC — 자기 포트를 못 끄게 막는다
        self.logs = []
        self.last_scan = ""
        self.scanned = []          # **세 번의 확인을 다 거친** 주소만 들어간다
        # 스캔이 끝까지 갔는가. 터졌거나 중지했으면 False 로 남는다.
        # 빈 IP 목록은 이 깃발 없이는 아무 뜻이 없다 — 안 훑은 주소와
        # 훑었는데 조용한 주소가 화면에서 똑같이 보이기 때문이다.
        self.scan_done = False
        self.cred = None           # 카메라 계정 (메모리에만 둔다)

    # -- 로그 --------------------------------------------------------------
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

    # -- 장비 --------------------------------------------------------------
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
                    # 제조사 앞자리(OUI)는 같은 회사 제품군일 뿐 장비 한 대의 정체가
                    # 아니다. 전체 MAC으로 직접 등록한 경우에만 확정으로 표시한다.
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
                    # 어느 랜카드로 잡혔는지. 카드를 둘 이상 골라 훑을 때
                    # 격리·검사를 엉뚱한 카드로 하면 실패한다.
                    "ifname": self.iface or "", "ifindex": self.ifindex,
                    "seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                self.order.append(k)
            return self.devices[k]

    def by_ip(self):
        """IP별로 묶어서 반환. 충돌(2대 이상) 우선 정렬."""
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
# 시스템 유틸
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
    """Windows가 알고 있는 IPv4 주소별 프리픽스 길이(/24 같은 값)를 읽는다."""
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
    """주소 하나와 프리픽스에서 실제 네트워크 표기(예: 192.168.0.0/23)를 만든다."""
    try:
        return str(ipaddress.ip_network("%s/%d" % (ip, prefix), strict=False))
    except (TypeError, ValueError):
        return ""


def list_ifaces():
    """사용 가능한 네트워크 인터페이스 목록. (느릴 수 있으니 스레드에서 호출)"""
    out = []
    if not ensure_scapy():
        return out
    try:
        # Npcap/Scapy는 인터페이스와 IP를 캐시한다. 제어판에서 IP를 바꾼 뒤에도
        # 새로고침 버튼이 현재 값을 보여주도록 매번 Windows 정보를 다시 읽는다.
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
                # Windows의 제어판 표시 이름은 코드 페이지에 따라 깨질 수 있다.
                # Npcap GUID는 ASCII이고 Scapy가 실제로 패킷을 보낼 때 요구하는 값이다.
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
# ARP 고정 / 해제
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 결과 저장과 스캔 비교
#
# 비교는 시공 검수에 쓴다. 들어가기 전에 한 번 찍어두고, 작업이 끝난 뒤 다시
# 스캔하면 "내가 뭘 붙였고 뭐가 사라졌는지" 가 그대로 나온다.
# 장비를 알아보는 기준은 IP 가 아니라 MAC 이다 — IP 는 바뀌어도 MAC 은 안 바뀐다.
# ---------------------------------------------------------------------------

HISTORY_FILE = "scan-history.json"
HISTORY_LIMIT = 30


def export_rows(path, rows, fmt="json", target="", columns=None):
    """스캔 결과를 파일로 남긴다."""
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
        # CSV는 화면에서 고른 칸만 담는다. 장비를 파악할 때만 쓰는 NetBIOS·mDNS·
        # UPnP·시리얼·TTL·상태를 Excel에 늘어놓으면 현장 인수표로 쓰기 어렵다.
        labels = {
            "ip": "IP", "mac": "MAC", "vendor": "제조사", "kind": "장비 종류",
            "model": "모델", "name": "이름", "ms": "응답(ms)", "os": "OS",
            "ports": "열린 포트", "swport": "스위치 포트", "vlan": "VLAN",
            "seen": "확인 시각",
        }
        chosen = [key for key in (columns or ["ip", "vendor", "kind", "model", "name", "ms", "os", "ports"])
                  if key in labels]
        # 화면에서는 IP와 MAC이 한 칸처럼 보이지만 Excel에서는 각각 정렬·필터할 수
        # 있어야 하므로 항상 나란한 두 칸으로 쓴다.
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
    """완료된 스캔 기록을 최신순으로 읽는다. 깨진 기록은 비워서 안전하게 시작한다."""
    try:
        with open(_history_path(), "r", encoding="utf-8") as fh:
            rows = json.load(fh).get("records", [])
        return [row for row in rows if isinstance(row, dict) and row.get("id")]
    except (OSError, ValueError, AttributeError):
        return []


def save_scan_history(devices, target="", iface=""):
    """현재 장비 목록을 비교용으로 남긴다. 최근 30회만 보관한다."""
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
    """MAC 기준으로 두 스캔을 비교한다. IP 변경은 장비 교체로 취급하지 않는다."""
    added = [{"mac": key, **value} for key, value in now.items() if key not in base]
    gone = [{"mac": key, **value} for key, value in base.items() if key not in now]
    moved = [{"mac": key, "from": base[key].get("ip", ""), "to": value.get("ip", "")}
             for key, value in now.items()
             if key in base and base[key].get("ip") != value.get("ip")]
    return added, gone, moved


# ---------------------------------------------------------------------------
# 포트 속도 이력 — "예전엔 1G였는데 지금 100M입니다"
# ---------------------------------------------------------------------------
# 기가 링크는 랜선 8가닥을 전부 쓴다. 그중 한 가닥만 끝이 헐거워도 링크는
# 안 끊기고 조용히 100M 로 내려앉는다. 화면에는 아무 증상이 없다. 카메라가
# 가끔 끊긴다는 민원이 몇 달 뒤에 올라온다.
#
# 그래서 포트 속도를 매번 적어 두고, 예전보다 느려졌으면 사람이 찾기 전에
# 먼저 말한다.

PORT_HISTORY_FILE = "port-history.json"
# 포트 조회는 이제 각자 스레드에서 돈다. 스위치 두 대를 동시에 읽으면 이
# 파일을 동시에 고치게 되고, 그러면 한쪽 기록이 통째로 날아간다.
PORT_HISTORY_LOCK = threading.RLock()
PORT_HISTORY_SWITCHES = 40        # 스위치 몇 대까지 기억할지
PORT_HISTORY_PORTS = 512          # 스위치 한 대에 포트 몇 개까지


def _port_history_path():
    return os.path.join(app_dir(), PORT_HISTORY_FILE)


def load_port_history():
    """스위치별 포트 이력. 깨졌으면 빈 것으로 시작한다 — 기록 때문에 툴이 죽으면 안 된다."""
    try:
        with open(_port_history_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        switches = data.get("switches") if isinstance(data, dict) else None
        if not isinstance(switches, dict):
            return {}
        # 값이 dict 가 아닌 줄이 하나라도 섞여 있으면(손으로 고쳤거나 쓰다 말았거나)
        # 나중에 정리하다 터진다. 여기서 걸러 둔다.
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
        # 기록을 못 남기는 건 참을 수 있다. 스캔까지 같이 죽는 건 못 참는다.
        try:
            os.remove(tmp)
        except OSError:
            pass


def port_key(info):
    """포트를 식별할 이름. 이름이 있으면 이름, 없으면 번호.

    이름을 먼저 쓰는 이유는 스위치를 재부팅하거나 모듈을 뺐다 꽂으면 ifIndex 가
    통째로 밀릴 수 있어서다. GigabitEthernet1/0/12 는 안 밀린다.
    """
    return (info.get("name") or "").strip() or "#%s" % info.get("index", "")


def port_number(info):
    """포트 이름에서 사람이 부르는 번호를 뽑는다. GigabitEthernet1/0/12 -> 12."""
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
    """포트 속도를 기록하고, 예전보다 느려진 포트를 돌려준다.

    기준을 '지난번' 이 아니라 **여태 본 최고 속도** 로 잡는다. 지난번과 비교하면
    1G 이던 포트가 100M 로 떨어지는 그 한 번만 알리고, 그다음부터는 100M 이 새
    기준이 되어 조용해진다. 랜선은 고칠 때까지 계속 나가 있으니 최고를 붙든다.

    물린 장비가 통째로 바뀌었으면 기준을 새로 잡는다. 1G 카메라 빼고 100M
    카메라를 꽂은 것을 고장이라고 부르면 안 된다.
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
        okay = int(was.get("okSpeed") or 0)     # 사람이 '이 속도가 정상' 이라 한 값
        was_macs = [m for m in (was.get("macs") or []) if isinstance(m, str)]

        # 장비가 통째로 바뀌었으면 예전 속도를 들이대지 않는다. 사람이 눌러 둔
        # '정상' 도 같이 지운다 — 그건 그때 물려 있던 장비를 보고 한 판단이다.
        #
        # 링크가 살아 있는데 MAC 이 하나도 안 보이면 그건 '아무것도 없다' 가
        # 아니라 'MAC 표를 못 읽었다' 이다. 그걸 교체로 치면 멀쩡한 포트의
        # 기준이 날아가고, 반대로 빈 목록으로 예전 목록을 덮으면 다음 판에
        # 진짜 교체를 못 알아본다. 못 읽었으면 예전 것을 그대로 지킨다.
        swapped = bool(macs and was_macs) and not (set(macs) & set(was_macs))
        if swapped:
            best, best_at, okay = 0, "", 0
        keep_macs = macs[:16] if macs else was_macs[:16]

        # 사람이 "이 속도가 정상" 이라 해 둔 뒤에 그보다 빨라진 적이 있으면,
        # 그 포트는 더 낼 수 있다는 것이 증명된 것이다. 봐주기를 거둔다.
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
            "macs": keep_macs,          # 업링크 뒤 수백 개를 다 적을 이유는 없다
        }

    if remember:
        # 이번에 본 포트만 남기고 나머지를 지우면 안 된다. 이름 walk 가 중간에
        # 끊겨 포트 열 개가 이름 없이 올라온 판 한 번이면, 그 포트들의 1G 기준이
        # 통째로 사라진다. 그러면 고장난 포트가 영원히 조용해진다.
        # 오래 안 보인 것만 덜어낸다.
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
    """이 속도가 정상이라고 못 박는다. 기준을 지금 속도로 내린다.

    100M 짜리 장비를 일부러 물려 놓은 포트가 영원히 빨갛게 남으면, 사람은
    곧 빨간색 전체를 무시하게 된다. 무시당하는 경고는 없는 것만 못하다.
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
    # 기록된 속도가 0 이면 '링크가 없을 때 읽은 판' 이다. 그걸 정상이라고
    # 못 박으면 기준(best)만 0 으로 날아가고 봐주기는 저장되지도 않는다.
    # 그래놓고 화면에는 "기록했습니다" 가 뜬다 — 고장이 영원히 조용해진다.
    speed = int(row.get("speed") or 0)
    if speed <= 0:
        return False
    row["best"] = speed
    row["okSpeed"] = speed
    row["bestAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_port_history(store)
    return True


# ---------------------------------------------------------------------------
# 격리 기록 — 비정상 종료 뒷정리
#
# 격리는 윈도우 ARP 표에 "이 IP 는 이 MAC 이다" 를 못박는 것이다. 정상 종료 때는
# 다시 뽑지만, 작업관리자로 죽이거나 프로그램이 뻗으면 못이 박힌 채 남는다.
# 그러면 그 PC 는 그 IP 로 계속 그 장비 한 대만 붙고, 쓴 사람은 이유를 모른다.
#
# 그래서 박을 때마다 파일에 적어두고, 다음 실행 때 남아 있는 것을 뽑는다.
# 우리가 적어둔 것만 건드린다 — 회사에서 일부러 걸어둔 정적 ARP 는 손대지 않는다.
#
# (못은 메모리에만 박히므로 재부팅해도 사라진다. 다만 그걸 아는 사람이 없다.)
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
    """지난번에 남긴 격리를 걷어낸다. 시작할 때 한 번 부른다.

    기록을 먼저 비우면 안 된다. 관리자 권한 없이 켰다면 못 지우는데, 기록이
    이미 사라져서 다음 판에는 시도조차 안 한다. 그 IP 는 재부팅할 때까지
    엉뚱한 MAC 으로 고정된 채 남는다. 정말 지워진 것만 기록에서 뺀다.
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
    """해당 IP를 지정한 MAC 장비 하나에만 묶는다."""
    if STORE.demo:
        return True, "demo"

    if os.name == "nt":
        if not ifindex:
            return False, "인터페이스 인덱스를 알 수 없습니다"

        # 1순위: netsh. PowerShell 과 결과는 같은데 훨씬 빠르다 — powershell.exe
        # 는 뜨는 데만 0.5~1.5초가 걸리고, 검사 한 번에 pin·unpin 으로 두 번
        # 부른다. 기사가 장비 하나 눌러놓고 기다리는 그 시간의 큰 몫이었다.
        run_cmd(["netsh", "interface", "ipv4", "delete", "neighbors",
                 str(ifindex), ip])
        rc, out, err = run_cmd(["netsh", "interface", "ipv4", "add",
                                "neighbors", str(ifindex), ip, dash_mac(mac)])
        if rc == 0:
            pin_remember(ip, mac, ifindex, ifname)
            return True, ""

        # 2순위: PowerShell. netsh 문법이 안 먹는 판이 있다.
        # (New-NetNeighbor 에는 -Store 옵션이 없다. 기본이 메모리 저장이라
        #  재부팅하면 저절로 사라진다)
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
    """격리를 푼다. 어느 방식으로 걸렸든 확실히 걷어낸다.

    성공했다고 무조건 대답하면 안 된다. 관리자 권한이 없으면 두 명령 다
    조용히 실패하는데, 그러면 이 PC 는 그 IP 를 계속 정해진 MAC 으로만
    보낸다 — 장비를 옮기거나 바꿔도 엉뚱한 데로 간다. 재부팅해야 풀린다.
    그걸 "풀었습니다" 라고 적으면 아무도 찾아볼 생각을 안 한다.
    """
    if remember:
        pin_forget(ip)
    if STORE.demo:
        return True, "demo"
    if os.name == "nt":
        # netsh 를 먼저. PowerShell 은 뜨는 데만 1초가 넘는다.
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
            return True, ""       # 둘 다 투덜댔지만 실제로는 없어졌다
        return False, (err2.strip() or out2.strip() or "지우지 못했습니다")[:200]
    rc, out, err = run_cmd(["ip", "neigh", "del", ip, "dev", ifname])
    return (rc == 0), (err.strip() or out.strip())


def _still_pinned(ip, ifindex):
    """그 IP 가 아직 고정(Permanent)으로 남아 있는지 본다. 못 읽으면 False."""
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
# 스캔
# ---------------------------------------------------------------------------
RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\s*-\s*(\d{1,3})$")
MAX_TARGETS = 4096


def parse_target(text):
    """'192.168.0.1-254' / '192.168.0.0/24' / '192.168.0.13' 을 IP 목록으로 편다.

    scapy 는 대시 범위 표기를 확장해 주지 않으므로 여기서 직접 편다.
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
        ipaddress.IPv4Address("%s.%d" % (base, a))   # 형식 검증
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
    """대상에 ARP를 뿌리고 응답한 (IP, MAC)을 전부 수집.

    한 번에 다 보내면 진행 상황을 알 수 없으므로 여러 묶음으로 나눠 보낸다.
    묶음이 끝날 때마다 찾은 것을 바로 넘겨줘서 화면에 실시간으로 뜬다.
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
    """"80,443,8000-8010" 같은 입력을 포트 목록으로 바꾼다."""
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
    """웹페이지 제목을 사람이 읽는 글자로 되돌린다.

    제목에는 HTML 특수문자가 그대로 박혀 있는 경우가 흔하다. 시놀로지가
    "RackStation&nbsp;-&nbsp;Synology" 처럼 준다. 그걸 풀지 않으면 목록에
    &nbsp; 가 글자 그대로 뜬다. 줄바꿈과 겹친 공백도 여기서 정리한다.
    """
    if not text:
        return ""
    # &nbsp; 는 풀어놓으면 보통 공백이 아니라서(U+00A0) 따로 갈아 끼운다
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
        # 401/403 도 정보가 많다 (realm 에 모델명이 박혀 있는 경우가 흔함)
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
    """유니캐스트 WS-Discovery. 응답하면 카메라 계열이 거의 확실하다."""
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
# 장비를 알아보는 다른 통로들
#
# 포트를 두드려 보는 것 말고도, 장비가 스스로 자기 이름을 알려주는 길이 몇 개
# 있다. 답해주는 장비는 공짜로 정확한 정보를 주므로 먼저 물어보고, 입을 다무는
# 장비만 포트를 두드린다.
#
#   역DNS      IP -> 이름          망에 DNS 서버가 있을 때
#   NetBIOS    137/UDP             윈도우 PC, NVR, 공유 장비
#   mDNS       224.0.0.251:5353    애플·프린터·AV 장비 (Bonjour)
#   SSDP       239.255.255.250     공유기·카메라·미디어 장비 (UPnP)
#   핑         응답시간과 TTL       거리와 OS 짐작
# ---------------------------------------------------------------------------

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900


def reverse_name(ip, timeout=1.0):
    """역DNS. 망에 DNS 서버가 있으면 IP 로 이름을 얻는다."""
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
    """열린 포트에 붙는 데 걸린 시간(ms). ICMP 가 막힌 곳에서 쓴다."""
    for port in (ports or [80, 443, 554]):
        start = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return round((time.time() - start) * 1000, 1)
        except OSError:
            continue
    return None


def os_from_ttl(ttl):
    """TTL 은 남은 홉 수다. 출발값을 되짚으면 OS 를 짐작할 수 있다."""
    if ttl is None:
        return ""
    start = 64 if ttl <= 64 else (128 if ttl <= 128 else 255)
    return {64: "리눅스 / 임베디드", 128: "윈도우", 255: "네트워크 장비"}[start]


def ping_once(ip, timeout_ms=800, ports=None):
    """응답시간(ms)과 TTL 을 얻는다.

    TTL 은 남은 홉 수라 처음 값을 짐작할 수 있다. 128 에서 출발하면 윈도우,
    64 면 리눅스·임베디드(카메라 대부분), 255 면 네트워크 장비인 경우가 많다.

    핑이 막혀 있거나(카메라 중에 ICMP 를 꺼둔 것이 있다) ping 명령 자체가
    없으면, 열린 포트에 붙는 시간으로 대신 잰다. 그때는 TTL 을 알 수 없다.
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
    """열린 포트에 SYN 하나를 던져 응답 패킷의 TTL 을 읽는다.

    윈도우 PC 는 방화벽이 핑을 기본으로 막는다. 그래서 ping 으로는 TTL 이
    안 나오는데, 정작 웹 포트는 열려 있는 경우가 많다. 그럴 때 SYN 을 보내고
    돌아온 SYN-ACK 의 TTL 을 읽으면 같은 값을 얻는다.

    scapy(=Npcap) 가 있어야 한다. 없으면 조용히 포기한다.
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
    """NetBIOS 이름 조회(137/UDP). 윈도우 PC 와 NVR 이 잘 답한다."""
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
        names.append((raw, kind, bool(flags & 0x8000)))   # 0x8000 = 그룹 이름
        pos += 18

    name = next((n for n, k, g in names if not g and k == 0x00), "")
    group = next((n for n, k, g in names if g and k == 0x00), "")
    return {"name": name, "group": group}


def _mdns_query(name, qtype=12):
    """mDNS 질의 한 통을 만든다. qtype 12 = PTR."""
    header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    body = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + body + qtype.to_bytes(2, "big") + b"\x00\x01"


def _dns_names(data):
    """응답 안에 들어 있는 이름 조각을 긁어모은다.

    압축 포인터까지 제대로 따라가려면 파서를 다 짜야 하는데, 우리는 '이 장비가
    뭐라고 부르는가' 만 알면 되므로 읽을 수 있는 이름만 주워 담는다.
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


# 장비 이름으로 볼 만한 글자인지 가린다.
# mDNS 응답에는 이름 말고도 TXT 기록이 섞여 온다 — "mac_address=00:11:32:.." 같은.
# 우리가 만든 조각내기는 그런 것까지 주워 담기 때문에 여기서 걸러야 한다.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$")


def looks_like_hostname(text):
    name = (text or "").strip()
    if not HOSTNAME_RE.match(name):
        return False
    if name.lower() in ("local", "_tcp", "_udp", "arpa", "in-addr", "ip6"):
        return False
    if name.startswith("_"):
        return False              # 서비스 종류지 장비 이름이 아니다
    if "=" in name or "|" in name:
        return False              # TXT 기록 조각
    if re.fullmatch(r"[0-9a-fA-F]{2}([-:][0-9a-fA-F]{2}){5}", name):
        return False              # MAC 을 이름이라고 내놓는 장비가 있다
    if re.fullmatch(r"[0-9.]+", name):
        return False              # IP 주소
    return True


def mdns_sweep(timeout=2.0):
    """망 전체에 대고 한 번 물어본다. 답한 장비들의 IP -> 이름.

    장비마다 찾아가는 게 아니라 멀티캐스트로 한 번 외치는 것이라,
    장비가 몇 대든 이 함수 한 번이면 된다.
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
    """UPnP 로 한 번 외친다. 답한 장비의 IP -> {이름, 제조사, 모델, 시리얼}."""
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
        for _ in range(2):                      # UDP 라 한 통은 흘릴 수 있다
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

    # 장비가 알려준 주소를 열어보면 이름·모델·시리얼이 들어 있다.
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
            pass                                 # 못 열어도 IP 는 건졌다
        if any(info.values()):
            out[ip] = info
    return out


# 아래 값들은 "달리 부를 말이 없어서" 붙인 이름이다. 포트나 제조사만 보고
# 뭉뚱그린 것이라, 장비 사전이 아는 이름이 있으면 그쪽이 늘 낫다.
# 예: 시놀로지 NAS 는 80·443·5000 이 열려 있어 '웹 관리 장비' 로 뭉뚱그려지는데,
#     사전은 이미 'NAS' 라고 알고 있다.
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
    """모델명이 아니라 장비의 역할만 말하는 넓은 표현인지 판단한다."""
    text = clean_title(value).lower()
    if not text:
        return True
    # AX6000M 같은 형식 번호가 있으면, 역할명(router)도 같이 있어도 모델명이다.
    if re.search(r"\d", text):
        return False
    return any(word in text for word in (
        "router", "gateway", "camera", "network camera", "nvr", "dvr",
        "switch", "web server", "webserver", "network device",
    ))


def preferred_model(current, candidate):
    """기존의 구체 모델명을 웹 제목 같은 일반 이름이 덮어쓰지 못하게 한다."""
    current = clean_title(current)
    candidate = clean_title(candidate)
    if not candidate:
        return current
    if not current:
        return candidate
    # 예: SSDP의 'ipTIME AX6000M'은 HTTP 인증 영역의 'ipTIME Router'보다 낫다.
    if generic_model_name(candidate) and not generic_model_name(current):
        return current
    if generic_model_name(current) and not generic_model_name(candidate):
        return candidate
    # 서로 같은 급이면 먼저 얻은 값을 보존한다. 스캔 결과가 검사로 퇴화하지 않는다.
    return current


def kind_family(kind):
    """표현은 달라도 같은 장비 범주인 경우를 한 묶음으로 본다."""
    value = (kind or "").lower()
    if "공유기" in value or "라우터" in value or "router" in value:
        return "router"
    return value


def identify_device(dev, ifindex, ifname, isolate=True, ports_text=""):
    """장비 하나의 정체를 파낸다. 필요하면 ARP로 격리한 상태에서 조사."""
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
            # 데모에서는 실제 네트워크로 나가지 않는다
            time.sleep(0.35)
            ports = dev.get("ports") or []
            http["title"] = dev.get("title") or ""
        else:
            ports = scan_ports(ip, parse_ports(ports_text))
            if STORE.cancel.is_set():
                return dev

            # 여기서부터는 전부 "답이 오길 기다리는" 일이다. 서로 기다릴 이유가
            # 하나도 없는데 예전에는 줄을 세워 놨다 — 웹 최대 15초, 그다음
            # ONVIF 2초, 그다음 이름 묶음. 카메라가 아니면 ONVIF 2초는 통째로
            # 버리는 시간이었다. 한 번에 보내고 제일 느린 하나만큼만 기다린다.
            def web():
                # 열려 있는 웹 포트 중 앞의 둘만 본다. 하나가 답하면 그걸 쓴다.
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
            # 핑이 막혀 TTL 을 못 얻었는데 열린 포트가 있으면, SYN 으로 다시 잰다.
            # 윈도우 PC 는 기본 방화벽이 핑만 막고 웹 포트는 열어두는 일이 흔하다.
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
                pass  # 데모 시드 모델명 유지
            else:
                scanned_model = pick_model(dev["title"], dev["realm"],
                                           dev["server"], ov)
                dev["model"] = preferred_model(dev.get("model", ""), scanned_model)
            found = guess_kind(dev["vendor"], ports, dev["title"],
                               dev["server"], dev["realm"], ov)
            if dev.get("book_exact") and dev.get("kind"):
                pass                      # 전체 MAC 으로 콕 집어 등록한 장비 — 사람 말이 이긴다
            elif dev.get("kind") and kind_family(dev["kind"]) == kind_family(found):
                pass                      # '공유기'와 '공유기 / 라우터'처럼 같은 뜻이면 기존 표현을 지킨다
            elif found not in WEAK_KINDS:
                dev["kind"] = found
                dev["kind_confidence"] = "estimated"
            elif dev.get("book") and dev.get("kind"):
                pass                      # 뭉뚱그린 짐작보다 사전이 아는 이름이 낫다
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
# 카메라 화면 미리보기 (ONVIF 스냅샷)
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
    """ONVIF 인증 헤더 (UsernameToken Digest)."""
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
    """지정된 ONVIF 서비스 URL에 SOAP 요청을 보낸다."""
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
    """ONVIF Device 서비스에서 Media 서비스 주소를 찾아 스냅샷 URI를 얻는다."""
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
                say("ONVIF Media 서비스 확인")
        except Exception:
            pass
        # 비표준이지만 Device 서비스에서 Media 요청을 함께 받는 장비도 있다.
        add(device_url)
        # 일부 구형 장비는 Capabilities 없이 아래 고정 경로만 제공한다.
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
    """Digest / Basic 어느 쪽이든 되는 방식으로 받아온다."""
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
    """스냅샷을 시도할 HTTP/HTTPS 주소들. SDK 포트(예: 8000)는 제외한다."""
    ports = set(dev.get("ports") or [])
    candidates = []
    for port, scheme in ((80, "http"), (443, "https"), (8080, "http"),
                         (8443, "https")):
        # 포트 스캔 결과를 우선하되, 80/443은 흔한 기본값이라 항상 한 번 시도한다.
        if port in ports or port in (80, 443):
            host = dev["ip"] if port in (80, 443) else "%s:%d" % (dev["ip"], port)
            candidates.append("%s://%s" % (scheme, host))
    # 장비가 응답한 일반 웹 포트도 빠뜨리지 않는다. 8000은 Hikvision SDK 포트라 제외한다.
    for port in sorted(ports - {80, 443, 8000, 554, 8554, 37777, 34567}):
        if port <= 0 or port > 65535:
            continue
        candidates.append("http://%s:%d" % (dev["ip"], port))
        candidates.append("https://%s:%d" % (dev["ip"], port))
    return list(dict.fromkeys(candidates))


def grab_snapshot(dev, user, pw, log=None):
    """카메라 한 장면을 가져온다. (bytes, 어떻게 가져왔는지) 를 돌려준다."""
    ip = dev["ip"]

    def say(m):
        if log:
            log(m)

    bases = camera_bases(dev)
    errors = []

    # 1순위: ONVIF 표준
    try:
        uri = onvif_snapshot_uri(ip, user, pw, bases, say)
        if uri:
            say("ONVIF 스냅샷 주소 확인")
            try:
                data = http_get_auth(uri, user, pw)
                if looks_like_image(data):
                    return data, "ONVIF"
            except Exception as e:
                errors.append("ONVIF 주소 응답 실패: %s" % e)
    except Exception as e:
        errors.append("ONVIF 조회 실패: %s" % e)

    # 2순위: 제조사별로 알려진 주소
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
    detail = errors[-1] if errors else "스냅샷 주소를 찾지 못했습니다"
    return None, detail[:180]


# ---------------------------------------------------------------------------
# 백그라운드 작업
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
# 스위치 포트 찾기 (SNMP)
#
# 현장에서 제일 오래 걸리는 일이 "이 카메라가 랙 어느 포트에 물렸나" 다.
# 스위치는 자기가 배운 MAC 표(어느 포트에서 어느 MAC 이 들어왔는지)를
# SNMP 로 알려준다. 그 표를 읽어와 우리 목록의 MAC 과 맞추면
# "이 카메라 = 3번 스위치 12번 포트" 가 바로 나온다.
#
# 라이브러리는 안 쓴다. SNMP v2c 는 UDP 한 통이면 되고, 필요한 것은
# BER 인코딩 몇 줄뿐이라 외부 의존성을 늘릴 이유가 없다.
# ---------------------------------------------------------------------------

SNMP_PORT = 161

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"          # dot1dTpFdbPort
OID_Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"    # dot1qTpFdbPort (VLAN 별)
OID_BASE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"      # dot1dBasePortIfIndex

# MAC 표를 한 건도 못 읽었을 때, 스위치가 무엇까지 내주는지 확인하는 목록.
# 값이 전부 0 이면 스위치가 브리지 MIB 자체를 안 내주는 것이다 (저가형에서 흔하다).
# ifName 만 숫자가 나오면 SNMP 는 되는데 MAC 표만 없는 것이다.
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
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"             # ifSpeed (bps, 옛 장비용)
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"         # ifAlias (포트에 적어둔 설명)

# --- PoE (POWER-ETHERNET-MIB, RFC 3621) ------------------------------------
# 포트마다 전원을 얼마나 물려 보내고 있는지, 그리고 그 전원을 껐다 켤 수 있다.
# 표의 번호는 (그룹.포트) 두 마디다. 스택 안 한 스위치는 그룹이 거의 1 이다.
OID_POE_ADMIN  = "1.3.6.1.2.1.105.1.1.1.3"       # pethPsePortAdminEnable (1 켬 / 2 끔)
OID_POE_STATUS = "1.3.6.1.2.1.105.1.1.1.6"       # pethPsePortDetectionStatus
OID_POE_CLASS  = "1.3.6.1.2.1.105.1.1.1.10"      # pethPsePortPowerClassifications
OID_POE_MAIN_CAP = "1.3.6.1.2.1.105.1.3.1.1.2"   # pethMainPsePower (총 용량 W)
OID_POE_MAIN_USE = "1.3.6.1.2.1.105.1.3.1.1.4"   # pethMainPseConsumptionPower (지금 쓰는 W)
# 포트별 실제 소비 전력은 표준에 없다. 시스코는 따로 내준다 (mW).
OID_POE_CISCO_W = "1.3.6.1.4.1.9.9.402.1.2.1.7"  # cpeExtPsePortPwrConsumption

# --- 포트 관리 (IF-MIB) ----------------------------------------------------
OID_IF_TYPE  = "1.3.6.1.2.1.2.2.1.3"             # ifType (6 = 이더넷)
OID_IF_PHYS  = "1.3.6.1.2.1.2.2.1.6"             # ifPhysAddress (스위치 자신의 MAC)
OID_IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"             # ifAdminStatus (1 켬 / 2 잠금)
OID_IF_OPER  = "1.3.6.1.2.1.2.2.1.8"             # ifOperStatus (1 링크 있음 / 2 없음)
IF_TYPE_ETHERNET = 6

# --- 듀플렉스 (EtherLike-MIB) ----------------------------------------------
# 현장에서 제일 안 잡히는 고장이 이것이다. 속도는 1G 라고 뜨는데 실제로는
# 파일 하나 옮기는 데 몇 분이 걸린다. 링크는 붙어 있고, 핑도 가고, 화면에는
# 아무 빨간색도 없다. 원인은 양끝의 듀플렉스가 안 맞는 것이다.
#
# 한쪽을 손으로 "100M 전이중" 으로 박아 두면, 그 상대편은 협상 상대가 없어서
# 속도만 겨우 알아채고 듀플렉스는 규칙대로 '반이중' 으로 내려앉는다. 그러면
# 반이중 쪽은 늦은 충돌(late collision)이 나고, 전이중 쪽은 깨진 프레임을 본다.
# 둘 다 링크는 안 끊는다. 그래서 사람 눈에는 "그냥 느리다" 로만 보인다.
#
# 값은 1 모름 / 2 반이중 / 3 전이중. 0 은 우리가 '못 읽었다' 는 뜻으로 쓴다 —
# 이 MIB 를 아예 안 내주는 스위치가 많은데, 그걸 '전이중' 으로 채우면 이 도구가
# 확인하지도 않은 것을 확인했다고 말하게 된다.
OID_DUPLEX     = "1.3.6.1.2.1.10.7.2.1.19"       # dot3StatsDuplexStatus
OID_LATE_COLL  = "1.3.6.1.2.1.10.7.2.1.8"        # dot3StatsLateCollisions
DUPLEX_UNKNOWN, DUPLEX_HALF, DUPLEX_FULL = 1, 2, 3

POE_STATUS = {1: ("꺼짐", "disabled"), 2: ("장비 찾는 중", "searching"),
              3: ("급전 중", "delivering"), 4: ("고장", "fault"),
              5: ("시험", "test"), 6: ("고장(기타)", "otherFault")}

# 클래스별 최대 전력. 실제 소비를 못 읽을 때 이걸로 어림한다.
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
    """(태그, 값, 다음위치) 를 돌려준다."""
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
        if tag != 0xA2:                                 # GetResponse 만 받는다
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
        # 커뮤니티가 틀리면 스위치는 대꾸를 안 한다. 그것도 '없음'으로 받는다.
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
        # 0x02 INTEGER 말고도 숫자로 오는 것들이 있다. ifHighSpeed 는 Gauge32
        # (0x42) 다 — 이걸 안 챙기면 속도가 바이트뭉치로 나와서 어디선가 0 이 된다.
        if tag in (0x02, 0x41, 0x42, 0x43, 0x46):   # INTEGER·Counter32·Gauge32·TimeTicks·Counter64
            return _int_of(body)
        return body
    finally:
        sock.close()


SNMP_WALK_TRUNCATED = set()


def snmp_walk(ip, community, root, timeout=1.5, limit=8000):
    """GETNEXT 를 반복해 하위 항목을 전부 읽는다. {OID: (태그, 값)}.

    limit 에서 잘리면 그 사실을 SNMP_WALK_TRUNCATED 에 남긴다. MAC 표가
    잘리면 업링크에 달린 MAC 이 빠져서 "장비 한 대뿐인 포트" 로 보인다 —
    그 상태로 잠그면 그 아래가 통째로 내려간다. 조용히 넘어가면 안 된다.
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
                # 윈도우는 닫힌 UDP 포트에 ICMP 도달불가를 돌려주고, 그것이
                # ConnectionResetError 로 올라온다. 통째로 터뜨릴 이유가 없다.
                break
            except (IndexError, ValueError):
                # 엉뚱한 곳에서 온 짧은 패킷. 무시하고 여기까지 읽은 것을 쓴다.
                break
            # 표의 끝에서 멈춰야 한다. 멈출 이유는 셋이다.
            #  - 오류가 왔다 / 우리 표 밖으로 넘어갔다
            #  - endOfMibView·noSuchObject 같은 '없다' 표시가 왔다 (태그 0x80~0x82)
            #  - OID 가 앞으로 안 나갔다 (일부 장비가 같은 자리를 되돌려준다)
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
    """OID 꼬리의 십진 6마디를 MAC 문자열로."""
    parts = [int(x) for x in tail.split(".") if x != ""]
    if len(parts) != 6 or any(p > 255 for p in parts):
        return ""
    return "".join("%02x" % p for p in parts)


def snmp_port_map(ip, community="public", timeout=1.5, log=None):
    """스위치에서 MAC -> 포트 표를 읽어온다.

    돌려주는 것: {"name": 스위치 이름, "ports": {mac: {...}}, "count": n}
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

    # 다리 포트 번호 -> 인터페이스 번호 -> 사람이 읽는 포트 이름
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

    # 포트 속도. 기가 포트에 100M 으로 붙은 장비를 찾으려는 것이 목적이다.
    # 케이블 네 쌍 중 하나만 나가도 링크는 안 끊기고 조용히 100M 으로 떨어진다.
    # 눈으로는 절대 못 찾는데, 스위치는 알고 있다.
    speeds = {}
    for k, v in snmp_walk(ip, community, OID_IF_HIGH_SPEED, timeout).items():
        speeds[k.rsplit(".", 1)[-1]] = _int_of(v[1])          # 이미 Mbps
    if not speeds:                                            # 옛 장비는 ifSpeed 만 준다
        for k, v in snmp_walk(ip, community, OID_IF_SPEED, timeout).items():
            speeds[k.rsplit(".", 1)[-1]] = _int_of(v[1]) // 1000000

    # 듀플렉스도 여기서 같이 읽는다. 이 값이 장비 목록까지 따라가야, 카메라
    # 한 줄만 보고도 "속도는 1G 인데 반이중" 을 알아챌 수 있다. 포트 관리 창을
    # 따로 열어야만 보이면 그 고장은 영영 안 잡힌다.
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
        label = names.get(str(ifindex)) or ("포트 %s" % bridge_port)
        ports[mac] = {"port": label, "portNo": bridge_port,
                      "ifIndex": ifindex, "vlan": vlan,
                      "speed": speeds.get(str(ifindex)) or 0,
                      "duplex": duplexes.get(str(ifindex)) or 0,
                      "alias": aliases.get(str(ifindex), "")}

    # 요즘 스위치는 VLAN 별 표(dot1q)를, 옛날 것은 통합 표(dot1d)를 준다.
    #
    # 꼬리 생김새를 7마디(VLAN 1 + MAC 6)로 못박아 두면 안 된다. 제조사마다
    # 앞에 뭘 더 붙이는 곳이 있어서, 그러면 표를 읽고도 한 줄도 못 건진다.
    # MAC 은 언제나 **끝의 여섯 마디**다. 그 앞은 전부 VLAN 자리로 본다.
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

    # 한 건도 못 읽었으면, 스위치가 무엇까지 내주는지 세어서 로그에 남긴다.
    # 커뮤니티가 틀린 것과 "이 스위치는 MAC 표를 SNMP 로 안 내준다" 는 것을
    # 구분해야 한다. 앞은 고칠 수 있고 뒤는 못 고친다.
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

    # 기준 속도는 "제일 빠른 포트" 가 아니라 "제일 흔한 속도" 다.
    # 10G SFP 업링크가 하나 꽂혀 있으면 최고가 10000 이 되고, 그러면 멀쩡한
    # 1G 포트가 전부 느린 것으로 잡힌다. 대다수가 쓰는 속도가 그 스위치의
    # 본래 속도다.
    top = common_speed([info["speed"] for info in ports.values()])
    for info in ports.values():
        info["slow"] = bool(top >= 1000 and 0 < info["speed"] <= top // 4)

    # 두 말의 낱말 차례가 달라서 자리번호(%s) 대신 이름표를 쓴다.
    # PoE — 스위치가 어느 포트에 전원을 주고 있는지. 못 읽어도 그냥 넘어간다.
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
# PoE — 포트 전원 보기와 껐다 켜기
#
# 현장에서 제일 많이 하는 일 중 하나가 "먹통 된 카메라 전원 뽑았다 꽂기" 다.
# PoE 로 물려 있으면 그 전원은 스위치가 주고 있으므로, 스위치한테 껐다 켜라고
# 하면 사다리를 안 타도 된다.
#
# 위험한 동작이므로 규칙을 셋 둔다.
#   1. 끄기만 하는 기능은 만들지 않는다. 언제나 껐다 다시 켜는 한 동작뿐이다.
#   2. 중간에 무슨 일이 생겨도 마지막에 반드시 다시 켠다 (finally).
#   3. 껐는지 읽어서 확인한다. 못 껐으면 쓰기 권한이 없는 것이므로 바로 멈춘다.
# 어느 포트를 건드리면 안 되는지(내 PC, 업링크)는 부르는 쪽이 막는다.
# ---------------------------------------------------------------------------


def _snmp_set_int(ip, community, oid, value, timeout=1.5):
    """정수 한 개를 쓴다. 스위치가 돌려준 값을 그대로 돌려준다."""
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
                # 3 = badValue, 4 = readOnly, 6 = noAccess, 16/17 = 권한 없음
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
    """포트별 PoE 상태를 읽는다. {포트번호: {...}} 와 스위치 전체 소비 전력."""
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

    # 시스코는 포트별 실제 소비를 mW 로 내준다. 있으면 어림값을 덮는다.
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
    """우리가 아는 포트 번호에 맞는 PoE 표의 번호(그룹.포트)를 찾는다."""
    want = str(port_no)
    if want in poe_ports:                     # 번호가 한 마디인 스위치
        return want
    for index in poe_ports:
        if index.rsplit(".", 1)[-1] == want:  # 보통은 "1.12" 처럼 그룹이 앞에 붙는다
            return index
    return ""


def poe_restart(ip, community, poe_index, wait=6.0, timeout=1.5, log=None):
    """한 포트의 PoE 를 껐다 켠다. 카메라 전원을 뽑았다 꽂는 것과 같다."""
    say = log or (lambda _m: None)
    admin_oid = "%s.%s" % (OID_POE_ADMIN, poe_index)

    # 켜져 있다(admin)는 것과 실제로 전원을 주고 있다(status 3)는 것은 다르다.
    # 아무것도 안 물린 포트를 껐다 켜는 것은 의미가 없고, 잘못 짚었다는 뜻이다.
    if snmp_get(ip, community, "%s.%s" % (OID_POE_STATUS, poe_index), timeout) != 3:
        raise RuntimeError(T("이 포트는 지금 PoE 로 전원을 주고 있지 않습니다.",
                             "This port is not delivering PoE right now."))
    if snmp_get(ip, community, admin_oid, timeout) != 1:
        raise RuntimeError(T("이 포트의 PoE 가 이미 꺼져 있습니다.",
                             "PoE on this port is already switched off."))

    # 보낸 순간부터 "껐을 수도 있다" 로 친다. 확인을 받은 뒤에 이 깃발을 세우면,
    # 껐는데 확인 답장만 잃어버린 경우에 되돌리기를 건너뛴다 — 카메라는 꺼진 채로
    # 남고 화면에는 "못 껐습니다" 가 뜬다. 기사는 찾아볼 생각조차 안 하게 된다.
    turned_off = True
    restore_failed = False
    try:
        got = _snmp_set_int(ip, community, admin_oid, 2, timeout)
        # 쓴 값을 다시 읽어 확인한다. 답만 받고 실제로는 안 바뀌는 장비가 있다.
        if got != 2 or snmp_get(ip, community, admin_oid, timeout) != 2:
            raise RuntimeError(T("전원을 끄지 못했습니다. 쓰기 권한이 있는 "
                                 "커뮤니티인지 확인하십시오.",
                                 "Could not switch the power off. Check that the "
                                 "community has write access."))
        say(T("포트 %s 전원 끊음 — %.0f초 기다립니다.",
              "Port %s powered off — waiting %.0f seconds.") % (poe_index, wait))
        time.sleep(max(1.0, wait))
    finally:
        # 무슨 일이 있어도 다시 켠다. 여기서 실패하면 사람이 가야 한다.
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
                # 여기까지 왔으면 사람이 가야 한다. 성공이라고 말하면 기사가
                # 1분을 기다린 뒤에야 장비가 죽은 걸 알게 된다.
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
# 포트 관리 — 스위치의 물리 포트를 전부 보고, 안 쓰는 포트를 잠근다
#
# 준공 때 "안 쓰는 포트는 잠가 두었는가" 가 점검 항목이다. 랙에 랜선 하나만
# 꽂으면 아무나 망에 들어올 수 있기 때문이다. 스위치 웹에서 포트를 하나씩
# 눌러 끄는 일을 여기서 한 번에 한다.
#
# 잠그는 것은 PoE 껐다 켜기와 성격이 다르다. 껐다 켜는 것은 몇 초 뒤 저절로
# 돌아오지만, 잠그는 것은 잠긴 채로 두는 것이 목적이라 자동 복구가 없다.
# 관리 경로가 지나는 포트를 잠그면 SNMP 자체가 안 닿아 현장에 가야 한다.
# 그래서 어느 포트를 못 잠그는지는 부르는 쪽이 반드시 막아야 한다.
# ---------------------------------------------------------------------------


# 마지막으로 읽은 스위치 전체 PoE 전력. {스위치IP: {"used":..,"capacity":..}}
LAST_POE_MAIN = {}


def switch_name(ip, community="public", timeout=1.5):
    """스위치 이름(sysName). 없으면 설명 첫 줄, 그것도 없으면 IP 를 쓴다."""
    name = snmp_get(ip, community, OID_SYS_NAME, timeout)
    if name is None:
        descr = snmp_get(ip, community, OID_SYS_DESCR, timeout)
        name = descr.splitlines()[0][:40] if descr else ""
    return (name or "").strip() or ip


def _blank_port(index):
    """포트 한 칸의 기본값. 못 읽은 항목이 무엇으로 남는지가 여기서 정해진다.

    duplex 0 은 '못 읽었다' 이다. 1(모름)·2(반이중)·3(전이중)은 스위치가 한 말이고
    0 은 스위치가 아무 말도 안 한 것이다. 이 둘을 섞으면 EtherLike-MIB 를 아예
    안 내주는 스위치가 전부 '정상' 으로 보인다.
    """
    return {"index": index, "name": "", "alias": "", "speed": 0,
            "admin": 0, "oper": 0, "poeIndex": "", "poeStatus": 0,
            "poeAdmin": 0, "poeWatt": 0.0, "poeClass": 0,
            "poeEstimated": True, "macs": [], "duplex": 0, "lateColl": None}


def read_switch_ports(ip, community="public", timeout=1.5):
    """스위치의 물리 포트를 전부 읽는다. {ifIndex: {...}}."""
    def by_index(root):
        return {oid.rsplit(".", 1)[-1]: value
                for oid, value in snmp_walk(ip, community, root, timeout).items()}

    types = by_index(OID_IF_TYPE)
    ports = {}
    for index, value in types.items():
        if _int_of(value[1]) == IF_TYPE_ETHERNET:      # VLAN·루프백은 뺀다
            ports[index] = _blank_port(index)
    if not ports:                                      # ifType 을 안 주는 장비도 있다
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

    # 듀플렉스. dot3StatsIndex 는 ifIndex 와 같은 번호를 쓴다.
    #
    # 이 표를 통째로 안 내주는 스위치가 흔하다. 그러면 전부 0 인 채로 남고,
    # 화면과 리포트는 듀플렉스 이야기를 아예 꺼내지 않는다. "확인 못 함" 을
    # "이상 없음" 으로 바꿔 적지 않기 위해서다.
    try:
        for index, value in by_index(OID_DUPLEX).items():
            if index in ports:
                ports[index]["duplex"] = _int_of(value[1])
    except Exception:
        pass

    # 늦은 충돌. 반이중으로 앉은 포트에서만 물어본다.
    #
    # 표를 통째로 훑으면 48포트짜리에서 왕복이 48번 더 든다. 반이중이 아닌
    # 포트의 늦은 충돌은 어차피 볼 일이 없으니, 걸린 포트만 하나씩 묻는다.
    # 이 숫자가 0 보다 크면 짐작이 아니라 증거다 — 듀플렉스가 실제로 안 맞아서
    # 지금 프레임이 깨지고 있다는 뜻이다.
    half = [i for i, p in ports.items() if p["duplex"] == DUPLEX_HALF]
    for index in half[:24]:
        try:
            got = snmp_get(ip, community, "%s.%s" % (OID_LATE_COLL, index), timeout)
        except Exception:
            got = None
        if isinstance(got, int) and not isinstance(got, bool):
            ports[index]["lateColl"] = got

    # 포트마다 어느 MAC 이 들어오는지. 업링크(여러 개)와 내 포트를 여기서 가린다.
    #
    # 번호가 안 맞을 수 있다. 스위치가 dot1dBasePortIfIndex 를 안 주면 MAC 표의
    # "다리 포트 번호" 와 여기 ifIndex 가 다른 체계일 수 있기 때문이다. 그래서
    # 번호로 한 번, 포트 이름으로 한 번 — 두 갈래로 맞춰 본다.
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
            # 번호가 있다고 바로 믿으면 안 된다. 다리 포트 번호와 ifIndex 가
            # 다른 체계인데 우연히 겹치면, 업링크의 MAC 목록이 엉뚱한 포트에
            # 붙는다. 그러면 진짜 업링크는 비어 보여서 잠글 수 있게 된다.
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
        # 스위치 전체 공급/소비 전력. 리포트가 이걸 또 읽으러 가면 PoE MIB 가 없는
        # 스위치에서 한 번 더 통째로 멈춘다. 여기서 읽은 것을 그대로 남겨 둔다.
        LAST_POE_MAIN[ip] = dict(poe.get("main") or {}, at=time.time())
        for index, info in ports.items():
            found = poe_index_for(index, poe["ports"])
            if found:
                info["poeIndex"] = found
                info["poeStatus"] = poe["ports"][found]["status"]
                info["poeWatt"] = poe["ports"][found]["watt"]
                info["poeAdmin"] = poe["ports"][found]["admin"] or 0
                # 리포트에 "어림 15.4W" 와 "실측 4.2W" 를 구분해서 적기 위한 것.
                # 고객이 전력을 물으면 그 둘은 완전히 다른 대답이다.
                info["poeClass"] = poe["ports"][found]["class"]
                info["poeEstimated"] = poe["ports"][found]["estimated"]
    except Exception:
        # 이번에 못 읽었으면 지난번 값을 그대로 두면 안 된다. 리포트가 옛 숫자를
        # 지금 소비 전력이라고 적는다. 지워서 '모른다' 로 만든다.
        LAST_POE_MAIN.pop(ip, None)

    return ports


def set_poe_admin(ip, community, poe_index, on, timeout=1.5):
    """PoE 급전을 켜거나 끈 채로 둔다. 껐다 켜기(poe_restart)와 달리 그대로 남는다."""
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
    """포트를 잠그거나(up=False) 푼다(up=True). 쓴 값을 되읽어 확인한다."""
    oid = "%s.%s" % (OID_IF_ADMIN, ifindex)
    want = 1 if up else 2
    _snmp_set_int(ip, community, oid, want, timeout)
    got = snmp_get(ip, community, oid, timeout)
    if got == want:
        return True
    # 여기가 갈린다. 답이 아예 없으면(None) 잠그기가 먹혀서 우리 길이 끊겼을
    # 수도 있다. "안 바뀌었다" 고 말하면 기사가 다시 누르고, 이미 끊긴 줄도
    # 모른 채 계속 일한다. 제일 큰 사고를 제일 조용한 문구로 덮는 셈이다.
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
    """포트 하나의 지금 상태만 싸게 읽는다. 링크가 붙기를 기다릴 때 쓴다.

    포트를 풀어도 통신이 곧바로 살아나지는 않는다. 랜선 양끝이 속도를 다시
    맞추는 데(오토니고) 2~3초, 그다음 스위치가 루프를 확인하는 동안(STP)
    포트는 링크가 붙은 채로도 데이터를 안 흘린다 — 기본 설정이면 여기서만
    30초까지 간다. 그동안 화면이 "풀었습니다" 하고 끝나 버리면, 기사는
    카메라가 안 올라온다며 멀쩡한 포트를 다시 만지게 된다.
    """
    # 못 읽은 값은 None 으로 둔다. 0 으로 적으면 안 된다 — ifOperStatus 에 0 은
    # 없으므로 화면이 그걸 '링크 없음' 으로 읽고, 그 포트는 '빈 포트' 가 되어
    # '빈 포트 전부 잠그기' 의 대상이 된다. 카메라가 물린 포트가 그렇게 잠긴다.
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
    if out["speed"] is None:                 # 옛 장비는 ifSpeed(bps) 만 준다
        try:
            slow = snmp_get(ip, community, "%s.%s" % (OID_IF_SPEED, ifindex), timeout)
        except Exception:
            slow = None
        if isinstance(slow, int):
            out["speed"] = slow // 1000000
    out["read"] = out["oper"] is not None
    return out


def read_own_macs(ip, community="public", timeout=1.5):
    """스위치 자신의 MAC 들. 이게 보이는 포트는 관리 경로라 건드리면 안 된다."""
    out = set()
    for _, value in snmp_walk(ip, community, OID_IF_PHYS, timeout).items():
        if value[0] == 0x04 and len(value[1]) == 6:
            out.add("".join("%02x" % b for b in value[1]))
    out.discard("000000000000")
    return out


def read_fdb(ip, community="public", timeout=1.5):
    """스위치의 MAC 표만 읽는다. {ifIndex 문자열: [mac, ...]}.

    포트 관리 화면이 "이 포트를 잠가도 되는가" 를 스스로 판단하려면, 우리
    장비 목록이 아니라 스위치가 아는 것을 봐야 한다. 스캔을 안 돌린 상태에서도
    업링크와 내 포트를 알아볼 수 있어야 하기 때문이다.
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
    """이 스위치의 '본래' 속도. 가장 많이 나오는 값, 같으면 빠른 쪽.

    최고 속도를 기준으로 삼으면 안 되는 이유가 둘이다.
      - 10G SFP 업링크 하나 때문에 멀쩡한 1G 포트가 전부 느린 것으로 잡힌다.
      - CCTV 현장은 카메라가 원래 100M 인 곳이 많다. 그런 스위치에서 100M 는
        정상이므로 경고를 띄우면 안 된다.
    대다수가 붙어 있는 속도가 그 현장의 기준선이다.
    """
    counts = {}
    for value in speeds:
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return 0
    return max(counts, key=lambda v: (counts[v], v))


def apply_port_map(result):
    """읽어온 표를 지금 목록에 붙인다. (붙은 장비 수, 느린 포트 목록)을 돌려준다.

    스위치가 여러 대인 현장에서 조심할 게 하나 있다. 3층 스위치에 물린 카메라는
    1층 스위치의 MAC 표에도 올라온다 — 업링크를 타고 들어오기 때문이다. 그래서
    나중에 조회한 스위치가 앞서 찾은 진짜 자리를 업링크 포트로 덮어쓴다.

    한 포트에 MAC 이 하나만 보이면 그게 장비가 실제로 꽂힌 자리다. 여럿 보이면
    그 아래 다른 스위치가 달린 업링크다. 그러니 이미 붙여둔 자리가 더 '혼자'
    이면 그대로 둔다.
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
            # 같은 스위치를 다시 읽은 것이면 언제나 새 값이 맞다 (장비가 옮겨졌을
            # 수도 있다). 다른 스위치일 때만, 이미 아는 자리가 더 좁으면 지킨다.
            # 스위치 구분은 IP 로 한다 — sysName 은 공장 초기값이면 겹친다.
            same_switch = dev.get("swhost") == result.get("ip", "")
            if dev.get("swport") and not same_switch:
                if (dev.get("swshared") or 1) <= shared:
                    continue          # 이미 더 좁은 자리를 알고 있다
            dev["swshared"] = shared
            dev["swport"] = info["port"]
            dev["swname"] = result["name"]
            # 이름(sysName)은 공장 초기값이면 두 대가 똑같다. IP 로도 기억한다.
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
                             "speed": info.get("speed") or 0})
            hit += 1
    slow.sort(key=lambda row: row["ip"])
    return hit, slow


# ---------------------------------------------------------------------------
# 빈 IP
#
# 대역을 훑고 나면 "쓰는 IP"는 목록에 있다. 그 나머지가 비어 있는 자리다.
# 무엇을 어디에 넣을지는 사람이 정한다 — 도구는 응답하지 않은 자리만 알려준다.
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
    # 연속된 자리는 묶어서 보여준다. 200줄보다 "13-72" 한 줄이 낫다.
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
    # complete 가 False 면 이 목록을 배정에 쓰면 안 된다. 화면과 CSV 가
    # 그렇게 말하도록 같이 넘긴다.
    return {"scanned": len(scanned), "used": len(used), "free": free,
            "blocks": blocks, "complete": done}


def export_candidate_ips(path):
    """Excel에서 배정 계획을 바로 적을 수 있도록 후보 IP를 한 행씩 저장한다.

    스캔이 끝까지 안 갔으면 그 사실을 파일 맨 위에 적는다. 이 CSV 는 현장에서
    그대로 배정표로 쓰인다 — 어디서 나온 목록인지 파일만 보고 알 수 없으면
    며칠 뒤에는 아무도 기억을 못 한다.
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
    """현장 리포트 한 장. 브라우저로 열어 그대로 인쇄하거나 PDF 로 뽑는다.

    현장에서 필요한 것은 데이터 덤프가 아니라 "무엇이 충돌했고 무엇을 손댔는지"
    한 장이다. 그래서 충돌부터 맨 위에 놓고, 빈 IP 를 끝에 붙인다.
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
                    facts.append(kind_show(d["os"]))   # TTL 숫자는 이미 OS 로 옮겼다
                # 모델 칸에 이름을 끌어다 썼으면 아래에 또 쓰지 않는다
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

    # 후보 IP의 실제 배정 계획은 HTML 보고서가 아니라 별도 CSV에서 관리한다.
    # CSV는 IP 한 줄마다 용도와 메모를 채울 수 있어 Excel로 열어 쓰기 좋다.

    parts.append("<footer>%s v%s &nbsp;·&nbsp; %s</footer>"
                 % (esc(APP_NAME), esc(APP_VER),
                    esc(T("훑은 주소 %d개", "%d addresses scanned") % empty["scanned"])))
    parts.append("</body></html>")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))
    return path


# ---------------------------------------------------------------------------
# 준공·점검 리포트 (엑셀)
# ---------------------------------------------------------------------------
# openpyxl 을 쓰지 않는다. 쓰면 빌드하는 사람이 pip 를 하나 더 깔아야 하고,
# 그걸 잊은 채로 exe 를 뽑으면 현장에서 리포트 버튼만 죽는다. xlsx 는 zip 안에
# XML 몇 장이라 필요한 만큼만 직접 쓴다. SNMP 를 직접 짠 것과 같은 이유다.

# XML 1.0 이 금지하는 제어문자. 스위치 설명(ifAlias)에 NUL 이 섞여 오거나,
# 워드에서 붙여넣은 소견에 수직탭이 끼면 파일이 통째로 안 열린다. 고객 앞에서
# "파일이 손상되었습니다" 를 보게 되는데, 그때 고칠 방법이 없다.
_XL_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_XL_CELL_MAX = 32000        # 엑셀 한 칸 한계는 32767 자


def _xl_text(value):
    """엑셀 칸에 넣어도 되는 글자로 다듬는다."""
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
    {},                                     # 0 보통
    {"b": 1},                               # 1 굵게
    {"b": 1, "sz": 16},                     # 2 제목
    {"sz": 10, "color": "6B7280"},          # 3 흐린 설명
    {"b": 1, "color": "FFFFFF"},            # 4 표 머리
    {"b": 1, "color": "B42318"},            # 5 빨강 굵게
    {"sz": 9, "color": "98A2B3"},           # 6 각주
    {"b": 1, "sz": 12},                     # 7 소제목
    {"sz": 9},                              # 8 작은 글씨
]
_XL_FILLS = [None, None,                    # 0,1 은 엑셀이 예약해 둔 자리
             "44546A", "FEF0C7", "FEE4E2", "E7F1FB", "F2F4F7", "D1FADF"]
# 이름 -> (글꼴, 채움, 테두리, 가로, 줄바꿈, 세로)
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
    """엑셀 시트 한 장. 셀은 값이거나 (값, 서식이름) 이다."""

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
        return len(self.rows)          # 1부터. 엑셀 행 번호와 같다.

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
    """시트 목록을 xlsx 파일 하나로 묶는다."""
    if not sheets:
        raise ValueError(T("내보낼 내용이 없습니다.", "Nothing to export."))
    names, used = [], set()
    for sheet in sheets:                       # 시트 이름이 겹치면 엑셀이 안 연다
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
    """듀플렉스를 사람 말로. 못 읽었으면 빈 문자열 — 아무 말도 하지 않는다.

    여기서 0 을 '전이중' 으로 채우고 싶은 유혹이 있다. 요즘 장비는 대개
    전이중이니 맞을 확률이 높다. 그래도 안 된다. 이 도구가 하는 말은 준공
    문서에 그대로 실린다. 확률이 높은 추측과 확인한 사실을 같은 칸에 적으면,
    다음에 진짜로 확인한 값도 같이 못 믿게 된다.
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
    """지금 링크가 붙어 있는데 반이중으로 앉은 포트인가.

    링크가 없는 포트의 듀플렉스는 의미가 없다. 꽂히지도 않은 포트에 경고를
    붙이면 빈 포트가 전부 빨개진다.
    """
    return (int(info.get("duplex") or 0) == DUPLEX_HALF
            and int(info.get("oper") or 0) == 1)


def speed_label(mbps):
    """포트 속도를 사람 말로. 0 은 링크가 없다는 뜻이다."""
    value = int(mbps or 0)
    if value <= 0:
        return "-"
    if value >= 1000 and value % 1000 == 0:
        return "%dG" % (value // 1000)
    return "%dM" % value


def _plate_layout(ports, slow_keys):
    """스위치 앞면 그림. 홀수는 윗줄, 짝수는 아랫줄 — 실물과 같은 배치다.

    번호가 깔끔하지 않은 장비(이름에서 번호를 못 뽑는 경우)는 그냥 순서대로
    두 줄에 늘어놓는다. 틀린 그림을 그리느니 단순한 그림이 낫다.
    """
    listed = sorted(ports.values(), key=port_number)
    numbers = [port_number(p) for p in listed]
    # 번호대로 자리를 잡되, 번호가 터무니없이 크면(VLAN·루프백이 섞였거나
    # ifIndex 가 수백만이면) 그 범위만큼 빈 칸을 그리다 문서가 터진다.
    tidy = (bool(numbers) and len(set(numbers)) == len(numbers)
            and min(numbers) >= 1 and max(numbers) <= len(numbers) * 2 + 8)

    slots = {}                      # (윗줄0/아랫줄1, 칸) -> 포트
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
    """포트 한 칸의 글자와 색."""
    no = port_number(info)
    text = str(no) if no else (info.get("name") or "")[-4:]
    if int(info.get("admin") or 1) != 1:
        return ("%s ✕" % text, "pDown")          # 사람이 잠가 놓은 포트
    if int(info.get("oper") or 0) != 1:
        return (text, "pIdle")                   # 아무것도 안 꽂힘 — 테두리만
    if is_half_duplex(info):
        # 속도 저하보다 앞에 둔다. 둘 다면 이쪽이 원인일 때가 많다.
        return ("%s½" % text, "pSlow")       # 반이중 — 양끝 설정이 안 맞음
    if port_key(info) in slow_keys:
        return (text, "pSlow")                   # 예전보다 느려짐
    if float(info.get("poeWatt") or 0) > 0:
        return (text, "pPoe")
    return (text, "pLive")


def export_xlsx(path, site="", note="", author="", switches=None, missed=None):
    """준공·점검 리포트 한 부. 시트 다섯 장.

    현장에서 이걸 손으로 엑셀에 치고 있다. 스캔 한 번이면 다 있는 내용이다.
    """
    switches = switches or []
    missed = missed or []          # 못 읽은 스위치 [(IP, 이유)]
    groups = STORE.by_ip()
    conflicts = [g for g in groups if g["conflict"]]
    devices = [d for g in groups for d in g["devices"]]
    empty = free_ips()
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    # 포트별로 어떤 장비가 물려 있는지. 스위치 IP + 포트 이름으로 묶는다
    # (이름만으로 묶으면 스위치 두 대의 같은 번호 포트가 섞인다).
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

    # ---- 1. 점검 소견 ------------------------------------------------------
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

    # 용량을 안 알려주는 스위치의 소비만 더하면 사용률이 100%% 를 넘어간다.
    # 둘 다 알려준 스위치만 넣고 센다.
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
        # 못 읽은 것을 조용히 빼면, 이 문서는 "그 스위치는 문제 없었다" 고
        # 거짓말하는 셈이 된다. 못 읽었다고 맨 위에 적는다.
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
    # 반이중. 속도 저하보다 찾기 어려운 고장이라 따로 세워 적는다.
    #
    # "1G 로 뜨는데 느리다" 는 신고가 들어오면 대개 이것이다. 속도 칸만 보고
    # 정상이라고 넘긴 뒤 카메라를 교체하러 다시 나오는 일이 실제로 생긴다.
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
    # 처음 온 현장은 비교할 지난 기록이 없다. 속도 저하가 '없는' 게 아니라
    # '아직 모르는' 것이다. 그걸 안 적으면 이 문서는 확인하지도 않은 것을
    # 확인했다고 말하는 셈이 된다.
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
    # 듀플렉스를 한 포트도 못 읽었으면 그 사실을 적는다. 안 적으면 이 문서에
    # '반이중' 항목이 없다는 것을 사람은 "확인했고 문제 없었다" 로 읽는다.
    # EtherLike-MIB 를 아예 안 내주는 스위치가 흔하다.
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

    # ---- 2. 장비 목록 ------------------------------------------------------
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

    # ---- 3. 스위치 포트 배치 -----------------------------------------------
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
        for start in range(0, columns, 24):       # 48포트 넘으면 줄을 바꾼다
            stop = min(start + 24, columns)
            for line in (0, 1):
                cells = []
                for col in range(start, stop):
                    info = slots.get((line, col))
                    cells.append(_plate_cell(info, slow_keys) if info else None)
                number = plate.row(*cells)
                plate.heights[number] = 22
            plate.blank()
        # 포트 하나하나
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
                      # 못 읽었으면 빈 칸으로 둔다. 빈 칸은 "안 봤다" 로 읽히고,
                      # '전이중' 이라고 적으면 "봤고 정상이다" 가 된다.
                      (duplex_label(info.get("duplex")) if up else "",
                       "bad" if half else "cc"),
                      (T("연결", "up") if up else T("없음", "down"), "cc"),
                      (T("잠김", "locked") if locked else T("열림", "open"),
                       "warn" if locked else "cc"),
                      (round(float(info.get("poeWatt") or 0), 1) or "", "cn"),
                      (behind, style))
        plate.blank(2)

    # ---- 4. PoE 전력 -------------------------------------------------------
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

    # ---- 5. 빈 IP ----------------------------------------------------------
    spare = XlSheet(T("남은 IP", "Free IPs"))
    spare.width((0, 18), (1, 18), (2, 10), (3, 22), (4, 30))
    spare.row((T("응답 없는 주소 — 배정에 쓸 수 있습니다", "Addresses with no reply"),
               "sect"))
    spare.merge(1, 0, 1, 4)
    if not empty.get("complete"):
        # 준공 문서에 "빈 IP" 라고 적힌 것을 고객이 그대로 배정에 쓴다.
        # 안 훑은 주소가 섞여 있으면 그건 문서가 아니라 사고다.
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
# 단독 실행
#
# 화면은 일렉트론(electron/)이 그린다. 이 파일은 그 뒤에서 도는 엔진이다.
# 예전에는 여기에 tkinter 화면이 같이 들어 있었지만, 일렉트론으로 옮긴 뒤로는
# 아무도 쓰지 않으면서 이미 지운 함수를 부르고 있어 들어냈다.
# ---------------------------------------------------------------------------


def main():
    """엔진 점검용. 실제 화면은 electron/ 쪽에서 띄운다."""
    parser = argparse.ArgumentParser(description="%s 엔진" % APP_NAME)
    parser.add_argument("mac", nargs="?", help="MAC 하나를 넣으면 무슨 장비인지 알려줍니다.")
    args = parser.parse_args()

    print("%s v%s — 엔진" % (APP_NAME, APP_VER))
    table = _oui_table()
    print("  제조사 등록부 : %s" % ("{:,}개".format(len(table)) if table else "읽지 못했습니다"))
    loaded = BOOK.load()
    print("  장비 사전     : %s" % (
        "%d개 앞자리 (%s)" % (len(BOOK.index), os.path.basename(BOOK.loaded_from))
        if loaded else "없습니다"))

    if args.mac:
        info = describe(args.mac)
        print()
        print("  %s" % dash_mac(args.mac))
        print("    제조사 : %s" % info["vendor"])
        print("    종류   : %s" % (info["kind"] or "(포트 스캔으로 판단)"))
        if info["note"]:
            print("    메모   : %s" % info["note"])
        return

    print()
    print("  화면은 일렉트론에서 띄웁니다:  cd electron && npm start")


if __name__ == "__main__":
    main()
