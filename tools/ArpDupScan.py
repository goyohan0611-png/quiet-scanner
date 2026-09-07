#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ArpDupScan - IP 충돌 정밀 스캐너

일반 IP 스캐너가 충돌난 장비를 한 대밖에 못 보는 이유는, OS의 ARP 테이블이
IP 하나당 MAC 하나만 저장하기 때문이다. 이 스크립트는 OS 테이블을 거치지 않고
ARP 응답 패킷을 직접 전부 받아서, 같은 IP를 쓰는 장비를 남김없이 찾아낸다.

필요한 것 (Windows):
    1) Npcap 설치        https://npcap.com   ("WinPcap API-compatible mode" 체크)
    2) pip install scapy
    3) 관리자 권한 명령 프롬프트에서 실행

사용법:
    # 특정 IP에 몇 대가 물려 있는지
    python ArpDupScan.py 192.168.1.64

    # 대역 전체를 훑어서 충돌난 IP를 자동으로 찾아내기
    python ArpDupScan.py 192.168.1.0/24 --sweep

    # 인터페이스를 직접 지정 (여러 랜카드가 있을 때)
    python ArpDupScan.py 192.168.1.64 -i "이더넷"

    # 사용 가능한 인터페이스 목록만 보기
    python ArpDupScan.py --list-ifaces
"""

import argparse
import csv
import sys
from collections import OrderedDict
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, conf, get_if_list
except ImportError:
    print("[X] scapy가 없습니다.  ->  pip install scapy")
    sys.exit(1)


# 현장에서 자주 보는 제조사만 추린 미니 OUI 표
OUI = {
    "44:47:cc": "Hikvision", "bc:ad:28": "Hikvision", "c0:56:e3": "Hikvision",
    "4c:bd:8f": "Hikvision", "28:57:be": "Hikvision", "58:03:fb": "Hikvision",
    "a4:14:37": "Hikvision", "e0:ca:3c": "Hikvision", "54:c4:15": "Hikvision",
    "90:02:a9": "Dahua", "3c:ef:8c": "Dahua", "4c:11:bf": "Dahua",
    "e0:50:8b": "Dahua", "08:ed:ed": "Dahua", "14:a7:8b": "Dahua",
    "24:52:6a": "Dahua", "bc:32:5f": "Dahua",
    "00:09:18": "Hanwha", "e4:30:22": "Hanwha", "00:16:6c": "Hanwha",
    "34:e6:d7": "Hanwha",
    "00:03:c5": "IDIS",
    "00:40:8c": "Axis", "ac:cc:8e": "Axis", "b8:a4:4f": "Axis",
    "48:ea:63": "Uniview", "6c:f1:7e": "Uniview",
    "00:07:5f": "Bosch", "00:1c:44": "Bosch",
    "00:80:45": "Panasonic", "08:00:23": "Panasonic",
    "30:f9:ed": "Sony", "54:42:49": "Sony",
    "00:05:a6": "Extron", "00:10:7f": "Crestron", "00:60:9f": "AMX",
    "00:1d:56": "Kramer", "7c:2e:0d": "Blackmagic", "00:04:a5": "Barco",
    "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti", "74:ac:b9": "Ubiquiti",
    "fc:ec:da": "Ubiquiti", "68:d7:9a": "Ubiquiti",
    "50:c7:bf": "TP-Link", "ec:08:6b": "TP-Link", "a4:2b:b0": "TP-Link",
    "60:a4:b7": "TP-Link",
    "00:1b:d4": "Cisco", "00:23:04": "Cisco", "6c:41:6a": "Cisco",
    "20:4e:7f": "Netgear", "a0:40:a0": "Netgear",
    "24:de:c6": "Aruba", "6c:f3:7f": "Aruba",
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:15:5d": "Hyper-V",
}


def vendor_of(mac: str) -> str:
    return OUI.get(mac.lower()[:8], "미상")


def probe(target: str, iface=None, timeout=3, retry=2):
    """대상(IP 또는 CIDR)에 ARP 요청을 뿌리고 응답한 (IP, MAC)을 전부 수집."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    ans, _ = srp(
        pkt,
        timeout=timeout,
        retry=retry,
        iface=iface,
        # 핵심: 응답 하나 받고 끝내지 않고 전부 받는다
        multi=True,
        verbose=0,
    )

    table = OrderedDict()
    for _, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc.lower()
        table.setdefault(ip, OrderedDict())[mac] = True
    return table


def main():
    ap = argparse.ArgumentParser(
        description="IP 충돌 정밀 스캐너 - 같은 IP를 쓰는 장비를 전부 찾아낸다",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("target", nargs="?", help="대상 IP 또는 대역 (예: 192.168.1.64 또는 192.168.1.0/24)")
    ap.add_argument("-i", "--iface", help="사용할 네트워크 인터페이스 이름")
    ap.add_argument("-t", "--timeout", type=int, default=3, help="응답 대기 시간(초). 기본 3")
    ap.add_argument("-r", "--retry", type=int, default=2, help="재시도 횟수. 기본 2")
    ap.add_argument("--sweep", action="store_true", help="대역 전체를 훑어 충돌 IP만 골라낸다")
    ap.add_argument("--csv", help="결과를 CSV로 저장할 경로")
    ap.add_argument("--list-ifaces", action="store_true", help="인터페이스 목록만 출력하고 종료")
    args = ap.parse_args()

    if args.list_ifaces:
        print("사용 가능한 인터페이스:")
        for name in get_if_list():
            print("  -", name)
        try:
            print("\n기본 인터페이스:", conf.iface)
        except Exception:
            pass
        return

    if not args.target:
        ap.print_help()
        return

    print()
    print("=" * 60)
    print("  ARP 정밀 스캔  |  대상: %s" % args.target)
    print("=" * 60)

    try:
        table = probe(args.target, iface=args.iface, timeout=args.timeout, retry=args.retry)
    except PermissionError:
        print("[X] 권한 부족입니다. 관리자 권한으로 다시 실행해 주십시오.")
        sys.exit(1)
    except OSError as e:
        print("[X] 네트워크 오류: %s" % e)
        print("    Npcap이 설치돼 있는지, -i 로 올바른 인터페이스를 지정했는지 확인하십시오.")
        sys.exit(1)

    if not table:
        print("[!] 응답한 장비가 없습니다. 랜선/PoE 전원/대역/인터페이스를 확인하십시오.")
        sys.exit(1)

    rows = []
    dup_found = False

    for ip, macs in table.items():
        mac_list = list(macs.keys())
        if args.sweep and len(mac_list) < 2:
            continue  # sweep 모드에서는 충돌난 것만 본다

        marker = "  <<< 충돌 %d대" % len(mac_list) if len(mac_list) > 1 else ""
        if len(mac_list) > 1:
            dup_found = True

        print()
        print("[ %s ]%s" % (ip, marker))
        for n, mac in enumerate(mac_list, 1):
            print("   %2d. %s   %s" % (n, mac.upper(), vendor_of(mac)))
            rows.append({"IP": ip, "MAC": mac.upper(), "제조사": vendor_of(mac),
                         "동일IP장비수": len(mac_list),
                         "시각": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

    print()
    if args.sweep and not rows:
        print("[OK] 대역 안에 IP 충돌은 없습니다.")
        return

    if dup_found:
        print("-" * 60)
        print("다음 단계 — 아래 명령을 관리자 PowerShell에 붙여넣으면")
        print("장비를 뽑았다 꽂지 않고 한 대씩 순차로 IP를 바꿀 수 있습니다.")
        print("-" * 60)
        for ip, macs in table.items():
            mac_list = list(macs.keys())
            if len(mac_list) < 2:
                continue
            quoted = ",".join("'%s'" % m.upper().replace(":", "-") for m in mac_list)
            print()
            print("  .\\IPFix.ps1 -Ip %s -Macs %s -NewIpStart 192.168.10.101" % (ip, quoted))
        print()
    else:
        print("[OK] 충돌 없음. 각 IP에 장비 한 대씩만 붙어 있습니다.")

    if args.csv and rows:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["IP", "MAC", "제조사", "동일IP장비수", "시각"])
            w.writeheader()
            w.writerows(rows)
        print("[OK] CSV 저장: %s" % args.csv)


if __name__ == "__main__":
    main()
