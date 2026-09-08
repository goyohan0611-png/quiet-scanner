#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ArpDupScan - precise duplicate-IP scanner

Copyright (C) 2026 고요한.  GPLv2 or later; see LICENSE.

A normal IP scanner shows only one of the devices in a conflict, because the
OS ARP table keeps one MAC per IP. This script bypasses that table and reads
every ARP reply off the wire, so every device sharing an IP shows up.

Requirements (Windows):
    1) Install Npcap    https://npcap.com   (tick "WinPcap API-compatible mode")
    2) pip install scapy
    3) Run from an administrator command prompt

Usage:
    # how many devices are sitting on one IP
    python ArpDupScan.py 192.168.1.64

    # sweep a whole range and pick out the conflicting IPs
    python ArpDupScan.py 192.168.1.0/24 --sweep

    # name the interface (when the machine has several)
    python ArpDupScan.py 192.168.1.64 -i "Ethernet"

    # just list the interfaces
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
    print("[X] scapy is not installed.  ->  pip install scapy")
    sys.exit(1)


# A small OUI table: only the vendors that turn up often on site.
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
    return OUI.get(mac.lower()[:8], "Unknown")


def probe(target: str, iface=None, timeout=3, retry=2):
    """ARP the target (an IP or CIDR) and collect every (IP, MAC) that answers."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    ans, _ = srp(
        pkt,
        timeout=timeout,
        retry=retry,
        iface=iface,
        # The point of the whole thing: take every reply, not just the first
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
        description="Precise duplicate-IP scanner - finds every device sharing an IP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("target", nargs="?", help="target IP or range (e.g. 192.168.1.64 or 192.168.1.0/24)")
    ap.add_argument("-i", "--iface", help="network interface to use")
    ap.add_argument("-t", "--timeout", type=int, default=3, help="seconds to wait for replies (default 3)")
    ap.add_argument("-r", "--retry", type=int, default=2, help="number of retries (default 2)")
    ap.add_argument("--sweep", action="store_true", help="sweep the whole range and list only the conflicting IPs")
    ap.add_argument("--csv", help="path to save the results as CSV")
    ap.add_argument("--list-ifaces", action="store_true", help="list the interfaces and exit")
    args = ap.parse_args()

    if args.list_ifaces:
        print("Available interfaces:")
        for name in get_if_list():
            print("  -", name)
        try:
            print("\nDefault interface:", conf.iface)
        except Exception:
            pass
        return

    if not args.target:
        ap.print_help()
        return

    print()
    print("=" * 60)
    print("  ARP conflict scan  |  target: %s" % args.target)
    print("=" * 60)

    try:
        table = probe(args.target, iface=args.iface, timeout=args.timeout, retry=args.retry)
    except PermissionError:
        print("[X] Not enough privileges. Run this again as administrator.")
        sys.exit(1)
    except OSError as e:
        print("[X] Network error: %s" % e)
        print("    Check that Npcap is installed and that -i names the right interface.")
        sys.exit(1)

    if not table:
        print("[!] Nothing answered. Check the cable, PoE power, range and interface.")
        sys.exit(1)

    rows = []
    dup_found = False

    for ip, macs in table.items():
        mac_list = list(macs.keys())
        if args.sweep and len(mac_list) < 2:
            continue  # in sweep mode only the conflicts are of interest

        marker = "  <<< %d in conflict" % len(mac_list) if len(mac_list) > 1 else ""
        if len(mac_list) > 1:
            dup_found = True

        print()
        print("[ %s ]%s" % (ip, marker))
        for n, mac in enumerate(mac_list, 1):
            print("   %2d. %s   %s" % (n, mac.upper(), vendor_of(mac)))
            rows.append({"IP": ip, "MAC": mac.upper(), "Vendor": vendor_of(mac),
                         "DevicesOnThisIP": len(mac_list),
                         "SeenAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

    print()
    if args.sweep and not rows:
        print("[OK] No duplicate IPs in this range.")
        return

    if dup_found:
        print("-" * 60)
        print("Next — paste the commands below into an administrator PowerShell")
        print("to change the IPs one device at a time, without unplugging anything.")
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
        print("[OK] No conflicts. One device per IP.")

    if args.csv and rows:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["IP", "MAC", "Vendor", "DevicesOnThisIP", "SeenAt"])
            w.writeheader()
            w.writerows(rows)
        print("[OK] CSV saved: %s" % args.csv)


if __name__ == "__main__":
    main()
