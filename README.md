# Quiet Scanner

**Sort out IP conflicts without unplugging a single cable.**

---

## Why this exists

CCTV and AV gear ships with the same factory IP. Hang eight cameras off one
switch and all eight insist they are `192.168.0.13`.

**A normal IP scanner shows you exactly one of them.** Windows keeps one MAC per
IP in its ARP table, so the other seven simply do not exist as far as the scanner
is concerned.

So this is what happens on site:

> unplug everything → plug one in → open its web page → change the IP →
> plug the next one in → repeat

Do that forty times from the top of a ladder and the day is gone.

**This tool does it without touching a cable.**

---

## How

**1. See every device in the conflict**

Raw ARP replies are read off the wire instead of asking the OS for its ARP table.
However many devices share an IP, all of them show up.

```
▼ 192.168.0.13   [4 in conflict]
    BC-AD-28-11-22-33   Hikvision   IP camera / NVR   DS-2CD2143G0-I
    BC-AD-28-44-55-66   Hikvision   IP camera / NVR   DS-2CD2043G2-I
    90-02-A9-AA-BB-CC   Dahua       DVR / NVR         IPC-HDW2431T
    E4-30-22-DE-AD-01   Hanwha      IP camera         XNV-6081
```

**2. Isolate one of them**

`Isolate this device only` pins that IP to one MAC with a static ARP entry.
From then on, connecting to that IP reaches **that one device**.

**3. Open its web page and change the IP**

Change it, save, release, move to the next device. No cable was touched.

---

## What makes it different

| | Normal IP scanner | Quiet Scanner |
|---|---|---|
| Devices sharing one IP | shows one | **shows all of them** |
| Isolating one of them | no | **yes** |
| Working out what a device is | MAC vendor | **ONVIF · ports · mDNS · UPnP** |
| Camera snapshot preview | no | **yes** |

A few tools *detect* conflicts. Detecting is where they stop. This one takes you
all the way to "right, now change this one's IP".

---

## Features

**Finding**

- Range scan (`192.168.0.1-254` and CIDR)
- Several ranges at once — `192.168.0.1-254, 192.168.1.1-254`
- Conflicting IPs detected and sorted to the top
- Choose the ports to scan (`80,443,8000-8010`)
- **Free IPs** — every unused address in the scanned range, one per line

**Identifying**

- **58,471 vendors** from the IEEE registry, built in — works offline
- Device book — MAC prefix to device type, editable on site
- Reverse DNS · NetBIOS name · reply time · OS guessed from TTL
- mDNS (Bonjour) and SSDP (UPnP) — devices announce their own name, model, serial
- ONVIF probe for cameras; model pulled from the web title and auth realm
- Camera snapshot preview (ONVIF)
- **Switch port lookup (SNMP)** — reads the switch's MAC table and shows which
  port each device is on. Read-only

**Fixing**

- Isolate one device at a time, open it, change the IP
- Static ARP entries left behind by a crash are cleaned up on the next start

**Recording**

- **HTML site report** — conflicts, device list and free IPs on one page,
  ready to print or save as PDF
- JSON · CSV · XML export
- Save a baseline and compare — **what appeared and what went missing**
- Search, sort, and choose which columns you want to see

---

## Device book

The MAC gets you as far as `Hikvision`. The device book takes it further.

```
BC:AD:28  →  Hikvision  ·  IP camera / NVR
00:05:A6  →  Extron     ·  AV equipment
00:10:7F  →  Crestron   ·  Controller
```

**150 brands / roughly 2,600 prefixes** ship with it — CCTV, AV, audio,
projectors, networking, printers, access control, industrial gear.

Met something new? **Right-click → Add to device book.** From the next site on,
it is named the moment you scan.

| Prefix entered | Applies to |
|---|---|
| `BC-AD-28` (6 digits) | **every device** from that vendor |
| `BC-AD-28-11-22-33` (12 digits) | **that one device** |

The book is a single file, `src/device-book.json`. Anything you add on site goes
to `src/device-book.local.json`, which stays out of the repository. Pass it around your team, or send
additions back here and the next person benefits.

> Credentials and stream URLs are deliberately not stored. They differ per
> firmware, a wrong value is worse than none, and a public file is no place for
> a password.

---

## Install

**Requirements**

| | |
|---|---|
| Windows 10 / 11 | 64-bit |
| [Npcap](https://npcap.com) | needed to work with ARP directly. Tick **"WinPcap API-compatible mode"** during install |
| Administrator | needed for isolation (static ARP) |

Npcap is **not bundled** — install it yourself; it is free for up to 5 devices.
([why](docs/third-party.md))

**From the installer**

Run `electron/installer/Quiet Scanner Setup 3.0.0.exe`.

**From source**

```
Python 3.12  ·  Node.js LTS  ·  pip install pyinstaller scapy
```

```
build.bat
```

---

## Using it

1. Pick an interface, check the range, hit **Scan range**
2. Conflicting IPs appear at the top, in red
3. Right-click a device → **Identify device**
4. **Isolate this device only** → open it in a browser → change its IP
5. **Release isolation** → next device
6. **Export** a site report when you are done

**Tip** — you will be hitting the same IP for several different devices, so use a
private browsing window. Otherwise the previous device's session gets in the way.

---

## Language

Korean and English, throughout — interface, reports and the built-in user guide.
It picks by your Windows language on first run; the button in the toolbar
switches it and remembers the choice.

---

## What it cannot do

**No conflict detection without Npcap.** Windows sockets only reach the IP layer
and up. ARP lives below that, at layer 2, and there is no getting at it without a
driver. Isolation, identification and web access all work without Npcap.

**Same subnet only.** Neither ARP nor mDNS crosses a router. Several ranges can be
scanned at once, but only devices on the same switch will answer.

**mDNS and SSDP only get answers from devices that answer.** AV gear is good about
it, CCTV cameras about half the time. When nothing answers, ports get knocked on
instead.

**Switch port lookup needs SNMP v2c read enabled.** Managed switches only —
an unmanaged switch does not tell anyone what it knows.

---

## Licence

**GPLv2**, because it carries Scapy (GPLv2) and Wireshark's vendor registry
(GPL-2.0-or-later). See [LICENSE.md](LICENSE.md) and
[docs/third-party.md](docs/third-party.md).

---

Built by **Goyohan** for CCTV, AV and network installation work.

---

## Layout

```
src/         engine (Python), device book, vendor database
electron/    the window (Electron)
scripts/     build tooling - build_electron.bat, IPFixBackend.spec
docs/        field procedure, third-party licences
tools/       side scripts (ArpDupScan.py, IPFix.ps1)
manual.html     user guide; F1 opens it from inside the app
```

