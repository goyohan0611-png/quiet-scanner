# Field procedure — clearing duplicate IPs

> How to sort out a rack of devices that all shipped with the same factory IP,
> **without unplugging anything**, one device at a time from the screen.

---

## Why a normal IP scanner cannot see the problem

Four devices are all using `192.168.0.13`. The PC broadcasts "who has
192.168.0.13?" and **all four answer**. But the Windows ARP table stores one MAC
per IP — the last reply overwrites the ones before it.

So a ping-based tool such as Advanced IP Scanner shows **exactly one** of them.
The other three are alive and simply not on screen.

Two things get you out of it:

1. **Read every ARP reply off the wire**, bypassing the OS table — now you see,
   MAC by MAC, how many devices are sitting on that IP.
2. **Pin one MAC with a static ARP entry (isolation)** — traffic to that IP now
   reaches that one device. The rest go quiet, and you can open each device in
   turn and change its IP.

---

## Before you start (once per laptop)

| | |
|---|---|
| **Npcap** | https://npcap.com — tick **"WinPcap API-compatible mode"** during install |
| **Administrator** | isolation writes a static ARP entry, which needs it. The app asks for elevation itself |
| **Building from source** | Python 3.12, Node.js LTS, `pip install pyinstaller scapy`, then `build.bat` |

---

## On site

### 1 — Scan the range (F5)

Pick an interface and the range fills in **from that adapter's own address**. A
laptop on `192.168.0.50` gets `192.168.0.1-254`. Change the interface and the
range follows.

What the range box accepts:

| Input | Meaning |
|---|---|
| `192.168.0.1-254` | the whole range |
| `192.168.0.10-40` | part of it — faster when you know where the gear sits |
| `192.168.0.13` | one address — just how many devices are on this IP |
| `192.168.0.0/24` | CIDR works too |
| `192.168.0.1-20,192.168.0.64` | several, comma-separated |

Every device sharing an IP is found, and **conflicting IPs sort to the top**.
The range is sent in chunks, so progress is live and devices appear as they are
found. **Stop** cuts a long scan short and keeps what was found.

**Conflicting IPs come expanded; single IPs come collapsed.** Addresses that did
not answer are not listed — they show up under **Candidate IPs**.

```
▼ 192.168.0.13   [4 in conflict]
    BC-AD-28-11-22-33   Hikvision   IP camera / NVR   DS-2CD2143G0-I   80/HTTP  554/RTSP  8000/HTTP
    BC-AD-28-44-55-66   Hikvision   IP camera / NVR   DS-2CD2043G2-I   80/HTTP  554/RTSP  8000/HTTP
    90-02-A9-AA-BB-CC   Dahua       DVR / NVR         IPC-HDW2431T     80/HTTP  554/RTSP  37777/Dahua
    E4-30-22-DE-AD-01   Hanwha      IP camera         XNV-6081         80/HTTP  554/RTSP
```

### 2 — Identify the devices

Right-click → **Identify device**. Each device is isolated briefly while open
ports, the web page title, the auth realm and ONVIF data are collected, which
fills in vendor, device type and model. It takes a few seconds per device;
stopping part-way keeps whatever was learned.

### 3 — Work through them one at a time

Select a device → **Isolate this device only** → open it in a browser. That IP
now points at that one device. Change its IP, save, then **Release isolation**
and move on.

**Use a private browsing window.** You will be hitting the same IP for several
different devices, and the previous device's session gets in the way otherwise.

### 4 — Leave a record

**Export** writes the results out (CSV / JSON / XML), and **Report** produces a
commissioning workbook: findings, device list, switch port layout, PoE power and
free IPs. **History** keeps the last 30 completed scans so you can compare a
later visit against this one — what appeared, what went missing, what moved.

---

## Switch port lookup (SNMP)

A managed switch remembers which MAC came in on which port. **Switch port**
reads that table over SNMP v2c and attaches a port number to every device in the
list — read-only; nothing on the switch is changed.

It also flags ports that are **linked slower than the rest of the switch** and
ports running **half duplex**. Both look fine in a speed column and are slow in
practice. Gigabit uses all eight wires; one loose wire drops the link to 100M
silently, with no other symptom.

---

## How far isolation reaches

Isolation applies to **one IP address only**. Isolating `192.168.0.13` has no
effect on the internet, the office network, or any other device. Only traffic
the PC sends to `192.168.0.13` is pinned to the device you chose; the others
sharing that IP go quiet.

**The one thing to watch** — if you leave isolation on and that IP is later
taken by a different device, you will not reach it, because the PC still
remembers the old MAC. So isolation is released automatically when:

1. you release it,
2. you isolate a different device (the previous one is released), or
3. you close the window.

The static ARP entry lives in memory only, so even if the program is killed
before it can clean up, **a reboot clears it**. To remove one by hand, from an
administrator PowerShell:

```powershell
Remove-NetNeighbor -IPAddress 192.168.0.13 -Confirm:$false
```

Leftover entries from a crash are also cleaned up the next time the app starts.

---

## Try this first — the vendor tools (30 seconds)

If the site is all one brand, this may be the whole job. These tools find gear
by L2 broadcast and ignore the IP, so overlapping addresses do not hide anything,
and most of them can **change IPs in bulk**.

| Vendor | Tool | Bulk change |
|---|---|---|
| Hikvision | **SADP** | yes |
| Dahua | **ConfigTool** | yes |
| Hanwha Vision | **Device Manager** | yes |
| IDIS | IDIS Discovery | yes |
| Axis | AXIS IP Utility | yes |
| Uniview | EZTools | yes |
| **Mixed brands** | **ONVIF Device Manager** | one at a time |

Use Quiet Scanner when the brands are mixed, or when AV and network gear are on
the same switch.

---

## Side scripts

For when Npcap cannot be installed, or the command line is simply faster.

| File | Purpose | Needs |
|---|---|---|
| **tools/ArpDupScan.py** | command-line scanner; `--sweep` finds conflicts across a range | Npcap + scapy |
| **tools/IPFix.ps1** | stock PowerShell, no Npcap. MAC collection is probabilistic, so not exhaustive | administrator only |
| **tools/build_oui.py** | rebuilds `src/oui.dat.gz` from the IEEE registry | internet |

```cmd
python tools\ArpDupScan.py 192.168.0.0/24 --sweep
python tools\ArpDupScan.py --list-ifaces
```

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\tools\IPFix.ps1 -Ip 192.168.0.13 -ScanOnly -Rounds 100
.\tools\IPFix.ps1 -Ip 192.168.0.13
```

---

## When something goes wrong

| Symptom | Cause / what to do |
|---|---|
| Interface list is empty | Npcap not installed. Reinstall with "WinPcap API-compatible mode" ticked |
| "scapy missing" | `pip install scapy` |
| Isolate does nothing | Not running as administrator. Close and restart elevated |
| Nothing answered | Cable, PoE power, wrong range, or the wrong interface selected |
| Device type stays "Unidentified" | Identify has not been run, or the device has no web/ONVIF service |
| Isolated, but several devices still answer | The switch may be doing storm control. Try connecting directly to the switch |
| The new IP will not verify | The device is rebooting, or has closed every port. Check it in a browser |
| Browser login gets confused | Use a private window |
| Snapshot preview fails | Check the credentials. ONVIF or snapshots may be disabled, or it is not a camera |
| Switch port lookup finds nothing | SNMP v2c read is not enabled, or the community string is wrong |

---

## Not having the problem next time

| Approach | What it means |
|---|---|
| **DHCP first** | Leave the router's DHCP on while gear is connected. A surprising amount of factory-reset equipment comes up on DHCP |
| **Managed PoE switch** | Bring up one port at a time and work through them in order. Fully scriptable over SSH |
| **Set up on intake** | Assign and label IPs in the warehouse before the gear ships. This saves the most site time of anything here |
| **Keep the records** | File the commissioning report per site; tracing a device a year later becomes trivial |
