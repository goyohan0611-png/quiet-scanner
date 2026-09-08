# Third-party components

Quiet Scanner is released under **GPLv2** because it carries the work below.

| Component | What it does | Licence |
|---|---|---|
| **Scapy** | Builds and receives ARP frames directly — the core of conflict detection | GPLv2 |
| **Wireshark manuf** | Source of the IEEE vendor registry (`oui.dat.gz` is derived from it) | GPL-2.0-or-later |
| **Pretendard** | Screen typeface | SIL OFL 1.1 |
| **Electron / Chromium** | Application window and rendering | MIT / BSD and others |
| **PyInstaller** | Bundles Python into an .exe | GPL with a linking exception (the bundled result is unencumbered) |

## Npcap is not bundled

Working with ARP directly needs the Npcap driver, but it is **not included in the
installer.** Download and install it yourself — https://npcap.com

The Npcap licence recommends this arrangement:

> Free and open-source projects are normally asked to direct users to download
> and install Npcap themselves. Use on up to 5 devices is free.

One or two installation laptops is well inside that limit.

## Full licence texts

- Scapy — https://github.com/secdev/scapy/blob/master/LICENSE
- Wireshark — https://gitlab.com/wireshark/wireshark/-/blob/master/COPYING
- Pretendard — https://github.com/orioncactus/pretendard/blob/main/LICENSE
- Npcap — https://github.com/nmap/npcap/blob/master/LICENSE
