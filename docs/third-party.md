# Third-party components

Quiet Scanner is released under **GPLv2** because it carries the work below.

| Component | What it does | Licence |
|---|---|---|
| **Tauri / Wry / Tao** | Rust desktop host and system WebView integration | MIT or Apache-2.0 |
| **Rust crates** | Windows API bindings, serialization, gzip, clipboard and runtime | Individual notices in `LICENSES/rust-dependencies.txt` |
| **Wireshark manuf** | Source of the IEEE vendor registry (`oui.dat.gz` is derived from it) | GPL-2.0-or-later |
| **Pretendard** | Screen typeface | SIL OFL 1.1 |

The 4.0 installer contains the Rust/Tauri app. The Electron host, Python,
Scapy and PyInstaller sources retained in this repository are legacy code and
are not bundled in the 4.0 installer. The current ARP/DHCP frame codec is in
`src-tauri/src/packet.rs`.

## Npcap is not bundled

Working with ARP directly needs the Npcap driver, but it is **not included in the
installer.** Download and install it yourself — https://npcap.com

Check the Npcap licence for your intended installation and redistribution.
Quiet Scanner does not redistribute the driver.

## Full licence texts

- Scapy — https://github.com/secdev/scapy/blob/master/LICENSE
- Wireshark — https://gitlab.com/wireshark/wireshark/-/blob/master/COPYING
- Pretendard — https://github.com/orioncactus/pretendard/blob/main/LICENSE
- Npcap — https://github.com/nmap/npcap/blob/master/LICENSE
- Rust dependencies — `LICENSES/rust-dependencies.txt`, generated from `Cargo.lock`
- Pretendard licence copy — `LICENSES/OFL-Pretendard.txt`
