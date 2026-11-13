# Third-party components

Quiet Scanner is released under **GPLv2** because it carries the work below.

| Component | What it does | Licence |
|---|---|---|
| **Tauri / Wry / Tao** | Rust desktop host and system WebView integration | MIT or Apache-2.0 |
| **Rust crates** | Windows API bindings, serialization, gzip, clipboard and runtime | Individual notices in `LICENSES/rust-dependencies.txt` |
| **Wireshark manuf** | Historical vendor assignments retained in `oui.dat.gz` and the curated device book | GPL-2.0-or-later |
| **IEEE Registration Authority** | Current MA-L, MA-M and MA-S assignments merged into the bundled vendor data | Public registry data; original source URLs and retrieval metadata in `vendor-data.json` |
| **SUIT Variable** | Screen typeface, bundled WOFF2 | SIL OFL 1.1 |

The 4.x installers contain the Rust/Tauri app. The Electron host, Python,
Scapy and PyInstaller sources retained in this repository are legacy code and
are not bundled in the 4.0 installer. The current ARP/DHCP frame codec is in
`src-tauri/src/packet.rs`.

## Npcap is not bundled

Npcap is used only on Windows. macOS uses its system libpcap; Linux uses the
distribution's libpcap package. The macOS/Linux preview includes target-specific
Rust dependency notices generated from the same Cargo lockfile.

Working with ARP directly needs the Npcap driver, but it is **not included in the
installer.** Download and install it yourself — https://npcap.com

Check the Npcap licence for your intended installation and redistribution.
Quiet Scanner does not redistribute the driver.

## Full licence texts

- Scapy — https://github.com/secdev/scapy/blob/master/LICENSE
- Wireshark — https://gitlab.com/wireshark/wireshark/-/blob/master/COPYING
- SUIT — https://github.com/sun-typeface/SUIT/blob/main/LICENSE
- Npcap — https://github.com/nmap/npcap/blob/master/LICENSE
- Rust dependencies — `LICENSES/rust-dependencies.txt`, generated from `Cargo.lock`
- SUIT licence copy — `LICENSES/OFL-SUIT.txt`

SUIT font source: `sun-typeface/SUIT` commit
`55118d981336d8fce005eb62888c12c0568ef7b0`,
`fonts/variable/woff2/SUIT-Variable.woff2`, unmodified.
The older Pretendard notice is retained for the legacy source history; its TTF
files are no longer included in the current renderer.

Current vendor registry sources:
- https://standards-oui.ieee.org/oui/oui.csv
- https://standards-oui.ieee.org/oui28/mam.csv
- https://standards-oui.ieee.org/oui36/oui36.csv

`tools/build_oui.py` retains historical assignments, refreshes current IEEE
registrants and adds prefixes to the curated book only where the organization
already has an unambiguous vendor match. New entries do not infer a product type.
