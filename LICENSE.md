# Licence

**Quiet Scanner** — a field tool for sorting out duplicate IPs
Copyright (C) 2026 Goyohan (고요한)

This program is free software. You can redistribute it and/or modify it under
the terms of the **GNU General Public License, version 2** as published by the
Free Software Foundation, or (at your option) any later version.

It is distributed in the hope that it will be useful, but **WITHOUT ANY
WARRANTY** — without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License for more details.

**The authoritative text is [`LICENSE`](LICENSE).** This file is a
plain-language summary. Where the two appear to disagree, `LICENSE` is what
counts.

---

## Why GPLv2

Handling ARP frames directly means shipping **Scapy** (GPLv2). The vendor
registry comes from **Wireshark's manuf file** (GPL-2.0-or-later). Distributing
GPL work puts the whole program under the same terms.

Everything borrowed is listed in [`docs/third-party.md`](docs/third-party.md).

---

## Using this program

- **Use it freely** — at work, on a customer's site, anywhere.
- **Change it freely.** If you hand your changes to someone else, the source has
  to go with them, under GPLv2.
- **Do not hand out the .exe alone.** GPLv2 §3 requires the source to accompany
  a binary, or a written offer good for three years. The source is all here, so
  passing along the repository address is enough.
- **The build scripts are part of the source** (`scripts/`, `build.bat`). GPLv2
  explicitly counts "the scripts used to control compilation" as source.

Do not remove the original copyright notice (`Copyright (C) 2026 고요한`).
