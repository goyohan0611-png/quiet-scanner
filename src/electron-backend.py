#!/usr/bin/env python3
# Quiet Scanner — field tool for sorting out IP conflicts
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
"""IPFix network engine called from the Electron UI (JSON Lines)."""
import base64
import concurrent.futures as futures
import ipaddress
import json
import sys
import threading

try:
    sys.stdout.reconfigure(encoding="utf-8")
    # Electron sends its request JSON as UTF-8. If a path has non-ASCII characters,
    # stdin has to be read in the same encoding or the filename comes through mangled.
    sys.stdin.reconfigure(encoding="utf-8")
except AttributeError:
    pass

import IPFixStudio as core
from IPFixStudio import T

# Move the old Korean file names to the new ones. pin_sweep below reads the
# isolation record, so this has to happen first — get the order wrong and a leftover
# static ARP entry goes unfound, pinning that IP to the wrong MAC until reboot.
_moved = core.migrate_old_names()

core.STORE = core.Store(demo=False)
core.BOOK.load()
for _line in _moved:
    core.STORE.log(T("기록 파일 이름을 바꿨습니다 — %s",
                     "Renamed a data file — %s") % _line, "info")
OUTPUT_LOCK = threading.Lock()
SCAN_LOCK = threading.Lock()
SCAN_CANCEL = threading.Event()
SCAN_RUNNING = False

# Clear any isolation left behind by a previous crash before anything else runs.
_left = core.pin_sweep(log=core.STORE.log)
if _left:
    core.STORE.log(T("지난 실행에서 남은 격리 %d건을 정리했습니다.",
                     "Cleared %d static ARP entries left over from a previous run.") % _left, "ok")


def serialize():
    snapshot = core.STORE.snapshot()
    return {
        "groups": core.STORE.by_ip(),
        "summary": snapshot["summary"],
        "iface": core.STORE.iface,
        "ifindex": core.STORE.ifindex,
        "progress": snapshot["progress"],
        "logs": snapshot["logs"],
        "isolated": snapshot["isolated"],
    }


def send_json(message):
    """Send JSON so the scan thread and a cancel request never share one line."""
    with OUTPUT_LOCK:
        print(json.dumps(message, ensure_ascii=False), flush=True)


def emit_state():
    send_json({"event": "state", "data": serialize()})


RECHECK_HISTORY = 3


# Before switching a port off, ask the switch itself whether it may be switched off.
#
# One rule — **if it cannot be confirmed, refuse.** Treating "don't know" as "it's
# fine" locks the management port in exactly the case where the switch will not
# answer. SNMP cannot reach it after that, so there is no undo. Console cable, on site.
#
# No cache either. A cache remembers the wiring from five minutes ago, and the installer
# may have moved the patch lead since. Writes are rare and cannot be undone — read fresh.

# This computer's adapter MACs. STORE is rebuilt on every scan, so keep these on
# the process side — a failed scan does not take them with it.
KNOWN_MACS = set()

NEVER_LOCK = ("이 컴퓨터가 물린 포트", "this computer's port",
              "스위치 관리 포트", "the switch's own port")


def my_macs_of_this_pc():
    """Every adapter MAC on this computer, flattened to 12 hex digits.

    The switch's MAC table arrives without separators (aabbcc...) and the adapter
    list arrives with colons (aa:bb:cc:...). Compare them as written and they never
    match — then "my own port" goes unrecognised and you cut your own link.
    """
    macs = set(core.STORE.mymacs or set())
    if core.STORE.mymac:
        macs.add(core.STORE.mymac)
    return {core.hex_mac(m) for m in macs if m}


def switch_own_macs(host, community, rows):
    """The switch's own MACs. Ask it directly, and add whatever the scan saw."""
    macs = set()
    try:
        macs |= core.read_own_macs(host, community)
    except Exception:
        pass
    store = core.STORE
    with store.lock:
        devices = list(store.devices.values())
    for dev in devices:
        if dev["ip"] == host:
            macs.add(core.hex_mac(dev["mac"]))
    return macs


def block_reason(macs, mine, switch_macs):
    """Why this port must not be switched off. Empty string if there is no reason."""
    macs = {core.hex_mac(m) for m in (macs or [])}
    if macs & mine:
        return T("이 컴퓨터가 물린 포트", "this computer's port")
    if macs & switch_macs:
        return T("스위치 관리 포트", "the switch's own port")
    if len(macs) > 1:
        return T("장비 %d대 — 아래에 스위치·허브가 달린 자리",
                 "%d devices — a switch or hub hangs below") % len(macs)
    return ""


def guard_rows(host, community, rows):
    """Tag each port with why it cannot be switched off. Used for the UI listing."""
    mine = my_macs_of_this_pc()
    switch_macs = switch_own_macs(host, community, rows)
    for row in rows:
        # A port ifOperStatus never answered for is unknown, not empty. Left lockable,
        # one dropped datagram is enough for "lock every unused port" to take a live
        # camera down. Checked before block_reason: not knowing outranks every other reason.
        if not row.get("read"):
            row["blocked"] = T("상태를 못 읽은 포트입니다 — 비어 있는지 알 수 없습니다",
                               "this port's state could not be read — no telling if it is free")
            continue
        row["blocked"] = block_reason(row.get("macs"), mine, switch_macs)
    return rows


def verify_writable(host, community, index, poe=False):
    """Check right now whether this port may be switched off. Raise if it may not.

    If anything at all cannot be confirmed, refuse:
      - the port list cannot be read
      - the MAC table cannot be read (no way to tell which port is the uplink)
      - this computer's adapters are unknown (cannot screen out my own port)
      - there is no port with that number
    """
    def refuse(message):
        raise RuntimeError(
            T("확인이 안 돼서 끄지 않았습니다 — %s. 잘못 끄면 되돌릴 방법이 없습니다.",
              "Refusing to switch anything off — %s. A wrong one cannot be undone.")
            % message)

    mine = my_macs_of_this_pc()
    if not mine:
        refuse(T("이 컴퓨터의 랜카드를 아직 모릅니다",
                 "this computer's adapters are not known yet"))
    try:
        ports = core.read_switch_ports(host, community)
    except Exception as exc:
        refuse(T("스위치에서 포트 목록을 못 읽었습니다 (%s)",
                 "could not read the port list from the switch (%s)") % exc)
        return
    if not ports:
        refuse(T("스위치가 포트 목록을 안 줍니다", "the switch returned no port list"))

    # Is it a number we know? PoE numbering is separate, so map it back through the table.
    target = str(index)
    if poe:
        matched = [i for i, info in ports.items()
                   if str(info.get("poeIndex") or "") == str(index)]
        if matched:
            target = matched[0]
        elif target not in ports:
            refuse(T("PoE 번호 %s 를 포트에 맞출 수 없습니다",
                     "PoE index %s does not map to a port") % index)
    if target not in ports:
        refuse(T("스위치에 %s 번 포트가 없습니다", "the switch has no port %s") % index)
    if not ports[target].get("read"):
        refuse(T("%s 번 포트의 상태를 못 읽었습니다 — 비어 있는지 알 수 없습니다",
                 "port %s's state could not be read — no telling if it is free") % target)

    if not any(info.get("macs") for info in ports.values()):
        refuse(T("스위치가 MAC 표를 안 내줍니다 — 어느 포트가 업링크인지 알 수 없습니다",
                 "the switch will not give up its MAC table — uplinks cannot be told apart"))
    if core.walk_truncated(host, core.OID_Q_FDB_PORT, core.OID_FDB_PORT):
        refuse(T("MAC 표가 너무 커서 다 못 읽었습니다 — 업링크를 놓칠 수 있습니다",
                 "the MAC table was too large to read in full — an uplink could be missed"))

    reason = block_reason(ports[target].get("macs"),
                          mine, switch_own_macs(host, community, ports))
    if reason:
        raise RuntimeError(T("이 포트는 끌 수 없습니다 — %s.",
                             "This port cannot be switched off — %s.") % reason)


def plan_ranges(target, cards):
    """Hand each piece of the range to the adapter that can reach it.

    On a box with two cables on two subnets — a server, say — a subnet only answers
    when the request goes out of the adapter that holds it. A piece that fits no
    adapter goes to the first one — someone typed another subnet on purpose.

    Returns: [(adapter, "range pieces"), ...]
    """
    nets = []
    for card in cards:
        rows = []
        for row in (card.get("ipv4") or []):
            try:
                rows.append(ipaddress.ip_network(row.get("cidr") or "", strict=False))
            except ValueError:
                pass
        nets.append(rows)

    # Never pick the adapter from the **first address** of a piece. When one piece
    # covers several subnets — 192.168.0.0/22, say — everything goes out the adapter
    # matching that first address. ARP cannot leave its own subnet, so the remaining
    # addresses are silent by construction, and that silence turns into "checked, and
    # free". Bind every address to the adapter that owns its subnet.
    buckets = [[] for _ in cards]
    homeless = []
    for piece in [p.strip() for p in str(target).split(",") if p.strip()]:
        try:
            addresses = core.parse_target(piece)
        except ValueError:
            addresses = []
        for text in addresses:
            try:
                one = ipaddress.ip_address(text)
            except ValueError:
                continue
            where = None
            for n, rows in enumerate(nets):
                if any(one in net for net in rows):
                    where = n
                    break
            if where is None:
                homeless.append(text)
            else:
                buckets[where].append(text)

    # Addresses that fit no adapter still get swept — the first adapter takes them.
    # Someone may have typed another subnet on purpose (past a router), and that is
    # their call. But silence there must never read as "free", so they come back flagged.
    if homeless and cards:
        buckets[0].extend(homeless)

    # If not one adapter subnet is known (Windows sometimes withholds the prefix), there
    # is no ground to call anything "outside the subnet". Not knowing is not the same as
    # not reachable — confuse the two and a perfectly good scan result drops out of the
    # free-IP list wholesale. The sweep is assigned above; this only drops the tag.
    if not any(nets):
        homeless = []

    plan = []
    for n, rows in enumerate(buckets):
        if rows:
            plan.append((cards[n], compact_ranges(rows)))
    return plan, sorted(set(homeless))


def compact_ranges(addresses):
    """Squeeze an address list back into "192.168.0.1-40,192.168.0.55" form.

    Joined one by one with commas, a single /22 becomes a 1,000-piece string. It goes
    back through parse_target below, so it is better kept short.
    """
    try:
        order = sorted(set(addresses), key=lambda x: int(ipaddress.IPv4Address(x)))
    except ValueError:
        return ",".join(addresses)
    out, run = [], []

    def flush():
        if not run:
            return
        head, tail = run[0], run[-1]
        out.append(head if head == tail
                   else "%s-%s" % (head, tail.rsplit(".", 1)[-1]))
    for text in order:
        if run:
            prev = ipaddress.IPv4Address(run[-1])
            here = ipaddress.IPv4Address(text)
            same_c = run[-1].rsplit(".", 1)[0] == text.rsplit(".", 1)[0]
            if same_c and int(here) == int(prev) + 1:
                run.append(text)
                continue
            flush()
            run = []
        run.append(text)
    flush()
    return ",".join(out)


def previous_scan_ips(target):
    """IPs that answered at least once across the last three sweeps of this range.

    Look at only one and a power-saving device that dropped two in a row is missed.
    Fold three together and it stays on the list. A device that really was taken out
    stays silent through three more asks, so it drops off quietly after three scans.

    Empty set when there is nothing to compare — a first scan has nothing to re-ask.
    """
    seen = set()
    used = 0
    for record in core.load_scan_history():
        if record.get("target") != target:
            continue
        seen |= {info.get("ip", "") for info in record.get("devices", {}).values()
                 if info.get("ip")}
        used += 1
        if used >= RECHECK_HISTORY:
            break
    return seen


def current_devices():
    with core.STORE.lock:
        return {core.hex_mac(d["mac"]): {"ip": d["ip"], "vendor": d.get("vendor", ""),
                                           "kind": d.get("kind", ""), "model": d.get("model", "")}
                for d in core.STORE.devices.values()}


def _refresh_from_book():
    """When the book changes, re-tag vendor and type on devices already listed."""
    with core.STORE.lock:
        for dev in core.STORE.devices.values():
            seen = core.describe(dev["mac"])
            dev["book"] = seen["from_book"]
            dev["book_exact"] = seen["exact"]
            dev["book_note"] = seen["note"]
            if seen["from_book"]:
                dev["vendor"] = seen["vendor"]
                # Do not overwrite a type that was already worked out by probing.
                # Unless someone registered the full MAC by hand — that name wins.
                if seen["exact"] or not dev.get("identified"):
                    if seen["kind"]:
                        dev["kind"] = seen["kind"]
                        dev["kind_confidence"] = "confirmed" if seen["exact"] else "estimated"


def run(action, payload):
    if action == "set_lang":
        # Change the language in the UI and the engine's own log has to follow.
        return {"lang": core.set_lang(payload.get("lang"))}

    if action == "kinds":
        # The engine holds exactly one set of device-type labels. The UI takes them.
        return core.KIND_EN

    if action == "interfaces":
        if not core.ensure_scapy():
            raise RuntimeError(T("scapy/Npcap을 불러오지 못했습니다: ",
                                 "Could not load scapy/Npcap: ") + core.SCAPY_ERR)
        cards = core.list_ifaces()
        # Remember this computer's adapter MACs here. Some people never run a scan
        # and go straight to locking ports, and "my own port" still has to be
        # recognised then. This action always runs once at startup.
        KNOWN_MACS.update(c.get("mac", "") for c in cards if c.get("mac"))
        core.STORE.mymacs = set(KNOWN_MACS)
        return cards

    if action == "demo":
        core.STORE = core.Store(demo=True)
        core.STORE.mymacs = set(KNOWN_MACS)
        seen = []
        for ip, devices in core.DEMO_SEED:
            seen.append(ip)
            for mac, ports, title, model in devices:
                dev = core.STORE.upsert(ip, mac)
                dev.update({"ports": ports, "title": title, "model": model, "identified": True})
        # The demo is a finished run. Unmarked, the free-IP window refuses with "the
        # scan did not finish" — which just looks broken to someone having a look around.
        base = seen[0].rsplit(".", 1)[0] if seen else "192.168.0"
        core.STORE.cidr = "%s.1-60" % base
        # The seeded IPs must be included. Leave them out and a used address shows as free.
        spread = ["%s.%d" % (base, n) for n in range(1, 61)]
        core.STORE.scanned = sorted(set(spread) | set(seen),
                                    key=lambda x: tuple(int(n) for n in x.split(".")))
        core.STORE.scan_done = True
        return serialize()

    if action == "cancel":
        if not SCAN_RUNNING:
            return {"canceled": False, "state": serialize()}
        SCAN_CANCEL.set()
        core.STORE.cancel.set()
        core.STORE.log(T("스캔 중지 요청 — 현재 확인 중인 묶음까지만 마칩니다.",
                         "Scan stop requested — finishing the current batch."), "warn")
        emit_state()
        return {"canceled": True, "state": serialize()}

    if action == "scan":
        # More than one adapter can be picked — so a box on two subnets over two
        # cables, a server for instance, is covered in a single sweep.
        cards = payload.get("ifaces") or [payload["iface"]]
        target = payload["target"]
        # Parse the range first. If this is going to be rejected, no reason to have wiped the list.
        targets = core.parse_target(target)
        if len(targets) > core.MAX_TARGETS:
            raise ValueError(T("대상이 너무 많습니다 (%d개). 범위를 좁혀 주십시오.",
                               "Too many targets (%d). Narrow the range.") % len(targets))
        KNOWN_MACS.update(c.get("mac", "") for c in cards if c.get("mac"))

        # Release any standing isolation before swapping in a new STORE.
        #
        # Skip it and the static ARP entry stays on this PC while the UI forgets it.
        # "Release isolation" then does nothing, and that IP keeps showing a single
        # MAC — the tool hiding the very conflict it was brought in to find.
        # The log line has to be written after the new STORE exists. Written here it is
        # thrown away one line below — and this is a message the installer must see.
        untangle = None
        if core.STORE.isolated:
            stuck = core.STORE.devices.get(core.STORE.isolated)
            if stuck:
                ok, why = core.arp_unpin(
                    stuck["ip"], stuck.get("ifindex") or core.STORE.ifindex,
                    stuck.get("ifname") or core.STORE.iface)
                untangle = (ok, stuck["ip"], why)
            core.STORE.isolated = None

        core.STORE = core.Store(demo=False)
        if untangle:
            ok, where, why = untangle
            if ok:
                core.STORE.log(T("스캔 전에 격리를 풀었습니다 — %s",
                                 "Released isolation before scanning — %s") % where, "info")
            else:
                core.STORE.log(
                    T("격리를 풀지 못했습니다 — %s (%s). 이 주소는 아직 한 장비에 "
                      "묶여 있어서, 이번 스캔에서 그 IP 의 충돌은 안 보일 수 "
                      "있습니다. 관리자 권한으로 다시 켜십시오.",
                      "Could not release isolation — %s (%s). That address is still "
                      "pinned to one device, so a conflict on it may not show in this "
                      "scan. Re-launch as administrator.")
                    % (where, why or "이유 모름"), "error")
        core.STORE.busy = True
        core.STORE.mymacs = set(KNOWN_MACS)
        if SCAN_CANCEL.is_set():
            core.STORE.cancel.set()
        core.STORE.cidr = target

        plan, homeless = plan_ranges(target, cards)
        first = plan[0][0] if plan else cards[0]
        if homeless:
            core.STORE.log(
                T("주소 %d개는 고른 랜카드의 대역 밖입니다 (%s…). ARP 는 대역을 못 "
                  "넘으므로 답이 없어도 '비어 있음' 이 아닙니다 — 빈 IP 목록에서 "
                  "빼겠습니다.",
                  "%d addresses are outside the selected adapters' subnets (%s…). ARP "
                  "cannot cross subnets, so silence there does not mean free — they are "
                  "left out of the free-IP list.")
                % (len(homeless), ", ".join(homeless[:3])), "warn")
        core.STORE.iface = first.get("scapyName") or first["name"]
        core.STORE.ifindex = first.get("index")
        core.STORE.mymac = first.get("mac", "")
        # Never pre-fill this with the whole target. If the scan blows up (no Npcap, no
        # privileges) or stops halfway, the device list is empty while 254 addresses sit
        # there as "swept". Hit candidate IPs in that state and **the whole range comes
        # back "free"**, and the installer puts a device on a used address. That is the
        # worst answer this tool can give. Only genuinely checked addresses go in.
        core.STORE.scanned = []
        core.STORE.scan_done = False
        core.STORE.set_progress(T("대역 스캔", "Range scan"), 0, len(targets),
                                T("주소 {n}개 확인 중", "checking {n} addresses").format(n=len(targets)))
        pieces = [p.strip() for p in target.split(",") if p.strip()]
        core.STORE.log(T("스캔 시작 — 대역 {t} (주소 {n}개{more})",
                         "Scan started — {t} ({n} addresses{more})").format(
            t=target, n=len(targets),
            more=T(" · %d개 대역", " in %d ranges") % len(pieces) if len(pieces) > 1 else ""))
        if len(plan) > 1:
            core.STORE.log(T("랜카드 %d개로 나눠 훑습니다 — %s",
                             "Sweeping through %d adapters — %s")
                           % (len(plan), " · ".join(
                               "%s → %s" % (c.get("desc") or c["name"], txt) for c, txt in plan)),
                           "info")
        emit_state()

        found, scanned = {}, []
        done_base = 0

        def sweep_card(card, sub_target):
            """Sweep one range through one adapter. Hits pile up in the outer lists."""
            nonlocal done_base
            # A device found on this adapter has to remember it, or isolation later fails.
            core.STORE.iface = card.get("scapyName") or card["name"]
            core.STORE.ifindex = card.get("index")
            sub_list = core.parse_target(sub_target)

            # ARP does not cross routers. Sweep a subnet other than your own and only
            # devices on the same switch answer. Silence does not mean nothing is there.
            my_ip = (card.get("ips") or [""])[0]
            if my_ip:
                mine = ".".join(my_ip.split(".")[:3])
                outside = {".".join(t.split(".")[:3]) for t in sub_list} - {mine}
                if outside:
                    core.STORE.log(
                        T("내 IP(%s)와 다른 대역이 섞여 있습니다 — %s. 같은 스위치에 물린 "
                          "장비만 답합니다.",
                          "Ranges outside your own subnet (%s) are included — %s. Only devices "
                          "on the same switch will answer.")
                        % (my_ip, ", ".join(sorted(o + ".x" for o in outside))[:80]),
                        "warn")

            def on_progress(cur, total):
                core.STORE.set_progress(
                    T("대역 스캔", "Range scan"), done_base + cur, len(targets),
                    T("{c} / {t} 주소 확인", "{c} / {t} addresses")
                    .format(c=done_base + cur, t=len(targets)))
                emit_state()

            def on_found(hits):
                for ip, macs in hits.items():
                    for mac in macs:
                        core.STORE.upsert(ip, mac)
                emit_state()

            got, swept = core.arp_sweep(sub_target, core.STORE.iface, timeout=1.4, retry=1,
                                        on_progress=on_progress, on_found=on_found)
            for ip, macs in got.items():
                for mac in macs:
                    core.STORE.upsert(ip, mac)
                    found.setdefault(ip, [])
                    if mac not in found[ip]:
                        found[ip].append(mac)
            if core.STORE.cancel.is_set():
                # An address that only got the first pass is not "checked". Leave it out.
                return

            # ── Below is the part that makes sure a used IP is caught ───────────
            #
            # ARP is a one-packet question. A busy switch, or an adapter dozing in
            # power-save, drops that one packet. Ask once and call it empty, and a
            # used IP gets reported as "free". That is the worst answer this tool can
            # give — the installer puts a new device on it and a conflict starts.
            #
            # So the silent addresses alone get asked twice more, each time more
            # patiently. Addresses that already answered are skipped; it costs little.

            def ask_again(addresses, timeout, retry, phase, note):
                """Re-ask a handful of addresses and add whatever answers to the lists."""
                if not addresses or core.STORE.cancel.is_set():
                    return 0
                order = sorted(addresses, key=lambda x: tuple(int(n) for n in x.split(".")))
                core.STORE.set_progress(phase, 0, len(order), note)
                emit_state()
                picked = 0
                # Throw them all out at once and they get dropped again. Ask in chunks.
                for i in range(0, len(order), 64):
                    if core.STORE.cancel.is_set():
                        break
                    part = order[i:i + 64]
                    again, _ = core.arp_sweep(",".join(part), core.STORE.iface,
                                              timeout=timeout, retry=retry)
                    for ip, macs in again.items():
                        for mac in macs:
                            core.STORE.upsert(ip, mac)
                            if mac not in found.setdefault(ip, []):
                                found[ip].append(mac)
                                picked += 1
                    core.STORE.set_progress(phase, min(i + 64, len(order)), len(order), note)
                    emit_state()
                return picked

            # Pass 2 — every silent address. Catches a first-time device that dropped the
            #       first question. On a new site's first scan there is no history to
            #       compare against, so this is the only net. Asking often beats waiting
            #       long — an ARP reply on the same LAN comes in milliseconds, not 1.8s.
            silent = [ip for ip in swept if ip not in found]
            got_n = ask_again(silent, 0.7, 3,
                              T("2차 확인", "Second pass"),
                              T("답이 없던 %d개를 다시 확인", "re-checking %d silent addresses")
                              % len(silent))
            if got_n:
                core.STORE.log(T("2차 확인에서 %d대를 더 찾았습니다.",
                                 "Second pass found %d more devices.") % got_n, "ok")

            # Pass 3 — addresses that were in the last scan and are still silent. Usually
            #       a power-saving device. Few of them, so ask most patiently of all.
            stubborn = (previous_scan_ips(target) & set(sub_list)) - set(found)
            # This third pass is the slowest, so it is capped at 64. If the cut is not
            # logged it reads as "everything was asked", and nobody notices the rest
            # leaking out into the free-IP list.
            asked_list = sorted(stubborn)[:64]
            got_n = ask_again(asked_list, 1.5, 3,
                              T("지난 기록 대조", "Checking against history"),
                              T("지난 스캔에 있던 %d개 확인", "checking %d from the last scan")
                              % len(asked_list))
            if stubborn:
                core.STORE.log(
                    T("지난 스캔에 있던 %d대 중 %d대를 다시 물었습니다 — %d대 응답",
                      "%d devices from the last scan: re-asked %d — %d replied")
                    % (len(stubborn), len(asked_list), got_n), "ok" if got_n else "info")
                if len(stubborn) > len(asked_list):
                    core.STORE.log(
                        T("지난 스캔의 %d개는 시간 때문에 다시 안 물었습니다. "
                          "빈 IP 목록에 섞여 있을 수 있으니 그대로 믿지 마십시오.",
                          "%d addresses from the last scan were not re-checked (time). "
                          "They may show up as free — do not trust that list blindly.")
                        % (len(stubborn) - len(asked_list)), "warn")

            # Last — this adapter itself. ARP never hears its own shout, so this
            # computer is never discovered by it. Leave it out and your own IP goes
            # out as a "free address", and the installer puts a device on it.
            # Only addresses that went through all three passes count as "swept". A range
            # a stop kept from reaching here drops out whole — an address asked once,
            # mixed into the free-IP list, looks the same on screen as one asked three times.
            if not core.STORE.cancel.is_set():
                # Out-of-subnet addresses were never reachable. Count that silence
                # as "checked" and it becomes a free IP.
                blind = set(homeless)
                scanned.extend([ip for ip in swept if ip not in blind])

            my_mac = card.get("mac", "")
            for own in (card.get("ips") or []):
                if own and own in set(swept) and own not in found and my_mac:
                    device = core.STORE.upsert(own, my_mac)
                    device["note"] = T("이 컴퓨터", "this computer")
                    found[own] = [core.norm_mac(my_mac)]
                    core.STORE.log(T("이 컴퓨터(%s)를 목록에 넣었습니다 — ARP 로는 자기 자신을 못 찾습니다.",
                                     "Added this computer (%s) — ARP cannot discover itself.") % own,
                                   "info")
            done_base += len(swept)

        for card, sub_target in plan:
            if core.STORE.cancel.is_set():
                break
            sweep_card(card, sub_target)

        core.STORE.scanned = scanned
        # Put the default adapter back to the first one — later actions use it as the default.
        core.STORE.iface = first.get("scapyName") or first["name"]
        core.STORE.ifindex = first.get("index")

        if core.STORE.cancel.is_set():
            core.STORE.set_progress(T("대역 스캔", "Range scan"), len(scanned), len(targets),
                                    T("중지됨", "stopped"))
            core.STORE.log(T("스캔 중지 — 주소 %d개만 확인했습니다.",
                             "Scan stopped after %d addresses.") % len(scanned), "warn")
            result = serialize()
            result["canceled"] = True
            return result
        emit_state()
        # Once the scan is done, shout across the whole LAN. It is two multicast
        # packets, not a visit per device, so more devices costs no more time.
        core.STORE.set_progress(T("장비 이름 수집", "Collecting names"), 0, 1,
                                T("mDNS · SSDP 응답 기다리는 중", "waiting for mDNS · SSDP replies"))
        emit_state()
        try:
            names = core.mdns_sweep(timeout=2.0)
            upnp = core.ssdp_sweep(timeout=2.5)
        except Exception as exc:
            names, upnp = {}, {}
            core.STORE.log(T("이름 수집을 건너뜁니다: %s",
                             "Skipping name collection: %s") % exc, "warn")

        picked = 0
        skipped = set()
        with core.STORE.lock:
            # mDNS and SSDP answer per address. On a conflicting IP exactly one reply comes
            # back for however many devices are sitting on it, and there is no way to tell
            # whose it is. Stamped on all of them, four devices get one name, one model and
            # one serial — the Dahua and the Hanwha both wearing the Hikvision's. An empty
            # cell is honest; a copied serial is an invented one, and it goes into the
            # commissioning report as fact. Identification handles these properly: it
            # isolates one device at a time, so what it finds belongs to that MAC.
            crowd = {}
            for dev in core.STORE.devices.values():
                crowd[dev["ip"]] = crowd.get(dev["ip"], 0) + 1
            for dev in core.STORE.devices.values():
                name = names.get(dev["ip"], "")
                info = upnp.get(dev["ip"]) or {}
                if crowd.get(dev["ip"], 1) > 1:
                    if name or info:
                        skipped.add(dev["ip"])
                    continue
                if name:
                    dev["mdns"] = name
                if info:
                    dev["ssdp"] = info.get("name", "")
                    if info.get("model") and not dev.get("model"):
                        dev["model"] = info["model"]
                    if info.get("serial"):
                        dev["serial"] = info["serial"]
                if name or info:
                    picked += 1
        if picked:
            core.STORE.log(T("장비 이름 %d대 수집 (mDNS %d · UPnP %d)",
                             "Collected names for %d devices (mDNS %d · UPnP %d)") % (
                picked, len(names), len(upnp)), "ok")
        # Say it out loud. Drop these quietly and the blank cells look like nothing
        # answered, and someone goes hunting for a fault that is not there.
        if skipped:
            core.STORE.log(T("충돌 IP %d곳(%s)은 이름·모델·시리얼을 붙이지 않았습니다 — "
                             "응답이 한 대 몫뿐이라 어느 장비 것인지 알 수 없습니다. "
                             "[장비 정보 검사]를 돌리면 한 대씩 격리해서 제대로 채웁니다.",
                             "Left name, model and serial blank on %d conflicting IP(s) (%s) — "
                             "only one reply came back for several devices, so there is no "
                             "telling whose it is. Run Identify device to fill them in "
                             "properly, one isolated device at a time.")
                           % (len(skipped), ", ".join(sorted(skipped)[:6])), "warn")

        if core.STORE.cancel.is_set():
            core.STORE.set_progress(T("대역 스캔", "Range scan"), len(scanned), len(targets),
                                    T("중지됨", "stopped"))
            core.STORE.log(T("스캔 중지 — 이름 수집 뒤에 종료했습니다.",
                             "Scan stopped after name collection."), "warn")
            result = serialize()
            result["canceled"] = True
            return result

        # A port typed in means "show only the devices using that port".
        # Knock on that port on every device ARP found, and drop the ones with nothing open.
        ports_text = (payload.get("ports") or "").strip()
        if ports_text:
            wanted = core.parse_ports(ports_text)
            with core.STORE.lock:
                targets = list(core.STORE.devices.values())
            core.STORE.set_progress(
                T("포트 확인", "Checking ports"), 0, len(targets),
                T("포트 {p} 열린 장비만", "keeping only devices with {p} open")
                .format(p=ports_text))
            emit_state()

            def probe(dev):
                return dev, core.scan_ports(dev["ip"], wanted)

            done = 0
            keep = []
            with futures.ThreadPoolExecutor(max_workers=32) as pool:
                for dev, open_ports in pool.map(probe, targets):
                    if core.STORE.cancel.is_set():
                        break
                    dev["ports"] = open_ports
                    if open_ports:
                        keep.append(dev["key"])
                    done += 1
                    if done % 8 == 0:
                        core.STORE.set_progress(T("포트 확인", "Checking ports"),
                                                done, len(targets), "")
                        emit_state()

            if core.STORE.cancel.is_set():
                # Stop pressed means no filtering. Leave a half-filtered list and
                # devices that were never checked go out as free IPs.
                core.STORE.log(T("포트 확인 중지 — 거르지 않고 그대로 둡니다.",
                                 "Port check stopped — leaving the list unfiltered."), "warn")
                result = serialize()
                result["canceled"] = True
                return result

            dropped = len(targets) - len(keep)
            with core.STORE.lock:
                kept = set(keep)
                hidden = {d["ip"] for d in targets if d["key"] not in kept}
                core.STORE.devices = {k: v for k, v in core.STORE.devices.items() if k in kept}
                core.STORE.order = [k for k in core.STORE.order if k in kept]
                # A hidden device's IP has to come out of "swept addresses" too.
                # Otherwise a used IP goes out on the free list — the worst answer there is.
                still = {d["ip"] for d in core.STORE.devices.values()}
                core.STORE.scanned = [ip for ip in core.STORE.scanned
                                      if ip not in (hidden - still)]
            core.STORE.log(
                T("포트 {p} 로 걸러 {n}대 남김 ({d}대는 해당 포트가 닫혀 있어 숨김)",
                  "Filtered by port {p} — {n} kept, {d} hidden (port closed)")
                .format(p=ports_text, n=len(keep), d=dropped),
                "ok" if keep else "warn")
            found = {ip: macs for ip, macs in found.items()
                     if any(core.STORE.key(ip, m) in kept for m in macs)}

        conflicts = sum(1 for macs in found.values() if len(macs) > 1)
        core.STORE.scan_done = True
        core.STORE.set_progress(T("대역 스캔", "Range scan"), len(scanned), len(scanned),
                                T("완료", "done"))
        core.STORE.log(T("스캔 완료 — IP {ips}개 응답 / 장비 {devs}대 / 충돌 IP {conf}개",
                         "Scan complete — {ips} IPs answered / {devs} devices / {conf} in conflict")
                       .format(ips=len(found), devs=sum(map(len, found.values())), conf=conflicts),
                       "warn" if conflicts else "ok")
        record = core.save_scan_history(current_devices(), target,
                                        " + ".join(c.get("desc") or c.get("name", "")
                                                    for c, _ in plan))
        core.STORE.log(T("스캔 기록 저장 — 최근 %d회까지 보관", "Scan history saved — keeping the latest %d")
                       % core.HISTORY_LIMIT, "info")
        result = serialize()
        result["historyId"] = record["id"]
        return result

    if action == "identify":
        dev = core.STORE.devices[payload["key"]]
        core.STORE.set_progress(T("장비 정보 검사", "Identifying"), 0, 1, dev["ip"])
        core.STORE.log(T("장비 정보 검사 시작 — {ip} {mac}",
                         "Identifying — {ip} {mac}").format(ip=dev["ip"], mac=dev["mac"]))
        emit_state()
        try:
            # It has to go out of the adapter that found the device. With more than
            # one adapter swept, that may not be the one selected now.
            core.identify_device(dev, dev.get("ifindex") or core.STORE.ifindex,
                                 dev.get("ifname") or core.STORE.iface,
                                 isolate=True, ports_text=payload.get("ports", ""))
        except Exception as exc:
            core.STORE.set_progress(T("장비 정보 검사", "Identifying"), 0, 1,
                                    T("실패", "failed"))
            core.STORE.log(T("장비 정보 검사 실패 — {ip}: {e}",
                             "Identification failed — {ip}: {e}").format(ip=dev["ip"], e=exc), "error")
            emit_state()
            raise
        core.STORE.set_progress(T("장비 정보 검사", "Identifying"), 1, 1, T("완료", "done"))
        core.STORE.log(T("장비 정보 검사 완료 — {ip} {kind} {model}",
                         "Identified — {ip} {kind} {model}").format(
            ip=dev["ip"], kind=core.kind_show(dev.get("kind")) or T("미확인", "unidentified"),
            model=dev.get("model") or ""), "ok")
        return serialize()

    if action == "isolate":
        dev = core.STORE.devices[payload["key"]]
        core.STORE.set_progress(T("장비 격리", "Isolating"), 0, 1, dev["ip"])
        core.STORE.log(T("격리 시작 — {ip} / {mac}",
                         "Isolating — {ip} / {mac}").format(ip=dev["ip"], mac=dev["mac"]))
        emit_state()
        if core.STORE.isolated and core.STORE.isolated != dev["key"]:
            previous = core.STORE.devices.get(core.STORE.isolated)
            if previous:
                core.arp_unpin(previous["ip"],
                               previous.get("ifindex") or core.STORE.ifindex,
                               previous.get("ifname") or core.STORE.iface)
                previous["status"] = "pending"
        ok, detail = core.arp_pin(dev["ip"], dev["mac"],
                                  dev.get("ifindex") or core.STORE.ifindex,
                                  dev.get("ifname") or core.STORE.iface)
        if not ok:
            raise RuntimeError(detail or T("ARP 격리에 실패했습니다.", "ARP isolation failed."))
        core.STORE.isolated = dev["key"]
        dev["status"] = "isolated"
        core.STORE.set_progress(T("장비 격리", "Isolating"), 1, 1, T("완료", "done"))
        core.STORE.log(T("격리됨 — {ip} / {mac}",
                         "Isolated — {ip} / {mac}").format(ip=dev["ip"], mac=dev["mac"]), "warn")
        return serialize()

    if action == "release":
        if core.STORE.isolated:
            dev = core.STORE.devices[core.STORE.isolated]
            core.arp_unpin(dev["ip"],
                           dev.get("ifindex") or core.STORE.ifindex,
                           dev.get("ifname") or core.STORE.iface)
            dev["status"] = "pending"
            core.STORE.isolated = None
            core.STORE.log(T("격리 해제 — {ip}", "Isolation released — {ip}").format(ip=dev["ip"]), "ok")
        return serialize()

    if action == "snapshot":
        dev = core.STORE.devices[payload["key"]]
        image, method = core.grab_snapshot(dev, payload.get("user", ""), payload.get("password", ""))
        if not image:
            raise RuntimeError(method or T("스냅샷 주소를 찾지 못했습니다.",
                                           "Could not find a snapshot URL."))
        return {"dataUrl": "data:image/jpeg;base64," + base64.b64encode(image).decode(), "method": method}

    # ── Device book ────────────────────────────────────────────────────
    # A table that reads vendor and device type off the MAC prefix. Register an
    # unfamiliar device once on site and it is named the moment the next scan sees it.

    if action == "export":
        fmt = payload.get("format", "json")
        if fmt == "html":
            # The report is a one-page document, not a table. The engine draws it itself.
            core.export_html(payload["path"], site=payload.get("site", ""),
                             note=payload.get("note", ""))
            count = len(core.STORE.devices)
            core.STORE.log(T("현장 리포트 저장 — %s (%d대)",
                             "Site report saved — %s (%d devices)") % (payload["path"], count), "ok")
            return {"path": payload["path"], "count": count}
        rows = []
        with core.STORE.lock:
            for dev in core.STORE.devices.values():
                rows.append({
                    "ip": dev["ip"], "mac": core.dash_mac(dev["mac"]),
                    "vendor": dev.get("vendor", ""), "kind": dev.get("kind", ""),
                    "model": dev.get("model", ""),
                    "name": next((value for value in (dev.get("host", ""), dev.get("mdns", ""),
                                                         dev.get("nbname", ""), dev.get("ssdp", ""))
                                  if value and value != dev.get("model", "")), ""),
                    "ports": dev.get("ports", []), "ms": dev.get("ms"),
                    "os": dev.get("os", ""), "swport": dev.get("swport", ""),
                    "vlan": dev.get("swvlan"), "seen": dev.get("seen", ""),
                })
        rows.sort(key=lambda r: tuple(int(x) for x in r["ip"].split(".")))
        core.export_rows(payload["path"], rows, fmt, core.STORE.cidr, payload.get("columns"))
        core.STORE.log(T("결과 저장 — %s (%d대)",
                         "Results saved — %s (%d devices)") % (payload["path"], len(rows)), "ok")
        return {"path": payload["path"], "count": len(rows)}

    if action == "free_ips":
        # Addresses in the swept range that did not answer. Confirm one before assigning it.
        #
        # If the scan did not run to the end, no list is handed out at all. Put a warning
        # next to the list and people read the list — and then put a device on one.
        if core.STORE.busy:
            raise RuntimeError(T("스캔이 끝난 뒤에 보십시오. 아직 안 훑은 주소가 "
                                 "빈 자리처럼 보입니다.",
                                 "Wait until the scan finishes — addresses not yet "
                                 "swept would look free."))
        info = core.free_ips()
        if not info.get("complete"):
            raise RuntimeError(T("스캔이 끝까지 가지 않았습니다. 이 상태의 빈 IP 목록은 "
                                 "믿을 수 없습니다 — 안 훑은 주소와 조용한 주소가 "
                                 "구분되지 않습니다. 대역을 다시 스캔하십시오.",
                                 "The scan did not finish. A free-IP list from this state "
                                 "cannot be trusted — addresses never swept look the same "
                                 "as silent ones. Re-scan the range."))
        core.STORE.log(T("응답 없는 IP %d개 (훑은 주소 %d개 중 %d개 응답)",
                         "%d non-responsive IPs (%d addresses scanned, %d responded)")
                       % (len(info["free"]), info["scanned"], info["used"]), "info")
        return info

    if action == "free_export":
        if not core.free_ips().get("complete"):
            raise RuntimeError(T("스캔이 끝까지 가지 않아 배정표를 만들 수 없습니다. "
                                 "대역을 다시 스캔하십시오.",
                                 "The scan did not finish, so no worksheet was written. "
                                 "Re-scan the range."))
        count = core.export_candidate_ips(payload["path"])
        core.STORE.log(T("후보 IP 배정표 저장 — %s (%d개)",
                         "Candidate IP worksheet saved — %s (%d rows)") % (payload["path"], count), "ok")
        return {"path": payload["path"], "count": count}

    if action == "snmp_ports":
        result = core.snmp_port_map(
            payload["switch"], payload.get("community") or "public",
            timeout=float(payload.get("timeout") or 1.5),
            log=lambda m: core.STORE.log(m, "ok"))
        hit, slow = core.apply_port_map(result)
        core.STORE.log(T("스위치 포트를 %d대에 붙였습니다.",
                         "Attached switch ports to %d devices.") % hit, "ok" if hit else "warn")
        # One bad pair in the cable and the link stays up, quietly dropping to 100M.
        # Nothing else tells anyone, so this does.
        for row in slow:
            core.STORE.log(
                T("느린 링크 — {ip} 가 {port} 에 {speed}Mbps 로 붙어 있습니다 "
                  "(이 포트는 {ref}Mbps 까지 됩니다). 랜케이블·포트를 확인하십시오.",
                  "Slow link — {ip} is connected at {speed}Mbps on {port} "
                  "(this port can carry {ref}Mbps). Check the cable and port.")
                .format(ip=row["ip"], port=row["port"], speed=row["speed"],
                        ref=row.get("ref") or result.get("top", 0)), "warn")
        return {"switch": result["name"], "read": result["count"], "matched": hit,
                "slow": slow, "top": result.get("top", 0), "state": serialize()}

    if action == "poe_restart":
        # Tell the switch to power-cycle that port. Saves climbing a ladder, but cycle
        # the wrong port and the whole site goes down. So three things are blocked first.
        # Two ways in: right-click a device in the list (key), or pick a port straight off
        # the switch front panel (index). The blocking rules have to be the same either way.
        dev = core.STORE.devices.get(payload.get("key") or "")
        host = (payload.get("switch") or "").strip()
        community = payload.get("community") or ""
        wait = float(payload.get("wait") or 6)
        if not host or not community:
            raise RuntimeError(T("스위치 IP 와 쓰기 커뮤니티 문자열이 필요합니다.",
                                 "The switch IP and a write community are required."))
        if dev is None:
            # The front-panel way in. The UI already worked out and tagged the untouchable ports.
            index = str(payload.get("index") or "")
            if not index:
                raise RuntimeError(T("포트를 고르십시오.", "Choose a port."))
            verify_writable(host, community, index, poe=True)
            core.STORE.log(T("PoE 재시작 — 포트 {p}", "PoE restart — port {p}")
                           .format(p=payload.get("name") or index), "warn")
            emit_state()
            core.poe_restart(host, community, index, wait=wait,
                             log=lambda m: core.STORE.log(m, "warn"))
            core.STORE.log(T("PoE 재시작 완료 — 포트 {p}", "PoE restart done — port {p}")
                           .format(p=payload.get("name") or index), "ok")
            return {"ok": True, "state": serialize()}
        index = dev.get("poeIndex") or ""
        if not index:
            raise RuntimeError(T("이 장비는 PoE 로 전원을 받고 있지 않습니다. "
                                 "먼저 스위치 포트를 조회하십시오.",
                                 "This device is not PoE powered. Run the switch "
                                 "port lookup first."))

        # 0) First, is this the switch the device was found on? Send a 3rd-floor
        #    camera's port number to the 1st-floor switch and some other device loses power.
        if dev.get("swhost") and dev["swhost"] != host:
            raise RuntimeError(
                T("이 장비는 {sw} 에서 찾았습니다. 그 스위치 IP 로 하십시오.",
                  "This device was found on {sw}. Use that switch's IP.")
                .format(sw="%s (%s)" % (dev.get("swname") or "", dev["swhost"])))
        # 1) The port this PC is plugged into is never cut. That is cutting your own line.
        my_macs = my_macs_of_this_pc()
        # 2) Nor the switch itself.
        if dev["ip"] == host:
            raise RuntimeError(T("스위치 자신의 포트는 껐다 켤 수 없습니다.",
                                 "The switch's own port cannot be cycled."))
        # 3) Several devices on one port means another switch or hub hangs below it.
        #    Cut that and everything under it goes down with it.
        sharing = [d for d in core.STORE.devices.values()
                   if d.get("swport") and d.get("swport") == dev.get("swport")
                   and d.get("swname") == dev.get("swname")]
        if len(sharing) > 1:
            raise RuntimeError(
                T("이 포트에 장비가 {n}대 보입니다. 아래에 다른 스위치나 허브가 "
                  "달린 자리라 끊으면 그 아래가 전부 내려갑니다.",
                  "{n} devices are seen on this port — another switch or hub hangs "
                  "below it, and cycling it would take all of them down.")
                .format(n=len(sharing)))
        if core.hex_mac(dev["mac"]) in my_macs:
            raise RuntimeError(T("이 컴퓨터가 물린 포트입니다.",
                                 "This is the port this computer is plugged into."))

        verify_writable(host, community, index, poe=True)
        core.STORE.log(T("PoE 재시작 — {ip} ({port})",
                         "PoE restart — {ip} ({port})")
                       .format(ip=dev["ip"], port=dev.get("swport") or index), "warn")
        emit_state()
        core.poe_restart(host, community, index, wait=wait,
                         log=lambda m: core.STORE.log(m, "warn"))
        core.STORE.log(T("PoE 재시작 완료 — {ip}", "PoE restart done — {ip}")
                       .format(ip=dev["ip"]), "ok")
        return {"ok": True, "state": serialize()}

    if action == "switch_ports":
        # Read every physical port on the switch into a table. Empty ports that are on no
        # list show up too, so "lock the unused ports" at handover happens here in one go.
        host = (payload.get("switch") or "").strip()
        community = payload.get("community") or "public"
        if not host:
            raise RuntimeError(T("스위치 IP 를 넣으십시오.", "Enter the switch IP."))
        ports = core.read_switch_ports(host, community,
                                       timeout=float(payload.get("timeout") or 1.5))
        if not ports:
            raise RuntimeError(T("스위치에서 포트 목록을 못 읽었습니다 (%s).",
                                 "Could not read the port list from the switch (%s).") % host)

        # What sits on which port comes from the switch's own MAC table (row["macs"]).
        # That holds for devices not in our scan list — even with no scan run yet.
        # For a MAC we do know, the IP and device type are shown alongside.
        # A scan swaps STORE out wholesale. Walk it in place while holding the lock and
        # you end up holding one STORE's lock while walking another. Copy it out first.
        store = core.STORE
        with store.lock:
            snapshot = list(store.devices.values())
        known = {core.hex_mac(dev["mac"]): {
                     "ip": dev["ip"], "mac": dev["mac"],
                     "kind": core.kind_show(dev.get("kind")) or "",
                     "vendor": dev.get("vendor") or ""}
                 for dev in snapshot}

        # Pass the originals through. Make copies and the fill-in below lands on the
        # copies only, and the UI still gets empty rows.
        listed = []
        for index, info in ports.items():
            info["index"] = index
            listed.append(info)

        # If the switch withholds its MAC table or the numbering does not line up, this
        # comes back empty. Then fill it from what the last lookup attached (swport) —
        # better than knowing nothing, and never insist "every device is unknown".
        fdb_ok = any(row.get("macs") for row in listed)
        if not fdb_ok:
            for row in listed:
                row["macs"] = [core.hex_mac(d["mac"]) for d in snapshot
                               if d.get("swhost") == host and d.get("swport") == row.get("name")]
            fdb_ok = any(row.get("macs") for row in listed)
            core.STORE.log(
                T("스위치가 MAC 표를 포트 번호에 맞춰 주지 않습니다 — 지난 조회 결과로 "
                  "메웠습니다. 붙은 장비가 비어 보이는 포트는 '모르는 장비' 가 아니라 "
                  "'확인 못 함' 입니다.",
                  "The switch did not line its MAC table up with the port numbers — filled in "
                  "from the last lookup. A port with no device listed is 'unknown', not 'empty'."),
                "warn")
        guard_rows(host, community, listed)

        # Record the port speeds and get back the ports slower than before. A gigabit
        # link sits down at 100M over one bad wire, and nobody finds that by eye.
        name = host
        try:
            name = core.switch_name(host, community)
            slow = core.compare_port_speeds(host, ports, name=name)
        except Exception as err:
            # History is nice to have; it is no reason to keep the port window shut.
            core.STORE.log(T("포트 속도 이력을 남기지 못했습니다 — %s",
                             "Could not record port speed history — %s") % err, "warn")
            slow = []
        slow_by_key = {row["key"]: row for row in slow}
        # What someone marked as "this port has always been 100M". The UI's other guess
        # (slower than its neighbours) has to be silenced too, or the button looks dead.
        okay = {}
        try:
            kept = (core.load_port_history().get(host) or {}).get("ports") or {}
            for key, row in kept.items():
                if isinstance(row, dict) and int(row.get("okSpeed") or 0):
                    okay[key] = int(row["okSpeed"])
        except Exception:
            okay = {}

        # Same judgement the scan's slow-link warning uses. It used to be worked out
        # again on the screen from a different population, and the two disagreed.
        core.mark_slow_ports(listed)

        rows = []
        for info in sorted(listed, key=lambda r: int(r["index"])):
            # For a MAC we do not know, leave the IP blank — the UI shows the MAC instead.
            seen = [known.get(core.hex_mac(m))
                    or {"ip": "", "mac": core.dash_mac(m), "kind": "", "vendor": ""}
                    for m in (info.get("macs") or [])]
            key = core.port_key(info)
            drop = slow_by_key.get(key)
            fine = okay.get(key, 0)
            rows.append(dict(info, devices=seen, speedKey=key,
                             wasSpeed=drop["best"] if drop else 0,
                             wasAt=(drop["bestAt"] if drop else "")[:10],
                             slowLink=bool(info.get("slow")),
                             slowRef=int(info.get("slowRef") or 0),
                             speedOk=bool(fine and int(info.get("speed") or 0) >= fine)))
        locked = sum(1 for r in rows if r["admin"] == 2)
        core.STORE.log(T("포트 {n}개를 읽었습니다 — 사용 중 {up}개 · 잠긴 포트 {lock}개",
                         "Read {n} ports — {up} in use, {lock} locked")
                       .format(n=len(rows), lock=locked,
                               up=sum(1 for r in rows if r["oper"] == 1)), "ok")
        # Half duplex. Reported apart from speed drops — a port caught here has a perfectly
        # normal speed column. Most "it's gigabit but it's slow" complaints are this.
        half = [r for r in rows if core.is_half_duplex(r)]
        if half:
            hits = sum(int(r.get("lateColl") or 0) for r in half)
            core.STORE.log(
                T("반이중으로 앉은 포트 %d개 — %s. 링크도 붙어 있고 속도도 정상으로 "
                  "보이지만 실제로는 느립니다. 양끝 중 한쪽만 속도·듀플렉스를 손으로 "
                  "박아 두면 반대쪽이 협상할 상대가 없어 반이중으로 내려앉습니다 — "
                  "양쪽 다 자동(auto)으로 두십시오.%s",
                  "%d ports running half duplex — %s. The link is up and the speed looks "
                  "fine, but throughput is not. If only one end has speed/duplex hard-coded, "
                  "the other has nothing to negotiate with and falls back to half duplex — "
                  "set both ends to auto.%s")
                % (len(half),
                   ", ".join("%s번" % core.port_number(r) for r in half[:8]),
                   T("  늦은 충돌 %d회가 쌓여 있습니다 — 짐작이 아니라 지금 프레임이 "
                     "깨지고 있다는 뜻입니다.",
                     "  %d late collisions have accumulated — this is not a guess; frames "
                     "are being lost right now.") % hits if hits else ""),
                "warn")

        if slow:
            core.STORE.log(
                T("예전보다 느려진 포트 %d개 — %s. 랜선 양끝을 다시 보십시오: 기가는 "
                  "8가닥을 다 쓰는데, 한 가닥만 헐거워도 링크는 안 끊기고 100M 로 "
                  "내려앉습니다.",
                  "%d ports slower than before — %s. Re-check both cable ends: gigabit "
                  "uses all 8 wires, and one loose wire silently drops it to 100M.")
                % (len(slow), ", ".join(
                    "%s번 %s->%s" % (row["no"], core.speed_label(row["best"]),
                                     core.speed_label(row["speed"])) for row in slow[:6])),
                "warn")
        # The name was already asked for above. Asking an unresponsive switch again
        # throws away 1.5 seconds with someone standing there waiting.
        return {"switch": host, "ports": rows, "fdbOk": fdb_ok, "slow": slow,
                "switchName": name}

    if action == "port_speed_ok":
        # "This port has always been 100M" — drop the baseline to the current speed.
        # If a port with a deliberately 100M device on it stays red forever, people
        # start ignoring red altogether. An ignored warning is worse than none.
        host = (payload.get("switch") or "").strip()
        key = (payload.get("port") or "").strip()
        if not host or not key:
            raise RuntimeError(T("어느 스위치의 어느 포트인지 알 수 없습니다.",
                                 "Missing switch or port."))
        if not core.accept_port_speed(host, key):
            raise RuntimeError(T("이 포트의 기록이 없습니다. 포트를 한 번 더 읽은 뒤에 "
                                 "다시 누르십시오.",
                                 "No history for this port. Read the ports once more, "
                                 "then try again."))
        core.STORE.log(T("%s %s — 지금 속도를 정상으로 기록했습니다.",
                         "%s %s — current speed recorded as normal.") % (host, key), "ok")
        return {"switch": host, "port": key}

    if action == "report_export":
        # Handover and inspection report. Exactly what installers used to type into Excel.
        #
        # The switches are gathered by themselves from the swhost tagged on the list.
        # Make someone re-enter the IPs and one gets missed, and a missed switch
        # disappears from the document without a trace. That is not a report, it is a lie.
        path = payload.get("path") or ""
        if not path:
            raise RuntimeError(T("저장할 곳을 정하십시오.", "Choose where to save."))
        # Mid-scan the device list is only half full. Pull a handover document then and
        # numbers like "12 devices, no conflicts" go straight to the customer.
        if core.STORE.busy:
            raise RuntimeError(T("스캔이 끝난 뒤에 뽑으십시오. 지금은 장비 목록이 "
                                 "아직 채워지는 중이라 문서의 숫자가 틀립니다.",
                                 "Wait until the scan finishes — the device list is "
                                 "still filling, so the numbers would be wrong."))
        community = payload.get("community") or "public"
        timeout = float(payload.get("timeout") or 1.5)
        hosts = [str(h).strip() for h in (payload.get("switches") or []) if str(h).strip()]
        if not hosts:
            with core.STORE.lock:
                hosts = sorted({(d.get("swhost") or "").strip()
                                for d in core.STORE.devices.values()} - {""})

        switches, missed = [], []
        REPORT_MAX = 8
        # Switches past the eighth that went unread still go in as "not checked". Drop
        # them silently and the document claims that switch was fine.
        for extra in hosts[REPORT_MAX:]:
            missed.append((extra, T("한 번에 스위치 %d대까지만 읽습니다. 스위치 IP 칸에 "
                                    "나눠 넣고 두 번 뽑으십시오.",
                                    "Only %d switches are read at once. Split them across "
                                    "two runs using the switch IP field.") % REPORT_MAX))
        for number, host in enumerate(hosts[:REPORT_MAX], 1):
            core.STORE.log(T("리포트: 스위치 읽는 중 %d/%d — %s",
                             "Report: reading switch %d/%d — %s")
                           % (number, min(len(hosts), 8), host), "info")
            try:
                ports = core.read_switch_ports(host, community, timeout)
                if not ports:
                    raise RuntimeError(T("포트 목록이 비었습니다.", "Empty port list."))
                name = core.switch_name(host, community, timeout)
                had = bool((core.load_port_history().get(host) or {}).get("ports"))
                slow = core.compare_port_speeds(host, ports, name=name)
            except Exception as err:
                # Unreadable is no reason to drop it. It goes in the report as "not checked".
                missed.append((host, str(err) or err.__class__.__name__))
                core.STORE.log(T("리포트: %s 스위치를 못 읽었습니다 — %s",
                                 "Report: could not read switch %s — %s")
                               % (host, err), "warn")
                continue
            switches.append({"ip": host, "name": name, "ports": ports,
                             "poeMain": core.LAST_POE_MAIN.get(host) or {},
                             "slow": slow, "hadHistory": had})

        core.export_xlsx(path, site=payload.get("site", ""),
                         note=payload.get("note", ""),
                         author=payload.get("author", ""),
                         switches=switches, missed=missed)
        drops = sum(len(sw["slow"]) for sw in switches)
        core.STORE.log(T("준공 리포트 저장 — %s (스위치 %d대 · 장비 %d대%s)",
                         "Report saved — %s (%d switches, %d devices%s)")
                       % (path, len(switches), len(core.STORE.devices),
                          T(" · 속도 저하 %d곳", ", %d speed drops") % drops if drops else ""),
                       "ok")
        return {"path": path, "switches": len(switches), "missed": len(missed),
                "slow": drops, "devices": len(core.STORE.devices)}

    if action == "port_admin":
        # Lock or unlock a port. Unlocking is always safe, so it is never blocked.
        host = (payload.get("switch") or "").strip()
        community = payload.get("community") or ""
        index = str(payload.get("index") or "")
        up = bool(payload.get("up"))
        if not host or not community:
            raise RuntimeError(T("스위치 IP 와 쓰기 커뮤니티 문자열이 필요합니다.",
                                 "The switch IP and a write community are required."))
        if not index:
            raise RuntimeError(T("포트를 고르십시오.", "Choose a port."))
        # Unlocking is always safe. Only locking gets verified.
        if not up:
            verify_writable(host, community, index)
        core.set_port_admin(host, community, index, up,
                            timeout=float(payload.get("timeout") or 1.5))
        core.STORE.log(
            (T("포트 {p} 를 풀었습니다 — 링크가 붙는 데 몇 초, 스위치가 루프를 "
               "확인하는 동안(STP) 통신이 트이기까지 최대 30초쯤 더 걸릴 수 "
               "있습니다.",
               "Unlocked port {p} — the link takes a few seconds, and traffic may "
               "not pass for up to ~30s more while the switch runs STP.") if up
             else T("포트 {p} 를 잠갔습니다 — 이 포트로는 이제 아무도 못 들어옵니다.",
                    "Locked port {p} — nothing can connect through it now."))
            .format(p=payload.get("name") or index), "ok" if up else "warn")
        return {"ok": True, "index": index, "up": up}

    if action == "port_link":
        # One port's state right now. Used while waiting for a link after unlocking.
        # Read-only, so no write community is needed and no lock check runs.
        host = (payload.get("switch") or "").strip()
        index = str(payload.get("index") or "")
        community = payload.get("community") or "public"
        if not host or not index:
            raise RuntimeError(T("스위치 IP 와 포트가 필요합니다.",
                                 "The switch IP and a port are required."))
        return core.read_port_link(host, community, index,
                                   timeout=float(payload.get("timeout") or 1.5))

    if action == "poe_admin":
        # Leave PoE on or off. Turning it off carries the same weight as locking a
        # port, so the same guards apply. Turning it on is always safe.
        host = (payload.get("switch") or "").strip()
        community = payload.get("community") or ""
        index = str(payload.get("index") or "")
        on = bool(payload.get("on"))
        if not host or not community:
            raise RuntimeError(T("스위치 IP 와 쓰기 커뮤니티 문자열이 필요합니다.",
                                 "The switch IP and a write community are required."))
        if not index:
            raise RuntimeError(T("포트를 고르십시오.", "Choose a port."))
        if not on:
            verify_writable(host, community, index, poe=True)
        core.set_poe_admin(host, community, index, on,
                           timeout=float(payload.get("timeout") or 1.5))
        core.STORE.log(
            (T("포트 {p} 에 PoE 전원을 넣었습니다.", "Restored PoE power on port {p}.") if on
             else T("포트 {p} 의 PoE 전원을 끊었습니다 — 다시 넣기 전까지 꺼진 채로 있습니다.",
                    "Cut PoE power on port {p} — it stays off until restored."))
            .format(p=payload.get("name") or index), "ok" if on else "warn")
        return {"ok": True, "index": index, "on": on}

    if action == "history_list":
        return [{"id": row["id"], "savedAt": row.get("savedAt", ""),
                 "target": row.get("target", ""), "iface": row.get("iface", ""),
                 "count": len(row.get("devices", {}))}
                for row in core.load_scan_history()]

    if action == "history_compare":
        record = core.find_scan_history(payload.get("id", ""))
        if not record:
            raise RuntimeError(T("선택한 스캔 기록을 찾지 못했습니다.",
                                 "The selected scan record was not found."))
        base = record.get("devices", {})
        added, gone, moved = core.compare_device_maps(base, current_devices())
        core.STORE.log(T("스캔 기록 비교 — 새로 %d대 · 사라짐 %d대 · IP 바뀜 %d대",
                         "Scan history compared — %d new · %d gone · %d changed IP") % (
            len(added), len(gone), len(moved)), "ok")
        return {"savedAt": record.get("savedAt", ""), "name": record.get("target", ""),
                "added": added, "gone": gone, "moved": moved, "baseCount": len(base)}

    if action == "book_list":
        return {"rows": core.BOOK.rows(), "path": core.BOOK.path,
                "count": len(core.BOOK.index)}

    if action == "book_lookup":
        return {"entry": core.BOOK.lookup(payload.get("prefix", ""))}

    if action == "book_save":
        created = core.BOOK.upsert(
            payload.get("prefix", ""), payload.get("vendor", ""),
            payload.get("kind", ""), payload.get("note", ""))
        core.BOOK.save()
        prefix = core.hex_mac(payload.get("prefix", ""))
        core.STORE.log(T("장비 사전 %s — %s (%s)", "Device book %s — %s (%s)") % (
            (T("등록", "add") if created else T("수정", "update")), prefix.upper(),
            payload.get("kind") or T("종류 없음", "no type")), "ok")
        # Apply it to the devices already on the list right away
        _refresh_from_book()
        return {"created": created, "rows": core.BOOK.rows(), "state": serialize()}

    if action == "book_remove":
        core.BOOK.remove(payload.get("prefix", ""))
        core.BOOK.save()
        core.STORE.log(T("장비 사전에서 지움 — %s",
                         "Removed from device book — %s") % payload.get("prefix", "").upper())
        _refresh_from_book()
        return {"rows": core.BOOK.rows(), "state": serialize()}

    if action == "book_export":
        core.BOOK.export_to(payload["path"])
        core.STORE.log(T("장비 사전 내보냄 — %s",
                         "Device book exported — %s") % payload["path"], "ok")
        return {"path": payload["path"], "count": len(core.BOOK.index)}

    if action == "book_import":
        added, updated = core.BOOK.import_from(payload["path"], payload.get("replace", False))
        core.BOOK.save()
        core.STORE.log(T("장비 사전 가져옴 — 추가 %d, 갱신 %d",
                         "Device book imported — %d added, %d updated") % (added, updated), "ok")
        _refresh_from_book()
        return {"added": added, "updated": updated,
                "rows": core.BOOK.rows(), "state": serialize()}

    raise RuntimeError(T("알 수 없는 요청: ", "Unknown request: ") + action)


# Long-running work. Run this on the reader thread and nothing the UI sends gets
# picked up meanwhile. A report can sweep eight switches at once, so one unresponsive
# switch among them stalls it for minutes.
# Anything that talks to a switch belongs here. port_admin calls verify_writable, which
# reads the whole port list: against a switch that receives but does not answer that is
# ~30s during which the stdin loop reads nothing at all — Stop included, which is the
# exact hazard finish()'s comment describes.
SLOW_ACTIONS = ("report_export", "switch_ports", "snmp_ports", "poe_restart",
                "port_admin", "poe_admin", "port_link")


def serve():
    """Long jobs like scans and reports are handled on a thread of their own."""
    global SCAN_RUNNING
    def finish(req):
        global SCAN_RUNNING
        action = req.get("action")
        try:
            data = run(action, req.get("payload") or {})
            response = {"id": req["id"], "ok": True, "data": data}
        except Exception as exc:
            response = {"id": req.get("id", 0), "ok": False, "error": str(exc)}
        finally:
            if action == "scan":
                core.STORE.busy = False
                with SCAN_LOCK:
                    SCAN_RUNNING = False
                    SCAN_CANCEL.clear()
                emit_state()
        send_json(response)

    for line in sys.stdin:
        try:
            req = json.loads(line)
            action = req.get("action")
        except Exception as exc:
            send_json({"id": 0, "ok": False, "error": str(exc)})
            continue
        if action == "scan":
            with SCAN_LOCK:
                if SCAN_RUNNING:
                    send_json({"id": req.get("id", 0), "ok": False,
                               "error": T("이미 스캔 중입니다.", "A scan is already running.")})
                    continue
                SCAN_RUNNING = True
                SCAN_CANCEL.clear()
            threading.Thread(target=finish, args=(req,), daemon=True).start()
        elif action in SLOW_ACTIONS:
            # Hold this line while several switches are swept and nothing the UI sends
            # is read. Stop stops working and the window looks dead.
            threading.Thread(target=finish, args=(req,), daemon=True).start()
        else:
            finish(req)


# Guarded so tests can import this file and call run() directly.
if __name__ == "__main__":
    serve()
