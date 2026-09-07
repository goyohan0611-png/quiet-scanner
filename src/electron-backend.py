#!/usr/bin/env python3
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
"""Electron 화면에서 호출하는 IPFix 네트워크 엔진(JSON Lines)."""
import base64
import concurrent.futures as futures
import ipaddress
import json
import sys
import threading

try:
    sys.stdout.reconfigure(encoding="utf-8")
    # Electron은 요청 JSON을 UTF-8로 보낸다. 경로에 한글이 있으면 stdin도
    # 같은 인코딩으로 읽어야 '현장리포트' 같은 파일명이 깨지지 않는다.
    sys.stdin.reconfigure(encoding="utf-8")
except AttributeError:
    pass

import IPFixStudio as core
from IPFixStudio import T

core.STORE = core.Store(demo=False)
core.BOOK.load()
OUTPUT_LOCK = threading.Lock()
SCAN_LOCK = threading.Lock()
SCAN_CANCEL = threading.Event()
SCAN_RUNNING = False

# 지난번에 비정상 종료돼서 남아 있는 격리가 있으면 먼저 걷어낸다.
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
    """스캔 스레드와 취소 요청의 JSON이 한 줄에 섞이지 않게 보낸다."""
    with OUTPUT_LOCK:
        print(json.dumps(message, ensure_ascii=False), flush=True)


def emit_state():
    send_json({"event": "state", "data": serialize()})


RECHECK_HISTORY = 3


# 포트를 끄기 전에 "꺼도 되는가" 를 스위치에게 직접 묻는다.
#
# 규칙이 하나다 — **확인이 안 되면 거절한다.** '모르겠다' 와 '괜찮다' 를 같이
# 취급하면, 스위치가 답을 안 하는 바로 그 상황에서 관리 포트가 잠긴다. 그러면
# 그 순간부터 SNMP 가 안 닿아서 되돌릴 방법도 없다. 콘솔 케이블 들고 현장이다.
#
# 캐시도 안 쓴다. 캐시는 5분 전 배선을 기억하는데, 그 사이 기사가 랜선을 옮겨
# 꽂았을 수 있다. 쓰기는 드물고 되돌릴 수 없으니 매번 다시 읽는다.

# 이 컴퓨터의 랜카드 MAC. STORE 는 스캔할 때마다 새로 만들어지므로
# 프로세스 쪽에 따로 둔다 — 스캔이 실패해도 이건 안 날아간다.
KNOWN_MACS = set()

NEVER_LOCK = ("이 컴퓨터가 물린 포트", "this computer's port",
              "스위치 관리 포트", "the switch's own port")


def my_macs_of_this_pc():
    """이 컴퓨터의 랜카드 MAC 전부. 16진수 12자리로만 맞춘다.

    스위치의 MAC 표는 구분자 없이(aabbcc...) 오고 랜카드 목록은 콜론을
    달고(aa:bb:cc:...) 온다. 겉모양으로 비교하면 절대 안 맞고, 그러면
    "내 포트" 를 못 알아봐서 스스로 연결을 끊게 된다.
    """
    macs = set(core.STORE.mymacs or set())
    if core.STORE.mymac:
        macs.add(core.STORE.mymac)
    return {core.hex_mac(m) for m in macs if m}


def switch_own_macs(host, community, rows):
    """스위치 자신의 MAC. 직접 묻고, 스캔에서 본 것도 더한다."""
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
    """이 포트를 끄면 안 되는 이유. 없으면 빈 글자."""
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
    """포트 목록에 '못 끄는 이유' 를 붙인다. 화면에 보여줄 때 쓴다."""
    mine = my_macs_of_this_pc()
    switch_macs = switch_own_macs(host, community, rows)
    for row in rows:
        row["blocked"] = block_reason(row.get("macs"), mine, switch_macs)
    return rows


def verify_writable(host, community, index, poe=False):
    """이 포트를 꺼도 되는지 지금 확인한다. 안 되면 예외를 던진다.

    확인할 수 없는 것이 하나라도 있으면 거절한다:
      - 포트 목록을 못 읽음
      - MAC 표를 못 읽음 (어느 포트가 업링크인지 알 수 없다)
      - 이 컴퓨터의 랜카드를 모름 (내 포트를 못 가린다)
      - 그런 번호의 포트가 없음
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

    # 우리가 아는 번호인가. PoE 는 번호 체계가 따로라 표에서 되짚는다.
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

    if not any(info.get("macs") for info in ports.values()):
        refuse(T("스위치가 MAC 표를 안 내줍니다 — 어느 포트가 업링크인지 알 수 없습니다",
                 "the switch will not give up its MAC table — uplinks cannot be told apart"))
    if core.SNMP_WALK_TRUNCATED & {core.OID_Q_FDB_PORT, core.OID_FDB_PORT}:
        refuse(T("MAC 표가 너무 커서 다 못 읽었습니다 — 업링크를 놓칠 수 있습니다",
                 "the MAC table was too large to read in full — an uplink could be missed"))

    reason = block_reason(ports[target].get("macs"),
                          mine, switch_own_macs(host, community, ports))
    if reason:
        raise RuntimeError(T("이 포트는 끌 수 없습니다 — %s.",
                             "This port cannot be switched off — %s.") % reason)


def plan_ranges(target, cards):
    """대역 조각을 랜카드에 나눠 준다.

    랜선 두 개로 대역 두 개를 쓰는 서버 같은 자리에서, 각 대역은 그 대역을
    가진 랜카드로 나가야 답이 온다. 어느 카드에도 안 맞는 조각은 첫 카드가
    맡는다 — 사람이 일부러 다른 대역을 적어 넣은 경우다.

    돌려주는 것: [(랜카드, "대역 조각들"), ...]
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

    # 조각의 **첫 주소만** 보고 카드를 고르면 안 된다. 192.168.0.0/22 처럼 한
    # 조각이 서브넷 여러 개를 덮으면, 첫 주소가 맞는 카드로 전부 나간다. ARP 는
    # 자기 대역 밖으로는 애초에 못 나가므로 나머지 주소는 조용할 수밖에 없고,
    # 그러면 그 주소들이 "확인했는데 비어 있음" 으로 둔갑한다. 주소 하나하나를
    # 자기 대역을 가진 카드에 붙인다.
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

    # 어느 카드에도 안 맞는 주소도 훑기는 한다 — 첫 카드가 맡는다. 사람이 일부러
    # 다른 대역을 적어 넣었을 수 있고(라우터 너머), 그건 사람 판단이다. 다만
    # 답이 없어도 "비어 있다" 고 말하면 안 되므로 따로 표시해 돌려준다.
    if homeless and cards:
        buckets[0].extend(homeless)

    # 카드의 대역을 하나도 모르면(윈도우가 프리픽스를 안 줄 때가 있다) "대역
    # 밖" 이라고 단정할 근거가 없다. 모른다는 것과 닿을 수 없다는 것은 다르다 —
    # 여기서 헷갈리면 멀쩡한 스캔 결과가 통째로 빈 IP 목록에서 빠진다.
    # 훑기는 위에서 이미 배정했고, 여기서는 '못 믿을 주소' 딱지만 뗀다.
    if not any(nets):
        homeless = []

    plan = []
    for n, rows in enumerate(buckets):
        if rows:
            plan.append((cards[n], compact_ranges(rows)))
    return plan, sorted(set(homeless))


def compact_ranges(addresses):
    """주소 목록을 "192.168.0.1-40,192.168.0.55" 처럼 짧게 되묶는다.

    한 개씩 쉼표로 이으면 /22 하나에 문자열이 1,000토막이 된다. 아래에서 다시
    parse_target 을 타므로 짧게 만들어 두는 편이 낫다.
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
    """같은 대역을 최근 세 번 훑는 동안 한 번이라도 답했던 IP 들.

    한 번만 보면 절전 장비가 두 번 내리 흘렸을 때 놓친다. 세 번을 합쳐 보면
    그런 장비도 목록에 남는다. 진짜로 뜯어간 장비는 여기서 세 번 더 물어봐도
    답이 없으니 세 스캔 뒤에는 조용히 사라진다.

    비교 대상이 없으면 빈 집합이다 — 첫 스캔이면 다시 물어볼 것도 없다.
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
    """사전이 바뀌면 이미 목록에 올라온 장비의 제조사·종류를 다시 매긴다."""
    with core.STORE.lock:
        for dev in core.STORE.devices.values():
            seen = core.describe(dev["mac"])
            dev["book"] = seen["from_book"]
            dev["book_exact"] = seen["exact"]
            dev["book_note"] = seen["note"]
            if seen["from_book"]:
                dev["vendor"] = seen["vendor"]
                # 이미 조사해서 알아낸 종류는 덮지 않는다.
                # 단 사람이 전체 MAC 으로 콕 집어 등록했다면 그 이름이 이긴다.
                if seen["exact"] or not dev.get("identified"):
                    if seen["kind"]:
                        dev["kind"] = seen["kind"]
                        dev["kind_confidence"] = "confirmed" if seen["exact"] else "estimated"


def run(action, payload):
    if action == "set_lang":
        # 화면에서 언어를 바꾸면 엔진이 만드는 로그도 따라가야 한다.
        return {"lang": core.set_lang(payload.get("lang"))}

    if action == "kinds":
        # 장비 종류 이름표는 엔진이 한 벌만 가지고 있다. 화면이 받아 쓴다.
        return core.KIND_EN

    if action == "interfaces":
        if not core.ensure_scapy():
            raise RuntimeError(T("scapy/Npcap을 불러오지 못했습니다: ",
                                 "Could not load scapy/Npcap: ") + core.SCAPY_ERR)
        cards = core.list_ifaces()
        # 이 컴퓨터의 랜카드 MAC 을 여기서 기억해 둔다. 스캔을 한 번도 안
        # 돌리고 바로 포트를 잠그러 가는 사람이 있고, 그때도 "내 포트" 를
        # 알아봐야 한다. 프로그램이 켜지면 이 동작은 무조건 한 번 돈다.
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
        # 데모는 완성된 한 판이다. 그렇게 표시해 두지 않으면 빈 IP 창이
        # "스캔이 안 끝났다" 며 거절한다 — 둘러보러 켠 사람에게는 고장으로 보인다.
        base = seen[0].rsplit(".", 1)[0] if seen else "192.168.0"
        core.STORE.cidr = "%s.1-60" % base
        # 시드 IP 를 반드시 포함시킨다. 빠지면 쓰고 있는 자리가 빈 IP 로 나온다.
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
        # 랜카드를 여러 개 고를 수 있다. 서버처럼 랜선 두 개로 대역 두 개를
        # 같이 쓰는 자리에서, 한 번 훑어 양쪽을 다 보기 위해서다.
        cards = payload.get("ifaces") or [payload["iface"]]
        target = payload["target"]
        # 대역을 먼저 따져 본다. 여기서 튕길 거면 지금 목록을 갈아엎을 이유가 없다.
        targets = core.parse_target(target)
        if len(targets) > core.MAX_TARGETS:
            raise ValueError(T("대상이 너무 많습니다 (%d개). 범위를 좁혀 주십시오.",
                               "Too many targets (%d). Narrow the range.") % len(targets))
        KNOWN_MACS.update(c.get("mac", "") for c in cards if c.get("mac"))

        # 새 STORE 로 갈아치우기 전에 걸려 있던 격리를 반드시 푼다.
        #
        # 안 풀면 정적 ARP 는 이 PC 에 그대로 남는데 화면은 그걸 잊는다. '격리
        # 해제' 를 눌러도 아무 일이 안 일어나고, 그 IP 는 계속 한 MAC 으로만
        # 보인다 — 찾으려던 충돌을 자기 툴이 가려 버리는 셈이다.
        # 로그는 새 STORE 가 생긴 뒤에 적어야 한다. 여기서 적으면 바로 아래
        # 줄에서 통째로 버려진다 — 그런데 이게 기사가 꼭 봐야 할 메시지다.
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
        # 여기에 대상 전체를 미리 넣으면 안 된다. 스캔이 터지거나(Npcap 없음,
        # 권한 없음) 중간에 멈추면 장비 목록은 비어 있는데 '훑은 주소' 만
        # 254개가 남는다. 그 상태로 후보 IP 를 누르면 **대역 전체가 "비었음"**
        # 으로 나오고, 기사는 쓰고 있는 자리에 장비를 박는다. 이 도구가 낼 수
        # 있는 제일 나쁜 오답이다. 실제로 확인이 끝난 주소만 넣는다.
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
            """랜카드 하나로 한 대역을 훑는다. 찾은 것은 바깥 목록에 쌓인다."""
            nonlocal done_base
            # 이 카드로 잡힌 장비는 이 카드를 기억해야 나중에 격리가 된다.
            core.STORE.iface = card.get("scapyName") or card["name"]
            core.STORE.ifindex = card.get("index")
            sub_list = core.parse_target(sub_target)

            # ARP 는 라우터를 못 넘는다. 내 IP 와 다른 대역을 훑으면 같은 스위치에
            # 물려 있는 장비만 답한다. 답이 없다고 장비가 없는 것은 아니다.
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
                # 1차만 돌고 멈춘 주소는 '확인했다' 고 할 수 없다. 넣지 않는다.
                return

            # ── 이 아래가 "쓰는 IP를 확실히 걸러낸다" 는 부분이다 ──────────────
            #
            # ARP 는 한 통짜리 물음이다. 스위치가 바쁘거나 랜카드가 절전에 들어가
            # 있으면 그 한 통을 흘린다. 한 번 물어보고 없다고 단정하면, 쓰고 있는
            # IP를 "비었다" 고 알려주게 된다. 그게 이 도구가 낼 수 있는 제일 나쁜
            # 오답이다 — 기사가 그 IP를 새 장비에 박으면 충돌이 난다.
            #
            # 그래서 답이 없는 주소만 골라 두 번 더, 점점 참을성 있게 다시 묻는다.
            # 이미 답한 주소는 다시 안 물으니 시간은 조금만 더 든다.

            def ask_again(addresses, timeout, retry, phase, note):
                """주소 몇 개만 다시 물어보고 찾은 것을 목록에 더한다."""
                if not addresses or core.STORE.cancel.is_set():
                    return 0
                order = sorted(addresses, key=lambda x: tuple(int(n) for n in x.split(".")))
                core.STORE.set_progress(phase, 0, len(order), note)
                emit_state()
                picked = 0
                # 한 번에 다 던지면 또 흘린다. 나눠서 묻는다.
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

            # 2차 — 답이 없던 주소 전부. 처음 보는 장비가 첫 물음을 흘린 경우를 잡는다.
            #       새 현장의 첫 스캔에서는 비교할 지난 기록이 없으니 이게 유일한 그물이다.
            #       오래 기다리는 것보다 여러 번 묻는 쪽이 낫다 — 같은 망에 있는 장비의
            #       ARP 응답은 밀리초 단위로 온다. 1.8초를 기다릴 이유가 없다.
            silent = [ip for ip in swept if ip not in found]
            got_n = ask_again(silent, 0.7, 3,
                              T("2차 확인", "Second pass"),
                              T("답이 없던 %d개를 다시 확인", "re-checking %d silent addresses")
                              % len(silent))
            if got_n:
                core.STORE.log(T("2차 확인에서 %d대를 더 찾았습니다.",
                                 "Second pass found %d more devices.") % got_n, "ok")

            # 3차 — 지난 스캔에 있었는데 여기까지도 답이 없는 주소. 대개 절전 장비다.
            #       숫자가 몇 개 안 되니 제일 참을성 있게 묻는다.
            stubborn = (previous_scan_ips(target) & set(sub_list)) - set(found)
            # 여기는 3차라 시간이 제일 많이 든다. 그래서 64개까지만 본다.
            # 자른 것을 로그에 안 적으면 "다 물어봤다" 로 읽혀서, 남은 주소가
            # 빈 IP 로 새어 나가는 것을 아무도 못 알아챈다.
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

            # 마지막 — 이 랜카드 자신. ARP 는 자기가 외친 것을 자기가 듣지 못하므로
            # 이 컴퓨터는 절대 스스로 잡히지 않는다. 넣어주지 않으면 내 IP가
            # "비어 있는 주소" 로 나가고, 기사가 그 주소를 장비에 박게 된다.
            # 세 번의 확인을 다 거친 주소만 '훑었다' 로 친다. 중지로 여기까지
            # 못 온 대역은 통째로 빠진다 — 한 번만 물어본 주소가 빈 IP 목록에
            # 섞이면, 그건 세 번 확인한 것과 화면에서 구분이 안 된다.
            if not core.STORE.cancel.is_set():
                # 대역 밖 주소는 애초에 닿지 않는다. 조용하다고 '확인했다' 로
                # 세면 그대로 빈 IP 가 된다.
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
        # 기본 랜카드를 첫 카드로 되돌린다 — 이후 동작이 이걸 기본값으로 쓴다.
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
        # 스캔이 끝나면 망 전체에 한 번 외친다. 장비마다 찾아가는 게 아니라
        # 멀티캐스트 두 통이면 끝이라, 대수가 많아도 시간이 늘지 않는다.
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
        with core.STORE.lock:
            for dev in core.STORE.devices.values():
                name = names.get(dev["ip"], "")
                info = upnp.get(dev["ip"]) or {}
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

        if core.STORE.cancel.is_set():
            core.STORE.set_progress(T("대역 스캔", "Range scan"), len(scanned), len(targets),
                                    T("중지됨", "stopped"))
            core.STORE.log(T("스캔 중지 — 이름 수집 뒤에 종료했습니다.",
                             "Scan stopped after name collection."), "warn")
            result = serialize()
            result["canceled"] = True
            return result

        # 포트를 적어 넣었으면 "그 포트를 쓰는 장비만" 보자는 뜻이다.
        # ARP 로 찾은 장비마다 그 포트를 두드려 보고, 아무것도 안 열려 있으면 뺀다.
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
                # 중지를 눌렀으면 거르지 않는다. 반쯤 거른 목록을 남기면
                # 확인 못 한 장비가 빈 IP 로 나간다.
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
                # 숨긴 장비의 IP 는 "훑은 주소" 에서도 빼야 한다. 안 그러면
                # 쓰고 있는 IP 가 빈 IP 목록으로 나간다 — 제일 나쁜 오답이다.
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
            # 그 장비를 찾은 랜카드로 나가야 한다. 카드를 둘 이상 골라 훑었으면
            # 지금 고른 카드와 다를 수 있다.
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

    # ── 장비 사전 ──────────────────────────────────────────────────────
    # MAC 앞자리로 제조사와 장비 종류를 알아보는 표. 현장에서 처음 보는 장비를
    # 한 번 등록해두면 다음부터는 스캔하자마자 이름이 뜬다.

    if action == "export":
        fmt = payload.get("format", "json")
        if fmt == "html":
            # 리포트는 표가 아니라 한 장짜리 문서다. 엔진이 직접 그린다.
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
        # 훑은 대역에서 응답하지 않은 자리. 실제 비어 있는지는 배정 전에 확인해야 한다.
        #
        # 스캔이 끝까지 안 갔으면 목록을 아예 안 준다. 경고만 띄우고 목록을
        # 같이 주면 사람은 목록을 본다 — 그리고 그 자리에 장비를 박는다.
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
        # 케이블 한 쌍만 나가도 링크는 안 끊기고 조용히 100M 으로 떨어진다.
        # 아무도 안 알려주니 여기서 알려준다.
        for row in slow:
            core.STORE.log(
                T("느린 링크 — {ip} 가 {port} 에 {speed}Mbps 로 붙어 있습니다 "
                  "(이 스위치 최고 {top}Mbps). 랜케이블·포트를 확인하십시오.",
                  "Slow link — {ip} is connected at {speed}Mbps on {port} "
                  "(this switch tops out at {top}Mbps). Check the cable and port.")
                .format(ip=row["ip"], port=row["port"], speed=row["speed"],
                        top=result.get("top", 0)), "warn")
        return {"switch": result["name"], "read": result["count"], "matched": hit,
                "slow": slow, "top": result.get("top", 0), "state": serialize()}

    if action == "poe_restart":
        # 스위치한테 그 포트 전원을 껐다 켜라고 시킨다. 사다리를 안 타도 되지만,
        # 엉뚱한 포트를 끄면 현장이 통째로 내려간다. 그래서 세 가지를 먼저 막는다.
        # 부르는 길이 둘이다. 목록에서 장비를 우클릭하거나(key), 스위치 앞판에서
        # 포트를 직접 고르거나(index). 어느 쪽이든 막는 규칙은 같아야 한다.
        dev = core.STORE.devices.get(payload.get("key") or "")
        host = (payload.get("switch") or "").strip()
        community = payload.get("community") or ""
        wait = float(payload.get("wait") or 6)
        if not host or not community:
            raise RuntimeError(T("스위치 IP 와 쓰기 커뮤니티 문자열이 필요합니다.",
                                 "The switch IP and a write community are required."))
        if dev is None:
            # 앞판에서 온 길. 못 만지는 포트인지는 화면이 이미 판단해 붙여 보낸다.
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

        # 0) 그 장비를 찾은 스위치가 맞는지부터 본다. 3층 카메라의 포트 번호를
        #    1층 스위치에 보내면 엉뚱한 장비의 전원이 나간다.
        if dev.get("swhost") and dev["swhost"] != host:
            raise RuntimeError(
                T("이 장비는 {sw} 에서 찾았습니다. 그 스위치 IP 로 하십시오.",
                  "This device was found on {sw}. Use that switch's IP.")
                .format(sw="%s (%s)" % (dev.get("swname") or "", dev["swhost"])))
        # 1) 내 PC 가 물린 포트는 절대 못 끊는다. 스스로 연결을 끊는 짓이다.
        my_macs = my_macs_of_this_pc()
        # 2) 스위치 자신도 안 된다.
        if dev["ip"] == host:
            raise RuntimeError(T("스위치 자신의 포트는 껐다 켤 수 없습니다.",
                                 "The switch's own port cannot be cycled."))
        # 3) 한 포트에 장비가 여럿 보이면 그 아래 다른 스위치나 허브가 달린 것이다.
        #    거기를 끊으면 그 아래가 통째로 내려간다.
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
        # 스위치의 물리 포트를 전부 읽어 표로 만든다. 목록에 없는 빈 포트까지
        # 나오므로, 준공 때 "안 쓰는 포트 잠그기" 를 여기서 한 번에 할 수 있다.
        host = (payload.get("switch") or "").strip()
        community = payload.get("community") or "public"
        if not host:
            raise RuntimeError(T("스위치 IP 를 넣으십시오.", "Enter the switch IP."))
        ports = core.read_switch_ports(host, community,
                                       timeout=float(payload.get("timeout") or 1.5))
        if not ports:
            raise RuntimeError(T("스위치에서 포트 목록을 못 읽었습니다 (%s).",
                                 "Could not read the port list from the switch (%s).") % host)

        # 어느 포트에 무엇이 붙었는지는 스위치가 내준 MAC 표(row["macs"])로 안다.
        # 우리 스캔 목록에 없어도 — 스캔을 아직 안 돌렸어도 — 판단이 선다.
        # 우리가 아는 MAC 이면 IP·장비 종류까지 같이 보여준다.
        # STORE 는 스캔이 통째로 갈아치운다. 잠금을 잡은 채로 그 자리에서 훑으면
        # 다른 STORE 의 잠금을 잡고 이 STORE 를 훑는 일이 생긴다. 먼저 베껴 온다.
        store = core.STORE
        with store.lock:
            snapshot = list(store.devices.values())
        known = {core.hex_mac(dev["mac"]): {
                     "ip": dev["ip"], "mac": dev["mac"],
                     "kind": core.kind_show(dev.get("kind")) or "",
                     "vendor": dev.get("vendor") or ""}
                 for dev in snapshot}

        # 원본을 그대로 넘긴다. 사본을 만들면 아래 메우기가 사본에만 들어가서,
        # 화면에는 여전히 빈 채로 나간다.
        listed = []
        for index, info in ports.items():
            info["index"] = index
            listed.append(info)

        # 스위치가 MAC 표를 안 내주거나 번호가 안 맞으면 여기가 통째로 빈다.
        # 그때는 지난 조회에서 목록에 붙여둔 것(swport)으로 메운다 — 아무것도
        # 모르는 것보다 낫고, 무엇보다 "다 모르는 장비" 라고 우기면 안 된다.
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

        # 포트 속도를 적어 두고, 예전보다 느려진 포트를 받아 온다. 기가 링크는
        # 랜선 한 가닥만 나가도 조용히 100M 로 앉는데, 이걸 사람 눈으로는 못 찾는다.
        name = host
        try:
            name = core.switch_name(host, community)
            slow = core.compare_port_speeds(host, ports, name=name)
        except Exception as err:
            # 이력은 있으면 좋은 것이지, 포트 관리 창을 못 열게 할 이유는 아니다.
            core.STORE.log(T("포트 속도 이력을 남기지 못했습니다 — %s",
                             "Could not record port speed history — %s") % err, "warn")
            slow = []
        slow_by_key = {row["key"]: row for row in slow}
        # 사람이 "이 포트는 원래 100M 입니다" 라고 눌러 둔 값. 화면의 다른 짐작
        # (옆 포트들보다 느리다)까지 같이 재워야 단추가 먹은 것처럼 보인다.
        okay = {}
        try:
            kept = (core.load_port_history().get(host) or {}).get("ports") or {}
            for key, row in kept.items():
                if isinstance(row, dict) and int(row.get("okSpeed") or 0):
                    okay[key] = int(row["okSpeed"])
        except Exception:
            okay = {}

        rows = []
        for info in sorted(listed, key=lambda r: int(r["index"])):
            # 우리가 모르는 MAC 이면 IP 는 비워 둔다 — 화면이 MAC 을 대신 보여준다.
            seen = [known.get(core.hex_mac(m))
                    or {"ip": "", "mac": core.dash_mac(m), "kind": "", "vendor": ""}
                    for m in (info.get("macs") or [])]
            key = core.port_key(info)
            drop = slow_by_key.get(key)
            fine = okay.get(key, 0)
            rows.append(dict(info, devices=seen, speedKey=key,
                             wasSpeed=drop["best"] if drop else 0,
                             wasAt=(drop["bestAt"] if drop else "")[:10],
                             speedOk=bool(fine and int(info.get("speed") or 0) >= fine)))
        locked = sum(1 for r in rows if r["admin"] == 2)
        core.STORE.log(T("포트 {n}개를 읽었습니다 — 사용 중 {up}개 · 잠긴 포트 {lock}개",
                         "Read {n} ports — {up} in use, {lock} locked")
                       .format(n=len(rows), lock=locked,
                               up=sum(1 for r in rows if r["oper"] == 1)), "ok")
        # 반이중. 속도 저하와 따로 알린다 — 여기 걸린 포트는 속도 칸이 멀쩡해서
        # 아무리 봐도 안 보인다. "1G 인데 느리다" 는 신고의 정체가 대개 이것이다.
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
        # 이름은 위에서 이미 물어봤다. 답 없는 스위치에 한 번 더 물으면
        # 사람이 기다리는 자리에서 1.5초를 그냥 버린다.
        return {"switch": host, "ports": rows, "fdbOk": fdb_ok, "slow": slow,
                "switchName": name}

    if action == "port_speed_ok":
        # "이 포트는 원래 100M 입니다" — 기준을 지금 속도로 내린다.
        # 일부러 100M 장비를 물려 둔 포트가 영원히 빨갛게 남으면, 사람은 곧 빨간색
        # 전체를 무시하게 된다. 무시당하는 경고는 없는 것만 못하다.
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
        # 준공·점검 리포트. 기사들이 손으로 엑셀에 치던 것을 그대로 뽑는다.
        #
        # 스위치는 목록에 붙은 swhost 에서 저절로 모은다. 사람이 IP 를 다시
        # 입력하게 만들면 한 대를 빠뜨리고, 빠뜨린 스위치는 문서에서 조용히
        # 사라진다. 그건 리포트가 아니라 거짓말이다.
        path = payload.get("path") or ""
        if not path:
            raise RuntimeError(T("저장할 곳을 정하십시오.", "Choose where to save."))
        # 스캔 도중이면 장비 목록이 반만 차 있다. 그 상태로 준공 문서를 뽑으면
        # "장비 12대, 충돌 없음" 같은 숫자가 그대로 고객에게 나간다.
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
        # 여덟 대를 넘겨 못 읽은 스위치도 '확인 못 함' 으로 적는다. 조용히
        # 빼면 문서가 "그 스위치는 문제 없었다" 고 거짓말하는 셈이 된다.
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
                # 못 읽었다고 그냥 빼면 안 된다. 리포트에 '확인 못 함' 으로 적는다.
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
        # 포트를 잠그거나 푼다. 푸는 것은 언제나 안전하므로 막지 않는다.
        host = (payload.get("switch") or "").strip()
        community = payload.get("community") or ""
        index = str(payload.get("index") or "")
        up = bool(payload.get("up"))
        if not host or not community:
            raise RuntimeError(T("스위치 IP 와 쓰기 커뮤니티 문자열이 필요합니다.",
                                 "The switch IP and a write community are required."))
        if not index:
            raise RuntimeError(T("포트를 고르십시오.", "Choose a port."))
        # 푸는 것은 언제나 안전하다. 잠그는 것만 확인한다.
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
        # 포트 하나의 지금 상태. 풀어 놓고 링크가 붙기를 기다리는 동안 쓴다.
        # 읽기만 하므로 쓰기 커뮤니티가 필요 없고, 잠금 검사도 하지 않는다.
        host = (payload.get("switch") or "").strip()
        index = str(payload.get("index") or "")
        community = payload.get("community") or "public"
        if not host or not index:
            raise RuntimeError(T("스위치 IP 와 포트가 필요합니다.",
                                 "The switch IP and a port are required."))
        return core.read_port_link(host, community, index,
                                   timeout=float(payload.get("timeout") or 1.5))

    if action == "poe_admin":
        # PoE 를 켠 채로/끈 채로 둔다. 끄는 것은 포트 잠그기와 같은 무게라
        # 같은 자리를 막는다. 켜는 것은 언제나 안전하다.
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
        # 이미 잡아둔 장비들에도 바로 반영한다
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


# 오래 걸리는 일. 이걸 읽기 스레드에서 그대로 돌리면 그동안 화면이 보내는
# 것을 하나도 못 받는다. 리포트는 스위치 여덟 대를 통째로 훑을 수 있어서
# 답 없는 스위치가 하나만 끼어도 분 단위로 멈춘다.
SLOW_ACTIONS = ("report_export", "switch_ports", "snmp_ports", "poe_restart")


def serve():
    """스캔·리포트처럼 오래 걸리는 일은 별도 스레드에서 처리한다."""
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
            # 스위치를 여러 대 훑는 동안 이 줄에서 붙잡고 있으면, 그동안 화면이
            # 보내는 것을 하나도 못 읽는다. 중지도 안 먹고 창이 죽은 것처럼 보인다.
            threading.Thread(target=finish, args=(req,), daemon=True).start()
        else:
            finish(req)


# 시험에서 이 파일을 불러다 run() 만 직접 부를 수 있도록 감싸둔다.
if __name__ == "__main__":
    serve()
