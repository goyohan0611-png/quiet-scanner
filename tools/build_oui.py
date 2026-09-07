# -*- coding: utf-8 -*-
"""IEEE 등록부에서 oui.dat.gz 를 다시 만든다.

왜 필요한가:
    처음 쓰던 표는 와이어샤크 manuf 의 옛 사본이었다. 2020년 이후 배정된
    앞자리가 통째로 빠져 있어서, 현장에서 하이크비전 CC-13-F3, 시스코
    84-5A-3E 같은 흔한 장비가 전부 "미상" 으로 떴다. MA-L 39,505개 중
    8,611개(22%)가 없었다.

쓰는 법:
    python tools/build_oui.py            # 받아서 만들고 oui.dat.gz 덮어쓰기

파일 꼴:
    앞자리(소문자 16진, 구분자 없음)\t제조사이름
    앞자리는 6자리(MA-L) · 7자리(MA-M) · 9자리(MA-S) 세 가지다.
    IPFixStudio.vendor_of() 가 9 → 7 → 6 순으로 좁은 것부터 본다.
"""
import csv, gzip, io, os, re, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "oui.dat.gz")

SOURCES = [
    ("https://standards-oui.ieee.org/oui/oui.csv", 6),
    ("https://standards-oui.ieee.org/oui28/mam.csv", 7),
    ("https://standards-oui.ieee.org/oui36/oui36.csv", 9),
]

# 현장에서 자주 보는 회사는 이름을 짧게 고정한다. 목록 칸이 좁고,
# "Hangzhou Hikvision Digital Technology Co.,Ltd." 는 읽을 사람이 없다.
BRANDS = [
    (r"hikvision", "Hikvision"),
    (r"\bdahua\b", "Dahua"),
    (r"hanwha|samsung techwin", "Hanwha"),
    (r"\buniview\b|zhejiang uniview", "Uniview"),
    (r"\baxis communication", "Axis"),
    (r"\bvivotek\b", "Vivotek"),
    (r"\bcisco\b", "Cisco"),
    (r"\bhuawei\b", "Huawei"),
    (r"\btp-?link\b", "TP-Link"),
    (r"\bd-?link\b", "D-Link"),
    (r"\bnetgear\b", "Netgear"),
    (r"\bubiquiti\b", "Ubiquiti"),
    (r"\bmikrotik\b|mikrotikls", "MikroTik"),
    (r"\bruijie\b", "Ruijie"),
    (r"\bhewlett[- ]packard\b|^hp inc|hewlett packard enterprise", "HP"),
    (r"\bdell\b", "Dell"),
    (r"\blenovo\b", "Lenovo"),
    (r"\basustek\b|\basus\b", "ASUS"),
    (r"\bapple\b", "Apple"),
    (r"\bintel\b", "Intel"),
    (r"\brealtek\b", "Realtek"),
    (r"\bsynology\b", "Synology"),
    (r"\bqnap\b", "QNAP"),
    (r"\bextron\b", "Extron"),
    (r"\bcrestron\b", "Crestron"),
    (r"\bkramer\b", "Kramer"),
    (r"\bbiamp\b", "Biamp"),
    (r"\bshure\b", "Shure"),
    (r"\bbarco\b", "Barco"),
    (r"\bepson\b|seiko epson", "Epson"),
    (r"\bcanon\b", "Canon"),
    (r"\bricoh\b", "Ricoh"),
    (r"\bbrother\b", "Brother"),
    (r"\bsamsung\b", "Samsung"),
    (r"\blg electronics\b|^lg innotek", "LG"),
    (r"\bxiaomi\b", "Xiaomi"),
    (r"\bsonos\b", "Sonos"),
    (r"\braspberry pi\b", "Raspberry Pi"),
    (r"\bvmware\b", "VMware"),
    (r"\bmicrosoft\b", "Microsoft"),
    (r"\bgoogle\b", "Google"),
    (r"\bamazon\b", "Amazon"),
]

# 회사 이름 끝에 붙는 법인 표기. 이름을 알아보는 데 도움이 안 된다.
SUFFIX = re.compile(
    r"[,\s]*(?:"
    r"co\.?|corp\.?|corporation|company|inc\.?|incorporated|ltd\.?|limited|"
    r"llc|l\.l\.c\.?|plc|gmbh|mbh|ag|a\.?g\.?|s\.?a\.?|s\.?a\.?s\.?|sarl|"
    r"s\.?p\.?a\.?|b\.?v\.?|n\.?v\.?|a/s|ab|oy|oyj|as|pty|pte|kg|kk|k\.k\.?|"
    r"llp|lp|jsc|ooo|zao|pjsc"
    r")\.?$", re.I)


def short(name):
    """긴 법인명을 목록 칸에 들어갈 이름으로 줄인다."""
    text = re.sub(r"\s+", " ", (name or "").replace('"', " ")).strip()
    low = text.lower()
    for pattern, brand in BRANDS:
        if re.search(pattern, low):
            return brand
    text = text.split(",")[0].strip()          # 쉼표 뒤는 대개 법인 표기다
    for _ in range(3):                          # "Co., Ltd." 처럼 겹쳐 붙는다
        stripped = SUFFIX.sub("", text).strip(" .,")
        if stripped == text:
            break
        text = stripped
    text = text.strip(" .,")
    return (text[:28].rstrip() if len(text) > 28 else text) or (name or "").strip()[:28]


def fetch(url):
    # 사용자 에이전트를 안 붙이면 IEEE 가 418 로 잘라 버린다.
    request = urllib.request.Request(url, headers={"User-Agent": "QuietScanner-oui-build/1.0"})
    with urllib.request.urlopen(request, timeout=120) as fh:
        return fh.read().decode("utf-8", "replace")


def main():
    table = {}
    # 옛 표를 먼저 깐다. 손으로 다듬은 이름과 특수 주소(멀티캐스트 등)를
    # 살리기 위해서다. IEEE 에서 새로 들어오는 것은 빈 자리만 채운다.
    if os.path.isfile(OUT):
        with gzip.open(OUT, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                key, _, value = line.rstrip("\n").partition("\t")
                if key and value:
                    table[key.strip().lower()] = value.strip()
    before = len(table)

    added = 0
    for url, width in SOURCES:
        rows = csv.DictReader(io.StringIO(fetch(url)))
        for row in rows:
            key = re.sub(r"[^0-9a-f]", "", (row.get("Assignment") or "").lower())
            name = (row.get("Organization Name") or "").strip()
            if len(key) != width or not name:
                continue
            if name.lower() in ("private", "ieee registration authority"):
                continue
            if key in table:
                continue
            table[key] = short(name)
            added += 1
        print(f"{url.rsplit('/', 1)[-1]}: 처리 완료")

    with gzip.open(OUT, "wt", encoding="utf-8", newline="\n") as fh:
        for key in sorted(table):
            fh.write(f"{key}\t{table[key]}\n")
    print(f"{before:,} → {len(table):,} (새로 {added:,}개)  {OUT}")


if __name__ == "__main__":
    sys.exit(main())
