# 이 프로그램이 쓰는 남의 코드

Quiet Scanner 는 **GPLv2** 로 공개합니다. 아래 것들을 가져다 쓰기 때문입니다.

| 가져다 쓴 것 | 하는 일 | 라이선스 |
|---|---|---|
| **Scapy** | ARP 패킷을 직접 만들고 받는다. 충돌 감지의 핵심 | GPLv2 |
| **Wireshark manuf** | IEEE 제조사 등록부 원본 (`oui.dat.gz` 가 여기서 나왔다) | GPL-2.0-or-later |
| **Pretendard** | 화면 글꼴 | SIL OFL 1.1 |
| **Electron / Chromium** | 앱 창과 화면 | MIT / BSD 등 |
| **PyInstaller** | 파이썬을 exe 로 묶는다 | GPL + 예외조항 (묶인 결과물은 자유) |

## Npcap 은 넣지 않았습니다

ARP 를 직접 다루려면 Npcap 드라이버가 필요하지만, **설치 파일에 끼워 넣지 않았습니다.**
쓰는 분이 직접 받아 설치하십시오 — https://npcap.com

Npcap 라이선스가 이 방식을 권합니다:

> 무료·오픈소스 개발자에게는 보통 사용자가 직접 내려받아 설치하도록 안내하라고
> 권합니다. 5대 이하면 무료입니다.

시공 노트북 한두 대면 5대 한도에 한참 못 미칩니다.

## 전문

- Scapy — https://github.com/secdev/scapy/blob/master/LICENSE
- Wireshark — https://gitlab.com/wireshark/wireshark/-/blob/master/COPYING
- Pretendard — https://github.com/orioncactus/pretendard/blob/main/LICENSE
- Npcap — https://github.com/nmap/npcap/blob/master/LICENSE
