# 라이선스 · License

**Quiet Scanner** — 현장 IP 충돌 정리 도구
Copyright (C) 2026 고요한

> **English** — This program is free software under the **GNU General Public
> License, version 2** (or, at your option, any later version). The full,
> authoritative licence text is in [`LICENSE`](LICENSE); this file is only a
> plain-language summary in Korean. There is **NO WARRANTY**.
> Third-party components are listed in [`docs/third-party.md`](docs/third-party.md).

이 프로그램은 자유 소프트웨어입니다. 자유 소프트웨어 재단이 공표한
**GNU 일반 공중 사용 허가서 제2판**(GPLv2) 또는 그 이후 판의 조건에 따라
재배포하거나 수정할 수 있습니다.

이 프로그램은 유용하게 쓰이기를 바라며 배포하지만, **아무런 보증도 하지
않습니다.** 상품성이나 특정 목적 적합성에 대한 묵시적 보증조차 없습니다.
자세한 내용은 GNU 일반 공중 사용 허가서를 보십시오.

**법적 효력이 있는 것은 [`LICENSE`](LICENSE) 파일의 영문 전문입니다.**
이 문서는 그것을 한국어로 풀어 쓴 안내일 뿐입니다. 둘이 어긋나 보이면
언제나 `LICENSE` 쪽이 맞습니다.

---

## GPLv2 를 쓰는 이유

ARP 패킷을 직접 다루는 데 **Scapy**(GPLv2)를 씁니다. 제조사 등록부는
**Wireshark 의 manuf 파일**(GPL-2.0-or-later)에서 가져왔습니다.
GPL 저작물을 담아 배포하므로 이 프로그램 전체도 같은 조건을 따릅니다.

가져다 쓴 것들의 목록은 [`docs/third-party.md`](docs/third-party.md) 를 보십시오.

---

## 이 프로그램을 가져다 쓸 때

- **써도 됩니다.** 회사 일에 쓰든 고객 현장에 쓰든 상관없습니다.
- **고쳐도 됩니다.** 다만 고친 것을 남에게 나눠줄 때는 그 소스도 같이
  GPLv2 로 공개해야 합니다.
- **exe 만 나눠주면 안 됩니다.** GPLv2 3조는 실행파일을 배포할 때 소스도
  같이 주거나, 소스를 주겠다는 서면 제안을 3년간 유지하라고 정합니다.
  여기서는 소스가 저장소에 통째로 있으므로 저장소 주소를 같이 알려주면 됩니다.
- **빌드 스크립트도 소스의 일부입니다** (`scripts/`, `build.bat`). GPLv2 가
  "실행파일을 만드는 데 쓰는 스크립트"를 명시적으로 소스에 포함시킵니다.

원저작자 표시(`Copyright (C) 2026 고요한`)는 지우면 안 됩니다.
