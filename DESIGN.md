---
name: Quiet Scanner
description: 많은 장비를 빠르게 읽는 고밀도 현장 스캐너
colors:
  blue: "#2878f0"
  blue-deep: "#1769df"
  blue-hover: "#1158c0"
  blue-active: "#e4efff"
  ink: "#182230"
  muted: "#596a80"
  control-text: "#34465c"
  secondary-text: "#63748a"
  panel: "#fff"
  bg: "#f7f9fc"
  line: "#e7ecf3"
  control-border: "#d7e0eb"
  hover: "#eef5ff"
  red-text: "#b82d42"
  red-bg: "#fff5f6"
  conflict-badge: "#ffe4e8"
  own-text: "#087c53"
  own-bg: "#effaf4"
  isolated-text: "#5c43c3"
  isolated-bg: "#f0ecff"
  terminal-bg: "#f8fafd"
typography:
  title:
    fontFamily: "SUIT, 'Malgun Gothic', sans-serif"
    fontSize: "16px"
    fontWeight: 650
    lineHeight: 1.45
  body:
    fontFamily: "SUIT, 'Malgun Gothic', sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.45
  data:
    fontFamily: "SUIT, 'Malgun Gothic', sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.45
  control:
    fontFamily: "SUIT, 'Malgun Gothic', sans-serif"
    fontSize: "13px"
    fontWeight: 500
    lineHeight: 1.45
  label:
    fontFamily: "SUIT, 'Malgun Gothic', sans-serif"
    fontSize: "11.5px"
    fontWeight: 400
    lineHeight: 1.45
  ip:
    fontFamily: "SUIT, 'Malgun Gothic', sans-serif"
    fontSize: "13.5px"
    fontWeight: 500
    lineHeight: 1.25
  terminal:
    fontFamily: "'Cascadia Mono', Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  inline: "3px"
  tag: "4px"
  item: "5px"
  control: "7px"
  menu: "9px"
  dialog: "12px"
spacing:
  tight: "6px"
  control-gap: "7px"
  compact: "8px"
  small: "10px"
  medium: "12px"
  related: "14px"
  section: "16px"
  page: "20px"
  dialog: "24px"
components:
  button-primary:
    backgroundColor: "{colors.blue-deep}"
    textColor: "{colors.panel}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "34px"
  button-primary-hover:
    backgroundColor: "{colors.blue-hover}"
    textColor: "{colors.panel}"
  button-secondary:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.control-text}"
    typography: "{typography.control}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "34px"
  button-danger:
    backgroundColor: "{colors.red-text}"
    textColor: "{colors.panel}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "34px"
  input:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "0 10px"
    height: "34px"
  conflict-chip:
    backgroundColor: "{colors.conflict-badge}"
    textColor: "{colors.red-text}"
    rounded: "{rounded.tag}"
    padding: "2px 6px"
  isolated-chip:
    backgroundColor: "{colors.isolated-bg}"
    textColor: "{colors.isolated-text}"
    rounded: "{rounded.tag}"
    padding: "2px 7px"
  dialog:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.dialog}"
    padding: "21px 24px 20px"
    width: "520px"
---

# Design System: Quiet Scanner

## Overview

**Creative North Star: "Quiet Scanner"**

현장에서 장비를 많이, 빠르게 읽는 기존 스캐너의 시각 체계다. 흰색·옅은 회색 바탕에 파란 동작, 빨간 충돌, 초록 자기 IP를 유지한다. 새 브랜드나 장식적 화면으로 확장하지 않고 SUIT와 작은 컨트롤, 얇은 구분선으로 읽기 순서를 정리한다.

**Key Characteristics:**
- 많은 장비를 한 화면에 담는 조밀한 표
- 색과 텍스트를 함께 쓰는 상태 구분
- 평평한 작업면과 필요한 순간의 메뉴·대화상자

근거: `electron/renderer/styles.css`, `index.html`, `app.js`. 사용자 선택과 적용 범위는 `PRODUCT.md`, `docs/ui-direction.md`, `.impeccable/surfaces/electron-renderer-index-html.md`에 따른다. 이 문서는 완성 코드에서 추출한 체계이며 seed가 아니다.

## Colors

흰 작업면과 차분한 회색 위에서 동작과 네트워크 상태를 구분한다. 값은 앞의 토큰을 기준으로 한다.

사이드카의 8단계 OKLCH 색상 램프는 패널 표시용으로 합성한 참고값이며, 제품 CSS의 추가 색상 토큰이 아니다.

### Primary
- **동작 파랑** (`blue-deep`): 스캔·저장·확인 버튼과 선택된 인터페이스 주소. `blue-hover`는 주 버튼 hover, `blue`는 키보드 초점과 진행률이다.
- **옅은 동작 파랑** (`hover`, `blue-active`): 보조 버튼·선택 항목의 hover와 보조 버튼의 active 상태다. 주 동작 버튼은 hover·active 모두 진한 파랑을 유지하며, 분리 확인 버튼은 진한 빨강을 유지한다.

### Secondary
- **충돌 빨강** (`red-text`, `red-bg`, `conflict-badge`): 충돌 그룹·오류·분리 확인 동작을 강조한다.
- **자기 IP 초록** (`own-text`, `own-bg`): 자기 PC 행과 태그. 성공 결과에도 같은 글자색을 쓴다.
- **분리 보라** (`isolated-text`, `isolated-bg`): 분리됨·분리 확인 필요 상태 태그다.

### Neutral
- **진한 잉크** (`ink`): 본문·IP와 대화상자 제목.
- **보조 잉크** (`control-text`, `muted`, `secondary-text`): 데이터·컨트롤, 설명·필드 이름, MAC·시각의 순서로 강도를 낮춘다.
- **흰 작업면** (`panel`)과 **옅은 바탕** (`bg`, `terminal-bg`): 주 작업면과 보조 영역을 분리한다.
- **가벼운 경계** (`line`, `control-border`): 목록 구분과 입력·버튼 윤곽이다.

**The 상태색 Rule.** 충돌은 빨강, 자기 IP는 초록으로 유지하고 상태 텍스트를 함께 표시한다.

## Typography

**Body Font:** 로컬 SUIT Variable, 한글 대체 Malgun Gothic, sans-serif. 로컬 파일은 `electron/renderer/fonts/SUIT-Variable.woff2`다.
**Label/Mono Font:** Ping 터미널에만 Cascadia Mono, Consolas, monospace를 사용한다.

### Hierarchy
- **Title:** 대화상자 제목. 대형 display 서체 단계는 없다.
- **Body:** 화면 기본 문장. 실제 장비 행은 더 조밀한 `data`, 버튼은 `control` 역할을 쓴다.
- **Label:** 상태·로그·보조 정보. 필드 이름은 더 작은 크기(11px), 표 머리는 같은 크기에 중간 굵기(500)를 쓴다.
- **IP:** 복사 가능한 주소. MAC 보조 줄은 작은 크기(11px), 일반 MAC 셀은 본문보다 작게(12px) 표시한다.
- **Terminal:** Ping 응답 행. 터미널 머리와 시각은 작은 크기(11px)를 쓴다.

**The 주소도 SUIT Rule.** 일반 IP·MAC·응답 수치는 UI와 같은 글꼴에 `tabular-nums`를 적용한다. 고정폭 서체는 Ping 터미널에 한정한다.

## Layout

세로 화면을 설정 줄, 결과·도구 줄, 남은 높이를 채우는 장비 목록, 로그 조절 손잡이(6px), 하단 로그로 나눈다. 본문 전체는 스크롤하지 않고 목록과 로그가 각각 스크롤한다. 로그 기본 높이는 134px이며 사용자가 조절한다.

장비·충돌 행은 최소 높이(40px), 좌우 여백은 `page`, 열 간격은 `medium`이다. IP와 MAC 두 줄의 실제 행 높이는 내용과 선을 포함해 약 40.3px다. 표 머리와 결과 행은 같은 동적 열 구성을 공유한다. 충돌 하위 장비는 추가 들여쓰기(22px)로 소속을 표시한다.

너비 1000px 이하에서는 바깥 여백을 16px로 줄이고 도구를 조밀하게 배치한다. 760px 이하에서는 인터페이스를 첫 줄 전체에 놓고 결과 도구를 줄바꿈하며 표 열 간격을 8px로 줄인다. 560px 이하에서는 DHCP 제목을 세로로 쌓고 사용 후보 IP를 두 열로 표시한다. 큰 화면의 빈 공간을 장식 카드로 채우지 않는다.

## Elevation & Depth

기본 작업면은 그림자 없이 흰 바탕·옅은 색면·얇은 선으로 나눈다. 떠 있는 메뉴와 대화상자에만 확산 그림자를 사용한다. 메뉴 그림자는 `0 8px 32px #18223029`, 대화상자는 `0 18px 56px #1822302e`이며 대화상자 뒤에는 반투명 바탕(`#09142066`)을 둔다.

**The 평평한 작업면 Rule.** 표와 로그에 그림자를 추가하지 않는다. 그림자는 떠 있는 메뉴와 대화상자의 층을 설명한다.

## Shapes

작은 모서리 곡률로 클릭 대상과 상태를 구분한다. 입력과 기본 버튼은 `control`, 태그는 `tag`, 메뉴 항목은 `item`, 메뉴는 `menu`, 대화상자는 `dialog`를 쓴다. 표 행은 둥근 카드로 분절하지 않고 직선 구분선을 공유한다. 아이콘은 채워진 문자 대신 단정한 SVG 윤곽선이며 기본 크기는 16px, 작은 도구에서는 14px다.

## Components

### Buttons
조밀하고 명확한 동작. 기본 버튼과 입력은 같은 높이를 공유한다. 주 버튼은 파란 채움·흰 글자·굵기(600), 보조 버튼은 흰 바탕·가벼운 윤곽, 분리 확인은 빨간 채움이다. 목록 도구는 더 작은 높이(32px)와 글자(12px)를 쓴다. hover의 배경·경계 전환은 140ms ease다. 초점은 파란 윤곽(2px)과 간격(2px), disabled는 옅은 바탕과 약해진 글자로 구분한다.

### Chips
짧고 작게 상태만 표시한다. 충돌 배지는 빨간 색면·글자(10.5px), 분리 배지는 보라 색면·글자(11.5px)다. 자기 IP는 초록 행과 작은 “내 PC” 글자(10px)로 표시하며 별도 칩 외곽을 만들지 않는다.

### Cards / Containers
주 화면은 카드 격자가 아닌 연속 표다. 대화상자만 흰 카드와 그림자를 사용하며 기본 너비는 `dialog`, 넓은 정보 창은 680px다. 화면보다 커지면 내부 스크롤을 사용한다. 제목·본문·푸터를 가벼운 간격으로 구분한다.

### Inputs / Fields
흰 바탕, 가벼운 경계, 작은 모서리, 글자(13px)를 사용한다. 초점에서 경계가 파랑으로 바뀌고 키보드 초점 윤곽도 유지한다. 검색은 윤곽 아이콘을 왼쪽에 놓고 입력 여백을 34px로 늘린다.

### Menus
독립 내비게이션 바는 없다. 인터페이스 선택과 장비 우클릭 메뉴는 흰색 팝업과 좌측 정렬 항목으로 구성한다. 메뉴 안쪽 여백(5px), 항목 높이(33px), 항목 글자(12.5px)를 사용한다. 선택된 인터페이스는 파란 체크 SVG와 옅은 파란 면을 함께 표시한다.

### 장비 표와 로그
충돌 그룹은 펼침 윤곽 아이콘·IP 복사 버튼·충돌 배지를 묶는다. 하위 장비는 옅은 빨간 면과 들여쓰기로 이어진다. IP 복사 버튼은 평소 투명하고 hover에서 파란 글자와 밑줄로 반응한다. 로그는 작은 SUIT로 시간과 메시지를 나누며 성공·경고·오류를 글자색으로 구분한다. 진행 막대는 4px 두께, 너비 전환은 160ms ease다. 줄어든 동작 설정에서는 전환을 제거한다.

## Do's and Don'ts

### Do:
- **Do** 많은 장비를 한 화면에 담는 조밀한 표와 독립 스크롤을 유지한다.
- **Do** 충돌·자기 IP의 기존 의미색과 상태 문구를 함께 유지한다.
- **Do** 일반 IP·MAC에 SUIT와 등폭 숫자를 사용하고 터미널만 고정폭으로 표시한다.
- **Do** 작은 버튼·입력의 정렬과 눈에 보이는 키보드 초점을 유지한다.

### Don't:
- **Don't** 프로그램 내부에 중복 제목이나 장식 배너를 추가한다.
- **Don't** 장비 행을 넓은 카드로 바꿔 사용자가 선택한 정보 밀도를 낮춘다.
- **Don't** 기본 표·로그에 팝업용 그림자를 적용한다.
