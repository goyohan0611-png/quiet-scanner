# Ubuntu/Linux 보호 모드 — 개발 중

Quiet Scanner 안에서 선택적으로 사용하는 호스트 보호 기능이다. 현재 배포된 4.2.0에는 포함되지 않았다. 자체 악성 패킷 판별 엔진이 아니라 **CrowdSec 탐지 엔진과 공식 nftables 방화벽 구성요소를 관리하는 통합 기능**이다. 기존 스캐너의 실행에 CrowdSec는 필요하지 않다.

## 보호 범위

- CrowdSec에 설정된 로그 수집·시나리오가 만든 IP 차단 결정을 사용한다.
- Quiet Scanner 전용 systemd 서비스가 IPv4/IPv6의 **input** 경로에 차단 규칙을 설치한다. 앱을 닫아도 서비스는 유지된다.
- Docker/VM의 전달 트래픽, 아웃바운드 악성 연결, HTTPS 본문 검사, 백신, 범용 IPS는 이번 구현 범위에 없다.
- CDN·외부 리버스 프록시 뒤의 서비스는 실제 공격 IP와 방화벽에서 보이는 접속 IP가 다를 수 있다. 해당 프록시/WAF의 차단 연동이 필요하다.
- Linux에서 실행 중인 **그 컴퓨터**가 대상이다. Windows 앱에서 원격 Linux 서버를 제어하는 기능은 없다.
- 엔진과 차단 구성요소의 메모리·CPU 사용량이 추가된다. 가벼움이나 탐지율은 아직 측정하지 않았다.

## 준비

Ubuntu 24.04 이상, systemd, nftables, CrowdSec 1.6.8 이상과 공식 firewall bouncer가 필요하다. CrowdSec의 [공식 Linux 설치 안내](https://docs.crowdsec.net/u/getting_started/installation/linux/)에 따라 저장소를 추가하고 버전을 확인한 뒤 설치한다.

```sh
sudo apt install crowdsec crowdsec-firewall-bouncer-nftables nftables
```

설치 패키지는 기본 `crowdsec-firewall-bouncer.service`를 자동 실행할 수 있다. 기존에 사용하던 차단 구성을 확인해야 한다. Quiet Scanner는 해당 서비스를 멈추거나 기존 방화벽 규칙을 덮어쓰지 않는다. 이 앱의 보호 모드를 꺼도 다른 구성요소의 차단은 유지된다.

CrowdSec에서 SSH 또는 웹 서버의 **실제 로그 수집과 탐지 규칙**을 설정한다. 엔진 프로세스가 실행된다는 사실만으로 서비스별 공격 탐지가 준비됐다는 뜻은 아니다. CrowdSec의 외부 API·위협 정보 공유·갱신 설정은 엔진 설정을 따른다. Quiet Scanner가 새 외부 계정에 가입하거나 데이터를 전송하지는 않는다.

## 앱에서 사용

1. 상단 **보호 모드 → 상태 확인**에서 관리자 승인.
2. **보호 준비**로 로컬 엔진 인증 키, 전용 구성과 systemd 서비스 생성. 이 단계에서 차단을 켜지는 않는다.
3. 원격 관리에 쓰는 신뢰할 IP를 **허용 예외**에 등록. 하나의 IPv4/IPv6 주소만 허용한다.
4. 보호 스위치를 켜고 상태 확인이 끝날 때까지 기다린다.
5. 서비스 실행·재부팅 후 유지·최근 엔진 API 조회(45초 이내)·IPv4/IPv6의 input 필터 경로를 확인해야 **보호 중**으로 표시한다. 공식 bouncer는 출처별 set과 DROP 규칙을 차단 결정이 생길 때 만든다. 초기에는 빈 경로의 준비 상태를, set이 생긴 뒤에는 source-set DROP 규칙을 확인한다. 활성 로컬 차단 결정이 있는 주소 계열은 빈 경로만으로 성공 처리하지 않는다.
6. 끌 때 서비스와 전용 테이블이 실제로 없어졌는지 확인한다. 일부 규칙이 남았거나 조회에 실패하면 꺼짐으로 표시하지 않는다.

기존 설정을 사용하며 기본 로컬 API 주소 `http://127.0.0.1:8080/`를 전제로 한다. 서비스가 다른 주소를 사용한다면 이번 통합 기능을 바로 사용할 수 없다.

## 화면 없는 서버

같은 실행 파일의 CLI로 제어할 수 있다. GUI와 별개로 보호 서비스가 유지된다.

```sh
sudo quiet-scanner --protection prepare
sudo quiet-scanner --protection allow 198.51.100.10
sudo quiet-scanner --protection on
sudo quiet-scanner --protection status
sudo quiet-scanner --protection off
sudo quiet-scanner --protection remove-allow 198.51.100.10
```

예시 IP 대신 실제 관리자의 주소를 입력한다. CLI 결과는 JSON이며, GUI 없이 실행하더라도 현재 DEB 패키지의 GUI 라이브러리 의존성은 남아 있다.

## 소유권과 해제

- 서비스: `quiet-scanner-protection.service`
- 설정: `/etc/quiet-scanner/protection/firewall.yaml` (root 전용; 엔진 키 포함)
- nftables 테이블: `ip quiet_scanner`, `ip6 quiet_scanner6`
- 엔진 키 이름: `quiet-scanner`
- 명시적인 허용 예외: CrowdSec의 `quiet-scanner-user` allowlist

**허용 예외는 이 서버의 CrowdSec 전체에 적용된다.** 등록 시 그 IP의 현재 차단 결정을 삭제하며 이후 결정을 제외한다. 다른 firewall/WAF 구성요소에도 영향을 줄 수 있으므로 화면에서 이 범위를 설명하고 IP별 확인을 받는다. 예외 삭제는 향후 탐지를 다시 허용하며 이전 차단 결정을 복원하지 않는다.

OFF는 Quiet Scanner가 만든 서비스·테이블만 정지·제거한다. 다른 CrowdSec 인스턴스·기본 bouncer·UFW·관리자가 만든 규칙은 유지한다. 예외 목록과 엔진 키는 보존한다. 서버에서 앱을 제거하기 전 보호를 끄고 상태를 확인해야 한다.

`최근 로컬 차단 결정`은 최대 100개 로컬 알림의 활성 IP ban만 보여 주며 시뮬레이션·만료·대역 차단·외부 CAPI 목록은 표시하지 않는다. 결정 목록은 패킷 차단 성공 건수와 다르다. 방화벽 반영 및 해제에는 최대 수십 초가 걸릴 수 있다.

## 검증 기준

단위 테스트: 실제 cscli의 중첩 alert/decision 형식, 시뮬레이션 제외, 신선한 bouncer 조회, nftables DROP 규칙, 주소와 RPC 인자 검증.

UI 테스트: 시작 시 관리자 승인 없음, 미지원 OS, 의존성 누락, 시작·종료 지연, 검증 실패 시 초록 표시 제거, 예외 등록·제거.

Linux 통합 테스트는 실제 CrowdSec API와 공식 bouncer를 사용해 전용 규칙 생성·차단·해제 및 기존 규칙 보존을 확인한다. 통합 테스트와 현장 검증이 끝나기 전 안정 보안 제품으로 배포하지 않는다.
