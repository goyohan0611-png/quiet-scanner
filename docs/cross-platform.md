# macOS·Linux 설치 안내

4.2.0은 Windows·macOS·Linux 설치 파일의 버전을 통일한 배포입니다. macOS 파일은 Developer ID 서명과 Apple 공증을 거쳤으며, 설치 파일에 공증 티켓을 첨부했습니다.

## 대상

| 운영체제 | 대상 | 파일 |
|---|---|---|
| macOS 13 이상 | Apple Silicon | [arm64 DMG](https://github.com/goyohan0611-png/quiet-scanner/releases/download/v4.2.0/Quiet.Scanner.4.2.0.macOS.AppleSilicon.dmg) |
| macOS 13 이상 | Intel | [x64 DMG](https://github.com/goyohan0611-png/quiet-scanner/releases/download/v4.2.0/Quiet.Scanner.4.2.0.macOS.Intel.dmg) |
| Ubuntu 24.04 이상 | x64 | [DEB](https://github.com/goyohan0611-png/quiet-scanner/releases/download/v4.2.0/Quiet.Scanner.4.2.0.Ubuntu24.04.x64.deb) |

맥의 **이 Mac에 관하여**에서 칩 항목이 M 시리즈이면 Apple Silicon용을, 프로세서가 Intel이면 Intel용을 선택합니다. DMG를 열고 Quiet Scanner를 응용 프로그램 폴더로 옮겨 실행합니다. Ubuntu에서는 DEB를 패키지 관리자로 설치하면 필요한 시스템 라이브러리도 함께 설치합니다.

다른 Linux 배포판은 소스 빌드를 이용할 수 있지만, 이번 설치 파일의 지원·검증 대상으로 포함하지 않습니다.

## 네트워크 권한

화면은 로그인한 사용자의 권한으로 실행합니다. 첫 스캔·DHCP 확인·장비 분리 때 운영체제의 관리자 승인을 받아 네트워크 작업만 별도의 작업 프로세스에서 실행합니다. 비밀번호를 프로그램에 입력하거나 저장하지 않습니다.

연결은 사용자 전용 임시 폴더, 임의 인증값, 운영체제가 보고하는 상대 프로세스 권한으로 확인합니다. 일반 명령 실행을 전달하지 않으며, 장비 검색·DHCP 탐색과 확인된 ARP 항목의 분리·해제만 처리합니다. 연결이 종료되면 이 작업에서 고정한 MAC만 확인 후 정리합니다. 사용자 영역의 분리 복구 기록은 별도로 유지합니다.

macOS에서는 기본 제공 libpcap·WKWebView를 사용합니다. Windows용 Npcap과 WebView2를 설치하지 않습니다.

Ubuntu에서는 DEB 설치 시 libpcap, WebKitGTK, iproute2, iputils-ping, pkexec 의존성이 필요합니다. 로그인한 데스크톱 세션에 관리자 인증 에이전트도 있어야 합니다. 프로그램 전체를 root 권한으로 실행할 필요는 없습니다.

## 기능

인터페이스 새로고침, ARP 스캔·충돌 탐지, MAC 사전, 이 PC에서의 장비 분리·해제, DHCP 서버 확인, 미응답 IP 후보, Ping, TCP 포트 검사와 IP 복사를 공통 화면에서 제공합니다. ARP 탐색과 분리는 같은 L2 구간에서 동작합니다.

## 빌드

각 운영체제의 Rust·Node.js·Tauri 빌드 도구를 설치한 뒤 저장소 루트에서 실행합니다.

```sh
npm ci
npm run build
```

macOS는 Xcode Command Line Tools, Ubuntu는 WebKitGTK 4.1 개발 라이브러리 등 Tauri 빌드 의존성이 필요합니다. 운영체제별 설정 파일을 자동으로 사용합니다.

```sh
cargo test --manifest-path src-tauri/Cargo.toml --locked
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
```

## 검증과 배포 범위

GitHub의 해당 운영체제 환경에서 컴파일·테스트·설치 파일 생성을 실행합니다. 인증 연결 테스트는 CI의 비대화형 sudo 권한으로 별도 작업 프로세스를 실행하고 실제 인터페이스와 libpcap 캡처 열기를 확인합니다. 이 테스트는 ARP 패킷이나 DHCP 요청을 보내지 않습니다.

CI의 관리자 연결 확인은 실제 데스크톱에서 뜨는 macOS·Linux 인증 대화상자를 대신 검증하지 않습니다. Windows에서는 현장 테스트를 진행했으며, macOS·Linux의 실제 현장 중복 IP·무선랜 조합과 인증 대화상자 동작은 별도로 확인해야 합니다.

4.2.0의 운영체제별 검사와 서명·공증 검증 기록은 [릴리즈 안내](release-v4.2.0.md)에 정리했습니다. 서명된 맥 파일도 프로그램을 실행해 네트워크를 검사하려면 운영체제의 관리자 승인이 필요합니다.

이전 4.1.0-beta.1은 서명·공증 전 테스트 배포로 보관합니다. 새로 설치할 때는 4.2.0 파일을 사용하십시오.

유료 개발자 계정으로 맥 없이 준비하는 절차는 [macOS 서명 안내](macos-signing.md)에 정리했습니다.
