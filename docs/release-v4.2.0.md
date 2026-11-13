# Quiet Scanner 4.2.0

Windows·macOS·Linux 설치 파일의 버전을 4.2.0으로 통일했습니다. 장비 검색, IP 충돌 표시, 이 PC에서의 장비 분리·해제, DHCP 서버 확인, 사용 가능한 IP 후보, Ping·TCP 확인과 MAC 사전을 그대로 제공합니다.

## macOS 서명·공증

Apple Silicon과 Intel용 DMG를 각각 Developer ID Application 인증서로 서명하고 Apple 공증을 받았습니다. DMG에 공증 티켓을 첨부하고 서명·Gatekeeper·앱 버전·CPU 종류를 확인한 파일만 배포합니다. macOS 13 이상이 필요합니다.

공증 요청을 제출하는 빌드와 승인 뒤 파일을 마무리하는 작업을 분리했습니다. Apple 처리가 길어져도 서명 파일과 제출 ID를 보관하며, 같은 파일을 재빌드하거나 다시 제출하지 않고 이어서 검증할 수 있습니다. 제출 작업의 성공은 공증 승인을 뜻하지 않습니다.

## Windows

Npcap과 WebView2 준비 상태를 설치 첫 화면에서 확인합니다. Windows 10·11 64비트와 관리자 권한이 필요합니다. 사용자 사전과 설정은 기존 앱 식별자로 유지합니다.

Windows 코드 서명은 아직 적용되지 않았습니다. macOS 공증과는 별개이며 Windows에서 알 수 없는 게시자 또는 SmartScreen 경고가 나올 수 있습니다.

## Linux

Ubuntu 24.04 이상 x64용 DEB를 제공합니다. libpcap·WebKitGTK·iproute2·iputils-ping·pkexec 등 필요한 패키지를 의존성으로 지정합니다. 실제 데스크톱의 관리자 인증 에이전트가 필요합니다.

## 검증 범위

Windows·macOS·Linux에서 Rust 테스트와 코드 검사를 실행하고 해당 운영체제용 설치 파일을 생성했습니다. macOS·Linux의 관리자 작업 프로세스 인증과 실제 인터페이스의 libpcap 열기를 CI에서 확인했습니다. 이 검사는 ARP·DHCP 패킷을 보내지 않습니다. 공증 절차에는 처리 중·거절된 요청과 변조된 파일을 검증 완료로 처리하지 않는 회귀 검사도 포함합니다.

Windows Rust 테스트 33개, macOS 각 38개, Linux 37개와 공증 회귀 검사 7개를 통과했습니다.

- [운영체제별 테스트·빌드·권한 연결 검사](https://github.com/goyohan0611-png/quiet-scanner/actions/runs/43391989116)
- [맥 서명과 공증 요청 제출](https://github.com/goyohan0611-png/quiet-scanner/actions/runs/43392301735)
- [Apple 승인 확인·티켓 첨부·Gatekeeper·버전·CPU 검증](https://github.com/goyohan0611-png/quiet-scanner/actions/runs/43394437206)

macOS·Linux의 실제 현장 충돌 장비와 인증 대화상자 동작은 CI 검사와 별개의 확인 대상입니다. 공증은 현장 기능 테스트를 대신하지 않습니다.

릴리즈의 `SHA256SUMS.txt`로 설치 파일의 SHA-256을 확인할 수 있습니다. macOS 검증 기록에는 제출 ID, 빌드 출처와 검증한 파일의 해시를 남깁니다. [설치 파일과 검증 실행 보기](https://github.com/goyohan0611-png/quiet-scanner/releases/tag/v4.2.0)
