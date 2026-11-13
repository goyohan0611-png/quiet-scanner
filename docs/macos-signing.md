# 맥 없이 macOS 서명·공증 준비하기

유료 Apple Developer Program 계정이 있으면 GitHub의 macOS 빌드 환경에서 서명과 공증을 진행할 수 있습니다. 이 저장소에서는 인증서를 준비한 뒤 수동으로 제출하고, Apple 승인 후 보관한 파일을 검증합니다.

## 1. Windows에서 공개 요청 파일 준비

Git for Windows의 OpenSSL과 Node.js가 설치된 PC에서 실행합니다.

```powershell
node scripts/prepare_macos_csr.cjs
```

공개 요청 파일은 `%LOCALAPPDATA%\QuietScannerSigning\QuietScanner-DeveloperID.certSigningRequest`입니다. 개인키는 같은 별도 보관 폴더에 암호화하며, 암호는 Windows 사용자 계정에 묶어 보호합니다. 다시 실행해도 기존 키를 바꾸지 않습니다. 이 폴더는 저장소와 별개이며 GitHub에 자동 업로드하지 않습니다.

## 2. Apple에서 인증서 발급

[Apple Developer의 Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/certificates/list)에 본인이 로그인합니다. 새 인증서에서 **Developer ID Application**을 선택하고 위 `.certSigningRequest` 파일을 올립니다. App Store용 Apple Distribution이나 Developer ID Installer와 구분하십시오. Developer ID 인증서 생성에는 Account Holder 권한이 필요합니다.

발급 후 공개 인증서인 `.cer` 파일을 다운로드합니다. 이 인증서의 공개키와 보관한 개인키가 일치하는지 확인한 뒤, CI용 암호화된 `.p12`로 묶는 단계가 필요합니다. 공개 `.cer`만 공유할 수 있으며 개인키·`.p12`·암호는 채팅이나 소스 코드에 넣지 않습니다.

## 3. GitHub 서명 설정

인증서가 준비되면 저장소의 `macos-signing` 환경에 다음 네 가지 비밀값을 등록합니다. 이 환경의 배포 브랜치는 `main`으로 제한합니다.

| 이름 | 내용 |
|---|---|
| `APPLE_CERTIFICATE` | 암호화된 `.p12`의 Base64 |
| `APPLE_CERTIFICATE_PASSWORD` | 그 `.p12` 암호 |
| `APPLE_ID` | Apple 계정 이메일 |
| `APPLE_PASSWORD` | 공증용 **앱 전용 암호**. 평소 로그인 비밀번호를 사용하지 않습니다. |

서명 이름과 Team ID는 인증서에서 자동으로 확인합니다. 설정 없이 작업을 실행하면 빠르게 종료하며, 서명되지 않은 파일을 서명 완료로 업로드하지 않습니다.

## 4. 서명과 공증 제출

GitHub Actions에서 `Build and submit macOS notarization`을 선택하고 `main`에서 실행합니다. 일반 빌드·검사는 서명 인증정보 없이 먼저 실행합니다. 이후 임시 키체인에 인증서를 불러와 앱과 DMG를 서명하고, 최종 DMG를 Apple에 한 번 제출합니다. Apple은 DMG 안의 앱도 함께 검사합니다.

공증 승인을 기다리며 빌드 환경을 계속 실행하지 않습니다. 서명한 DMG와 제출 ID·SHA-256·원본 커밋·아키텍처를 `pending-quiet-scanner-*` 결과물에 30일 동안 보관합니다. **제출 작업의 초록색 성공 표시는 업로드 성공이며 공증 승인을 의미하지 않습니다.** 개인키나 암호는 결과물에 포함하지 않으며 임시 키체인은 종료 시 정리합니다.

## 5. 기존 요청 상태 확인

`Apple notarization status` 작업을 `main`에서 실행하고 인증서의 10자리 Team ID를 입력합니다. 기존 Quiet Scanner 요청만 조회하며 새 파일을 제출하지 않습니다. 빌드 작업이 시간 초과로 취소되어도 Apple에 접수된 요청은 별도로 처리될 수 있습니다. 시간 초과와 Apple의 `Invalid` 또는 `Rejected` 결과를 구분하십시오.

## 6. 승인된 설치 파일 마무리

`Finalize accepted macOS installers`를 `main`에서 실행합니다. 4단계 작업의 실행 ID와 Team ID를 입력합니다. 다른 저장소·브랜치·워크플로에서 가져온 결과물은 거부합니다. 보관한 DMG의 SHA-256과 원본 실행·커밋·아키텍처를 확인한 뒤 기존 제출 ID를 조회합니다.

`In Progress`이면 설치 파일을 배포하지 않고 종료합니다. 나중에 같은 실행 ID로 다시 확인할 수 있으며 재빌드나 재제출하지 않습니다. `Accepted`일 때만 공증 로그를 확인하고 DMG에 티켓을 첨부한 뒤 서명·Gatekeeper·앱 버전·CPU 종류를 검증합니다. 검증을 모두 통과한 DMG와 해시·검증 기록만 `signed-quiet-scanner-*` 결과물로 올립니다. 기존 공개 릴리즈는 자동으로 교체하지 않습니다.

예전의 대기 방식에서 시간 초과로 종료된 빌드는 원본 서명 파일을 보관하지 않았습니다. 상태 조회는 가능하지만 파일 보관은 위 새 절차로 실행한 빌드부터 적용됩니다.

현재 공개된 4.1.0-beta.1은 서명·공증 전 버전입니다. 이 자동화 설정이 추가됐다는 사실만으로 기존 파일이 공증되는 것은 아닙니다.

공식 문서: [Apple Developer ID](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/), [Tauri macOS 서명·공증](https://v2.tauri.app/distribute/sign/macos/).
