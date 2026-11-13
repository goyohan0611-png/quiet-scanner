# 맥 없이 macOS 서명·공증 준비하기

유료 Apple Developer Program 계정이 있으면 GitHub의 macOS 빌드 환경에서 서명과 공증을 진행할 수 있습니다. 이 저장소에서는 인증서를 준비한 뒤 수동으로 실행하는 `Signed macOS installers` 작업을 사용합니다.

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

## 4. 자동 서명 작업

GitHub Actions에서 `Signed macOS installers`를 선택하고 `main`에서 실행합니다. 일반 빌드·검사는 서명 인증정보 없이 먼저 실행합니다. 이후 임시 키체인에 인증서를 불러와 서명·Apple 공증·티켓 첨부를 진행합니다.

서명과 공증 티켓, Gatekeeper 확인을 모두 통과한 DMG만 Actions 결과물로 올립니다. 임시 키체인은 종료 시 정리합니다. 이 작업은 기존 공개 릴리즈 파일을 자동으로 교체하지 않습니다. 검증된 결과물을 확인한 뒤 새 릴리즈로 배포합니다.

현재 공개된 4.1.0-beta.1은 서명·공증 전 버전입니다. 이 자동화 설정이 추가됐다는 사실만으로 기존 파일이 공증되는 것은 아닙니다.

공식 문서: [Apple Developer ID](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/), [Tauri macOS 서명·공증](https://v2.tauri.app/distribute/sign/macos/).
