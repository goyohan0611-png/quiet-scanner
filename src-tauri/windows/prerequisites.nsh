!ifndef QUIET_SCANNER_PREREQUISITES_PAGE
!define QUIET_SCANNER_PREREQUISITES_PAGE
!include nsDialogs.nsh
!include FileFunc.nsh
!include "${__FILEDIR__}\prerequisites-detect.nsh"

LangString QSTitle 1042 "필수 구성 요소 확인"
LangString QSTitle 1033 "Required components"
LangString QSSubtitle 1042 "Npcap과 WebView2가 준비되면 설치를 계속합니다."
LangString QSSubtitle 1033 "Install Npcap and WebView2 to continue."
LangString QSIntro 1042 "없는 항목의 설치 버튼을 눌러 공식 사이트에서 받아 설치하세요.$\r$\n이 화면은 1초마다 설치 상태를 확인합니다."
LangString QSIntro 1033 "Use the install buttons to download missing components from official sites.$\r$\nThis page checks installation status every second."
LangString QSNpcapDescription 1042 "네트워크 장비 검색 · IP 충돌 확인"
LangString QSNpcapDescription 1033 "Network discovery and IP conflict detection"
LangString QSWebViewDescription 1042 "프로그램 화면 표시"
LangString QSWebViewDescription 1033 "Application display engine"
LangString QSInstall 1042 "설치하러 가기"
LangString QSInstall 1033 "Get installer"
LangString QSInstalled 1042 "설치 완료"
LangString QSInstalled 1033 "Installed"
LangString QSReady 1042 "✓ 설치 완료"
LangString QSReady 1033 "✓ Installed"
LangString QSMissing 1042 "✕ 설치 필요"
LangString QSMissing 1033 "✕ Not installed"
LangString QSComplete 1042 "2 / 2 준비 완료 · 다음을 눌러 계속하세요."
LangString QSComplete 1033 "2 / 2 ready. Choose Next to continue."
LangString QSIncomplete 1042 "설치가 끝나면 자동으로 초록색으로 바뀝니다."
LangString QSIncomplete 1033 "The status turns green once installation is detected."
LangString QSMissingError 1042 "Npcap과 Microsoft Edge WebView2 Runtime을 모두 설치한 뒤 다시 확인해 주세요."
LangString QSMissingError 1033 "Install both Npcap and Microsoft Edge WebView2 Runtime before continuing."
LangString QSLinkError 1042 "다운로드 페이지를 열지 못했습니다. 인터넷 연결과 기본 브라우저를 확인하세요."
LangString QSLinkError 1033 "Could not open the download page. Check your connection and default browser."

Var QSPage
Var QSNpcapStatus
Var QSWebViewStatus
Var QSNpcapButton
Var QSWebViewButton
Var QSPageFooter
Var QSPreviousNpcap
Var QSPreviousWebView

; The hook is included before Tauri's standard pages, so this checklist is first.
Page custom QSPrerequisitesPage QSPrerequisitesLeave

Function QSPrerequisitesPage
  IfSilent qs_skip_page
  Push $0
  ${GetOptions} $CMDLINE "/P" $0
  ${IfNot} ${Errors}
    Pop $0
    Goto qs_skip_page
  ${EndIf}
  Pop $0

  !insertmacro MUI_HEADER_TEXT "$(QSTitle)" "$(QSSubtitle)"
  nsDialogs::Create 1018
  Pop $QSPage
  ${If} $QSPage == error
    Abort
  ${EndIf}
  ${NSD_CreateLabel} 0 0 100% 28u "$(QSIntro)"
  Pop $0

  ${NSD_CreateGroupBox} 0 28u 100% 42u "Npcap"
  Pop $0
  ${NSD_CreateLabel} 12u 40u 205u 12u "$(QSNpcapDescription)"
  Pop $0
  ${NSD_CreateLabel} 12u 54u 205u 12u ""
  Pop $QSNpcapStatus
  ${NSD_CreateButton} -88u 42u 78u 21u "$(QSInstall)"
  Pop $QSNpcapButton
  ${NSD_OnClick} $QSNpcapButton QSOpenNpcapDownload

  ${NSD_CreateGroupBox} 0 78u 100% 42u "Microsoft Edge WebView2 Runtime"
  Pop $0
  ${NSD_CreateLabel} 12u 90u 205u 12u "$(QSWebViewDescription)"
  Pop $0
  ${NSD_CreateLabel} 12u 104u 205u 12u ""
  Pop $QSWebViewStatus
  ${NSD_CreateButton} -88u 92u 78u 21u "$(QSInstall)"
  Pop $QSWebViewButton
  ${NSD_OnClick} $QSWebViewButton QSOpenWebViewDownload
  ${NSD_CreateLabel} 0 128u 100% 18u ""
  Pop $QSPageFooter

  StrCpy $QSPreviousNpcap -1
  StrCpy $QSPreviousWebView -1
  Call QSRefreshPrerequisites
  ${NSD_CreateTimer} QSRefreshPrerequisites 1000
  nsDialogs::Show
  ${NSD_KillTimer} QSRefreshPrerequisites
  Return
  qs_skip_page:
    Abort
FunctionEnd

Function QSRefreshPrerequisites
  Push $0
  Call QSDetectPrerequisites
  ${If} $QSPreviousNpcap != $QSNpcapReady
    ${If} $QSNpcapReady == 1
      SetCtlColors $QSNpcapStatus "006F46" "transparent"
      ${NSD_SetText} $QSNpcapStatus "$(QSReady)"
      ${NSD_SetText} $QSNpcapButton "$(QSInstalled)"
      EnableWindow $QSNpcapButton 0
    ${Else}
      SetCtlColors $QSNpcapStatus "C92B3D" "transparent"
      ${NSD_SetText} $QSNpcapStatus "$(QSMissing)"
      ${NSD_SetText} $QSNpcapButton "$(QSInstall)"
      EnableWindow $QSNpcapButton 1
    ${EndIf}
    System::Call 'user32::RedrawWindow(p $QSNpcapStatus, p 0, p 0, i 0x185)'
    StrCpy $QSPreviousNpcap $QSNpcapReady
  ${EndIf}
  ${If} $QSPreviousWebView != $QSWebViewReady
    ${If} $QSWebViewReady == 1
      SetCtlColors $QSWebViewStatus "006F46" "transparent"
      ${NSD_SetText} $QSWebViewStatus "$(QSReady)"
      ${NSD_SetText} $QSWebViewButton "$(QSInstalled)"
      EnableWindow $QSWebViewButton 0
    ${Else}
      SetCtlColors $QSWebViewStatus "C92B3D" "transparent"
      ${NSD_SetText} $QSWebViewStatus "$(QSMissing)"
      ${NSD_SetText} $QSWebViewButton "$(QSInstall)"
      EnableWindow $QSWebViewButton 1
    ${EndIf}
    System::Call 'user32::RedrawWindow(p $QSWebViewStatus, p 0, p 0, i 0x185)'
    StrCpy $QSPreviousWebView $QSWebViewReady
  ${EndIf}
  GetDlgItem $0 $HWNDPARENT 1
  ${If} $QSNpcapReady == 1
  ${AndIf} $QSWebViewReady == 1
    EnableWindow $0 1
    ${NSD_SetText} $QSPageFooter "$(QSComplete)"
  ${Else}
    EnableWindow $0 0
    ${NSD_SetText} $QSPageFooter "$(QSIncomplete)"
  ${EndIf}
  Pop $0
FunctionEnd

Function QSPrerequisitesLeave
  Call QSDetectPrerequisites
  ${If} $QSNpcapReady != 1
  ${OrIf} $QSWebViewReady != 1
    Call QSRefreshPrerequisites
    Abort
  ${EndIf}
FunctionEnd

Function QSOpenNpcapDownload
  Pop $0
  ClearErrors
  ExecShell "open" "https://npcap.com/#download"
  ${If} ${Errors}
    MessageBox MB_ICONEXCLAMATION|MB_OK "$(QSLinkError)"
  ${EndIf}
FunctionEnd

Function QSOpenWebViewDownload
  Pop $0
  ClearErrors
  ExecShell "open" "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
  ${If} ${Errors}
    MessageBox MB_ICONEXCLAMATION|MB_OK "$(QSLinkError)"
  ${EndIf}
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  ; Recheck at the actual install boundary, including silent/passive installs.
  Call QSDetectPrerequisites
  ${If} $QSNpcapReady != 1
  ${OrIf} $QSWebViewReady != 1
    MessageBox MB_ICONEXCLAMATION|MB_OK "$(QSMissingError)" /SD IDOK
    SetErrorLevel 1603
    Abort
  ${EndIf}
!macroend
!endif
