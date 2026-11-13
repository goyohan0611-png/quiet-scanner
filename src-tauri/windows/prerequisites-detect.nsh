!ifndef QUIET_SCANNER_PREREQUISITES_DETECT
!define QUIET_SCANNER_PREREQUISITES_DETECT
!include LogicLib.nsh
!include x64.nsh

Var QSNpcapReady
Var QSWebViewReady

Function QSDetectPrerequisites
  Push $0
  StrCpy $QSNpcapReady 0
  StrCpy $QSWebViewReady 0

  ; Compile-time fixtures are used only by the isolated installer-page preview.
  ; No command-line flag in a shipped installer can override detection.
  !ifdef QS_PREREQUISITE_TEST_DIR
    IfFileExists "${QS_PREREQUISITE_TEST_DIR}\npcap.ready" 0 +2
      StrCpy $QSNpcapReady 1
    IfFileExists "${QS_PREREQUISITE_TEST_DIR}\webview2.ready" 0 +2
      StrCpy $QSWebViewReady 1
  !else
    ; NSIS itself is 32-bit; inspect the native DLL/driver used by the x64 app.
    ${If} ${RunningX64}
      ${DisableX64FSRedirection}
    ${EndIf}
    IfFileExists "$SYSDIR\Npcap\wpcap.dll" 0 qs_npcap_checked
    IfFileExists "$SYSDIR\drivers\npcap.sys" 0 qs_npcap_checked
      StrCpy $QSNpcapReady 1
    qs_npcap_checked:
    ${If} ${RunningX64}
      ${EnableX64FSRedirection}
    ${EndIf}

    ; Microsoft documents both machine-wide and per-user Runtime registrations.
    ; Read the 32-bit registry view first, then the native view as a fallback.
    SetRegView 32
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
    ${If} $0 == ""
    ${OrIf} $0 == "0.0.0.0"
      ReadRegStr $0 HKCU "SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
    ${EndIf}
    SetRegView lastused
    ${If} $0 == ""
    ${OrIf} $0 == "0.0.0.0"
      SetRegView 64
      ReadRegStr $0 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
      ${If} $0 == ""
      ${OrIf} $0 == "0.0.0.0"
        ReadRegStr $0 HKCU "SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
      ${EndIf}
      SetRegView lastused
    ${EndIf}
    ${If} $0 != ""
    ${AndIf} $0 != "0.0.0.0"
      StrCpy $QSWebViewReady 1
    ${EndIf}
  !endif
  Pop $0
FunctionEnd
!endif
