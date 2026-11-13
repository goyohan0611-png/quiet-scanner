Unicode true
RequestExecutionLevel user
SilentInstall silent
Name "Quiet Scanner prerequisite detector test"
OutFile "${TEST_OUTPUT}"
!include "${__FILEDIR__}\..\src-tauri\windows\prerequisites-detect.nsh"
Function .onInit
  Call QSDetectPrerequisites
  IntOp $0 $QSWebViewReady * 2
  IntOp $0 $0 | $QSNpcapReady
  SetErrorLevel $0
  Quit
FunctionEnd
Section
SectionEnd
