!macro customInstall
  IfFileExists "$SYSDIR\Npcap\wpcap.dll" npcap_ready
  MessageBox MB_ICONEXCLAMATION|MB_OK "IP Scanner 설치는 완료되었습니다.$\r$\n$\r$\n네트워크 스캔을 사용하려면 Npcap 드라이버가 필요합니다. 다음 화면에서 공식 설치 파일을 받아 설치해 주세요."
  ExecShell "open" "https://npcap.com/#download"
  npcap_ready:
!macroend
