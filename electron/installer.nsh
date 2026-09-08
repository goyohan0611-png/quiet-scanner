!macro customInstall
  IfFileExists "$SYSDIR\Npcap\wpcap.dll" npcap_ready
  MessageBox MB_ICONEXCLAMATION|MB_OK "Quiet Scanner is installed.$\r$\n$\r$\nNetwork scanning needs the Npcap driver. The download page opens next - install it from there, ticking 'WinPcap API-compatible mode'.$\r$\n$\r$\n설치가 끝났습니다. 네트워크 스캔에는 Npcap 드라이버가 필요합니다. 다음 화면에서 받아 설치하십시오."
  ExecShell "open" "https://npcap.com/#download"
  npcap_ready:
!macroend
