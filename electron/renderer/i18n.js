/* Quiet Scanner — field IP conflict cleanup tool
 * Copyright (C) 2026 고요한
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version. This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */
/* ── Strings ───────────────────────────────────────────────────────────
   Every string the screen shows, in one place, as [Korean, English] pairs.
   Split them into separate files and one gets fixed while the other is forgotten.

   On first run the Windows language decides. Once a person picks one, that
   choice is remembered.
   Device types (KINDS) come out of the book file and the engine in Korean, so
   they are translated here at display time. A type someone typed in by hand is
   left alone - it is not in the table.
   ------------------------------------------------------------------- */

const LANG_STORE = 'ipscan.lang';

let lang = 'ko';
try {
  const saved = localStorage.getItem(LANG_STORE);
  lang = saved === 'ko' || saved === 'en'
    ? saved
    : (String(navigator.language || '').toLowerCase().startsWith('ko') ? 'ko' : 'en');
} catch (_) {
  lang = String(navigator.language || '').toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

const STRINGS = {
  /* Top control bar */
  ifaceLabel:      ['네트워크 인터페이스', 'Network interface'],
  engineLoading:   ['네트워크 엔진 준비 중...', 'Starting network engine…'],
  refresh:         ['↻ 새로고침', '↻ Refresh'],
  refreshTitle:    ['네트워크 인터페이스 및 IP 주소 다시 읽기', 'Re-read interfaces and IP addresses'],
  targetLabel:     ['스캔할 대역', 'Range to scan'],
  targetTitle:     ['인터페이스의 실제 서브넷이 자동으로 들어갑니다. CIDR·단일 IP·여러 대역(쉼표)을 지원합니다.',
                    'The actual interface subnet is filled automatically. CIDR, one IP, and comma-separated ranges are supported.'],
  largeRangeConfirm:['{target} 대역은 약 {n}개 주소를 확인합니다. 오래 걸릴 수 있습니다. 계속하시겠습니까?',
                    '{target} contains about {n} addresses and may take a while. Continue?'],
  largeRangeLimit: ['{target} 대역은 주소가 {n}개라 한 번에 스캔할 수 없습니다. 더 작은 대역으로 나누십시오.',
                    '{target} has {n} addresses, which is too large for one scan. Split it into smaller ranges.'],
  scan:            ['대역 스캔', 'Scan range'],

  /* Work bar */
  idle:            ['대기 중', 'Idle'],
  pickIface:       ['인터페이스를 선택하고 스캔을 시작하십시오.', 'Choose an interface and start a scan.'],
  filterPh:        ['검색 — IP · MAC · 이름 · 제조사', 'Search — IP · MAC · name · vendor'],
  historyBtn:      ['기록', 'History'],
  historyTitle:    ['스캔 기록', 'Scan history'],
  historyHint:     ['완료된 스캔을 현재 목록과 비교합니다. 최근 30회까지 보관합니다.',
                    'Compare completed scans against the current list. The latest 30 are kept.'],
  historyEmpty:    ['아직 완료된 스캔 기록이 없습니다.', 'No completed scan history yet.'],
  historyCompare:  ['현재와 비교', 'Compare with current'],
  free:            ['후보 IP', 'Candidate IPs'],
  freeTitle:       ['응답이 없었던 IP를 확인합니다', 'List IPs that did not respond'],
  swport:          ['스위치 포트', 'Switch port'],
  swportTitle:     ['스위치에 물어 장비가 몇 번 포트에 물렸는지 찾습니다',
                    'Ask the switch which port each device is on'],
  exportBtn:       ['내보내기', 'Export'],
  /* Menu bar */
  mbFile:          ['파일', 'File'],
  mbView:          ['보기', 'View'],
  mbScan:          ['스캔', 'Scan'],
  mbSwitch:        ['스위치', 'Switch'],
  mbTool:          ['도구', 'Tools'],
  mbExport:        ['결과 내보내기…', 'Export results…'],
  mbReport:        ['준공 · 점검 리포트…', 'Commissioning report…'],
  mbFreeCsv:       ['후보 IP 배정표 저장…', 'Save candidate-IP worksheet…'],
  mbQuit:          ['끝내기', 'Quit'],
  mbDense:         ['밀집 보기', 'Compact rows'],
  mbColumns:       ['칸 고르기…', 'Choose columns…'],
  mbLangKo:        ['언어 — 한국어', 'Language — 한국어'],
  mbLangEn:        ['언어 — English', 'Language — English'],
  mbScanRun:       ['대역 스캔', 'Scan range'],
  mbScanStop:      ['스캔 중지', 'Stop scan'],
  mbHistory:       ['스캔 기록…', 'Scan history…'],
  mbFree:          ['후보 IP…', 'Candidate IPs…'],
  mbPorts:         ['스위치 포트 관리…', 'Switch port management…'],
  mbBook:          ['장비 사전…', 'Device book…'],
  mbAbout:         ['정보', 'About'],
  mbStatIdle:      ['대기 중', 'idle'],
  mbStatNets:      ['{if} · 대역 {n}개', '{if} · {n} range(s)'],
  mbAboutText:     ['{app} v{ver} · (C) 2026 고요한 · GPLv2 — ARP 로 훑고 SNMP 로 스위치에 묻습니다. 스캔 결과는 이 컴퓨터에만 남습니다.',
                    '{app} v{ver} · (C) 2026 Goyohan · GPLv2 — ARP sweep plus SNMP switch queries. Scan results stay on this computer.'],
  mbDenseOn:       ['밀집 보기 — 한 화면에 더 많이 보입니다. (Ctrl+D 로 되돌리기)',
                    'Compact rows on — more fits on screen. (Ctrl+D to undo)'],
  mbDenseOff:      ['보통 보기로 돌아왔습니다.', 'Back to normal row height.'],
  reportBtn:       ['준공 리포트', 'Report'],
  reportTitle:     ['스캔 결과와 스위치 포트를 준공·점검용 엑셀 한 부로 뽑습니다.',
                    'Export the scan and switch ports as a commissioning/inspection workbook.'],
  langMenu:        ['언어 ▾', 'Language ▾'],

  /* Device list */
  headTitle:       ['우클릭하면 볼 칸을 고를 수 있습니다', 'Right-click to choose which columns to show'],
  emptyList:       ['아직 발견된 장비가 없습니다.', 'No devices found yet.'],
  noMatch:         ['검색과 맞는 장비가 없습니다.', 'No device matches the search.'],
  searchResult:    ['검색 "{q}" — {n}대', 'Search "{q}" — {n} device{s}'],
  groupNote:       ['{n}대가 이 IP를 함께 사용', '{n} devices share this IP'],
  conflictBadge:   ['충돌 {n}대', '{n} in conflict'],
  colReset:        ['기본값으로', 'Reset to default'],

  /* Column headings */
  colIp:           ['IP / 장비 MAC', 'IP / device MAC'],
  colVendor:       ['MAC 제조사', 'MAC vendor'],
  colKind:         ['장비 종류', 'Device type'],
  colModel:        ['모델', 'Model'],
  colName:         ['이름', 'Name'],
  colMs:           ['응답', 'Reply'],
  colOs:           ['OS', 'OS'],
  colPorts:        ['열린 포트', 'Open ports'],
  colSwport:       ['스위치 포트', 'Switch port'],
  colSerial:       ['시리얼', 'Serial'],
  colNbname:       ['NetBIOS 이름', 'NetBIOS name'],
  colMdns:         ['mDNS 이름', 'mDNS name'],
  colSsdp:         ['UPnP 이름', 'UPnP name'],
  colVlan:         ['VLAN', 'VLAN'],
  colSeen:         ['확인 시각', 'Seen at'],

  /* Cell text */
  unknownVendor:   ['미상', 'Unknown'],
  unknownKind:     ['미확인', 'Unidentified'],
  kindConfirmed:   ['확정', 'Confirmed'],
  kindEstimated:   ['추정', 'Estimated'],
  isolatedBadge:   ['격리 중', 'Isolated'],
  ttlUnread:       ['못 읽음', 'no reply'],
  bookExactTip:    ['이 장비로 직접 등록됨', 'Registered for this exact device'],
  namesTip:        ['다른 이름 {n}개 — {rest}', '{n} more name{s} — {rest}'],
  bookMatchTip:    ['장비 사전에서 인식', 'Matched in the device book'],

  /* Summary */
  mIps:            ['발견된 IP', 'IPs found'],
  mConflictIps:    ['충돌난 IP', 'Conflicting IPs'],
  mDevices:        ['전체 장비', 'Devices'],
  mConflictDev:    ['충돌 장비', 'Devices in conflict'],
  titleConflict:   ['충돌 IP {n}개', '{n} conflicting IP{s}'],
  titleDevices:    ['발견 장비 {n}대', '{n} device{s} found'],
  subConflict:     ['충돌 장비를 우클릭해 검사 또는 격리를 선택하십시오.',
                    'Right-click a device in conflict to identify or isolate it.'],
  subDevices:      ['장비를 우클릭하면 작업 메뉴가 열립니다.', 'Right-click a device for the action menu.'],
  countConflict:   ['충돌 {n}', '{n} in conflict'],
  countDevices:    ['장비 {n}', '{n} devices'],
  countIps:        ['IP {n}', '{n} IPs'],

  /* Activity log */
  logResizeTitle:  ['드래그하여 로그창 크기 조절', 'Drag to resize the log pane'],
  logHead:         ['작업 로그', 'Activity log'],
  ready:           ['준비됨', 'Ready'],
  logEmpty:        ['작업 기록이 여기에 표시됩니다.', 'Activity will appear here.'],

  /* Right-click menu */
  menuIdentify:    ['장비 정보 검사', 'Identify device'],
  menuIsolate:     ['이 장비만 격리', 'Isolate this device only'],
  menuRelease:     ['격리 해제', 'Release isolation'],
  menuBook:        ['장비 사전에 등록…', 'Add to device book…'],
  menuCopyMac:     ['MAC 주소 복사', 'Copy MAC address'],

  /* Device book dialog */
  bookTitle:       ['장비 사전에 등록', 'Add to device book'],
  bookHint:        ['MAC 앞자리로 장비를 알아봅니다. 앞 6자리만 적으면 그 제조사 장비 전부에, 12자리를 다 적으면 이 장비 한 대에만 적용됩니다.',
                    'Devices are recognised by their MAC prefix. Six digits covers every device from that vendor; all twelve covers this one device only.'],
  bookPrefixLabel: ['MAC 앞자리', 'MAC prefix'],
  bookVendorLabel: ['제조사', 'Vendor'],
  bookKindLabel:   ['장비 종류', 'Device type'],
  bookKindPh:      ['IP 카메라', 'IP camera'],
  bookNoteLabel:   ['메모', 'Note'],
  optional:        ['선택', 'optional'],
  bookListHead:    ['등록된 사전', 'Registered entries'],
  bookSearchPh:    ['제조사 · 종류 · 앞자리', 'Vendor · type · prefix'],
  bookCount:       ['항목 {n}개 · MAC 앞자리 {p}개', '{n} entries · {p} MAC prefixes'],
  bookCountFound:  ['{n}개 찾음 (전체 {all}개)', '{n} of {all} shown'],
  bookPrefixes:    ['앞자리 {n}개', '{n} prefixes'],
  bookMorePrefixes:['외 {n}개 — 검색으로 찾으십시오', '+{n} more — use the search box'],
  bookMine:        ['직접 등록', 'yours'],
  bookNoneYet:     ['아직 등록된 항목이 없습니다.', 'Nothing registered yet.'],
  bookNoMatch:     ['찾는 항목이 없습니다.', 'No matching entry.'],
  bookDelete:      ['사전에서 지우기', 'Remove from book'],
  cancel:          ['취소', 'Cancel'],
  save:            ['저장', 'Save'],
  close:           ['닫기', 'Close'],

  /* Compare dialog */
  compareDlg:      ['스캔 기록 비교', 'Scan record comparison'],
  compareWhen:     ['기준 기록: {when}{name} · 장비 {n}대', 'Saved scan: {when}{name} · {n} device{s}'],
  compareAdded:    ['새로 생긴 장비', 'New devices'],
  compareGone:     ['사라진 장비', 'Missing devices'],
  compareMoved:    ['IP가 바뀐 장비', 'Devices whose IP changed'],
  compareNone:     ['없음', 'none'],

  /* Free IP dialog */
  freeDlg:         ['사용 가능 후보 IP', 'Candidate IPs'],
  freeCopyBtn:     ['목록 복사', 'Copy list'],
  freeExportBtn:   ['배정용 CSV 저장', 'Save assignment CSV'],
  freeSummary:     ['훑은 주소 {scanned}개 · 응답 {used}개 · 응답 없음 {free}개',
                    'Scanned {scanned} · responded {used} · no response {free}'],
  freeCaution:     ['응답이 없었던 IP 목록입니다. 절전·방화벽 장비도 포함될 수 있으니 배정 전 실제 사용 여부를 확인하십시오.',
                    'These IPs did not respond. Sleeping or firewalled devices may be included, so confirm before assigning one.'],
  freeScanFirst:   ['먼저 대역을 스캔하십시오.', 'Scan a range first.'],
  freeNone:        ['응답이 없는 IP가 없습니다.', 'No IPs failed to respond.'],
  freeNoScan:      ['스캔 기록이 없습니다.', 'No scan on record.'],
  freeNothingCopy: ['복사할 후보 IP가 없습니다.', 'No candidate IPs to copy.'],
  freeCopied:      ['후보 IP {n}개를 복사했습니다.', 'Copied {n} candidate IP{s}.'],
  candidateFileName: ['후보IP_배정표', 'candidate-ip-assignment'],
  freeExported:    ['후보 IP {n}개를 배정용 CSV로 저장했습니다.', 'Saved {n} candidate IPs as an assignment CSV.'],

  /* Switch port dialog */
  snmpDlg:         ['스위치 포트 찾기', 'Find switch port'],
  snmpHint:        ['스위치는 어느 포트에서 어느 MAC이 들어왔는지 기억합니다. 그 표를 읽어와 목록에 붙입니다. 스위치에서 <b>SNMP v2c 읽기</b>가 켜져 있어야 합니다.',
                    'A switch remembers which MAC came in on which port. This reads that table and attaches it to the list. <b>SNMP v2c read</b> must be enabled on the switch.'],
  snmpHostLabel:   ['스위치 IP', 'Switch IP'],
  snmpCommLabel:   ['커뮤니티 문자열', 'Community string'],
  snmpScope:       ['읽기 전용 조회입니다. 스위치 설정은 건드리지 않습니다.',
                    'Read-only query. Nothing on the switch is changed.'],
  snmpRun:         ['조회', 'Query'],
  snmpNeedHost:    ['스위치 IP를 넣으십시오.', 'Enter the switch IP.'],
  snmpReading:     ['스위치에서 MAC 표를 읽는 중입니다…', 'Reading the MAC table from the switch…'],
  snmpMatched:     ['{sw} — MAC {read}개를 읽어 {n}대에 포트를 붙였습니다.',
                    '{sw} — read {read} MACs and matched {n} device{s}.'],
  mbManual:        ['사용설명서', 'User guide'],
  manualFail:      ['사용설명서를 열지 못했습니다. {why}', 'Could not open the user guide. {why}'],
  slowLinkTip:     ['이 스위치의 다른 포트보다 느리게 붙어 있습니다 — 랜케이블·포트 확인',
                    'Linked slower than the rest of this switch — check the cable and port'],
  halfLinkTip:     ['반이중으로 붙어 있습니다 — 속도는 정상이지만 실제로는 느립니다. 양끝의 속도·듀플렉스를 자동으로 맞추십시오',
                    'Running half duplex — the speed looks fine but throughput is not. Set speed/duplex to auto on both ends'],
  snmpSlowFound:   ['느린 링크 {n}대를 찾았습니다 — {list}. 작업 로그를 보십시오.',
                    'Found {n} slow link{s} — {list}. See the activity log.'],
  snmpNoMatch:     ['{sw} — MAC {read}개를 읽었지만 목록과 맞는 장비가 없습니다.',
                    '{sw} — read {read} MACs but none of them match the list.'],

  /* PoE — power-cycle a port */
  menuPoe:         ['이 장비 전원 재시작 (PoE)', 'Restart this device (PoE)'],
  poeDlg:          ['PoE 전원 재시작', 'PoE power restart'],
  poeHint:         ['스위치에게 이 포트의 전원을 껐다 켜라고 시킵니다. 장비의 랜선을 뽑았다 꽂는 것과 같습니다. <b>쓰기 권한이 있는 커뮤니티</b>가 필요합니다.',
                    'Tells the switch to cut and restore power on this port — the same as unplugging the device and plugging it back in. A <b>community with write access</b> is required.'],
  poeTargetLabel:  ['대상', 'Target'],
  poeWaitLabel:    ['끄고 기다릴 시간(초)', 'Seconds to stay off'],
  poeWriteLabel:   ['쓰기 커뮤니티 문자열', 'Write community string'],
  poeWarn:         ['이 포트에 물린 장비가 꺼졌다가 다시 올라옵니다. 올라오는 데 30초에서 1분쯤 걸립니다. 녹화 중이면 그동안 영상이 끊깁니다.',
                    'The device on this port goes down and comes back. It needs 30-60 seconds to boot. If it is recording, the video stops for that long.'],
  poeRun:          ['전원 껐다 켜기', 'Cycle power'],
  poeRunning:      ['{ip} 전원을 껐다 켜는 중입니다…', 'Cycling power on {ip}…'],
  poeDone:         ['{ip} 전원을 다시 넣었습니다. 30초에서 1분 뒤 다시 스캔해 보십시오.',
                    'Power restored to {ip}. Scan again in 30-60 seconds.'],
  poeNeedComm:     ['쓰기 커뮤니티 문자열을 넣으십시오.', 'Enter the write community string.'],
  poeNoPort:       ['먼저 스위치 포트를 조회해야 합니다.', 'Run the switch port lookup first.'],
  poeTip:          ['이 포트가 PoE 로 전원을 주고 있습니다', 'This port is delivering PoE'],

  /* Port management */
  portsBtn:        ['포트 관리…', 'Manage ports…'],
  portsTitle:      ['스위치의 포트를 전부 보고, 안 쓰는 포트를 잠급니다',
                    'See every port on the switch and lock the unused ones'],
  reportDlg:       ['준공 · 점검 리포트', 'Commissioning · inspection report'],
  reportHint:      ['스캔 결과와 스위치 포트를 엑셀 한 부로 뽑습니다. 시트 다섯 장 — 점검 소견 · 장비 목록 · 스위치 포트 배치 · PoE 전력 · 남은 IP.',
                    'Exports the scan and switch ports as one workbook: findings, devices, switch layout, PoE power, free IPs.'],
  reportSite:      ['현장 이름', 'Site'],
  reportSitePh:    ['○○고등학교 본관', 'Building / customer name'],
  reportAuthor:    ['점검자', 'Inspected by'],
  reportAuthorPh:  ['이름', 'Your name'],
  reportSwitches:  ['스위치 IP', 'Switch IPs'],
  reportSwitchesPh:['비워 두면 목록에서 찾은 스위치를 모두 읽습니다 (쉼표로 여러 대)',
                    'Leave blank to use every switch found in the list (comma-separated)'],
  reportCommunity: ['읽기 커뮤니티 문자열', 'Read community string'],
  reportNote:      ['현장 소견', "Engineer's notes"],
  reportNotePh:    ['문서에 그대로 들어갑니다. 비워 두면 손으로 적을 빈칸이 남습니다.',
                    'Goes into the document as-is. Leave blank for a hand-written space.'],
  reportGo:        ['엑셀로 저장', 'Save as Excel'],
  reportScopeAuto: ['목록에서 스위치 {n}대를 찾았습니다: {list}',
                    'Found {n} switch(es) in the list: {list}'],
  reportScopeNone: ['목록에 스위치 정보가 없습니다. 스위치 IP 를 직접 넣으십시오 — 비워 두면 IP 충돌만 담긴 리포트가 나옵니다.',
                    'No switch info in the list. Enter switch IPs — leaving it blank produces an IP-conflict-only report.'],
  reportSaving:    ['스위치를 읽고 리포트를 만드는 중…', 'Reading switches and building the report…'],
  reportDone:      ['리포트를 저장했습니다 — 스위치 {sw}대 · 장비 {n}대', 'Report saved — {sw} switch(es), {n} devices'],
  reportDoneSlow:  ['리포트를 저장했습니다 — 스위치 {sw}대 · 장비 {n}대 · 속도 저하 {slow}곳',
                    'Report saved — {sw} switch(es), {n} devices, {slow} speed drops'],
  reportMissed:    ['스위치 {n}대를 못 읽었습니다. 문서에 \'확인 못 함\' 으로 적혀 있습니다.',
                    'Could not read {n} switch(es); marked "not checked" in the document.'],
  filterXlsx:      ['엑셀 통합 문서', 'Excel workbook'],
  reportFile:      ['준공리포트', 'report'],
  portsWas:        ['예전에는 {was} 였습니다 ({when} 확인). 지금 {now}.',
                    'This port ran at {was} on {when}. Now {now}.'],
  portsWasWhy:     ['랜선 양끝을 다시 보십시오. 기가는 8가닥을 다 쓰는데, 한 가닥만 헐거워도 링크는 안 끊기고 조용히 100M 로 내려앉습니다.',
                    'Re-check both cable ends. Gigabit uses all 8 wires; one loose wire silently drops the link to 100M with no other symptom.'],
  portsSlowGuess:  ['이 스위치에서 이 포트만 {now} 입니다. 지난 기록은 없어서 떨어진 것인지는 모릅니다.',
                    'This port alone runs at {now} on this switch. With no earlier record, we cannot tell if it dropped.'],
  portsWasOk:      ['이 속도가 정상입니다', 'This speed is normal'],
  portsWasOkTitle: ['일부러 100M 장비를 물려 둔 포트라면 눌러 두십시오. 다음부터 이 포트는 빨갛게 나오지 않습니다.',
                    'Press this if a 100M device is meant to be here. The port stops being flagged.'],
  portsWasDone:    ['{port} — 지금 속도를 정상으로 기록했습니다.', '{port} — current speed recorded as normal.'],
  portsTallyWas:   ['예전보다 느림', 'slower than before'],
  portsTallyHalf:  ['반이중', 'half duplex'],
  // The legend swatch already carries the ½. Put it in the label too and you get '½½'.
  portsLegendHalf: ['반이중 — 설정 불일치', 'half duplex — config mismatch'],
  portsFull:       ['전이중', 'full duplex'],
  portsHalfTip:    ['반이중 — 속도는 정상이지만 실제로는 느립니다',
                    'half duplex — the speed looks fine but throughput is not'],
  portsHalf:       ['{s} 로 붙어 있지만 반이중입니다. 속도 칸만 보면 정상으로 보이는데 실제로는 느립니다.',
                    'Linked at {s} but running half duplex. The speed column looks fine; the throughput is not.'],
  portsHalfWhy:    ['양끝 중 한쪽만 속도·듀플렉스를 손으로 박아 두면, 반대쪽은 협상할 상대가 없어 반이중으로 내려앉습니다. 양쪽 다 자동(auto)으로 맞추십시오. 정말 오래된 10M 장비라면 원래 반이중일 수 있습니다.',
                    'If only one end has speed/duplex hard-coded, the other has nothing to negotiate with and falls back to half duplex. Set both ends to auto. A genuinely old 10M device may be half duplex by design.'],
  portsHalfProof:  ['늦은 충돌 {n}회가 쌓여 있습니다 — 짐작이 아니라 지금 프레임이 깨지고 있다는 뜻입니다.',
                    '{n} late collisions have accumulated — this is not a guess; frames are being lost right now.'],
  portsLinkWait:   ['{p} — 링크가 붙기를 기다립니다…', '{p} — waiting for the link…'],
  portsLinkUp:     ['{p} — 링크가 붙었습니다. {s} · {n}초 걸림.',
                    '{p} — link is up at {s} after {n}s.'],
  portsLinkStp:    ['링크는 붙었지만 통신은 아직일 수 있습니다. 스위치가 루프를 확인하는 동안(STP) 30초쯤 더 걸립니다 — 장비가 안 올라와도 그동안은 정상입니다.',
                    'The link is up but traffic may still be blocked: the switch runs STP for ~30s more. A device not coming back yet is normal during that time.'],
  portsLinkNone:   ['{p} — {n}초를 기다렸는데 링크가 안 붙습니다. 잠금은 풀렸으니 랜선과 반대편 장비를 보십시오.',
                    '{p} — no link after {n}s. The port is unlocked, so check the cable and the device at the other end.'],
  portsDlg:        ['스위치 포트 관리', 'Switch port management'],
  portsCommPh:     ['잠그거나 풀 때만 필요합니다', 'Only needed to lock or unlock'],
  portsLockFree:   ['빈 포트 전부 잠그기', 'Lock every unused port'],
  portsStateUp:    ['사용 중', 'in use'],
  portsStateDown:  ['링크 없음', 'no link'],
  portsStateLock:  ['잠김', 'locked'],
  portsLock:       ['잠그기', 'Lock'],
  portsUnlock:     ['풀기', 'Unlock'],
  portsNeedComm:   ['잠그거나 풀려면 쓰기 커뮤니티 문자열이 필요합니다.',
                    'A write community string is needed to lock or unlock.'],
  portsLocked:     ['포트 {p} 를 잠갔습니다.', 'Locked port {p}.'],
  portsUnlocked:   ['포트 {p} 를 풀었습니다.', 'Unlocked port {p}.'],
  portsLockAsk:    ['빈 포트 {n}개를 잠급니다 — 다시 누르십시오', 'Locks {n} unused ports — click again'],
  portsLockNone:   ['잠글 빈 포트가 없습니다.', 'There are no unused ports to lock.'],
  portsLockDone:   ['빈 포트 {n}개를 잠갔습니다.', 'Locked {n} unused port{s}.'],
  portsReading:    ['스위치에서 포트 목록을 읽는 중입니다…', 'Reading the port list from the switch…'],
  netAll:          ['전체', 'All'],
  ifaceMany:       ['랜카드 {n}개 — {list}', '{n} adapters — {list}'],
  portsUplink:     ['업링크 · SFP', 'Uplink · SFP'],
  portsLegend:     ['1G 연결', '1G link'],
  portsLegendSlow: ['100M — 케이블 의심', '100M — suspect cable'],
  portsGhost:      ['이 포트에 물린 MAC {n}개가 스캔 목록에 없습니다 — IP 가 아직 없는 장비이거나, 훑지 않은 대역을 쓰고 있습니다.',
                    '{n} MAC{s} on this port {s2} not in the scan — the device may have no IP yet, or sit in a range you did not sweep.'],
  portsLegendIdle: ['빈 포트', 'unused'],
  portsLegendLock: ['잠김', 'locked'],
  portsWhere:      ['{sw} · 포트 {n}개', '{sw} · {n} ports'],
  // The device list names the switch by its sysName, this window by its IP. With only
  // one of the two on screen there is no telling which switch you are looking at.
  portsWhereNamed: ['{name} · {sw} · 포트 {n}개', '{name} · {sw} · {n} ports'],
  portsTallyUp:    ['연결', 'up'],
  portsTallySlow:  ['100M', '100M'],
  portsTallyLock:  ['잠김', 'locked'],
  portsLegendPoe:  ['PoE 급전 중', 'PoE powered'],
  portsLegendKeep: ['못 잠그는 포트', 'cannot be locked'],
  poeAdminOff:     ['전원 끊기', 'Cut power'],
  poeAdminOn:      ['전원 넣기', 'Restore power'],
  poeCycle:        ['전원 껐다 켜기', 'Cycle power'],
  poeCut:          ['포트 {p} 전원을 끊었습니다.', 'Cut power on port {p}.'],
  poeRestored:     ['포트 {p} 전원을 넣었습니다.', 'Restored power on port {p}.'],

  /* Notices */
  engineReady:     ['네트워크 엔진 준비됨', 'Network engine ready'],
  engineFailOpt:   ['네트워크 엔진을 시작하지 못했습니다', 'Could not start the network engine'],
  engineCheck:     ['네트워크 엔진 확인 필요', 'Network engine needs attention'],
  noIp:            ['(IP 없음)', '(no IP)'],
  refreshing:      ['네트워크 인터페이스 정보를 새로 읽는 중입니다…', 'Re-reading network interfaces…'],
  refreshed:       ['인터페이스와 IP 주소를 새로고침했습니다.', 'Interfaces and IP addresses refreshed.'],
  pickIfaceWarn:   ['네트워크 인터페이스를 선택하십시오.', 'Choose a network interface.'],
  scanning:        ['대역을 스캔 중입니다…', 'Scanning the range…'],
  scanDone:        ['스캔이 완료되었습니다.', 'Scan complete.'],
  cancelScan:      ['스캔 중지', 'Stop scan'],
  canceling:       ['스캔을 중지하는 중입니다…', 'Stopping the scan…'],
  scanCanceled:    ['스캔을 중지했습니다. 확인한 결과는 그대로 남았습니다.',
                    'Scan stopped. Results found so far were kept.'],
  identifying:     ['장비 정보를 검사 중입니다…', 'Identifying the device…'],
  identifyDone:    ['장비 정보 검사가 완료되었습니다.', 'Device identified.'],
  isolatePhase:    ['장비 격리', 'Isolating'],
  isolateMsg:      ['선택 장비를 격리 중입니다.', 'Isolating the selected device.'],
  isolateDone:     ['선택 장비만 격리했습니다.', 'Isolated the selected device.'],
  releaseDone:     ['격리를 해제했습니다.', 'Isolation released.'],
  macCopied:       ['MAC 주소를 복사했습니다.', 'MAC address copied.'],
  ipCopyTitle:     ['클릭하여 IP 주소 복사', 'Click to copy IP address'],
  ipCopied:        ['IP 주소를 복사했습니다 — {ip}', 'Copied IP address — {ip}'],
  ipCopyFailed:    ['IP 주소를 복사하지 못했습니다.', 'Could not copy the IP address.'],
  isolateDlg:      ['장비 격리 확인', 'Confirm device isolation'],
  isolateCaution:  ['이 컴퓨터에서는 이 IP를 선택한 MAC 주소에만 연결합니다. 작업 뒤에는 격리 해제를 누르십시오.',
                    'On this computer, this IP will be connected only to the selected MAC address. Release isolation when finished.'],
  isolateConfirm:  ['이 장비만 격리', 'Isolate this device only'],

  /* Device book notices */
  bookNeedPrefix:  ['MAC 앞자리를 6자리 이상 적어주십시오. (제조사 코드)',
                    'Enter at least six hex digits (the vendor code).'],
  bookScopeOne:    ['{p} — 이 장비 한 대에만 적용됩니다.', '{p} — applies to this one device only.'],
  bookScopeAll:    ['{p} — 이 앞자리로 시작하는 장비 전부에 적용됩니다.',
                    '{p} — applies to every device whose MAC starts with this.'],
  bookNew:         ['사전에 없는 앞자리입니다. 새로 등록됩니다.', 'Not in the book yet — this will be added.'],
  bookEmptyEntry:  ['(내용 없음)', '(empty)'],
  bookExists:      ['이미 사전에 있습니다 — 현재 "{now}".', 'Already in the book — currently "{now}".'],
  bookSplit:       ['저장하면 이 앞자리만 따로 떼어내 바꿉니다. 같은 묶음의 나머지 {n}개는 그대로입니다.',
                    'Saving splits this prefix out on its own; the other {n} in the same group {s2} left alone.'],
  bookOverwrite:   ['저장하면 덮어씁니다.', 'Saving overwrites it.'],
  bookPrefixShort: ['MAC 앞자리는 6자리 이상이어야 합니다.', 'The MAC prefix needs at least six digits.'],
  bookAdded:       ['장비 사전에 등록했습니다.', 'Added to the device book.'],
  bookUpdated:     ['장비 사전을 수정했습니다.', 'Device book updated.'],
  bookRemoved:     ['장비 사전에서 지웠습니다.', 'Removed from the device book.'],

  /* Export */
  saveDlgTitle:    ['스캔 결과 저장', 'Save scan results'],
  reportFileName:  ['현장리포트', 'site-report'],
  filterCsv:       ['스캔 결과 (CSV)', 'Scan results (CSV)'],
  filterHtml:      ['현장 리포트 (HTML)', 'Site report (HTML)'],
  exportedHtml:    ['현장 리포트를 저장했습니다 ({n}대). 브라우저로 열어 인쇄하면 됩니다.',
                    'Site report saved ({n} device{s}). Open it in a browser to print.'],
  exported:        ['{n}대를 저장했습니다.', 'Saved {n} device{s}.'],
};

/* Device kinds. The engine (IPFixStudio.py) holds the only copy of this table;
   the screen fetches it at startup and fills this in. If the fetch fails, the
   Korean names the engine emits show through unchanged. */
const KINDS = {};

/** One string. {name} placeholders are filled from the second argument. */
function t(key, vars) {
  const pair = STRINGS[key];
  let text = pair ? (pair[lang === 'en' ? 1 : 0] ?? pair[0]) : key;
  if (vars) {
    // English drops the s when there is one. {s} fills itself from the number n.
    if (vars.n !== undefined && vars.s === undefined) {
      vars = { ...vars, s: Number(vars.n) === 1 ? '' : 's',
               s2: Number(vars.n) === 1 ? 'is' : 'are' };
    }
    for (const [name, value] of Object.entries(vars)) {
      text = text.replaceAll(`{${name}}`, String(value));
    }
  }
  return text;
}

/** Device kind / OS names the engine gives in Korean, in the screen's language.
    Anything not in the table passes through unchanged. */
function tk(text) {
  if (!text) return '';
  return lang === 'en' ? (KINDS[text] || text) : text;
}

/** Swap the text baked into index.html for the current language. */
function applyStaticText() {
  document.documentElement.lang = lang;
  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.innerHTML = t(el.dataset.i18n);
  }
  for (const el of document.querySelectorAll('[data-i18n-ph]')) {
    el.placeholder = t(el.dataset.i18nPh);
  }
  for (const el of document.querySelectorAll('[data-i18n-title]')) {
    el.title = t(el.dataset.i18nTitle);
  }
}
