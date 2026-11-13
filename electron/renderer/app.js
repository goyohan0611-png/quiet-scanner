/* Quiet Scanner — local ARP scan and IP-conflict separation */
const $ = (selector) => document.querySelector(selector);
const copyText = (text) => window.ipfix.copyText ? window.ipfix.copyText(text) : navigator.clipboard.writeText(text);
const ICONS = {
  refresh: 'M20 7v5h-5M4 17v-5h5M6.1 6.1A8 8 0 0 1 19.6 10M4.4 14A8 8 0 0 0 17.9 17.9',
  scan: 'M8 3H3v5M16 3h5v5M21 16v5h-5M8 21H3v-5M5 12h14',
  stop: 'M6 6h12v12H6z',
  search: 'M21 21l-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
  dhcp: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01M16 7h2M16 17h2',
  available: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  book: 'M12 5v16M3 3h5a4 4 0 0 1 4 2 4 4 0 0 1 4-2h5v16h-5a4 4 0 0 0-4 2 4 4 0 0 0-4-2H3z',
  copy: 'M9 9h12v12H9zM15 5V3H3v12h2',
  ping: 'M2 12h4l3-8 6 16 3-8h4',
  tcp: 'M4 4h16v12h-5v4H9v-4H4zM8 8v3M12 8v3M16 8v3',
  isolate: 'M9 15l6-6M7 8 5 6M17 16l2 2M8 3v2M16 19v2M3 8h2M19 16h2M7 12l-2 2a4 4 0 0 0 5 5l2-2M12 7l2-2a4 4 0 0 1 5 5l-2 2',
  release: 'M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-2 2M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l2-2',
  x: 'M6 6l12 12M18 6 6 18',
  check: 'M5 12l4 4L19 6',
  chevron: 'M9 5l7 7-7 7',
  down: 'M6 9l6 6 6-6'
  ,shield: 'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6'
};
function icon(name) {
  return `<svg class="icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="${ICONS[name] || ''}"/></svg>`;
}

let state = { groups: [], summary: {}, progress: {}, logs: [], isolated: null };
let interfaces = [];
let selectedInterface = null;
let expandedGroups = new Set();
let filterText = '';
let scanRunning = false;
let operationRunning = false;
let interfacesLoading = true;
let progressVisible = false;
let progressRun = 0;
let contextKey = null;
let isolateKey = null;

const COLUMNS = [
  ['IP / 장비 MAC', 'minmax(220px, 1.5fr)'],
  ['제조사', '1.5fr'],
  ['등록 종류', '1fr'],
  ['응답', '.6fr'],
  ['상태', '.8fr'],
];

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function macText(device) {
  return String(device?.mac || '').toUpperCase().replaceAll(':', '-');
}

function ipKey(ip) {
  return String(ip || '').split('.').reduce((value, bit) => value * 256 + (Number(bit) || 0), 0);
}

function deviceOf(key) {
  for (const group of state.groups || []) {
    const found = (group.devices || []).find((device) => device.key === key);
    if (found) return found;
  }
  return null;
}

function selectedCard() {
  return interfaces.find((card) => card.scapyName === selectedInterface) || interfaces[0] || null;
}

function bestInterface(cards) {
  const score = (card) => {
    const ips = (card.ips || []).filter(Boolean);
    const real = ips.filter((ip) => !/^(169\.254|127\.|0\.)/.test(ip));
    if (!real.length) return -100;
    let value = 0;
    if (real.some((ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip))) value += 20;
    if ((card.ipv4 || []).some((row) => row.cidr)) value += 5;
    if (/virtual|vmware|hyper-v|bluetooth|loopback|vpn|wintun|tap/i.test(`${card.desc || ''} ${card.name || ''}`)) value -= 30;
    return value;
  };
  return cards.reduce((best, card) => !best || score(card) > score(best) ? card : best, null);
}

function interfaceLabel(card) {
  if (!card) return '인터페이스를 선택하십시오';
  const ip = (card.ips || [])[0];
  return `${card.desc || card.name}${ip ? '  —  ' + ip : '  —  IP 없음'}`;
}

function setTarget() {
  const card = selectedCard();
  const cidr = card?.ipv4?.[0]?.cidr;
  const ip = card?.ips?.[0];
  if (cidr) $('#target').value = cidr;
  else if (ip) $('#target').value = `${ip.split('.').slice(0, 3).join('.')}.1-254`;
}

function renderInterfaceMenu() {
  const current = selectedCard();
  $('#ifaceBtn').innerHTML = current ? `<span class="iface-name">${esc(current.desc || current.name)}</span><span class="iface-address">${esc(current.ips?.[0] || 'IP 없음')}</span>${icon('down')}` : esc(interfaceLabel(null));
  $('#ifaceBtn').title = interfaceLabel(current);
  $('#ifaceMenu').innerHTML = interfaces.map((card) => {
    const selected = card.scapyName === selectedInterface;
    const net = card.ipv4?.[0]?.cidr || card.ips?.[0] || 'IP 없음';
    return `<button class="${selected ? 'selected' : ''}" data-interface="${esc(card.scapyName)}"><i class="tick">${selected ? icon('check') : ''}</i><i class="if-name">${esc(card.desc || card.name)}</i><i class="if-net">${esc(net)}</i></button>`;
  }).join('');
}

async function loadInterfaces(keep = selectedInterface) {
  if (scanRunning || operationRunning) return;
  interfacesLoading = true;
  paintScanButton();
  try {
    interfaces = await call('interfaces');
    const saved = interfaces.find((card) => card.scapyName === keep);
    selectedInterface = (saved || bestInterface(interfaces))?.scapyName || null;
    $('#ifaceBtn').disabled = !selectedInterface;
    renderInterfaceMenu();
    setTarget();
    notice('네트워크 인터페이스를 불러왔습니다.');
  } catch (error) {
    interfaces = [];
    selectedInterface = null;
    $('#ifaceBtn').textContent = '인터페이스 조회 실패 — 새로고침하십시오';
    notice(cleanMessage(error.message), true);
  } finally {
    interfacesLoading = false;
    paintScanButton();
  }
}

function isOwnIp(ip) {
  return (selectedCard()?.ips || []).includes(ip);
}

function matchesFilter(group, device) {
  if (!filterText) return true;
  const text = [group.ip, device.mac, device.vendor, device.kind].join(' ').toLowerCase();
  return text.includes(filterText);
}

function renderHead() {
  $('#tableHead').style.setProperty('--grid-cols', COLUMNS.map((column) => column[1]).join(' '));
  $('#tableHead').innerHTML = COLUMNS.map((column) => `<span>${column[0]}</span>`).join('');
}

function responseText(device) {
  return device.ms == null ? '—' : `${device.ms}ms`;
}

function statusHtml(device) {
  if (device.status === 'isolation_unknown') return '<span class="status isolated">분리 확인 필요</span>';
  return state.isolated === device.key
    ? '<span class="status isolated">분리됨</span>'
    : '<span class="status">확인됨</span>';
}

function rowHtml(device) {
  return `<div class="device-row" data-key="${esc(device.key)}">
    <div class="mac">${esc(macText(device))}</div>
    <div class="vendor-cell" title="${esc(device.vendor || '미확인')}">${esc(device.vendor || '미확인')}</div>
    <div class="kind-cell">${esc(device.book ? device.kind : '') || '—'}</div>
    <div class="response-cell">${esc(responseText(device))}</div>
    <div>${statusHtml(device)}</div>
  </div>`;
}

function soloHtml(group, device) {
  const own = isOwnIp(group.ip) ? ' own-ip' : '';
  return `<div class="solo-row${own}" data-key="${esc(device.key)}">
    <div class="ip-cell"><div class="ip-line"><button class="ip ip-copy" data-copy-ip="${esc(group.ip)}" title="IP 주소 복사">${esc(group.ip)}</button>${own ? '<span class="own-tag">내 PC</span>' : ''}</div><span class="mac-sub">${esc(macText(device))}</span></div>
    <div class="vendor-cell" title="${esc(device.vendor || '미확인')}">${esc(device.vendor || '미확인')}</div>
    <div class="kind-cell">${esc(device.book ? device.kind : '') || '—'}</div>
    <div class="response-cell">${esc(responseText(device))}</div>
    <div>${statusHtml(device)}</div>
  </div>`;
}

function groupHtml(group, open) {
  const count = group.devices?.length || group.count || 0;
  return `<div class="group-row conflict" data-ip="${esc(group.ip)}">
    <div class="ip-cell"><button class="chevron${open ? ' open' : ''}" data-toggle-group="${esc(group.ip)}" aria-expanded="${open}" aria-label="${esc(group.ip)} 충돌 장비 ${open ? '접기' : '펼치기'}">${icon('chevron')}</button><button class="ip ip-copy" data-copy-ip="${esc(group.ip)}" title="IP 주소 복사">${esc(group.ip)}</button><span class="conflict-badge">MAC ${count}개 충돌</span></div>
    <span class="group-note">펼쳐서 장비 확인 · 우클릭으로 분리</span>
  </div>`;
}

function render() {
  renderHead();
  const summary = state.summary || {};
  const devices = Number(summary.devices || 0);
  const conflicts = Number(summary.conflictIps || 0);
  $('#titleCount').textContent = conflicts ? `IP 충돌 ${conflicts}곳` : (devices ? `발견 장비 ${devices}대` : '대기 중');
  $('#titleCount').classList.toggle('has-conflicts', conflicts > 0);
  $('#subTitle').textContent = devices
    ? `${conflicts ? `장비 ${devices}대 · ` : ''}응답 IP ${summary.ips || 0}개`
    : '인터페이스와 대역을 확인하십시오.';

  const rows = [];
  let matched = 0;
  const groups = [...(state.groups || [])].sort((left, right) => {
    if (Boolean(right.conflict) !== Boolean(left.conflict)) return right.conflict ? 1 : -1;
    return ipKey(left.ip) - ipKey(right.ip);
  });
  for (const group of groups) {
    const devicesInGroup = (group.devices || []).filter((device) => matchesFilter(group, device));
    if (!devicesInGroup.length) continue;
    matched += devicesInGroup.length;
    if (!group.conflict && devicesInGroup.length === 1) {
      rows.push(soloHtml(group, devicesInGroup[0]));
      continue;
    }
    const open = Boolean(filterText) || expandedGroups.has(group.ip);
    rows.push(groupHtml(group, open));
    if (open) rows.push(...devicesInGroup.sort((a, b) => macText(a).localeCompare(macText(b))).map(rowHtml));
  }
  $('#deviceList').style.setProperty('--grid-cols', COLUMNS.map((column) => column[1]).join(' '));
  $('#deviceList').innerHTML = rows.length
    ? rows.join('')
    : `<div class="empty">${filterText ? '검색 결과가 없습니다.' : '아직 발견된 장비가 없습니다.'}</div>`;
  if (filterText) $('#subTitle').textContent = `검색 결과 ${matched}대`;
  renderActivity();
}

function renderActivity() {
  const progress = state.progress || {};
  const pct = Math.max(0, Math.min(100, Number(progress.pct) || 0));
  $('#scanProgress').hidden = !progressVisible;
  $('#scanProgressText').textContent = progress.msg ? `${progress.msg} · ${pct}%` : `${pct}%`;
  $('#scanProgressBar').style.width = `${pct}%`;
  const logs = state.logs || [];
  $('#logEntries').innerHTML = logs.length
    ? logs.map((log) => `<div class="log-entry ${esc(log.level || 'info')}"><span class="log-time">${esc(log.t || '')}</span><span class="log-message">${esc(log.msg || '')}</span></div>`).join('')
    : '<div class="log-empty">작업 기록이 여기에 표시됩니다.</div>';
  $('#logEntries').scrollTop = $('#logEntries').scrollHeight;
}

function applyState(next) {
  if (next.revision != null && next.revision < (state.revision || 0)) return;
  state = { ...state, ...next };
  render();
  paintScanButton();
}

function notice(text, isError = false) {
  const target = $('#notice');
  target.textContent = text;
  target.style.color = isError ? 'var(--red-text)' : '';
}

function showProgress() {
  progressRun += 1;
  progressVisible = true;
}

function hideProgressLater() {
  const run = progressRun;
  window.setTimeout(() => {
    if (run === progressRun) {
      progressVisible = false;
      renderActivity();
    }
  }, 5000);
}

function cleanMessage(message) {
  let text = String(message || '');
  text = text.replace(/^Error invoking remote method\s+'[^']*':\s*/, '');
  while (/^(Error|TypeError|RuntimeError):\s*/.test(text)) text = text.replace(/^\w+:\s*/, '');
  return text.trim() || '작업을 완료하지 못했습니다.';
}

async function call(action, payload) {
  try {
    return await window.ipfix.request(action, payload);
  } catch (error) {
    notice(cleanMessage(error?.message), true);
    throw error;
  }
}

function maxTargetSize(target) {
  const match = String(target || '').trim().match(/\/(\d{1,2})$/);
  if (!match) return 0;
  const prefix = Number(match[1]);
  return prefix >= 0 && prefix <= 32 ? 2 ** (32 - prefix) : 0;
}

function paintScanButton() {
  const button = $('#scanBtn');
  button.innerHTML = `${icon(scanRunning ? 'stop' : 'scan')}${scanRunning ? '스캔 중지' : '대역 스캔'}`;
  button.classList.toggle('danger', scanRunning);
  button.disabled = operationRunning || interfacesLoading || (!scanRunning && !selectedCard());
  $('#ifaceBtn').disabled = scanRunning || operationRunning || interfacesLoading || !selectedCard();
  $('#refreshInterfaces').disabled = scanRunning || operationRunning || interfacesLoading;
  $('#bookBtn').disabled = scanRunning || operationRunning || interfacesLoading;
  $('#dhcpBtn').disabled = scanRunning || operationRunning || interfacesLoading || !selectedCard();
  $('#dhcpAgain').disabled = $('#dhcpBtn').disabled;
  $('#availableBtn').disabled = scanRunning || operationRunning || interfacesLoading || !scanMatchesInterface();
}

function scanMatchesInterface() {
  const before = state.completedScan?.card;
  const now = selectedCard();
  if (!before || !now) return false;
  const addresses = card => (card.ipv4 || []).map(ip => `${ip.ip}/${ip.prefix}`).sort().join(',');
  return before.scapyName.toLowerCase() === now.scapyName.toLowerCase()
    && before.index === now.index && before.mac.toLowerCase() === now.mac.toLowerCase()
    && [...before.ips].sort().join(',') === [...now.ips].sort().join(',') && addresses(before) === addresses(now);
}

function closeInterfaceMenu() {
  $('#ifaceMenu').hidden = true;
  $('#ifaceBtn').setAttribute('aria-expanded', 'false');
}

function hideContextMenu() {
  $('#contextMenu').hidden = true;
  contextKey = null;
}

function showContextMenu(event, key) {
  event.preventDefault();
  const device = deviceOf(key);
  if (!device) return;
  contextKey = key;
  const menu = $('#contextMenu');
  for (const button of menu.querySelectorAll('button')) {
    button.hidden = false;
    button.disabled = button.dataset.menu !== 'copyMac' && (scanRunning || operationRunning || interfacesLoading);
  }
  for (const separator of menu.querySelectorAll(':scope > span')) separator.hidden = false;
  if (device) {
    menu.querySelector('[data-menu="isolate"]').hidden = state.isolated === key;
    menu.querySelector('[data-menu="release"]').hidden = state.isolated !== key;
  }
  menu.hidden = false;
  menu.style.left = `${Math.min(event.clientX, window.innerWidth - menu.offsetWidth - 8)}px`;
  menu.style.top = `${Math.min(event.clientY, window.innerHeight - menu.offsetHeight - 8)}px`;
}

function openIsolate(key) {
  const device = deviceOf(key);
  if (!device) return;
  isolateKey = key;
  $('#isolateTarget').textContent = `${device.ip}  ·  ${macText(device)}`;
  $('#isolateDialog').hidden = false;
  $('#isolateConfirm').focus();
}

function closeIsolate() {
  $('#isolateDialog').hidden = true;
  isolateKey = null;
}

$('#ifaceBtn').addEventListener('click', (event) => {
  event.stopPropagation();
  const menu = $('#ifaceMenu');
  if (!menu.hidden) return closeInterfaceMenu();
  renderInterfaceMenu();
  const box = $('#ifaceBtn').getBoundingClientRect();
  menu.hidden = false;
  $('#ifaceBtn').setAttribute('aria-expanded', 'true');
  menu.style.left = `${box.left}px`;
  menu.style.top = `${box.bottom + 4}px`;
  menu.style.minWidth = `${box.width}px`;
});

$('#ifaceMenu').addEventListener('click', (event) => {
  const button = event.target.closest('button[data-interface]');
  if (!button) return;
  selectedInterface = button.dataset.interface;
  renderInterfaceMenu();
  setTarget();
  closeInterfaceMenu();
  paintScanButton();
});

$('#refreshInterfaces').addEventListener('click', () => loadInterfaces(selectedInterface));

$('#scanBtn').addEventListener('click', async () => {
  if (operationRunning || interfacesLoading) return;
  if (scanRunning) {
    $('#scanBtn').disabled = true;
    notice('스캔 중지 요청을 보냈습니다.');
    try {
      const result = await call('cancel');
      if (result.state) applyState(result.state);
    } finally {
      $('#scanBtn').disabled = false;
    }
    return;
  }
  const card = selectedCard();
  const target = $('#target').value.trim();
  if (!card) return notice('네트워크 인터페이스를 선택하십시오.', true);
  if (!target) return notice('스캔할 대역을 입력하십시오.', true);
  const count = maxTargetSize(target);
  if (count > 4096) return notice('한 번에 최대 4,096개 주소까지만 스캔할 수 있습니다.', true);
  if (count > 1024 && !window.confirm(`${count.toLocaleString()}개 주소를 스캔합니다. 계속할까요?`)) return;
  scanRunning = true;
  expandedGroups.clear();
  showProgress();
  state.progress = { phase: 'scan', pct: 0, msg: '인터페이스 확인 · 스캔 준비' };
  renderActivity();
  paintScanButton();
  notice('대역을 스캔하는 중입니다…');
  try {
    const result = await call('scan', { iface: card, ifaces: [card], target });
    applyState(result);
    notice(result.canceled ? '스캔을 중지했습니다.' : '스캔을 완료했습니다.');
  } catch (_) { /* call() reports the failure */
  } finally {
    scanRunning = false;
    paintScanButton();
    hideProgressLater();
    renderActivity();
  }
});

$('#filterInput').addEventListener('input', (event) => {
  filterText = event.target.value.trim().toLowerCase();
  render();
});

$('#deviceList').addEventListener('click', (event) => {
  const copyIp = event.target.closest('[data-copy-ip]')?.dataset.copyIp;
  if (copyIp) {
    event.stopPropagation();
    copyText(copyIp)
      .then(() => notice(`${copyIp}을(를) 클립보드에 복사했습니다.`))
      .catch(() => notice('IP 주소를 복사하지 못했습니다.', true));
    return;
  }
  const group = event.target.closest('.group-row');
  if (!group) return;
  const ip = group.dataset.ip;
  if (expandedGroups.has(ip)) expandedGroups.delete(ip); else expandedGroups.add(ip);
  render();
  if (event.target.closest('[data-toggle-group]')) $(`[data-toggle-group="${CSS.escape(ip)}"]`)?.focus();
});

$('#deviceList').addEventListener('contextmenu', (event) => {
  const row = event.target.closest('.device-row, .solo-row');
  if (row) showContextMenu(event, row.dataset.key);
  else event.preventDefault();
});

$('#contextMenu').addEventListener('click', async (event) => {
  const action = event.target.closest('[data-menu]')?.dataset.menu;
  const key = contextKey;
  if (!action || !key) return;
  if (action !== 'copyMac' && (scanRunning || operationRunning || interfacesLoading)) return;
  hideContextMenu();
  try {
    if (action === 'isolate') return openIsolate(key);
    if (action === 'book') return await openBook(key);
    if (action === 'ping' || action === 'tcp') return openDiagnostic(action, key);
    if (action === 'release') {
      operationRunning = true;
      paintScanButton();
      try {
        applyState(await call('release'));
        notice('장비 분리를 해제했습니다.');
      } finally {
        operationRunning = false;
        paintScanButton();
      }
      return;
    }
    if (action === 'copyMac') {
      await copyText(macText(deviceOf(key)));
      notice('MAC 주소를 클립보드에 복사했습니다.');
    }
  } catch (_) { /* call() displays the error */ }
});

$('#isolateClose').addEventListener('click', closeIsolate);
$('#isolateCancel').addEventListener('click', closeIsolate);
$('#isolateDialog').addEventListener('mousedown', (event) => {
  if (event.target === $('#isolateDialog')) closeIsolate();
});
$('#isolateConfirm').addEventListener('click', async () => {
  if (!isolateKey || scanRunning || operationRunning || interfacesLoading) return;
  const key = isolateKey;
  closeIsolate();
  operationRunning = true;
  paintScanButton();
  showProgress();
  state.progress = { pct: 0, msg: '선택한 장비로 연결을 고정하는 중' };
  renderActivity();
  try {
    applyState(await call('isolate', { key }));
    notice('선택한 장비만 연결되도록 분리했습니다.');
  } catch (_) { /* keep the backend's verified/unknown state visible */
  } finally {
    operationRunning = false;
    paintScanButton();
    hideProgressLater();
    renderActivity();
  }
});

document.addEventListener('click', (event) => {
  if (!event.target.closest('#contextMenu')) hideContextMenu();
  if (!event.target.closest('#ifaceMenu') && !event.target.closest('#ifaceBtn')) closeInterfaceMenu();
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    hideContextMenu();
    closeInterfaceMenu();
    closeIsolate();
    $('#bookDialog').hidden = true;
    $('#dhcpDialog').hidden = true;
    closeAvailable();
    closeDiagnostic();
  }
});

let resizeStartY = 0;
let resizeStartHeight = 0;
const resizeHandle = $('#logResizeHandle');
function setLogHeight(height) {
  const maxHeight = Math.max(140, window.innerHeight - 300);
  const next = Math.round(Math.max(110, Math.min(maxHeight, height)));
  document.documentElement.style.setProperty('--log-height', `${next}px`);
  resizeHandle.setAttribute('aria-valuenow', String(next));
  resizeHandle.setAttribute('aria-valuemax', String(maxHeight));
}
resizeHandle.setAttribute('aria-valuemax', String(Math.max(140, window.innerHeight - 300)));
resizeHandle.addEventListener('keydown', event => {
  if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return;
  event.preventDefault();
  setLogHeight($('.activity-panel').getBoundingClientRect().height + (event.key === 'ArrowUp' ? 16 : -16));
});
resizeHandle.addEventListener('pointerdown', (event) => {
  resizeStartY = event.clientY;
  resizeStartHeight = $('.activity-panel').getBoundingClientRect().height;
  resizeHandle.classList.add('dragging');
  resizeHandle.setPointerCapture(event.pointerId);
});
resizeHandle.addEventListener('pointermove', (event) => {
  if (!resizeHandle.hasPointerCapture(event.pointerId)) return;
  setLogHeight(resizeStartHeight - (event.clientY - resizeStartY));
});
function finishResize(event) {
  if (resizeHandle.hasPointerCapture(event.pointerId)) resizeHandle.releasePointerCapture(event.pointerId);
  resizeHandle.classList.remove('dragging');
}
resizeHandle.addEventListener('pointerup', finishResize);
resizeHandle.addEventListener('pointercancel', finishResize);

let bookRows = [];
function bookDigits(value) {
  return String(value || '').replace(/[:-]|\s|\./g, '').toLowerCase();
}
function bookFields(prefix = '', vendor = '', kind = '', note = '') {
  $('#bookPrefix').value = prefix;
  $('#bookVendor').value = vendor;
  $('#bookKind').value = kind;
  $('#bookNote').value = note;
  $('#bookMessage').textContent = '';
  $('#bookDelete').disabled = !bookRows.some(row => row[0] === bookDigits(prefix));
}
function renderBook() {
  const query = $('#bookSearch').value.trim().toLowerCase();
  const matches = bookRows.filter(row => row.join(' ').toLowerCase().includes(query));
  $('#bookList').innerHTML = matches.slice(0, 200).map(row =>
    `<button type="button" data-prefix="${esc(row[0])}"><b>${esc(row[0].match(/.{1,2}/g).join('-').toUpperCase())}</b><span>${esc(row[1])}</span><span>${esc(row[2])}</span></button>`
  ).join('') || '<p class="modal-hint">등록된 항목이 없습니다.</p>';
  if (matches.length > 200) $('#bookList').insertAdjacentHTML('beforeend', '<p class="modal-hint">검색어를 입력하면 나머지 항목도 찾을 수 있습니다.</p>');
}
async function openBook(key) {
  bookRows = (await call('book_list')).rows || [];
  const device = deviceOf(key);
  const prefix = device ? bookDigits(device.mac).slice(0, 6) : '';
  const row = bookRows.find(row => row[0] === prefix);
  bookFields(...(row || [prefix, device?.vendor || '', device?.book ? device.kind : '', '']));
  $('#bookSearch').value = '';
  renderBook();
  $('#bookDialog').hidden = false;
  $('#bookPrefix').focus();
}
$('#bookBtn').addEventListener('click', () => openBook().catch(() => {}));
$('#bookClose').addEventListener('click', () => { $('#bookDialog').hidden = true; });
$('#bookNew').addEventListener('click', () => { bookFields(); $('#bookPrefix').focus(); });
$('#bookSearch').addEventListener('input', renderBook);
$('#bookPrefix').addEventListener('input', () => {
  $('#bookDelete').disabled = !bookRows.some(row => row[0] === bookDigits($('#bookPrefix').value));
});
$('#bookList').addEventListener('click', event => {
  const button = event.target.closest('[data-prefix]');
  if (!button) return;
  const row = bookRows.find(row => row[0] === button.dataset.prefix);
  if (row) bookFields(...row);
});
$('#bookForm').addEventListener('submit', async event => {
  event.preventDefault();
  $('#bookSave').disabled = true;
  try {
    const result = await call('book_save', {
      prefix: $('#bookPrefix').value.trim(), vendor: $('#bookVendor').value.trim(),
      kind: $('#bookKind').value.trim(), note: $('#bookNote').value.trim()
    });
    bookRows = result.rows;
    applyState(result.state);
    renderBook();
    $('#bookDelete').disabled = false;
    $('#bookMessage').textContent = '저장했습니다. 현재 목록과 다음 스캔에 반영됩니다.';
  } catch (error) { $('#bookMessage').textContent = cleanMessage(error.message); }
  finally { $('#bookSave').disabled = false; }
});
$('#bookDelete').addEventListener('click', async () => {
  const prefix = $('#bookPrefix').value.trim();
  if (!window.confirm(`${prefix} 등록을 삭제할까요?`)) return;
  $('#bookDelete').disabled = true;
  try {
    const result = await call('book_remove', { prefix });
    bookRows = result.rows;
    applyState(result.state);
    bookFields();
    renderBook();
    $('#bookMessage').textContent = '등록을 삭제했습니다.';
  } catch (error) { $('#bookMessage').textContent = cleanMessage(error.message); }
  finally { $('#bookDelete').disabled = !bookRows.some(row => row[0] === bookDigits($('#bookPrefix').value)); }
});

function leaseText(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return '';
  if (value >= 0xffffffff) return '무제한';
  if (value % 86400 === 0) return `${value / 86400}일`;
  if (value >= 3600) return `${Math.round(value / 360) / 10}시간`;
  if (value >= 60) return `${Math.round(value / 60)}분`;
  return `${value}초`;
}

function dhcpRowHtml(server) {
  const who = [server.vendor || '제조사 미확인', server.kind].filter(Boolean).join(' · ');
  const addresses = values => values?.length ? values.map(value => `<span>${esc(value)}</span>`).join('') : '미제공';
  const facts = [
    ['제안 IP', `${esc(server.offered || '미제공')}${server.mask ? `<small>마스크 ${esc(server.mask)}</small>` : ''}`],
    ['게이트웨이', addresses(server.router)],
    ['DNS', addresses(server.dns)],
    ['임대 시간', esc(leaseText(server.lease) || '미제공')],
  ];
  if (server.domain) facts.push(['도메인', esc(server.domain)]);
  if (server.relay) facts.push(['중계 주소', esc(server.relay)]);
  return `<section class="dhcp-row">
    <div class="dhcp-server-head"><strong>${esc(server.ip || '주소 미확인')}</strong><span>${esc(who)}</span></div>
    <p class="dhcp-mac">MAC ${esc(macText(server) || '미확인')}</p>
    <dl class="dhcp-facts">${facts.map(([label,value]) => `<div><dt>${label}</dt><dd>${value}</dd></div>`).join('')}</dl>
  </section>`;
}

function renderDhcp(result, reveal = true) {
  const servers = result.servers || [];
  $('#dhcpInterface').textContent = result.iface || '';
  $('#dhcpSummary').textContent = `응답한 DHCP 서버 ${servers.length}대`;
  const caution = $('#dhcpCaution');
  caution.hidden = servers.length < 2;
  caution.textContent = servers.length < 2 ? ''
    : '여러 서버가 응답했습니다. 의도한 서버와 제안 대역인지 확인하십시오. 정상적인 이중화 구성일 수도 있습니다.';
  $('#dhcpList').innerHTML = servers.length ? servers.map(dhcpRowHtml).join('')
    : '<div class="dialog-empty"><strong>응답한 서버가 없습니다.</strong><p>고정 IP만 사용하는 망에서는 정상일 수 있습니다.</p></div>';
  if (reveal) $('#dhcpDialog').hidden = false;
  if (!$('#dhcpDialog').hidden) $('#dhcpOk').focus();
}

async function runDhcp() {
  if (scanRunning || operationRunning || interfacesLoading) return;
  const card = selectedCard();
  if (!card) return notice('네트워크 인터페이스를 선택하십시오.', true);
  operationRunning = true;
  paintScanButton();
  $('#dhcpInterface').textContent = card.desc || card.name;
  $('#dhcpSummary').textContent = 'DHCP 서버 확인 중…';
  $('#dhcpCaution').hidden = true;
  $('#dhcpList').setAttribute('aria-busy', 'true');
  $('#dhcpList').innerHTML = '<div class="dhcp-loading" role="status">서버의 주소 제안을 기다리고 있습니다.</div>';
  $('#dhcpDialog').hidden = false;
  $('#dhcpClose').focus();
  notice('DHCP 서버를 확인하는 중입니다… (최대 6초)');
  try {
    const result = await call('dhcp_servers', { iface: card });
    if (result.state) applyState(result.state);
    renderDhcp(result, false);
    const count = (result.servers || []).length;
    notice(count ? `DHCP 서버 ${count}대를 확인했습니다.` : '응답한 DHCP 서버가 없습니다.', count > 1);
  } catch (error) {
    $('#dhcpSummary').textContent = 'DHCP 서버 확인 실패';
    $('#dhcpList').innerHTML = `<div class="dialog-empty"><strong>검사를 완료하지 못했습니다.</strong><p>${esc(cleanMessage(error.message))}</p></div>`;
  } finally {
    $('#dhcpList').removeAttribute('aria-busy');
    operationRunning = false;
    paintScanButton();
  }
}

$('#dhcpBtn').addEventListener('click', runDhcp);
$('#dhcpAgain').addEventListener('click', runDhcp);
$('#dhcpClose').addEventListener('click', () => { $('#dhcpDialog').hidden = true; });
$('#dhcpOk').addEventListener('click', () => { $('#dhcpDialog').hidden = true; });
$('#dhcpDialog').addEventListener('mousedown', (event) => {
  if (event.target === $('#dhcpDialog')) $('#dhcpDialog').hidden = true;
});

let availableIps = [];
function filteredAvailable() {
  const query = $('#availableSearch').value.trim();
  return availableIps.filter(ip => ip.includes(query));
}
function renderAvailable() {
  const ips = filteredAvailable();
  $('#availableList').innerHTML = ips.map(ip => `<li><button type="button" data-available-ip="${esc(ip)}" aria-label="${esc(ip)} 복사">${esc(ip)}</button></li>`).join('');
  $('#availableEmpty').hidden = ips.length > 0;
  $('#availableEmpty').textContent = availableIps.length ? '일치하는 IP가 없습니다.' : '현재 스캔 범위에 사용 후보 IP가 없습니다.';
  $('#availableCopy').disabled = ips.length === 0;
}
function closeAvailable() {
  const open = !$('#availableDialog').hidden;
  $('#availableDialog').hidden = true;
  if (open && !$('#availableBtn').disabled) $('#availableBtn').focus();
}
$('#availableBtn').addEventListener('click', async () => {
  if (scanRunning || operationRunning || interfacesLoading || !scanMatchesInterface()) return;
  operationRunning = true; paintScanButton();
  try {
    const result = await call('available_ips', { iface:selectedCard() });
    availableIps = result.ips || [];
    $('#availableSummary').textContent = `사용 후보 ${availableIps.length}개 · ${result.scanned}개 주소 검사`;
    $('#availableTarget').textContent = result.target;
    $('#availableTime').textContent = `${result.completedAt} 기준`;
    $('#availableSearch').value = '';
    $('#availableStatus').textContent = 'IP를 클릭하면 복사합니다.';
    renderAvailable();
    $('#availableDialog').hidden = false;
    $('#availableSearch').focus();
  } catch (_) { /* call() reports the failure */ }
  finally { operationRunning = false; paintScanButton(); }
});
$('#availableSearch').addEventListener('input', renderAvailable);
$('#availableList').addEventListener('click', async event => {
  const ip = event.target.closest('[data-available-ip]')?.dataset.availableIp;
  if (!ip) return;
  try { await copyText(ip); $('#availableStatus').textContent = `${ip} 복사됨`; }
  catch (_) { $('#availableStatus').textContent = '복사하지 못했습니다. 다시 시도하십시오.'; }
});
$('#availableCopy').addEventListener('click', async () => {
  const ips = filteredAvailable();
  if (!ips.length) return;
  try { await copyText(ips.join('\r\n')); $('#availableStatus').textContent = `${ips.length}개 IP 복사됨`; }
  catch (_) { $('#availableStatus').textContent = '복사하지 못했습니다. 다시 시도하십시오.'; }
});
$('#availableClose').addEventListener('click', closeAvailable);
$('#availableOk').addEventListener('click', closeAvailable);
$('#availableDialog').addEventListener('mousedown', event => { if (event.target === $('#availableDialog')) closeAvailable(); });
for (const id of ['#dhcpDialog', '#availableDialog', '#diagnosticDialog', '#bookDialog', '#isolateDialog']) {
  $(id).addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const controls = [...$(id).querySelectorAll('button:not(:disabled), input:not(:disabled), summary')].filter(control => control.getClientRects().length);
    const first = controls[0], last = controls.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
}

let diagnostic = null;

function diagnosticLine(result) {
  const line = document.createElement('div');
  line.className = `diagnostic-line ${result.ok ? 'success' : 'failure'}`;
  const now = new Date();
  const time = [now.getHours(), now.getMinutes(), now.getSeconds()].map(value => String(value).padStart(2, '0')).join(':');
  const ms = result.ms == null ? '' : (result.ms === 0 ? '<1ms' : `${result.ms}ms`);
  const isPing = diagnostic?.mode === 'ping';
  const text = isPing ? (result.ok ? `Reply from ${diagnostic.ip}` : result.status === 'timeout' ? 'Request timed out' : result.status === 'unreachable' ? 'Destination unreachable' : result.message) : result.message;
  const sequence = isPing ? `<i class="ping-sequence">#${String(diagnostic.sent).padStart(3, '0')}</i>` : '';
  line.innerHTML = `<time>${esc(time)}</time>${sequence}<span title="${esc(result.message)}">${esc(text)}</span><b>${esc(ms)}</b>`;
  const list = $('#diagnosticResult');
  const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 24;
  list.append(line);
  while (list.children.length > 60) list.firstElementChild.remove();
  if (atBottom) list.scrollTop = list.scrollHeight;
}

function stopPing() {
  if (!diagnostic || diagnostic.mode !== 'ping') return;
  diagnostic.active = false;
  $('#pingRunState').textContent = operationRunning ? 'STOPPING' : 'STOPPED';
  $('#pingRunState').classList.remove('running');
  diagnostic.wake?.();
  $('#pingToggle').disabled = operationRunning;
  $('#pingToggle').textContent = operationRunning ? '중지 중…' : '다시 시작';
}

function closeDiagnostic() {
  stopPing();
  $('#diagnosticDialog').hidden = true;
}

function openDiagnostic(mode, key) {
  if (scanRunning || operationRunning || interfacesLoading) return;
  const device = deviceOf(key);
  if (!device || !['ping', 'tcp'].includes(mode)) return;
  diagnostic = { mode, key, ip: device.ip, active: false, sent: 0, received: 0, totalMs: 0 };
  $('#diagnosticDialog').classList.toggle('is-ping', mode === 'ping');
  $('#diagnosticDialog').classList.toggle('is-terminal', mode === 'ping');
  $('#diagnosticTitle').textContent = mode === 'ping' ? '연속 Ping' : 'TCP 포트 확인';
  $('#diagnosticTarget').textContent = diagnostic.ip;
  $('#diagnosticTarget').hidden = mode !== 'tcp';
  $('#pingTerminalHead').hidden = mode === 'tcp';
  $('#pingCommand').textContent = `PING ${diagnostic.ip}`;
  $('#diagnosticConflict').hidden = !state.groups.some(group => group.ip === device.ip && group.conflict) || (state.isolated === key && device.status !== 'isolation_unknown');
  $('#tcpForm').hidden = mode !== 'tcp';
  $('#pingRunState').textContent = 'READY'; $('#pingRunState').classList.remove('running');
  $('#pingToggle').hidden = mode !== 'ping';
  $('#pingSummary').hidden = mode !== 'ping';
  $('#pingHint').hidden = mode !== 'ping';
  $('#diagnosticResult').replaceChildren();
  $('#diagnosticDialog').hidden = false;
  if (mode === 'ping') runPing(diagnostic);
  else { $('#tcpPort').focus(); $('#tcpPort').select(); }
}

function paintPing(current) {
  const lost = current.sent - current.received;
  const loss = current.sent ? Math.round(lost / current.sent * 1000) / 10 : 0;
  const average = current.received ? `${Math.round(current.totalMs / current.received * 10) / 10}ms` : '—';
  $('#pingSummary').innerHTML = [['전송',current.sent],['응답',current.received],['손실',`${lost} (${loss}%)`],['평균',average]]
    .map(([label,value]) => `<span class="ping-metric"><span>${label} </span><b>${esc(value)}</b></span>`).join('');
}

async function runPing(current) {
  if (operationRunning || current !== diagnostic) return;
  current.active = true;
  current.sent = current.received = current.totalMs = 0;
  operationRunning = true;
  paintScanButton(); paintPing(current);
  $('#diagnosticResult').replaceChildren();
  $('#pingToggle').disabled = false;
  $('#pingToggle').textContent = '중지';
  $('#pingRunState').textContent = 'RUNNING';
  $('#pingRunState').classList.add('running');
  let started = false;
  try {
    await call('ping_start', { key: current.key });
    started = true;
    while (current.active) {
      const begin = Date.now();
      const reply = await call('ping', { key: current.key });
      current.sent += 1;
      if (reply.ok) { current.received += 1; current.totalMs += reply.ms || 0; }
      if (current === diagnostic) { diagnosticLine(reply); paintPing(current); }
      if (!current.active) break;
      await new Promise(resolve => {
        const timer = window.setTimeout(() => { current.wake = null; resolve(); }, Math.max(0, 1000 - (Date.now() - begin)));
        current.wake = () => { window.clearTimeout(timer); current.wake = null; resolve(); };
      });
    }
  } catch (error) {
    if (current === diagnostic) diagnosticLine({ ok: false, message: cleanMessage(error.message) });
  } finally {
    current.active = false;
    if (started) { try { await call('ping_stop', { key: current.key }); } catch (_) {} }
    operationRunning = false;
    paintScanButton();
    if (current === diagnostic) {
      $('#pingToggle').disabled = false; $('#pingToggle').textContent = '다시 시작';
      $('#pingRunState').textContent = 'STOPPED'; $('#pingRunState').classList.remove('running');
    }
  }
}

$('#pingToggle').addEventListener('click', () => {
  if (diagnostic?.active) stopPing(); else if (diagnostic) runPing(diagnostic);
});
$('#tcpForm').addEventListener('submit', async event => {
  event.preventDefault();
  if (operationRunning || diagnostic?.mode !== 'tcp') return;
  const port = Number($('#tcpPort').value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return $('#tcpPort').reportValidity();
  const current = diagnostic;
  operationRunning = true; paintScanButton();
  $('#tcpRun').disabled = true; $('#tcpPort').disabled = true;
  $('#diagnosticResult').textContent = `${current.ip}:${port} 연결 확인 중…`;
  try {
    const result = await call('tcp_check', { key: current.key, port });
    if (current === diagnostic) { $('#diagnosticResult').replaceChildren(); diagnosticLine(result); }
  } catch (error) {
    if (current === diagnostic) { $('#diagnosticResult').replaceChildren(); diagnosticLine({ ok: false, message: cleanMessage(error.message) }); }
  } finally {
    operationRunning = false; paintScanButton();
    $('#tcpRun').disabled = false; $('#tcpPort').disabled = false;
  }
});
$('#diagnosticClose').addEventListener('click', closeDiagnostic);
$('#diagnosticOk').addEventListener('click', closeDiagnostic);
$('#diagnosticDialog').addEventListener('mousedown', event => { if (event.target === $('#diagnosticDialog')) closeDiagnostic(); });

for (const element of document.querySelectorAll('[data-icon]')) element.insertAdjacentHTML('afterbegin', icon(element.dataset.icon));
window.ipfix.onState(applyState);
render();
loadInterfaces().catch(() => {});
