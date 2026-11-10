/* Quiet Scanner — local ARP scan and IP-conflict separation */
const $ = (selector) => document.querySelector(selector);

let state = { groups: [], summary: {}, progress: {}, logs: [], isolated: null };
let interfaces = [];
let selectedInterface = null;
let expandedGroups = new Set();
let filterText = '';
let scanRunning = false;
let progressVisible = false;
let progressRun = 0;
let contextKey = null;
let isolateKey = null;

const COLUMNS = [
  ['IP / 장비 MAC', '2.4fr'],
  ['제조사', '1.35fr'],
  ['등록 종류', '.9fr'],
  ['응답', '.75fr'],
  ['상태', '.85fr'],
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
  $('#ifaceBtn').textContent = interfaceLabel(selectedCard());
  $('#ifaceMenu').innerHTML = interfaces.map((card) => {
    const selected = card.scapyName === selectedInterface;
    const net = card.ipv4?.[0]?.cidr || card.ips?.[0] || 'IP 없음';
    return `<button data-interface="${esc(card.scapyName)}"><i class="tick">${selected ? '●' : '○'}</i><i class="if-name">${esc(card.desc || card.name)}</i><i class="if-net">${esc(net)}</i></button>`;
  }).join('');
}

async function loadInterfaces(keep = selectedInterface) {
  const button = $('#refreshInterfaces');
  button.disabled = true;
  try {
    interfaces = await call('interfaces');
    const saved = interfaces.find((card) => card.scapyName === keep);
    selectedInterface = (saved || bestInterface(interfaces))?.scapyName || null;
    $('#ifaceBtn').disabled = !selectedInterface;
    renderInterfaceMenu();
    setTarget();
    notice('네트워크 인터페이스를 불러왔습니다.');
  } finally {
    button.disabled = false;
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
  return state.isolated === device.key
    ? '<span class="status isolated">분리됨</span>'
    : '<span class="status">확인됨</span>';
}

function rowHtml(device) {
  return `<div class="device-row" data-key="${esc(device.key)}">
    <div class="mac">${esc(macText(device))}</div>
    <div>${esc(device.vendor || '미확인')}</div>
    <div>${esc(device.book ? device.kind : '') || '—'}</div>
    <div>${esc(responseText(device))}</div>
    <div>${statusHtml(device)}</div>
  </div>`;
}

function soloHtml(group, device) {
  const own = isOwnIp(group.ip) ? ' own-ip' : '';
  return `<div class="solo-row${own}" data-key="${esc(device.key)}">
    <div class="ip-cell"><button class="ip ip-copy" data-copy-ip="${esc(group.ip)}" title="IP 주소 복사">${esc(group.ip)}</button><span class="mac-sub">${esc(macText(device))}</span></div>
    <div>${esc(device.vendor || '미확인')}</div>
    <div>${esc(device.book ? device.kind : '') || '—'}</div>
    <div>${esc(responseText(device))}</div>
    <div>${statusHtml(device)}</div>
  </div>`;
}

function groupHtml(group, open) {
  const count = group.devices?.length || group.count || 0;
  return `<div class="group-row conflict" data-ip="${esc(group.ip)}">
    <div class="ip-cell"><span class="chevron">${open ? '▾' : '▸'}</span><button class="ip ip-copy" data-copy-ip="${esc(group.ip)}" title="IP 주소 복사">${esc(group.ip)}</button><span class="conflict-badge">MAC ${count}개 충돌</span></div>
    <span class="group-note">클릭해서 충돌 장비를 확인하고, 대상 장비를 우클릭해 분리하십시오.</span>
  </div>`;
}

function render() {
  renderHead();
  const summary = state.summary || {};
  const devices = Number(summary.devices || 0);
  const conflicts = Number(summary.conflictIps || 0);
  $('#titleCount').textContent = conflicts ? `IP 충돌 ${conflicts}곳` : (devices ? `발견 장비 ${devices}대` : '대기 중');
  $('#subTitle').textContent = devices
    ? `장비 ${devices}대 · 응답 IP ${summary.ips || 0}개${conflicts ? ` · 충돌 IP ${conflicts}곳` : ''}`
    : '인터페이스를 선택하고 스캔을 시작하십시오.';

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
  state = { ...state, ...next };
  render();
}

function notice(text, isError = false) {
  const target = $('#notice');
  target.textContent = text;
  target.style.color = isError ? '#e7475b' : '';
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
  button.textContent = scanRunning ? '스캔 중지' : '대역 스캔';
  button.classList.toggle('danger', scanRunning);
  button.disabled = false;
}

function closeInterfaceMenu() {
  $('#ifaceMenu').hidden = true;
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
  menu.querySelector('[data-menu="isolate"]').hidden = state.isolated === key;
  menu.querySelector('[data-menu="release"]').hidden = state.isolated !== key;
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
});

$('#refreshInterfaces').addEventListener('click', () => loadInterfaces(selectedInterface));

$('#scanBtn').addEventListener('click', async () => {
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
  paintScanButton();
  notice('대역을 스캔하는 중입니다…');
  try {
    const result = await call('scan', { iface: card, ifaces: [card], target });
    applyState(result);
    notice(result.canceled ? '스캔을 중지했습니다.' : '스캔을 완료했습니다.');
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
    navigator.clipboard.writeText(copyIp)
      .then(() => notice(`${copyIp}을(를) 클립보드에 복사했습니다.`))
      .catch(() => notice('IP 주소를 복사하지 못했습니다.', true));
    return;
  }
  const group = event.target.closest('.group-row');
  if (!group) return;
  const ip = group.dataset.ip;
  if (expandedGroups.has(ip)) expandedGroups.delete(ip); else expandedGroups.add(ip);
  render();
});

$('#deviceList').addEventListener('contextmenu', (event) => {
  const row = event.target.closest('.device-row, .solo-row');
  if (row) showContextMenu(event, row.dataset.key);
});

$('#contextMenu').addEventListener('click', async (event) => {
  const action = event.target.dataset.menu;
  const key = contextKey;
  if (!action || !key) return;
  hideContextMenu();
  try {
    if (action === 'isolate') return openIsolate(key);
    if (action === 'book') return await openBook(key);
    if (action === 'release') {
      applyState(await call('release'));
      notice('장비 분리를 해제했습니다.');
      return;
    }
    if (action === 'copyMac') {
      await navigator.clipboard.writeText(macText(deviceOf(key)));
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
  if (!isolateKey) return;
  const key = isolateKey;
  closeIsolate();
  showProgress();
  state.progress = { pct: 0, msg: '선택한 장비로 연결을 고정하는 중' };
  renderActivity();
  try {
    applyState(await call('isolate', { key }));
    notice('선택한 장비만 연결되도록 분리했습니다.');
  } finally {
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
  }
});

let resizeStartY = 0;
let resizeStartHeight = 0;
const resizeHandle = $('#logResizeHandle');
resizeHandle.addEventListener('pointerdown', (event) => {
  resizeStartY = event.clientY;
  resizeStartHeight = $('.activity-panel').getBoundingClientRect().height;
  resizeHandle.classList.add('dragging');
  resizeHandle.setPointerCapture(event.pointerId);
});
resizeHandle.addEventListener('pointermove', (event) => {
  if (!resizeHandle.hasPointerCapture(event.pointerId)) return;
  const maxHeight = Math.max(140, window.innerHeight - 300);
  const next = Math.max(110, Math.min(maxHeight, resizeStartHeight - (event.clientY - resizeStartY)));
  document.documentElement.style.setProperty('--log-height', `${Math.round(next)}px`);
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

window.ipfix.onState(applyState);
render();
loadInterfaces().catch(() => {});
