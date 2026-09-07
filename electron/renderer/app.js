/* Quiet Scanner — 현장 IP 충돌 정리 도구
 * Copyright (C) 2026 고요한
 *
 * 이 프로그램은 자유 소프트웨어입니다. GNU 일반 공중 사용 허가서 제2판 또는
 * 그 이후 판의 조건에 따라 재배포하거나 수정할 수 있습니다. 아무런 보증도
 * 하지 않습니다. 자세한 것은 같은 폴더의 LICENSE 를 보십시오.
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
const $ = (s) => document.querySelector(s);
let state = { groups: [], summary: {}, progress: {}, logs: [], isolated: null };
let interfaces = [];

let menuKey = null;
let sortKey = 'ip';
let sortDesc = false;
let filterText = '';
let expandedGroups = new Set();
let progressVisible = false;
let progressRun = 0;
let scanRunning = false;

const portName = { 80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP', 554: 'RTSP', 8000: 'HIK', 37777: 'Dahua', 22: 'SSH' };

/* ── 목록의 칸 ────────────────────────────────────────────────────────
   읽어오는 정보가 늘어나면서 한 칸에 다 밀어넣을 수 없게 됐다.
   칸을 나누고, 무엇을 볼지는 사람이 고른다 — 머리글 우클릭.
   현장마다 보는 것이 다르니, 고른 것은 다음 실행 때도 그대로 남는다.
   ------------------------------------------------------------------- */

const COLUMNS = [
  { key: 'ip',     name: 'colIp',     width: '2fr',    fixed: true },
  { key: 'vendor', name: 'colVendor', width: '.85fr',  on: true },
  { key: 'kind',   name: 'colKind',   width: '1.35fr', on: true },
  { key: 'model',  name: 'colModel',  width: '1.2fr',  on: true },
  { key: 'name',   name: 'colName',   width: '1.15fr', on: true },
  { key: 'ms',     name: 'colMs',     width: '.5fr',   on: true },
  { key: 'os',     name: 'colOs',     width: '.8fr',   on: true },
  { key: 'ports',  name: 'colPorts',  width: '.95fr',  on: true },
  { key: 'swport', name: 'colSwport', width: '1.7fr',  on: true },
  { key: 'vlan',   name: 'colVlan',   width: '.5fr' },
  { key: 'seen',   name: 'colSeen',   width: '1fr' },
];

const COLUMN_STORE = 'ipscan.columns';
const defaultColumns = () => COLUMNS.filter(c => c.fixed || c.on).map(c => c.key);
let shownColumns = defaultColumns();

try {
  const saved = JSON.parse(localStorage.getItem(COLUMN_STORE) || 'null');
  if (Array.isArray(saved) && saved.length) {
    // 저장해둔 목록에 없는 칸(옛 버전)은 버리고, IP 칸은 무슨 일이 있어도 남긴다.
    const known = saved.filter(k => COLUMNS.some(c => c.key === k));
    shownColumns = known.includes('ip') ? known : ['ip', ...known];
  }
} catch (_) { /* 저장소를 못 읽어도 기본값으로 돈다 */ }

function saveColumns() {
  try { localStorage.setItem(COLUMN_STORE, JSON.stringify(shownColumns)); }
  catch (_) { /* 못 저장해도 이번 실행에는 적용된다 */ }
}

/** 화면에 보이는 칸을, 정해둔 순서대로. */
function visibleColumns() {
  return COLUMNS.filter(c => shownColumns.includes(c.key));
}

/** 장비 하나에서 이름 후보를 겹치는 것 없이 모은다. */
function deviceNames(d) {
  const out = [];
  for (const name of [d.host, d.mdns, d.nbname, d.ssdp]) {
    if (!name) continue;
    if (out.some(x => x.toLowerCase() === String(name).toLowerCase())) continue;
    if (d.model && String(name).toLowerCase() === String(d.model).toLowerCase()) continue;
    out.push(name);
  }
  return out;
}

/** 칸 하나에 들어갈 글자. 정렬·검색·내보내기가 모두 이것을 쓴다. */
function cellText(d, key) {
  switch (key) {
    case 'ip':     return (d.mac || '').toUpperCase().replaceAll(':', '-');
    case 'vendor': return d.vendor || t('unknownVendor');
    case 'kind':   return tk(d.kind) || t('unknownKind');
    case 'model':  return d.model || '';
    case 'name':   return deviceNames(d)[0] || '';
    case 'ms':     return d.ms == null ? '' : `${d.ms}ms`;
    case 'os':     return tk(d.os) || (d.ttl != null ? `TTL ${d.ttl}` : '');
    case 'ports':  return (d.ports || []).join(', ');
    case 'swport': return d.swport || '';
    case 'serial': return d.serial || '';
    case 'nbname': return d.nbname || '';
    case 'mdns':   return d.mdns || '';
    case 'ssdp':   return d.ssdp || '';
    case 'vlan':   return d.swvlan == null ? '' : String(d.swvlan);
    case 'seen':   return d.seen || '';
    default:       return '';
  }
}

/** 정렬할 때 쓰는 값. 숫자는 숫자로 비교해야 10이 9 뒤에 온다. */
function cellSortValue(d, key) {
  switch (key) {
    case 'ip':    return ipKey(d.ip);
    case 'ms':    return d.ms == null ? Number.MAX_SAFE_INTEGER : Number(d.ms);
    case 'ports': return (d.ports || []).length;
    case 'vlan':  return d.swvlan == null ? Number.MAX_SAFE_INTEGER : Number(d.swvlan);
    default:      return cellText(d, key).toLowerCase();
  }
}

/** 링크 속도를 사람이 읽는 단위로. 1000 이상은 기가로 적는다. */
function formatSpeed(mbps) {
  const value = Number(mbps) || 0;
  if (!value) return '';
  return value >= 1000 ? `${value / 1000}G` : `${value}M`;
}

/** 칸 하나를 그린다. */
function cellHtml(d, key) {
  if (key === 'ip') {
    const isolated = state.isolated === d.key;
    return `<div class="mac">${esc(cellText(d, 'ip'))}${isolated ? `<span class="status isolated">${t('isolatedBadge')}</span>` : ''}</div>`;
  }
  if (key === 'vendor') {
    const tag = d.book
      ? `<i class="book-tag" title="${d.book_exact ? t('bookExactTip') : t('bookMatchTip')}">${d.book_exact ? '★' : '·'}</i>`
      : '';
    return `<div>${esc(cellText(d, 'vendor'))}${tag}</div>`;
  }
  if (key === 'kind') {
    const text = cellText(d, 'kind');
    if (!text) return '<div class="dim">-</div>';
    const confidence = d.kind_confidence || '';
    const label = confidence === 'confirmed' ? t('kindConfirmed')
      : (confidence === 'estimated' ? t('kindEstimated') : '');
    return '<div class="kind-cell"><span>' + esc(text) + '</span>'
      + (label ? '<i class="kind-confidence ' + confidence + '">' + esc(label) + '</i>' : '')
      + '</div>';
  }
  if (key === 'name') {
    const names = deviceNames(d);
    if (!names.length) return '<div class="dim">-</div>';
    // 한 장비가 역DNS·mDNS·NetBIOS·UPnP 로 이름을 여럿 내놓는 일이 흔하다.
    // 칸에는 첫 개만 두고, 나머지는 +N 으로 세어 보여준 뒤 마우스에 맡긴다.
    const rest = names.slice(1);
    const tip = rest.length ? t('namesTip', { n: rest.length, rest: rest.join(' · ') }) : names[0];
    return `<div title="${esc(tip)}">${esc(names[0])}${rest.length ? `<i class="more" title="${esc(tip)}">+${rest.length}</i>` : ''}</div>`;
  }
  if (key === 'os') {
    // TTL 숫자는 화면에 안 쓴다 — 64면 리눅스라는 걸 우리가 이미 번역했다.
    // 값 자체는 마우스를 올리면 나오고, 내보내기 파일에는 그대로 들어간다.
    if (d.ttl == null) return `<div class="dim">${d.identified ? t('ttlUnread') : '-'}</div>`;
    return `<div title="TTL ${d.ttl}">${esc(tk(d.os))}</div>`;
  }
  if (key === 'ports') {
    const ports = (d.ports || []).map(p => `<span class="port">${portName[p] || p}</span>`).join('');
    return `<div class="ports">${ports}</div>`;
  }
  if (key === 'swport') {
    if (!d.swport) return '<div class="dim">-</div>';
    // 포트 이름 옆에 링크 속도를 붙인다. 기가 스위치인데 100M 으로 붙어 있으면
    // 빨갛게 띄운다 — 케이블 한 쌍이 나가도 링크는 안 끊기고 조용히 떨어진다.
    // 화면에는 Gi1/0/12 로 줄여 적으므로, 전체 이름은 반드시 설명에 남긴다.
    // 스위치 화면에서 찾을 때 기사는 그 긴 이름 그대로를 본다.
    // 반이중은 속도 칸이 멀쩡해 보이는 고장이라, 목록에서 바로 안 보이면
    // 영영 안 잡힌다. 속도 옆에 ½ 를 붙여 둔다.
    const dupHalf = Number(d.swduplex || 0) === 2;
    const hint = [d.swname ? `${d.swname} ${d.swport}` : d.swport,
                  d.swalias, d.swvlan ? `VLAN ${d.swvlan}` : '',
                  dupHalf ? t('halfLinkTip') : '',
                  d.swslow ? t('slowLinkTip') : ''].filter(Boolean).join(' · ');
    const speed = d.swspeed
      ? `<i class="swspeed${d.swslow || dupHalf ? ' slow' : ''}">${formatSpeed(d.swspeed)}`
        + `${dupHalf ? '<b>\u00bd</b>' : ''}</i>` : '';
    // PoE 로 전원을 받고 있으면 몇 W 인지 같이 보여준다. 3 = 급전 중.
    const poe = d.poeStatus === 3
      ? `<i class="poe" title="${esc(t('poeTip'))}">${d.poeWatt ? d.poeWatt.toFixed(1) : '?'}W</i>` : '';
    // 현장에 스위치가 여러 대면 "12번 포트" 만으로는 못 찾아간다. 어느
    // 스위치인지를 같이 적되 **한 줄**로 둔다 — 두 줄이면 줄 높이가 45px 로
    // 붙박여서 밀집 보기가 아예 안 먹는다.
    //
    // 포트 이름도 줄인다. GigabitEthernet1/0/12 는 21글자인데 그중 18글자가
    // 늘 같은 소리다. Gi1/0/12 는 기사들이 원래 그렇게 적는 표기다.
    const where = d.swname ? `<span class="swname">${esc(d.swname)}</span>` : '';
    return `<div class="swcell" title="${esc(hint)}">${where}`
      + `<span class="swport">${esc(shortPort(d.swport))}</span>${speed}${poe}</div>`;
  }
  const text = cellText(d, key);
  return text ? `<div>${esc(text)}</div>` : '<div class="dim">-</div>';
}

function renderHead() {
  const cols = visibleColumns();
  document.documentElement.style.setProperty(
    '--grid-cols', cols.map(c => c.width).join(' '));
  $('#tableHead').innerHTML = cols.map(c =>
    `<span class="sortable" data-sort="${c.key}"${sortKey === c.key ? ` data-dir="${sortDesc ? 'desc' : 'asc'}"` : ''}>${esc(t(c.name))}</span>`).join('');
}

/* 볼 칸 고르기 — 머리글 우클릭 */
function renderColumnMenu() {
  $('#columnMenu').innerHTML = COLUMNS.map(c => {
    const on = shownColumns.includes(c.key);
    return `<button data-col="${c.key}"${c.fixed ? ' disabled' : ''}><i class="tick">${on ? '☑' : '☐'}</i>${esc(t(c.name))}</button>`;
  }).join('') + `<span></span><button data-col="__reset">${t('colReset')}</button>`;
}

$('#tableHead').addEventListener('contextmenu', (event) => {
  event.preventDefault();
  hideMenu();
  renderColumnMenu();
  const menu = $('#columnMenu');
  menu.hidden = false;
  menu.style.left = `${Math.min(event.clientX, window.innerWidth - menu.offsetWidth - 8)}px`;
  menu.style.top = `${Math.min(event.clientY, window.innerHeight - menu.offsetHeight - 8)}px`;
});

$('#columnMenu').addEventListener('click', (event) => {
  // 여기서 멈춘다. 안 그러면 아래의 '바깥 누르면 닫기' 가 이 클릭까지 바깥으로
  // 친다 — 메뉴를 다시 그리면서 눌린 단추가 문서에서 떨어져 나가기 때문이다.
  event.stopPropagation();
  const button = event.target.closest('button');
  if (!button) return;
  const key = button.dataset.col;
  if (key === '__reset') {
    shownColumns = defaultColumns();
  } else {
    const column = COLUMNS.find(c => c.key === key);
    if (!column || column.fixed) return;
    shownColumns = shownColumns.includes(key)
      ? shownColumns.filter(k => k !== key)
      : COLUMNS.filter(c => shownColumns.includes(c.key) || c.key === key).map(c => c.key);
  }
  saveColumns();
  renderColumnMenu();       // 창은 열어둔다 — 여러 개를 이어서 고르기 편하다
  render();
});

function esc(text) { return String(text || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
/* 알림.

   로그 줄(#notice)은 화면 맨 아래 작업 로그 안에 있다. 창이 하나라도 열려
   있으면 그 줄은 창 뒤에 완전히 가려진다 — 그래서 포트를 잠그려다 거절당해도
   화면에는 아무 일도 안 일어난 것처럼 보인다. 사람은 단추가 고장 난 줄 알고
   다시 누른다. 지금은 확인이 안 되면 거절하도록 되어 있어서 거절이 드물지도
   않다. 거절한 이유는 반드시 그 자리에서 보여야 한다.

   그래서 창이 열려 있으면 그 창 안에도 실행 로그를 쌓는다. 한 줄이 아니라
   여러 줄인 이유는, 포트를 풀고 링크가 붙기를 기다리는 것처럼 시간이 걸리는
   일은 진행 과정이 남아 있어야 하기 때문이다.
   ------------------------------------------------------------------- */

const DIALOG_LOG_KEEP = 8;

/* 열려 있는 창 중 '지금 보고 있는' 것.

   DOM 순서로 마지막을 고르면 안 된다 — #snmpDialog 가 #portsDialog 뒤에 있어서,
   포트 관리 창에서 거절당한 이유가 뒤에 숨은 다른 창으로 들어가 버린다.
   화면에서 제일 위에 그려진 것(z-index, 그다음 DOM 순서)을 고른다. */
function openModal() {
  const open = [...document.querySelectorAll('.modal')].filter(m => !m.hidden);
  if (!open.length) return null;
  let top = open[0];
  let best = -Infinity;
  for (const box of open) {
    const z = Number(getComputedStyle(box).zIndex);
    const rank = Number.isFinite(z) ? z : 0;
    if (rank >= best) { best = rank; top = box; }
  }
  return top;
}

/** 열려 있는 창 안에 로그 한 줄. kind: '' | 'ok' | 'warn' | 'bad' */
function say(text, kind = '') {
  const open = openModal();
  for (const box of document.querySelectorAll('.modal-log')) {
    if (!open || !open.contains(box)) box.remove();
  }
  if (!open || !text) return;
  const card = open.querySelector('.modal-card');
  if (!card) return;
  let box = card.querySelector('.modal-log');
  if (!box) {
    box = document.createElement('div');
    box.className = 'modal-log';
    const foot = card.querySelector('footer');
    if (foot) card.insertBefore(box, foot); else card.appendChild(box);
  }
  const line = document.createElement('div');
  line.className = `ml-line${kind ? ' ' + kind : ''}`;
  const now = new Date();
  line.innerHTML = `<i>${String(now.getHours()).padStart(2, '0')}:`
    + `${String(now.getMinutes()).padStart(2, '0')}:`
    + `${String(now.getSeconds()).padStart(2, '0')}</i><span>${esc(text)}</span>`;
  box.appendChild(line);
  while (box.children.length > DIALOG_LOG_KEEP) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

/** 창을 열 때 지난 로그를 지운다. 지난 현장 얘기가 남아 있으면 안 된다. */
function clearSay() {
  for (const box of document.querySelectorAll('.modal-log')) box.remove();
}

function notice(text, bad = false) {
  $('#notice').textContent = text;
  $('#notice').style.color = bad ? '#e7475b' : '';
  // '준비됨' 은 알릴 내용이 아니라 아무 일도 없다는 뜻이다. 로그에 쌓지 않는다.
  if (text && text !== t('ready')) say(text, bad ? 'bad' : '');
}
function applyState(next) { state = { ...state, ...next }; render(); }
function metric(label, value, type = '') { return `<div class="metric ${type}"><i></i><span>${label}</span><strong>${value || 0}</strong></div>`; }
function showProgress() { progressRun += 1; progressVisible = true; }
function hideProgressAfterCompletion() {
  const finishedRun = progressRun;
  window.setTimeout(() => {
    if (finishedRun === progressRun) { progressVisible = false; renderActivity(); }
  }, 5000);
}

/* ── 대역 탭 ──────────────────────────────────────────────────────────
   랜카드를 둘 이상 골라 훑으면 대역이 섞인다. 172 대역 200개와 192 대역
   50개가 한 줄로 이어지면 어느 쪽을 보고 있는지 알 수가 없다. 대역마다
   탭을 만들어 나눈다 — 검색할 때만 전부 한 번에 본다.
   ------------------------------------------------------------------- */

let activeNet = '';

/** IP 의 대역. 앞 세 마디로 가른다 — 현장의 망은 거의 /24 다. */
function netOf(ip) { return String(ip || '').split('.').slice(0, 3).join('.'); }

/** 지금 목록에 있는 대역과 그 안의 IP·장비 수. 나오는 순서는 IP 순. */
function netTally() {
  const tally = new Map();
  for (const group of (state.groups || [])) {
    const net = netOf(group.ip);
    const row = tally.get(net) || { net, ips: 0, devices: 0 };
    row.ips += 1;
    row.devices += (group.devices || []).length;
    tally.set(net, row);
  }
  return [...tally.values()].sort((a, b) => ipKey(a.net + '.0') - ipKey(b.net + '.0'));
}

function renderNetTabs(nets) {
  const box = $('#netTabs');
  if (nets.length < 2) { box.hidden = true; box.innerHTML = ''; return; }
  box.hidden = false;
  const total = nets.reduce((n, row) => n + row.devices, 0);
  const tabs = nets.map(row =>
    `<button class="net-tab${row.net === activeNet ? ' on' : ''}" data-net="${esc(row.net)}">`
    + `${esc(row.net)}.x<i>${row.devices}</i></button>`);
  tabs.push(`<button class="net-tab${activeNet === '*' ? ' on' : ''}" data-net="*">`
    + `${esc(t('netAll'))}<i>${total}</i></button>`);
  box.innerHTML = tabs.join('');
}

$('#netTabs').addEventListener('click', (event) => {
  const tab = event.target.closest('button[data-net]');
  if (!tab) return;
  activeNet = tab.dataset.net;
  render();
});

function render() {
  const s = state.summary || {};
  $('#titleCount').textContent = s.conflictIps ? t('titleConflict', { n: s.conflictIps }) : (s.devices ? t('titleDevices', { n: s.devices }) : t('idle'));
  // 색점 네 개짜리 띠를 없앴다. '발견된 IP 23' 과 '전체 장비 24' 는 사실상 같은
  // 숫자였고, 그 띠가 화면 56px 을 먹으면서 웹 대시보드처럼 보이게 했다.
  // 숫자는 여기 한 줄로 적는다.
  $('#subTitle').textContent = s.devices
    ? [s.conflictIps ? t('countConflict', { n: s.conflictIps }) : '',
       t('countDevices', { n: s.devices }),
       t('countIps', { n: s.ips })].filter(Boolean).join('  ·  ')
    : t('pickIface');
  renderHead();
  const columns = visibleColumns();
  const rows = [];
  let shown = 0;
  // 목록은 IP 로 묶여 있다. 머리글로 정렬하면 묶음 안쪽뿐 아니라 묶음 자체도
  // 같은 기준으로 줄세운다. 단 충돌난 IP 는 늘 위에 둔다 — 그게 이 도구의 목적이다.
  const groupValue = (g) => {
    const first = sortDevices(g.devices || [])[0];
    if (!first) return ipKey(g.ip);
    return sortKey === 'ip' ? ipKey(g.ip) : cellSortValue(first, sortKey);
  };
  // 대역이 둘 이상이면 탭으로 나눈다. 검색 중에는 나누지 않는다 —
  // 찾는 것이 다른 탭에 있으면 못 찾은 것처럼 보이기 때문이다.
  const nets = netTally();
  if (!nets.some(row => row.net === activeNet) && activeNet !== '*') {
    activeNet = nets.length ? nets[0].net : '';
  }
  renderNetTabs(nets);
  const split = nets.length > 1 && !filterText && activeNet && activeNet !== '*';

  const groups = [...(state.groups || [])]
    .filter(g => !split || netOf(g.ip) === activeNet)
    .sort((a, b) => {
    if (!!b.conflict !== !!a.conflict) return b.conflict ? 1 : -1;
    const x = groupValue(a), y = groupValue(b);
    if (x < y) return sortDesc ? 1 : -1;
    if (x > y) return sortDesc ? -1 : 1;
    return ipKey(a.ip) - ipKey(b.ip);
  });
  // 검색어가 있으면 걸러내고, 걸린 IP는 접혀 있어도 펼쳐서 보여준다.
  for (const group of groups) {
    const devices = (group.devices || []).filter(matchesFilter);
    if (filterText && !devices.length) continue;
    const conflict = (group.conflict ? ' conflict' : '')
      + (isSelectedInterfaceIp(group.ip) ? ' own-ip' : '');
    const open = filterText ? true : expandedGroups.has(group.ip);
    shown += devices.length;
    const note = group.conflict ? t('groupNote', { n: group.count }) : '';
    // 묶음 줄은 첫 칸만 장비 줄과 폭을 맞추고, 나머지는 한 칸으로 이어 붙인다
    // (styles.css 의 .group-note). 칸을 하나씩 채우면 글이 좁은 칸에서 접힌다.
    // 장비가 한 대뿐인 IP 는 접을 이유가 없다.
    //
    // 접어 두면 그 줄에는 IP 하나만 남고 나머지 여덟 칸이 통째로 빈다. 제조사도
    // 종류도 스위치 포트도 안 보이고, 보려면 한 번 더 눌러야 한다. 현장 IP 는
    // 대부분 한 대짜리라 화면 전체가 빈 격자가 된다 — 머리글만 허공에 뜬다.
    // 그 줄이 곧 그 장비이니 한 줄로 다 적는다. 우클릭도 바로 먹는다.
    //
    // 충돌난 IP 만 묶음으로 남긴다. 거기는 진짜 둘 이상이라 '어느 쪽을' 고르는
    // 단계가 필요하다.
    if (!group.conflict && devices.length === 1) {
      rows.push(soloRow(group, devices[0], columns));
      continue;
    }
    const filler = '';
    rows.push(`<div class="group-row${conflict}" data-ip="${esc(group.ip)}"><div class="ip-cell"><span class="chevron">${open ? '▾' : '▸'}</span><button class="ip ip-copy" data-copy-ip="${esc(group.ip)}" title="${esc(t('ipCopyTitle'))}">${esc(group.ip)}</button>${group.conflict ? `<span class="conflict-badge">${t('conflictBadge', { n: group.count })}</span>` : ''}</div><span class="group-note">${esc(note)}</span>${filler}</div>`);
    if (open) for (const device of sortDevices(devices)) rows.push(deviceRow(device, columns));
  }
  $('#deviceList').innerHTML = rows.length
    ? rows.join('')
    : `<div class="empty">${filterText ? t('noMatch') : t('emptyList')}</div>`;
  if (filterText) $('#subTitle').textContent = t('searchResult', { q: filterText, n: shown });
  renderActivity();
}

/** GigabitEthernet1/0/12 -> Gi1/0/12 · TenGigabitEthernet1/0/1 -> Te1/0/1
    시스코 표기법 그대로다. 전체 이름은 칸에 마우스를 올리면 나온다. */
function shortPort(name) {
  const text = String(name || '');
  const m = text.match(/^([A-Za-z]+)(.*)$/);
  if (!m) return text;
  const word = m[1].toLowerCase();
  const tail = m[2];
  const map = [['tengigabit', 'Te'], ['twentyfivegig', 'Twe'], ['fortygigabit', 'Fo'],
               ['hundredgig', 'Hu'], ['gigabit', 'Gi'], ['fastethernet', 'Fa'],
               ['ethernet', 'Et'], ['port', '']];
  for (const [long, small] of map) {
    if (word.startsWith(long)) return small + tail;
  }
  return text;
}

function deviceRow(d, columns) {
  const cells = (columns || visibleColumns()).map(c => cellHtml(d, c.key)).join('');
  return `<div class="device-row" data-key="${esc(d.key)}">${cells}</div>`;
}

/** 한 대짜리 IP — IP 와 장비를 한 줄에. 첫 칸만 직접 그리고 나머지는 그대로. */
function soloRow(group, d, columns) {
  const mine = isSelectedInterfaceIp(group.ip) ? ' own-ip' : '';
  const isolated = state.isolated === d.key
    ? `<span class="status isolated">${t('isolatedBadge')}</span>` : '';
  const head = `<div class="ip-cell">`
    + `<button class="ip ip-copy" data-copy-ip="${esc(group.ip)}"`
    + ` title="${esc(t('ipCopyTitle'))}">${esc(group.ip)}</button>`
    + `<span class="mac-sub">${esc(cellText(d, 'ip'))}</span>${isolated}</div>`;
  const rest = (columns || visibleColumns()).slice(1)
    .map(c => cellHtml(d, c.key)).join('');
  return `<div class="solo-row${mine}" data-key="${esc(d.key)}">${head}${rest}</div>`;
}

function renderActivity() {
  const p = state.progress || {};
  const pct = Math.max(0, Math.min(100, Number(p.pct) || 0));
  $('#scanProgress').hidden = !progressVisible;
  $('#scanProgressText').textContent = p.msg ? `${p.msg} · ${pct}%` : `${pct}%`;
  $('#scanProgressBar').style.width = `${pct}%`;
  const logs = state.logs || [];
  $('#logEntries').innerHTML = logs.length
    ? logs.map(log => `<div class="log-entry ${esc(log.level || 'info')}"><span class="log-time">${esc(log.t || '')}</span><span class="log-message">${esc(log.msg || '')}</span></div>`).join('')
    : `<div class="log-empty">${t('logEmpty')}</div>`;
  $('#logEntries').scrollTop = $('#logEntries').scrollHeight;
}

// 일렉트론이 IPC 오류를 "Error invoking remote method 'x': Error: 진짜 내용"
// 으로 감싸서 던진다. 기사분들이 볼 화면이니 껍데기는 벗겨서 보여준다.
function cleanMessage(text) {
  let out = String(text || '');
  out = out.replace(/^Error invoking remote method\s+'[^']*':\s*/, '');
  while (/^(Error|TypeError|RuntimeError):\s*/.test(out)) out = out.replace(/^\w+:\s*/, '');
  return out.trim() || String(text || '');
}

async function call(action, payload) {
  try { return await window.ipfix.request(action, payload); }
  catch (e) { notice(cleanMessage(e.message), true); throw e; }
}

async function loadInterfaces(previousNames = []) {
  try {
    interfaces = await call('interfaces');
    $('#ifaceBtn').disabled = false;
    // 새로고침해도 고른 카드를 지킨다. 이름으로 다시 찾는다 — 목록 순서는
    // 랜선을 꽂았다 뽑으면 바뀐다. 하나도 못 찾으면 그때만 기본값으로 돌아간다.
    const keep = previousNames
      .map(name => interfaces.findIndex(i => i.scapyName === name))
      .filter(n => n >= 0);
    if (keep.length) {
      pickedIfaces = [...new Set(keep)].sort((a, b) => a - b);
    } else {
      pickedIfaces = [bestIface(interfaces)];
    }
    renderIfaceMenu();
    setTarget(); notice(t('engineReady'));
  } catch (error) {
    $('#ifaceBtn').textContent = t('engineFailOpt');
    notice(error?.message || t('engineCheck'), true);
  }
}

/* ── 랜카드 고르기 ────────────────────────────────────────────────────
   서버처럼 랜선 두 개로 대역 두 개를 쓰는 자리가 있다. 그런 곳에서 카드를
   하나씩 두 번 훑으면 목록이 나뉘어 충돌이 안 보인다. 그래서 여러 개를
   골라 한 번에 훑는다 — 대역은 각자의 카드로 나간다.
   ------------------------------------------------------------------- */

let pickedIfaces = [0];

function selectedIfaces() {
  return pickedIfaces.map(n => interfaces[n]).filter(Boolean);
}
function selectedIface() { return selectedIfaces()[0]; }
/* 켜자마자 어느 랜카드를 고를 것인가.

   예전에는 이름에 'ethernet' 이 들어가는 것을 찾고, 못 찾으면 목록의 첫 번째를
   골랐다. 그래서 블루투스 PAN 이 맨 위에 있는 노트북에서는 그게 잡혔다.
   블루투스·가상 어댑터는 대개 169.254.x.x 를 달고 있는데, 그건 주소를 못 받아서
   윈도우가 혼자 지어낸 번호다(APIPA). **거기엔 아무것도 없다.**

   그러니 이름이 아니라 **주소를 보고** 고른다. 진짜 주소를 가진 카드가
   무조건 이긴다. 사람이 화면을 보면 1초 만에 아는 것을, 코드도 그렇게 본다.
   ------------------------------------------------------------------- */
function ifaceScore(card) {
  const rows = card.ipv4 || [];
  const ips = rows.map(r => r.ip).concat(card.ips || []).filter(Boolean);
  const real = ips.filter(ip => !/^(169\.254|127\.|0\.)/.test(ip));
  if (!real.length) return -1;              // 169.254 뿐이면 네트워크가 없는 것이다

  let score = 100;
  // 사설 대역이면 현장 망일 가능성이 높다. 공인 주소는 대개 WAN 쪽이다.
  if (real.some(ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip))) score += 40;
  // 프리픽스를 아는 카드가 낫다 — 대역을 정확히 만들 수 있다.
  if (rows.some(r => r.cidr)) score += 10;

  const name = `${card.desc || ''} ${card.name || ''}`.toLowerCase();
  // 가상·터널·블루투스는 뒤로. 이름은 마지막 판단 근거로만 쓴다.
  if (/virtual|vmware|virtualbox|hyper-v|loopback|tap-|tun|vpn|wintun|bluetooth|pseudo|npcap/.test(name)) score -= 60;
  if (/wi-?fi|wireless|무선/.test(name)) score += 5;
  if (/ethernet|이더넷|realtek|intel\(r\) i2|gigabit/.test(name)) score += 15;
  return score;
}

/** 제일 그럴듯한 랜카드의 자리. 하나도 쓸 만한 게 없으면 0. */
function bestIface(cards) {
  let best = 0, top = -Infinity;
  cards.forEach((card, n) => {
    const score = ifaceScore(card);
    if (score > top) { top = score; best = n; }
  });
  return best;
}

function isSelectedInterfaceIp(ip) {
  return selectedIfaces().some(card => (card.ips || []).includes(ip));
}

/** 단추에 적히는 글. 하나면 그 이름, 여럿이면 몇 개인지. */
function ifaceLabel() {
  const cards = selectedIfaces();
  if (!cards.length) return t('pickIface');
  if (cards.length === 1) {
    const card = cards[0];
    return `${card.desc || card.name}${card.ips?.[0] ? '  —  ' + card.ips[0] : '  ' + t('noIp')}`;
  }
  return t('ifaceMany', { n: cards.length, list: cards.map(c => c.ips?.[0] || (c.desc || c.name)).join(', ') });
}

function renderIfaceMenu() {
  $('#ifaceBtn').textContent = ifaceLabel();
  $('#ifaceMenu').innerHTML = interfaces.map((card, n) => {
    const on = pickedIfaces.includes(n);
    const where = card.ipv4?.[0]?.cidr || card.ips?.[0] || t('noIp');
    // span 은 못 쓴다. 이 메뉴의 .context-menu span 이 구분선(높이 1px 회색 막대)
    // 이라서, 이름을 span 에 담으면 글자가 1px 로 잘려 안 보인다.
    return `<button data-iface="${n}"><i class="tick">${on ? '☑' : '☐'}</i>`
      + `<i class="if-name">${esc(card.desc || card.name)}</i>`
      + `<i class="if-net">${esc(where)}</i></button>`;
  }).join('');
}

$('#ifaceBtn').addEventListener('click', (event) => {
  event.stopPropagation();
  const menu = $('#ifaceMenu');
  if (!menu.hidden) { menu.hidden = true; return; }
  renderIfaceMenu();
  const box = $('#ifaceBtn').getBoundingClientRect();
  menu.hidden = false;
  menu.style.left = `${box.left}px`;
  menu.style.top = `${box.bottom + 4}px`;
  menu.style.minWidth = `${box.width}px`;
});

$('#ifaceMenu').addEventListener('click', (event) => {
  event.stopPropagation();
  const button = event.target.closest('button[data-iface]');
  if (!button) return;
  const n = Number(button.dataset.iface);
  if (pickedIfaces.includes(n)) {
    // 마지막 하나는 못 끈다. 아무것도 안 고른 상태는 쓸모가 없다.
    if (pickedIfaces.length > 1) pickedIfaces = pickedIfaces.filter(x => x !== n);
  } else {
    pickedIfaces = [...pickedIfaces, n].sort((a, b) => a - b);
  }
  renderIfaceMenu();
  setTarget();
});

function setTarget() {
  // 고른 카드마다 자기 대역을 하나씩. 쉼표로 이으면 엔진이 카드별로 나눠 훑는다.
  const parts = [];
  for (const card of selectedIfaces()) {
    const cidr = card.ipv4?.[0]?.cidr;
    const ip = card.ips?.[0];
    if (cidr) parts.push(cidr);
    else if (ip) parts.push(ip.split('.').slice(0, 3).join('.') + '.1-254');
  }
  if (parts.length) $('#target').value = parts.join(', ');
  paintMenubarStat();       // 메뉴바 오른쪽 줄도 같이 바뀐다
}
function targetAddressCount(value) {
  const match = String(value || '').trim().match(/\/(\d{1,2})$/);
  if (!match) return 0;
  const prefix = Number(match[1]);
  if (prefix < 0 || prefix > 32) return 0;
  return Math.pow(2, 32 - prefix);
}

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
  const nextHeight = Math.max(110, Math.min(maxHeight, resizeStartHeight - (event.clientY - resizeStartY)));
  document.documentElement.style.setProperty('--log-height', `${Math.round(nextHeight)}px`);
});
function finishLogResize(event) {
  if (resizeHandle.hasPointerCapture(event.pointerId)) resizeHandle.releasePointerCapture(event.pointerId);
  resizeHandle.classList.remove('dragging');
}
resizeHandle.addEventListener('pointerup', finishLogResize);
resizeHandle.addEventListener('pointercancel', finishLogResize);

$('#refreshInterfaces').addEventListener('click', async () => {
  const button = $('#refreshInterfaces');
  const previousNames = selectedIfaces().map(c => c.scapyName);
  button.disabled = true;
  notice(t('refreshing'));
  try { await loadInterfaces(previousNames); notice(t('refreshed')); }
  finally { button.disabled = false; }
});
/** 스캔 중에는 같은 자리의 단추가 빨간 '중지'로 바뀐다.
    단추를 늘리면 누를 것이 하나 더 생기지만, 스캔 중에 '대역 스캔'을 누를 일은
    어차피 없다. 자리를 지키는 쪽이 눈이 덜 헷갈린다. */
function paintScanButton() {
  const button = $('#scanBtn');
  button.textContent = scanRunning ? t('cancelScan') : t('scan');
  button.classList.toggle('danger', scanRunning);
  button.disabled = false;
  paintMenubarStat();       // 메뉴바 오른쪽 점도 같이 바꾼다
}

$('#scanBtn').addEventListener('click', async () => {
  if (scanRunning) {          // 스캔 중이면 이 단추는 중지 단추다
    $('#scanBtn').disabled = true;
    notice(t('canceling'));
    try {
      const result = await call('cancel');
      if (result.state) applyState(result.state);
    } catch (_) { /* call()에서 상태 메시지를 표시 */ }
    finally { $('#scanBtn').disabled = false; }
    return;
  }
  const cards = selectedIfaces();
  if (!cards.length) return notice(t('pickIfaceWarn'), true);
  const target = $('#target').value.trim();
  const targetCount = targetAddressCount(target);
  if (targetCount > 4096) {
    return notice(t('largeRangeLimit', { target, n: targetCount.toLocaleString() }), true);
  }
  if (targetCount > 1024
      && !window.confirm(t('largeRangeConfirm', { target, n: targetCount.toLocaleString() }))) return;
  scanRunning = true;
  paintScanButton();
  showProgress();
  expandedGroups = new Set();
  sortKey = 'ip'; sortDesc = false;   // 새 스캔은 늘 .1 부터
  notice(t('scanning'));
  try {
    const result = await call('scan', { ifaces: cards, iface: cards[0], target });
    applyState(result);
    notice(result.canceled ? t('scanCanceled') : t('scanDone'));
  } finally {
    scanRunning = false;
    paintScanButton();
    hideProgressAfterCompletion();
    renderActivity();
  }
});

/* ── 창 바깥을 눌러 닫기 ──────────────────────────────────────────────
   글자를 끌어서 선택하다가 손을 창 밖에서 떼면 창이 꺼지던 문제가 있었다.
   브라우저는 누른 곳과 뗀 곳이 다르면 그 둘의 공통 부모에 click 을 준다.
   칸 안에서 눌러 덮개 위에서 뗐다면 공통 부모가 바로 그 덮개다 — 그래서
   덮개를 누른 것으로 잘못 읽혔다.

   그래서 click 을 안 쓰고, 누른 곳과 뗀 곳이 **둘 다** 덮개일 때만 닫는다. */
function closeOnBackdrop(id, close) {
  const dialog = document.getElementById(id);
  if (!dialog) return;
  let pressedOnBackdrop = false;
  dialog.addEventListener('mousedown', (event) => {
    pressedOnBackdrop = event.target === dialog;
  });
  dialog.addEventListener('mouseup', (event) => {
    const outside = pressedOnBackdrop && event.target === dialog;
    pressedOnBackdrop = false;
    if (outside) close();
  });
}

function hideMenu() { $('#contextMenu').hidden = true; menuKey = null; }
function showMenu(event, key) {
  event.preventDefault();
  menuKey = key;
  const menu = $('#contextMenu');
  menu.hidden = false;
  menu.style.left = `${Math.min(event.clientX, window.innerWidth - menu.offsetWidth - 8)}px`;
  menu.style.top = `${Math.min(event.clientY, window.innerHeight - menu.offsetHeight - 8)}px`;
  // 지금 상태에서 할 수 있는 것만 띄운다. 둘 다 늘어놔봐야 헷갈리기만 한다.
  const isolated = state.isolated === key;
  menu.querySelector('[data-menu="isolate"]').hidden = isolated;
  menu.querySelector('[data-menu="release"]').hidden = !isolated;
  // PoE 재시작은 스위치가 실제로 전원을 주고 있는 포트에만 뜬다.
  // 3 = 급전 중. 그 외에는 껐다 켤 전원이 없다.
  menu.querySelector('[data-menu="poe"]').hidden = deviceOf(key)?.poeStatus !== 3;
}

/** key 로 장비 하나를 찾는다. 묶음 안에 들어 있어 한 번 헤집어야 한다. */
function deviceOf(key) {
  for (const group of (state.groups || []))
    for (const device of group.devices) if (device.key === key) return device;
  return null;
}

$('#deviceList').addEventListener('click', (event) => {
  const copiedIp = event.target.closest('[data-copy-ip]')?.dataset.copyIp;
  if (copiedIp) {
    event.stopPropagation();
    navigator.clipboard.writeText(copiedIp)
      .then(() => notice(t('ipCopied', { ip: copiedIp })))
      .catch(() => notice(t('ipCopyFailed'), true));
    return;
  }
  const group = event.target.closest('.group-row');
  if (!group) return;
  const ip = group.dataset.ip;
  if (expandedGroups.has(ip)) expandedGroups.delete(ip); else expandedGroups.add(ip);
  render();
});
$('#deviceList').addEventListener('contextmenu', (event) => {
  // 합친 줄(.solo-row)에도 걸어야 한다. 안 그러면 한 대짜리 IP 는 우클릭이
  // 아예 안 먹어서 검사도 격리도 못 한다.
  const row = event.target.closest('.device-row, .solo-row');
  if (row) showMenu(event, row.dataset.key);
});
document.addEventListener('click', (event) => { if (!event.target.closest('#contextMenu')) hideMenu(); });
document.addEventListener('click', (event) => {
  if (!event.target.closest('#columnMenu') && !event.target.closest('#tableHead')) $('#columnMenu').hidden = true;
  if (!event.target.closest('#ifaceMenu') && !event.target.closest('#ifaceBtn')) $('#ifaceMenu').hidden = true;
});
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { hideMenu(); closeMenubar(); $('#columnMenu').hidden = true; $('#ifaceMenu').hidden = true; } });

$('#contextMenu').addEventListener('click', async (event) => {
  const action = event.target.dataset.menu;
  if (!action || !menuKey) return;
  const key = menuKey;
  hideMenu();
  if (action === 'isolate') { openIsolate(key); return; }
  if (action === 'poe') { openPoe(key); return; }
  try {
    if (action === 'identify') { notice(t('identifying')); applyState(await call('identify', { key })); notice(t('identifyDone')); }
    if (action === 'release') { applyState(await call('release')); notice(t('releaseDone')); }
    if (action === 'book') { openBook(key); }
    if (action === 'copyMac') {
      const device = (state.groups || []).flatMap(group => group.devices).find(d => d.key === key);
      await navigator.clipboard.writeText((device?.mac || '').toUpperCase().replaceAll(':', '-'));
      notice(t('macCopied'));
    }
  } catch (_) { /* call()에서 상태 메시지를 표시 */ }
});



/* ── 장비 사전 ────────────────────────────────────────────────────────
   MAC 앞자리로 제조사와 장비 종류를 알아보는 표. 현장에서 처음 보는 장비를
   한 번 등록해두면 다음 현장부터는 스캔하자마자 이름이 뜬다.
   앞 6자리만 적으면 그 제조사 전체, 12자리를 다 적으면 그 장비 한 대에만.
   ------------------------------------------------------------------- */

function deviceByKey(key) {
  return (state.groups || []).flatMap(group => group.devices).find(d => d.key === key) || null;
}

let isolateKey = null;
function openIsolate(key) {
  const device = deviceByKey(key);
  if (!device) return;
  isolateKey = key;
  $('#isolateTarget').textContent = device.ip + '  ·  '
    + (device.mac || '').toUpperCase().replaceAll(':', '-');
  $('#isolateDialog').hidden = false;
  $('#isolateConfirm').focus();
}
function closeIsolate() { $('#isolateDialog').hidden = true; isolateKey = null; }
$('#isolateClose').addEventListener('click', closeIsolate);
$('#isolateCancel').addEventListener('click', closeIsolate);
closeOnBackdrop('isolateDialog', closeIsolate);
$('#isolateConfirm').addEventListener('click', async () => {
  const key = isolateKey;
  if (!key) return;
  closeIsolate();
  showProgress();
  state.progress = { phase: t('isolatePhase'), pct: 0, msg: t('isolateMsg') };
  renderActivity();
  try { applyState(await call('isolate', { key })); notice(t('isolateDone')); }
  catch (_) { /* call()에서 상태 메시지를 표시 */ }
  finally { hideProgressAfterCompletion(); renderActivity(); }
});

function macDigits(value) {
  return (value || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

let scopeTimer = null;

async function describeScope() {
  const digits = macDigits($('#bookPrefix').value);
  const box = $('#bookScope');
  if (digits.length < 6) {
    box.textContent = t('bookNeedPrefix');
    $('#bookDelete').hidden = true;
    return;
  }
  const pretty = (digits.match(/.{1,2}/g) || []).join('-').toUpperCase();
  const range = digits.length >= 12
    ? t('bookScopeOne', { p: pretty })
    : t('bookScopeAll', { p: pretty });
  box.textContent = range;

  // 사전에 이미 있는 앞자리인지 확인해서 알려준다.
  clearTimeout(scopeTimer);
  scopeTimer = setTimeout(async () => {
    let found = null;
    try { found = (await call('book_lookup', { prefix: digits })).entry; } catch (_) { return; }
    if (macDigits($('#bookPrefix').value) !== digits) return;   // 그새 바뀌었으면 버린다
    $('#bookDelete').hidden = !found;
    if (!found) {
      box.textContent = `${range}\n${t('bookNew')}`;
      return;
    }
    const now = [found.vendor, tk(found.kind)].filter(Boolean).join(' · ') || t('bookEmptyEntry');
    box.textContent = found.shared > 1
      ? `${range}\n${t('bookExists', { now })}\n${t('bookSplit', { n: found.shared - 1 })}`
      : `${range}\n${t('bookExists', { now })} ${t('bookOverwrite')}`;
  }, 180);
}

function openBook(key) {
  const device = deviceByKey(key);
  if (!device) {
    // 도구 메뉴에서 부르면 고른 장비가 없다. 그때는 빈 채로 열어 손으로
    // 앞자리를 적게 한다 — 아직 스캔에 안 잡힌 장비를 미리 등록할 수 있다.
    for (const id of ['#bookPrefix', '#bookVendor', '#bookKind', '#bookNote']) $(id).value = '';
    describeScope();
    $('#bookSearch').value = '';
    bookOpen.clear();
    bookBrowsing = true;
    $('#bookDialog').hidden = false;
    $('#bookPrefix').focus();
    loadBookList();
    return;
  }
  const mac = (device.mac || '').toUpperCase().replaceAll(':', '-');
  // 기본값은 제조사 앞 3바이트. 이 장비만 지정하려면 뒤까지 붙여 쓰면 된다.
  $('#bookPrefix').value = mac.split('-').slice(0, 3).join('-');
  $('#bookVendor').value = device.vendor && device.vendor !== '미상' ? device.vendor : '';
  // 사전에는 엔진이 쓰는 한국어 이름 그대로 넣는다 — 화면에서만 옮겨 보인다.
  $('#bookKind').value = device.kind && device.kind !== '미확인' ? device.kind : '';
  $('#bookNote').value = device.book_note || '';
  describeScope();
  $('#bookSearch').value = '';
  bookOpen.clear();
  bookBrowsing = false;
  $('#bookDialog').hidden = false;
  $('#bookPrefix').focus();
  loadBookList();
}

function closeBook() { $('#bookDialog').hidden = true; }

/* ── 등록된 사전 목록 ───────────────────────────────────────────────
   앞자리는 2,600개가 넘는데 항목은 150개다. 시스코 하나가 앞자리를 1,076개
   물고 있기 때문이다. 앞자리를 한 줄씩 늘어놓으면 아무도 못 읽으므로
   제조사·종류·메모가 같은 것끼리 묶어서 한 줄로 보여준다.
   ------------------------------------------------------------------- */

let bookRows = [];        // [[앞자리, 제조사, 종류, 메모], ...] — 엔진이 준 그대로
// 도구 메뉴에서 열었으면 '목록을 보는 중' 이다. 그때는 하나 고치고 창이
// 닫혀 버리면 다시 열어야 한다 — 여러 개를 이어서 손보는 자리이기 때문이다.
let bookBrowsing = false;

function bookGroups() {
  const byWhat = new Map();
  for (const [prefix, vendor, kind, note] of bookRows) {
    // 12자리를 다 적은 것은 '이 장비 한 대' 를 콕 집은 것이다. 제조사·종류가
    // 같다고 앞자리 뭉치에 섞으면, 사람이 이름 붙여 등록해 둔 카메라 한 대가
    // "Cisco · 앞자리 1076개" 안으로 사라진다. 따로 세운다.
    const exact = String(prefix).length >= 12;
    const key = exact ? `\u0001${prefix}` : `${vendor}\u0000${kind}\u0000${note}`;
    if (!byWhat.has(key)) byWhat.set(key, { vendor, kind, note, exact, prefixes: [] });
    byWhat.get(key).prefixes.push(prefix);
  }
  const out = [...byWhat.values()];
  for (const row of out) row.prefixes.sort();
  // 직접 등록한 것을 맨 위로. 기본 사전 2,600개에 묻히면 안 된다.
  out.sort((a, b) => (b.exact ? 1 : 0) - (a.exact ? 1 : 0)
    || (a.vendor || '').localeCompare(b.vendor || '')
    || (a.kind || '').localeCompare(b.kind || ''));
  return out;
}

function renderBookList() {
  const box = $('#bookList');
  const all = bookGroups();
  const q = $('#bookSearch').value.trim().toLowerCase().replaceAll('-', '').replaceAll(':', '');
  const rows = !q ? all : all.filter(r =>
    (r.vendor || '').toLowerCase().includes(q)
    || (r.kind || '').toLowerCase().includes(q)
    || (r.note || '').toLowerCase().includes(q)
    || r.prefixes.some(p => p.toLowerCase().includes(q)));

  $('#bookCount').textContent = q
    ? t('bookCountFound', { n: rows.length, all: all.length })
    : t('bookCount', { n: all.length, p: bookRows.length });

  if (!rows.length) {
    box.innerHTML = `<div class="bk-empty">${esc(t(all.length ? 'bookNoMatch' : 'bookNoneYet'))}</div>`;
    return;
  }
  // 200줄 넘게 그리면 창이 버벅인다. 검색으로 좁히라고 말한다.
  const shown = rows.slice(0, 200);
  box.innerHTML = shown.map((row, n) => {
    const many = row.prefixes.length > 1;
    const head = many ? t('bookPrefixes', { n: row.prefixes.length })
                      : dashPrefix(row.prefixes[0]);
    // 앞자리가 여럿이면 접어 두고, 눌러서 전부 펼쳐 본다. 예전에는 첫 번째
    // 하나만 칸에 올라와서 나머지 37개를 볼 방법이 아예 없었다.
    const open = bookOpen.has(row.prefixes[0]);
    const chips = !many ? '' :
      `<div class="bk-pres"${open ? '' : ' hidden'}>`
      + row.prefixes.slice(0, BOOK_CHIPS).map(p =>
          `<button class="bk-chip" data-pick="${esc(p)}">${esc(dashPrefix(p))}</button>`).join('')
      + (row.prefixes.length > BOOK_CHIPS
          ? `<i class="bk-more">${esc(t('bookMorePrefixes',
              { n: row.prefixes.length - BOOK_CHIPS }))}</i>` : '')
      + `</div>`;
    return `<div class="bk-item" data-n="${n}" data-prefix="${esc(row.prefixes[0])}">`
      + `<div class="bk-row${many ? ' many' : ''}${open ? ' open' : ''}">`
      + `<span><b>${esc(row.vendor || '-')}</b>`
      + (row.exact ? `<i class="bk-mine">${esc(t('bookMine'))}</i>` : '')
      + `</span>`
      + `<span class="bk-kind">${esc(kindShow(row.kind) || '-')}</span>`
      + `<span class="bk-pre">${many ? '<em></em>' : ''}${esc(head)}</span>`
      + (row.note ? `<span class="bk-note">${esc(row.note)}</span>` : '')
      + `</div>${chips}</div>`;
  }).join('') + (rows.length > shown.length
    ? `<div class="bk-empty">${esc(t('bookCountFound', { n: shown.length, all: rows.length }))}</div>`
    : '');
}

// 한 항목에서 한 번에 그릴 앞자리 수. 시스코 하나가 1,074개라 다 그리면 멈춘다.
const BOOK_CHIPS = 120;
const bookOpen = new Set();     // 펼쳐 둔 항목 (첫 앞자리로 기억한다)

/** 000f7c -> 00-0F-7C */
function dashPrefix(prefix) {
  const hex = String(prefix || '').toUpperCase();
  return (hex.match(/.{1,2}/g) || [hex]).join('-');
}

/** 사전은 엔진이 쓰는 한국어 종류를 담는다. 화면에서만 옮겨 보인다. */
function kindShow(kind) {
  return (typeof KINDS === 'object' && KINDS && KINDS[kind]) ? KINDS[kind] : (kind || '');
}

async function loadBookList() {
  try {
    const result = await window.ipfix.request('book_list', {});
    bookRows = result.rows || [];
  } catch (_) { bookRows = []; }
  renderBookList();
}

$('#bookSearch').addEventListener('input', renderBookList);

/* 목록에서 누를 때.

   앞자리가 여럿인 항목은 눌러도 칸에 올리지 않는다 — 올릴 '하나' 가 없기
   때문이다. 대신 펼쳐서 앞자리를 다 보여주고, 그중 하나를 누르면 그때 올린다.
   ------------------------------------------------------------------- */
$('#bookList').addEventListener('click', (event) => {
  const item = event.target.closest('.bk-item');
  if (!item) return;
  const group = bookGroups().find(g => g.prefixes[0] === item.dataset.prefix);
  if (!group) return;

  const chip = event.target.closest('.bk-chip');
  if (!chip && group.prefixes.length > 1) {
    // 묶인 항목 — 접었다 폈다만 한다
    if (bookOpen.has(group.prefixes[0])) bookOpen.delete(group.prefixes[0]);
    else bookOpen.add(group.prefixes[0]);
    renderBookList();
    return;
  }
  pickBookEntry(group, chip ? chip.dataset.pick : group.prefixes[0]);
  for (const other of document.querySelectorAll('.bk-chip.on, .bk-row.on')) {
    other.classList.remove('on');
  }
  (chip || item.querySelector('.bk-row')).classList.add('on');
});

/** 고른 앞자리를 위 칸으로 올린다. 고치거나 지우기 위해서다. */
function pickBookEntry(group, prefix) {
  $('#bookPrefix').value = dashPrefix(prefix);
  $('#bookVendor').value = group.vendor || '';
  $('#bookKind').value = group.kind || '';
  $('#bookNote').value = group.note || '';
  describeScope();
}

$('#bookPrefix').addEventListener('input', describeScope);
$('#bookClose').addEventListener('click', closeBook);
$('#bookCancel').addEventListener('click', closeBook);
closeOnBackdrop('bookDialog', closeBook);

$('#bookSave').addEventListener('click', async () => {
  const prefix = macDigits($('#bookPrefix').value);
  if (prefix.length < 6) { notice(t('bookPrefixShort')); return; }
  try {
    const result = await call('book_save', {
      prefix,
      vendor: $('#bookVendor').value.trim(),
      kind: $('#bookKind').value.trim(),
      note: $('#bookNote').value.trim()
    });
    if (result.state) applyState(result.state);
    notice(result.created ? t('bookAdded') : t('bookUpdated'));
    if (bookBrowsing) { bookRows = result.rows || bookRows; renderBookList(); }
    else closeBook();
  } catch (_) { /* call()에서 메시지 표시 */ }
});

$('#bookDelete').addEventListener('click', async () => {
  const prefix = macDigits($('#bookPrefix').value);
  if (prefix.length < 6) { closeBook(); return; }
  try {
    const result = await call('book_remove', { prefix });
    if (result.state) applyState(result.state);
    notice(t('bookRemoved'));
    if (bookBrowsing) {
      bookRows = result.rows || bookRows;
      for (const id of ['#bookPrefix', '#bookVendor', '#bookKind', '#bookNote']) $(id).value = '';
      describeScope();
      renderBookList();
    } else closeBook();
  } catch (_) { /* call()에서 메시지 표시 */ }
});



/* ── 목록 다루기 ──────────────────────────────────────────────────────
   장비가 서른 대만 넘어가도 눈으로 훑기 어렵다. 검색으로 걸러내고,
   머리글을 눌러 정렬한다. 걸러낸 결과 그대로 파일로도 내보낸다.
   ------------------------------------------------------------------- */

function deviceText(d) {
  // 지금 안 보이는 칸의 값도 뒤진다. 숨겼다고 못 찾으면 곤란하다.
  return [d.ip, d.mac, d.host, d.nbname, d.mdns, d.ssdp, d.vendor, d.kind,
          d.model, d.serial, d.swport, d.os, (d.ports || []).join(' ')]
    .filter(Boolean).join(' ').toLowerCase();
}

function matchesFilter(d) {
  if (!filterText) return true;
  return deviceText(d).includes(filterText);
}

function ipKey(ip) {
  return (ip || '').split('.').reduce((acc, part) => acc * 256 + (Number(part) || 0), 0);
}

function sortDevices(list) {
  const sorted = [...list].sort((a, b) => {
    const x = cellSortValue(a, sortKey), y = cellSortValue(b, sortKey);
    if (x < y) return -1;
    if (x > y) return 1;
    return ipKey(a.ip) - ipKey(b.ip);
  });
  return sortDesc ? sorted.reverse() : sorted;
}

$('#filterInput').addEventListener('input', (event) => {
  filterText = event.target.value.trim().toLowerCase();
  render();
});

$('#tableHead').addEventListener('click', (event) => {
  const head = event.target.closest('[data-sort]');
  if (!head) return;
  const key = head.dataset.sort;
  if (sortKey === key) sortDesc = !sortDesc;
  else { sortKey = key; sortDesc = false; }
  render();
});

/* ── 준공 · 점검 리포트 ─────────────────────────────────────────────
   기사들이 스캔하고 나서 손으로 엑셀에 치던 것 — 장비 목록, 몇 번 포트에
   뭐가 물렸는지, 속도, PoE 전력 — 을 그대로 한 부로 뽑는다. 스위치 IP 는
   목록에서 저절로 모은다. 사람이 다시 입력하게 만들면 한 대를 빠뜨리고,
   빠뜨린 스위치는 문서에서 조용히 사라진다. 그건 리포트가 아니다.
   ------------------------------------------------------------------- */

/** 지금 목록에 붙어 있는 스위치 IP 를 모은다. */
function switchesInList() {
  const found = new Set();
  for (const group of (state.groups || [])) {
    for (const dev of (group.devices || [])) {
      if (dev.swhost) found.add(dev.swhost);
    }
  }
  return [...found].sort();
}

function renderReportScope() {
  const typed = $('#reportSwitches').value.split(',').map(x => x.trim()).filter(Boolean);
  const found = typed.length ? typed : switchesInList();
  const scope = $('#reportScope');
  scope.classList.toggle('modal-caution', !found.length);
  scope.textContent = found.length
    ? t('reportScopeAuto', { n: found.length, list: found.join(', ') })
    : t('reportScopeNone');
}

$('#reportBtn').addEventListener('click', () => {
  if (!$('#reportSite').value.trim()) $('#reportSite').value = $('#target').value.trim();
  // 포트 관리 창에서 쓰던 문자열을 그대로 가져다 준다. 같은 스위치, 같은 값이다.
  if (!$('#reportCommunity').value.trim()) {
    $('#reportCommunity').value = ($('#snmpCommunity').value || '').trim();
  }
  renderReportScope();
  clearSay();
  $('#reportDialog').hidden = false;
  $('#reportSite').focus();
});
$('#reportSwitches').addEventListener('input', renderReportScope);
const closeReport = () => { $('#reportDialog').hidden = true; };
$('#reportClose').addEventListener('click', closeReport);
$('#reportCancel').addEventListener('click', closeReport);
closeOnBackdrop('reportDialog', closeReport);

$('#reportGo').addEventListener('click', async () => {
  const site = $('#reportSite').value.trim();
  const picked = await window.ipfix.saveDialog({
    title: t('reportDlg'),
    defaultPath: `${t('reportFile')}_${site ? site.replace(/[\\/:*?"<>|]/g, '') + '_' : ''}`
      + `${new Date().toISOString().slice(0, 10)}.xlsx`,
    filters: [{ name: t('filterXlsx'), extensions: ['xlsx'] }]
  });
  if (!picked) return;
  const button = $('#reportGo');
  button.disabled = true;
  notice(t('reportSaving'));
  try {
    const result = await call('report_export', {
      path: picked, site,
      author: $('#reportAuthor').value.trim(),
      note: $('#reportNote').value.trim(),
      community: $('#reportCommunity').value.trim() || 'public',
      switches: $('#reportSwitches').value.split(',').map(x => x.trim()).filter(Boolean),
    });
    closeReport();
    notice(result.slow
      ? t('reportDoneSlow', { sw: result.switches, n: result.devices, slow: result.slow })
      : t('reportDone', { sw: result.switches, n: result.devices }));
    // 못 읽은 스위치가 있으면 조용히 넘어가지 않는다. 문서에도 적혀 있지만,
    // 저장한 그 자리에서 한 번 더 말해 줘야 사람이 다시 뽑을 생각을 한다.
    if (result.missed) setTimeout(() => notice(t('reportMissed', { n: result.missed }), true), 2500);
  } catch (_) { /* call()에서 메시지 표시 */ }
  finally { button.disabled = false; }
});

/* ── 내보내기 ─────────────────────────────────────────────────────── */

$('#exportBtn').addEventListener('click', async () => {
  const picked = await window.ipfix.saveDialog({
    title: t('saveDlgTitle'),
    defaultPath: `${t('reportFileName')}_${new Date().toISOString().slice(0, 10)}.csv`,
    filters: [
      { name: t('filterCsv'), extensions: ['csv'] },
      { name: t('filterHtml'), extensions: ['html'] },
      { name: 'JSON', extensions: ['json'] },
      { name: 'XML', extensions: ['xml'] }
    ]
  });
  if (!picked) return;
  const format = (picked.split('.').pop() || 'json').toLowerCase();
  try {
    const result = await call('export', {
      path: picked, format, site: $('#target').value.trim(), columns: shownColumns
    });
    notice(format === 'html'
      ? t('exportedHtml', { n: result.count })
      : t('exported', { n: result.count }));
  } catch (_) { /* call()에서 메시지 표시 */ }
});

function compareRows(title, items, render) {
  if (!items.length) return `<div class="compare-group"><h4>${title} <b>0</b></h4><p class="compare-none">${t('compareNone')}</p></div>`;
  return `<div class="compare-group"><h4>${title} <b>${items.length}</b></h4>`
    + items.map(render).join('') + '</div>';
}

function showCompare(result) {
  const mac = (m) => (m || '').toUpperCase().match(/.{1,2}/g)?.join('-') || '';
  $('#compareWhen').textContent =
    t('compareWhen', { when: result.savedAt, name: result.name ? ` · ${result.name}` : '', n: result.baseCount });
  $('#compareBody').innerHTML =
      compareRows(t('compareAdded'), result.added,
        (d) => `<div class="compare-row is-add"><span class="ip">${esc(d.ip)}</span><span>${esc(mac(d.mac))}</span><span>${esc(d.vendor || '')} ${esc(tk(d.kind))}</span></div>`)
    + compareRows(t('compareGone'), result.gone,
        (d) => `<div class="compare-row is-gone"><span class="ip">${esc(d.ip)}</span><span>${esc(mac(d.mac))}</span><span>${esc(d.vendor || '')} ${esc(tk(d.kind))}</span></div>`)
    + compareRows(t('compareMoved'), result.moved,
        (d) => `<div class="compare-row is-move"><span class="ip">${esc(d.from)} → ${esc(d.to)}</span><span>${esc(mac(d.mac))}</span><span></span></div>`);
  $('#compareDialog').hidden = false;
}

$('#compareClose').addEventListener('click', () => { $('#compareDialog').hidden = true; });
$('#compareOk').addEventListener('click', () => { $('#compareDialog').hidden = true; });
closeOnBackdrop('compareDialog', () => { $('#compareDialog').hidden = true; });

async function openHistory() {
  let rows;
  try { rows = await call('history_list'); } catch (_) { return; }
  $('#historyBody').innerHTML = rows.length
    ? rows.map(row => `<div class="history-row"><div><strong>${esc(row.savedAt)}</strong><span>${esc(row.target || '-')} · ${esc(row.iface || '-')} · ${row.count}</span></div><button class="ghost-btn" data-history-id="${esc(row.id)}">${t('historyCompare')}</button></div>`).join('')
    : `<p class="compare-none">${t('historyEmpty')}</p>`;
  $('#historyDialog').hidden = false;
}

$('#historyBtn').addEventListener('click', openHistory);
$('#historyBody').addEventListener('click', async (event) => {
  const id = event.target.closest('[data-history-id]')?.dataset.historyId;
  if (!id) return;
  try {
    const result = await call('history_compare', { id });
    $('#historyDialog').hidden = true;
    showCompare(result);
  } catch (_) { /* call()에서 메시지 표시 */ }
});
const closeHistory = () => { $('#historyDialog').hidden = true; };
$('#historyClose').addEventListener('click', closeHistory);
$('#historyOk').addEventListener('click', closeHistory);
closeOnBackdrop('historyDialog', closeHistory);

/* ── 언어 ─────────────────────────────────────────────────────────────
   화면 문구는 i18n.js 가, 로그 문구는 엔진이 만든다. 그래서 바꿀 때
   양쪽에 다 알려야 한다. 이미 쌓인 로그는 그때 언어 그대로 남는다 —
   지나간 기록을 나중에 고쳐 쓰면 그게 더 헷갈린다.
   ------------------------------------------------------------------- */

/* ── 메뉴바 · 밀집 보기 ─────────────────────────────────────────────
   메뉴는 아래 작업줄 단추를 대신하지 않는다. 자주 쓰는 것은 단추로 그대로
   두고, 메뉴는 "그게 어디 있더라" 를 없애고 단축키를 붙이는 자리다.
   그래서 여기 있는 항목은 전부 기존 단추를 그대로 누른다 — 같은 동작이
   두 벌 있으면 한쪽만 고치고 다른 쪽을 잊는다.
   ------------------------------------------------------------------- */

const DENSE_STORE = 'ipscan.dense';
// 기본이 밀집이다. 한 화면에 두 배 가까이 들어간다. 끈 사람만 기억한다.
let dense = true;
try { dense = localStorage.getItem(DENSE_STORE) !== '0'; } catch (_) { dense = true; }

function applyDense() {
  document.body.classList.toggle('dense', dense);
  try { localStorage.setItem(DENSE_STORE, dense ? '1' : '0'); } catch (_) { /* 이번 판만 적용 */ }
}

function setDense(on) {
  dense = !!on;
  applyDense();
  notice(t(dense ? 'mbDenseOn' : 'mbDenseOff'));
}

function setLang(picked) {
  if (picked === lang) return;
  lang = picked;
  try { localStorage.setItem(LANG_STORE, lang); } catch (_) { /* 못 저장해도 이번엔 적용된다 */ }
  applyStaticText();
  if (interfaces.length) renderIfaceMenu();     // 단추 글도 언어를 탄다
  paintScanButton();
  renderColumnMenu();
  paintMenubarStat();
  render();
  call('set_lang', { lang }).catch(() => { /* 엔진이 못 받아도 화면은 바뀐다 */ });
}

/** 메뉴 한 벌. [글, 단축키, 누르면 할 일, 체크 여부] */
function menuItems(which) {
  const hit = (id) => () => $(id).click();
  if (which === 'file') return [
    [t('mbExport'), 'Ctrl+E', hit('#exportBtn')],
    [t('mbReport'), 'Ctrl+R', hit('#reportBtn')],
    ['-'],
    [t('mbQuit'), 'Alt+F4', () => window.close()],
  ];
  if (which === 'view') return [
    // 칸 고르기는 넣지 않는다. 머리글 우클릭이 원래 자리고, 거기 있는 것을
    // 메뉴에 한 번 더 두면 목록만 길어진다.
    [t('mbDense'), 'Ctrl+D', () => setDense(!dense), dense],
    ['-'],
    [t('mbLangKo'), '', () => setLang('ko'), lang === 'ko'],
    [t('mbLangEn'), '', () => setLang('en'), lang === 'en'],
  ];
  if (which === 'scan') return [
    [scanRunning ? t('mbScanStop') : t('mbScanRun'), 'Ctrl+Enter', hit('#scanBtn')],
    ['-'],
    [t('mbHistory'), 'Ctrl+H', hit('#historyBtn')],
    [t('mbFree'), 'Ctrl+F', hit('#freeBtn')],
  ];
  if (which === 'switch') return [
    [t('mbPorts'), 'Ctrl+P', hit('#snmpBtn')],
  ];
  return [
    [t('mbBook'), '', () => openBook('')],
    ['-'],
    [t('mbManual'), 'F1', openManual],
    [t('mbAbout'), '', () => notice(t('mbAboutText', { app: 'Quiet Scanner', ver: '3.0' }))],
  ];
}

/** 사용설명서를 기본 브라우저로 연다.
    못 열면 반드시 말한다 — 눌렀는데 아무 일도 안 일어나면 사람은
    프로그램이 고장 난 줄 알고 계속 누른다. */
async function openManual() {
  try {
    const got = await window.ipfix.openManual(lang);
    if (!got || !got.ok) notice(t('manualFail', { why: (got && got.why) || '' }), 'error');
  } catch (err) {
    notice(t('manualFail', { why: String(err && err.message || err) }), 'error');
  }
}

function closeMenubar() {
  mbPressed = '';
  $('#mbPop').hidden = true;
  for (const button of document.querySelectorAll('.menubar button')) button.classList.remove('on');
}

function openMenubar(button) {
  const items = menuItems(button.dataset.menu);
  const pop = $('#mbPop');
  pop.innerHTML = items.map(([text, key, , on], n) => text === '-'
    ? '<hr>'
    : `<button data-n="${n}" class="${on ? 'tick' : ''}">`
      + `<b>${esc(text)}</b><i>${esc(key || '')}</i></button>`).join('');
  pop.hidden = false;
  pop.dataset.menu = button.dataset.menu;
  const box = button.getBoundingClientRect();
  // 창 오른쪽 끝을 넘어가면 왼쪽으로 붙인다
  const left = Math.min(box.left, window.innerWidth - pop.offsetWidth - 8);
  pop.style.left = `${Math.max(8, left)}px`;
  pop.style.top = `${box.bottom + 3}px`;
  for (const other of document.querySelectorAll('.menubar button')) {
    other.classList.toggle('on', other === button);
  }
}

/* 눌러서 연 메뉴의 이름.

   '열려 있으면 닫는다' 를 그냥 쓰면 안 된다. 메뉴가 열려 있을 때 옆 항목으로
   마우스를 가져가면 그것이 열리는데(아래 mouseover), 거기서 누르는 순간
   '이미 열려 있으니 닫자' 가 되어 방금 연 메뉴가 손가락을 떼기도 전에
   사라진다. 그래서 '눌러서 연 것' 만 다시 눌러 닫는다. */
let mbPressed = '';

document.querySelector('.menubar').addEventListener('mousedown', (event) => {
  const button = event.target.closest('button[data-menu]');
  if (!button) return;
  event.preventDefault();          // 글자가 드래그로 선택되지 않게
  event.stopPropagation();
  if (mbPressed === button.dataset.menu) { closeMenubar(); return; }
  openMenubar(button);
  mbPressed = button.dataset.menu;
});

// 하나가 열려 있으면 옆으로 지나가기만 해도 바뀐다 — 보통 메뉴바가 그렇다
document.querySelector('.menubar').addEventListener('mouseover', (event) => {
  const button = event.target.closest('button[data-menu]');
  if (!button || $('#mbPop').hidden || button.classList.contains('on')) return;
  openMenubar(button);
  mbPressed = '';                  // 지나가서 열린 것은 눌러서 연 것이 아니다
});

// 바깥을 누르면 닫는다
document.addEventListener('mousedown', (event) => {
  if (!event.target.closest('#mbPop') && !event.target.closest('.menubar')) closeMenubar();
});

$('#mbPop').addEventListener('click', (event) => {
  const button = event.target.closest('button');
  if (!button) return;
  event.stopPropagation();
  const items = menuItems($('#mbPop').dataset.menu);
  const item = items[Number(button.dataset.n)];
  closeMenubar();
  if (item && typeof item[2] === 'function') item[2]();
});

/** 오른쪽 끝 한 줄 — 지금 무엇으로 보고 있는지가 늘 눈에 있어야 한다. */
function paintMenubarStat() {
  const box = $('#mbStat');
  if (!box) return;
  const cards = (typeof selectedIfaces === 'function' ? selectedIfaces() : []) || [];
  if (!cards.length) {
    box.className = 'mb-stat';
    box.innerHTML = `<i></i>${esc(t('mbStatIdle'))}`;
    return;
  }
  const nets = ($('#target').value || '').split(',').map(x => x.trim()).filter(Boolean).length;
  const names = cards.map(shortIfaceName).join(' + ');
  box.className = `mb-stat ${scanRunning ? 'busy' : 'live'}`;
  box.innerHTML = `<i></i>${esc(t('mbStatNets', { if: names, n: nets || 1 }))}`;
}

/** 랜카드 이름을 짧게. 제조사 수식어는 랙 앞에서 아무 도움이 안 된다. */
function shortIfaceName(card) {
  const text = String((card && (card.desc || card.name)) || '');
  const short = text
    .replace(/\(R\)|\(TM\)|Intel|Realtek|Ethernet|Connection|Network|Adapter|Gigabit|PCIe|Family|Controller|\(\d+\)/gi, '')
    .replace(/\s+/g, ' ').trim();
  return short || text.slice(0, 18);
}

/* F1 = 사용설명서. 어느 창에 있든, 글자를 치는 중이라도 먹는다 —
   막혀서 도움을 찾는 순간에 조건을 붙이면 안 된다. */
document.addEventListener('keydown', (event) => {
  if (event.key === 'F1') { event.preventDefault(); closeMenubar(); openManual(); }
});

/* 단축키. 글자 칸에 타이핑 중일 때는 가로채지 않는다. */
document.addEventListener('keydown', (event) => {
  if (!event.ctrlKey || event.altKey || event.metaKey) return;
  const key = event.key.toLowerCase();
  // Ctrl+Enter 는 글자 칸 안에서도 먹어야 한다 — 대역을 치고 바로 돌린다.
  if (key === 'enter') { event.preventDefault(); closeMenubar(); return $('#scanBtn').click(); }
  if (/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '')) return;
  const shortcuts = {
    d: () => setDense(!dense),
    e: () => $('#exportBtn').click(),
    r: () => $('#reportBtn').click(),
    h: () => $('#historyBtn').click(),
    f: () => $('#freeBtn').click(),
    p: () => $('#snmpBtn').click(),
  };
  const run = shortcuts[key];
  if (run) { event.preventDefault(); closeMenubar(); run(); }
});

applyDense();

applyStaticText();
$('#target').addEventListener('input', paintMenubarStat);
paintMenubarStat();
window.ipfix.onState(applyState);
call('set_lang', { lang }).catch(() => {});
// 장비 종류 이름표를 엔진에서 받아온다. 못 받으면 한국어 그대로 보인다.
call('kinds').then((map) => { Object.assign(KINDS, map || {}); render(); }).catch(() => {});
loadInterfaces();
render();


/* ── 빈 IP ──────────────────────────────────────────────────────────
   훑은 대역에서 아무도 답하지 않은 자리. 연속된 자리는 묶어서 보여준다.
   무엇을 어디에 넣을지는 사람이 정한다 — 도구는 빈자리만 알려준다.
   ------------------------------------------------------------------- */

let freeList = [];

$('#freeBtn').addEventListener('click', async () => {
  let info;
  try {
    info = await window.ipfix.request('free_ips', {});
  } catch (error) {
    // 스캔이 끝까지 안 갔으면 엔진이 목록 자체를 안 준다. 그 이유를 아래 로그
    // 한 줄로 흘리면 아무도 안 읽는다 — 창을 열어 거기 크게 적는다. 빈 IP 는
    // 그대로 배정에 쓰이는 목록이라, 못 믿을 이유를 반드시 읽혀야 한다.
    freeList = [];
    $('#freeWhen').textContent = '';
    $('#freeBody').innerHTML = `<p class="free-refuse">${esc(cleanMessage(error.message))}</p>`;
    $('#freeDialog').hidden = false;
    notice(cleanMessage(error.message), true);
    return;
  }
  freeList = info.free || [];
  $('#freeWhen').textContent = info.scanned
    ? t('freeSummary', { scanned: info.scanned, used: info.used, free: freeList.length })
    : t('freeScanFirst');
  // 묶어서 보여주면 짧지만, 현장에서는 "몇 번을 줄까" 를 눈으로 짚는다.
  // 그래서 한 줄에 하나씩 그대로 늘어놓는다.
  $('#freeBody').innerHTML = freeList.length
    ? freeList.map(ip => `<div class="free-ip">${esc(ip)}</div>`).join('')
    : `<p class="compare-none">${info.scanned ? t('freeNone') : t('freeNoScan')}</p>`;
  $('#freeDialog').hidden = false;
});
$('#freeCopy').addEventListener('click', async () => {
  if (!freeList.length) return notice(t('freeNothingCopy'), true);
  await navigator.clipboard.writeText(freeList.join('\n'));
  notice(t('freeCopied', { n: freeList.length }));
});
$('#freeExport').addEventListener('click', async () => {
  if (!freeList.length) return notice(t('freeNothingCopy'), true);
  const picked = await window.ipfix.saveDialog({
    title: t('freeExportBtn'),
    defaultPath: `${t('candidateFileName')}_${new Date().toISOString().slice(0, 10)}.csv`,
    filters: [{ name: t('filterCsv'), extensions: ['csv'] }]
  });
  if (!picked) return;
  try {
    const result = await call('free_export', { path: picked });
    notice(t('freeExported', { n: result.count }));
  } catch (_) { /* call()에서 메시지 표시 */ }
});
const closeFree = () => { $('#freeDialog').hidden = true; };
$('#freeClose').addEventListener('click', closeFree);
$('#freeOk').addEventListener('click', closeFree);
closeOnBackdrop('freeDialog', closeFree);

/* ── 스위치 포트 찾기 (SNMP) ─────────────────────────────────────────
   "이 카메라가 랙 어느 포트에 물렸나" 를 스위치에 직접 물어본다.
   읽기 전용이다. 스위치 설정은 건드리지 않는다.
   ------------------------------------------------------------------- */

$('#snmpBtn').addEventListener('click', () => {
  if (!$('#snmpHost').value) {
    // 대개 스위치는 대역의 첫 주소다. 아니면 사람이 고쳐 넣는다.
    const ip = selectedIface()?.ips?.[0];
    if (ip) $('#snmpHost').value = ip.split('.').slice(0, 3).join('.') + '.1';
  }
  if (!$('#snmpCommunity').value) $('#snmpCommunity').value = 'public';
  $('#snmpDialog').hidden = false;
  $('#snmpHost').focus();
});
const closeSnmp = () => { $('#snmpDialog').hidden = true; };
$('#snmpClose').addEventListener('click', closeSnmp);
$('#snmpCancel').addEventListener('click', closeSnmp);
closeOnBackdrop('snmpDialog', closeSnmp);
$('#snmpRun').addEventListener('click', async () => {
  const switchIp = $('#snmpHost').value.trim();
  if (!switchIp) return notice(t('snmpNeedHost'), true);
  $('#snmpRun').disabled = true;
  notice(t('snmpReading'));
  try {
    const result = await call('snmp_ports', { switch: switchIp, community: $('#snmpCommunity').value.trim() });
    applyState(result.state);
    closeSnmp();
    const slow = result.slow || [];
    notice(slow.length
      ? t('snmpSlowFound', { n: slow.length, list: slow.slice(0, 3).map(r => r.ip).join(', ') })
      : (result.matched
        ? t('snmpMatched', { sw: result.switch, read: result.read, n: result.matched })
        : t('snmpNoMatch', { sw: result.switch, read: result.read })),
      slow.length > 0 || !result.matched);
  } catch (_) { /* call()에서 메시지 표시 */ }
  finally { $('#snmpRun').disabled = false; }
});

/* ── PoE 전원 재시작 ──────────────────────────────────────────────────
   먹통 된 카메라의 랜선을 뽑았다 꽂는 일을, 스위치를 시켜서 한다.
   쓰는 동작이라 커뮤니티가 따로 필요하고(대개 읽기용과 다르다),
   되돌릴 수 없는 일이므로 무엇을 끄는지 확인 창에서 보여준다.
   ------------------------------------------------------------------- */

let poeKey = null;

function openPoe(key) {
  const device = deviceOf(key);
  if (!device) return;
  if (device.poeStatus !== 3) return notice(t('poeNoPort'), true);
  poeKey = key;
  $('#poeTarget').value = `${device.ip}  ·  ${device.swport || ''}`
    + (device.poeWatt ? `  ·  ${device.poeWatt.toFixed(1)}W` : '');
  // 스위치 IP 는 방금 포트 조회에 쓴 것을 그대로 가져온다.
  if (!$('#poeHost').value) $('#poeHost').value = $('#snmpHost').value || '';
  $('#poeDialog').hidden = false;
  $('#poeCommunity').focus();
}

const closePoe = () => { $('#poeDialog').hidden = true; poeKey = null; };
$('#poeClose').addEventListener('click', closePoe);
$('#poeCancel').addEventListener('click', closePoe);
closeOnBackdrop('poeDialog', closePoe);

$('#poeRun').addEventListener('click', async () => {
  const key = poeKey;
  if (!key) return;
  const community = $('#poeCommunity').value.trim();
  if (!community) return notice(t('poeNeedComm'), true);
  const host = $('#poeHost').value.trim();
  if (!host) return notice(t('snmpNeedHost'), true);
  const device = deviceOf(key);
  $('#poeRun').disabled = true;
  notice(t('poeRunning', { ip: device?.ip || '' }));
  try {
    const result = await call('poe_restart', {
      key, switch: host, community,
      wait: Number($('#poeWait').value) || 6,
    });
    applyState(result.state);
    closePoe();
    notice(t('poeDone', { ip: device?.ip || '' }));
  } catch (_) { /* call()에서 메시지 표시 */ }
  finally { $('#poeRun').disabled = false; }
});

/* ── 스위치 포트 관리 ─────────────────────────────────────────────────
   목록에는 장비가 붙은 포트만 나온다. 빈 포트는 안 나온다 — 그런데 준공 때
   잠가야 하는 것이 바로 그 빈 포트다. 그래서 스위치에 직접 물어 전체 포트를
   가져온다.

   못 잠그는 포트(내 PC·업링크·스위치 자신)는 백엔드가 이유까지 붙여 보내고,
   여기서는 단추를 아예 못 누르게 한다. 눌렀다 거절당하는 것보다 낫다.
   ------------------------------------------------------------------- */

let portsData = { switch: '', rows: [], fdbOk: false };
let pickedPort = null;
let lockFreeArmed = false;
let lockFreeTimer = null;

function portStateLabel(row) {
  if (row.admin === 2) return { text: t('portsStateLock'), cls: 'locked' };
  if (row.oper === 1) return { text: t('portsStateUp'), cls: 'up' };
  return { text: t('portsStateDown'), cls: 'down' };
}

/** 포트 이름에서 앞판에 적힌 번호를 뽑는다. GigabitEthernet1/0/12 -> 12
    엔진(port_number)과 규칙이 같아야 한다. 다르면 엑셀 리포트에 찍힌 번호와
    화면에 뜬 번호가 어긋나고, 기사는 그 번호를 세면서 랙 앞에 서 있다. */
function portNumber(row) {
  const runs = String(row.name || '').match(/\d+/g);
  if (runs && runs.length) return Number(runs[runs.length - 1]);
  return Number(row.index) || 0;
}

/** 업링크·광포트는 앞판에서 따로 떨어져 있다. 속도나 이름으로 가린다. */
function isUplink(row) {
  return (row.speed || 0) >= 10000 || /^(te|twe|fo|fi|hu|xg|sfp)/i.test(String(row.name || ''));
}

/** 링크가 붙어 있는데 반이중으로 앉았는가. 2 = 반이중, 3 = 전이중.
    0 은 스위치가 이 값을 아예 안 내준 것이라 아무 말도 하지 않는다 —
    0 을 '전이중' 으로 읽으면 확인하지도 않은 것을 정상이라고 칠하게 된다. */
function isHalfDuplex(row) {
  return Number(row.duplex || 0) === 2 && row.oper === 1;
}

function portClass(row) {
  if (row.admin === 2) return 'locked';
  if (row.oper !== 1) return 'idle';
  // 느리다고 볼 근거가 셋이다. wasSpeed 는 '이 포트가 전에는 더 빨랐다' 는
  // 기록이라 훨씬 확실하다. slowLink 는 '옆 포트들보다 느리다' 는 짐작이다.
  // 반이중은 짐작이 아니라 스위치가 직접 한 말이라 제일 확실하다 — 그런데
  // 속도 칸은 멀쩡해 보이기 때문에 여기서 칠해주지 않으면 아무도 못 찾는다.
  return (isHalfDuplex(row) || row.wasSpeed || row.slowLink) ? 'slow' : 'live';
}

/** 스위치 앞판. 실물처럼 홀수는 위, 짝수는 아래로 놓는다. */
function renderFace() {
  const rows = portsData.rows || [];
  // 기준은 최고 속도가 아니라 '제일 흔한 속도'. 10G 업링크 하나 때문에
  // 멀쩡한 1G 포트가 전부 느린 것으로 잡히면 안 된다.
  // 링크가 붙어 있는 포트만 센다. 안 꽂힌 포트에 명목 속도를 적어 내는
  // 스위치가 있어서, 빈 포트 스무 개가 '보통 1G' 라고 투표해 버린다.
  const live = rows.filter(r => r.oper === 1 && r.speed > 0);
  const tally = new Map();
  for (const row of live) tally.set(row.speed, (tally.get(row.speed) || 0) + 1);
  let usual = 0;
  for (const [speed, n] of tally) {
    const best = tally.get(usual) || 0;
    // 동수면 느린 쪽을 보통으로 본다. CCTV 현장은 100M 카메라가 절반인 곳이
    // 흔해서, 빠른 쪽으로 기울이면 멀쩡한 카메라 열 대가 전부 빨개진다.
    if (n > best || (n === best && speed < usual)) usual = speed;
  }
  // 느린 쪽이 소수일 때만 '이상하다' 고 할 수 있다. 절반이 100M 인 스위치에서
  // 100M 은 고장이 아니라 그냥 이 현장의 모습이다.
  const slowSide = live.filter(r => usual >= 1000 && r.speed <= usual / 4).length;
  const minority = live.length >= 4 && slowSide * 3 <= live.length;
  for (const row of rows) {
    // speedOk 는 사람이 "이 포트는 원래 이 속도" 라고 눌러 둔 것이다. 그걸
    // 누르고도 계속 빨갛게 남으면 단추가 안 먹은 것처럼 보이고, 그다음부터
    // 사람은 빨간색 전체를 무시한다.
    row.slowLink = !row.speedOk && minority && usual >= 1000 && row.oper === 1
      && row.speed > 0 && row.speed <= usual / 4;
  }
  const access = rows.filter(r => !isUplink(r)).sort((a, b) => portNumber(a) - portNumber(b));
  const uplink = rows.filter(isUplink).sort((a, b) => portNumber(a) - portNumber(b));

  const cell = (row) => {
    if (!row) return '<span class="pport pport--gap"></span>';
    const marks = [portClass(row)];
    if (row.poeStatus === 3) marks.push('has-poe');
    if (row.blocked) marks.push('keep');
    if (String(row.index) === String(pickedPort)) marks.push('picked');
    const who = (row.devices || []).map(d => d.ip || (d.mac || '').toUpperCase()).join(', ');
    const half = isHalfDuplex(row);
    const tip = [`${portNumber(row)} · ${row.name}`,
                 row.speed ? formatSpeed(row.speed) : t('portsLegendIdle'),
                 half ? t('portsHalfTip') : '',
                 row.wasSpeed ? `← ${formatSpeed(row.wasSpeed)} (${row.wasAt})` : '',
                 row.poeStatus === 3 ? `PoE ${(row.poeWatt || 0).toFixed(1)}W` : '',
                 who, row.blocked].filter(Boolean).join(' · ');
    // 반이중은 색만으로는 속도 저하와 구분이 안 된다. 조치가 다르다 —
    // 하나는 랜선을 다시 성단하는 일이고, 하나는 양끝 설정을 맞추는 일이다.
    const face = row.admin === 2 ? '\u2715'
      : (half ? `${portNumber(row)}<i class="pp-half">\u00bd</i>` : portNumber(row));
    return `<button class="pport ${marks.join(' ')}" data-index="${esc(row.index)}"`
      + ` title="${esc(tip)}">${face}</button>`;
  };

  // 실물 스위치는 1번 밑에 2번, 3번 밑에 4번이 온다. 그러니 번호 순으로
  // 늘어놓으면 안 되고 자리를 잡아 놓아야 한다 — 없는 번호는 빈 칸으로 둔다.
  // 그래야 랙 앞에서 세어본 위치와 화면이 같아진다.
  const byNumber = new Map(access.map(r => [portNumber(r), r]));
  const last = Math.max(0, ...byNumber.keys());
  const top = [], bottom = [];
  for (let n = 1; n <= last; n += 2) {
    top.push(cell(byNumber.get(n)));
    bottom.push(cell(byNumber.get(n + 1)));
  }
  const bank = () => `<div class="face-bank">`
    + `<div class="face-line">${top.join('')}</div>`
    + `<div class="face-line">${bottom.join('')}</div></div>`;

  // 범례는 여섯 개. 색 다섯 + 점선 하나로 앞판의 모든 상태가 설명된다.
  const legend = [
    ['live', t('portsLegend')], ['slow', t('portsLegendSlow')],
    ['slow half', t('portsLegendHalf')],
    ['idle', t('portsLegendIdle')], ['locked', t('portsLegendLock')],
    ['live has-poe', t('portsLegendPoe')], ['keep', t('portsLegendKeep')],
  ].map(([cls, text]) => `<span class="face-key"><i class="pport ${cls}">${cls === 'locked' ? '\u2715' : (cls === 'slow half' ? '\u00bd' : '')}</i>${esc(text)}</span>`).join('');

  // 창 맨 위 한 줄. 숫자 넷이면 이 스위치 상태가 다 설명된다.
  $('#portsWhere').textContent = t('portsWhere', { sw: portsData.switch, n: rows.length });
  $('#portsTally').innerHTML = [
    ['live', rows.filter(r => portClass(r) === 'live').length, t('portsTallyUp')],
    ['slow', rows.filter(r => r.slowLink && !r.wasSpeed).length, t('portsTallySlow')],
    ['slow', rows.filter(r => r.wasSpeed).length, t('portsTallyWas')],
    ['slow', rows.filter(isHalfDuplex).length, t('portsTallyHalf')],
    ['locked', rows.filter(r => r.admin === 2).length, t('portsTallyLock')],
    ['pwr', rows.filter(r => r.poeStatus === 3).length, 'PoE'],
  ].filter(([, n]) => n).map(([cls, n, label]) =>
    `<span class="tally ${cls}"><b>${n}</b>${esc(label)}</span>`).join('');

  $('#portsFace').innerHTML = `<div class="face-plate">${bank()}`
    + (uplink.length
      ? `<div class="face-bank face-bank--uplink"><div class="face-line">${uplink.map(cell).join('')}</div>`
        + `<div class="face-tag">${esc(t('portsUplink'))}</div></div>` : '')
    + `</div><div class="face-legend">${legend}</div>`;
}

/** 고른 포트 하나. 한 줄 요약과 다룰 수 있는 단추뿐이다.
    포트를 고르기 전에는 아예 나오지 않는다 — 빈 칸도 화면을 어지럽힌다. */
function renderDetail() {
  const panel = $('#portsDetail');
  const row = (portsData.rows || []).find(r => String(r.index) === String(pickedPort));
  if (!row) { panel.hidden = true; panel.innerHTML = ''; return; }

  const state = portStateLabel(row);
  // 듀플렉스는 아는 경우에만 적는다. 3(전이중)이면 조용히 옆에 붙여 두고,
  // 0(스위치가 안 알려줌)이면 아무 말도 안 한다.
  const dup = row.oper === 1 && Number(row.duplex || 0) === 3 ? t('portsFull') : '';
  const meta = [
    row.speed ? formatSpeed(row.speed) : '',
    dup,
    row.poeStatus === 3 ? `PoE ${(row.poeWatt || 0).toFixed(1)}W` : '',
    (row.devices || []).map(d => `${d.ip || (d.mac || '').toUpperCase()}${d.kind ? ' · ' + d.kind : ''}`).join(' / '),
  ].filter(Boolean).join('  ·  ');

  const acts = [];
  if (row.admin === 2) {
    acts.push(`<button class="ghost-btn" data-act="unlock">${esc(t('portsUnlock'))}</button>`);
  } else {
    if (row.poeStatus === 3) {
      acts.push(`<button class="primary danger" data-act="cycle"${row.blocked ? ' disabled' : ''}>${esc(t('poeCycle'))}</button>`);
      acts.push(`<button class="ghost-btn danger-btn" data-act="poeoff"${row.blocked ? ' disabled' : ''}>${esc(t('poeAdminOff'))}</button>`);
    } else if (row.poeAdmin === 2) {
      acts.push(`<button class="ghost-btn" data-act="poeon">${esc(t('poeAdminOn'))}</button>`);
    }
    acts.push(`<button class="ghost-btn danger-btn" data-act="lock"${row.blocked ? ' disabled' : ''}>${esc(t('portsLock'))}</button>`);
  }

  // "모르는 장비" 라고 말할 수 있는 경우는 하나뿐이다 —
  // 스위치가 MAC 을 알려줬는데(fdbOk) 그 MAC 이 우리 목록에 없을 때.
  //
  // MAC 자체를 못 읽었으면 그냥 모르는 것이지 '없는' 것이 아니다. 거기에
  // 경고를 붙이면 포트마다 빨간 딱지가 붙어서 진짜 봐야 할 것을 덮는다.
  const seen = row.devices || [];
  const strangers = seen.filter(d => !d.ip);
  const ghost = portsData.fdbOk && row.oper === 1 && seen.length && !seen.some(d => d.ip)
    ? `<div class="pd-ghost">${esc(t('portsGhost', { n: strangers.length }))}</div>` : '';

  // 이 포트가 예전에 더 빨랐다는 기록. 짐작이 아니라 우리가 적어둔 사실이라
  // 따로, 눈에 띄게 내놓는다. 옆에 '정상입니다' 를 같이 둔다 — 일부러 100M
  // 장비를 물려둔 포트가 영원히 빨갛게 남으면 사람은 빨간색 전체를 무시한다.
  //
  // 근거가 둘이다. wasSpeed 는 "이 포트가 전에는 더 빨랐다" 는 우리 기록이라
  // 확실하고, slowLink 는 "옆 포트들보다 느리다" 는 짐작이다. 둘 다 빨갛게
  // 칠하는 이상, 둘 다 "정상입니다" 로 재울 수 있어야 한다. 짐작으로 빨개진
  // 포트를 끌 방법이 없으면 그 빨강은 영원히 남고, 곧 무시당한다.
  const why = row.wasSpeed
    ? t('portsWas', { was: formatSpeed(row.wasSpeed), when: row.wasAt || '-',
                      now: formatSpeed(row.speed) || '-' })
    : (row.slowLink ? t('portsSlowGuess', { now: formatSpeed(row.speed) || '-' }) : '');
  const was = why
    ? `<div class="pd-was"><b>${esc(why)}</b>`
      + `<span>${esc(t('portsWasWhy'))}</span>`
      + `<button class="ghost-btn" data-act="speedok" title="${esc(t('portsWasOkTitle'))}">`
      + `${esc(t('portsWasOk'))}</button></div>`
    : '';

  // 반이중. 속도 저하와 나란히 두되 따로 세운다 — 조치가 완전히 다르다.
  // 속도 저하는 랜선을 다시 성단하는 일이고, 반이중은 양끝 설정을 맞추는 일이다.
  // 여기서 랜선부터 뜯으면 멀쩡한 성단을 두 번 하고도 안 고쳐진다.
  const hits = Number(row.lateColl || 0);
  const half = isHalfDuplex(row)
    ? `<div class="pd-half"><b>${esc(t('portsHalf', { s: formatSpeed(row.speed) || '-' }))}</b>`
      + `<span>${esc(t('portsHalfWhy'))}</span>`
      + (hits > 0 ? `<span class="pd-proof">${esc(t('portsHalfProof', { n: hits }))}</span>` : '')
      + `</div>`
    : '';

  panel.hidden = false;
  panel.innerHTML =
    `<div class="pd-line">`
    + `<b>${esc(row.name || row.index)}</b>`
    + `<span class="port-state ${state.cls}">${esc(state.text)}</span>`
    + (meta ? `<span class="pd-meta">${esc(meta)}</span>` : '')
    + (row.alias ? `<i class="pd-alias">${esc(row.alias)}</i>` : '')
    + (row.blocked ? `<em class="pd-keep">${esc(row.blocked)}</em>` : '')
    + `</div>${half}${was}${ghost}<div class="pd-acts">${acts.join('')}</div>`;
}

function renderPorts() {
  renderFace();
  renderDetail();
}

/* 지켜보는 중에 부르는 새로고침.

   아래 칸(renderDetail)은 innerHTML 을 통째로 갈아치운다. 그런데 그 안의
   단추는 누르는 순간 disabled 로 잠가서 두 번 눌리는 것을 막고 있다. 요청이
   아직 날아가는 중에 다시 그려 버리면 잠기지 않은 새 단추가 생긴다 — 성격
   급한 사람이 한 번 더 누르면 PoE 를 두 번 끄거나 카메라 전원을 두 번 껐다
   켠다. 그래서 손대는 중에는 앞판만 고쳐 그린다. */
function refreshPorts() {
  const busy = $('#portsDetail').querySelector('button[data-act][disabled]');
  renderFace();
  if (!busy) renderDetail();
}

async function openPorts() {
  const host = $('#snmpHost').value.trim();
  if (!host) return notice(t('snmpNeedHost'), true);
  notice(t('portsReading'));
  let result;
  try {
    result = await call('switch_ports', { switch: host, community: $('#snmpCommunity').value.trim() });
  } catch (_) { return; }
  portsData = { switch: result.switch, rows: result.ports || [], fdbOk: !!result.fdbOk,
                name: result.switchName || '' };
  pickedPort = null;
  linkEpoch += 1;            // 다른 스위치를 열었으면 앞의 지켜보기는 끝난 얘기다
  $('#snmpDialog').hidden = true;
  renderPorts();
  clearSay();
  $('#portsDialog').hidden = false;
  notice(t('ready'));
}

$('#portsBtn').addEventListener('click', openPorts);
const closePorts = () => {
  $('#portsDialog').hidden = true;
  // 예약해둔 '전부 잠그기' 를 푼다. 안 그러면 창을 닫았다 다시 열어 한 번만
  // 눌러도 확인 없이 전부 잠긴다.
  clearTimeout(lockFreeTimer);
  lockFreeArmed = false;
  linkEpoch += 1;              // 링크 지켜보기도 같이 멈춘다
  $('#portsLockFree').textContent = t('portsLockFree');
  $('#portsLockFree').classList.remove('danger-btn');
};
$('#portsClose').addEventListener('click', closePorts);
$('#portsOk').addEventListener('click', closePorts);
closeOnBackdrop('portsDialog', closePorts);

/** 포트 하나를 잠그거나 푼다. 성공하면 그 줄만 고쳐 그린다. */
async function setPort(index, up) {
  const row = portsData.rows.find(r => String(r.index) === String(index));
  if (!row) return false;
  const community = $('#portsCommunity').value.trim();
  if (!community) { notice(t('portsNeedComm'), true); return false; }
  await call('port_admin', {
    switch: portsData.switch, community, index, up,
    name: row.name, blocked: up ? '' : (row.blocked || ''),
  });
  row.admin = up ? 1 : 2;
  if (!up) row.oper = 2;
  return true;
}

$('#portsLockFree').addEventListener('click', async () => {
  // 링크가 없고, 막을 이유도 없는 포트만 고른다. 준공 마감에 쓰는 단추다.
  const targets = portsData.rows.filter(r => r.oper !== 1 && r.admin !== 2 && !r.blocked);
  if (!targets.length) return notice(t('portsLockNone'), true);
  if (!$('#portsCommunity').value.trim()) return notice(t('portsNeedComm'), true);
  // 한 번에 여러 포트를 끄는 단추라 한 번 더 묻는다. 창을 띄우는 대신
  // 단추가 스스로 물어보고, 4초 안에 다시 누르지 않으면 없던 일이 된다.
  if (!lockFreeArmed) {
    lockFreeArmed = true;
    const button = $('#portsLockFree');
    const original = button.textContent;
    button.textContent = t('portsLockAsk', { n: targets.length });
    button.classList.add('danger-btn');
    clearTimeout(lockFreeTimer);
    lockFreeTimer = setTimeout(() => {
      lockFreeArmed = false;
      button.textContent = original;
      button.classList.remove('danger-btn');
    }, 4000);
    return;
  }
  clearTimeout(lockFreeTimer);
  lockFreeArmed = false;
  $('#portsLockFree').textContent = t('portsLockFree');
  $('#portsLockFree').classList.remove('danger-btn');
  $('#portsLockFree').disabled = true;
  let done = 0;
  try {
    for (const row of targets) {
      try { if (await setPort(row.index, false)) done += 1; }
      catch (_) { break; }
    }
  } finally {
    $('#portsLockFree').disabled = false;
    renderPorts();
    if (done) notice(t('portsLockDone', { n: done }));
  }
});

/* 포트를 풀어도 통신이 곧바로 살아나지 않는다.

   랜선 양끝이 속도를 다시 맞추는 데(오토니고) 2~3초. 그다음 스위치가 루프를
   확인하는 동안(STP) 링크는 붙어 있는데도 데이터가 안 흐른다 — 기본 설정이면
   여기서만 30초까지 간다. "풀었습니다" 하고 화면이 끝나 버리면 기사는 카메라가
   안 올라온다며 멀쩡한 포트를 다시 만진다. 그러니 붙는 것을 직접 보고 알린다. */

const LINK_WAIT_MS = 45000;
const LINK_POLL_MS = 2500;
let linkEpoch = 0;                 // 창을 닫거나 다른 스위치를 열면 올린다
const linkWatching = new Set();    // 지금 지켜보는 포트들

async function watchLink(index, label) {
  // 준공 마감에는 포트를 서너 개 연달아 푼다. 하나 풀 때마다 앞의 것을
  // 버리면, 나머지는 "풀었습니다" 만 남고 붙었는지 아닌지 아무 말이 없다.
  // 그래서 포트마다 따로 지켜본다.
  if (linkWatching.has(String(index))) return;
  linkWatching.add(String(index));
  const era = linkEpoch;
  const host = portsData.switch;
  const community = ($('#snmpCommunity') || {}).value || 'public';
  const began = Date.now();
  say(t('portsLinkWait', { p: label }));
  try {
    while (Date.now() - began < LINK_WAIT_MS) {
      await new Promise(done => setTimeout(done, LINK_POLL_MS));
      // 창을 닫았거나 다른 스위치를 열었으면 조용히 그만둔다.
      if (era !== linkEpoch || $('#portsDialog').hidden) return;
      let now;
      try { now = await window.ipfix.request('port_link', { switch: host, community, index }); }
      catch (_) { continue; }            // 한 번 놓친 것으로 포기하지 않는다
      if (era !== linkEpoch) return;
      // read 가 false 면 이번에 못 읽은 것이다. 그걸 '링크 없음' 으로 적으면
      // 그 포트가 빈 포트로 보이고, '빈 포트 전부 잠그기' 가 물어간다.
      if (!now || !now.read) continue;
      const row = (portsData.rows || []).find(r => String(r.index) === String(index));
      if (row) {
        row.oper = now.oper;
        if (now.admin) row.admin = now.admin;
        if (now.speed) row.speed = now.speed;
        refreshPorts();
      }
      if (now.oper === 1) {
        const secs = Math.round((Date.now() - began) / 1000);
        say(t('portsLinkUp', { p: label, s: formatSpeed(now.speed) || '-', n: secs }), 'ok');
        say(t('portsLinkStp'), 'warn');
        return;
      }
    }
    if (era !== linkEpoch) return;
    say(t('portsLinkNone', { p: label, n: Math.round(LINK_WAIT_MS / 1000) }), 'warn');
  } finally {
    linkWatching.delete(String(index));
  }
}

$('#portsFace').addEventListener('click', (event) => {
  const cell = event.target.closest('button[data-index]');
  if (!cell) return;
  pickedPort = cell.dataset.index;
  renderFace();
  renderDetail();
});

$('#portsDetail').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-act]');
  if (!button || button.disabled) return;
  const row = (portsData.rows || []).find(r => String(r.index) === String(pickedPort));
  if (!row) return;
  const act = button.dataset.act;
  const label = row.name || row.index;
  if (act === 'speedok') {
    // 스위치를 건드리지 않는다 — 우리 기록의 기준선만 지금 속도로 내린다.
    // 그래서 쓰기 커뮤니티 문자열도 필요 없다.
    button.disabled = true;
    try {
      await call('port_speed_ok', { switch: portsData.switch, port: row.speedKey || row.name });
      row.wasSpeed = 0;
      row.wasAt = '';
      row.speedOk = true;
      row.slowLink = false;
      notice(t('portsWasDone', { port: label }));
      renderPorts();
    } catch (_) { button.disabled = false; }
    return;
  }
  const community = $('#portsCommunity').value.trim();
  if (!community) return notice(t('portsNeedComm'), true);
  button.disabled = true;
  try {
    if (act === 'lock' || act === 'unlock') {
      const up = act === 'unlock';
      if (await setPort(row.index, up)) {
        notice(t(up ? 'portsUnlocked' : 'portsLocked', { p: label }));
        // 풀었으면 링크가 실제로 붙는지 끝까지 본다. 기다리는 동안에도 창은
        // 계속 쓸 수 있어야 하므로 붙잡지 않는다.
        if (up) watchLink(row.index, label);
      }
    } else if (act === 'poeoff' || act === 'poeon') {
      const on = act === 'poeon';
      await call('poe_admin', {
        switch: portsData.switch, community, index: row.poeIndex || row.index, on,
        name: label, blocked: on ? '' : (row.blocked || ''),
      });
      row.poeAdmin = on ? 1 : 2;
      row.poeStatus = on ? 3 : 1;
      if (!on) { row.poeWatt = 0; row.oper = 2; }
      notice(t(on ? 'poeRestored' : 'poeCut', { p: label }));
    } else if (act === 'cycle') {
      notice(t('poeRunning', { ip: (row.devices || [])[0]?.ip || label }));
      await call('poe_restart', {
        key: (row.devices || [])[0]?.key || '', switch: portsData.switch, community,
        index: row.poeIndex || row.index, name: label,
        blocked: row.blocked || '', wait: 6,
      });
      notice(t('poeDone', { ip: (row.devices || [])[0]?.ip || label }));
    }
    renderPorts();
  } catch (_) { /* call()에서 메시지 표시 */ }
  finally { button.disabled = false; }
});
