/* Quiet Scanner — field tool for sorting out IP conflicts
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

/* ── List columns ─────────────────────────────────────────────────────
   As we read more off each device, it stopped fitting into one column.
   Split it into columns and let the tech choose what to see — right-click the header.
   Every site looks at different things, so the choice survives the next run.
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
    // Drop saved keys that no longer exist (old version); keep the IP column no matter what.
    const known = saved.filter(k => COLUMNS.some(c => c.key === k));
    shownColumns = known.includes('ip') ? known : ['ip', ...known];
  }
} catch (_) { /* unreadable storage still runs on the defaults */ }

function saveColumns() {
  try { localStorage.setItem(COLUMN_STORE, JSON.stringify(shownColumns)); }
  catch (_) { /* if it will not save, it still applies for this run */ }
}

/** The visible columns, in the order we fixed. */
function visibleColumns() {
  return COLUMNS.filter(c => shownColumns.includes(c.key));
}

/** Collect one device's candidate names with no duplicates. */
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

/** The text for one cell. Sorting, search and export all use this. */
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

/** Value used for sorting. Numbers must compare as numbers, or 10 lands before 9. */
function cellSortValue(d, key) {
  switch (key) {
    case 'ip':    return ipKey(d.ip);
    case 'ms':    return d.ms == null ? Number.MAX_SAFE_INTEGER : Number(d.ms);
    case 'ports': return (d.ports || []).length;
    case 'vlan':  return d.swvlan == null ? Number.MAX_SAFE_INTEGER : Number(d.swvlan);
    default:      return cellText(d, key).toLowerCase();
  }
}

/** Link speed in units a person reads. 1000 and up is written as gigabit. */
function formatSpeed(mbps) {
  const value = Number(mbps) || 0;
  if (!value) return '';
  return value >= 1000 ? `${value / 1000}G` : `${value}M`;
}

/** Draws one cell. */
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
    // One device commonly hands back several names — reverse DNS, mDNS, NetBIOS, UPnP.
    // The cell keeps the first, counts the rest as +N, and leaves them to the tooltip.
    const rest = names.slice(1);
    const tip = rest.length ? t('namesTip', { n: rest.length, rest: rest.join(' · ') }) : names[0];
    return `<div title="${esc(tip)}">${esc(names[0])}${rest.length ? `<i class="more" title="${esc(tip)}">+${rest.length}</i>` : ''}</div>`;
  }
  if (key === 'os') {
    // The raw TTL never hits the screen — we already translated 64 into Linux.
    // The number itself shows on hover, and goes into the export file as-is.
    if (d.ttl == null) return `<div class="dim">${d.identified ? t('ttlUnread') : '-'}</div>`;
    return `<div title="TTL ${d.ttl}">${esc(tk(d.os))}</div>`;
  }
  if (key === 'ports') {
    const ports = (d.ports || []).map(p => `<span class="port">${portName[p] || p}</span>`).join('');
    return `<div class="ports">${ports}</div>`;
  }
  if (key === 'swport') {
    if (!d.swport) return '<div class="dim">-</div>';
    // Link speed goes next to the port name. A gigabit switch sitting at 100M
    // gets painted red — lose one cable pair and the link never drops, it just sags.
    // The screen shortens it to Gi1/0/12, so the full name must stay in the tooltip.
    // On the switch CLI the tech reads that long name exactly as it is.
    // Half duplex is the fault where the speed column still looks fine, so if the
    // list does not show it outright nobody ever finds it. Hang a ½ off the speed.
    const dupHalf = Number(d.swduplex || 0) === 2;
    const hint = [d.swname ? `${d.swname} ${d.swport}` : d.swport,
                  d.swalias, d.swvlan ? `VLAN ${d.swvlan}` : '',
                  dupHalf ? t('halfLinkTip') : '',
                  d.swslow ? t('slowLinkTip') : ''].filter(Boolean).join(' · ');
    const speed = d.swspeed
      ? `<i class="swspeed${d.swslow || dupHalf ? ' slow' : ''}">${formatSpeed(d.swspeed)}`
        + `${dupHalf ? '<b>\u00bd</b>' : ''}</i>` : '';
    // If the port is feeding PoE, show how many watts alongside. 3 = delivering power.
    const poe = d.poeStatus === 3
      ? `<i class="poe" title="${esc(t('poeTip'))}">${d.poeWatt ? d.poeWatt.toFixed(1) : '?'}W</i>` : '';
    // With several switches on site, "port 12" alone gets you nowhere. Name the
    // switch too, but keep it to **one line** — two lines pin the row height at
    // 45px and dense view stops working entirely.
    //
    // Shorten the port name as well. GigabitEthernet1/0/12 is 21 characters and 18
    // of them say the same thing every time. Gi1/0/12 is how techs write it anyway.
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

/* Pick which columns to see — right-click the header */
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
  // Stop here. Otherwise the 'click outside to close' handler below counts this
  // click as outside — redrawing the menu detaches the pressed button from the document.
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
  renderColumnMenu();       // keep it open — easier to tick several in a row
  render();
});

function esc(text) { return String(text || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
/* Notices.

   The log line (#notice) sits inside the activity log at the very bottom. If any
   dialog is open, that line is completely hidden behind it — so a port lock that
   gets refused looks like nothing happened at all. The tech decides the button is
   broken and presses it again. We now refuse whenever we cannot verify, so refusals
   are not rare either. The reason for a refusal has to show where the eyes are.

   So while a dialog is open we stack the run log inside that dialog too. Several
   lines, not one, because jobs that take time — unlocking a port and waiting for
   the link to come up — need their progress left on screen.
   ------------------------------------------------------------------- */

const DIALOG_LOG_KEEP = 8;

/* Of the open dialogs, the one actually being looked at.

   Do not take the last one in DOM order — #snmpDialog sits after #portsDialog, so
   a refusal from the port manager ends up in another dialog hidden behind it.
   Take the one drawn topmost (z-index, then DOM order). */
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

/** One log line inside the open dialog. kind: '' | 'ok' | 'warn' | 'bad' */
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

/** Wipe the old log when a dialog opens. The last site's messages must not linger. */
function clearSay() {
  for (const box of document.querySelectorAll('.modal-log')) box.remove();
}

function notice(text, bad = false) {
  $('#notice').textContent = text;
  $('#notice').style.color = bad ? '#e7475b' : '';
  // 'Ready' is not news, it means nothing is happening. Do not stack it in the log.
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

/* ── Subnet tabs ──────────────────────────────────────────────────────
   Scan with two or more NICs picked and the subnets mix. 200 addresses on 172
   running straight into 50 on 192 and you cannot tell which one you are looking
   at. One tab per subnet — only a search looks at all of them at once.
   ------------------------------------------------------------------- */

let activeNet = '';

/** An IP's subnet. Cut at the first three octets — site networks are almost always /24. */
function netOf(ip) { return String(ip || '').split('.').slice(0, 3).join('.'); }

/** Subnets in the current list, with their IP and device counts. Ordered by IP. */
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
  // Dropped the strip of four coloured dots. 'IPs found 23' and 'devices 24' were
  // effectively the same number, and the strip ate 56px of screen while making this
  // look like a web dashboard. The numbers go on this one line.
  $('#subTitle').textContent = s.devices
    ? [s.conflictIps ? t('countConflict', { n: s.conflictIps }) : '',
       t('countDevices', { n: s.devices }),
       t('countIps', { n: s.ips })].filter(Boolean).join('  ·  ')
    : t('pickIface');
  renderHead();
  const columns = visibleColumns();
  const rows = [];
  let shown = 0;
  // The list is grouped by IP. Sorting on a header orders the groups themselves,
  // not just their contents. Conflicting IPs always stay on top — that is what this tool is for.
  const groupValue = (g) => {
    const first = sortDevices(g.devices || [])[0];
    if (!first) return ipKey(g.ip);
    return sortKey === 'ip' ? ipKey(g.ip) : cellSortValue(first, sortKey);
  };
  // Two or more subnets get split into tabs. Not while searching, though —
  // if the hit is on another tab it looks like nothing was found.
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
  // With a search term, filter down and force matching IPs open even if collapsed.
  for (const group of groups) {
    const devices = (group.devices || []).filter(matchesFilter);
    if (filterText && !devices.length) continue;
    const conflict = (group.conflict ? ' conflict' : '')
      + (isSelectedInterfaceIp(group.ip) ? ' own-ip' : '');
    const open = filterText ? true : expandedGroups.has(group.ip);
    shown += devices.length;
    const note = group.conflict ? t('groupNote', { n: group.count }) : '';
    // The group row only matches the device row on the first column; the rest is
    // merged into one cell (.group-note in styles.css). Fill them one by one and the
    // text wraps inside the narrow ones. An IP with one device has nothing to fold.
    //
    // Folded, that row shows one IP and eight empty columns. No vendor, no kind, no
    // switch port, and it takes another click to see any of it. Most site IPs hold
    // one device, so the whole screen becomes an empty grid — headers over nothing.
    // That row is the device, so write it all on one line. Right-click works there too.
    //
    // Only conflicting IPs stay grouped. Those really do hold two or more, so there
    // has to be a step where you pick which one.
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
    Cisco's own shorthand. The full name shows when you hover the cell. */
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

/** Single-device IP — IP and device on one row. First cell is custom, the rest as-is. */
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

// Electron wraps IPC errors as "Error invoking remote method 'x': Error: the real thing"
// before throwing. Techs read this screen, so strip the wrapper off first.
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
    // A refresh keeps the picked cards. Match them back by name — the list order
    // shifts when a cable goes in or out. Fall back to the default only if none match.
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

/* ── Picking NICs ─────────────────────────────────────────────────────
   Some racks run two subnets on two cables, server-style. Scan those one card at a
   time and the list splits in two, so the conflict never shows. So we pick several
   and scan in one pass — each subnet goes out its own card.
   ------------------------------------------------------------------- */

let pickedIfaces = [0];

function selectedIfaces() {
  return pickedIfaces.map(n => interfaces[n]).filter(Boolean);
}
function selectedIface() { return selectedIfaces()[0]; }
/* Which NIC to pick the moment the app opens.

   It used to look for 'ethernet' in the name and fall back to the first entry in the
   list. On a laptop with Bluetooth PAN at the top, that is what got picked.
   Bluetooth and virtual adapters usually carry 169.254.x.x, a number Windows made up
   on its own because it never got an address (APIPA). **Nothing is out there.**

   So pick on the **address**, not the name. A card with a real address wins every
   time. A person reads that off the screen in a second; the code reads it the same way.
   ------------------------------------------------------------------- */
function ifaceScore(card) {
  const rows = card.ipv4 || [];
  const ips = rows.map(r => r.ip).concat(card.ips || []).filter(Boolean);
  const real = ips.filter(ip => !/^(169\.254|127\.|0\.)/.test(ip));
  if (!real.length) return -1;              // nothing but 169.254 means there is no network

  let score = 100;
  // A private range is likely the site network. Public addresses are usually the WAN side.
  if (real.some(ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip))) score += 40;
  // A card that knows its prefix is better — we can build the exact range.
  if (rows.some(r => r.cidr)) score += 10;

  const name = `${card.desc || ''} ${card.name || ''}`.toLowerCase();
  // Virtual, tunnel and Bluetooth go to the back. The name is the last thing we judge on.
  if (/virtual|vmware|virtualbox|hyper-v|loopback|tap-|tun|vpn|wintun|bluetooth|pseudo|npcap/.test(name)) score -= 60;
  if (/wi-?fi|wireless|무선/.test(name)) score += 5;
  if (/ethernet|이더넷|realtek|intel\(r\) i2|gigabit/.test(name)) score += 15;
  return score;
}

/** Index of the most plausible NIC. 0 if none of them are any use. */
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

/** Text on the button. One card gets its name, several get a count. */
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
    // span is off limits. In this menu .context-menu span is the separator (a 1px
    // grey bar), so a name put inside a span gets cut to 1px and vanishes.
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
    // The last one cannot be unticked. Nothing selected is a useless state.
    if (pickedIfaces.length > 1) pickedIfaces = pickedIfaces.filter(x => x !== n);
  } else {
    pickedIfaces = [...pickedIfaces, n].sort((a, b) => a - b);
  }
  renderIfaceMenu();
  setTarget();
});

function setTarget() {
  // One range per picked card. Joined by commas, the engine splits the scan per card.
  const parts = [];
  for (const card of selectedIfaces()) {
    const cidr = card.ipv4?.[0]?.cidr;
    const ip = card.ips?.[0];
    if (cidr) parts.push(cidr);
    else if (ip) parts.push(ip.split('.').slice(0, 3).join('.') + '.1-254');
  }
  if (parts.length) $('#target').value = parts.join(', ');
  paintMenubarStat();       // the menubar's right-hand line changes with it
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
/** While a scan runs, the button in that same spot turns into a red 'stop'.
    A second button would be one more thing to hit, and nobody presses 'scan range'
    mid-scan anyway. Holding the position confuses the eye less. */
function paintScanButton() {
  const button = $('#scanBtn');
  button.textContent = scanRunning ? t('cancelScan') : t('scan');
  button.classList.toggle('danger', scanRunning);
  button.disabled = false;
  paintMenubarStat();       // the menubar's right-hand dot changes with it
}

$('#scanBtn').addEventListener('click', async () => {
  if (scanRunning) {          // mid-scan this button is the stop button
    $('#scanBtn').disabled = true;
    notice(t('canceling'));
    try {
      const result = await call('cancel');
      if (result.state) applyState(result.state);
    } catch (_) { /* call() already shows the status message */ }
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
  sortKey = 'ip'; sortDesc = false;   // a new scan always starts at .1
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

/* ── Click outside to close ───────────────────────────────────────────
   Dragging to select text and releasing outside the dialog used to close it.
   When press and release land in different places, the browser fires click on their
   common ancestor. Press inside a field, release on the backdrop, and that ancestor
   is the backdrop — so it read as a click on the backdrop.

   So we skip click, and close only when press and release are **both** on the backdrop. */
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
  // Show only what is possible in the current state. Listing both just confuses.
  const isolated = state.isolated === key;
  menu.querySelector('[data-menu="isolate"]').hidden = isolated;
  menu.querySelector('[data-menu="release"]').hidden = !isolated;
  // PoE restart only appears on ports the switch is actually powering.
  // 3 = delivering power. Anything else has no power to cycle.
  menu.querySelector('[data-menu="poe"]').hidden = deviceOf(key)?.poeStatus !== 3;
}

/** Find one device by key. They live inside groups, so we dig one level down. */
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
  // This has to catch the merged row (.solo-row) too. Otherwise right-click does
  // nothing at all on a single-device IP — no identify, no isolate.
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
  } catch (_) { /* call() already shows the status message */ }
});



/* ── Device book ──────────────────────────────────────────────────────
   A table that reads vendor and device kind off the MAC prefix. Register a device
   you meet for the first time and it comes up named on the next site's scan.
   Six digits covers that whole vendor; all twelve pin it to that one device.
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
  catch (_) { /* call() already shows the status message */ }
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

  // Check whether the prefix is already in the book, and say so.
  clearTimeout(scopeTimer);
  scopeTimer = setTimeout(async () => {
    let found = null;
    try { found = (await call('book_lookup', { prefix: digits })).entry; } catch (_) { return; }
    if (macDigits($('#bookPrefix').value) !== digits) return;   // changed meanwhile, drop it
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
    // Called from the tools menu there is no picked device. Open it empty and let
    // the prefix be typed — a device not yet scanned can be registered ahead of time.
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
  // Default is the vendor's first three bytes. Type the rest to pin it to this device.
  $('#bookPrefix').value = mac.split('-').slice(0, 3).join('-');
  $('#bookVendor').value = device.vendor && device.vendor !== '미상' ? device.vendor : '';
  // The book stores the Korean kind names the engine uses — only the screen translates.
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

/* ── The registered book ────────────────────────────────────────────
   Over 2,600 prefixes, but only 150 entries. Cisco alone holds 1,076 of the
   prefixes. One line per prefix is unreadable, so entries sharing vendor, kind
   and note are merged onto a single line.
   ------------------------------------------------------------------- */

let bookRows = [];        // [[prefix, vendor, kind, note], ...] — exactly as the engine gave it
// Opened from the tools menu means 'browsing the list'. Closing the dialog after
// one edit would mean reopening it — this is where you fix several in a row.
let bookBrowsing = false;

function bookGroups() {
  const byWhat = new Map();
  for (const [prefix, vendor, kind, note] of bookRows) {
    // All twelve digits means somebody pinned one specific device. Merge it into the
    // prefix pile because vendor and kind match, and the one camera a tech named and
    // registered disappears inside "Cisco · 1076 prefixes". Keep it separate.
    const exact = String(prefix).length >= 12;
    const key = exact ? `\u0001${prefix}` : `${vendor}\u0000${kind}\u0000${note}`;
    if (!byWhat.has(key)) byWhat.set(key, { vendor, kind, note, exact, prefixes: [] });
    byWhat.get(key).prefixes.push(prefix);
  }
  const out = [...byWhat.values()];
  for (const row of out) row.prefixes.sort();
  // Hand-registered entries go on top. They must not be buried under 2,600 stock ones.
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
  // Past 200 rows the dialog stutters. Tell them to narrow it with a search.
  const shown = rows.slice(0, 200);
  box.innerHTML = shown.map((row, n) => {
    const many = row.prefixes.length > 1;
    const head = many ? t('bookPrefixes', { n: row.prefixes.length })
                      : dashPrefix(row.prefixes[0]);
    // Several prefixes stay folded and open on a click. It used to lift only the
    // first one into the field, with no way whatsoever to see the other 37.
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

// Prefixes drawn at once for one entry. Cisco alone has 1,074 — draw them all and it stalls.
const BOOK_CHIPS = 120;
const bookOpen = new Set();     // unfolded entries (remembered by first prefix)

/** 000f7c -> 00-0F-7C */
function dashPrefix(prefix) {
  const hex = String(prefix || '').toUpperCase();
  return (hex.match(/.{1,2}/g) || [hex]).join('-');
}

/** The book holds the Korean kind names the engine uses. Only the screen translates. */
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

/* Clicking in the list.

   An entry with several prefixes does not load into the fields on a click — there is
   no single 'one' to load. It unfolds instead, and a click on one prefix loads that.
   ------------------------------------------------------------------- */
$('#bookList').addEventListener('click', (event) => {
  const item = event.target.closest('.bk-item');
  if (!item) return;
  const group = bookGroups().find(g => g.prefixes[0] === item.dataset.prefix);
  if (!group) return;

  const chip = event.target.closest('.bk-chip');
  if (!chip && group.prefixes.length > 1) {
    // merged entry — folds and unfolds, nothing else
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

/** Load the picked prefix into the fields above, to edit or delete it. */
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
  } catch (_) { /* call() already shows the message */ }
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
  } catch (_) { /* call() already shows the message */ }
});



/* ── Working the list ─────────────────────────────────────────────────
   Past thirty devices you cannot scan it by eye. Filter with a search, sort by
   clicking a header. Whatever the filter leaves is exactly what goes out to file.
   ------------------------------------------------------------------- */

function deviceText(d) {
  // Search hidden columns too. Hiding a column must not make its value unfindable.
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

/* ── Handover · inspection report ───────────────────────────────────
   What techs used to retype into Excel after a scan — the device list, what sits on
   which port, speeds, PoE draw — comes out as one document. Switch IPs are collected
   off the list on their own. Make a person retype them and one switch gets missed,
   and a missed switch vanishes quietly from the document. That is not a report.
   ------------------------------------------------------------------- */

/** Collect the switch IPs attached to the current list. */
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
  // Carry over the community string from the port manager. Same switch, same value.
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
    // A switch we could not read never passes quietly. It is in the document too,
    // but saying it again right where they saved is what makes them re-export.
    if (result.missed) setTimeout(() => notice(t('reportMissed', { n: result.missed }), true), 2500);
  } catch (_) { /* call() already shows the message */ }
  finally { button.disabled = false; }
});

/* ── Export ───────────────────────────────────────────────────────── */

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
  } catch (_) { /* call() already shows the message */ }
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
  } catch (_) { /* call() already shows the message */ }
});
const closeHistory = () => { $('#historyDialog').hidden = true; };
$('#historyClose').addEventListener('click', closeHistory);
$('#historyOk').addEventListener('click', closeHistory);
closeOnBackdrop('historyDialog', closeHistory);

/* ── Language ─────────────────────────────────────────────────────────
   i18n.js makes the screen text, the engine makes the log text. So a change has to
   be told to both. Log lines already stacked stay in the language they were written
   in — rewriting past records after the fact confuses more than it helps.
   ------------------------------------------------------------------- */

/* ── Menubar · dense view ───────────────────────────────────────────
   The menu does not replace the toolbar buttons below. What gets used often stays a
   button; the menu is where "now where was that" dies and shortcuts live.
   So every item here just presses the existing button — keep two copies of one
   action and you fix one and forget the other.
   ------------------------------------------------------------------- */

const DENSE_STORE = 'ipscan.dense';
// Dense is the default. Nearly twice as much fits on a screen. We only remember who turned it off.
let dense = true;
try { dense = localStorage.getItem(DENSE_STORE) !== '0'; } catch (_) { dense = true; }

function applyDense() {
  document.body.classList.toggle('dense', dense);
  try { localStorage.setItem(DENSE_STORE, dense ? '1' : '0'); } catch (_) { /* this run only */ }
}

function setDense(on) {
  dense = !!on;
  applyDense();
  notice(t(dense ? 'mbDenseOn' : 'mbDenseOff'));
}

function setLang(picked) {
  if (picked === lang) return;
  lang = picked;
  try { localStorage.setItem(LANG_STORE, lang); } catch (_) { /* if it will not save, it still applies now */ }
  applyStaticText();
  if (interfaces.length) renderIfaceMenu();     // button text follows the language too
  paintScanButton();
  renderColumnMenu();
  paintMenubarStat();
  render();
  call('set_lang', { lang }).catch(() => { /* the screen changes even if the engine misses it */ });
}

/** One menu's worth. [text, shortcut, what to do, ticked] */
function menuItems(which) {
  const hit = (id) => () => $(id).click();
  if (which === 'file') return [
    [t('mbExport'), 'Ctrl+E', hit('#exportBtn')],
    [t('mbReport'), 'Ctrl+R', hit('#reportBtn')],
    ['-'],
    [t('mbQuit'), 'Alt+F4', () => window.close()],
  ];
  if (which === 'view') return [
    // Column picking is not in here. Right-click on the header is its home, and
    // putting it in the menu as well only makes the list longer.
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

/** Opens the manual in the default browser.
    If it will not open, say so — press a button, watch nothing happen, and a person
    decides the program is broken and keeps pressing. */
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
  // past the right edge of the window it snaps to the left
  const left = Math.min(box.left, window.innerWidth - pop.offsetWidth - 8);
  pop.style.left = `${Math.max(8, left)}px`;
  pop.style.top = `${box.bottom + 3}px`;
  for (const other of document.querySelectorAll('.menubar button')) {
    other.classList.toggle('on', other === button);
  }
}

/* Name of the menu that was opened by a press.

   Plain 'if it is open, close it' does not work here. With a menu open, moving the
   mouse onto the neighbouring item opens that one (mouseover below), and pressing
   there becomes 'already open, so close' — the menu you just opened disappears
   before your finger comes up. So only a press-opened menu closes on a press. */
let mbPressed = '';

document.querySelector('.menubar').addEventListener('mousedown', (event) => {
  const button = event.target.closest('button[data-menu]');
  if (!button) return;
  event.preventDefault();          // stop the label being drag-selected
  event.stopPropagation();
  if (mbPressed === button.dataset.menu) { closeMenubar(); return; }
  openMenubar(button);
  mbPressed = button.dataset.menu;
});

// With one open, just passing over the next one switches — that is how menubars work
document.querySelector('.menubar').addEventListener('mouseover', (event) => {
  const button = event.target.closest('button[data-menu]');
  if (!button || $('#mbPop').hidden || button.classList.contains('on')) return;
  openMenubar(button);
  mbPressed = '';                  // opened by passing over is not opened by a press
});

// press outside to close
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

/** The line at the far right — what you are looking through must always be in sight. */
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

/** Shorten the NIC name. Vendor padding helps nobody standing in front of a rack. */
function shortIfaceName(card) {
  const text = String((card && (card.desc || card.name)) || '');
  const short = text
    .replace(/\(R\)|\(TM\)|Intel|Realtek|Ethernet|Connection|Network|Adapter|Gigabit|PCIe|Family|Controller|\(\d+\)/gi, '')
    .replace(/\s+/g, ' ').trim();
  return short || text.slice(0, 18);
}

/* F1 = manual. Works in any dialog, even mid-typing — the moment someone is
   stuck and reaching for help is no place for conditions. */
document.addEventListener('keydown', (event) => {
  if (event.key === 'F1') { event.preventDefault(); closeMenubar(); openManual(); }
});

/* Shortcuts. Not intercepted while typing in a text field. */
document.addEventListener('keydown', (event) => {
  if (!event.ctrlKey || event.altKey || event.metaKey) return;
  const key = event.key.toLowerCase();
  // Ctrl+Enter has to work inside a text field too — type the range and run it.
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
// Fetch the device-kind labels from the engine. Without them the Korean shows as-is.
call('kinds').then((map) => { Object.assign(KINDS, map || {}); render(); }).catch(() => {});
loadInterfaces();
render();


/* ── Free IPs ───────────────────────────────────────────────────────
   Addresses in the scanned range that nobody answered on. Runs are shown merged.
   What goes where is the tech's call — the tool only points at the empty seats.
   ------------------------------------------------------------------- */

let freeList = [];

$('#freeBtn').addEventListener('click', async () => {
  let info;
  try {
    info = await window.ipfix.request('free_ips', {});
  } catch (error) {
    // If the scan did not finish, the engine hands back no list at all. Slip that
    // reason into one log line below and nobody reads it — open the dialog and write
    // it large. These IPs get assigned straight off this list; the doubt must be read.
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
  // Merged ranges are shorter, but on site you point at "which number do I give it".
  // So they get listed one per line, exactly as they are.
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
  } catch (_) { /* call() already shows the message */ }
});
const closeFree = () => { $('#freeDialog').hidden = true; };
$('#freeClose').addEventListener('click', closeFree);
$('#freeOk').addEventListener('click', closeFree);
closeOnBackdrop('freeDialog', closeFree);

/* ── Finding switch ports (SNMP) ─────────────────────────────────────
   Asks the switch directly: "which port in the rack is this camera on".
   Read-only. It does not touch the switch config.
   ------------------------------------------------------------------- */

$('#snmpBtn').addEventListener('click', () => {
  if (!$('#snmpHost').value) {
    // The switch is usually the first address in the range. If not, it gets typed in.
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
  } catch (_) { /* call() already shows the message */ }
  finally { $('#snmpRun').disabled = false; }
});

/* ── PoE power cycle ──────────────────────────────────────────────────
   Unplugging and replugging a dead camera's cable, done by the switch instead.
   It is a write, so it needs its own community (usually not the read one), and
   it cannot be undone, so the confirm dialog shows exactly what is being cut.
   ------------------------------------------------------------------- */

let poeKey = null;

function openPoe(key) {
  const device = deviceOf(key);
  if (!device) return;
  if (device.poeStatus !== 3) return notice(t('poeNoPort'), true);
  poeKey = key;
  $('#poeTarget').value = `${device.ip}  ·  ${device.swport || ''}`
    + (device.poeWatt ? `  ·  ${device.poeWatt.toFixed(1)}W` : '');
  // The switch IP carries over from the port lookup just run.
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
  } catch (_) { /* call() already shows the message */ }
  finally { $('#poeRun').disabled = false; }
});

/* ── Switch port management ───────────────────────────────────────────
   The list only shows ports with a device on them. Empty ports never appear — and
   the empty ports are exactly what has to be locked at handover. So we ask the
   switch directly for every port.

   Ports we must not lock (this PC, the uplink, the switch itself) come back from the
   backend with a reason attached, and we grey the button out. Better than a refusal after the press.
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

/** Pulls the number printed on the faceplate out of the port name. GigabitEthernet1/0/12 -> 12
    Must follow the same rule as the engine (port_number). Differ, and the number in
    the Excel report and the one on screen disagree while a tech counts ports at the rack. */
function portNumber(row) {
  const runs = String(row.name || '').match(/\d+/g);
  if (runs && runs.length) return Number(runs[runs.length - 1]);
  return Number(row.index) || 0;
}

/** Uplinks and fibre ports sit apart on the faceplate. Told apart by speed or name. */
function isUplink(row) {
  return (row.speed || 0) >= 10000 || /^(te|twe|fo|fi|hu|xg|sfp)/i.test(String(row.name || ''));
}

/** Link is up, but did it settle at half duplex. 2 = half, 3 = full.
    0 means the switch never reported the value at all, so we say nothing —
    reading 0 as 'full' paints something we never checked as healthy. */
function isHalfDuplex(row) {
  return Number(row.duplex || 0) === 2 && row.oper === 1;
}

function portClass(row) {
  if (row.admin === 2) return 'locked';
  if (row.oper !== 1) return 'idle';
  // Three grounds for calling a port slow. wasSpeed is our own record that this port
  // used to run faster, so it is solid. slowLink is a guess: it is slower than its
  // neighbours. Half duplex is no guess — the switch said it itself, so it is surest
  // of the three, and the speed column looks fine, so nobody finds it unless we paint it.
  return (isHalfDuplex(row) || row.wasSpeed || row.slowLink) ? 'slow' : 'live';
}

/** The switch faceplate. Like the real thing: odds on top, evens below. */
function renderFace() {
  const rows = portsData.rows || [];
  // The baseline is the most common speed, not the highest. One 10G uplink must not
  // make every healthy 1G port read as slow.
  // Only ports with a link count. Some switches report a nominal speed on ports with
  // nothing plugged in, so twenty empty ports vote '1G is normal'.
  const live = rows.filter(r => r.oper === 1 && r.speed > 0);
  const tally = new Map();
  for (const row of live) tally.set(row.speed, (tally.get(row.speed) || 0) + 1);
  let usual = 0;
  for (const [speed, n] of tally) {
    const best = tally.get(usual) || 0;
    // On a tie, the slower side is normal. Half the cameras on a CCTV site are often
    // 100M, and leaning fast turns ten healthy cameras red.
    if (n > best || (n === best && speed < usual)) usual = speed;
  }
  // Only a minority running slow can be called wrong. On a switch that is half 100M,
  // 100M is not a fault, it is just what this site looks like.
  const slowSide = live.filter(r => usual >= 1000 && r.speed <= usual / 4).length;
  const minority = live.length >= 4 && slowSide * 3 <= live.length;
  for (const row of rows) {
    // speedOk is a tech pressing "this port always ran at this speed". Press that and
    // have the port stay red and the button looks dead, and from then on the tech
    // ignores red everywhere.
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
    // Colour alone cannot separate half duplex from a slow link. The fix differs —
    // one is reterminating the cable, the other is matching settings at both ends.
    const face = row.admin === 2 ? '\u2715'
      : (half ? `${portNumber(row)}<i class="pp-half">\u00bd</i>` : portNumber(row));
    return `<button class="pport ${marks.join(' ')}" data-index="${esc(row.index)}"`
      + ` title="${esc(tip)}">${face}</button>`;
  };

  // On a real switch, 2 sits under 1 and 4 under 3. So they cannot just be laid out
  // in number order, they have to be placed — missing numbers stay empty slots.
  // That is what makes the screen match what you counted at the rack.
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

  // Six legend keys. Five colours plus one dashed outline explain every faceplate state.
  const legend = [
    ['live', t('portsLegend')], ['slow', t('portsLegendSlow')],
    ['slow half', t('portsLegendHalf')],
    ['idle', t('portsLegendIdle')], ['locked', t('portsLegendLock')],
    ['live has-poe', t('portsLegendPoe')], ['keep', t('portsLegendKeep')],
  ].map(([cls, text]) => `<span class="face-key"><i class="pport ${cls}">${cls === 'locked' ? '\u2715' : (cls === 'slow half' ? '\u00bd' : '')}</i>${esc(text)}</span>`).join('');

  // One line at the top of the dialog. Four numbers describe this switch completely.
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

/** The one picked port. A one-line summary and the buttons that apply, nothing else.
    Before a port is picked it does not appear at all — an empty panel is clutter too. */
function renderDetail() {
  const panel = $('#portsDetail');
  const row = (portsData.rows || []).find(r => String(r.index) === String(pickedPort));
  if (!row) { panel.hidden = true; panel.innerHTML = ''; return; }

  const state = portStateLabel(row);
  // Duplex is written only when we know it. 3 (full) gets tucked quietly alongside;
  // 0 (the switch never told us) says nothing at all.
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

  // There is exactly one case where we may say "unknown device" —
  // the switch gave us a MAC (fdbOk) and that MAC is not in our list.
  //
  // If we could not read the MAC at all, we simply do not know; that is not the same
  // as absent. Warn there and every port gets a red tag, burying what really matters.
  const seen = row.devices || [];
  const strangers = seen.filter(d => !d.ip);
  const ghost = portsData.fdbOk && row.oper === 1 && seen.length && !seen.some(d => d.ip)
    ? `<div class="pd-ghost">${esc(t('portsGhost', { n: strangers.length }))}</div>` : '';

  // Our record that this port used to be faster. Not a guess but a fact we wrote
  // down, so it gets its own prominent spot. A 'this is normal' button sits beside
  // it — a port deliberately holding a 100M device, left red forever, kills red.
  //
  // Two grounds. wasSpeed is our record that "this port used to run faster", so it
  // is certain; slowLink is the guess that "it is slower than its neighbours". As
  // long as both paint red, both have to be silenceable with "this is normal". With
  // no way to clear a port reddened by a guess, that red stays forever and is ignored.
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

  // Half duplex. Sits next to the slow link but stands apart — the fix is different.
  // A slow link means reterminating the cable; half duplex means matching both ends.
  // Tear into the cable here and you reterminate a good run twice and still not fix it.
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

/* The refresh called while we are watching.

   The panel below (renderDetail) replaces its innerHTML wholesale. But the buttons
   in it go disabled the moment they are pressed, to stop a double press. Redraw
   while the request is still in flight and a fresh, unlocked button appears — an
   impatient hand presses again and cuts PoE twice, or power-cycles the camera
   twice. So while something is in progress only the faceplate is redrawn. */
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
  linkEpoch += 1;            // another switch opened means the earlier watch is over
  $('#snmpDialog').hidden = true;
  renderPorts();
  clearSay();
  $('#portsDialog').hidden = false;
  notice(t('ready'));
}

$('#portsBtn').addEventListener('click', openPorts);
const closePorts = () => {
  $('#portsDialog').hidden = true;
  // Disarm the pending 'lock them all'. Otherwise close the dialog, reopen it, press
  // once, and everything locks with no confirmation.
  clearTimeout(lockFreeTimer);
  lockFreeArmed = false;
  linkEpoch += 1;              // the link watch stops with it
  $('#portsLockFree').textContent = t('portsLockFree');
  $('#portsLockFree').classList.remove('danger-btn');
};
$('#portsClose').addEventListener('click', closePorts);
$('#portsOk').addEventListener('click', closePorts);
closeOnBackdrop('portsDialog', closePorts);

/** Lock or unlock one port. On success only that row is redrawn. */
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
  // Only ports with no link and no reason to keep them. This is the handover button.
  const targets = portsData.rows.filter(r => r.oper !== 1 && r.admin !== 2 && !r.blocked);
  if (!targets.length) return notice(t('portsLockNone'), true);
  if (!$('#portsCommunity').value.trim()) return notice(t('portsNeedComm'), true);
  // It shuts several ports at once, so it asks twice. Instead of a dialog the button
  // asks by itself, and if it is not pressed again within 4 seconds it never happened.
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

/* Unlocking a port does not bring traffic straight back.

   Both ends renegotiate speed (autoneg) for 2-3 seconds. Then, while the switch
   checks for loops (STP), the link is up but no data flows — on defaults that alone
   runs up to 30 seconds. End the screen at "unlocked" and the tech says the camera
   is not coming up and starts poking a healthy port. So we watch it come up and say so. */

const LINK_WAIT_MS = 45000;
const LINK_POLL_MS = 2500;
let linkEpoch = 0;                 // bumped when the dialog closes or another switch opens
const linkWatching = new Set();    // ports being watched right now

async function watchLink(index, label) {
  // At handover you unlock three or four ports in a row. Drop the previous watch
  // each time and the rest are left with "unlocked" and no word on whether they
  // came up. So each port is watched separately.
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
      // Dialog closed or another switch opened — stop quietly.
      if (era !== linkEpoch || $('#portsDialog').hidden) return;
      let now;
      try { now = await window.ipfix.request('port_link', { switch: host, community, index }); }
      catch (_) { continue; }            // one missed read is no reason to give up
      if (era !== linkEpoch) return;
      // read false means we failed to read this time. Write that down as 'no link' and
      // the port looks empty, and 'lock all empty ports' swallows it.
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
    // The switch is not touched — only our own baseline drops to the current speed.
    // That is why no write community string is needed.
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
        // After an unlock, watch to the end whether the link actually comes up. The
        // dialog has to stay usable while waiting, so we do not block on it.
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
  } catch (_) { /* call() already shows the message */ }
  finally { button.disabled = false; }
});
