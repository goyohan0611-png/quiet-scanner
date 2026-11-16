(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const paths = {
    shield:'M12 3 4.5 6v5c0 4.5 3 7.8 7.5 10 4.5-2.2 7.5-5.5 7.5-10V6L12 3Z M8.5 12l2.3 2.3 4.7-5',
    overview:'M3.5 3.5h7v7h-7z M14 3.5h6.5v7H14z M3.5 14h7v6.5h-7z M14 14h6.5v6.5H14z',
    network:'M9 3.5h6v5H9z M3.5 15.5h6v5h-6z M14.5 15.5h6v5h-6z M12 8.5v4 M6.5 15.5v-3h11v3',
    history:'M3.5 5.5v5h5 M4.2 10a8 8 0 1 1 .8 7 M12 7v5l3 2',
    server:'M4 4h16v6H4z M4 14h16v6H4z M7 7h.01 M7 17h.01 M11 7h6 M11 17h6',
    refresh:'M19.5 4.5v5h-5 M4.5 19.5v-5h5 M19 9a7.5 7.5 0 0 0-13-3 M5 15a7.5 7.5 0 0 0 13 3',
    logout:'M10 4H4v16h6 M8 12h12 M16 8l4 4-4 4',
    arrow:'M5 12h14 M14 7l5 5-5 5',
    info:'M12 8h.01 M12 11v6 M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z',
    eye:'M2.5 12s3.5-7 9.5-7 9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7Z M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',
    check:'M5 12l4 4L19 6',
    warning:'M12 3 2.5 20h19L12 3Z M12 9v5 M12 17h.01',
    search:'M15.5 15.5 21 21 M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z',
    download:'M12 3v12 M7 10l5 5 5-5 M4 15v5h16v-5',
    globe:'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z M3 12h18 M12 3c4 4 4 14 0 18-4-4-4-14 0-18Z',
    key:'M14.5 3.5a6 6 0 1 1-5.8 7.5L3 16.5V21h4v-3h3v-3l1.4-1.4 M16.5 7.5h.01'
  };
  const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="${paths[name] || paths.info}"/></svg>`;
  const icons = () => document.querySelectorAll('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); });
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const names = {prepare_dependencies:'필수 프로그램 준비',exposure_enable:'노출 점검 켜기',exposure_check:'노출 점검 실행',exposure_disable:'노출 점검 끄기',ssh_enable:'SSH 접속 보호 켜기',ssh_disable:'SSH 접속 보호 끄기',waf_enable:'웹 요청 검사 연결',waf_disable:'웹 요청 검사 끄기',agent_restart:'상태 수집 다시 시작'};
  const jobNames = {running:'진행 중',succeeded:'완료',failed:'실패',interrupted:'확인 필요'};
  const copy = {overview:['서버 개요','보호 상태와 확인할 항목을 함께 살펴보세요.'],protection:['보호 설정','필요한 기능을 연결하고 실제 동작을 확인하세요.'],exposure:['노출 점검','열린 포트와 실행 프로그램, 확인 범위를 살펴보세요.'],history:['작업 기록','설정 변경과 점검 결과를 확인하세요.']};
  let token = sessionStorage.getItem('quiet-guard-access') || '';
  let data = null, view = 'overview', online = false, pending = false, toastTimer, polling = false;
  let acknowledgedJobs = new Set();
  const formatTime = seconds => seconds ? new Date(seconds * 1000).toLocaleTimeString('ko-KR',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '—';
  const active = () => data?.jobs?.find(j => j.status === 'running');
  const busy = () => pending || !!active();
  function toast(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').hidden = true, 5500); }
  function setView(next) {
    if (!copy[next]) next = 'overview'; view = next;
    document.querySelectorAll('.view').forEach(el => el.hidden = el.id !== `view-${next}`);
    document.querySelectorAll('nav [data-view]').forEach(el => { if (el.dataset.view === next) el.setAttribute('aria-current','page'); else el.removeAttribute('aria-current'); });
    $('page-title').textContent = copy[next][0]; $('page-description').textContent = copy[next][1];
    if (next === 'exposure') renderTable();
  }
  async function api(path, body) {
    const response = await fetch(path,{method:body ? 'POST' : 'GET',headers:{'Authorization':`Bearer ${token}`,...(body ? {'Content-Type':'application/json'} : {})},body:body ? JSON.stringify(body) : undefined,cache:'no-store',signal:AbortSignal.timeout(6500)});
    let result; try { result = await response.json(); } catch { result = {}; }
    if (!response.ok) { const error = new Error(result.error || (response.status === 422 ? '입력한 IP 주소와 포트 형식을 확인해 주세요.' : '요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.')); error.status = response.status; throw error; }
    return result;
  }
  function stateOf(kind) {
    if (!online) return ['neutral','연결 확인 필요'];
    const s = data?.[kind] || {}, state = s.state;
    if (kind === 'exposure') {
      if (state === 'off') return ['neutral','꺼짐']; if (state === 'not_configured') return ['neutral','설정 전'];
      if (state === 'unknown') return ['warn','상태 확인 필요']; if (s.risk === 'attention') return ['warn','검토 항목 있음'];
      if (state === 'incomplete') return ['warn','일부 확인']; if (state === 'local_and_operator_probe') return ['good','연결 결과 확인']; return ['good','로컬 점검 완료'];
    }
    return ({verified:['good','동작 확인'],off:['neutral','꺼짐'],not_configured:['neutral','설정 전'],awaiting_external_check:['warn','외부 확인 대기'],degraded:['warn','일부 검사 제한'],unknown:['warn','상태 확인 필요']})[state] || ['neutral','확인 중'];
  }
  function badge(kind) { const [tone,label] = stateOf(kind); return `<span class="state-badge ${tone}"><i class="status-dot"></i>${label}</span>`; }
  const configured = kind => !!data?.configured?.[kind];
  const isOff = kind => ['off','not_configured'].includes(data?.[kind]?.state);
  function serviceDescription(kind) {
    const s = data?.[kind] || {};
    if (kind === 'ssh') return s.state === 'verified' ? `SSH 포트의 탐지·차단을 확인했어요.${s.blocked_ips == null ? '' : ` 현재 차단 ${s.blocked_ips.toLocaleString()}개.`}` : '반복 로그인 공격을 감지하고 등록한 SSH 포트에서 차단해요.';
    if (kind === 'waf') return s.state === 'awaiting_external_check' ? '검사를 연결했어요. 별도 PC에서 실제 접속 경로를 확인해 주세요.' : s.state === 'degraded' ? '최근 검사 실패 또는 완전히 검사하지 못한 요청이 있어요.' : '웹 요청을 검사하고 알려진 공격 요청을 차단해요.';
    if (s.state === 'unknown') return '최근 점검 결과가 없거나 유효 시간이 지났어요. 다시 점검해 주세요.';
    return s.listener_count == null ? '앱·DB·관리 포트가 어떤 주소에 열려 있는지 살펴봐요.' : `수신 포트 ${s.listener_count.toLocaleString()}개 · 검토 항목 ${(s.review_count || 0).toLocaleString()}개. 외부 접근은 별도 증거예요.`;
  }
  function serviceRows(settings) {
    return [['ssh','key','SSH 접속 보호'],['waf','globe','웹 요청 검사'],['exposure','network','노출 점검']].map(([kind,symbol,title]) => {
      const off = isOff(kind), setup = !configured(kind);
      let button = settings ? `<button class="button ${off ? 'secondary' : 'quiet'}" data-service="${kind}" data-operation="${off ? 'enable' : 'disable'}">${off ? (setup ? '설정하기' : '다시 켜기') : '끄기'}</button>` : `<button class="button quiet" data-service="${kind}" data-operation="manage">${setup ? '설정하기' : '관리'}</button>`;
      if (settings && kind === 'exposure' && !off) button = `<button class="button quiet" data-service="exposure" data-operation="check">다시 점검</button>${button}`;
      return `<div class="service-row"><span class="service-symbol">${icon(symbol)}</span><div class="service-info"><strong>${title}</strong><p>${esc(serviceDescription(kind))}</p></div>${badge(kind)}<div class="service-actions">${button}</div></div>`;
    }).join('');
  }
  function empty(title,description) { return `<div class="empty-state"><strong>${esc(title)}</strong>${esc(description)}</div>`; }
  function findingText(f) {
    if (f.evidence === 'connected_from_one_operator_probe') return '한 외부 출발지에서 TCP 접속 성공을 보고했어요. 의도한 공개 서비스인지 확인해 주세요.';
    if (f.category === 'database_process' || f.category === 'cache_process') return '데이터 저장 서비스가 루프백 외 주소에 열려 있어요. 필요한 접근 범위를 확인해 주세요.';
    if (f.category === 'application_process') return '앱 프로세스가 별도 주소에서 접속을 기다려요. 웹 검사 경로를 우회할 수 있는지 확인해 주세요.';
    return '루프백 외 주소에 바인딩돼 있어요. 실제 외부 접속 여부와 필요한 공개 범위를 확인해 주세요.';
  }
  function renderFindings() {
    const findings = (data.findings || []).filter(f => f.severity === 'review');
    $('nav-count').hidden = !findings.length; $('nav-count').textContent = findings.length;
    $('priority-findings').innerHTML = findings.length ? findings.slice(0,3).map(f => `<div class="finding-row"><span class="finding-marker">${icon('warning')}</span><div><strong>${esc(f.address || '주소 확인 필요')}:${esc(f.port)} <span class="muted">· ${esc(String(f.transport).toUpperCase())}</span></strong><p>${esc(findingText(f))}</p></div></div>`).join('') : empty(configured('exposure') ? '표시할 검토 항목이 없어요' : '노출 점검을 시작해 주세요',configured('exposure') ? '확인 범위 안의 결과예요. 다른 경로나 앱 권한까지 안전하다는 뜻은 아니에요.' : '열린 앱·DB 포트를 살펴보고 필요한 항목을 여기에 표시해요.');
  }
  function jobRows(jobs, full) {
    if (!jobs?.length) return empty('아직 작업 기록이 없어요','보호 설정을 변경하거나 점검하면 결과를 여기에 표시해요.');
    return jobs.map(j => {
      const tone = j.status === 'succeeded' ? 'good' : j.status === 'failed' ? 'bad' : 'neutral';
      if (!full) return `<div class="job-row"><span class="job-marker ${tone}">${icon(j.status === 'succeeded' ? 'check' : 'history')}</span><div class="job-info"><strong>${esc(names[j.action] || '관리 작업')}</strong><p>${esc(jobNames[j.status] || '확인 필요')}</p></div><span class="job-time">${formatTime(j.finished || j.started)}</span></div>`;
      return `<div class="history-row" data-job-id="${esc(j.id)}"><div class="history-head"><strong>${esc(names[j.action] || '관리 작업')}</strong><span class="state-badge ${tone}">${esc(jobNames[j.status] || '확인 필요')}</span><span class="job-time">${formatTime(j.started)}${j.finished ? ` → ${formatTime(j.finished)}` : ''}</span></div>${j.status === 'interrupted' ? '<p>관리 연결이 중단된 작업이에요. 현재 보호 상태를 먼저 확인해 주세요.</p>' : ''}${j.output ? `<details><summary>진단 내용 보기</summary><pre>${esc(j.output)}</pre></details>` : ''}</div>`;
    }).join('');
  }
  function renderTable() {
    if (!data) return;
    const query = $('filter').value.trim().toLowerCase(), all = data.listeners || [];
    const rows = all.filter(row => `${row.address} ${row.port} ${(row.owners || []).map(o => o.executable).join(' ')}`.toLowerCase().includes(query));
    $('listener-count').textContent = `${rows.length.toLocaleString()}개 표시`;
    $('listener-rows').innerHTML = rows.length ? rows.map(row => {
      const findings = (data.findings || []).filter(f => f.port === row.port && f.transport === row.transport && f.address === row.address && f.severity === 'review');
      const loopback = row.address === '::1' || /^127\./.test(row.address), wildcard = row.address === '0.0.0.0' || row.address === '::';
      const owners = [...new Set((row.owners || []).map(o => o.executable))].join(', ') || '확인되지 않음';
      return `<tr class="${findings.length ? 'review' : ''}"><td class="address">${esc(row.address.includes(':') ? `[${row.address}]` : row.address)}:${esc(row.port)}</td><td>${esc(String(row.transport).toUpperCase())}</td><td>${esc(owners)}</td><td>${loopback ? '루프백 전용' : wildcard ? '모든 인터페이스' : '특정 인터페이스'}</td><td><span class="${findings.length ? 'state-badge warn' : 'muted'}">${findings.length ? '공개 범위 검토' : loopback ? '로컬 바인딩' : '범위 확인'}</span></td></tr>`;
    }).join('') : `<tr><td colspan="5" class="table-empty">${all.length ? '검색 조건에 맞는 포트가 없어요.' : '노출 점검을 켜고 실행하면 포트 목록이 나타나요.'}</td></tr>`;
    $('table-message').textContent = `${data.exposure?.state === 'unknown' ? '이전 점검 정보일 수 있어요. 현재 상태를 다시 확인해 주세요. ' : ''}${data.exposure_truncated ? '목록 일부만 표시하고 있어요. ' : ''}바인딩은 외부 접속 성공을 뜻하지 않아요. UDP는 로컬 바인딩만 확인해요.`;
    $('exposure-description').textContent = data.exposure?.external_probe_current ? '운영자가 제공한 외부 TCP 결과도 있어요. 한 출발지에서 확인한 시점의 증거예요.' : '현재는 로컬 바인딩 정보예요. 외부 접근 가능 여부는 별도 확인이 필요해요.';
  }
  function controls() {
    document.querySelectorAll('[data-service], #prepare-dependencies, #exposure-run, #ssh-form button[type=submit], #waf-form button[type=submit]').forEach(el => el.disabled = !online || busy());
  }
  function render() {
    const focused = document.activeElement?.closest('[data-service]');
    const focusKey = focused ? [focused.dataset.service,focused.dataset.operation] : null;
    const expanded = [...document.querySelectorAll('#history-jobs details[open]')].map(el => el.closest('[data-job-id]').dataset.jobId);
    $('hostname').textContent = data.server?.hostname || '서버'; $('platform').textContent = data.server?.platform || 'Linux'; $('version').textContent = data.version || '개발판';
    $('preview-banner').hidden = !data.preview; $('updated').textContent = `${formatTime(data.updated)} 확인`;
    const connected = online && data.agent?.agent === 'running';
    $('connection').innerHTML = `<i class="status-dot ${connected ? 'good' : 'neutral'}"></i>${connected ? '서버 연결됨' : online ? '상태 수집 확인 필요' : '연결 끊김'}`;
    const verified = ['ssh','waf'].filter(k => data[k]?.state === 'verified').length;
    $('protection-summary').textContent = !online ? '현재 상태 확인 필요' : verified ? '일부 보호 확인' : ['ssh','waf'].every(isOff) ? '보호 설정 필요' : '동작 확인 필요';
    $('protection-summary').className = !online ? 'neutral' : verified ? 'good' : 'warn';
    $('protection-detail').textContent = verified ? `SSH·웹 검사 중 ${verified}개 기능의 동작을 확인했어요.` : '필요한 보호를 켜고 실제 동작을 확인해 주세요.';
    const count = data.exposure?.review_count || 0;
    $('risk-summary').textContent = !online ? '현재 상태 확인 필요' : data.exposure?.risk === 'attention' ? `${count.toLocaleString()}개 항목 검토 필요` : ['not_configured','off'].includes(data.exposure?.state) ? '노출 점검 필요' : data.exposure?.state === 'unknown' ? '점검 결과 확인 필요' : '확인 범위 살펴보기';
    $('risk-summary').className = online && count ? 'warn' : 'neutral'; $('risk-detail').textContent = '서비스의 의도한 공개 범위와 비교해 주세요.';
    const ready = Object.values(data.prerequisites || {}).every(Boolean), anyConfigured = Object.values(data.configured || {}).some(Boolean);
    $('onboarding').hidden = anyConfigured && verified > 0; $('step-ready').classList.toggle('done',ready); $('step-configure').classList.toggle('done',anyConfigured); $('step-verify').classList.toggle('done',verified > 0);
    $('overview-services').innerHTML = serviceRows(false); $('setting-services').innerHTML = serviceRows(true);
    const prerequisites = [['crowdsec','공격 검사 엔진'],['nginx','Nginx 웹 서버'],['lua','웹 검사 연결 모듈'],['nftables','SSH 차단 도구']];
    $('prerequisite-list').innerHTML = prerequisites.map(([key,label]) => `<div class="prerequisite-item ${data.prerequisites?.[key] ? '' : 'missing'}">${icon(data.prerequisites?.[key] ? 'check' : 'info')}<span>${label}</span><small>${data.prerequisites?.[key] ? '설치됨' : '준비 필요'}</small></div>`).join('');
    renderFindings(); $('recent-jobs').innerHTML = jobRows((data.jobs || []).slice(0,3),false); $('history-jobs').innerHTML = jobRows(data.jobs,true); renderTable();
    for (const row of document.querySelectorAll('#history-jobs [data-job-id]')) if (expanded.includes(row.dataset.jobId)) row.querySelector('details')?.setAttribute('open','');
    if (focusKey) document.querySelector(`#${view === 'protection' ? 'setting' : 'overview'}-services [data-service="${focusKey[0]}"][data-operation="${focusKey[1]}"]`)?.focus({preventScroll:true});
    const job = active(); $('active-job').hidden = !job; if (job) { $('active-job-label').textContent = `${names[job.action] || '관리 작업'} 진행 중`; $('active-job-elapsed').textContent = `${Math.max(0,Math.floor(Date.now()/1000 - job.started))}초 경과`; }
    controls();
  }
  async function load(first = false) {
    if (polling || !token) return; polling = true;
    try {
      const next = await api('/api/state'); online = true; $('offline-banner').hidden = true;
      if (!first && data) for (const j of next.jobs || []) if (['succeeded','failed'].includes(j.status) && !acknowledgedJobs.has(j.id) && data.jobs?.some(old => old.id === j.id && old.status === 'running')) toast(`${names[j.action] || '작업'}${j.status === 'succeeded' ? ' 완료했어요.' : '에 실패했어요. 작업 기록에서 진단 내용을 확인해 주세요.'}`);
      data = next; acknowledgedJobs = new Set((data.jobs || []).filter(j => j.status !== 'running').map(j => j.id));
      $('login').hidden = true; $('app').hidden = false; sessionStorage.setItem('quiet-guard-access',token); render();
    } catch (error) {
      online = false;
      if (error.status === 401) { sessionStorage.removeItem('quiet-guard-access'); token = ''; $('app').hidden = true; $('login').hidden = false; $('login-error').textContent = error.message; }
      else if (data) { $('offline-banner').hidden = false; render(); }
      else $('login-error').textContent = '서버에 연결하지 못했습니다. 접속 주소와 관리 서비스를 확인해 주세요.';
    } finally { polling = false; controls(); }
  }
  function confirm(title,description,label = '계속',danger = false) {
    return new Promise(resolve => {
      $('confirm-title').textContent = title; $('confirm-description').textContent = description; $('confirm-action').textContent = label; $('confirm-action').className = `button ${danger ? 'danger' : 'primary'}`;
      const dialog = $('confirm'); dialog.returnValue = ''; dialog.addEventListener('close',() => resolve(dialog.returnValue === 'confirm'),{once:true}); dialog.showModal();
    });
  }
  async function perform(body) {
    if (data?.preview) return toast('화면 미리보기예요. 실제 서버에서는 설정과 점검을 실행할 수 있어요.');
    if (!online || busy()) return;
    pending = true; controls();
    try { await api('/api/actions',body); toast('작업을 시작했어요. 진행 상태를 확인해 주세요.'); await load(); }
    catch (error) { toast(error.message); }
    finally { pending = false; controls(); }
  }
  async function service(kind,operation) {
    if (operation === 'manage') { setView('protection'); if (!configured(kind) && kind !== 'exposure') openSetup(kind); return; }
    if (operation === 'check') return perform({action:'exposure_check'});
    if (operation === 'disable') {
      if (kind !== 'exposure' && !await confirm(`${kind === 'ssh' ? 'SSH 접속 보호' : '웹 요청 검사'}를 끌까요?`,kind === 'ssh' ? '이후 SSH 공격 탐지와 해당 기능의 차단이 중단돼요. 서버의 SSH 서비스는 계속 실행돼요.' : '웹 요청 검사를 해제하고 보관한 Nginx 설정을 복원해요. 사용자가 바꾼 설정이 있으면 자동으로 덮어쓰지 않고 확인이 필요해요.','보호 끄기',true)) return;
      return perform({action:`${kind}_disable`,...(kind !== 'exposure' ? {confirmed:true} : {})});
    }
    if (kind === 'exposure') return perform({action:'exposure_enable'});
    if (!configured(kind)) return openSetup(kind);
    return perform(kind === 'ssh' ? {action:'ssh_enable',management_ips:[],ports:[],direct:false} : {action:'waf_enable',probe_peer:null,sites:[],direct:false});
  }
  function openSetup(kind) { setView('protection'); for (const key of ['ssh','waf']) $(`${key}-setup`).hidden = key !== kind; const region = $(`${kind}-setup`); region.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth',block:'nearest'}); region.querySelector('input,textarea').focus({preventScroll:true}); }
  document.addEventListener('click',event => { const viewButton = event.target.closest('[data-view],[data-go]'); if (viewButton) setView(viewButton.dataset.view || viewButton.dataset.go); const button = event.target.closest('[data-service]'); if (button) service(button.dataset.service,button.dataset.operation); const close = event.target.closest('[data-close]'); if (close) $(close.dataset.close).hidden = true; });
  $('filter').addEventListener('input',renderTable);
  $('refresh').addEventListener('click',() => load());
  ['logout','logout-mobile'].forEach(id => $(id).addEventListener('click',() => { token = ''; sessionStorage.removeItem('quiet-guard-access'); data = null; online = false; $('app').hidden = true; $('login').hidden = false; $('access-key').value = ''; $('login-error').textContent = ''; }));
  $('login-form').addEventListener('submit',event => { event.preventDefault(); token = $('access-key').value.trim(); if (!/^[a-f0-9]{64}$/i.test(token)) { $('login-error').textContent = '서버에서 확인한 64자리 접속 키를 입력해 주세요.'; return; } load(true); });
  $('prepare-dependencies').addEventListener('click',async () => { if (await confirm('필수 프로그램을 준비할까요?','검사 엔진과 Nginx 연결 모듈을 내려받고 설치해요. 패키지 설치 중 웹 서버가 다시 설정을 읽을 수 있어요. 기존 보호 기능을 자동으로 켜지는 않아요.','프로그램 준비')) perform({action:'prepare_dependencies'}); });
  $('exposure-run').addEventListener('click',() => perform({action:configured('exposure') && !isOff('exposure') ? 'exposure_check' : 'exposure_enable'}));
  $('ssh-form').addEventListener('submit',event => { event.preventDefault(); const ports = $('ssh-ports').value.split(/[\s,]+/).filter(Boolean).map(Number); if (!ports.length || ports.some(p => !Number.isInteger(p) || p < 1 || p > 65535)) return toast('SSH 포트는 1~65535 사이 숫자로 입력해 주세요.'); perform({action:'ssh_enable',management_ips:$('management-ips').value.split(/[\s,]+/).filter(Boolean),ports,direct:$('ssh-direct').checked}); });
  $('waf-form').addEventListener('submit',event => { event.preventDefault(); perform({action:'waf_enable',probe_peer:$('probe-peer').value.trim(),sites:$('web-sites').value.split(/\s+/).filter(Boolean),direct:$('waf-direct').checked}); });
  const fragment = new URLSearchParams(location.hash.slice(1)).get('access'); if (fragment) { token = fragment; history.replaceState(null,'',location.pathname); }
  icons(); setView('overview'); if (token) load(true);
  setInterval(() => { if (!document.hidden && token) load(); },5000);
  document.addEventListener('visibilitychange',() => { if (!document.hidden && token) load(); });
})();
