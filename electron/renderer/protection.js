/* Optional Ubuntu host protection. UI state follows verified backend results. */
(() => {
  const el = id => document.getElementById(id);
  const dialog = el('protectionDialog');
  let status = { phase: 'unchecked', protecting: false };
  let busy = false;
  let authorized = false;
  let timer = null;
  let pending = null;
  let failures = 0;
  const labels = { unchecked: '상태 확인 필요', unsupported: '지원 예정', missing: '구성요소 설치 필요', unprepared: '보호 준비 필요', on: '보호 중', off: '보호 꺼짐', degraded: '보호 확인 필요', error: '상태 확인 실패' };

  function error(message = '') {
    el('protectionError').hidden = !message;
    el('protectionError').textContent = message;
  }
  function render() {
    const working = Boolean(pending);
    const phase = status.phase;
    el('protectionState').textContent = working ? (pending.target === 'on' ? '보호 시작 확인 중…' : '보호 해제 확인 중…') : (labels[phase] || labels.unchecked);
    el('protectionMessage').textContent = status.message || '관리자 승인 후 상태를 확인하십시오.';
    const badge = el('protectionBadge');
    badge.textContent = working ? '확인 중' : ({on:'켜짐',off:'꺼짐',unsupported:'Linux',error:'확인 실패',degraded:'확인 필요'}[phase] || '확인 필요');
    badge.classList.toggle('is-on', status.protecting === true && !working);
    badge.classList.toggle('is-error', ['degraded','error'].includes(phase));
    const toggle = el('protectionToggle');
    toggle.setAttribute('aria-checked', String(status.protecting === true));
    toggle.disabled = busy || working || !authorized || !status.prepared || !status.dependencies;
    toggle.setAttribute('aria-label', status.protecting ? '보호 모드 끄기' : '보호 모드 켜기');
    // A degraded/stopped service with residual rules must still offer OFF.
    toggle.dataset.stop = String(['on','degraded'].includes(phase));
    el('protectionRefresh').disabled = busy || status.supported === false;
    el('protectionPrepare').hidden = !status.supported || !status.dependencies || status.prepared;
    el('protectionPrepare').disabled = busy || working;
    el('protectionAllowAdd').disabled = busy || working || !authorized || !status.prepared;
    const checks = {engine:'탐지 엔진',service:'차단 서비스',boot:'재부팅 후 유지',connection:'엔진 연결',ipv4:'IPv4 규칙',ipv6:'IPv6 규칙',decisions:'차단 목록'};
    el('protectionChecks').innerHTML = Object.entries(status.checks || {}).map(([key,ok]) => `<span class="${ok ? 'ok' : 'unknown'}">${icon(ok ? 'check' : 'stop')}${esc(checks[key] || key)} ${ok ? '확인' : '미확인'}</span>`).join('');
    const rows = status.decisions || [];
    el('protectionCount').textContent = authorized ? `${rows.length}건` : '상태 확인 후 표시';
    el('protectionDecisions').innerHTML = rows.length ? rows.map(row => `<div class="protection-decision"><span><b>${esc(row.ip)}</b><small>${esc(row.reason || '차단 결정')} · ${esc(row.origin || 'CrowdSec')}</small></span><span class="protection-duration" title="엔진이 보고한 남은 시간">${esc(row.remaining || '—')}</span><button class="ghost protection-except" data-allow-ip="${esc(row.ip)}" ${busy || working ? 'disabled' : ''}>허용 예외</button></div>`).join('') : `<p class="dialog-empty">${authorized ? '현재 표시할 차단 결정이 없습니다.' : '상태 확인 후 목록이 표시됩니다.'}</p>`;
    el('protectionAllowlist').innerHTML = (status.allowlist || []).map(ip => `<div><span>${esc(ip)}</span><button class="ghost" data-remove-allow-ip="${esc(ip)}" ${busy || working ? 'disabled' : ''}>예외 삭제</button></div>`).join('');
    el('protectionChecked').textContent = status.checkedAt ? `확인 ${new Date(status.checkedAt).toLocaleTimeString('en-GB', {hour12:false})}` : '';
  }
  async function request(action, payload = {}) {
    if (busy) return null;
    busy = true; error(); render();
    try {
      const next = await window.ipfix.request(action, payload);
      if (!next || typeof next.supported !== 'boolean' || typeof next.phase !== 'string') throw new Error('보호 상태 응답을 확인하지 못했습니다.');
      status = next;
      authorized = action !== 'protection_info';
      failures = 0;
      if (pending && status.phase === pending.target) pending = null;
      return next;
    } catch (e) {
      failures += 1;
      // Never leave a stale green indicator after a failed verification.
      status = {...status, phase:'error', protecting:false, checks:{}, decisions:[], checkedAt:null};
      error(String(e.message || e));
      if (failures >= 3) { authorized = false; pending = null; }
      return null;
    } finally { busy = false; render(); }
  }
  function schedule() {
    clearTimeout(timer);
    if (!authorized || document.hidden) return;
    timer = setTimeout(async () => {
      if (pending && Date.now() > pending.deadline) {
        pending = null; error('요청한 보호 상태를 확인하지 못했습니다. 서버의 서비스·방화벽 상태를 다시 확인하십시오.'); render();
      }
      await request('protection_status'); schedule();
    }, pending ? 2000 : 10000);
  }
  function close() { dialog.hidden = true; schedule(); el('protectionBtn').focus(); }
  el('protectionBtn').addEventListener('click', async () => {
    dialog.hidden = false; dialog.querySelector('[role="dialog"]').focus();
    if (authorized) await request('protection_status');
    else await request('protection_info');
    el('protectionSetup').open = ['missing','unprepared'].includes(status.phase);
    schedule();
  });
  el('protectionClose').addEventListener('click', close);
  dialog.addEventListener('mousedown', event => { if (event.target === dialog) close(); });
  document.addEventListener('keydown', event => {
    if (dialog.hidden) return;
    if (event.key === 'Escape') { event.preventDefault(); close(); }
    if (event.key === 'Tab') {
      const controls = [...dialog.querySelectorAll('button:not(:disabled),input:not(:disabled),summary')].filter(e=>e.getClientRects().length);
      if (!controls.length) return;
      const first = controls[0], last = controls.at(-1);
      if (event.shiftKey && (document.activeElement === first || !controls.includes(document.activeElement))) {event.preventDefault();last.focus();}
      else if (!event.shiftKey && document.activeElement === last) {event.preventDefault();first.focus();}
    }
  });
  document.addEventListener('visibilitychange', schedule);
  el('protectionRefresh').addEventListener('click', async () => {await request('protection_status');schedule();});
  el('protectionPrepare').addEventListener('click', async () => {await request('protection_prepare');schedule();});
  el('protectionToggle').addEventListener('click', async () => {
    const stop = el('protectionToggle').dataset.stop === 'true';
    pending = {target:stop?'off':'on',deadline:Date.now()+45000};
    const result=await request(stop?'protection_disable':'protection_enable');
    if (!result) pending=null;
    render();schedule();
  });
  async function allow(ip) {
    // This confirmation concerns a concrete exemption, not the authorized build.
    if (!window.confirm(`${ip}을(를) 신뢰하는 주소로 등록할까요?\n이 서버의 CrowdSec 전체에서 기존 차단을 해제하고 향후 차단 대상에서 제외합니다.`)) return;
    await request('protection_allow',{ip});schedule();
  }
  el('protectionDecisions').addEventListener('click', event => {const ip=event.target.closest('[data-allow-ip]')?.dataset.allowIp;if(ip)void allow(ip);});
  el('protectionAllowForm').addEventListener('submit', async event => {event.preventDefault();const ip=el('protectionAllowIp').value.trim();if(ip)await allow(ip);});
  el('protectionAllowlist').addEventListener('click', async event => {const ip=event.target.closest('[data-remove-allow-ip]')?.dataset.removeAllowIp;if(ip){await request('protection_remove_allow',{ip});schedule();}});
  // Platform discovery never prompts for root or starts protection at launch.
  void request('protection_info');
})();
