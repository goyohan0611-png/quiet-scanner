// Run against a test app started with WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=
// --remote-debugging-port=9227. No neighbor-table writes are performed.
const assert = require('node:assert/strict');
const fs = require('node:fs');

(async () => {
  const targets = await fetch('http://127.0.0.1:9227/json/list').then(r => r.json());
  const page = targets.find(target => target.type === 'page' && target.title === 'Quiet Scanner');
  assert.ok(page, 'test WebView exists');
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let nextId = 0;
  const pending = new Map();
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    const waiter = pending.get(message.id);
    if (waiter) { pending.delete(message.id); message.error ? waiter.reject(message.error) : waiter.resolve(message.result); }
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId; pending.set(id, { resolve, reject }); socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async expression => {
    const answer = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (answer.exceptionDetails) throw new Error(JSON.stringify(answer.exceptionDetails));
    return answer.result.value;
  };
  try {
    if (process.argv.includes('--inspect')) {
      console.log(await evaluate(`JSON.stringify({progress:document.querySelector('#scanProgress').outerHTML,button:document.querySelector('#scanBtn').outerHTML,notice:document.querySelector('#notice').textContent,ready:typeof window.ipfix,body:document.body.innerText.slice(0,1600)})`));
      return;
    }
    const result = await evaluate(`(async () => {
      const query = selector => document.querySelector(selector);
      const check = (ok, message) => { if (!ok) throw new Error(message); };
      const wait = async predicate => {
        const end = Date.now() + 20000;
        while (!predicate()) { if (Date.now() > end) throw new Error('UI wait timed out'); await new Promise(resolve => setTimeout(resolve, 25)); }
      };
      await wait(() => !query('#scanBtn').disabled);
      check(query('#scanProgress').hidden, 'initial progress must be hidden');
      check(query('#ifaceBtn').textContent.includes('192.168.'), 'interface IP must be visible');
      const cards = await window.ipfix.request('interfaces');
      const current = cards.find(card => query('#ifaceBtn').textContent.includes(card.desc));
      check(current && current.ips.length, 'selected native interface exists');
      const local = current.ips[0];
      const gateway = local.split('.').slice(0,3).join('.') + '.1';
      query('#target').value = gateway + ',' + local;
      let eventCount = 0, firstFoundBeforeFinish = false;
      const progress = [];
      const stop = window.ipfix.onState(next => {
        eventCount++;
        if (Number.isFinite(next.progress.pct)) progress.push({pct:next.progress.pct,msg:next.progress.msg});
        if (next.groups.some(group => group.ip === gateway) && next.progress.phase === 'scan') firstFoundBeforeFinish = true;
      });
      query('#scanBtn').click();
      await wait(() => query('#scanProgress').hidden === false && query('#scanProgressText').textContent.includes('검색'));
      let busyRejected = false;
      try { await window.ipfix.request('interfaces'); } catch(error) { busyRejected = error.message.includes('진행 중'); }
      check(busyRejected, 'concurrent operation must be rejected');
      await wait(() => query('#scanBtn').textContent === '대역 스캔');
      stop();
      check(firstFoundBeforeFinish && eventCount > 2, 'live device state must arrive during scan');
      check(progress.some(point => point.pct > 0 && point.pct < 100 && point.msg.includes('주소 요청')), 'progress follows actual sent requests');
      check(progress.every((point,index) => !index || point.pct >= progress[index-1].pct), 'progress does not go backwards');
      check(query('.own-ip'), 'own IP is highlighted');
      check(query('#deviceList').textContent.includes(gateway), 'gateway row rendered');
      check(query('#logEntries').textContent.includes('스캔 완료'), 'scan completion logged');
      check(query('#scanProgress').hidden === false, 'completion progress remains briefly');
      await wait(() => query('#scanProgress').hidden);
      query('#bookBtn').click();
      await wait(() => !query('#bookDialog').hidden);
      check(query('#bookList').querySelectorAll('button').length > 10, 'device book rendered');
      query('#bookClose').click();
      query('#dhcpBtn').click();
      await wait(() => !query('#dhcpDialog').hidden);
      check(query('#dhcpSummary').textContent.includes('DHCP'), 'DHCP result rendered');
      const dhcp = query('#dhcpSummary').textContent;
      query('#dhcpOk').click();
      query('#refreshInterfaces').click();
      await wait(() => !query('#refreshInterfaces').disabled);
      check(query('#ifaceBtn').textContent.includes(local), 'interface refresh retains current card');
      return { interface: query('#ifaceBtn').textContent, eventCount, firstFoundBeforeFinish,
        rows: query('#deviceList').querySelectorAll('.solo-row,.device-row').length, dhcp, progress,
        progressHidden: query('#scanProgress').hidden, log: query('#logEntries').innerText };
    })()`);
    fs.mkdirSync('_smoke', { recursive: true });
    const screenshot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync('_smoke/tauri-ui.png', Buffer.from(screenshot.data, 'base64'));
    fs.writeFileSync('_smoke/tauri-ui.json', JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result, null, 2));
  } finally {
    fs.mkdirSync('_smoke', { recursive: true });
    const screenshot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync('_smoke/tauri-ui.png', Buffer.from(screenshot.data, 'base64'));
    socket.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
