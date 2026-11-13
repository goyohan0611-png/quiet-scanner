// Run after test_tauri_ui.cjs against the same debug WebView on port 9227.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');

(async () => {
  let page;
  const pageDeadline=Date.now()+15000;
  while(!page&&Date.now()<pageDeadline) {
    try { const pages=await fetch('http://127.0.0.1:9227/json/list').then(response=>response.json());page=pages.find(item=>item.type==='page'&&item.url==='http://tauri.localhost/'); } catch (_) {}
    if(!page)await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.ok(page);
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve,reject) => { socket.onopen = resolve; socket.onerror = reject; });
  const pending = new Map(); let id = 0;
  socket.onmessage = event => {
    const message = JSON.parse(event.data); const entry = pending.get(message.id);
    if (entry) { pending.delete(message.id); message.error ? entry.reject(message.error) : entry.resolve(message.result); }
  };
  const send = (method,params) => new Promise((resolve,reject) => { const key=++id;pending.set(key,{resolve,reject});socket.send(JSON.stringify({id:key,method,params})); });
  const evaluate = async expression => {
    const result = await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  const server = net.createServer(connection => connection.end());
  let listening = false;
  try {
    let ready=false;
    const deadline=Date.now()+15000;
    while(!ready&&Date.now()<deadline) {
      try { ready=await evaluate("typeof selectedCard === 'function' && !!selectedCard()?.ips?.length && !interfacesLoading && !scanRunning && !operationRunning"); } catch (_) {}
      if(!ready)await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.ok(ready,'app initialized');
    const local = await evaluate(`(async()=>{
      const card=selectedCard();const ip=card.ips[0];
      if(!state.groups.some(group=>group.ip===ip))applyState(await window.ipfix.request('scan',{iface:card,target:ip}));
      closeDiagnostic();return ip;
    })()`);
    await new Promise((resolve,reject) => { server.once('error',reject);server.listen(0,local,resolve); }); listening=true;
    const port = server.address().port;
    const result = await evaluate(`(async () => {
      const query = selector => document.querySelector(selector);
      const check = (ok,message) => { if (!ok) throw new Error(message); };
      const wait = async predicate => { const end=Date.now()+8000;while(!predicate()) { if(Date.now()>end) throw new Error('Diagnostic UI wait timed out');await new Promise(resolve=>setTimeout(resolve,20)); } };
      const open = mode => {
        const row=query('[data-copy-ip="${local}"]').closest('.solo-row');
        row.dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,clientX:80,clientY:160}));
        check(!query('#contextMenu').hidden,'context menu must open');
        query('[data-menu="'+mode+'"]').click();
      };
      open('ping');
      check(getComputedStyle(query('#tcpForm')).display==='none','TCP form must be hidden in Ping mode');
      await wait(()=>/전송 [2-9]/.test(query('#pingSummary').textContent));
      check(query('#diagnosticResult .success'),'real ICMP response is rendered');
      query('#pingToggle').click();
      await wait(()=>query('#pingToggle').textContent==='다시 시작');
      const stopped=query('#pingSummary').textContent;
      await new Promise(resolve=>setTimeout(resolve,1100));
      check(query('#pingSummary').textContent===stopped,'stop must prevent further probes');
      query('#pingToggle').click();
      await wait(()=>/전송 [1-9]/.test(query('#pingSummary').textContent));
      query('#diagnosticOk').click();
      await wait(()=>!query('#scanBtn').disabled);
      check(query('#diagnosticDialog').hidden,'closing Ping stops and closes the dialog');
      open('tcp');
      check(query('#pingToggle').hidden,'Ping controls must be hidden in TCP mode');
      query('#tcpPort').value='${port}';query('#tcpRun').click();
      await wait(()=>!query('#tcpRun').disabled && query('#diagnosticResult .success'));
      check(query('#diagnosticResult').textContent.includes('TCP 연결 성공'),'open port must show a successful native TCP connection');
      return { ping:stopped,tcp:query('#diagnosticResult').textContent,port:${port},local:'${local}' };
    })()`);
    await new Promise((resolve,reject) => server.close(error => error ? reject(error) : resolve())); listening=false;
    result.closed = await evaluate(`(async () => {
      document.querySelector('#tcpRun').click();
      const end=Date.now()+5000;
      while(document.querySelector('#tcpRun').disabled) { if(Date.now()>end) throw new Error('TCP close check timed out');await new Promise(resolve=>setTimeout(resolve,20)); }
      const text=document.querySelector('#diagnosticResult').textContent;
      if (!/연결 거부|시간 초과/.test(text)) throw new Error('Closed listener must not be reported open: '+text);
      return text;
    })()`);
    fs.mkdirSync('_smoke',{recursive:true});
    result.terminal = await evaluate(`(async () => {
      closeDiagnostic();
      const query=selector=>document.querySelector(selector);
      const end=Date.now()+8000;
      const row=query('[data-copy-ip="${local}"]').closest('.solo-row');
      row.dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,clientX:80,clientY:160}));query('[data-menu="ping"]').click();
      while(!query('#diagnosticResult .success')){if(Date.now()>end)throw new Error('Ping display timed out');await new Promise(resolve=>setTimeout(resolve,20));}
      if(query('#pingSummary').querySelectorAll('.ping-metric').length!==4)throw new Error('Ping metrics must remain above the terminal');
      if(!query('.ping-sequence'))throw new Error('Terminal must show request sequence');
      const clock=query('#diagnosticResult time');
      if(clock.textContent.length!==8||clock.textContent.split(':').length!==3||clock.getBoundingClientRect().height>24)throw new Error('Clock must stay on one compact line');
      return 'compact time, request sequence and four metrics verified';
    })()`);
    const pingShot=await send('Page.captureScreenshot',{format:'png'});
    fs.writeFileSync('_smoke/tauri-ping-terminal.png',Buffer.from(pingShot.data,'base64'));
    fs.writeFileSync('_smoke/tauri-diagnostics.json',JSON.stringify(result,null,2));
    await evaluate('closeDiagnostic()');
    console.log(JSON.stringify(result,null,2));
  } finally {
    if (listening) server.close();
    socket.close();
  }
})().catch(error => { console.error(error);process.exitCode=1; });
