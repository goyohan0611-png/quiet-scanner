const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

(async () => {
  let deliver, register;
  const registered = new Promise(resolve => { register = resolve; });
  const invoked = [];
  const window = { __TAURI__: {
    event: { listen: async (name, callback) => { assert.equal(name, 'network:state'); deliver = callback; await registered; return () => {}; } },
    core: { invoke: async (command, args) => { invoked.push([command, args]); if (args?.action === 'fail') throw 'native failure'; return { ok: true }; } }
  } };
  vm.runInNewContext(fs.readFileSync('electron/renderer/tauri-bridge.js', 'utf8'), { window, Error });
  let state;
  const off = window.ipfix.onState(value => { state = value; });
  const pending = window.ipfix.request('interfaces');
  assert.equal(invoked.length, 0, 'request waits for event subscription');
  register(); await pending;
  assert.equal(invoked[0][0], 'request'); assert.equal(invoked[0][1].action, 'interfaces');
  deliver({ payload: { groups: [1] } }); assert.deepEqual(state, { groups: [1] });
  off(); deliver({ payload: { groups: [2] } }); assert.deepEqual(state, { groups: [1] });
  await assert.rejects(window.ipfix.request('fail'), /native failure/);
  await window.ipfix.copyText('192.168.0.1'); assert.equal(invoked.at(-1)[0], 'copy_text');
  const legacy = { ipfix: { existing: true } };
  vm.runInNewContext(fs.readFileSync('electron/renderer/tauri-bridge.js', 'utf8'), { window: legacy });
  assert.equal(legacy.ipfix.existing, true);
  console.log('Tauri bridge: subscription, state, native errors, clipboard, legacy host passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
