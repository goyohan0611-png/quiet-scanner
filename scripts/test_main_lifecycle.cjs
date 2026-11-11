const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function load() {
  const events = {};
  const timers = [];
  let quits = 0;
  const app = {
    on: (name, listener) => { events[name] = listener; },
    whenReady: () => ({ then: () => {} }),
    quit: () => { quits++; },
  };
  const context = {
    require: name => name === 'electron'
      ? { app, ipcMain: { handle: () => {} } } : require(name),
    __dirname: path.resolve(__dirname, '../electron'),
    process: { platform: 'win32' },
    setTimeout: fn => { timers.push(fn); return timers.length; },
    clearTimeout: () => {},
  };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, '../electron/main.js'), 'utf8')
    + '\n globalThis.hooks = { backend: value => backend = value, request: value => request = value };', context);
  return { events, timers, hooks: context.hooks, quits: () => quits };
}

(async () => {
  const normal = load();
  let killed = 0, prevented = 0;
  const actions = [];
  normal.hooks.backend({ killed: false, kill: () => killed++ });
  normal.hooks.request(async action => { actions.push(action); });
  normal.events['before-quit']({ preventDefault: () => prevented++ });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(actions, ['cancel', 'release']);
  assert.equal(prevented, 1);
  assert.equal(killed, 1);
  assert.equal(normal.quits(), 1);
  normal.timers[0]();
  assert.equal(normal.quits(), 1, 'cleanup must finish only once');

  const hung = load();
  hung.hooks.backend({ killed: false, kill: () => {} });
  hung.hooks.request(() => new Promise(() => {}));
  hung.events['before-quit']({ preventDefault: () => {} });
  hung.timers[0]();
  assert.equal(hung.quits(), 1, 'a hung engine must not prevent closing forever');
  console.log('Main lifecycle: normal cleanup and bounded shutdown passed');
})().catch(error => { console.error(error); process.exitCode = 1; });

