// Compile and execute the actual NSIS prerequisite detector without installing
// or removing drivers, runtimes, registry entries, or the application.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const makensis = process.env.MAKENSIS || path.join(process.env.LOCALAPPDATA, 'tauri/NSIS/makensis.exe');
const run = (file, args) => spawnSync(file, args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 30000 });
const folder = path.join(root, '_smoke', `installer-test-${Date.now()}`);
fs.mkdirSync(folder, { recursive: true });
function compile(name, fixture) {
  const exe = path.join(folder, `${name}.exe`);
  const args = ['/INPUTCHARSET', 'UTF8', `/DTEST_OUTPUT=${exe}`];
  if (fixture) args.push(`/DQS_PREREQUISITE_TEST_DIR=${folder}`);
  args.push(path.join(__dirname, 'installer-prerequisites-test.nsi'));
  const result = run(makensis, args);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return exe;
}
const testExe = compile('fixture', true);
for (const expected of [0, 1, 3, 2, 0]) {
  for (const [name, bit] of [['npcap', 1], ['webview2', 2]]) {
    const file = path.join(folder, `${name}.ready`);
    if (expected & bit) fs.writeFileSync(file, 'ready');
    else if (fs.existsSync(file)) fs.unlinkSync(file);
  }
  const actual = run(testExe, []);
  assert.equal(actual.status, expected, actual.stderr || `Detector state mismatch: ${expected}`);
}
// Compare the real native detector with independent filesystem/registry reads.
const realExe = compile('native', false);
const system = path.join(process.env.WINDIR, process.arch === 'ia32' ? 'Sysnative' : 'System32');
const npcap = ['Npcap/wpcap.dll', 'drivers/npcap.sys'].every(file => fs.existsSync(path.join(system, file)));
const key = 'SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
let webview = false;
for (const hive of ['HKLM', 'HKCU']) for (const view of ['32', '64']) {
  const result = run('reg.exe', ['query', `${hive}\\${key}`, '/v', 'pv', `/reg:${view}`]);
  const version = result.stdout?.match(/REG_SZ\s+(\d+\.\d+\.\d+\.\d+)/)?.[1];
  if (version && version !== '0.0.0.0') webview = true;
}
const actual = run(realExe, []);
assert.equal(actual.status, Number(npcap) + Number(webview) * 2, 'Native prerequisite detection mismatch');
console.log(`Installer detector: missing, partial, complete, removal and native states passed (Npcap=${npcap}, WebView2=${webview}).`);
