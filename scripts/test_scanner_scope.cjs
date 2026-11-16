// The scanner distribution must not expose or bundle the separate Guard prototype.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
for (const file of ['electron/renderer/index.html', 'electron/renderer/app.js',
  'electron/renderer/tauri-bridge.js', 'src-tauri/src/main.rs',
  'src-tauri/src/engine.rs', 'src-tauri/src/privilege.rs']) {
  const source = fs.readFileSync(path.join(root, file), 'utf8');
  assert.ok(!/protection_|protectionBtn|protectionDialog|protection\.js|mod protection|--protection/.test(source), file);
}
for (const file of ['electron/renderer/protection.js', 'src-tauri/src/protection.rs', 'src-tauri/src/protection']) {
  assert.ok(!fs.existsSync(path.join(root, file)), `prototype must be outside the scanner: ${file}`);
}
const html = fs.readFileSync(path.join(root, 'electron/renderer/index.html'), 'utf8');
for (const id of ['scanBtn', 'dhcpBtn', 'availableBtn', 'bookBtn']) {
  assert.ok(html.includes(`id="${id}"`), `scanner control retained: ${id}`);
}
console.log('PASS: scanner controls retained; Guard UI and execution routes absent');
