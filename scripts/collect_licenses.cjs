// Generate redistributable notices from the exact dependency lockfile.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const target = process.env.CARGO_BUILD_TARGET || execFileSync('rustc', ['-vV'], { encoding: 'utf8', windowsHide: true }).match(/^host: (.+)$/m)?.[1]?.trim();
if (!target) throw new Error('Cannot determine the Rust build target');
const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--manifest-path', 'src-tauri/Cargo.toml', '--locked', '--filter-platform', target, '--format-version', '1'], { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, windowsHide: true }));
const nodes = new Map(metadata.resolve.nodes.map(node => [node.id, node]));
const included = new Set();
function visit(id) { if (included.has(id)) return; included.add(id); for (const child of nodes.get(id)?.dependencies || []) visit(child); }
visit(metadata.resolve.root);
const sections = [`Quiet Scanner: locked ${target} Rust dependency notices\nIncludes build dependencies for this target.\nSource: https://github.com/goyohan0611-png/quiet-scanner\n`];
const missing = [];
(async () => {
for (const pkg of metadata.packages.sort((a,b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`))) {
  if (!pkg.source || !included.has(pkg.id)) continue;
  const folder = path.dirname(pkg.manifest_path);
  const files = fs.readdirSync(folder, { withFileTypes: true }).filter(item => item.isFile() && /^(licen[cs]e|copying|notice)([.\-_]|$)/i.test(item.name)).map(item => path.join(folder, item.name));
  if (pkg.license_file && !files.includes(pkg.license_file)) files.push(pkg.license_file);
  sections.push(`\n${'='.repeat(72)}\n${pkg.name} ${pkg.version}\nLicense: ${pkg.license || 'See text below'}\n${pkg.repository || ''}\n`);
  for (const file of files) sections.push(`\n--- ${path.basename(file)} ---\n${fs.readFileSync(file, 'utf8')}\n`);
  if (!files.length) {
    const vcs = JSON.parse(fs.readFileSync(path.join(folder, '.cargo_vcs_info.json'), 'utf8'));
    const repo = (pkg.repository || '').match(/^https:\/\/github.com\/([^/]+\/[^/]+?)(?:\.git)?\/?$/)?.[1];
    let found = false;
    const cache = path.join(root, 'LICENSES', `${pkg.name}-${pkg.version}.txt`);
    if (fs.existsSync(cache)) { sections.push(fs.readFileSync(cache, 'utf8')); found = true; }
    if (!found && repo && vcs.git.sha1) {
      for (const name of ['LICENSE', 'LICENSE-MIT', 'LICENSE.md', 'LICENSE.txt', 'license.txt', 'COPYING']) {
        const url = `https://raw.githubusercontent.com/${repo}/${vcs.git.sha1}/${name}`;
        const response = await fetch(url, { signal: AbortSignal.timeout(15000) });
        if (!response.ok) continue;
        const text = `Source: ${url}\n\n${await response.text()}`;
        fs.writeFileSync(cache, text); sections.push(text); found = true; break;
      }
    }
    if (!found && pkg.license === 'MPL-2.0') {
      const url = 'https://www.mozilla.org/media/MPL/2.0/index.txt';
      const response = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (response.ok) {
        const text = `Source package: ${pkg.repository} @ ${vcs.git.sha1}\nAuthors: ${(pkg.authors || []).join(', ')}\nLicense text: ${url}\n\n${await response.text()}`;
        fs.writeFileSync(cache, text); sections.push(text); found = true;
      }
    }
    if (!found) missing.push(`${pkg.name}@${pkg.version}`);
  }
}
if (missing.length) throw new Error(`Dependency license files missing: ${missing.join(', ')}`);
fs.mkdirSync(path.join(root, 'LICENSES'), { recursive: true });
fs.writeFileSync(path.join(root, 'LICENSES/rust-dependencies.txt'), sections.join('\n'));
console.log(`Collected notices for ${metadata.packages.filter(pkg => pkg.source && included.has(pkg.id)).length} locked ${target} Rust dependencies.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
