/* Quiet Scanner — field IP conflict cleanup tool
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
const { app, BrowserWindow, ipcMain, dialog, Menu, shell } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { pathToFileURL } = require('url');
const readline = require('readline');

let backend;
let backendError = null;
let nextId = 1;
const pending = new Map();

function backendCommand() {
  if (app.isPackaged) return { file: path.join(process.resourcesPath, 'IPFixBackend', 'IPFixBackend.exe'), args: [] };
  return { file: 'python', args: [path.join(__dirname, '..', 'src', 'electron-backend.py')] };
}

function startBackend() {
  const cmd = backendCommand();
  let child;
  try {
    child = spawn(cmd.file, cmd.args, { windowsHide: true });
  } catch (_) {
    backend = null;
    backendError = new Error('Could not start the network engine. Check the installation.');
    return;
  }
  backend = child;
  backendError = null;
  const lines = readline.createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    try {
      const message = JSON.parse(line);
      if (message.event === 'state') {
        for (const win of BrowserWindow.getAllWindows()) win.webContents.send('network:state', message.data);
        return;
      }
      const job = pending.get(message.id);
      if (!job) return;
      pending.delete(message.id);
      message.ok ? job.resolve(message.data) : job.reject(new Error(message.error || 'Backend error'));
    } catch (_) { /* anything that is not protocol output gets ignored */ }
  });
  child.on('error', () => {
    backendError = new Error('Could not start the network engine. Check the installation.');
    if (backend === child) backend = null;
    for (const { reject } of pending.values()) reject(backendError);
    pending.clear();
  });
  child.on('exit', () => {
    const error = new Error('The network engine stopped.');
    if (backend === child) backend = null;
    for (const { reject } of pending.values()) reject(error);
    pending.clear();
  });
}

function request(action, payload = {}) {
  if (!backend || backend.killed) startBackend();
  if (!backend || backend.killed || !backend.stdin || backend.stdin.destroyed) {
    return Promise.reject(backendError || new Error('Could not start the network engine.'));
  }
  const id = nextId++;
  const child = backend;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify({ id, action, payload }) + '\n', (error) => {
      if (!error) return;
      const job = pending.get(id);
      if (!job) return;
      pending.delete(id);
      job.reject(new Error('Could not pass the request to the network engine.'));
    });
  });
}

function createWindow() {
  // Same path either way. The repository root has no icon — .gitignore blocks one there
  // on purpose so the app's own copy survives — so the dev branch pointed at nothing.
  const appIcon = path.join(__dirname, 'renderer', 'IPFixStudio.ico');
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1120,
    minHeight: 680,
    backgroundColor: '#f7f9fc',
    title: 'Quiet Scanner',
    icon: appIcon,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false }
  });
  // This window shows one local page and nothing else, ever. Device names, ONVIF titles
  // and SNMP aliases are rendered in it, and while they are all escaped, a window that
  // can be navigated or can spawn another is one bug away from being worth attacking.
  // Anything that wants a browser gets the real browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (event, url) => {
    if (url !== win.webContents.getURL()) event.preventDefault();
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  startBackend();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => { if (backend && !backend.killed) backend.kill(); });

ipcMain.handle('network:request', (_event, action, payload) => request(action, payload));
// The save dialog hands back {canceled, filePath}. The renderer only needs the one
// path, so unwrap it here. null on cancel.
ipcMain.handle('dialog:save', async (_event, options) => {
  const result = await dialog.showSaveDialog(options);
  return result.canceled ? null : (result.filePath || null);
});

// Open the user guide in the default browser.
//
// In an installed build it sits next to the exe (extraFiles). In development we use
// the copy in the source folder. If the file is missing, do not fail silently — say
// why. Click a menu item, have nothing happen, and people assume the program is broken.
ipcMain.handle('open:manual', async (_event, lang) => {
  const spots = app.isPackaged
    ? [path.join(path.dirname(app.getPath('exe')), 'manual.html'),
       path.join(process.resourcesPath, 'manual.html')]
    : [path.join(__dirname, '..', 'manual.html')];
  // The guide holds both languages in one file and picks with the URL fragment (#ko·#en).
  // Open a Korean document for someone running the program in English and there was no point opening it.
  const tag = lang === 'en' ? 'en' : 'ko';
  for (const spot of spots) {
    if (fs.existsSync(spot)) {
      const err = await shell.openExternal(pathToFileURL(spot).href + '#' + tag)
        .then(() => '', (e) => String(e && e.message || e));
      if (!err) return { ok: true };
      // If the browser would not launch, at least open the file — then the language falls back to whatever was chosen last.
      const back = await shell.openPath(spot);
      return back ? { ok: false, why: back } : { ok: true };
    }
  }
  return { ok: false, why: 'manual.html not found (' + spots[0] + ')' };
});
