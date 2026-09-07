/* Quiet Scanner — 현장 IP 충돌 정리 도구
 * Copyright (C) 2026 고요한
 *
 * 이 프로그램은 자유 소프트웨어입니다. GNU 일반 공중 사용 허가서 제2판 또는
 * 그 이후 판의 조건에 따라 재배포하거나 수정할 수 있습니다. 아무런 보증도
 * 하지 않습니다. 자세한 것은 같은 폴더의 LICENSE 를 보십시오.
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
  return { file: 'python', args: [path.join(__dirname, '..', 'electron-backend.py')] };
}

function startBackend() {
  const cmd = backendCommand();
  let child;
  try {
    child = spawn(cmd.file, cmd.args, { windowsHide: true });
  } catch (_) {
    backend = null;
    backendError = new Error('네트워크 엔진을 실행하지 못했습니다. 설치를 다시 확인하십시오.');
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
      message.ok ? job.resolve(message.data) : job.reject(new Error(message.error || '백엔드 오류'));
    } catch (_) { /* 프로토콜 외 출력은 무시 */ }
  });
  child.on('error', () => {
    backendError = new Error('네트워크 엔진을 실행하지 못했습니다. 설치를 다시 확인하십시오.');
    if (backend === child) backend = null;
    for (const { reject } of pending.values()) reject(backendError);
    pending.clear();
  });
  child.on('exit', () => {
    const error = new Error('네트워크 엔진이 종료되었습니다.');
    if (backend === child) backend = null;
    for (const { reject } of pending.values()) reject(error);
    pending.clear();
  });
}

function request(action, payload = {}) {
  if (!backend || backend.killed) startBackend();
  if (!backend || backend.killed || !backend.stdin || backend.stdin.destroyed) {
    return Promise.reject(backendError || new Error('네트워크 엔진을 시작하지 못했습니다.'));
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
      job.reject(new Error('네트워크 엔진에 요청을 전달하지 못했습니다.'));
    });
  });
}

function createWindow() {
  const appIcon = app.isPackaged
    ? path.join(__dirname, 'renderer', 'IPFixStudio.ico')
    : path.join(__dirname, '..', 'IPFixStudio.ico');
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
// 저장 창은 {canceled, filePath} 를 돌려준다. 화면 쪽은 경로 하나만 필요하니
// 여기서 풀어서 넘긴다. 취소면 null.
ipcMain.handle('dialog:save', async (_event, options) => {
  const result = await dialog.showSaveDialog(options);
  return result.canceled ? null : (result.filePath || null);
});

// 사용설명서를 기본 브라우저로 연다.
//
// 설치본에서는 exe 옆에 깔린다(extraFiles). 개발 중에는 소스 폴더의 것을 본다.
// 파일이 없으면 조용히 실패하지 말고 이유를 말한다 — 메뉴를 눌렀는데 아무 일도
// 안 일어나면 사람은 프로그램이 고장 난 줄 안다.
ipcMain.handle('open:manual', async (_event, lang) => {
  const spots = app.isPackaged
    ? [path.join(path.dirname(app.getPath('exe')), '사용설명서.html'),
       path.join(process.resourcesPath, '사용설명서.html')]
    : [path.join(__dirname, '..', '사용설명서.html')];
  // 설명서는 한 파일에 두 말을 담고 주소 끝(#ko·#en)으로 고른다. 프로그램을
  // 영어로 쓰는 사람에게 한글 문서를 띄우면 연 보람이 없다.
  const tag = lang === 'en' ? 'en' : 'ko';
  for (const spot of spots) {
    if (fs.existsSync(spot)) {
      const err = await shell.openExternal(pathToFileURL(spot).href + '#' + tag)
        .then(() => '', (e) => String(e && e.message || e));
      if (!err) return { ok: true };
      // 브라우저를 못 띄웠으면 파일이라도 연다 — 그러면 말은 지난 선택을 따른다.
      const back = await shell.openPath(spot);
      return back ? { ok: false, why: back } : { ok: true };
    }
  }
  return { ok: false, why: '사용설명서.html 을 찾지 못했습니다 (' + spots[0] + ')' };
});
