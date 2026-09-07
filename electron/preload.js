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
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ipfix', {
  request: (action, payload) => ipcRenderer.invoke('network:request', action, payload),
  onState: (listener) => {
    const wrapped = (_event, state) => listener(state);
    ipcRenderer.on('network:state', wrapped);
    return () => ipcRenderer.removeListener('network:state', wrapped);
  },
  saveDialog: (options) => ipcRenderer.invoke('dialog:save', options),
  openManual: (lang) => ipcRenderer.invoke('open:manual', lang)
});
