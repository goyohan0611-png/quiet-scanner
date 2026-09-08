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
