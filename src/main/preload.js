'use strict';
// The only bridge between the page and the app: a single request channel plus two push events.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('netwatch', {
  call: (type, payload) => ipcRenderer.invoke('nw:call', type, payload),
  onState: (cb) => ipcRenderer.on('nw:state', (_e, state) => cb(state)),
  onOpenProgram: (cb) => ipcRenderer.on('nw:open-program', (_e, name) => cb(name)),
});
