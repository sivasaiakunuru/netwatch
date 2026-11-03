'use strict';
// Electron main process: window, tray, desktop notifications and OS integration around the shared service.
const { app, BrowserWindow, Tray, Menu, ipcMain, Notification, nativeImage, shell, dialog, safeStorage, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs');
const { createService } = require('./service');
const system = require('./system');
const { dayKey, SEVERITY_RANK } = require('./util');

// Command-line options: --hidden (start in the tray), --data-dir=PATH, --serve-ui=PORT (test server),
// --tab=NAME, --screenshot=FILE [--screenshot-delay=MS] [--quit-after-screenshot]
const argv = process.argv.slice(1);
const opt = (name) => {
  const a = argv.find((x) => x === `--${name}` || x.startsWith(`--${name}=`));
  if (a === undefined) return null;
  return a.includes('=') ? a.slice(a.indexOf('=') + 1) : true;
};

if (opt('data-dir')) app.setPath('userData', path.resolve(String(opt('data-dir'))));
app.setAppUserModelId('com.netwatch.app');

const ASSETS = path.join(__dirname, '..', 'assets');
const RENDERER = path.join(__dirname, '..', 'renderer', 'index.html');
const SEV_LABEL = { LOW: 'Low', MEDIUM: 'Medium', HIGH: 'High' };

let win = null, tray = null, svc = null;
let quitting = false, trayHintShown = false, unseenAlerts = 0;

// ---------- window & tray ----------

function sendState() {
  if (win && !win.isDestroyed() && win.isVisible() && !win.isMinimized()) win.webContents.send('nw:state', svc.stateForUi());
}

function showWindow() {
  if (!win || win.isDestroyed()) createWindow(true);
  else { if (win.isMinimized()) win.restore(); win.show(); win.focus(); }
  unseenAlerts = 0;
  updateTray();
}

function createWindow(show) {
  win = new BrowserWindow({
    width: 1320, height: 900, minWidth: 380, minHeight: 500, show: false, title: 'NetWatch',
    icon: path.join(ASSETS, 'icon.png'),
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#0d0d0d' : '#f9f9f7',
    autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, nodeIntegration: false, spellcheck: false },
  });
  win.loadFile(RENDERER, { hash: typeof opt('tab') === 'string' ? opt('tab') : '' });
  win.once('ready-to-show', () => { if (show) win.show(); });
  win.on('show', () => { unseenAlerts = 0; updateTray(); sendState(); });
  win.on('restore', sendState);
  win.on('close', (e) => {
    if (quitting) return;
    e.preventDefault();
    win.hide();
    if (!trayHintShown && Notification.isSupported()) {
      trayHintShown = true;
      new Notification({ title: 'NetWatch is still running', body: 'It keeps watching from the tray. Right-click the tray icon to quit.', icon: path.join(ASSETS, 'icon.png') }).show();
    }
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (e) => e.preventDefault());
}

function trayImage() {
  const file = unseenAlerts > 0 ? 'tray-alert.png' : 'tray.png';
  return nativeImage.createFromPath(path.join(ASSETS, file)).resize({ width: 16, height: 16 });
}

function updateTray() {
  if (!tray || !svc) return;
  tray.setImage(trayImage());
  tray.setToolTip(unseenAlerts ? `NetWatch: ${unseenAlerts} new alert${unseenAlerts === 1 ? '' : 's'}` : 'NetWatch: watching your network');
  const snoozedUntil = svc.stateForUi().app.snoozedUntil;
  const items = [
    { label: 'Open NetWatch', click: showWindow },
    { type: 'separator' },
    svc.isSnoozed()
      ? { label: `Resume alerts (paused until ${new Date(snoozedUntil).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })})`, click: () => svc.snooze(0) }
      : { label: 'Pause alerts for 1 hour', click: () => svc.snooze(60) },
  ];
  if (process.platform === 'win32' && !svc.monitor.admin) items.push({ label: 'Restart as administrator', click: () => relaunchAdmin() });
  items.push({ type: 'separator' }, { label: 'Quit NetWatch', click: () => { quitting = true; app.quit(); } });
  tray.setContextMenu(Menu.buildFromTemplate(items));
}

async function relaunchAdmin() {
  app.releaseSingleInstanceLock();
  if (await system.relaunchAsAdmin()) {
    quitting = true;
    app.quit();
    return true;
  }
  app.requestSingleInstanceLock();
  return false;
}

function onAlert(a) {
  if (!win || !win.isVisible()) { unseenAlerts++; updateTray(); }
  if (svc.isSnoozed()) return;
  if (SEVERITY_RANK[a.severity] >= SEVERITY_RANK[svc.getSettings().desktopMinSeverity] && Notification.isSupported()) {
    const n = new Notification({
      title: `NetWatch: ${SEV_LABEL[a.severity]} alert`, body: a.message, icon: path.join(ASSETS, 'icon.png'),
      urgency: a.severity === 'HIGH' ? 'critical' : 'normal',
    });
    n.on('click', () => { showWindow(); if (a.program) win.webContents.send('nw:open-program', a.program); });
    n.show();
  }
}

// ---------- requests from the UI ----------

const EXTERNAL_OK = [
  /^https:\/\/www\.virustotal\.com\/gui\/file\/[0-9a-f]{64}$/i,
  /^https:\/\/db-ip\.com\/?$/,
  /^https:\/\/(docs\.)?ntfy\.sh\/?[\w/-]*$/,
  /^https:\/\/core\.telegram\.org\/bots[\w/#-]*$/,
];

async function handle(type, payload = {}) {
  switch (type) {
    case 'relaunchAdmin': return relaunchAdmin();
    case 'openDataFolder': await shell.openPath(app.getPath('userData')); return true;
    case 'openExternal': {
      if (!EXTERNAL_OK.some((re) => re.test(String(payload.url)))) throw new Error('That link is not allowed.');
      await shell.openExternal(payload.url);
      return true;
    }
    case 'export': {
      const kind = payload.kind === 'alerts' ? 'alerts' : 'usage';
      const { canceled, filePath } = await dialog.showSaveDialog(win, {
        title: kind === 'alerts' ? 'Export alerts' : 'Export data usage',
        defaultPath: path.join(app.getPath('downloads'), `netwatch-${kind}-${dayKey()}.csv`),
        filters: [{ name: 'CSV', extensions: ['csv'] }],
      });
      if (canceled || !filePath) return '';
      fs.writeFileSync(filePath, svc.csvText(kind));
      return filePath;
    }
    case 'settings': {
      const result = await svc.handle(type, payload);
      nativeTheme.themeSource = svc.getSettings().theme;
      return result;
    }
    default: return svc.handle(type, payload);
  }
}

ipcMain.handle('nw:call', async (e, type, payload) => {
  if (!win || e.sender !== win.webContents) return { ok: false, error: 'Not allowed.' };
  try { return { ok: true, result: await handle(String(type), payload || {}) }; } catch (err) { return { ok: false, error: err.message || String(err) }; }
});

// ---------- startup ----------

async function init() {
  const secrets = safeStorage.isEncryptionAvailable()
    ? { encrypt: (s) => safeStorage.encryptString(s).toString('base64'), decrypt: (b) => safeStorage.decryptString(Buffer.from(b, 'base64')) }
    : null;
  try {
    svc = createService({
      dataDir: app.getPath('userData'),
      version: app.getVersion(),
      secrets,
      setAutostart: system.setAutostart,
      appInfo: () => ({ canRelaunchAdmin: process.platform === 'win32' && svc && !svc.monitor.admin, packaged: app.isPackaged, desktop: true }),
    });
  } catch (e) {
    dialog.showErrorBox('NetWatch', e.message);
    app.exit(1);
    return;
  }
  nativeTheme.themeSource = svc.getSettings().theme;
  svc.monitor.on('state', sendState);
  svc.monitor.on('alert', onAlert);
  svc.onSnooze(updateTray);

  if (process.platform === 'darwin') {
    Menu.setApplicationMenu(Menu.buildFromTemplate([{ role: 'appMenu' }, { role: 'editMenu' }, { role: 'windowMenu' }]));
  } else {
    Menu.setApplicationMenu(null);
  }
  tray = new Tray(trayImage());
  tray.on('click', showWindow);
  updateTray();
  createWindow(!opt('hidden'));

  if (opt('serve-ui')) require('./devserver').start(+opt('serve-ui'), handle, path.dirname(RENDERER));
  if (opt('screenshot')) {
    win.once('ready-to-show', () => setTimeout(async () => {
      const img = await win.webContents.capturePage();
      fs.writeFileSync(path.resolve(String(opt('screenshot'))), img.toPNG());
      if (opt('quit-after-screenshot')) { quitting = true; app.quit(); }
    }, +opt('screenshot-delay') || 8000));
  }

  await svc.start();
  updateTray();
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => showWindow());
  app.on('activate', () => showWindow());
  app.on('before-quit', () => { quitting = true; if (svc) svc.stop(); });
  app.on('window-all-closed', () => { /* keep running in the tray */ });
  app.whenReady().then(init).catch((e) => { dialog.showErrorBox('NetWatch failed to start', String((e && e.stack) || e)); app.exit(1); });
}
