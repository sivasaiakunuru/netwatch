'use strict';
// Everything NetWatch does that doesn't need Electron: settings, monitor, threat lists, countries, phone alerts,
// pausing alerts and CSV exports. Used by the desktop app (main.js) and by browser mode (web.js).
const { Store, sanitizeSettings } = require('./store');
const { ThreatIntel } = require('./intel');
const { Geo } = require('./geo');
const { Monitor } = require('./monitor');
const { PushNotifier, checkNtfyUrl } = require('./notify');

/**
 * @param {object} o
 * @param {string} o.dataDir           where settings, history and logs live
 * @param {string} o.version
 * @param {object} [o.secrets]         { encrypt(str) -> base64, decrypt(base64) -> str } for the Telegram token
 * @param {function} [o.setAutostart]  async (enabled, admin, isAdmin) => void
 * @param {function} [o.appInfo]       () => extra fields for the UI's `app` block
 */
function createService(o) {
  const store = new Store(o.dataDir);
  const secrets = o.secrets || null;

  function loadSettings() {
    const s = store.loadSettings();
    const enc = s.push && s.push.telegramTokenEnc;
    if (enc && secrets) { try { s.push.telegramToken = secrets.decrypt(enc); } catch { s.push.telegramToken = ''; } }
    delete s.push.telegramTokenEnc;
    return s;
  }
  function saveSettings(s) {
    const copy = JSON.parse(JSON.stringify(s));
    if (copy.push.telegramToken && secrets) {
      copy.push.telegramTokenEnc = secrets.encrypt(copy.push.telegramToken);
      copy.push.telegramToken = '';
    }
    store.saveSettings(copy);
  }

  let settings = loadSettings();
  const getSettings = () => settings;
  const push = new PushNotifier(getSettings);
  const intel = new ThreatIntel(o.dataDir, getSettings);
  intel.load();
  const geo = new Geo(o.dataDir, getSettings);
  const monitor = new Monitor({ platform: require('./platform'), store, intel, geo, settings, version: o.version });

  let snoozedUntil = 0, snoozeTimer = null;
  const listeners = { snooze: [] };
  function snooze(minutes) {
    snoozedUntil = minutes > 0 ? Date.now() + minutes * 60e3 : 0;
    clearTimeout(snoozeTimer);
    if (minutes > 0) snoozeTimer = setTimeout(() => { snoozedUntil = 0; listeners.snooze.forEach((f) => f()); monitor.emit('state'); }, minutes * 60e3);
    listeners.snooze.forEach((f) => f());
    monitor.emit('state');
  }
  const isSnoozed = () => snoozedUntil > Date.now();

  monitor.on('alert', (a) => { if (!isSnoozed()) push.send(a).catch(() => { /* best effort */ }); });

  function publicSettings() {
    const c = JSON.parse(JSON.stringify(settings));
    c.push.telegramTokenSet = !!settings.push.telegramToken;
    c.push.telegramToken = '';
    return c;
  }

  async function applySettings(incoming) {
    if (!incoming || typeof incoming !== 'object') throw new Error('Missing settings.');
    const next = sanitizeSettings(incoming);
    const p = incoming.push || {};
    if (!p.telegramToken && !p.clearTelegramToken) next.push.telegramToken = settings.push.telegramToken;
    if (p.clearTelegramToken) next.push.telegramToken = '';
    delete next.push.telegramTokenSet;
    delete next.push.clearTelegramToken;
    if (next.push.ntfyUrl) next.push.ntfyUrl = checkNtfyUrl(next.push.ntfyUrl);
    if (next.autostart !== settings.autostart || (next.autostart && next.autostartAdmin !== settings.autostartAdmin)) {
      if (!o.setAutostart) throw new Error('Start at login is only available in the desktop app.');
      await o.setAutostart(next.autostart, next.autostartAdmin, monitor.admin);
    }
    settings = next;
    saveSettings(settings);
    monitor.setSettings(settings);
    return settings;
  }

  function stateForUi() {
    return {
      ...monitor.getState(),
      settings: publicSettings(),
      app: { snoozedUntil, dataDir: o.dataDir, ...(o.appInfo ? o.appInfo() : {}) },
    };
  }

  /** CSV rows for an export: 'usage' (per day and program) or 'alerts' (the whole rotated log). */
  function csvRows(kind) {
    if (kind === 'alerts') {
      return [['time', 'severity', 'program', 'message'], ...store.readAlerts(0).map((a) => [new Date(a.t).toISOString(), a.severity, a.program || '', a.message])];
    }
    const rows = [['date', 'program', 'downloaded_bytes', 'uploaded_bytes']];
    const days = monitor.getReport().days;
    for (const d of Object.keys(days).sort()) {
      for (const [name, [rx, tx]] of Object.entries(days[d]).sort((a, b) => (b[1][0] + b[1][1]) - (a[1][0] + a[1][1]))) {
        rows.push([d, name === '*total*' ? '(whole computer)' : name, Math.round(rx), Math.round(tx)]);
      }
    }
    return rows;
  }

  const csvCell = (v) => {
    let s = String(v === undefined || v === null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // keep spreadsheets from treating text as a formula
    return `"${s.replace(/"/g, '""')}"`;
  };
  const csvText = (kind) => `﻿${csvRows(kind).map((r) => r.map(csvCell).join(',')).join('\r\n')}\r\n`;

  /** Requests from the UI that don't depend on Electron. */
  async function handle(type, payload = {}) {
    switch (type) {
      case 'getState': return stateForUi();
      case 'report': return monitor.getReport();
      case 'details': return monitor.programDetails(String(payload.name || ''));
      case 'settings': await applySettings(payload.settings); return stateForUi();
      case 'snooze': snooze(Math.max(0, Math.min(24 * 60, +payload.minutes || 0))); return stateForUi();
      case 'testPush':
        await push.send({ severity: 'HIGH', message: 'Test alert from NetWatch. If you can read this, phone alerts work.' }, { test: true });
        return true;
      default:
        await monitor.action(type, payload);
        return stateForUi();
    }
  }

  async function start() {
    await monitor.start();
    geo.load().then(() => { monitor.emit('state'); return geo.update(false); }).then(() => monitor.emit('state')).catch(() => {});
  }

  return {
    store, monitor, push, intel, geo, getSettings, handle, stateForUi, csvText, snooze, isSnoozed,
    onSnooze: (f) => listeners.snooze.push(f),
    start,
    stop: () => monitor.stop(),
  };
}

module.exports = { createService };
