'use strict';
// JSON files in the app's data folder, written atomically, plus a rotating alert log.
const fs = require('fs');
const path = require('path');

const ALERT_LOG_MAX_BYTES = 5 * 1024 * 1024;
const ALERT_LOG_KEEP = 3;

const DEFAULT_SETTINGS = {
  intervalSec: 5,
  floodThreshold: 150,
  desktopMinSeverity: 'MEDIUM',
  push: { enabled: false, minSeverity: 'HIGH', ntfyUrl: '', telegramChatId: '', telegramToken: '' },
  dailyCapGB: 0,
  uploadSpikeMB: 200,
  quiet: { enabled: false, from: '00:00', to: '06:00', thresholdMB: 50 },
  alertCountries: [],
  intel: { enabled: true, feeds: { spamhaus: true, firehol: true, et: true, feodo: true, sslbl: true } },
  geo: { enabled: true },
  dns: { enabled: true, flagRandomDomains: true },
  lan: { enabled: true, alertNewDevices: true },
  autostart: false,
  autostartAdmin: false,
  theme: 'system',
};

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Deep-merges `over` onto a fresh copy of `base`. Where `base` has a section (an object) and `over` has
 * something else there (null, a string, ...), the section's defaults are kept, so a damaged settings
 * file can't leave sanitizeSettings dereferencing null.
 */
function merge(base, over) {
  const out = structuredClone(base);
  if (!isPlainObject(over)) return out;
  for (const k of Object.keys(over)) {
    if (isPlainObject(base[k])) { if (isPlainObject(over[k])) out[k] = merge(base[k], over[k]); } else out[k] = over[k];
  }
  return out;
}

const clampNum = (v, min, max, dflt) => (Number.isFinite(+v) ? Math.min(max, Math.max(min, +v)) : dflt);
const SEVS = ['LOW', 'MEDIUM', 'HIGH'];

/** Keeps settings within sane bounds whatever the UI (or a hand-edited file) sends. */
function sanitizeSettings(s) {
  const d = DEFAULT_SETTINGS;
  s = merge(d, s);
  s.intervalSec = clampNum(s.intervalSec, 2, 60, d.intervalSec);
  s.floodThreshold = clampNum(s.floodThreshold, 20, 5000, d.floodThreshold);
  s.desktopMinSeverity = SEVS.includes(s.desktopMinSeverity) ? s.desktopMinSeverity : d.desktopMinSeverity;
  s.push.minSeverity = SEVS.includes(s.push.minSeverity) ? s.push.minSeverity : 'HIGH';
  s.push.enabled = !!s.push.enabled;
  s.push.ntfyUrl = String(s.push.ntfyUrl || '').trim();
  s.push.telegramChatId = String(s.push.telegramChatId || '').trim();
  s.push.telegramToken = String(s.push.telegramToken || '').trim();
  s.dailyCapGB = clampNum(s.dailyCapGB, 0, 100000, 0);
  s.uploadSpikeMB = clampNum(s.uploadSpikeMB, 10, 1000000, d.uploadSpikeMB);
  s.quiet.enabled = !!s.quiet.enabled;
  s.quiet.thresholdMB = clampNum(s.quiet.thresholdMB, 1, 1000000, d.quiet.thresholdMB);
  if (!/^\d{1,2}:\d{2}$/.test(String(s.quiet.from))) s.quiet.from = d.quiet.from;
  if (!/^\d{1,2}:\d{2}$/.test(String(s.quiet.to))) s.quiet.to = d.quiet.to;
  s.alertCountries = [...new Set((Array.isArray(s.alertCountries) ? s.alertCountries : [])
    .map((c) => String(c).trim().toUpperCase()).filter((c) => /^[A-Z]{2}$/.test(c)))];
  s.theme = ['system', 'light', 'dark'].includes(s.theme) ? s.theme : 'system';
  for (const k of ['autostart', 'autostartAdmin']) s[k] = !!s[k];
  return s;
}

class Store {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
  }

  file(name) { return path.join(this.dir, name); }

  readJson(name, fallback) {
    try { return JSON.parse(fs.readFileSync(this.file(name), 'utf8')); } catch { return fallback; }
  }

  writeJson(name, data) {
    const target = this.file(name);
    const tmp = `${target}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data));
    fs.renameSync(tmp, target);
  }

  loadSettings() { return sanitizeSettings(this.readJson('settings.json', {})); }
  saveSettings(s) { this.writeJson('settings.json', s); }

  appendAlert(alert) {
    const log = this.file('alerts.jsonl');
    try {
      if (fs.existsSync(log) && fs.statSync(log).size > ALERT_LOG_MAX_BYTES) {
        for (let i = ALERT_LOG_KEEP - 1; i >= 1; i--) {
          const from = this.file(`alerts.${i}.jsonl`);
          if (fs.existsSync(from)) fs.renameSync(from, this.file(`alerts.${i + 1}.jsonl`));
        }
        fs.renameSync(log, this.file('alerts.1.jsonl'));
        const oldest = this.file(`alerts.${ALERT_LOG_KEEP + 1}.jsonl`);
        if (fs.existsSync(oldest)) fs.unlinkSync(oldest);
      }
      fs.appendFileSync(log, `${JSON.stringify(alert)}\n`);
    } catch { /* logging must never break monitoring */ }
  }

  /** Alerts oldest-first: the newest `limit` from the current log, or every rotated file when limit is 0. */
  readAlerts(limit = 500) {
    const files = limit ? ['alerts.jsonl'] : [...Array.from({ length: ALERT_LOG_KEEP }, (_, i) => `alerts.${ALERT_LOG_KEEP - i}.jsonl`), 'alerts.jsonl'];
    const out = [];
    for (const f of files) {
      let text = '';
      try { text = fs.readFileSync(this.file(f), 'utf8'); } catch { continue; }
      for (const line of text.split('\n')) {
        if (!line) continue;
        try { out.push(JSON.parse(line)); } catch { /* skip a torn line */ }
      }
    }
    return limit ? out.slice(-limit) : out;
  }
}

module.exports = { Store, sanitizeSettings };
