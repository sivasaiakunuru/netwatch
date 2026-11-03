'use strict';
// Phone alerts through ntfy (any ntfy server, e.g. https://ntfy.sh/<your-topic>) and/or a Telegram bot.
const { SEVERITY_RANK } = require('./util');

const MAX_PER_HOUR = 20;
const LABEL = { LOW: 'Low', MEDIUM: 'Medium', HIGH: 'High' };

function checkNtfyUrl(u) {
  let url;
  try { url = new URL(u); } catch { throw new Error('The ntfy address is not a valid URL.'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new Error('The ntfy address must start with https://');
  if (url.pathname.length < 2) throw new Error('Add your topic to the ntfy address, e.g. https://ntfy.sh/my-secret-topic');
  return url.toString();
}

class PushNotifier {
  constructor(getSettings) {
    this.getSettings = getSettings;
    this.sent = [];
  }

  /** Sends one alert; with test=true, sends regardless of filters and throws if nothing could be delivered. */
  async send(alert, { test = false } = {}) {
    const p = this.getSettings().push;
    if (!test) {
      if (!p.enabled || SEVERITY_RANK[alert.severity] < SEVERITY_RANK[p.minSeverity]) return;
      const now = Date.now();
      this.sent = this.sent.filter((t) => t > now - 3600e3);
      if (this.sent.length >= MAX_PER_HOUR) return;
      this.sent.push(now);
    }
    const title = `NetWatch: ${LABEL[alert.severity] || alert.severity} alert`;
    const jobs = [];
    if (p.ntfyUrl) {
      const url = checkNtfyUrl(p.ntfyUrl);
      jobs.push(fetch(url, {
        method: 'POST',
        body: alert.message,
        headers: { Title: title, Priority: alert.severity === 'HIGH' ? 'high' : 'default', Tags: alert.severity === 'HIGH' ? 'rotating_light' : 'warning' },
        signal: AbortSignal.timeout(15000),
      }).then((r) => { if (!r.ok) throw new Error(`ntfy answered HTTP ${r.status}`); }));
    }
    if (p.telegramToken && p.telegramChatId) {
      if (!/^\d+:[\w-]+$/.test(p.telegramToken)) throw new Error('The Telegram bot token looks wrong (it should look like 123456:ABC-...).');
      jobs.push(fetch(`https://api.telegram.org/bot${p.telegramToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: p.telegramChatId, text: `${title}\n${alert.message}` }),
        signal: AbortSignal.timeout(15000),
      }).then(async (r) => { if (!r.ok) throw new Error(`Telegram answered HTTP ${r.status}: ${(await r.json().catch(() => ({}))).description || ''}`); }));
    }
    if (!jobs.length) {
      if (test) throw new Error('Add an ntfy address or a Telegram bot first.');
      return;
    }
    const results = await Promise.allSettled(jobs);
    const failed = results.filter((r) => r.status === 'rejected');
    if (test && failed.length) throw new Error(failed.map((f) => f.reason.message).join('; '));
  }
}

module.exports = { PushNotifier, checkNtfyUrl };
