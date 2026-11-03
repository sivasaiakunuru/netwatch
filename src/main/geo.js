'use strict';
// Offline country lookup using the free DB-IP "IP to Country Lite" database (CC BY 4.0, attribution shown in the app).
// Downloaded on first run, refreshed monthly, kept in the app's data folder.
const fs = require('fs');
const path = require('path');
const net = require('net');
const { ipv4ToInt, ipv6High64 } = require('./util');

const BASE = 'https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-country';
const FILES = { v4: 'dbip-country-ipv4-num.csv', v6: 'dbip-country-ipv6.csv' };
const MAX_AGE_MS = 30 * 24 * 3600 * 1000;

const tick = () => new Promise((r) => setImmediate(r));

class Geo {
  constructor(dir, getSettings) {
    this.dir = path.join(dir, 'geo');
    this.getSettings = getSettings;
    fs.mkdirSync(this.dir, { recursive: true });
    this.codes = [];
    this.codeIndex = new Map();
    this.v4 = null;
    this.v6 = null;
    this.cache = new Map();
    this.meta = {};
    this.state = 'empty';
    this.error = '';
  }

  code(cc) {
    let i = this.codeIndex.get(cc);
    if (i === undefined) { i = this.codes.length; this.codes.push(cc); this.codeIndex.set(cc, i); }
    return i;
  }

  // Parsing yields to the event loop every few thousand lines so the app stays responsive.
  async parseV4(text) {
    const lines = text.split('\n');
    const starts = new Uint32Array(lines.length), ends = new Uint32Array(lines.length), cc = new Uint16Array(lines.length);
    let n = 0;
    for (let i = 0; i < lines.length; i++) {
      const f = lines[i].split(',');
      if (f.length < 3) continue;
      starts[n] = +f[0]; ends[n] = +f[1]; cc[n] = this.code(f[2].trim()); n++;
      if (i % 50000 === 0) await tick();
    }
    return { starts: starts.subarray(0, n), ends: ends.subarray(0, n), cc: cc.subarray(0, n) };
  }

  async parseV6(text) {
    const lines = text.split('\n');
    const starts = new BigUint64Array(lines.length), ends = new BigUint64Array(lines.length), cc = new Uint16Array(lines.length);
    let n = 0;
    for (let i = 0; i < lines.length; i++) {
      const f = lines[i].split(',');
      if (f.length < 3) continue;
      try { starts[n] = ipv6High64(f[0]); ends[n] = ipv6High64(f[1]); } catch { continue; }
      cc[n] = this.code(f[2].trim()); n++;
      if (i % 20000 === 0) await tick();
    }
    return { starts: starts.subarray(0, n), ends: ends.subarray(0, n), cc: cc.subarray(0, n) };
  }

  /** Loads the saved database once; every caller (update() included) waits for that same load. */
  ensureLoaded() {
    if (!this.loading) this.loading = this.load();
    return this.loading;
  }

  async load() {
    try { this.meta = JSON.parse(fs.readFileSync(path.join(this.dir, 'meta.json'), 'utf8')); } catch { this.meta = {}; }
    try {
      this.state = 'loading';
      const v4 = path.join(this.dir, FILES.v4), v6 = path.join(this.dir, FILES.v6);
      if (fs.existsSync(v4)) this.v4 = await this.parseV4(fs.readFileSync(v4, 'utf8'));
      if (fs.existsSync(v6)) this.v6 = await this.parseV6(fs.readFileSync(v6, 'utf8'));
      this.state = this.v4 ? 'ready' : 'empty';
      this.cache.clear();
    } catch (e) { this.state = 'error'; this.error = e.message; }
  }

  async update(force = false) {
    if (!this.getSettings().geo.enabled || this.updating) return false;
    this.updating = true;
    try {
      // Judge freshness from the copy on disk, never from the empty state before it has loaded.
      await this.ensureLoaded();
      if (!force && this.v4 && this.meta.updatedAt && Date.now() - this.meta.updatedAt < MAX_AGE_MS) return false;
      this.state = 'downloading';
      for (const file of Object.values(FILES)) {
        const res = await fetch(`${BASE}/${file}`, { signal: AbortSignal.timeout(180000) });
        if (!res.ok) throw new Error(`HTTP ${res.status} for ${file}`);
        fs.writeFileSync(path.join(this.dir, `${file}.tmp`), Buffer.from(await res.arrayBuffer()));
      }
      for (const file of Object.values(FILES)) fs.renameSync(path.join(this.dir, `${file}.tmp`), path.join(this.dir, file));
      this.meta = { updatedAt: Date.now() };
      fs.writeFileSync(path.join(this.dir, 'meta.json'), JSON.stringify(this.meta));
      this.error = '';
      this.loading = this.load();
      await this.loading;
      return true;
    } catch (e) {
      this.error = e.message || String(e);
      this.state = this.v4 ? 'ready' : 'error';
      return false;
    } finally {
      this.updating = false;
    }
  }

  static find(table, value) {
    let lo = 0, hi = table.starts.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (value < table.starts[mid]) hi = mid - 1;
      else if (value > table.ends[mid]) lo = mid + 1;
      else return table.cc[mid];
    }
    return -1;
  }

  /** Two-letter country code, or '' when unknown. */
  lookup(ip) {
    if (!ip || !this.getSettings().geo.enabled) return '';
    if (this.cache.has(ip)) return this.cache.get(ip);
    let i = -1;
    if (net.isIPv4(ip) && this.v4) i = Geo.find(this.v4, ipv4ToInt(ip));
    else if (net.isIPv6(ip) && this.v6) i = Geo.find(this.v6, ipv6High64(ip));
    const cc = i >= 0 ? this.codes[i] : '';
    if (this.cache.size > 50000) this.cache.clear();
    if (this.state === 'ready') this.cache.set(ip, cc);
    return cc;
  }

  status() {
    return { state: this.state, updatedAt: this.meta.updatedAt || 0, error: this.error, enabled: this.getSettings().geo.enabled };
  }
}

module.exports = { Geo };
