'use strict';
// The monitoring engine: turns each collector sample into connections, programs, history, usage and alerts.
// Plain Node (no Electron), so it can be driven by the app, the dev server or tests.
const EventEmitter = require('events');
const crypto = require('crypto');
const dns = require('dns').promises;
const fs = require('fs');
const U = require('./util');
const { isRandomMac } = require('./platform/parsers');

const SUSPICIOUS_PORTS = {
  23: 'Telnet (unencrypted remote shell)', 1337: 'common backdoor port', 4444: 'Metasploit / reverse-shell default',
  4445: 'reverse-shell', 5555: 'ADB / remote-access trojan', 6666: 'IRC (botnet control)', 6667: 'IRC (botnet control)',
  6697: 'IRC over TLS (botnet control)', 9001: 'Tor relay', 9050: 'Tor SOCKS', 12345: 'NetBus trojan',
  20000: 'common remote-access trojan port', 31337: 'Back Orifice backdoor',
};
const BAD_SIGNATURES = new Set(['NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError']);
const RISK_RANK = { '': 0, MEDIUM: 2, HIGH: 3 };
const HOUR = 3600e3, DAY = 24 * HOUR, MB = 1024 * 1024, GB = 1024 * MB;

const fmtBytes = (b) => (b >= GB ? `${(b / GB).toFixed(1)} GB` : b >= MB ? `${(b / MB).toFixed(0)} MB` : `${Math.round(b / 1024)} KB`);
const withTimeout = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);

class Monitor extends EventEmitter {
  constructor({ platform, store, intel, geo, settings, version }) {
    super();
    this.platform = platform;
    this.store = store;
    this.intel = intel;
    this.geo = geo;
    this.settings = settings;
    this.version = version || '';
    this.startedAt = Date.now();

    const rules = store.readJson('rules.json', {});
    this.trusted = new Set(rules.trusted || []);
    this.blocklist = new Set(rules.blocklist || []);
    this.knownApps = new Set(rules.knownApps || []);
    this.learning = this.knownApps.size === 0;

    const hist = store.readJson('history.json', {});
    const cut = (rows, age) => (rows || []).filter((r) => r[0] >= Date.now() - age);
    this.history = { raw: cut(hist.raw, HOUR), min: cut(hist.min, DAY), hour: cut(hist.hour, 30 * DAY) };
    this.minAcc = null;
    this.hourAcc = null;

    const usage = store.readJson('usage.json', {});
    this.usage = { days: usage.days || {}, uploadHours: usage.uploadHours || {} };

    const dev = store.readJson('devices.json', {});
    this.devices = dev.devices || {};
    this.devicesLearned = !!dev.learned;

    this.alerts = store.readAlerts(500);
    this.alerted = new Set();
    this.sigCache = new Map();
    this.sigQueue = new Set();
    this.hostCache = new Map();
    this.dnsMap = new Map();
    this.dnsSeen = new Set();
    this.firstSeen = new Map();
    this.prevBytes = new Map();
    this.prevProcBytes = new Map();
    this.prevTotals = null;
    this.prevTime = 0;
    this.upWindows = new Map();
    this.quiet = { key: '', perProgram: new Map(), total: 0 };
    this.listenerBaseline = null;
    this.newListeners = new Set();
    this.blocked = new Map(); // lower-case path -> path, from the firewall
    this.snapshot = null;
    this.lastError = '';
    this.timers = [];
    this.admin = false;
  }

  // ---------- lifecycle ----------

  async start() {
    this.admin = this.platform.isAdmin();
    await this.refreshBlocked();
    await this.scan();
    this.schedule();
    this.timers.push(setInterval(() => this.save(), 60e3));
    this.timers.push(setInterval(() => this.refreshDns(), 20e3));
    this.timers.push(setInterval(() => this.refreshDevices(), 60e3));
    this.timers.push(setInterval(() => this.refreshSignatures(), 3e3));
    this.timers.push(setInterval(() => this.updateFeeds(false), HOUR));
    this.refreshDns();
    this.refreshDevices();
    this.updateFeeds(false);
  }

  schedule() {
    clearTimeout(this.scanTimer);
    this.scanTimer = setTimeout(async () => { await this.scan(); this.schedule(); }, this.settings.intervalSec * 1000);
  }

  stop() {
    clearTimeout(this.scanTimer);
    this.timers.forEach(clearInterval);
    this.save();
  }

  async updateFeeds(force) {
    const [a, b] = await Promise.all([this.intel.update(force).catch(() => false), this.geo.update(force).catch(() => false)]);
    if (a || b) this.emit('state');
  }

  save() {
    try {
      this.store.writeJson('rules.json', { trusted: [...this.trusted], blocklist: [...this.blocklist], knownApps: [...this.knownApps] });
      this.store.writeJson('history.json', this.history);
      this.store.writeJson('usage.json', this.usage);
      this.store.writeJson('devices.json', { learned: this.devicesLearned, devices: this.devices });
    } catch (e) { this.lastError = `Could not save: ${e.message}`; }
  }

  // ---------- alerts ----------

  alert(severity, key, message, program = '', extra = {}) {
    if (this.alerted.has(key)) return;
    this.alerted.add(key);
    const a = { id: crypto.randomUUID(), t: Date.now(), severity, message, program, ...extra };
    this.alerts.push(a);
    if (this.alerts.length > 500) this.alerts.shift();
    this.store.appendAlert(a);
    this.emit('alert', a);
  }

  isTrusted(name, path) {
    return (!!path && this.trusted.has(path.toLowerCase())) || this.trusted.has(String(name).toLowerCase());
  }

  // ---------- background lookups ----------

  hostName(ip) {
    if (this.hostCache.has(ip)) return this.hostCache.get(ip);
    this.hostCache.set(ip, null); // null = looking up
    if (this.hostCache.size > 5000) this.hostCache.clear();
    withTimeout(dns.reverse(ip), 5000)
      .then((names) => this.hostCache.set(ip, names[0] || ''))
      .catch(() => this.hostCache.set(ip, ''));
    return null;
  }

  async refreshSignatures() {
    if (!this.platform.signatureSupported || !this.sigQueue.size || this.sigBusy) return;
    this.sigBusy = true;
    const batch = [...this.sigQueue].slice(0, 40);
    try {
      const res = await this.platform.signatures(batch);
      for (const p of batch) { this.sigCache.set(p, res.get(p) || { status: 'Unknown', signer: '' }); this.sigQueue.delete(p); }
    } catch { batch.forEach((p) => { this.sigCache.set(p, { status: 'Unknown', signer: '' }); this.sigQueue.delete(p); }); }
    finally { this.sigBusy = false; }
  }

  signature(path) {
    if (!path) return { status: 'Unknown', signer: '' };
    if (!this.platform.signatureSupported) return { status: 'n/a', signer: '' };
    const s = this.sigCache.get(path);
    if (s) return s;
    this.sigQueue.add(path);
    return { status: 'Checking', signer: '' };
  }

  async refreshDns() {
    if (!this.settings.dns.enabled || !this.platform.dnsSupported || this.dnsBusy) return;
    this.dnsBusy = true;
    try {
      const map = await this.platform.dnsCache();
      if (map && map.size) for (const [ip, name] of map) this.dnsMap.set(ip, name);
      if (this.dnsMap.size > 20000) this.dnsMap = new Map([...this.dnsMap].slice(-10000));
    } catch { /* not available, e.g. needs admin */ } finally { this.dnsBusy = false; }
  }

  async refreshDevices() {
    if (!this.settings.lan.enabled || this.lanBusy) return;
    this.lanBusy = true;
    try {
      const rows = await this.platform.arp();
      const now = Date.now();
      for (const { ip, mac } of rows) {
        let d = this.devices[mac];
        if (!d) {
          d = { mac, ip, firstSeen: now, label: '', name: '', random: isRandomMac(mac) };
          this.devices[mac] = d;
          if (this.devicesLearned && this.settings.lan.alertNewDevices) {
            this.alert('LOW', `device|${mac}`, `New device on your network: ${ip} (${mac})${d.random ? ', using a private/random address' : ''}`, '', { device: mac });
          }
        }
        d.ip = ip;
        d.lastSeen = now;
        if (!d.name) withTimeout(dns.reverse(ip), 4000).then((n) => { if (n[0]) d.name = n[0]; }).catch(() => {});
      }
      this.devicesLearned = true;
    } catch { /* arp unavailable */ } finally { this.lanBusy = false; }
  }

  async refreshBlocked() {
    if (!this.platform.firewall.supported) return;
    try {
      const list = await this.platform.firewall.list();
      this.blocked = new Map(list.map((p) => [p.toLowerCase(), p]));
    } catch { /* keep the previous list */ }
  }

  // ---------- the scan ----------

  async scan() {
    if (this.scanning) return;
    this.scanning = true;
    try {
      const s = await this.platform.sample();
      this.process(s);
      this.lastError = '';
    } catch (e) {
      this.lastError = `Scan failed: ${e.message || e}`;
    } finally {
      this.scanning = false;
      this.emit('state');
    }
  }

  process(s) {
    const now = Date.now();
    const st = this.settings;
    const dt = this.prevTime ? (now - this.prevTime) / 1000 : 0;
    const today = U.dayKey(new Date(now));
    const dayUsage = (this.usage.days[today] = this.usage.days[today] || {});
    const addUsage = (name, rx, tx) => {
      const u = (dayUsage[name] = dayUsage[name] || [0, 0]);
      u[0] += rx; u[1] += tx;
    };
    const hourKey = now - (now % HOUR);

    const established = s.tcp.filter((c) => c.state === 'ESTABLISHED' && U.isPublicIp(c.remoteIp));
    const proc = (pid) => s.procs.get(pid) || { name: pid ? `PID ${pid}` : 'System', path: null, ppid: 0 };
    const rows = [];
    const newBytes = new Map();
    const seenKeys = new Set();

    for (const c of established) {
      const p = proc(c.pid);
      const name = p.name, path = p.path;
      const remoteIp = U.normalizeIp(c.remoteIp);
      const remote = `${remoteIp}:${c.remotePort}`;
      const who = path ? `${name} (${path})` : name;
      const trusted = this.isTrusted(name, path);
      const sig = this.signature(path);
      const flags = [];
      let risk = '';
      const raise = (level) => { if (RISK_RANK[level] > RISK_RANK[risk]) risk = level; };

      const listed = this.blocklist.has(remoteIp) ? { id: 'user', name: 'your blocklist' } : this.intel.lookup(remoteIp);
      if (listed) {
        this.alert('HIGH', `intel|${name}|${remoteIp}`, `${who} connected to ${remote}, which is on ${listed.name}`, name);
        flags.push(`Listed by ${listed.name}`); raise('HIGH');
      }
      const portWhy = SUSPICIOUS_PORTS[c.remotePort];
      if (portWhy) {
        this.alert('HIGH', `port|${name}|${remote}`, `${who} connected to ${remote}: port ${c.remotePort} is a ${portWhy}`, name);
        flags.push(`Suspicious port: ${portWhy}`); raise('HIGH');
      }
      if (path && !trusted) {
        if (this.platform.riskyFolders.some((f) => path.toLowerCase().startsWith(f.toLowerCase()))) {
          this.alert('HIGH', `risky|${path}`, `${who} is running from a risky folder and talking to ${remote}`, name);
          flags.push('Runs from a risky folder'); raise('HIGH');
        }
        if (BAD_SIGNATURES.has(sig.status)) {
          this.alert('MEDIUM', `sig|${path}`, `${who} has no valid digital signature (${sig.status}) and is talking to ${remote}`, name);
          flags.push(`No valid signature (${sig.status})`); raise('MEDIUM');
        }
      }
      const country = this.geo.lookup(remoteIp);
      if (country && st.alertCountries.includes(country)) {
        this.alert('MEDIUM', `country|${name}|${country}`, `${who} connected to ${remote} in a country on your watch list (${country})`, name);
        flags.push(`Country on your watch list (${country})`); raise('MEDIUM');
      }
      const domain = this.dnsMap.get(remoteIp) || '';
      if (domain && st.dns.flagRandomDomains && !trusted && U.looksRandomDomain(domain) && !this.dnsSeen.has(domain)) {
        this.dnsSeen.add(domain);
        this.alert('LOW', `dga|${domain}`, `${name} connected to a random-looking domain: ${domain} (${remote}). Some malware generates names like this.`, name);
      }

      const appKey = (path || name).toLowerCase();
      if (!this.knownApps.has(appKey)) {
        const knownByName = this.knownApps.has(name.toLowerCase());
        this.knownApps.add(appKey);
        if (!this.learning && !knownByName) this.alert('LOW', `new|${appKey}`, `New program online for the first time: ${who} -> ${remote}`, name);
      }

      const key = `${c.pid}|${remoteIp}|${c.remotePort}|${c.localPort}`;
      seenKeys.add(key);
      if (!this.firstSeen.has(key)) this.firstSeen.set(key, now);
      let rxBps = null, txBps = null;
      const b = s.connBytes && s.connBytes.get(`${c.pid}|${c.remoteIp}|${c.remotePort}|${c.localPort}`);
      if (b) {
        newBytes.set(key, b);
        const prev = this.prevBytes.get(key);
        rxBps = 0; txBps = 0;
        if (prev && dt > 0) {
          const dIn = Math.max(0, b.rx - prev.rx), dOut = Math.max(0, b.tx - prev.tx);
          rxBps = Math.round((dIn * 8) / dt); txBps = Math.round((dOut * 8) / dt);
          addUsage(name, dIn, dOut);
        }
      }
      rows.push({
        pid: c.pid, program: name, path, remoteIp, remotePort: c.remotePort, localPort: c.localPort,
        host: this.hostName(remoteIp), domain, country, signature: sig.status, publisher: sig.signer,
        since: this.firstSeen.get(key), risk, flags, rxBps, txBps, trusted,
      });
    }
    for (const k of this.firstSeen.keys()) if (!seenKeys.has(k)) this.firstSeen.delete(k);
    this.prevBytes = newBytes;

    // macOS reports bytes per process rather than per connection.
    const procRates = new Map();
    if (s.procBytes) {
      for (const [pid, b] of s.procBytes) {
        const prev = this.prevProcBytes.get(pid);
        if (prev && dt > 0) {
          const dIn = Math.max(0, b.rx - prev.rx), dOut = Math.max(0, b.tx - prev.tx);
          procRates.set(pid, { rx: Math.round((dIn * 8) / dt), tx: Math.round((dOut * 8) / dt), dIn, dOut });
        }
      }
      this.prevProcBytes = s.procBytes;
    }

    // Whole-machine throughput
    let rxTotal = 0, txTotal = 0, haveRate = false;
    if (s.totals && this.prevTotals && dt > 0) {
      const dRx = Math.max(0, s.totals.rx - this.prevTotals.rx), dTx = Math.max(0, s.totals.tx - this.prevTotals.tx);
      rxTotal = Math.round((dRx * 8) / dt); txTotal = Math.round((dTx * 8) / dt);
      addUsage('*total*', dRx, dTx);
      haveRate = true;
    }
    if (s.totals) this.prevTotals = s.totals;
    this.prevTime = now;

    // ---------- programs ----------
    const programs = new Map();
    const prog = (name) => {
      let p = programs.get(name);
      if (!p) {
        p = { name, paths: new Set(), pids: new Set(), conns: 0, udpPorts: new Set(), rxBps: null, txBps: null, risk: '', countries: new Set(), signature: 'Unknown', publisher: '', parent: null };
        programs.set(name, p);
      }
      return p;
    };
    for (const r of rows) {
      const p = prog(r.program);
      if (r.path) p.paths.add(r.path);
      p.pids.add(r.pid);
      p.conns++;
      if (r.rxBps !== null) { p.rxBps = (p.rxBps || 0) + r.rxBps; p.txBps = (p.txBps || 0) + r.txBps; }
      if (RISK_RANK[r.risk] > RISK_RANK[p.risk]) p.risk = r.risk;
      if (r.country) p.countries.add(r.country);
      if (r.signature !== 'Checking') { p.signature = r.signature; p.publisher = r.publisher; }
    }
    for (const u of s.udp) {
      if (!u.pid) continue;
      const info = s.procs.get(u.pid);
      if (!info || !programs.has(info.name)) continue; // UDP shown for programs that are online
      programs.get(info.name).udpPorts.add(u.localPort);
    }
    if (procRates.size) {
      for (const [pid, r] of procRates) {
        const info = s.procs.get(pid);
        if (!info) continue;
        const p = programs.get(info.name);
        if (p) { p.rxBps = (p.rxBps || 0) + r.rx; p.txBps = (p.txBps || 0) + r.tx; }
        if (r.dIn || r.dOut) addUsage(info.name, r.dIn, r.dOut);
      }
    }
    for (const name of Object.keys(dayUsage)) if (name !== '*total*') prog(name);

    // Floods, upload spikes and quiet hours are judged per program.
    const quietNow = st.quiet.enabled && U.inDailyWindow(new Date(now), st.quiet.from, st.quiet.to);
    // A window like 23:00-06:00 that is now past midnight belongs to the night that started yesterday.
    const nowMin = new Date(now).getHours() * 60 + new Date(now).getMinutes();
    const startedYesterday = U.parseClock(st.quiet.from) > U.parseClock(st.quiet.to) && nowMin < U.parseClock(st.quiet.to);
    const quietKey = quietNow ? U.dayKey(new Date(now - (startedYesterday ? DAY : 0))) : '';
    if (quietKey !== this.quiet.key) this.quiet = { key: quietKey, perProgram: new Map(), total: 0 };

    for (const p of programs.values()) {
      const firstPath = [...p.paths][0] || null;
      const trusted = this.isTrusted(p.name, firstPath) || [...p.paths].some((x) => this.trusted.has(x.toLowerCase()));
      if (p.conns > st.floodThreshold && !trusted) {
        this.alert('MEDIUM', `flood|${p.name}|${Math.floor(p.conns / 100)}`, `${p.name} has ${p.conns} open internet connections (possible scan or bot activity)`, p.name);
      }
      const used = dayUsage[p.name];
      const dTx = p.txBps !== null && dt > 0 ? (p.txBps * dt) / 8 : 0;
      const dAll = p.rxBps !== null && dt > 0 ? ((p.rxBps + p.txBps) * dt) / 8 : 0;
      if (dTx > 0) {
        const hours = (this.usage.uploadHours[p.name] = this.usage.uploadHours[p.name] || {});
        hours[hourKey] = (hours[hourKey] || 0) + dTx;
        const win = (this.upWindows.get(p.name) || []).filter((w) => w[0] > now - 600e3);
        win.push([now, dTx]);
        this.upWindows.set(p.name, win);
        const sum10 = win.reduce((a, w) => a + w[1], 0);
        if (!trusted && sum10 > st.uploadSpikeMB * MB) {
          const past = Object.entries(hours).filter(([h]) => +h < hourKey).map(([, v]) => v);
          const typical10 = past.length >= 6 ? past.reduce((a, v) => a + v, 0) / past.length / 6 : 0;
          if (past.length < 6 || sum10 > 5 * typical10) {
            this.alert('MEDIUM', `upload|${p.name}|${hourKey}`, `${p.name} uploaded ${fmtBytes(sum10)} in the last 10 minutes, far more than usual. Check it isn't sending your files somewhere.`, p.name);
          }
        }
      }
      if (quietNow && dAll > 0 && !trusted) {
        const q = (this.quiet.perProgram.get(p.name) || 0) + dAll;
        this.quiet.perProgram.set(p.name, q);
        if (q > st.quiet.thresholdMB * MB) {
          this.alert('MEDIUM', `quiet|${quietKey}|${p.name}`, `${p.name} used ${fmtBytes(q)} during your quiet hours (${st.quiet.from}-${st.quiet.to})`, p.name);
        }
      }
      p.today = used ? { rx: used[0], tx: used[1] } : { rx: 0, tx: 0 };
      p.trusted = trusted;
      p.firstPath = firstPath;
    }
    if (quietNow && !s.measuring && haveRate) {
      this.quiet.total += ((rxTotal + txTotal) * dt) / 8;
      if (this.quiet.total > st.quiet.thresholdMB * MB) {
        this.alert('MEDIUM', `quiet|${quietKey}|*total*`, `Your computer used ${fmtBytes(this.quiet.total)} during your quiet hours (${st.quiet.from}-${st.quiet.to})`);
      }
    }

    // Daily data cap
    const totalToday = dayUsage['*total*'] ? dayUsage['*total*'][0] + dayUsage['*total*'][1] : 0;
    if (st.dailyCapGB > 0) {
      const cap = st.dailyCapGB * GB;
      if (totalToday >= cap) this.alert('HIGH', `cap100|${today}`, `Daily data limit reached: ${fmtBytes(totalToday)} used today (limit ${st.dailyCapGB} GB)`);
      else if (totalToday >= cap * 0.8) this.alert('MEDIUM', `cap80|${today}`, `80% of today's data limit used: ${fmtBytes(totalToday)} of ${st.dailyCapGB} GB`);
    }

    // Listeners open to the network
    const listeners = new Map();
    for (const l of s.tcp) {
      if (l.state !== 'LISTEN' || !['0.0.0.0', '::', '*'].includes(l.localIp)) continue;
      const name = proc(l.pid).name;
      const key = `${name}|${l.localPort}`;
      listeners.set(key, { program: name, pid: l.pid, port: l.localPort, address: l.localIp, isNew: false });
    }
    if (!this.listenerBaseline) this.listenerBaseline = new Set(listeners.keys());
    for (const [key, l] of listeners) {
      if (!this.listenerBaseline.has(key)) {
        this.listenerBaseline.add(key);
        this.newListeners.add(key);
        this.alert('MEDIUM', `listen|${key}`, `${l.program} started listening for incoming connections on port ${l.port}`, l.program);
      }
      l.isNew = this.newListeners.has(key);
    }

    // History
    if (haveRate) this.addHistory(now, rows.length, rxTotal, txTotal);
    this.pruneUsage(now);

    const measuring = !!s.measuring;
    this.snapshot = {
      t: now,
      rxBps: rxTotal,
      txBps: txTotal,
      todayRx: dayUsage['*total*'] ? dayUsage['*total*'][0] : 0,
      todayTx: dayUsage['*total*'] ? dayUsage['*total*'][1] : 0,
      measuring,
      connections: rows,
      programs: [...programs.values()].map((p) => {
        const paths = [...p.paths];
        const parentPid = p.pids.size ? (s.procs.get([...p.pids][0]) || {}).ppid : 0;
        return {
          name: p.name, path: p.firstPath, paths, pids: [...p.pids], conns: p.conns,
          udpPorts: [...p.udpPorts].sort((a, b) => a - b).slice(0, 50), udpCount: p.udpPorts.size,
          rxBps: measuring && p.conns ? p.rxBps || 0 : null, txBps: measuring && p.conns ? p.txBps || 0 : null,
          todayRx: p.today.rx, todayTx: p.today.tx, risk: p.risk, signature: p.signature, publisher: p.publisher,
          countries: [...p.countries].sort(),
          parent: parentPid ? { pid: parentPid, name: proc(parentPid).name } : null,
          trustKey: paths.length === 1 ? paths[0].toLowerCase() : p.name.toLowerCase(),
          trusted: p.trusted,
          blocked: paths.some((x) => this.blocked.has(x.toLowerCase())),
        };
      }),
      listeners: [...listeners.values()].sort((a, b) => a.port - b.port),
    };
    if (this.learning) this.learning = false;
  }

  addHistory(t, conns, rx, tx) {
    const h = this.history;
    h.raw.push([t, conns, rx, tx]);
    while (h.raw.length && h.raw[0][0] < t - HOUR) h.raw.shift();
    const bucket = (acc, size, target, maxAge) => {
      const start = t - (t % size);
      if (acc && acc.start !== start) {
        target.push([acc.start, Math.round(acc.c / acc.n), Math.round(acc.rx / acc.n), Math.round(acc.tx / acc.n)]);
        while (target.length && target[0][0] < t - maxAge) target.shift();
        acc = null;
      }
      acc = acc || { start, n: 0, c: 0, rx: 0, tx: 0 };
      acc.n++; acc.c += conns; acc.rx += rx; acc.tx += tx;
      return acc;
    };
    this.minAcc = bucket(this.minAcc, 60e3, h.min, DAY);
    this.hourAcc = bucket(this.hourAcc, HOUR, h.hour, 30 * DAY);
  }

  pruneUsage(now) {
    if (this.lastPrune && now - this.lastPrune < HOUR) return;
    this.lastPrune = now;
    const oldestDay = U.dayKey(new Date(now - 31 * DAY));
    for (const d of Object.keys(this.usage.days)) if (d < oldestDay) delete this.usage.days[d];
    for (const [name, hours] of Object.entries(this.usage.uploadHours)) {
      for (const h of Object.keys(hours)) if (+h < now - 7 * DAY) delete hours[h];
      if (!Object.keys(hours).length) delete this.usage.uploadHours[name];
    }
  }

  // ---------- what the UI sees ----------

  getState() {
    const snap = this.snapshot;
    return {
      version: this.version,
      platform: this.platform.name,
      admin: this.admin,
      startedAt: this.startedAt,
      interval: this.settings.intervalSec,
      lastError: this.lastError,
      capabilities: {
        perProgram: snap ? snap.measuring : false,
        firewall: !!this.platform.firewall.supported && this.admin,
        firewallSupported: !!this.platform.firewall.supported,
        signatures: !!this.platform.signatureSupported,
        dns: !!this.platform.dnsSupported && (this.platform.name !== 'windows' || this.admin) && this.settings.dns.enabled,
        dnsSupported: !!this.platform.dnsSupported,
      },
      snapshot: snap && {
        ...snap,
        trusted: [...this.trusted].sort(),
        blocked: [...this.blocked.values()].sort(),
        blocklist: [...this.blocklist].sort(),
      },
      alerts: this.alerts,
      history: this.history,
      devices: Object.values(this.devices).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0)),
      intel: this.intel.status(),
      geo: this.geo.status(),
    };
  }

  getReport() {
    return { days: this.usage.days, hour: this.history.hour };
  }

  async programDetails(name) {
    const p = this.snapshot && this.snapshot.programs.find((x) => x.name === name);
    if (!p) return null;
    let commandLine = '';
    try { commandLine = p.pids.length ? await withTimeout(this.platform.commandLine(p.pids[0]), 15000) : ''; } catch { /* access denied */ }
    let sha256 = '';
    if (p.path) {
      try {
        sha256 = await new Promise((resolve, reject) => {
          const h = crypto.createHash('sha256');
          fs.createReadStream(p.path).on('data', (d) => h.update(d)).on('end', () => resolve(h.digest('hex'))).on('error', reject);
        });
      } catch { /* locked or inaccessible */ }
    }
    return { name, commandLine: String(commandLine || '').trim(), sha256 };
  }

  // ---------- changes from the UI ----------

  async action(type, payload = {}) {
    switch (type) {
      case 'trust': {
        const key = String(payload.key || '').toLowerCase();
        if (!key) throw new Error('Missing program.');
        if (payload.trusted) this.trusted.add(key); else this.trusted.delete(key);
        break;
      }
      case 'blocklist': {
        const ip = U.normalizeIp(String(payload.ip || '').trim());
        if (!require('net').isIP(ip)) throw new Error(`"${payload.ip}" is not a valid IP address.`);
        if (payload.add) this.blocklist.add(ip); else this.blocklist.delete(ip);
        this.intel.cache.clear();
        break;
      }
      case 'firewall': {
        const fw = this.platform.firewall;
        if (!fw.supported) throw new Error('Blocking programs is only available on Windows.');
        if (!this.admin) throw new Error('Blocking needs NetWatch to run as administrator.');
        const p = String(payload.path || '');
        if (payload.block) {
          const known = this.snapshot && this.snapshot.programs.some((x) => x.paths.includes(p));
          if (!known) throw new Error('NetWatch can only block programs it has seen online.');
          if (this.platform.systemPrefixes.some((pre) => p.toLowerCase().startsWith(pre.toLowerCase()))) {
            throw new Error('NetWatch will not block system programs: that can break your internet connection or updates.');
          }
          await fw.block(p);
        } else {
          if (!this.blocked.has(p.toLowerCase())) throw new Error('That program is not blocked by NetWatch.');
          await fw.unblock(this.blocked.get(p.toLowerCase()));
        }
        await this.refreshBlocked();
        break;
      }
      case 'deviceLabel': {
        const d = this.devices[String(payload.mac || '')];
        if (!d) throw new Error('Unknown device.');
        d.label = String(payload.label || '').slice(0, 60);
        break;
      }
      case 'forgetDevice': {
        delete this.devices[String(payload.mac || '')];
        break;
      }
      case 'updateFeeds':
        await this.updateFeeds(true);
        break;
      default:
        throw new Error(`Unknown action: ${type}`);
    }
    this.save();
    await this.scan();
  }

  setSettings(next) {
    const intervalChanged = next.intervalSec !== this.settings.intervalSec;
    const feedsChanged = JSON.stringify(next.intel) !== JSON.stringify(this.settings.intel);
    const geoTurnedOn = next.geo.enabled && !this.settings.geo.enabled;
    this.settings = next;
    if (intervalChanged) this.schedule();
    if (feedsChanged) { this.intel.cache.clear(); this.updateFeeds(false); }
    if (geoTurnedOn) this.geo.update(false).then(() => this.emit('state'));
    this.geo.cache.clear();
  }
}

module.exports = { Monitor, SUSPICIOUS_PORTS };
