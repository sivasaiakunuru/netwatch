'use strict';
// Free, regularly updated lists of known-malicious IP addresses. Downloaded once a day and cached.
const fs = require('fs');
const path = require('path');
const { parseIpv4Cidr, ipv4ToInt, isPublicIp } = require('./util');
const net = require('net');

const FEEDS = [
  { id: 'spamhaus', name: 'Spamhaus DROP', about: 'Networks controlled by criminals and spammers', url: 'https://www.spamhaus.org/drop/drop_v4.json' },
  { id: 'firehol', name: 'FireHOL Level 1', about: 'Attack sources combined from several lists', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset' },
  { id: 'et', name: 'Emerging Threats', about: 'Hosts known to be compromised', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt' },
  { id: 'feodo', name: 'abuse.ch Feodo Tracker', about: 'Botnet control servers', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt' },
  { id: 'sslbl', name: 'abuse.ch SSL Blacklist', about: 'Botnet control servers', url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt' },
];
const MAX_AGE_MS = 24 * 3600 * 1000;

/** Text of a feed -> merged, sorted [start, end] ranges of public IPv4 space. */
function parseFeed(text) {
  const ranges = [];
  for (let line of text.split('\n')) {
    line = line.trim();
    if (!line || line[0] === '#' || line[0] === ';') continue;
    let token = line.split(/[\s,;]/)[0];
    if (line[0] === '{') { try { token = JSON.parse(line).cidr || ''; } catch { continue; } }
    const r = parseIpv4Cidr(token);
    if (!r) continue;
    const startIp = [r[0] >>> 24, (r[0] >>> 16) & 255, (r[0] >>> 8) & 255, r[0] & 255].join('.');
    if (!isPublicIp(startIp)) continue; // FireHOL also lists private/reserved space
    ranges.push(r);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  return merged;
}

function inRanges(ranges, n) {
  let lo = 0, hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (n < ranges[mid][0]) hi = mid - 1;
    else if (n > ranges[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

class ThreatIntel {
  constructor(dir, getSettings) {
    this.dir = path.join(dir, 'intel');
    this.getSettings = getSettings;
    fs.mkdirSync(this.dir, { recursive: true });
    this.meta = {};
    this.ranges = {};
    this.cache = new Map();
    this.updating = false;
  }

  load() {
    try { this.meta = JSON.parse(fs.readFileSync(path.join(this.dir, 'meta.json'), 'utf8')); } catch { this.meta = {}; }
    for (const f of FEEDS) {
      try { this.ranges[f.id] = parseFeed(fs.readFileSync(path.join(this.dir, `${f.id}.txt`), 'utf8')); } catch { this.ranges[f.id] = []; }
    }
    this.cache.clear();
  }

  enabledFeeds() {
    const s = this.getSettings().intel;
    return s.enabled ? FEEDS.filter((f) => s.feeds[f.id] !== false) : [];
  }

  /** Downloads feeds older than a day (or all of them when forced). Returns true if anything changed. */
  async update(force = false) {
    if (this.updating) return false;
    this.updating = true;
    let changed = false;
    try {
      for (const f of this.enabledFeeds()) {
        const m = this.meta[f.id] || {};
        if (!force && m.updatedAt && Date.now() - m.updatedAt < MAX_AGE_MS) continue;
        try {
          const res = await fetch(f.url, { signal: AbortSignal.timeout(45000), headers: { 'User-Agent': 'NetWatch/1.0 (network monitor)' } });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const text = await res.text();
          const ranges = parseFeed(text);
          fs.writeFileSync(path.join(this.dir, `${f.id}.txt`), text);
          this.ranges[f.id] = ranges;
          this.meta[f.id] = { updatedAt: Date.now(), count: ranges.length, error: '' };
          changed = true;
        } catch (e) {
          this.meta[f.id] = { ...m, error: e.message || String(e), triedAt: Date.now() };
        }
      }
      fs.writeFileSync(path.join(this.dir, 'meta.json'), JSON.stringify(this.meta));
      if (changed) this.cache.clear();
    } finally { this.updating = false; }
    return changed;
  }

  /** The first enabled feed that lists this IP, or null. IPv6 isn't covered by these lists. */
  lookup(ip) {
    if (!net.isIPv4(ip)) return null;
    if (this.cache.has(ip)) return this.cache.get(ip);
    const n = ipv4ToInt(ip);
    let hit = null;
    for (const f of this.enabledFeeds()) {
      if (inRanges(this.ranges[f.id] || [], n)) { hit = { id: f.id, name: f.name }; break; }
    }
    if (this.cache.size > 20000) this.cache.clear();
    this.cache.set(ip, hit);
    return hit;
  }

  status() {
    const s = this.getSettings().intel;
    return FEEDS.map((f) => ({
      id: f.id, name: f.name, about: f.about,
      enabled: s.enabled && s.feeds[f.id] !== false,
      ranges: (this.ranges[f.id] || []).length,
      updatedAt: (this.meta[f.id] || {}).updatedAt || 0,
      error: (this.meta[f.id] || {}).error || '',
    }));
  }
}

module.exports = { ThreatIntel, FEEDS, parseFeed, inRanges };
