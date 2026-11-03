(() => {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
  };

  // In the app the preload script provides window.netwatch; in browser mode we talk to the local server.
  const NO_KEY = 'Open NetWatch with the link it printed when it started: the link contains your access key.';
  const bridge = window.netwatch || (() => {
    // The access key arrives in the link NetWatch printed (#token=...). It is kept for this tab only and
    // removed from the address bar so it doesn't linger in history or get copied along with the URL.
    let token = '';
    const m = /(?:^#|&)token=([0-9a-f]+)/.exec(location.hash);
    if (m) {
      token = m[1];
      try { sessionStorage.setItem('nw.token', token); } catch { /* storage unavailable: key lives in memory */ }
      history.replaceState(null, '', location.pathname + location.search);
    } else {
      try { token = sessionStorage.getItem('nw.token') || ''; } catch { /* storage unavailable */ }
    }
    const call = async (type, payload) => {
      if (type === 'openExternal') { window.open(payload.url, '_blank', 'noopener'); return { ok: true, result: true }; }
      if (!token) return { ok: false, error: NO_KEY };
      try {
        const r = await fetch('/api/call', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-NetWatch-Token': token }, body: JSON.stringify({ type, payload }) });
        if (r.status === 403) return { ok: false, error: `${NO_KEY} (NetWatch makes a new key each time it starts.)` };
        return await r.json();
      } catch (e) { return { ok: false, error: 'NetWatch is not running.' }; }
    };
    return {
      call,
      onState(cb) { setInterval(async () => { const r = await call('getState'); if (r.ok) cb(r.result); else failed = true; }, 3000); },
      onOpenProgram() {},
    };
  })();

  // ---------- icons (status is never shown by colour alone) ----------
  const ICON = {
    HIGH: '<svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><path d="M5.2 1h5.6L15 5.2v5.6L10.8 15H5.2L1 10.8V5.2z" fill="var(--critical)"/><path d="M8 4.5v4.2M8 11.2v.3" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/></svg>',
    MEDIUM: '<svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.3l7 12.6H1z" fill="var(--warning)" stroke="var(--warning)" stroke-width="1" stroke-linejoin="round"/><path d="M8 6v3.6M8 11.8v.2" stroke="#0b0b0b" stroke-width="1.7" stroke-linecap="round"/></svg>',
    LOW: '<svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.3" fill="none" stroke="var(--muted)" stroke-width="1.5"/><path d="M8 7.2v4M8 4.8v.2" stroke="var(--muted)" stroke-width="1.6" stroke-linecap="round"/></svg>',
    OK: '<svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 8.4l2.9 2.9 6-6.3" fill="none" stroke="var(--good)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    TRUSTED: '<svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5l5.5 2.2v3.9c0 3.3-2.3 6-5.5 7-3.2-1-5.5-3.7-5.5-7V3.7z" fill="none" stroke="var(--good)" stroke-width="1.5" stroke-linejoin="round"/><path d="M5.6 8.1l1.7 1.7 3.2-3.3" fill="none" stroke="var(--good)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    BLOCKED: '<svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.2" fill="none" stroke="var(--critical)" stroke-width="1.6"/><path d="M3.7 12.3l8.6-8.6" stroke="var(--critical)" stroke-width="1.6"/></svg>',
    CLOSE: '<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    INFO: '<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" style="flex:none;margin-top:2px"><circle cx="8" cy="8" r="6.3" fill="none" stroke="var(--muted)" stroke-width="1.5"/><path d="M8 7.2v4M8 4.8v.2" stroke="var(--muted)" stroke-width="1.6" stroke-linecap="round"/></svg>',
  };
  const SEV_LABEL = { HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low' };
  const sevTag = (sev) => `<span class="sev ${sev === 'LOW' ? 'low' : ''}">${ICON[sev]}${SEV_LABEL[sev]}</span>`;
  const trustedBadge = `<span class="badge">${ICON.TRUSTED}Trusted</span>`;
  const blockedBadge = `<span class="badge">${ICON.BLOCKED}Blocked</span>`;
  const regionNames = (() => { try { return new Intl.DisplayNames(['en'], { type: 'region' }); } catch { return null; } })();
  const countryName = (cc) => { try { return (regionNames && regionNames.of(cc)) || cc; } catch { return cc; } };

  // ---------- formatting ----------
  function fmtRate(bps) {
    if (bps == null) return { v: '–', u: '' };
    if (bps < 1e3) return { v: Math.round(bps).toString(), u: 'bps' };
    if (bps < 1e6) return { v: (bps / 1e3).toFixed(bps < 1e4 ? 1 : 0), u: 'Kbps' };
    if (bps < 1e9) return { v: (bps / 1e6).toFixed(bps < 1e7 ? 2 : 1), u: 'Mbps' };
    return { v: (bps / 1e9).toFixed(2), u: 'Gbps' };
  }
  const rateText = (bps) => { const r = fmtRate(bps); return r.u ? `${r.v} ${r.u}` : r.v; };
  function fmtAxisRate(v) {
    if (v === 0) return '0';
    if (v < 1e3) return `${Math.round(v)} bps`;
    if (v < 1e6) return `${+(v / 1e3).toFixed(1)} Kbps`;
    if (v < 1e9) return `${+(v / 1e6).toFixed(1)} Mbps`;
    return `${+(v / 1e9).toFixed(1)} Gbps`;
  }
  function fmtBytes(b) {
    if (b == null) return { v: '–', u: '' };
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
    return { v: i === 0 ? String(Math.round(b)) : b.toFixed(b < 10 ? 2 : b < 100 ? 1 : 0), u: units[i] };
  }
  const bytesText = (b) => { const r = fmtBytes(b); return r.u ? `${r.v} ${r.u}` : r.v; };
  const fmtAxisBytes = (v) => (v === 0 ? '0' : bytesText(v).replace(/\.00 /, ' '));
  function fmtDuration(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ${m % 60}m`;
    return `${Math.floor(h / 24)}d ${h % 24}h`;
  }
  function fmtAgo(t) {
    const d = Date.now() - t;
    if (d < 45e3) return 'just now';
    if (d < 36e5) return `${Math.round(d / 6e4)} min ago`;
    if (d < 864e5) return `${Math.round(d / 36e5)} h ago`;
    return new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' });
  }
  const fmtClock = (t, secs) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: secs ? '2-digit' : undefined });
  const fmtDay = (t) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' });
  function niceMax(v) {
    if (!(v > 0)) return 1;
    const e = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 1.2, 1.6, 2, 2.4, 3.2, 4, 6, 8, 10]) if (m * e >= v) return m * e; // each splits into 4 round steps
    return 10 * e;
  }
  function niceBytesMax(v) {
    if (!(v > 0)) return 1024;
    const unit = Math.pow(1024, Math.floor(Math.log(v) / Math.log(1024)));
    return niceMax(v / unit) * unit;
  }
  const dayKey = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const RANGE_LABEL = { 5: '5 min', 15: '15 min', 60: '1 hour', 360: '6 hours', 1440: '24 hours' };

  // ---------- tooltip & toast ----------
  const tip = $('#tip');
  function showTip(html, x, y) {
    tip.innerHTML = html;
    tip.hidden = false;
    const r = tip.getBoundingClientRect();
    let left = x + 14, top = y + 14;
    if (left + r.width > innerWidth - 8) left = x - r.width - 14;
    if (top + r.height > innerHeight - 8) top = y - r.height - 14;
    tip.style.left = `${Math.max(8, left)}px`;
    tip.style.top = `${Math.max(8, top)}px`;
  }
  const hideTip = () => { tip.hidden = true; };
  let toastTimer;
  function toast(msg, isError) {
    const el = $('#toast');
    el.innerHTML = `${isError ? ICON.HIGH : ICON.OK}<span>${esc(msg)}</span>`;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, isError ? 8000 : 3500);
  }

  // ---------- charts ----------
  function lineChart(el, opts) {
    const { points, series, t0, t1, yFmt, gapMs, endLabels, area } = opts;
    const W = Math.max(260, el.clientWidth), H = el.clientHeight || 220;
    const m = { t: 10, r: endLabels ? 74 : 14, b: 24, l: 64 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    if (points.length < 2) {
      el.innerHTML = `<div class="empty">${esc(opts.emptyText || 'Collecting data…')}</div>`;
      el.onpointermove = el.onpointerleave = null;
      return;
    }
    let max = 0;
    for (const p of points) for (const s of series) max = Math.max(max, p[s.key]);
    const top = Math.max(niceMax(max * 1.05), opts.minTop || 0);
    const x = (t) => m.l + ((t - t0) / (t1 - t0)) * iw;
    const y = (v) => m.t + ih - (v / top) * ih;
    let svg = `<svg width="${W}" height="${H}" role="img" aria-label="${esc(opts.label)}">`;
    for (let i = 0; i <= 4; i++) {
      const v = (top / 4) * i, yy = Math.round(y(v)) + 0.5;
      svg += `<line x1="${m.l}" x2="${m.l + iw}" y1="${yy}" y2="${yy}" stroke="${i === 0 ? 'var(--axis)' : 'var(--grid)'}" stroke-width="1"/>`;
      svg += `<text x="${m.l - 8}" y="${yy + 3.5}" text-anchor="end">${esc(yFmt(v))}</text>`;
    }
    const span = t1 - t0;
    const tickFmt = opts.tickFmt || ((t) => fmtClock(t, span <= 6 * 60e3));
    for (let i = 0; i <= 3; i++) {
      const t = t0 + (span / 3) * i;
      svg += `<text x="${x(t)}" y="${H - 6}" text-anchor="${i === 0 ? 'start' : i === 3 ? 'end' : 'middle'}">${esc(tickFmt(t))}</text>`;
    }
    const labels = [];
    for (const s of series) {
      let d = '', prev = null, runStart = null, areaD = '';
      const closeArea = (endX) => { if (area && runStart != null) areaD += `L${endX},${y(0)}L${runStart},${y(0)}Z`; };
      for (const p of points) {
        const px = x(p.t).toFixed(1), py = y(p[s.key]).toFixed(1);
        if (prev == null || p.t - prev.t > gapMs) {
          if (prev != null) closeArea(x(prev.t).toFixed(1));
          d += `M${px},${py}`; areaD += `M${px},${py}`; runStart = px;
        } else { d += `L${px},${py}`; areaD += `L${px},${py}`; }
        prev = p;
      }
      closeArea(x(prev.t).toFixed(1));
      if (area) svg += `<path d="${areaD}" fill="var(${s.color})" opacity="0.10"/>`;
      svg += `<path d="${d}" fill="none" stroke="var(${s.color})" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
      if (endLabels) labels.push({ y: y(prev[s.key]), text: s.name });
    }
    if (labels.length) {
      labels.sort((a, b) => a.y - b.y);
      for (let i = 1; i < labels.length; i++) if (labels[i].y - labels[i - 1].y < 14) labels[i].y = labels[i - 1].y + 14;
      const overflow = labels[labels.length - 1].y - (m.t + ih - 4);
      if (overflow > 0) labels.forEach((l) => { l.y -= overflow; });
      for (const l of labels) svg += `<text class="end-label" x="${m.l + iw + 8}" y="${l.y + 4}">${esc(l.text)}</text>`;
    }
    svg += `<line class="xh" y1="${m.t}" y2="${m.t + ih}" stroke="var(--axis)" stroke-width="1" visibility="hidden"/>`;
    for (const s of series) svg += `<circle class="hd" data-k="${s.key}" r="4" fill="var(${s.color})" stroke="var(--surface)" stroke-width="2" visibility="hidden"/>`;
    el.innerHTML = `${svg}</svg>`;
    const xh = el.querySelector('.xh');
    const dots = [...el.querySelectorAll('.hd')];
    const leave = () => { xh.setAttribute('visibility', 'hidden'); dots.forEach((c) => c.setAttribute('visibility', 'hidden')); hideTip(); el._hover = null; };
    const hover = (cx, cy) => {
      const px = cx - el.getBoundingClientRect().left;
      if (px < m.l - 10 || px > m.l + iw + 10) return leave();
      const t = t0 + ((px - m.l) / iw) * (t1 - t0);
      let best = points[0];
      for (const p of points) if (Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
      const bx = x(best.t);
      xh.setAttribute('x1', bx); xh.setAttribute('x2', bx); xh.setAttribute('visibility', 'visible');
      dots.forEach((c) => { c.setAttribute('cx', bx); c.setAttribute('cy', y(best[c.dataset.k])); c.setAttribute('visibility', 'visible'); });
      let html = `<div class="tip-title">${esc(opts.tipTitle ? opts.tipTitle(best.t) : fmtClock(best.t, true))}</div>`;
      for (const s of series) html += `<div class="tip-row"><i class="sw" style="background:var(${s.color})"></i>${esc(s.name)}<b>${esc(s.fmt(best[s.key]))}</b></div>`;
      showTip(html, cx, cy);
      el._hover = [cx, cy];
    };
    el.onpointermove = (e) => hover(e.clientX, e.clientY);
    el.onpointerleave = leave;
    if (el._hover) hover(...el._hover);
  }

  /** Grouped bars per category (here: download and upload per day). */
  function barChart(el, { cats, series, yFmt, label, catFmt }) {
    const W = Math.max(260, el.clientWidth), H = el.clientHeight || 220;
    const m = { t: 10, r: 10, b: 24, l: 64 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    let max = 0;
    for (const c of cats) for (const s of series) max = Math.max(max, c[s.key]);
    if (!max) { el.innerHTML = '<div class="empty">No data yet for this period.</div>'; el.onpointermove = null; return; }
    const top = niceBytesMax(max * 1.05);
    const y = (v) => m.t + ih - (v / top) * ih;
    const band = iw / cats.length;
    const gap = 2;
    const bw = Math.max(2, Math.min(22, (band * 0.7 - gap) / series.length));
    let svg = `<svg width="${W}" height="${H}" role="img" aria-label="${esc(label)}">`;
    for (let i = 0; i <= 4; i++) {
      const v = (top / 4) * i, yy = Math.round(y(v)) + 0.5;
      svg += `<line x1="${m.l}" x2="${m.l + iw}" y1="${yy}" y2="${yy}" stroke="${i === 0 ? 'var(--axis)' : 'var(--grid)'}" stroke-width="1"/>`;
      svg += `<text x="${m.l - 8}" y="${yy + 3.5}" text-anchor="end">${esc(yFmt(v))}</text>`;
    }
    const every = Math.ceil(cats.length / 7);
    cats.forEach((c, i) => {
      const cx = m.l + band * i + band / 2;
      const groupW = bw * series.length + gap * (series.length - 1);
      series.forEach((s, j) => {
        const v = c[s.key];
        if (v <= 0) return;
        const bx = cx - groupW / 2 + j * (bw + gap), by = y(v), bh = Math.max(1, y(0) - by);
        const r = Math.min(4, bw / 2, bh);
        svg += `<path d="M${bx},${y(0)}V${by + r}Q${bx},${by} ${bx + r},${by}H${bx + bw - r}Q${bx + bw},${by} ${bx + bw},${by + r}V${y(0)}Z" fill="var(${s.color})"/>`;
      });
      if (i % every === 0 || i === cats.length - 1) svg += `<text x="${cx}" y="${H - 6}" text-anchor="middle">${esc(catFmt(c))}</text>`;
    });
    el.innerHTML = `${svg}</svg>`;
    el.onpointermove = (e) => {
      const px = e.clientX - el.getBoundingClientRect().left - m.l;
      const i = Math.floor(px / band);
      if (i < 0 || i >= cats.length) return hideTip();
      const c = cats[i];
      let html = `<div class="tip-title">${esc(catFmt(c, true))}</div>`;
      for (const s of series) html += `<div class="tip-row"><i class="sw box" style="background:var(${s.color})"></i>${esc(s.name)}<b>${esc(bytesText(c[s.key]))}</b></div>`;
      showTip(html, e.clientX, e.clientY);
    };
    el.onpointerleave = hideTip;
  }

  // ---------- state ----------
  let state = null, lastOk = 0, failed = false;
  let tab = 'overview';
  let rangeMin = +store.get('nw.range') || 15;
  if (!RANGE_LABEL[rangeMin]) rangeMin = 15;
  let metric = store.get('nw.metric') || 'conns';
  let alertSev = 'ALL';
  let openProgram = null;
  const details = new Map();
  let report = null, repDays = +store.get('nw.repDays') || 7;
  let settingsDirty = false, clearToken = false;
  let editingDevice = null;

  const snap = () => state && state.snapshot;
  const programByName = (name) => (snap() ? snap().programs.find((p) => p.name === name) : null);

  async function call(type, payload, okMsg) {
    const res = await bridge.call(type, payload || {});
    if (!res || !res.ok) { toast((res && res.error) || 'Something went wrong.', true); return null; }
    if (res.result && res.result.snapshot !== undefined) { state = res.result; render(); }
    if (okMsg) toast(okMsg);
    return res.result === undefined ? true : res.result;
  }

  function setPressed(groupSel, attr, val) {
    $$(`${groupSel} button`).forEach((b) => b.setAttribute('aria-pressed', String(b.dataset[attr] === String(val))));
  }

  // ---------- tabs ----------
  function showTab(name, push = true) {
    if (!['overview', 'devices', 'reports', 'settings'].includes(name)) name = 'overview';
    tab = name;
    $$('#tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
    $$('main[role="tabpanel"]').forEach((m) => { m.hidden = m.id !== `tab-${name}`; });
    if (push) history.replaceState(null, '', `#${name}`);
    if (name === 'reports') loadReport();
    if (name === 'settings') { settingsDirty = false; renderSettings(); }
    render();
  }
  $('#tabs').addEventListener('click', (e) => { const b = e.target.closest('button[data-tab]'); if (b) showTab(b.dataset.tab); });

  // ---------- header, notices, footer ----------
  function updateStatus() {
    const el = $('#status'), txt = $('#statusText');
    const stale = !lastOk || (failed && Date.now() - lastOk > 10e3);
    const paused = state && state.app && state.app.snoozedUntil > Date.now();
    el.classList.toggle('live', !stale && !paused);
    el.classList.toggle('paused', !stale && !!paused);
    el.classList.toggle('down', stale && failed);
    if (!lastOk) txt.textContent = failed ? 'Not connected' : 'Starting…';
    else if (stale) txt.textContent = `Disconnected. Last update ${fmtAgo(lastOk)}`;
    else if (paused) txt.textContent = `Alerts paused until ${fmtClock(state.app.snoozedUntil)}`;
    else {
      const age = snap() ? Math.round((Date.now() - snap().t) / 1000) : 0;
      txt.textContent = `Live · scanned ${age <= 1 ? 'just now' : `${age}s ago`}`;
    }
  }
  setInterval(updateStatus, 1000);

  function renderHeader() {
    const paused = state.app.snoozedUntil > Date.now();
    $('#snoozeBtn').textContent = paused ? 'Resume alerts' : 'Pause alerts 1 h';
    $('#devCount').textContent = state.devices.length || '';
    const n = $('#capNotice');
    const caps = state.capabilities;
    let html = '';
    if (state.lastError) {
      html = `${ICON.HIGH}<div><b>Problem:</b> ${esc(state.lastError)}</div>`;
    } else if (!state.admin) {
      const missing = [caps.perProgram ? '' : 'per-program speed and data use', state.platform === 'windows' ? 'website names and firewall blocking' : '']
        .filter(Boolean).join(', ');
      if (state.platform === 'windows') {
        html = `${ICON.INFO}<div><b>Running without admin rights.</b> ${esc(missing ? `Off until you restart as administrator: ${missing}.` : '')}</div>` +
          (state.app.canRelaunchAdmin ? '<button class="btn" data-act="relaunchAdmin">Restart as administrator</button>' : '');
      } else if (!caps.perProgram || state.platform === 'macos') {
        // The desktop app can't run as root (Electron refuses), so point at browser mode instead.
        html = `${ICON.INFO}<div><b>Running without root.</b> Connections of system services and other users show as "Unknown process". ` +
          'To see them, run NetWatch\'s browser mode with <code>sudo</code> (see the README, "Browser mode").</div>';
      }
    }
    n.innerHTML = html;
    n.hidden = !html;
    const geo = state.geo;
    $('#foot').innerHTML = `NetWatch ${esc(state.version)} · ${esc(state.platform)}${state.admin ? ' · administrator' : ''} · scanning every ${esc(state.interval)} s · running for ${esc(fmtDuration(Date.now() - state.startedAt))}` +
      (geo.enabled ? ` · <button class="link" data-act="openExternal" data-url="https://db-ip.com">IP Geolocation by DB-IP</button>` : '');
  }

  // ---------- render dispatcher ----------
  function render() {
    if (!state) return;
    renderHeader();
    if (tab === 'overview' && snap()) {
      renderTiles(); renderCharts(); renderAlerts(); renderBars(); renderTable(); renderListeners(); renderRules();
    }
    if (tab === 'devices' && !editingDevice) renderDevices();
    // Settings are drawn when the tab opens or after a save, never on live updates (that would close open dropdowns).
    const sel = getSelection();
    const selectingInDrawer = sel && !sel.isCollapsed && $('#drawer').contains(sel.anchorNode);
    if (openProgram && !selectingInDrawer) renderDrawer();
    updateStatus();
  }

  // ---------- overview ----------
  function windowPoints() {
    const minute = rangeMin > 60;
    const raw = (minute ? state.history.min : state.history.raw) || [];
    const now = snap() ? snap().t : Date.now();
    const from = now - rangeMin * 60e3;
    const pts = raw.filter((a) => a[0] >= from).map((a) => ({ t: a[0], conns: a[1], rx: a[2], tx: a[3] }));
    const minSpan = minute ? 30 * 60e3 : 60e3;
    const t0 = pts.length ? Math.min(Math.max(from, pts[0].t), now - minSpan) : from;
    return { pts, t0, t1: now, minute };
  }

  function renderTiles() {
    const s = snap();
    const programs = new Set(s.connections.map((c) => c.program));
    const flagged = s.connections.filter((c) => c.risk).length;
    $('#tConns').textContent = s.connections.length;
    $('#tConnsSub').textContent = `from ${programs.size} program${programs.size === 1 ? '' : 's'}${flagged ? ` · ${flagged} flagged` : ''}`;
    const { pts, minute } = windowPoints();
    const rx = fmtRate(s.rxBps), tx = fmtRate(s.txBps);
    $('#tRx').innerHTML = `${esc(rx.v)}<small>${esc(rx.u)}</small>`;
    $('#tTx').innerHTML = `${esc(tx.v)}<small>${esc(tx.u)}</small>`;
    const peak = (k) => pts.reduce((a, p) => Math.max(a, p[k]), 0);
    const word = minute ? 'busiest minute' : 'peak';
    $('#tRxSub').textContent = pts.length ? `${word} ${rateText(peak('rx'))} in last ${RANGE_LABEL[rangeMin]}` : 'measuring…';
    $('#tTxSub').textContent = pts.length ? `${word} ${rateText(peak('tx'))} in last ${RANGE_LABEL[rangeMin]}` : 'measuring…';
    const today = fmtBytes(s.todayRx + s.todayTx);
    $('#tToday').innerHTML = `${esc(today.v)}<small>${esc(today.u)}</small>`;
    const cap = state.settings.dailyCapGB;
    $('#tTodaySub').textContent = cap ? `${Math.round(((s.todayRx + s.todayTx) / (cap * 1024 ** 3)) * 100)}% of your ${cap} GB limit` : `↓ ${bytesText(s.todayRx)} · ↑ ${bytesText(s.todayTx)}`;
    const newL = s.listeners.filter((l) => l.isNew).length;
    $('#tListen').textContent = s.listeners.length;
    $('#tListenSub').textContent = newL ? `${newL} opened since NetWatch started` : 'no new ones since start';
    const since = Date.now() - 864e5;
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const a of state.alerts) if (a.t >= since && counts[a.severity] !== undefined) counts[a.severity]++;
    $('#tAlerts').innerHTML = ['HIGH', 'MEDIUM', 'LOW'].map((k) => `<span>${ICON[k]}<b>${counts[k]}</b>${SEV_LABEL[k]}</span>`).join('');
  }

  function renderCharts() {
    const { pts, t0, t1, minute } = windowPoints();
    const gapMs = minute ? 180e3 : state.interval * 3000;
    const emptyText = minute ? 'Longer history builds up while NetWatch keeps running. It is saved, so restarts keep it.' : 'Collecting data… the chart fills in over the next few seconds.';
    const tipTitle = minute ? (t) => `${fmtClock(t)} · 1-min average` : undefined;
    lineChart($('#speedChart'), {
      label: 'Download and upload speed over time', points: pts, t0, t1, gapMs, emptyText, tipTitle, endLabels: true, yFmt: fmtAxisRate,
      series: [{ key: 'rx', name: 'Download', color: '--s1', fmt: rateText }, { key: 'tx', name: 'Upload', color: '--s2', fmt: rateText }],
    });
    lineChart($('#connChart'), {
      label: 'Number of internet connections over time', points: pts, t0, t1, gapMs, emptyText, tipTitle, area: true, minTop: 4,
      yFmt: (v) => String(Math.round(v)), series: [{ key: 'conns', name: 'Connections', color: '--s1', fmt: (v) => String(v) }],
    });
  }

  function renderAlerts() {
    const list = state.alerts.filter((a) => alertSev === 'ALL' || a.severity === alertSev).slice(-200).reverse();
    const el = $('#alerts');
    if (!list.length) {
      el.innerHTML = `<div class="empty" style="height:120px">${ICON.OK}&nbsp; ${alertSev === 'ALL' ? 'No alerts. Everything looks normal.' : `No ${SEV_LABEL[alertSev].toLowerCase()} alerts.`}</div>`;
      return;
    }
    el.innerHTML = list.map((a) => {
      const linked = a.program && programByName(a.program);
      return `<div class="alert-row ${linked ? 'clickable' : ''}" ${linked ? `data-program="${esc(a.program)}" title="Show ${esc(a.program)} details"` : ''}>
        ${sevTag(a.severity)}<div class="alert-msg">${esc(a.message)}</div>
        <div class="alert-time" title="${esc(new Date(a.t).toLocaleString())}">${esc(fmtAgo(a.t))}</div></div>`;
    }).join('');
  }
  $('#alerts').addEventListener('click', (e) => { const r = e.target.closest('[data-program]'); if (r) openDrawer(r.dataset.program); });

  const METRIC = {
    conns: { get: (p) => p.conns, fmt: (v) => String(v), other: () => 0 },
    rx: { get: (p) => p.rxBps || 0, fmt: rateText, other: (s, sum) => Math.max(0, s.rxBps - sum) },
    tx: { get: (p) => p.txBps || 0, fmt: rateText, other: (s, sum) => Math.max(0, s.txBps - sum) },
    today: { get: (p) => p.todayRx + p.todayTx, fmt: bytesText, other: (s, sum) => Math.max(0, s.todayRx + s.todayTx - sum) },
  };

  function renderBars() {
    const s = snap(), el = $('#bars');
    const hasToday = s.programs.some((p) => p.todayRx + p.todayTx > 0);
    $$('#metric button').forEach((b) => {
      const k = b.dataset.metric;
      b.disabled = k === 'rx' || k === 'tx' ? !s.measuring : k === 'today' ? !s.measuring && !hasToday : false;
      b.title = b.disabled ? 'Needs per-program measuring (run NetWatch as administrator)' : '';
    });
    if ($(`#metric button[data-metric="${metric}"]`).disabled) metric = 'conns';
    setPressed('#metric', 'metric', metric);
    const M = METRIC[metric];
    let rows = s.programs.map((p) => ({ p, name: p.name, n: M.get(p) })).filter((r) => r.n > 0).sort((a, b) => b.n - a.n || a.name.localeCompare(b.name));
    const sum = rows.reduce((a, r) => a + r.n, 0);
    if (rows.length > 7) {
      const rest = rows.slice(6);
      rows = rows.slice(0, 6);
      rows.push({ name: `${rest.length} other programs`, n: rest.reduce((a, r) => a + r.n, 0), other: true, list: rest.map((r) => r.name) });
    }
    const otherTraffic = M.other(s, sum);
    if (otherTraffic > 0 && metric !== 'conns') rows.push({ name: 'Other traffic', n: otherTraffic, other: true, unattributed: true });
    if (!rows.length) {
      el.innerHTML = `<div class="empty" style="height:120px">${metric === 'conns' ? 'No programs are connected to the internet right now.' : 'No traffic right now.'}</div>`;
      return;
    }
    const max = Math.max(...rows.map((r) => r.n));
    el.innerHTML = rows.map((r, i) => {
      const p = r.p;
      const icon = p ? (p.blocked ? ICON.BLOCKED : p.risk ? ICON[p.risk] : p.trusted ? ICON.TRUSTED : '') : '';
      return `<div class="bar-row ${p ? 'clickable' : ''}" data-i="${i}">
        <div class="bar-label">${icon}<span>${esc(r.name)}</span></div>
        <div class="bar-track"><div class="bar ${r.other ? 'other' : ''}" style="width:${(r.n / max) * 100}%"></div></div>
        <div class="bar-val">${esc(M.fmt(r.n))}</div></div>`;
    }).join('');
    el.onpointermove = (e) => {
      const row = e.target.closest('.bar-row'); if (!row) return hideTip();
      const r = rows[+row.dataset.i];
      let html = `<div class="tip-title">${esc(r.name)} · ${esc(M.fmt(r.n))}</div>`;
      if (r.unattributed) html += '<div>Traffic NetWatch can\'t tie to one program: UDP (video calls, games, some streaming), DNS and the system itself.</div>';
      else if (r.other) html += r.list.slice(0, 10).map((n) => `<div>${esc(n)}</div>`).join('');
      else {
        const p = r.p;
        if (p.risk) html += `<div style="margin-bottom:4px">${sevTag(p.risk)} flagged</div>`;
        html += `<div class="tip-row">Connections<b>${p.conns}</b></div>`;
        if (s.measuring) html += `<div class="tip-row">Download<b>${esc(rateText(p.rxBps))}</b></div><div class="tip-row">Upload<b>${esc(rateText(p.txBps))}</b></div>`;
        if (p.todayRx + p.todayTx > 0) html += `<div class="tip-row">Used today<b>${esc(bytesText(p.todayRx + p.todayTx))}</b></div>`;
        html += '<div class="dim" style="margin-top:4px">Click for details</div>';
      }
      showTip(html, e.clientX, e.clientY);
    };
    el.onpointerleave = hideTip;
    el.onclick = (e) => { const row = e.target.closest('.bar-row'); const r = row && rows[+row.dataset.i]; if (r && r.p) { hideTip(); openDrawer(r.p.name); } };
  }

  const SIG = { Valid: 'Signed', NotSigned: 'Unsigned', HashMismatch: 'Tampered', NotTrusted: 'Untrusted', UnknownError: 'Invalid', Unknown: 'Unknown', Checking: 'Checking…', 'n/a': 'n/a' };
  const riskRank = { HIGH: 2, MEDIUM: 1, '': 0 };
  const sigCell = (sig, publisher) => sig === 'Valid' ? `${esc(SIG[sig])}${publisher ? `<span class="sub" style="word-break:normal;min-width:110px">${esc(publisher)}</span>` : ''}`
    : ['Unknown', 'Checking', 'n/a', ''].includes(sig || '') ? `<span class="dim">${esc(SIG[sig] || 'Unknown')}</span>`
      : `<span class="sev">${ICON.MEDIUM}${esc(SIG[sig] || sig)}</span>`;
  const speedText = (c) => (c.rxBps == null ? '<span class="dim">–</span>'
    : `<span class="nowrap">↓ ${esc(rateText(c.rxBps))}</span><br><span class="nowrap dim">↑ ${esc(rateText(c.txBps))}</span>`);
  const siteCell = (c) => {
    if (c.domain) return `${esc(c.domain)}${c.host && c.host !== c.domain ? `<span class="sub">${esc(c.host)}</span>` : ''}`;
    return c.host ? esc(c.host) : c.host === null ? '<span class="dim">looking up…</span>' : '<span class="dim">no name</span>';
  };
  const ccCell = (cc) => (cc ? `<span class="cc" title="${esc(countryName(cc))}">${esc(cc)}</span><span class="dim">${esc(countryName(cc))}</span>` : '<span class="dim">–</span>');

  function renderTable() {
    const s = snap();
    const showSpeed = s.measuring;
    $('#connHead').innerHTML = `<th>Status</th><th>Program</th><th>Website</th><th>Address</th><th>Country</th>${showSpeed ? '<th>Speed</th>' : ''}<th>Signature</th><th>Seen for</th>`;
    const q = $('#search').value.trim().toLowerCase();
    const only = $('#onlyFlagged').checked;
    const all = s.connections;
    const rows = all
      .filter((c) => !only || c.risk)
      .filter((c) => !q || [c.program, c.host, c.domain, c.remoteIp, c.path, String(c.remotePort), c.country, c.country && countryName(c.country)].some((v) => v && String(v).toLowerCase().includes(q)))
      .sort((a, b) => riskRank[b.risk] - riskRank[a.risk] || a.program.localeCompare(b.program) || (a.domain || a.host || a.remoteIp).localeCompare(b.domain || b.host || b.remoteIp));
    const cols = showSpeed ? 8 : 7;
    $('#connRows').innerHTML = rows.length ? rows.map((c) => `
      <tr class="clickable ${c.risk ? c.risk.toLowerCase() : ''}" data-program="${esc(c.program)}">
        <td>${c.risk ? sevTag(c.risk) : `<span class="sev low">${ICON.OK}OK</span>`}</td>
        <td title="${esc(c.path || '')}">${esc(c.program)} <span class="dim num">· ${c.pid}</span> ${c.trusted ? trustedBadge : ''}
          ${c.path && c.risk ? `<span class="sub">${esc(c.path)}</span>` : ''}${c.flags.length ? `<span class="flags">${esc(c.flags.join(' · '))}</span>` : ''}</td>
        <td>${siteCell(c)}</td>
        <td class="mono">${esc(c.remoteIp)}:${c.remotePort}</td>
        <td class="nowrap">${ccCell(c.country)}</td>
        ${showSpeed ? `<td class="num">${speedText(c)}</td>` : ''}
        <td>${sigCell(c.signature, c.publisher)}</td>
        <td class="num dim">${c.since ? esc(fmtDuration(s.t - c.since)) : '–'}</td>
      </tr>`).join('') : `<tr><td colspan="${cols}" class="dim" style="text-align:center;padding:24px">${all.length ? 'No connections match.' : 'No internet connections right now.'}</td></tr>`;
    $('#connFoot').textContent = rows.length === all.length ? `${all.length} connections` : `Showing ${rows.length} of ${all.length} connections`;
  }
  $('#connRows').addEventListener('click', (e) => { const r = e.target.closest('tr[data-program]'); if (r) openDrawer(r.dataset.program); });
  $('#search').addEventListener('input', () => renderTable());
  $('#onlyFlagged').addEventListener('change', () => renderTable());

  function renderListeners() {
    const s = snap();
    $('#listenRows').innerHTML = s.listeners.length ? s.listeners.map((l) => `
      <tr class="${l.isNew ? 'medium' : ''}"><td>${esc(l.program)}</td><td class="num">${l.port}</td>
        <td class="mono">${l.address === '::' ? 'All (IPv6)' : l.address === '0.0.0.0' || l.address === '*' ? 'All (IPv4)' : esc(l.address)}</td>
        <td class="num dim">${l.pid}</td><td>${l.isNew ? `<span class="badge">${ICON.MEDIUM}New</span>` : ''}</td></tr>`).join('')
      : '<tr><td colspan="5" class="dim" style="text-align:center;padding:20px">Nothing is listening for incoming connections.</td></tr>';
  }

  function renderRules() {
    const s = snap();
    const canBlock = state.capabilities.firewall;
    const empty = (t) => `<li><span class="dim">${t}</span></li>`;
    $('#ruleTrusted').innerHTML = s.trusted.length ? s.trusted.map((k) => `<li>${ICON.TRUSTED}<span>${esc(k)}</span><button class="btn small" data-act="untrust" data-key="${esc(k)}">Remove</button></li>`).join('')
      : empty('None yet. Trust a program from its details panel.');
    $('#ruleBlocked').innerHTML = !state.capabilities.firewallSupported ? empty('Blocking programs is available on Windows only.')
      : s.blocked.length ? s.blocked.map((p) => `<li>${ICON.BLOCKED}<span>${esc(p)}</span><button class="btn small" data-act="unblock" data-path="${esc(p)}" ${canBlock ? '' : 'disabled title="Needs admin rights"'}>Unblock</button></li>`).join('')
        : empty('No programs blocked.');
    $('#ruleBlocklist').innerHTML = s.blocklist.length ? s.blocklist.map((ip) => `<li><span class="mono">${esc(ip)}</span><button class="btn small" data-act="unlist" data-ip="${esc(ip)}">Remove</button></li>`).join('')
      : empty('No addresses blocklisted.');
  }
  $('#addIpForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = $('#addIp').value.trim();
    if (ip && await call('blocklist', { ip, add: true }, `${ip} added to the blocklist`)) $('#addIp').value = '';
  });

  // controls
  setPressed('#range', 'min', rangeMin);
  setPressed('#alertFilter', 'sev', alertSev);
  $('#range').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    rangeMin = +b.dataset.min; store.set('nw.range', rangeMin); setPressed('#range', 'min', rangeMin); renderTiles(); renderCharts();
  });
  $('#alertFilter').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    alertSev = b.dataset.sev; setPressed('#alertFilter', 'sev', alertSev); renderAlerts();
  });
  $('#metric').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b || b.disabled) return;
    metric = b.dataset.metric; store.set('nw.metric', metric); renderBars();
  });

  // ---------- program drawer ----------
  async function openDrawer(name) {
    openProgram = name;
    $('#backdrop').hidden = false; $('#drawer').hidden = false;
    document.body.classList.add('drawer-open');
    renderDrawer();
    const close = $('#drawer .icon-btn'); if (close) close.focus();
    const cached = details.get(name);
    if (!cached || Date.now() - cached.at > 60e3) {
      const d = await call('details', { name });
      details.set(name, { at: Date.now(), d: d || {} });
      if (openProgram === name) renderDrawer();
    }
  }
  function closeDrawer() {
    openProgram = null;
    $('#backdrop').hidden = true; $('#drawer').hidden = true;
    document.body.classList.remove('drawer-open');
  }
  $('#backdrop').addEventListener('click', closeDrawer);
  addEventListener('keydown', (e) => { if (e.key === 'Escape' && openProgram) closeDrawer(); });

  function renderDrawer() {
    const s = snap(), el = $('#drawer');
    if (!s) return;
    const p = programByName(openProgram);
    const keepScroll = el.scrollTop;
    if (!p) {
      el.innerHTML = `<div class="drawer-head"><h2>${esc(openProgram)}</h2><button class="icon-btn" data-act="close" aria-label="Close">${ICON.CLOSE}</button></div><p class="dim">This program isn't online anymore.</p>`;
      return;
    }
    const conns = s.connections.filter((c) => c.program === openProgram);
    const groups = [], byAddr = new Map();
    for (const c of conns) {
      const k = `${c.remoteIp}|${c.remotePort}`;
      let g = byAddr.get(k);
      if (!g) { g = { ...c, n: 0, rxBps: c.rxBps == null ? null : 0, txBps: c.txBps == null ? null : 0 }; byAddr.set(k, g); groups.push(g); }
      g.n++;
      if (c.rxBps != null) { g.rxBps += c.rxBps; g.txBps += c.txBps; }
      if (c.host) g.host = c.host;
    }
    const alerts = state.alerts.filter((a) => a.program === openProgram).slice().reverse();
    const caps = state.capabilities;
    const sysPath = p.path && /^([a-z]:\\windows\\|\/system\/|\/usr\/(libexec|sbin)\/)/i.test(p.path);
    let blockBtn = '', blockNote = '';
    if (caps.firewallSupported) {
      if (p.blocked) blockBtn = `<button class="btn" data-act="unblock" data-path="${esc(p.path)}" ${caps.firewall ? '' : 'disabled'}>Unblock</button>`;
      else {
        const why = !p.path ? 'Its file location is hidden; restart NetWatch as administrator to see it.'
          : sysPath ? 'System programs can\'t be blocked here; blocking them can break your connection.'
            : !caps.firewall ? 'Blocking needs NetWatch to run as administrator.' : '';
        blockBtn = `<button class="btn danger" data-act="block" data-path="${esc(p.path || '')}" ${why ? 'disabled' : ''}>${ICON.BLOCKED} Block in firewall</button>`;
        blockNote = why;
      }
    }
    const trustBtn = p.trusted
      ? `<button class="btn" data-act="untrust" data-key="${esc(p.trustKey)}">Stop trusting</button>`
      : `<button class="btn" data-act="trust" data-key="${esc(p.trustKey)}">${ICON.TRUSTED} Trust this program</button>`;
    const stat = (label, val) => `<div class="stat"><div class="tile-label">${label}</div><div class="v">${val}</div></div>`;
    const rate = (v) => { const r = fmtRate(v); return `${esc(r.v)}<small>${esc(r.u)}</small>`; };
    const bytes = (v) => { const r = fmtBytes(v); return `${esc(r.v)}<small>${esc(r.u)}</small>`; };
    const dash = '<span class="dim">–</span>';
    const det = (details.get(openProgram) || {}).d;
    const loading = '<span class="dim">loading…</span>';

    el.innerHTML = `
      <div class="drawer-head"><h2>${esc(p.name)}</h2><button class="icon-btn" data-act="close" aria-label="Close">${ICON.CLOSE}</button></div>
      <div class="path">${p.paths.length ? p.paths.map(esc).join('<br>') : 'File location unknown'}</div>
      <div class="chips">
        ${p.risk ? `<span class="badge">${ICON[p.risk]}${SEV_LABEL[p.risk]} risk</span>` : `<span class="badge">${ICON.OK}No problems found</span>`}
        ${p.trusted ? trustedBadge : ''}${p.blocked ? blockedBadge : ''}
        ${caps.signatures ? `<span class="badge">Signature: ${esc(SIG[p.signature] || p.signature)}</span>` : ''}
      </div>
      <div class="stats">
        ${stat('Connections now', p.conns)}
        ${stat('Used today', s.measuring || p.todayRx + p.todayTx ? bytes(p.todayRx + p.todayTx) : dash)}
        ${stat('Download now', s.measuring ? rate(p.rxBps || 0) : dash)}
        ${stat('Upload now', s.measuring ? rate(p.txBps || 0) : dash)}
      </div>
      ${p.unknown
        ? '<p class="action-note">NetWatch can\'t see which programs own these connections: they belong to system services or other users. They are grouped here, so they can\'t be trusted and get no per-program alerts. Run browser mode as root (or NetWatch as administrator on Windows) to see each program.</p>'
        : `<div class="actions">${trustBtn}${blockBtn}</div>
      <p class="action-note">${esc(blockNote || 'Trusting stops signature, risky-folder, busy-program, upload and quiet-hours alerts for this program.' + (caps.firewallSupported ? ' Blocking adds a firewall rule so it can\'t use the network.' : ''))}</p>`}
      <section>
        <h4>About this program</h4>
        <dl class="kv">
          <dt>Publisher</dt><dd>${p.publisher ? esc(p.publisher) : '<span class="dim">unknown</span>'}</dd>
          <dt>Started by</dt><dd>${p.parent ? `${esc(p.parent.name)} <span class="dim num">· ${p.parent.pid}</span>` : '<span class="dim">unknown</span>'}</dd>
          <dt>Process IDs</dt><dd class="num">${esc(p.pids.join(', '))}</dd>
          <dt>Countries</dt><dd>${p.countries.length ? p.countries.map((c) => esc(countryName(c))).join(', ') : '<span class="dim">–</span>'}</dd>
          <dt>UDP ports</dt><dd>${p.udpCount ? `${p.udpCount} open${p.udpPorts.length ? `: <span class="mono">${esc(p.udpPorts.slice(0, 12).join(', '))}${p.udpCount > 12 ? '…' : ''}</span>` : ''}` : '<span class="dim">none</span>'}</dd>
          <dt>Command line</dt><dd class="mono">${det ? (det.commandLine ? esc(det.commandLine) : '<span class="dim">not available</span>') : loading}</dd>
          <dt>SHA-256</dt><dd class="mono">${det ? (det.sha256 ? `${esc(det.sha256)}<br><button class="btn small" style="margin-top:6px" data-act="openExternal" data-url="https://www.virustotal.com/gui/file/${esc(det.sha256)}">Check on VirusTotal</button>` : '<span class="dim">not available</span>') : loading}</dd>
        </dl>
        ${det && det.sha256 ? '<p class="action-note" style="margin-top:6px">VirusTotal looks up this fingerprint in its database. NetWatch never uploads the file.</p>' : ''}
      </section>
      <section>
        <h4>Connections (${conns.length})</h4>
        ${groups.length ? groups.map((c) => `
          <div class="conn-item">
            <div>${siteCell(c)}${c.n > 1 ? ` <span class="dim">× ${c.n}</span>` : ''}<div class="mono">${esc(c.remoteIp)}:${c.remotePort}${c.country ? ` · ${esc(countryName(c.country))}` : ''}${c.risk ? ` · ${esc(c.flags.join(', '))}` : ''}</div></div>
            <div style="text-align:right">
              ${s.measuring && c.rxBps != null ? `<div class="num" style="font-size:12px">${speedText(c)}</div>` : ''}
              ${s.blocklist.includes(c.remoteIp.toLowerCase()) ? '<span class="badge">Blocklisted</span>'
                : `<button class="btn small" data-act="list" data-ip="${esc(c.remoteIp)}" title="Raise a High alert whenever anything connects here">Blocklist address</button>`}
            </div>
          </div>`).join('') : '<p class="dim">No open connections right now.</p>'}
      </section>
      <section>
        <h4>Alerts for this program (${alerts.length})</h4>
        ${alerts.length ? alerts.slice(0, 50).map((a) => `<div class="alert-row">${sevTag(a.severity)}<div class="alert-msg">${esc(a.message)}</div>
          <div class="alert-time" title="${esc(new Date(a.t).toLocaleString())}">${esc(fmtAgo(a.t))}</div></div>`).join('') : '<p class="dim">No alerts for this program.</p>'}
      </section>`;
    el.scrollTop = keepScroll;
  }

  // ---------- devices ----------
  function renderDevices() {
    const now = Date.now();
    const devs = state.devices;
    $('#devRows').innerHTML = devs.length ? devs.map((d) => {
      const online = now - (d.lastSeen || 0) < 3 * 60e3;
      const name = d.label || d.name;
      const nameCell = editingDevice === d.mac
        ? `<form class="add-row" data-dev-form="${esc(d.mac)}" style="margin:0"><input class="input" name="label" value="${esc(d.label || d.name || '')}" maxlength="60" aria-label="Device name"><button class="btn small" type="submit">Save</button><button class="btn small" type="button" data-act="cancelRename">Cancel</button></form>`
        : `<button class="link" data-act="renameDevice" data-mac="${esc(d.mac)}" style="color:var(--ink);text-decoration:none" title="Rename">${name ? esc(name) : '<span class="dim">Unknown device</span>'}</button>${d.label && d.name ? `<span class="sub">${esc(d.name)}</span>` : ''}`;
      return `<tr>
        <td><span class="sev ${online ? '' : 'low'}" style="font-weight:500">${online ? ICON.OK : ''}</span> ${nameCell}</td>
        <td class="mono">${esc(d.ip)}</td>
        <td class="mono">${esc(d.mac)}${d.random ? ' <span class="badge" title="Phones and laptops use private random addresses for privacy">Private address</span>' : ''}</td>
        <td class="dim nowrap">${esc(fmtAgo(d.firstSeen))}</td>
        <td class="nowrap">${online ? 'Online now' : `<span class="dim">${esc(fmtAgo(d.lastSeen))}</span>`}</td>
        <td><button class="btn small" data-act="forgetDevice" data-mac="${esc(d.mac)}">Forget</button></td>
      </tr>`;
    }).join('') : `<tr><td colspan="6" class="dim" style="text-align:center;padding:24px">${state.settings.lan.enabled ? 'No devices seen yet. The list fills in as your PC talks to other devices.' : 'Device tracking is turned off in Settings.'}</td></tr>`;
  }
  $('#devRows').addEventListener('submit', async (e) => {
    const f = e.target.closest('[data-dev-form]'); if (!f) return;
    e.preventDefault();
    const mac = f.dataset.devForm;
    editingDevice = null;
    await call('deviceLabel', { mac, label: f.label.value.trim() }, 'Device renamed');
  });

  // ---------- reports ----------
  async function loadReport() {
    const r = await call('report');
    if (r) { report = r; renderReport(); }
  }

  function renderReport() {
    if (!report) return;
    setPressed('#repRange', 'days', repDays);
    const days = [];
    for (let i = repDays - 1; i >= 0; i--) {
      const d = new Date(); d.setHours(12, 0, 0, 0); d.setDate(d.getDate() - i);
      const k = dayKey(d);
      const tot = (report.days[k] || {})['*total*'] || [0, 0];
      days.push({ key: k, t: d.getTime(), rx: tot[0], tx: tot[1] });
    }
    barChart($('#dailyChart'), {
      label: 'Data downloaded and uploaded per day', cats: days, yFmt: fmtAxisBytes,
      catFmt: (c, long) => (long ? new Date(c.t).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' }) : fmtDay(c.t)),
      series: [{ key: 'rx', name: 'Downloaded', color: '--s1' }, { key: 'tx', name: 'Uploaded', color: '--s2' }],
    });
    const now = Date.now(), from = now - repDays * 864e5;
    const pts = (report.hour || []).filter((a) => a[0] >= from).map((a) => ({ t: a[0], rx: a[2], tx: a[3] }));
    lineChart($('#hourChart'), {
      label: 'Average speed per hour', points: pts, t0: pts.length ? Math.max(from, Math.min(pts[0].t, now - 6 * 3600e3)) : from, t1: now, gapMs: 3 * 3600e3,
      yFmt: fmtAxisRate, endLabels: true, emptyText: 'Hourly history builds up while NetWatch keeps running.',
      tickFmt: (t) => fmtDay(t), tipTitle: (t) => `${new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })} · hourly average`,
      series: [{ key: 'rx', name: 'Download', color: '--s1', fmt: rateText }, { key: 'tx', name: 'Upload', color: '--s2', fmt: rateText }],
    });
    const totals = new Map();
    for (const d of days) {
      for (const [name, [rx, tx]] of Object.entries(report.days[d.key] || {})) {
        if (name === '*total*') continue;
        const t = totals.get(name) || { rx: 0, tx: 0 };
        t.rx += rx; t.tx += tx; totals.set(name, t);
      }
    }
    const rows = [...totals.entries()].map(([name, t]) => ({ name, ...t, all: t.rx + t.tx })).sort((a, b) => b.all - a.all).slice(0, 20);
    const max = rows.length ? rows[0].all : 1;
    $('#topTitle').textContent = `Programs that used the most data (last ${repDays} days)`;
    $('#topRows').innerHTML = rows.length ? rows.map((r) => `
      <tr><td>${esc(r.name)}</td><td class="r num">${esc(bytesText(r.rx))}</td><td class="r num">${esc(bytesText(r.tx))}</td><td class="r num"><b>${esc(bytesText(r.all))}</b></td>
      <td><div class="bar-track" style="border-left:1px solid var(--axis)"><div class="bar" style="width:${(r.all / max) * 100}%"></div></div></td></tr>`).join('')
      : '<tr><td colspan="5" class="dim" style="text-align:center;padding:24px">No per-program data for this period yet.</td></tr>';
    $('#topHint').textContent = state && !state.capabilities.perProgram ? 'Per-program data is only counted while NetWatch can measure each program (as administrator on Windows).' : '';
  }
  $('#repRange').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    repDays = +b.dataset.days; store.set('nw.repDays', repDays); renderReport();
  });

  // ---------- settings ----------
  const SEV_OPTIONS = (val) => ['LOW', 'MEDIUM', 'HIGH'].map((s) => `<option value="${s}" ${val === s ? 'selected' : ''}>${SEV_LABEL[s]} and above</option>`).join('').replace('High and above', 'High only');
  const field = (label, controls, help) => `<div class="field"><div class="label">${label}</div><div class="controls">${controls}</div>${help ? `<div class="help">${help}</div>` : ''}</div>`;
  const chk = (name, val, text = '') => `<label class="check"><input type="checkbox" name="${name}" ${val ? 'checked' : ''}>${text}</label>`;
  const num = (name, val, min, max, step = 1) => `<input class="input narrow" type="number" name="${name}" value="${esc(val)}" min="${min}" max="${max}" step="${step}">`;
  const text = (name, val, ph = '', type = 'text') => `<input class="input" type="${type}" name="${name}" value="${esc(val)}" placeholder="${esc(ph)}" spellcheck="false">`;

  function renderSettings() {
    if (!state) return;
    const s = state.settings, caps = state.capabilities, win = state.platform === 'windows';
    const feeds = state.intel.map((f) => `
      <div class="feed-row"><input type="checkbox" name="intel.feeds.${esc(f.id)}" ${s.intel.feeds[f.id] !== false ? 'checked' : ''} aria-label="${esc(f.name)}">
        <div><b style="font-weight:600">${esc(f.name)}</b><span class="sub">${esc(f.about)}</span></div>
        <div class="dim" style="font-size:12px;text-align:right">${f.error ? `${ICON.MEDIUM} ${esc(f.error)}` : f.updatedAt ? `${f.ranges.toLocaleString()} ranges · ${esc(fmtAgo(f.updatedAt))}` : 'not downloaded yet'}</div></div>`).join('');
    const geo = state.geo;
    const geoStatus = !geo.enabled ? 'Off' : geo.state === 'ready' ? `Ready · updated ${fmtAgo(geo.updatedAt)}` : geo.state === 'downloading' ? 'Downloading (about 30 MB)…' : geo.state === 'loading' ? 'Loading…' : geo.error ? `Problem: ${geo.error}` : 'Not downloaded yet';
    const cc = s.alertCountries.join(', ');
    $('#settingsForm').innerHTML = `
      <div class="settings">
        <section class="card">
          <h3>General</h3>
          ${state.app.desktop ? field('Start NetWatch when you log in', chk('autostart', s.autostart), 'It starts quietly in the tray.') : ''}
          ${state.app.desktop && win ? field('…with administrator rights', chk('autostartAdmin', s.autostartAdmin), 'Uses a Windows scheduled task, so there is no permission prompt at every login. Needs NetWatch installed for all users (in Program Files) and running as administrator when you turn it on.') : ''}
          ${field('Theme', `<select class="input" name="theme">${['system', 'light', 'dark'].map((t) => `<option value="${t}" ${s.theme === t ? 'selected' : ''}>${t[0].toUpperCase() + t.slice(1)}</option>`).join('')}</select>`)}
          ${field('Scan every', `${num('intervalSec', s.intervalSec, 2, 60)} <span class="dim">seconds</span>`)}
          ${field('Your data', `<button class="btn small" type="button" data-act="openDataFolder">Open data folder</button>`, `Settings, history and the alert log are kept in ${esc(state.app.dataDir)}`)}
        </section>

        <section class="card">
          <h3>Alerts</h3>
          ${field('Desktop notifications for', `<select class="input" name="desktopMinSeverity">${SEV_OPTIONS(s.desktopMinSeverity)}</select>`)}
          ${field('Busy program warning', `${num('floodThreshold', s.floodThreshold, 20, 5000)} <span class="dim">connections</span>`, 'Alert when one program holds more open connections than this (scans, bots).')}
          ${field('Upload spike warning', `${num('uploadSpikeMB', s.uploadSpikeMB, 10, 1000000)} <span class="dim">MB in 10 min</span>`, 'Alert when a program uploads more than this and far more than it usually does. Needs per-program measuring.')}
          ${field('Daily data limit', `${num('dailyCapGB', s.dailyCapGB, 0, 100000, 0.5)} <span class="dim">GB (0 = off)</span>`, 'Alerts at 80% and 100% of the limit.')}
          ${field('Quiet hours', `${chk('quiet.enabled', s.quiet.enabled, 'On')} ${text('quiet.from', s.quiet.from, '00:00', 'time').replace('class="input"', 'class="input narrow" style="width:110px"')} – ${text('quiet.to', s.quiet.to, '06:00', 'time').replace('class="input"', 'class="input narrow" style="width:110px"')}`, 'Alert if something uses the network while you are away or asleep.')}
          ${field('…alert above', `${num('quiet.thresholdMB', s.quiet.thresholdMB, 1, 1000000)} <span class="dim">MB per program</span>`)}
          ${field('Countries to watch', text('alertCountries', cc, 'e.g. RU, KP, IR'), `Two-letter codes. Alerts when anything connects to these countries.${s.alertCountries.length ? ` Now watching: ${esc(s.alertCountries.map(countryName).join(', '))}.` : ''}`)}
          ${field('Random-looking website names', chk('dns.flagRandomDomains', s.dns.flagRandomDomains, 'Alert'), 'Some malware generates names like xkqzvbtrmwplh.com to find its servers.')}
          ${field('New devices on your network', chk('lan.alertNewDevices', s.lan.alertNewDevices, 'Alert'))}
        </section>

        <section class="card">
          <h3>Phone alerts</h3>
          <p class="hint">Sends alerts to your phone. The alert text leaves your computer, so only turn this on if you're fine with that.</p>
          ${field('Send alerts to my phone', chk('push.enabled', s.push.enabled, 'On'))}
          ${field('Send', `<select class="input" name="push.minSeverity">${SEV_OPTIONS(s.push.minSeverity)}</select>`)}
          ${field('ntfy address', text('push.ntfyUrl', s.push.ntfyUrl, 'https://ntfy.sh/your-secret-topic'), 'Install the free ntfy app, subscribe to a hard-to-guess topic and paste its address here. <button class="link" type="button" data-act="openExternal" data-url="https://docs.ntfy.sh/">How ntfy works</button>')}
          ${field('Telegram bot token', `${text('push.telegramToken', '', s.push.telegramTokenSet && !clearToken ? 'Saved. Leave blank to keep it' : '123456:ABC…', 'password')}${s.push.telegramTokenSet && !clearToken ? ' <button class="btn small" type="button" data-act="clearToken">Remove</button>' : ''}`, 'Optional. Create a bot with @BotFather. The token is stored encrypted when your system supports it. <button class="link" type="button" data-act="openExternal" data-url="https://core.telegram.org/bots#how-do-i-create-a-bot">Telegram bots</button>')}
          ${field('Telegram chat ID', text('push.telegramChatId', s.push.telegramChatId, 'e.g. 123456789'))}
          ${field('', '<button class="btn" type="button" data-act="testPush">Save and send a test alert</button>')}
        </section>

        <section class="card">
          <h3>Threat lists</h3>
          ${field('Check connections against known-bad addresses', chk('intel.enabled', s.intel.enabled, 'On'), 'Free public lists, downloaded once a day.')}
          ${feeds}
          <div style="margin-top:10px"><button class="btn small" type="button" data-act="updateFeeds">Update lists now</button></div>
        </section>

        <section class="card">
          <h3>Countries and website names</h3>
          ${field('Show the country of each connection', chk('geo.enabled', s.geo.enabled, 'On'), `${esc(geoStatus)}. Uses the free <button class="link" type="button" data-act="openExternal" data-url="https://db-ip.com">DB-IP</button> country database, stored on this computer.`)}
          ${field('Show website names looked up by programs', chk('dns.enabled', s.dns.enabled, 'On'), caps.dnsSupported ? (caps.dns ? 'Working.' : win ? 'Needs NetWatch to run as administrator on this version of Windows.' : 'Turned off.') : 'Not available on this system yet. Reverse lookups are used instead.')}
        </section>

        <section class="card">
          <h3>Devices on your network</h3>
          ${field('Keep a list of devices on your network', chk('lan.enabled', s.lan.enabled, 'On'), 'Reads your computer\'s ARP table once a minute. Nothing is scanned or sent.')}
        </section>
      </div>
      <div class="savebar"><span class="dim" id="dirtyNote"></span><button class="btn primary" type="submit" id="saveBtn" disabled>Save settings</button></div>`;
    $('#saveBtn').disabled = !settingsDirty;
  }

  function collectSettings() {
    const s = JSON.parse(JSON.stringify(state.settings));
    const setPath = (obj, pathStr, val) => {
      const parts = pathStr.split('.');
      let o = obj;
      for (let i = 0; i < parts.length - 1; i++) { o[parts[i]] = o[parts[i]] || {}; o = o[parts[i]]; }
      o[parts[parts.length - 1]] = val;
    };
    for (const el of $('#settingsForm').elements) {
      if (!el.name) continue;
      if (el.type === 'checkbox') setPath(s, el.name, el.checked);
      else if (el.type === 'number') setPath(s, el.name, +el.value);
      else if (el.name === 'alertCountries') s.alertCountries = el.value.split(/[\s,;]+/).map((c) => c.trim().toUpperCase()).filter(Boolean);
      else setPath(s, el.name, el.value);
    }
    if (clearToken) s.push.clearTelegramToken = true;
    return s;
  }

  async function saveSettings(okMsg = 'Settings saved') {
    const res = await call('settings', { settings: collectSettings() }, okMsg);
    if (res) { settingsDirty = false; clearToken = false; renderSettings(); }
    return !!res;
  }
  $('#settingsForm').addEventListener('input', () => { settingsDirty = true; $('#saveBtn').disabled = false; $('#dirtyNote').textContent = 'You have unsaved changes.'; });
  $('#settingsForm').addEventListener('submit', (e) => { e.preventDefault(); saveSettings(); });

  // ---------- one handler for every action button ----------
  document.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-act]');
    if (!b || b.disabled) return;
    const d = b.dataset;
    switch (d.act) {
      case 'close': closeDrawer(); break;
      case 'snooze': call('snooze', { minutes: state && state.app.snoozedUntil > Date.now() ? 0 : 60 }); break;
      case 'relaunchAdmin': {
        const ok = await call('relaunchAdmin');
        if (ok === false) toast('NetWatch keeps running without admin rights.', true);
        break;
      }
      case 'trust': call('trust', { key: d.key, trusted: true }, 'Program marked as trusted'); break;
      case 'untrust': call('trust', { key: d.key, trusted: false }, 'Program is no longer trusted'); break;
      case 'block':
        if (confirm(`Block ${d.path} from using the network?\n\nNetWatch adds a firewall rule. You can unblock it later under "Your rules".`)) {
          call('firewall', { path: d.path, block: true }, 'Program blocked in the firewall');
        }
        break;
      case 'unblock': call('firewall', { path: d.path, block: false }, 'Program unblocked'); break;
      case 'list': call('blocklist', { ip: d.ip, add: true }, `${d.ip} added to the blocklist`); break;
      case 'unlist': call('blocklist', { ip: d.ip, add: false }, `${d.ip} removed from the blocklist`); break;
      case 'export': {
        const file = await call('export', { kind: d.kind });
        if (file && typeof file === 'string') toast(`Saved to ${file}`);
        break;
      }
      case 'openExternal': call('openExternal', { url: d.url }); break;
      case 'openDataFolder': call('openDataFolder'); break;
      case 'updateFeeds': toast('Updating threat lists and the country database…'); await call('updateFeeds', {}, 'Lists updated'); if (!settingsDirty) renderSettings(); break;
      case 'testPush': if (await saveSettings('Settings saved')) await call('testPush', {}, 'Test alert sent. Check your phone.'); break;
      case 'clearToken': clearToken = true; settingsDirty = true; renderSettings(); $('#saveBtn').disabled = false; $('#dirtyNote').textContent = 'The Telegram token will be removed when you save.'; break;
      case 'renameDevice': editingDevice = d.mac; renderDevices(); { const i = $('#devRows input[name="label"]'); if (i) { i.focus(); i.select(); } } break;
      case 'cancelRename': editingDevice = null; renderDevices(); break;
      case 'forgetDevice':
        if (confirm('Forget this device? If it shows up again it will be reported as new.')) call('forgetDevice', { mac: d.mac }, 'Device forgotten');
        break;
    }
  });

  let resizeTimer;
  addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (tab === 'overview' && snap()) renderCharts(); if (tab === 'reports') renderReport(); }, 120); });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { render(); if (tab === 'reports') renderReport(); });

  // ---------- start ----------
  bridge.onState((s) => { state = s; lastOk = Date.now(); failed = false; render(); });
  bridge.onOpenProgram((name) => { showTab('overview'); openDrawer(name); });
  (async () => {
    const res = await bridge.call('getState');
    if (res && res.ok) { state = res.result; lastOk = Date.now(); } else { failed = true; toast(res && res.error ? res.error : 'NetWatch is not running.', true); }
    const h = decodeURIComponent(location.hash.slice(1));
    if (h.startsWith('program=')) { showTab('overview', false); openDrawer(h.slice(8)); } else showTab(h || 'overview', false);
  })();
})();
