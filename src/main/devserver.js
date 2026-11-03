'use strict';
// Serves the UI and the request handler over http://127.0.0.1:<port>: browser mode (web.js) and the
// desktop app's --serve-ui=PORT test flag. Any web page can make the browser send requests here, so
// nothing a request contains may throw outside a try/catch.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml' };

function start(port, handle, dir) {
  const token = crypto.randomBytes(16).toString('hex');
  const origins = [`http://127.0.0.1:${port}`, `http://localhost:${port}`];
  const server = http.createServer((req, res) => {
    try {
      route(req, res);
    } catch {
      if (!res.headersSent) res.writeHead(400);
      res.end();
    }
  });
  function route(req, res) {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'POST' && url.pathname === '/api/call') {
      const origin = req.headers.origin;
      if (req.headers['x-netwatch-token'] !== token || (origin && !origins.includes(origin))) { res.writeHead(403); res.end(); return; }
      let body = '';
      req.on('data', (d) => { body += d; if (body.length > 65536) req.destroy(); });
      req.on('end', async () => {
        let out;
        try {
          const { type, payload } = JSON.parse(body || '{}');
          out = { ok: true, result: await handle(String(type), payload || {}) };
        } catch (e) { out = { ok: false, error: e.message || String(e) }; }
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(out));
      });
      return;
    }
    if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
    let rel;
    try { rel = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1)); } catch { res.writeHead(400); res.end(); return; }
    const file = path.resolve(dir, rel);
    if (!file.startsWith(path.resolve(dir) + path.sep)) { res.writeHead(404); res.end(); return; }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404); res.end(); return; }
      if (rel === 'index.html') data = Buffer.from(String(data).replace('</head>', `<meta name="nw-dev-token" content="${token}"></head>`));
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      res.end(data);
    });
  }
  server.listen(port, '127.0.0.1');
  return server;
}

module.exports = { start };
