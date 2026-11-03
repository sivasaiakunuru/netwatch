'use strict';
// Serves the UI and the request handler over http://127.0.0.1:<port>: browser mode (web.js) and the
// desktop app's --serve-ui=PORT test flag. Any web page can make the browser send requests here, and
// any user or program on this computer can connect, so:
//   - every API call needs the per-run access key, which is never served by the server itself; the
//     launcher hands it to its own user in a link (#token=...) and an owner-only file
//   - requests must be addressed to 127.0.0.1/localhost (blocks DNS-rebinding pages) and come from
//     the page's own origin
//   - nothing a request contains may throw outside a try/catch.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml' };

/** Starts the server. Returns { server, token }; build the link once 'listening' fires (port 0 picks a free port). */
function start(port, handle, dir) {
  const token = crypto.randomBytes(24).toString('hex');
  const tokenBuf = Buffer.from(token);
  const server = http.createServer((req, res) => {
    try {
      route(req, res);
    } catch {
      if (!res.headersSent) res.writeHead(400);
      res.end();
    }
  });

  const listeningPort = () => (server.address() || {}).port;
  const allowedHost = (req) => [`127.0.0.1:${listeningPort()}`, `localhost:${listeningPort()}`].includes(String(req.headers.host || '').toLowerCase());
  const allowedOrigin = (req) => !req.headers.origin || [`http://127.0.0.1:${listeningPort()}`, `http://localhost:${listeningPort()}`].includes(req.headers.origin);
  const hasToken = (req) => {
    const given = Buffer.from(String(req.headers['x-netwatch-token'] || ''));
    return given.length === tokenBuf.length && crypto.timingSafeEqual(given, tokenBuf);
  };

  function route(req, res) {
    if (!allowedHost(req)) { res.writeHead(403); res.end(); return; }
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'POST' && url.pathname === '/api/call') {
      if (!hasToken(req) || !allowedOrigin(req)) { res.writeHead(403); res.end(); return; }
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
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      res.end(data);
    });
  }

  server.listen(port, '127.0.0.1');
  return { server, token };
}

module.exports = { start };
