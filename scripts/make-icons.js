'use strict';
// Draws the NetWatch shield icon and writes the PNGs the app and installer use. Run: node scripts/make-icons.js
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = CRC_TABLE[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };

function png(size, rgba) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

// Shape tests in a 0..1 square.
function inShield(x, y) {
  const dx = Math.abs(x - 0.5);
  const top = 0.1 + 0.05 * (dx / 0.36);
  if (y < top) return false;
  if (y <= 0.52) return dx <= 0.36;
  const t = (y - 0.52) / 0.42;
  return t <= 1 && dx <= 0.36 * Math.sqrt(Math.max(0, 1 - t * t * t));
}
function distToSegment(px, py, ax, ay, bx, by) {
  const vx = bx - ax, vy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * vx + (py - ay) * vy) / (vx * vx + vy * vy)));
  return Math.hypot(px - (ax + t * vx), py - (ay + t * vy));
}
const inCheck = (x, y) => Math.min(distToSegment(x, y, 0.33, 0.5, 0.45, 0.62), distToSegment(x, y, 0.45, 0.62, 0.68, 0.37)) < 0.045;
const inDot = (x, y) => Math.hypot(x - 0.8, y - 0.2) < 0.19;
const inDotRing = (x, y) => Math.hypot(x - 0.8, y - 0.2) < 0.25;

function draw(size, { alert = false } = {}) {
  const ss = 4; // supersampling for smooth edges
  const out = Buffer.alloc(size * size * 4);
  const BLUE = [42, 120, 214], WHITE = [255, 255, 255], RED = [208, 59, 59];
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const x = (px + (sx + 0.5) / ss) / size, y = (py + (sy + 0.5) / ss) / size;
          let col = null;
          if (alert && inDot(x, y)) col = RED;
          else if (alert && inDotRing(x, y)) col = null; // transparent gap around the dot
          else if (inShield(x, y)) col = inCheck(x, y) ? WHITE : BLUE;
          if (col) { r += col[0]; g += col[1]; b += col[2]; a += 255; }
        }
      }
      const n = ss * ss, o = (py * size + px) * 4;
      if (a) { out[o] = r / (a / 255); out[o + 1] = g / (a / 255); out[o + 2] = b / (a / 255); }
      out[o + 3] = a / n;
    }
  }
  return png(size, out);
}

const root = path.join(__dirname, '..');
const write = (rel, buf) => { const f = path.join(root, rel); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, buf); console.log('wrote', rel); };
write('build/icon.png', draw(512));
write('src/assets/icon.png', draw(256));
write('src/assets/tray.png', draw(32));
write('src/assets/tray-alert.png', draw(32, { alert: true }));
