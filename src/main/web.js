'use strict';
// Browser mode: runs NetWatch without the desktop app and serves the same interface at http://127.0.0.1:<port>.
// Handy on headless machines or servers.  Usage: node src/main/web.js [--port=8790] [--data-dir=PATH]
// On Linux/macOS run it with sudo to see every process (the desktop app itself can't run as root).
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createService } = require('./service');
const { dayKey } = require('./util');

const opt = (name, dflt) => {
  const a = process.argv.find((x) => x.startsWith(`--${name}=`));
  return a ? a.slice(name.length + 3) : dflt;
};

const port = +opt('port', 8790);
const dataDir = path.resolve(opt('data-dir', path.join(os.homedir(), '.netwatch')));
const version = require('../../package.json').version;

const svc = createService({ dataDir, version, appInfo: () => ({ canRelaunchAdmin: false, desktop: false }) });

svc.monitor.on('alert', (a) => {
  console.log(`${new Date(a.t).toLocaleString()}  [${a.severity}]  ${a.message}`);
});

async function handle(type, payload = {}) {
  switch (type) {
    case 'export': {
      const kind = payload.kind === 'alerts' ? 'alerts' : 'usage';
      const dir = fs.existsSync(path.join(os.homedir(), 'Downloads')) ? path.join(os.homedir(), 'Downloads') : dataDir;
      // Never overwrite an earlier export: add -2, -3, ... when the name is taken.
      const base = `netwatch-${kind}-${dayKey()}`;
      let file = path.join(dir, `${base}.csv`);
      for (let n = 2; fs.existsSync(file); n++) file = path.join(dir, `${base}-${n}.csv`);
      fs.writeFileSync(file, svc.csvText(kind), { flag: 'wx' });
      return file;
    }
    case 'openDataFolder': throw new Error(`Your data is in ${dataDir}`);
    case 'relaunchAdmin': throw new Error('In browser mode, restart NetWatch from an administrator terminal (or with sudo).');
    case 'openExternal': throw new Error('Links open in your browser directly in browser mode.');
    default: return svc.handle(type, payload);
  }
}

svc.start().then(() => {
  require('./devserver').start(port, handle, path.join(__dirname, '..', 'renderer'));
  console.log(`NetWatch is running in browser mode: http://127.0.0.1:${port}/`);
  console.log(`Data folder: ${dataDir}${svc.monitor.admin ? '  (administrator)' : ''}`);
});

const shutdown = () => { svc.stop(); process.exit(0); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
