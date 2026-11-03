'use strict';
// OS integration: start at login (optionally elevated on Windows) and relaunching with admin rights.
const { app } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile, spawn } = require('child_process');
const { isAdminOnlyInstallDir } = require('./util');

const TASK_NAME = 'NetWatch';

function launchArgs(extra = []) {
  return app.isPackaged ? extra : [app.getAppPath(), ...extra];
}

function exePath() {
  return process.env.APPIMAGE || process.execPath;
}

const run = (cmd, args) => new Promise((resolve, reject) => {
  execFile(cmd, args, { windowsHide: true, timeout: 30000 }, (err, stdout, stderr) => {
    if (err) reject(new Error(String(stderr || stdout || err.message).trim().split('\n')[0]));
    else resolve(String(stdout));
  });
});

const quoteArg = (a) => (/[\s"]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a);

async function windowsTaskExists() {
  try { await run('schtasks', ['/Query', '/TN', TASK_NAME]); return true; } catch { return false; }
}

/**
 * Turns start-at-login on or off. On Windows, `admin` uses a Task Scheduler task that runs
 * with highest privileges at logon, so there is no permission prompt every time.
 */
async function setAutostart(enabled, admin, isAdmin) {
  const args = launchArgs(['--hidden']);
  if (process.platform === 'win32') {
    // Check before changing anything, so a refused request leaves the current setup as it was.
    if (enabled && admin) {
      if (!isAdmin) throw new Error('To start with admin rights at login, first restart NetWatch as administrator, then turn this on.');
      if (!app.isPackaged || !isAdminOnlyInstallDir(path.dirname(exePath()))) {
        throw new Error('Starting with admin rights at login needs NetWatch installed for all users (in Program Files). '
          + 'An "only for me" install can be changed by other programs on your account, which would then run with admin rights. '
          + 'Reinstall NetWatch and choose "Anyone who uses this computer", or start it normally at login instead.');
      }
    }
    app.setLoginItemSettings({ openAtLogin: false, path: exePath(), args });
    if (await windowsTaskExists()) {
      try { await run('schtasks', ['/Delete', '/TN', TASK_NAME, '/F']); } catch (e) {
        if (!enabled || !admin) throw new Error('Removing the admin start-up task needs NetWatch to run as administrator.');
      }
    }
    if (!enabled) return;
    if (admin) {
      const tr = [quoteArg(exePath()), ...args.map(quoteArg)].join(' ');
      await run('schtasks', ['/Create', '/TN', TASK_NAME, '/TR', tr, '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/F']);
    } else {
      app.setLoginItemSettings({ openAtLogin: true, path: exePath(), args });
    }
    return;
  }
  if (process.platform === 'darwin') {
    app.setLoginItemSettings({ openAtLogin: enabled, openAsHidden: true, args });
    return;
  }
  // Linux: freedesktop autostart entry
  const dir = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'autostart');
  const file = path.join(dir, 'netwatch.desktop');
  if (!enabled) { try { fs.unlinkSync(file); } catch { /* not there */ } return; }
  fs.mkdirSync(dir, { recursive: true });
  const exec = [exePath(), ...args].map((a) => `"${a.replace(/"/g, '\\"')}"`).join(' ');
  fs.writeFileSync(file, `[Desktop Entry]\nType=Application\nName=NetWatch\nComment=Network traffic monitor\nExec=${exec}\nX-GNOME-Autostart-enabled=true\n`);
}

/** Starts an elevated copy of the app (Windows UAC prompt). Resolves true if the user agreed. */
function relaunchAsAdmin() {
  if (process.platform !== 'win32') return Promise.resolve(false);
  const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
  const args = launchArgs([]);
  const cmd = `Start-Process -FilePath ${q(exePath())}${args.length ? ` -ArgumentList ${args.map(q).join(',')}` : ''} -Verb RunAs`;
  return new Promise((resolve) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd], { windowsHide: true });
    child.on('close', (code) => resolve(code === 0));
    child.on('error', () => resolve(false));
  });
}

module.exports = { setAutostart, relaunchAsAdmin };
