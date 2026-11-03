'use strict';
// electron-builder afterPack hook: switch off Electron features an attacker could use to run code inside
// NetWatch through environment variables. This matters on Windows, where NetWatch can start with admin
// rights at login: environment variables are per-user, so any program running as the user could set
// ELECTRON_RUN_AS_NODE or NODE_OPTIONS and have its code run with admin rights.
// macOS/Linux builds keep RunAsNode, because browser mode as root is started through it there.
const path = require('path');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

exports.default = async function afterPack(context) {
  if (context.electronPlatformName !== 'win32') return;
  const exe = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.exe`);
  await flipFuses(exe, {
    version: FuseVersion.V1,
    [FuseV1Options.RunAsNode]: false,                            // ignore ELECTRON_RUN_AS_NODE
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false, // ignore NODE_OPTIONS
    [FuseV1Options.EnableNodeCliInspectArguments]: false,        // ignore --inspect debugging flags
    [FuseV1Options.OnlyLoadAppFromAsar]: true,                   // only run the packaged app code
  });
  console.log(`  • NetWatch: hardened Electron fuses in ${path.basename(exe)}`);
};
