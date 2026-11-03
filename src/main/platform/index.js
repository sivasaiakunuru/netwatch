'use strict';
// Picks the network collector for this operating system. Each one exposes the same interface:
//   sample() -> { tcp, udp, procs, connBytes, procBytes, totals, measuring }
//   isAdmin(), signatures(paths), dnsCache(), arp(), commandLine(pid), firewall { supported, list, block, unblock }
//   riskyFolders, systemPrefixes, signatureSupported, dnsSupported
switch (process.platform) {
  case 'win32': module.exports = require('./windows'); break;
  case 'darwin': module.exports = require('./macos'); break;
  case 'linux': module.exports = require('./linux'); break;
  default: throw new Error(`NetWatch does not support ${process.platform} yet.`);
}
