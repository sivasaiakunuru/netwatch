'use strict';
// Windows collector. Connections, processes and byte counters come straight from Win32 APIs via koffi,
// so a scan costs a few milliseconds. Rare jobs (signatures, DNS cache, firewall) go through PowerShell.
const koffi = require('koffi');
const path = require('path');
const { spawn, execFile } = require('child_process');
const { formatIpv6 } = require('../util');
const { parseArp } = require('./parsers');

const iphlp = koffi.load('iphlpapi.dll');
const k32 = koffi.load('kernel32.dll');
const shell32 = koffi.load('shell32.dll');

const GetExtendedTcpTable = iphlp.func('uint32 __stdcall GetExtendedTcpTable(void *table, void *size, int order, uint32 af, int cls, uint32 reserved)');
const GetExtendedUdpTable = iphlp.func('uint32 __stdcall GetExtendedUdpTable(void *table, void *size, int order, uint32 af, int cls, uint32 reserved)');
const GetPerTcpConnectionEStats = iphlp.func('uint32 __stdcall GetPerTcpConnectionEStats(void *row, int type, void *rw, uint32 rwVer, uint32 rwSize, void *ros, uint32 rosVer, uint32 rosSize, void *rod, uint32 rodVer, uint32 rodSize)');
const SetPerTcpConnectionEStats = iphlp.func('uint32 __stdcall SetPerTcpConnectionEStats(void *row, int type, void *rw, uint32 rwVer, uint32 rwSize, uint32 offset)');
const GetPerTcp6ConnectionEStats = iphlp.func('uint32 __stdcall GetPerTcp6ConnectionEStats(void *row, int type, void *rw, uint32 rwVer, uint32 rwSize, void *ros, uint32 rosVer, uint32 rosSize, void *rod, uint32 rodVer, uint32 rodSize)');
const SetPerTcp6ConnectionEStats = iphlp.func('uint32 __stdcall SetPerTcp6ConnectionEStats(void *row, int type, void *rw, uint32 rwVer, uint32 rwSize, uint32 offset)');
const GetIfTable2 = iphlp.func('uint32 __stdcall GetIfTable2(_Out_ void **table)');
const FreeMibTable = iphlp.func('void __stdcall FreeMibTable(void *table)');

const CreateToolhelp32Snapshot = k32.func('void * __stdcall CreateToolhelp32Snapshot(uint32 flags, uint32 pid)');
const Process32FirstW = k32.func('int __stdcall Process32FirstW(void *snap, void *entry)');
const Process32NextW = k32.func('int __stdcall Process32NextW(void *snap, void *entry)');
const OpenProcess = k32.func('void * __stdcall OpenProcess(uint32 access, int inherit, uint32 pid)');
const QueryFullProcessImageNameW = k32.func('int __stdcall QueryFullProcessImageNameW(void *h, uint32 flags, void *buf, void *size)');
const CloseHandle = k32.func('int __stdcall CloseHandle(void *h)');
const IsUserAnAdmin = shell32.func('int __stdcall IsUserAnAdmin()');

const AF_INET = 2, AF_INET6 = 23;
const TCP_TABLE_OWNER_PID_ALL = 5, UDP_TABLE_OWNER_PID = 1;
const TCP_STATES = { 2: 'LISTEN', 5: 'ESTABLISHED' };
const ESTATS_DATA = 1;
const ERROR_ACCESS_DENIED = 5;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const TH32CS_SNAPPROCESS = 0x2;
const PROCESSENTRY32W_SIZE = 568; // x64 / arm64 layout

// MIB_IF_ROW2, declared so koffi works out the field offsets (and we can sanity-check the size).
const MIB_IF_ROW2 = koffi.struct('NW_MIB_IF_ROW2', {
  InterfaceLuid: 'uint64', InterfaceIndex: 'uint32', InterfaceGuid: koffi.array('uint8', 16),
  Alias: koffi.array('uint16', 257), Description: koffi.array('uint16', 257),
  PhysicalAddressLength: 'uint32', PhysicalAddress: koffi.array('uint8', 32), PermanentPhysicalAddress: koffi.array('uint8', 32),
  Mtu: 'uint32', Type: 'uint32', TunnelType: 'int32', MediaType: 'int32', PhysicalMediumType: 'int32',
  AccessType: 'int32', DirectionType: 'int32', InterfaceAndOperStatusFlags: 'uint8',
  OperStatus: 'int32', AdminStatus: 'int32', MediaConnectState: 'int32', NetworkGuid: koffi.array('uint8', 16),
  ConnectionType: 'int32', TransmitLinkSpeed: 'uint64', ReceiveLinkSpeed: 'uint64',
  InOctets: 'uint64', InUcastPkts: 'uint64', InNUcastPkts: 'uint64', InDiscards: 'uint64', InErrors: 'uint64',
  InUnknownProtos: 'uint64', InUcastOctets: 'uint64', InMulticastOctets: 'uint64', InBroadcastOctets: 'uint64',
  OutOctets: 'uint64', OutUcastPkts: 'uint64', OutNUcastPkts: 'uint64', OutDiscards: 'uint64', OutErrors: 'uint64',
  OutUcastOctets: 'uint64', OutMulticastOctets: 'uint64', OutBroadcastOctets: 'uint64', OutQLen: 'uint64',
});
const IF_ROW = {
  size: koffi.sizeof(MIB_IF_ROW2),
  flags: koffi.offsetof(MIB_IF_ROW2, 'InterfaceAndOperStatusFlags'),
  oper: koffi.offsetof(MIB_IF_ROW2, 'OperStatus'),
  type: koffi.offsetof(MIB_IF_ROW2, 'Type'),
  inOctets: koffi.offsetof(MIB_IF_ROW2, 'InOctets'),
  outOctets: koffi.offsetof(MIB_IF_ROW2, 'OutOctets'),
};

// ---------- tables ----------

function readTable(fn, af, cls) {
  const size = Buffer.alloc(4);
  for (let attempt = 0; attempt < 4; attempt++) {
    fn(null, size, 0, af, cls, 0);
    const n = size.readUInt32LE(0) + 8192; // room for sockets opened between the two calls
    size.writeUInt32LE(n, 0);
    const buf = Buffer.alloc(n);
    if (fn(buf, size, 0, af, cls, 0) === 0) return buf;
  }
  return null;
}

const ipv4At = (b, o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
const ipv6At = (b, o) => formatIpv6(b.subarray(o, o + 16));

function readTcp() {
  const rows = [];
  const t4 = readTable(GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL);
  if (t4) {
    const n = t4.readUInt32LE(0);
    for (let i = 0, o = 4; i < n; i++, o += 24) {
      const state = TCP_STATES[t4.readUInt32LE(o)];
      if (!state) continue;
      rows.push({
        v6: false, state, localIp: ipv4At(t4, o + 4), localPort: t4.readUInt16BE(o + 8),
        remoteIp: ipv4At(t4, o + 12), remotePort: t4.readUInt16BE(o + 16), pid: t4.readUInt32LE(o + 20),
        estatsRow: state === 'ESTABLISHED' ? Buffer.from(t4.subarray(o, o + 20)) : null, // MIB_TCPROW = first 20 bytes
      });
    }
  }
  const t6 = readTable(GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL);
  if (t6) {
    const n = t6.readUInt32LE(0);
    for (let i = 0, o = 4; i < n; i++, o += 56) {
      const stateNum = t6.readUInt32LE(o + 48);
      const state = TCP_STATES[stateNum];
      if (!state) continue;
      let estatsRow = null;
      if (state === 'ESTABLISHED') {
        // MIB_TCP6ROW: State, LocalAddr[16], LocalScopeId, LocalPort, RemoteAddr[16], RemoteScopeId, RemotePort
        estatsRow = Buffer.alloc(52);
        estatsRow.writeUInt32LE(stateNum, 0);
        t6.copy(estatsRow, 4, o, o + 24);
        t6.copy(estatsRow, 28, o + 24, o + 48);
      }
      rows.push({
        v6: true, state, localIp: ipv6At(t6, o), localPort: t6.readUInt16BE(o + 20),
        remoteIp: ipv6At(t6, o + 24), remotePort: t6.readUInt16BE(o + 44), pid: t6.readUInt32LE(o + 52), estatsRow,
      });
    }
  }
  return rows;
}

function readUdp() {
  const rows = [];
  const t4 = readTable(GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID);
  if (t4) {
    const n = t4.readUInt32LE(0);
    for (let i = 0, o = 4; i < n; i++, o += 12) {
      rows.push({ localIp: ipv4At(t4, o), localPort: t4.readUInt16BE(o + 4), pid: t4.readUInt32LE(o + 8) });
    }
  }
  const t6 = readTable(GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID);
  if (t6) {
    const n = t6.readUInt32LE(0);
    for (let i = 0, o = 4; i < n; i++, o += 28) {
      rows.push({ localIp: ipv6At(t6, o), localPort: t6.readUInt16BE(o + 20), pid: t6.readUInt32LE(o + 24) });
    }
  }
  return rows;
}

// ---------- per-connection byte counters (needs admin) ----------

let accessDenied = false;
let enabledKeys = new Set();
const rwOn = Buffer.from([1]);          // TCP_ESTATS_DATA_RW_v0 { EnableCollection = TRUE }
const rod = Buffer.alloc(96);           // TCP_ESTATS_DATA_ROD_v0

function readConnBytes(rows) {
  const out = new Map();
  const seen = new Set();
  for (const r of rows) {
    if (!r.estatsRow) continue;
    const key = `${r.pid}|${r.remoteIp}|${r.remotePort}|${r.localPort}`;
    seen.add(key);
    const set = r.v6 ? SetPerTcp6ConnectionEStats : SetPerTcpConnectionEStats;
    const get = r.v6 ? GetPerTcp6ConnectionEStats : GetPerTcpConnectionEStats;
    if (!enabledKeys.has(key)) {
      if (accessDenied) continue;
      const rc = set(r.estatsRow, ESTATS_DATA, rwOn, 0, 1, 0);
      if (rc === ERROR_ACCESS_DENIED) { accessDenied = true; continue; }
      if (rc !== 0) continue;
      enabledKeys.add(key);
    }
    if (get(r.estatsRow, ESTATS_DATA, null, 0, 0, null, 0, 0, rod, 0, rod.length) !== 0) continue;
    out.set(key, { tx: Number(rod.readBigUInt64LE(0)), rx: Number(rod.readBigUInt64LE(16)) });
  }
  enabledKeys = new Set([...enabledKeys].filter((k) => seen.has(k)));
  return out;
}

// ---------- processes ----------

let procCache = new Map(); // pid -> { name, path, ppid }
const pathBuf = Buffer.alloc(32768 * 2);
const pathLen = Buffer.alloc(4);

function processPath(pid) {
  const h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
  if (!h) return null;
  try {
    pathLen.writeUInt32LE(32768, 0);
    if (!QueryFullProcessImageNameW(h, 0, pathBuf, pathLen)) return null;
    return pathBuf.toString('utf16le', 0, pathLen.readUInt32LE(0) * 2);
  } finally { CloseHandle(h); }
}

function readProcesses() {
  const out = new Map();
  const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (!snap || koffi.address(snap) === 0xffffffffffffffffn) return procCache;
  try {
    const e = Buffer.alloc(PROCESSENTRY32W_SIZE);
    e.writeUInt32LE(PROCESSENTRY32W_SIZE, 0);
    for (let ok = Process32FirstW(snap, e); ok; ok = Process32NextW(snap, e)) {
      const pid = e.readUInt32LE(8);
      const ppid = e.readUInt32LE(32);
      const raw = e.toString('utf16le', 44, 44 + 520);
      const exe = raw.slice(0, raw.indexOf('\0') >>> 0);
      const name = exe.replace(/\.exe$/i, '') || (pid === 4 ? 'System' : `PID ${pid}`);
      const cached = procCache.get(pid);
      const p = cached && cached.name === name ? cached.path : (pid > 4 ? processPath(pid) : null);
      out.set(pid, { name, path: p, ppid });
    }
  } finally { CloseHandle(snap); }
  procCache = out;
  return out;
}

// ---------- adapter totals ----------

// koffi registers every type it creates, so array types are reused per length instead of made per scan.
// The adapter count rarely changes, so this stays tiny.
const byteArrayTypes = new Map();
function byteArray(len) {
  let t = byteArrayTypes.get(len);
  if (!t) { t = koffi.array('uint8', len, 'Typed'); byteArrayTypes.set(len, t); }
  return t;
}

function readTotals() {
  const holder = [null];
  if (IF_ROW.size !== 1352 || GetIfTable2(holder) !== 0 || !holder[0]) return null;
  try {
    const n = koffi.decode(holder[0], 'uint32');
    // Copy the table out: Electron forbids JS buffers that point at native memory (koffi.view would crash it).
    const bytes = koffi.decode(holder[0], byteArray(8 + n * IF_ROW.size));
    const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let rx = 0, tx = 0;
    for (let i = 0; i < n; i++) {
      const o = 8 + i * IF_ROW.size;
      const flags = buf[o + IF_ROW.flags];
      const hardware = (flags & 1) === 1, filter = (flags & 2) === 2;
      if (!hardware || filter || buf.readInt32LE(o + IF_ROW.oper) !== 1 || buf.readUInt32LE(o + IF_ROW.type) === 24) continue;
      rx += Number(buf.readBigUInt64LE(o + IF_ROW.inOctets));
      tx += Number(buf.readBigUInt64LE(o + IF_ROW.outOctets));
    }
    return { rx, tx };
  } finally { FreeMibTable(holder[0]); }
}

// ---------- PowerShell helpers for the occasional jobs ----------

function runPowerShell(script, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    // -EncodedCommand (UTF-16LE base64) keeps multi-line scripts intact; "-Command -" would run stdin line by line.
    const full = `[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = 'Stop'\n${script}`;
    const encoded = Buffer.from(full, 'utf16le').toString('base64');
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], { windowsHide: true });
    let out = '', err = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('PowerShell timed out')); }, timeoutMs);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(out.trim());
      else reject(new Error((err.split('\n').find((l) => l.trim()) || `PowerShell exited with ${code}`).trim()));
    });
    child.stdin.end();
  });
}

// Strings reach PowerShell as base64 so paths with quotes or unicode can't break the script.
const psString = (s) => `([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(String(s), 'utf8').toString('base64')}')))`;

function parseJsonArray(text) {
  if (!text) return [];
  const v = JSON.parse(text);
  return Array.isArray(v) ? v : [v];
}

// The encoded PowerShell command must stay under Windows' 32,767-character command-line limit
// (it grows to about 3.6x the paths' JSON), so batches are capped by size as well as count.
const MAX_BATCH_JSON_BYTES = 6000;
function signatureBatches(paths) {
  const batches = [];
  let cur = [];
  for (const p of paths) {
    if (cur.length && (cur.length >= 40 || Buffer.byteLength(JSON.stringify([...cur, p])) > MAX_BATCH_JSON_BYTES)) { batches.push(cur); cur = []; }
    cur.push(p);
  }
  if (cur.length) batches.push(cur);
  return batches;
}

/** Signature status and signer per path. Paths whose check failed are left out so the caller can retry them. */
async function signatures(paths) {
  const out = new Map();
  for (const batch of signatureBatches(paths)) {
    const script = `$paths = ${psString(JSON.stringify(batch))} | ConvertFrom-Json
$out = foreach ($p in $paths) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $n = ''
    if ($s.SignerCertificate) { $n = $s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
    [pscustomobject]@{ path = $p; status = [string]$s.Status; signer = $n }
  } catch { [pscustomobject]@{ path = $p; status = 'Unknown'; signer = '' } }
}
ConvertTo-Json -Compress -InputObject @($out)`;
    try {
      for (const r of parseJsonArray(await runPowerShell(script, 60000))) out.set(r.path, { status: r.status || 'Unknown', signer: r.signer || '' });
    } catch { /* this batch is left out; the monitor retries it later */ }
  }
  return out;
}

async function dnsCache() {
  const text = await runPowerShell(`ConvertTo-Json -Compress -InputObject @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | Select-Object Entry, Data)`);
  const map = new Map();
  for (const r of parseJsonArray(text)) if (r && r.Data && r.Entry) map.set(String(r.Data).toLowerCase(), String(r.Entry).toLowerCase());
  return map;
}

const firewall = {
  supported: true,
  async list() {
    const text = await runPowerShell(`ConvertTo-Json -Compress -InputObject @(Get-NetFirewallRule -Group 'NetWatch' -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter | ForEach-Object { $_.Program } | Where-Object { $_ } | Sort-Object -Unique)`);
    return parseJsonArray(text).filter(Boolean);
  },
  async block(p) {
    await runPowerShell(`$p = ${psString(p)}; $n = [IO.Path]::GetFileName($p)
foreach ($d in 'Outbound', 'Inbound') { New-NetFirewallRule -DisplayName "NetWatch: block $n ($d)" -Group 'NetWatch' -Direction $d -Program $p -Action Block -Profile Any | Out-Null }`);
  },
  async unblock(p) {
    await runPowerShell(`$p = ${psString(p)}
Get-NetFirewallRule -Group 'NetWatch' -ErrorAction SilentlyContinue | Where-Object { ($_ | Get-NetFirewallApplicationFilter).Program -eq $p } | Remove-NetFirewallRule`);
  },
};

function arp() {
  return new Promise((resolve) => {
    execFile('arp', ['-a'], { windowsHide: true, timeout: 15000 }, (err, stdout) => resolve(err ? [] : parseArp(String(stdout))));
  });
}

async function commandLine(pid) {
  const n = parseInt(pid, 10);
  if (!(n > 0)) return '';
  return runPowerShell(`(Get-CimInstance Win32_Process -Filter "ProcessId=${n}").CommandLine`);
}

// ---------- public collector ----------

const env = process.env;
module.exports = {
  name: 'windows',
  isAdmin: () => IsUserAnAdmin() !== 0,
  riskyFolders: [env.TEMP, env.USERPROFILE && path.join(env.USERPROFILE, 'Downloads'), env.PUBLIC, 'C:\\$Recycle.Bin']
    .filter(Boolean).map((f) => f.replace(/\\+$/, '') + '\\'),
  systemPrefixes: [(env.SystemRoot || 'C:\\Windows').replace(/\\+$/, '') + '\\'],
  signatureSupported: true,
  dnsSupported: true,
  dnsNeedsAdmin: true, // reading the DNS client cache needs elevation on current Windows builds
  firewall,
  async sample() {
    const tcp = readTcp();
    const measuring = IsUserAnAdmin() !== 0 && !accessDenied;
    const connBytes = measuring ? readConnBytes(tcp) : null;
    return {
      tcp: tcp.map(({ estatsRow, v6, ...r }) => r),
      udp: readUdp(),
      procs: readProcesses(),
      connBytes: measuring && !accessDenied ? connBytes : null,
      procBytes: null,
      totals: readTotals(),
      measuring: measuring && !accessDenied,
    };
  },
  signatures,
  dnsCache,
  arp,
  commandLine,
};
