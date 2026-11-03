'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../src/main/platform/parsers');
const U = require('../src/main/util');

test('Linux /proc/net/tcp (IPv4 + IPv6)', () => {
  const v4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18235 1 0000000000000000 100 0 0 10 0
   1: 0501A8C0:A8CA 22D8B85D:01BB 01 00000000:00000000 02:000A7D9C 00000000  1000        0 45121 2 0000000000000000 20 4 30 10 -1
`;
  const rows = P.parseProcNetTcp(v4);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], { localIp: '127.0.0.1', localPort: 631, remoteIp: '0.0.0.0', remotePort: 0, state: 'LISTEN', inode: '18235' });
  assert.deepEqual(rows[1], { localIp: '192.168.1.5', localPort: 43210, remoteIp: '93.184.216.34', remotePort: 443, state: 'ESTABLISHED', inode: '45121' });

  const v6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000501A8C0:C350 0000000000000000FFFF000022D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0000000000000000 100 0 0 10 0
   2: B80D0120000000000000000001000000:C351 B80D0120000000000000000002000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 3333 1 0000000000000000 100 0 0 10 0
`;
  const r6 = P.parseProcNetTcp(v6);
  assert.equal(r6[0].localIp, '::1');
  assert.equal(r6[0].localPort, 22);
  assert.equal(r6[1].remoteIp, '93.184.216.34', 'IPv4-mapped addresses become plain IPv4');
  assert.equal(r6[2].localIp, '2001:db8::1');
  assert.equal(r6[2].remoteIp, '2001:db8::2');
});

test('Linux /proc/net/dev skips loopback and container bridges', () => {
  const text = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  500000    100    0    0    0     0          0         0   500000     100    0    0    0     0       0          0
  eth0: 1000000   2000    0    0    0     0          0         0   250000    1500    0    0    0     0       0          0
docker0:   9999     10    0    0    0     0          0         0     9999      10    0    0    0     0       0          0
 wlan0:    2000     20    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
`;
  assert.deepEqual(P.parseProcNetDev(text), { rx: 1002000, tx: 251000 });
});

test('Linux stat parent pid with spaces in the name', () => {
  assert.equal(P.parseProcStatPpid('1234 (Web Content (x)) S 987 1234 1234 0 -1'), 987);
});

test('ss -tinH byte counters', () => {
  const text = `0      0      192.168.1.5:43210      93.184.216.34:443
\t cubic wscale:7,7 rto:204 rtt:3.2/1.2 ato:40 mss:1448 cwnd:10 bytes_sent:1200 bytes_acked:1201 bytes_received:56789 segs_out:20
0      0      [2001:db8::1]:50001      [2001:db8::2]:443
\t cubic rto:204 bytes_acked:300 bytes_received:400
0      0      [::ffff:192.168.1.5]:50002      [::ffff:1.1.1.1]:853
\t cubic bytes_sent:7 bytes_received:8
`;
  const m = P.parseSsTcpInfo(text);
  assert.deepEqual(m.get('192.168.1.5|43210|93.184.216.34|443'), { rx: 56789, tx: 1200 });
  assert.deepEqual(m.get('2001:db8::1|50001|2001:db8::2|443'), { rx: 400, tx: 300 }, 'falls back to bytes_acked');
  assert.deepEqual(m.get('192.168.1.5|50002|1.1.1.1|853'), { rx: 8, tx: 7 });
});

test('ss -tuanpH socket owners', () => {
  const text = `tcp   ESTAB  0      0      192.168.1.5:43210     93.184.216.34:443   users:(("firefox",pid=2345,fd=87))
tcp   LISTEN 0      4096   127.0.0.53%lo:53      0.0.0.0:*           users:(("systemd-resolve",pid=611,fd=14))
tcp   LISTEN 0      128    [::]:22               [::]:*
udp   UNCONN 0      0      0.0.0.0:5353          0.0.0.0:*           users:(("avahi-daemon",pid=612,fd=12),("avahi-daemon",pid=612,fd=13))
tcp   ESTAB  0      0      [::ffff:192.168.1.5]:50002 [::ffff:1.1.1.1]:853 users:(("resolved",pid=700,fd=3))
`;
  const m = P.parseSsProcesses(text);
  assert.equal(m.get('tcp|192.168.1.5|43210|93.184.216.34|443'), 2345);
  assert.equal(m.get('tcp|L|53'), 611);
  assert.equal(m.has('tcp|L|22'), false, 'sockets without a visible owner are left out');
  assert.equal(m.get('udp|L|5353'), 612);
  assert.equal(m.get('tcp|192.168.1.5|50002|1.1.1.1|853'), 700, 'IPv4-mapped addresses match /proc parsing');
});

test('threat feed parsing skips private space and merges ranges', () => {
  const { parseFeed, inRanges } = require('../src/main/intel');
  const ranges = parseFeed('# comment\n10.0.0.0/8\n1.2.3.0/24\n1.2.3.128/25\n5.6.7.8\n{"cidr":"9.9.9.0/24","sblid":"x"}\n{"type":"metadata"}\n');
  assert.equal(ranges.length, 3);
  assert.equal(inRanges(ranges, U.ipv4ToInt('1.2.3.200')), true);
  assert.equal(inRanges(ranges, U.ipv4ToInt('5.6.7.8')), true);
  assert.equal(inRanges(ranges, U.ipv4ToInt('9.9.9.1')), true);
  assert.equal(inRanges(ranges, U.ipv4ToInt('10.1.1.1')), false, 'private ranges are dropped');
});

test('macOS lsof -F output', () => {
  const text = ['p501', 'cSafari', 'f23', 'PTCP', 'n192.168.1.5:50123->17.253.144.10:443', 'TST=ESTABLISHED', 'TQR=0',
    'f24', 'PUDP', 'n*:5353', 'p88', 'cmDNSResponder', 'f5', 'PTCP', 'n*:7000', 'TST=LISTEN',
    'f6', 'PTCP', 'n[2001:db8::5]:50200->[2001:db8::9]:443', 'TST=ESTABLISHED', ''].join('\n');
  const rows = P.parseLsof(text);
  assert.equal(rows.length, 4);
  assert.deepEqual(rows[0], { pid: 501, command: 'Safari', proto: 'TCP', localIp: '192.168.1.5', localPort: 50123, remoteIp: '17.253.144.10', remotePort: 443, state: 'ESTABLISHED' });
  assert.equal(rows[1].proto, 'UDP');
  assert.equal(rows[1].localIp, '*');
  assert.equal(rows[1].localPort, 5353);
  assert.equal(rows[2].state, 'LISTEN');
  assert.equal(rows[2].command, 'mDNSResponder');
  assert.equal(rows[3].remoteIp, '2001:db8::9');
});

test('macOS nettop, netstat -ibn and ps', () => {
  const nettop = ',bytes_in,bytes_out,\nSafari.501,1000,200,\ncom.apple.WebKit.Networking.640,5000,700,\nkernel_task.0,9,9,\n';
  const n = P.parseNettop(nettop);
  assert.deepEqual(n.get(501), { rx: 1000, tx: 200 });
  assert.deepEqual(n.get(640), { rx: 5000, tx: 700 });
  assert.equal(n.has(0), false);

  const netstat = `Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                         10000     0    9999999    10000     0    9999999     0
en0        1500  <Link#6>    a4:83:e7:12:34:56   200000     0  300000000   150000     0   40000000     0
en0        1500  192.168.1     192.168.1.5        200000     -  300000000   150000     -   40000000     -
en5        1500  <Link#9>    ac:de:48:00:11:22      100     0      50000       90     0      20000     0
utun3      1380  <Link#20>                          500     0     700000      400     0      80000     0
`;
  assert.deepEqual(P.parseNetstatIbn(netstat), { rx: 300050000, tx: 40020000 });

  const ps = '    1     0 /sbin/launchd\n  501     1 /Applications/Safari.app/Contents/MacOS/Safari\n';
  assert.deepEqual(P.parsePs(ps).get(501), { ppid: 1, path: '/Applications/Safari.app/Contents/MacOS/Safari' });
});

test('ARP tables from all three systems', () => {
  const win = `
Interface: 192.168.0.76 --- 0x7
  Internet Address      Physical Address      Type
  192.168.0.1           c8-d1-2a-3c-f1-1c     dynamic
  192.168.0.56          cc-af-e3-e7-04-18     dynamic
  192.168.0.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
`;
  assert.deepEqual(P.parseArp(win), [{ ip: '192.168.0.1', mac: 'c8:d1:2a:3c:f1:1c' }, { ip: '192.168.0.56', mac: 'cc:af:e3:e7:04:18' }]);

  const mac = `? (192.168.1.1) at a4:83:e7:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.20) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.30) at 6e:5:aa:bb:cc:dd on en0 ifscope [ethernet]`;
  const m = P.parseArp(mac);
  assert.deepEqual(m, [{ ip: '192.168.1.1', mac: 'a4:83:e7:01:02:03' }, { ip: '192.168.1.30', mac: '6e:05:aa:bb:cc:dd' }]);
  assert.equal(P.isRandomMac('6e:05:aa:bb:cc:dd'), true);
  assert.equal(P.isRandomMac('a4:83:e7:01:02:03'), false);

  const linux = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a4:83:e7:01:02:03     *        wlan0
192.168.1.40     0x1         0x0         00:00:00:00:00:00     *        wlan0`;
  assert.deepEqual(P.parseArp(linux), [{ ip: '192.168.1.1', mac: 'a4:83:e7:01:02:03' }]);
});

test('IP helpers', () => {
  assert.equal(U.isPublicIp('8.8.8.8'), true);
  for (const ip of ['10.1.2.3', '192.168.1.1', '172.20.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '224.0.0.1', '::1', 'fe80::1', 'fd00::1']) {
    assert.equal(U.isPublicIp(ip), false, ip);
  }
  assert.equal(U.isPublicIp('2606:4700::6810:84e5'), true);
  assert.equal(U.isPublicIp('::ffff:8.8.8.8'), true);
  assert.deepEqual(U.parseIpv4Cidr('1.2.3.0/24'), [U.ipv4ToInt('1.2.3.0'), U.ipv4ToInt('1.2.3.255')]);
  assert.deepEqual(U.parseIpv4Cidr('1.2.3.77/24'), [U.ipv4ToInt('1.2.3.0'), U.ipv4ToInt('1.2.3.255')], 'host bits are masked');
  assert.equal(U.parseIpv4Cidr('2001:db8::/32'), null);
  assert.equal(U.ipv6High64('2001:db8::1'), 0x20010db800000000n);
  assert.equal(U.formatIpv6([0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0x84, 0xe5]), '2606:4700::6810:84e5');
  assert.equal(U.formatIpv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 4, 4]), '8.8.4.4');
});

test('random-looking domain heuristic', () => {
  assert.equal(U.looksRandomDomain('xkqzvbtrmwplhgfd.com'), true);
  assert.equal(U.looksRandomDomain('a8f3k2l9q7x1z5m4.net'), true);
  for (const d of ['www.google.com', 'd3k2l9q7x1z5m4abc.cloudfront.net', 'login.microsoftonline.com', 'encrypted-tbn0.gstatic.com', 'anthropic.com', 'mail.example.co.uk']) {
    assert.equal(U.looksRandomDomain(d), false, d);
  }
});

test('daily windows that wrap midnight', () => {
  const at = (h, m) => new Date(2026, 0, 1, h, m);
  assert.equal(U.inDailyWindow(at(23, 30), '23:00', '06:00'), true);
  assert.equal(U.inDailyWindow(at(3, 0), '23:00', '06:00'), true);
  assert.equal(U.inDailyWindow(at(12, 0), '23:00', '06:00'), false);
  assert.equal(U.inDailyWindow(at(1, 0), '00:00', '06:00'), true);
  assert.equal(U.inDailyWindow(at(6, 0), '00:00', '06:00'), false);
});
