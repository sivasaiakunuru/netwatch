# NetWatch

A desktop app that watches your computer's internet traffic and alerts you when something looks wrong.
Runs on Windows, macOS and Linux.

## What it does

**Watches**
- Every internet connection: which program, which website, which country, how fast, and since when
- Download/upload speed, connections over time (5 minutes to 30 days of history, kept across restarts)
- Data used per day and per program, with CSV export
- Listening ports, UDP sockets, and devices on your local network

**Alerts you** (tray icon, desktop notification, optionally your phone) when:

| Level | When |
|---|---|
| High | a connection goes to an address on a threat list (Spamhaus, FireHOL, Emerging Threats, abuse.ch) or your own blocklist |
| High | a connection uses a port typical of malware or backdoors |
| High | a program running from Temp or Downloads goes online |
| High | your daily data limit is reached |
| Medium | an unsigned or tampered program goes online |
| Medium | a program starts accepting incoming connections |
| Medium | a program opens an unusual number of connections |
| Medium | a program uploads far more than it normally does |
| Medium | something uses the network during your quiet hours |
| Medium | a connection goes to a country on your watch list |
| Low | a program goes online for the first time, a new device joins your network, or a program contacts a random-looking domain |

**Lets you act**: trust a program, block it in the firewall (Windows), blocklist an address, look a program up on VirusTotal
(by fingerprint only; nothing is uploaded), pause alerts for an hour.

## Install

Run `NetWatch Setup 1.0.0.exe` (Windows). macOS and Linux installers are built by the GitHub workflow (see below).

The installers aren't code-signed, so Windows SmartScreen will say "Windows protected your PC". Click
**More info → Run anyway**. On macOS, right-click the app and choose **Open** the first time.

## Admin rights

NetWatch works without them, but some features need them:

| Feature | Windows | macOS | Linux |
|---|---|---|---|
| Connections, alerts, countries, threat lists, devices | ✓ | ✓ (own programs; root for all) | ✓ (own programs; root for all) |
| Speed and data use per program | admin | ✓ | ✓ |
| Website names from the DNS cache | admin | – | – |
| Block a program in the firewall | admin | – | – |

On Windows, use **Restart as administrator** in the app or tray. In Settings you can make it start at login with admin
rights (a scheduled task, so there's no prompt every time).

On macOS and Linux the desktop app can't run as root (Electron refuses to), so connections of system services and other
users appear as **Unknown process**. To see every program, run [browser mode](#browser-mode) with `sudo` instead.

## Phone alerts

Settings → Phone alerts. Either:
- **ntfy** (free): install the ntfy app, subscribe to a long random topic name and paste `https://ntfy.sh/<topic>`.
- **Telegram**: create a bot with @BotFather, paste its token and your chat ID.

Phone alerts send the alert text off your computer, so they're off by default.

## Browser mode

`npm run web` runs NetWatch without the desktop window and serves the same interface at http://127.0.0.1:8790
(local only). Useful on servers or headless machines, and the way to monitor every process as root on macOS/Linux:

```bash
# from the source folder
sudo node src/main/web.js --port=8790

# from an installed Linux package (no Node.js needed: the app's own runtime runs it)
sudo ELECTRON_RUN_AS_NODE=1 /opt/NetWatch/netwatch /opt/NetWatch/resources/app.asar/src/main/web.js

# from the installed macOS app
sudo ELECTRON_RUN_AS_NODE=1 /Applications/NetWatch.app/Contents/MacOS/NetWatch /Applications/NetWatch.app/Contents/Resources/app.asar/src/main/web.js
```

## Developing

```bash
npm install
npm start          # run the desktop app
npm test           # parser and helper tests
npm run dist:win   # build the Windows installer into dist/
```

Building on Windows from a very long folder path fails (the NSIS installer tool can't open paths over 260
characters); build from a short path such as `C:\src\netwatch`.

macOS and Linux installers must be built on those systems. Push the project to GitHub and run the
**Build NetWatch** workflow (Actions tab): it builds `.exe`, `.dmg`, `.AppImage` and `.deb` and attaches them to the run.

## Where data lives

Settings, rules, history, data usage and the alert log (rotated at 5 MB) are in the app data folder
(Settings → Open data folder): `%APPDATA%\NetWatch` on Windows, `~/Library/Application Support/NetWatch` on macOS,
`~/.config/NetWatch` on Linux.

## Limits

- Per-program speed covers TCP. UDP traffic (video calls, games, QUIC) appears as "Other traffic".
- Browsers with their own secure DNS (Brave, Chrome, Firefox) don't use the system DNS cache, so their website names
  come from reverse lookups instead.
- Firewall blocking is Windows-only for now.
- NetWatch is a monitoring tool, not antivirus. Keep your antivirus on.

Country data: [IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0).
