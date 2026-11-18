# Lantern mobile roadmap

## Done (base scaffold, 2026-11-18)

- Capacitor 8 app shell: `package.json`, `capacitor.config.ts`
  (appId `com.beardlab.lantern`, appName `Lantern`, webDir `www`,
  CapacitorHttp enabled). Versions verified on npm 2026-11-18:
  `@capacitor/core` 8.6.2, `@capacitor/cli` 8.6.2,
  `@capacitor/preferences` 8.0.1, `typescript` 7.0.2.
- `src/api.js`: `LanternApi` covering every server endpoint
  (status, scans, latest, scan by id, diff, report, scan, demo,
  trust), timeout, plain-English errors, CapacitorHttp with fetch
  fallback.
- `src/settings.js`: server address validation (http only, port
  required, private RFC1918 or Tailscale host only, localhost for
  testing), localStorage storage with a TODO for Capacitor
  Preferences, Test Connection via `GET /api/status`.
- `src/mobile.js`: bootstrap that rewrites relative `/api/...`
  calls to the configured server, builds the Settings screen
  (server address, Test Connection, Save), and rewrites the HTML
  report link to the server.
- `scripts/sync-web.sh`: copies the dashboard into `www/` and
  injects the mobile bootstrap. Idempotent.
- `docs/ADR-001-mobile-architecture.md`: the Capacitor decision,
  alternatives, Phase 1 vs Phase 2, platform limits.
- `mobile/README.md` and this roadmap.
- `mobile/.gitignore`: node_modules, www, android, ios, logs.
- Verified: `node --check` on the JS files, the sync script
  produces a working `www/`, the Python test suite still passes,
  and `git status` shows only new mobile files (plus the short
  mobile section in the repo README). No file under `lantern/` was
  changed. No em dashes in any new file.

## Not done yet

- No native platforms added. There is no `android/` or `ios/`
  directory yet. Android Studio, Xcode, and the Android SDK are
  not installed in this workspace.
- No device test. The app has not run on a phone.
- No app icon or splash screen.
- No store listing, no Apple Developer or Google Play setup.
- Server address storage is localStorage, not Capacitor Preferences.
- No push notifications, no background refresh. Both are Phase 2
  ideas at most.

## Next commands for Landon (when home)

Run these from `~/workspace/lantern/mobile/`:

```bash
cd ~/workspace/lantern/mobile
npm install
bash scripts/sync-web.sh
npx cap add android
npx cap add ios
npx cap sync
```

Then:

- Android: open `android/` in Android Studio (needs JDK 21),
  connect a phone or start an emulator, run the app.
- iOS: open `ios/` in Xcode on a Mac (needs Xcode 26 or newer),
  or use a cloud build such as Expo EAS or Codemagic. There is
  no Mac in this workspace, so iOS cannot be built here.
- Start the home server first, reachable over Tailscale:
  `python3 -m lantern web` on the home machine, then open the
  app, set the server address on the Settings screen (http,
  Tailscale hostname or private IP, port 8068), and tap Test
  Connection. It should report the Lantern version, the saved scan
  count, and the server subnet.
- Test these flows against the home server: view the latest scan,
  run the demo, run a real scan, mark a device trusted, open the
  HTML report, and check the diff banner after two scans.
- After any dashboard or mobile client change, re-run
  `bash scripts/sync-web.sh` and `npx cap sync`.

## Open decisions for Landon

- CapacitorHttp vs server CORS: keep CapacitorHttp enabled
  (current default, no server change), or add a narrow CORS
  allowance to the server for `capacitor://localhost` and
  `https://localhost`. Try CapacitorHttp on device first.
- Distribution: App Store and Play Store, or sideloading and
  TestFlight for home use only.
- App icon and splash screen: no assets exist yet.
- Storage: move the server address to Capacitor Preferences now,
  or leave localStorage until the first device test passes.
- Release hygiene: bump the Capacitor patch version before
  release if a newer 8.x is out, and re-check the Xcode and JDK
  requirements in the ADR at build time.

## Phase 2 (future work only, not started)

On-device scanning from the phone itself, with no home server.
Blocked on design, not just code:

- iOS cannot do ARP or raw ping from an app, and it does not
  expose the local MAC table. Discovery from the phone is limited
  to TCP connect scans of hosts found another way.
- Android Wi-Fi scanning needs location permission, and a phone on
  Wi-Fi sees a different view than a wired host.
- A phone scan needs its own history store, its own risk rules,
  and a merge strategy with the server history. None of that is
  designed yet.
- Do not start Phase 2 until Phase 1 works on a real device
  against the home server over Tailscale.
