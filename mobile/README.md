# Lantern mobile (experimental base)

A Capacitor remote client for Lantern, the local-first home network
scanner. One codebase, iOS and Android.

Status: base scaffold only, November 2026. It has not been built or
tested on a phone yet. Landon finishes it when he is home. See
[ROADMAP.md](ROADMAP.md) for the exact next commands.

## How it works

Your phone is a remote client, not a scanner. In Phase 1 the phone
does no scanning at all.

1. A Lantern server runs on a machine at home (the same Python
   server as the desktop dashboard, `python3 -m lantern web`).
2. The phone app shows the same dashboard, synced from
   `lantern/web/` by `scripts/sync-web.sh` into `mobile/www/`.
3. The app talks to the server over your home network or over
   Tailscale. You enter the server address on the Settings screen
   at the top of the dashboard.
4. Scanning, history, diff, and trust all still run on the server.
   The phone only asks for them through the JSON API.

Why this shape: the dashboard UI already exists as plain HTML/CSS/JS,
Node is available, and the Python scanner can only see the LAN from
a machine on it. A phone on Wi-Fi sees a different, smaller view.
On-device scanning is Phase 2, future work only. See
[docs/ADR-001-mobile-architecture.md](docs/ADR-001-mobile-architecture.md).

## Safety rules

These come from the Lantern project and do not change on mobile:

- Private RFC1918 subnets only, max /16. Public IPs are refused.
- No brute force, no exploits, no default password checks, ever.
- Defensive only. Only scan networks you own or have explicit
  permission to scan.
- The dashboard has no login, by design, for local use. Only point
  the app at a private address, a Tailscale address or hostname, or
  localhost for testing. The Settings screen enforces this and
  refuses public IPs and hostnames.
- Never expose the Lantern server to the internet. Keep it on the
  home LAN or behind Tailscale.

## Layout

- `package.json`, `capacitor.config.ts`: Capacitor 8 app,
  appId `com.beardlab.lantern`, webDir `www`.
- `scripts/sync-web.sh`: copies the dashboard into `www/` and
  injects the mobile bootstrap. Idempotent, run it any time the
  dashboard or the mobile client changes.
- `src/api.js`: `LanternApi`, a client for every server endpoint
  (status, scans, latest, scan by id, diff, report, scan, demo,
  trust), with a timeout and plain-English errors. Uses
  CapacitorHttp when available, plain fetch otherwise.
- `src/settings.js`: server address validation and storage
  (localStorage for now, TODO: Capacitor Preferences), plus Test
  Connection against `GET /api/status`.
- `src/mobile.js`: the bootstrap injected into the dashboard. It
  rewrites relative `/api/...` calls to the configured server so
  `app.js` needs no changes, and it builds the Settings screen
  (server address field, Test Connection, Save).
- `docs/ADR-001-mobile-architecture.md`: the Capacitor decision,
  alternatives, Phase 1 vs Phase 2, platform limits.
- `ROADMAP.md`: what is done, the exact next commands, and what
  Phase 2 would need.
- `www/`: generated, never edited by hand, ignored by git.

## Run it in a desktop browser (testing, no phone needed)

This is how you verify the mobile client before the native shell
exists. The bundled dashboard must work here against a local
Lantern server.

```bash
cd mobile
bash scripts/sync-web.sh
python3 -m lantern web
python3 -m http.server 8100 --directory www
# open http://127.0.0.1:8100/
```

Leave the server address blank to use same-origin mode, or set it
to your local server address on the Settings screen. In a desktop
browser the address must be localhost (or the page origin), because
plain fetch is same-origin only. On the phone, CapacitorHttp handles
the cross-origin call to the home server.

## Build the native app (when home)

Full steps are in [ROADMAP.md](ROADMAP.md). The short version:

```bash
cd mobile
npm install
bash scripts/sync-web.sh
npx cap add android
npx cap add ios
npx cap sync
```

Then open `android/` in Android Studio, or `ios/` in Xcode (Mac
only, or use a cloud build like EAS or Codemagic). Run the app
against the home server over Tailscale, and test scan, trust, and
demo flows.

## What Landon still needs to decide

- Whether to keep CapacitorHttp (current default) or add a narrow
  CORS allowance to the server for the app origins. CapacitorHttp
  is the safer default, no server change needed.
- Whether to distribute through the App Store and Play Store, or
  keep it to sideloading and TestFlight for home use.
- App icon and splash screen. There are no assets yet.
- Whether to move server address storage to Capacitor Preferences
  now, or leave localStorage until the first device test.
