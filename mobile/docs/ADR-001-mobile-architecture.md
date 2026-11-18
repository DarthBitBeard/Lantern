# ADR-001: Lantern mobile is a Capacitor remote client

Date: 2026-11-18
Status: Accepted (Phase 1 base only, not yet built or tested on a device)

## Context

Lantern is a local-first home network scanner. The Python core
(stdlib only) does the scanning, and the dashboard is plain
HTML/CSS/JS served by the Python server on 127.0.0.1:8068, with a
JSON API. Landon wants to check scan results, run scans, and mark
devices trusted from his phone, on iOS and Android, from one
codebase. He will finish the work himself when he is home from his
cruise. This record fixes the approach so the base does not drift.

## Decision

Phase 1 is a Capacitor remote client, not a second scanner.

- The existing dashboard UI is reused as-is. `scripts/sync-web.sh`
  copies `lantern/web/` into `mobile/www/` and injects a small
  bootstrap (`src/mobile.js`) plus an API client (`src/api.js`) and
  settings (`src/settings.js`). One codebase covers iOS and Android.
- The phone does no scanning in Phase 1. It talks to a Lantern
  server running on a machine at home, over the home LAN or over
  Tailscale. Scanning stays where it can actually see the LAN.
- Capacitor 8 is the pinned line (verified on npm 2026-11-18:
  `@capacitor/core` 8.6.2, `@capacitor/cli` 8.6.2). The task brief
  suggested Capacitor 7, but 8 is the current stable line, and 8.6.2
  is above the fix for CVE-2026-103922 (fixed in 8.5.1), so pinning
  8.6.2 keeps the base clear of that flaw. Re-check the latest
  patch before release.
- CapacitorHttp is enabled in `capacitor.config.ts`, so API calls go
  through the native layer and bypass the browser CORS check. The
  Lantern server is same-origin only and sends no CORS headers, so
  plain fetch from the app WebView would be blocked. The fallback
  in `src/api.js` is plain fetch, which works in a desktop browser
  against a local server for testing.

## Alternatives considered

- Flutter: a second UI in Dart, duplicating a dashboard that already
  exists in HTML/CSS/JS, and Flutter is not installed here.
- React Native / Expo: also a second UI, plus a JavaScript toolchain
  the project does not otherwise use, for no gain over reusing the
  dashboard.
- Native Swift/Kotlin: two codebases, two UIs, the most work, for a
  read-mostly remote client.
- Plain WebView wrapper without Capacitor: no plugin bridge, no
  native HTTP, so the CORS problem has no clean answer and there is
  no path to native storage or notifications later.
- PWA (add to home screen, no store): the cheapest option, and a
  reasonable fallback if the native shell stalls, but it cannot use
  CapacitorHttp, so it needs a server-side CORS change, and it has
  no App Store presence.

## Phase 1 vs Phase 2

Phase 1 (this base): remote client only. View scans, run a scan,
run the demo, view the diff, mark devices trusted, view the report.
Everything the dashboard already does, from a phone.

Phase 2 (future work only, not started): scanning from the phone
itself, with no home server. This is hard, and that is why it is
Phase 2:

- iOS cannot do ARP or raw ping from an app, and it does not expose
  the local MAC table. A phone can only do TCP connect scans to
  hosts it discovers another way, and discovery itself is limited.
- Android can do more, but Wi-Fi scanning needs location
  permission, and a phone on Wi-Fi sees a different view of the
  network than a wired host (no ARP table, no visibility of wired
  devices that never answer the phone).
- A phone scan would also need its own history store, its own
  risk rules, and a merge strategy with the server history. None
  of that is designed yet. Do not start Phase 2 until Phase 1
  works on a real device against the home server.

## Platform limits

- iOS builds need macOS and Xcode (Capacitor 8 needs Xcode 26 or
  newer and an iOS deployment target of 15.0, per the Capacitor 8
  release notes; re-check at build time), or a cloud build service
  such as Expo EAS or Codemagic. There is no Mac in this workspace,
  so iOS cannot be built here.
- Android builds need Android Studio and JDK 21 (Capacitor 8
  requires JDK 21 to run Gradle), and an Android minSdk of 24.
  No Mac is needed to build Android.
- App Store and Play Store distribution need developer accounts
  (Apple Developer, Google Play). For home use, sideloading the
  Android APK or a TestFlight internal build is enough to start.
- The app origin is `capacitor://localhost` on iOS and
  `https://localhost` on Android. If CapacitorHttp is ever turned
  off, the server would need a CORS allowance for exactly those
  two origins, and nothing else.

## Security considerations

- The dashboard has no login, by design, for local use. The mobile
  client inherits that: it must only ever point at a private
  RFC1918 address, a Tailscale address or hostname, or localhost
  for testing. `src/settings.js` enforces this and refuses public
  IPs and hostnames.
- Never expose the Lantern server to the internet. Keep it on the
  home LAN or behind Tailscale, exactly as the server README says.
- Server address storage is localStorage for now, with a TODO to
  move to Capacitor Preferences. No credentials exist to store, and
  none should be added without a design note.
- Scanning stays defensive and local-first: private subnets only,
  max /16, no brute force, no exploits, no password checks. The
  mobile client cannot change those rules, it only asks the server
  to run a scan.

## Consequences

- Landon keeps one UI. Dashboard fixes land on the phone by
  re-running `scripts/sync-web.sh` and `npx cap sync`.
- The phone is useless without the home server running. That is
  accepted for Phase 1 and documented in the README.
- The next real work is on a device, not in this repo: `npx cap add
  android`, `npx cap add ios`, open in Android Studio or Xcode (or
  a cloud build), and test scan, trust, and demo flows against the
  home server over Tailscale.
