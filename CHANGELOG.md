# Changelog

## 0.2.1 - 2026-10-27

- Include `lantern/web` HTML/CSS/JS in the package so `pip install` and Docker serve the dashboard.
- Fix subnet auto-detect on hosts whose hostname resolves to `127.0.0.1`.
- Add `lantern web --debug` for HTTP request logging, clearer run/debug docs in the README.
- Fail fast with a clear error if dashboard assets are missing after a bad install.

## 0.2.0 - 2026-10-27

- Web dashboard, stdlib only, on `http://127.0.0.1:8068/` by default.
- Device labels and a trusted device list, stored by MAC address.
- Scan history view, search and filters, JSON and HTML reports from the dashboard.
- JSON API: status, scans, latest, diff, report, scan, demo, trust.
- Dockerfile and docker-compose with host networking.
- SECURITY.md, CONTRIBUTING.md, and CI workflow.

## 0.1.0 - 2026-10-27

- First scaffold. CLI scan, diff, and report.
- 25-port TCP connect scan, plain English risk rules, SQLite history and diff.
- Demo mode with a fake home network, including a new device with Telnet open.
- Safety rules: private subnets only, max /16, no brute force or exploits.
