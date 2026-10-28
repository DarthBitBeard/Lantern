# Changelog

## Unreleased

- The dashboard rejects any request whose `Host` header is not loopback on the bound port (`127.0.0.1`, `localhost`, or `[::1]`), or a host named with repeatable `--allow-host`. This blocks DNS rebinding. `POST /api/*` also requires the per-process `X-Lantern-Token` embedded in the page (compared with `hmac.compare_digest`, not logged) and, when `Origin` is sent, an `http` or `https` origin on that same allowlist. A missing `Origin` is accepted only with a valid token. `GET` still has to pass the Host check and does not need the token. Private-subnet limits are unchanged (RFC1918 only, at most 1024 addresses).
- The dashboard refuses any bind that is not loopback (`127.0.0.1`, `localhost`, `::1`, or another loopback address) unless `--allow-lan` is set. The Docker image command is `--host 127.0.0.1`. Compose still uses host networking so a scan can see the host LAN, and the dashboard stays on the host's loopback. `--allow-lan` does not start an unauthenticated listener: until `webapp.serve` accepts a startup token argument (`api_token`, `token`, or `startup_token`), the flag exits with "requires S1 token support". When that argument exists, Lantern generates a token with `secrets.token_urlsafe`, prints it once on stderr, and prints a loud warning.
- The image runs as non-root uid/gid 10001 and owns `/data`. Compose drops all capabilities, sets a read-only root filesystem with a tmpfs on `/tmp` and the `/data` volume, and sets `no-new-privileges`. ICMP ping needs `CAP_NET_RAW` and a ping binary; neither is added. TCP connect scans and the host ARP cache need no extra capability. The offline Docker smoke job checks the process is not root, the listening socket is `127.0.0.1:8068`, and a LAN bind without `--allow-lan` is refused. Containers in that job use `--network none`.
- New database files, migration backups (`.vN.bak`), and the demo HTML report are created mode 0600. A directory Lantern creates for the database is mode 0700, including the `data/` directory the CLI opens for a new database. That holds under umask 022 and under a permissive umask. Lantern leaves a directory it did not create at the mode you set. If an existing database or backup is readable by the group or by other users, Lantern prints a warning on stderr and leaves the file unchanged. A database path that is a symlink is refused, including a dangling link. On Windows these Unix mode bits are not set or checked; the user profile ACL is what keeps the file private. For a bind-mounted Docker data directory, run `mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data` before `docker compose up`.
- `lantern.store.write_private_file` writes a file atomically at mode 0600. The demo HTML report uses it, and a later CSV or JSON export can too. `warn_loose_permissions` is the stderr warning the CLI can call; it does not raise and it does not change the file.
- A scope config larger than 64 KiB is refused before it is parsed. The error does not include the file contents.
- CI runs the test suite on Linux, macOS, and Windows for Python 3.11, 3.12, and 3.13.
- CI builds an sdist and a wheel, installs the wheel outside the source tree, and runs an offline `lantern demo` on Linux, macOS, and Windows.
- Guessing the local subnet gives up on a slow hostname lookup after half a second, so a stuck DNS answer cannot stall the CLI or the dashboard. The UDP route check is unchanged and still does not send a packet.
- SQLite files record a `schema_version`. Opening a database created by 0.3.0 upgrades it in place and keeps its scans, devices, and trusted devices. Before that upgrade, Lantern writes a sibling copy (`<file>.v0.bak`). Migrations only move forward. A file written by a newer Lantern is refused and left unchanged.
- `lantern.toml` can name scan scopes (`subnet` plus an optional `description`). `lantern scopes` lists them and does not scan. `lantern scan --config lantern.toml --scope home` scans that one subnet. `--subnet` still works on its own. Each scope is checked with the same rules as `--subnet`: private RFC1918 only, at most 1024 addresses, no loopback or link-local. Extra keys (excludes, more than one CIDR, a custom port list) are rejected. See `examples/lantern.toml`. The dashboard does not read this file.
- CI builds the Docker image and, with container networking disabled, runs `lantern --version`, an offline `lantern demo`, and a check that loopback and public subnets are refused.

## 0.3.0 - 2026-10-27

Review pass across every layer. No new dependencies.

Scanner and discovery
- One subnet size limit everywhere: at most 1024 addresses (a /22). Before, `validate_subnet` allowed a /16 but the scan then refused anything over 1024 hosts with a v0.1 message.
- Correct ping wait flags per OS. macOS `-W 1` meant 1 millisecond, so every host looked offline.
- Neighbor cache: read `/proc/net/arp` first, then `arp -a`, then `ip neigh`; skip incomplete and malformed entries instead of crashing the scan.
- Loopback and link-local subnets are refused like public ones; a host address such as `192.168.1.5/24` is normalized to its network.
- Banners are cleaned to one printable line; live hosts are port-scanned 8 at a time instead of one by one.

CLI
- `lantern history` lists saved scans; `lantern report --scan-id N` prints an older scan; `lantern --version`.
- `lantern scan --demo` no longer needs a detectable subnet, and stores the demo subnet.
- Reports and `scan` text output apply trusted labels, matching the dashboard. Diffs describe IP moves ("moved from ...").
- Clear errors (exit 2) for an unwritable database path, a port already in use, or an out-of-range `--port`.

Web API
- POST bodies must be `application/json` (415 otherwise) and at most 64 KiB (413). Cross-site POSTs (mismatched `Origin` or `Sec-Fetch-Site: cross-site`) get 403. Responses carry `X-Content-Type-Options: nosniff`, a strict CSP on HTML, and `Cache-Control: no-store`.
- `GET /api/scans/{id}` now includes that scan's diff against the scan before it; `/api/report` accepts the same ids and validates `format`.
- `/api/status` reports `scan_running`; `/api/demo` returns `scan_id`; `/api/trust` requires a boolean `trusted`, normalizes dashed MACs, and trims labels.
- Devices are ordered numerically by IP (`.2` before `.10`), in the API and the CLI.

Dashboard
- History selection stays in sync with what is shown; trusting a device while viewing an old scan no longer jumps to the latest scan.
- Older scans show their own "what changed" panel. Buttons are disabled while a scan or demo runs. Enter in a label field saves it.
- Search also matches port numbers; banners show as tooltips on port chips; version shown in the footer.
- Responsive fixes for narrow screens, visible keyboard focus, `aria-live` status, `noscript` note.

Tests and docs
- Test suite moved to `unittest` with per-module files (discovery, scanner, store, CLI, web); `python3 tests/run_tests.py` discovers them all.
- README, CONTRIBUTING, and SECURITY updated for the subnet limit, new commands, and API hygiene.

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
