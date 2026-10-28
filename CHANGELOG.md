# Changelog

## Unreleased

- `lantern asset` records owner, location, tags, criticality, and notes for a device that already appears in a saved scan. The record is kept across scans, keyed by MAC, or by IP when the device has no MAC. `report` and `diff` include the fields. The trust label is unchanged. The dashboard does not show them yet; that view arrives in M4, and the API does not serve the stored values. Owner, location, and notes are personal data kept only in the local mode-0600 database, and they are included in reports and diffs you may share. Schema 3 adds the table; opening an older database copies it to `.vN.bak` first. At most 10000 records are stored. Blank values are rejected. Tags are de-duplicated before the 10-tag limit, and a tag that case folding or NFKC would rewrite is rejected. Control, format, and separator characters are rejected and stripped from report text. `history`, `diff`, `report`, and `asset list --scope` still match a scope name that remains on saved scans after it is removed from the config file. An exact stored spelling is used when more than one case variant is stored.
- `history`, `diff`, and `report --scope` use the spelling stored in the scope file. `scan --scope LAB-2` and `history --scope lab-2` refer to the same scope when the file names it `Lab-2`. A typed name is checked against the scope-name rules before case folding, so a Kelvin sign or `ß` is rejected instead of being folded.
- A diff compares a scan only to the previous scan of the same scope, including `lantern diff` and `lantern report` with no `--scope`, and the dashboard. Unscoped scans compare only to earlier unscoped scans.
- Scan targets must lie fully inside `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`. `0.0.0.0/8`, `240.0.0.0/4`, `192.0.0.0/24`, the TEST-NET blocks, and `198.18.0.0/15` are refused. Scope names that differ only by case are the same name.
- `lantern scan --all --format html` prints one HTML document for the scopes that ran. One run still allows exactly 1024 unique addresses and refuses 1025 before any probe.
- `lantern scan --config lantern.toml --all` scans every named scope in file order. Repeat `--scope` to scan a chosen list in the order given. A repeated name is scanned once. Each stored scan is tagged with its scope name (schema 2, forward only). A database from schema 1 is copied to `.v1.bak` and then gains that column; older rows keep a null name. `history`, `diff`, and `report` take `--scope` to stay inside that name, and a single-scope scan diffs against the previous scan of that same scope. One scope that fails does not drop the others; the summary lists which ran and which failed. Each scope is still checked with the private-range rule. One run scans at most 1024 unique addresses: overlapping ranges are collapsed, and a merged total over 1024 is refused before any probe. HTML reports and the dashboard escape the scope name, hostname, label, banner, and any owner, tag, or notes text.
- An empty `LANTERN_STRICT_AUTH` is treated as unset, so strict auth stays on. Opt-out values are only `0`, `false`, `no`, and `off`. Any other non-empty value refuses to start, including when `--strict-auth` or `--no-strict-auth` is also set. Compose uses `restart: on-failure:3` so a missing token, which exits 2, does not restart forever. Compose secrets are untested.
- Strict auth is the default for `lantern web`, on loopback and with `--allow-lan`. The token is not embedded in the page, and every `/api` route, including `GET`, requires `X-Lantern-Token`. On a terminal a generated token is printed once as `http://127.0.0.1:PORT/#token=...`. The link is valid until that process restarts; the fragment is not a request. Without a terminal and without `LANTERN_API_TOKEN_FILE` or `LANTERN_API_TOKEN`, startup exits 2 and does not listen. `--no-strict-auth` or `LANTERN_STRICT_AUTH=0` opts out and re-opens the local-user token gap on loopback. `0` does not override `--strict-auth`. `--no-strict-auth` turns strict auth off even when `LANTERN_STRICT_AUTH=1`, and the warning names that flag or the actual off value (`0`, `false`, `no`, or `off`).
- The page uses the `#token=` fragment in strict auth and LAN mode, and a 403 clears a stored token in both. Without a terminal, the token must come from `LANTERN_API_TOKEN_FILE` or `LANTERN_API_TOKEN`.
- A GET or HEAD with `Content-Length` greater than 0 closes the connection, so the unread body is not a second request. A `Content-Length` that is negative, not an integer, or repeated is 400 on every method, and the connection is still closed. Any `Transfer-Encoding` header, including an empty one, is a 400 and the connection is closed. Reading the request line, headers, and body shares one 10 second deadline, so a slow body drip cannot hold a slot. The response is sent in 16 KiB chunks. Each chunk waits up to 10 seconds or the time remaining on a 60 second overall deadline, whichever is shorter. A reader that keeps going may take longer than 10 seconds overall, up to 60 seconds, and a stall is dropped when the chunk's wait runs out. A 405 response includes `Allow: GET, HEAD, POST`. At most 32 connections are served at once, and at most 8 from one client address. `TRACE` and `CONNECT` list `Connection: close` once. `--allow-host` shorthand such as `127.1` is rejected with a message that says to use the full dotted form.
- Docker Swarm secrets (mode 0444) and Kubernetes secrets (default 0644) are refused as the API token file until the mode is 0400. Compose secrets are untested. The commented top-level `secrets:` block in `docker-compose.yml` is at column 0, and the service `secrets:` comment uses the same prefix as the other LAN-snippet comments, so uncommenting that snippet is valid YAML.
- The package CI job installs `pip`, `build`, `setuptools`, and `wheel` from pinned hashes and runs `python -m build --no-isolation`. Windows also pins `colorama==0.4.6`.
- `--allow-host` rejects shorthand and loose IPv4 forms such as `127.1`, `0x7f000001`, `0177.0.0.1`, `0x7f.1`, and `127.000.000.001`.
- Reading a dashboard request line and its headers has a 10 second deadline in addition to the per-read socket timeout, so a client that drips bytes cannot hold a connection. Concurrent connections are capped per client address as well as in total. A full cap is still 503. A presented API token that does not match waits a short fixed time.
- `LANTERN_API_TOKEN_FILE` must be a regular file of at most 4 KiB, opened with `O_NOFOLLOW` and `O_NONBLOCK` where the platform has them. A symlink, a FIFO, or a larger file is refused and does not hang startup. The token itself is at most 512 characters. On macOS and Linux the file mode must be 0400 or 0600. Mode 0444 is refused, including a Docker secret mounted that way: Compose uses the host file's mode unchanged, so set 0400 and ownership uid 10001 on the host. `--debug` does not print a generated token; set the file or `LANTERN_API_TOKEN` instead.
- `OPTIONS`, `PUT`, `DELETE`, and `PATCH` return 405 after the Host check and, when LAN-bound, the token check. `Transfer-Encoding` is a 400 and the connection is closed. Every POST closes the connection. `--allow-host 0` and other all-digit names are rejected, along with the unspecified addresses already refused.
- GitHub Actions are pinned to commit SHAs, checkout does not persist credentials, and the Docker base image is pinned by digest. Dependabot watches GitHub Actions and Docker.
- The dashboard rejects any request whose `Host` header is not on the allowlist. On loopback that is `127.0.0.1`, `localhost`, or `[::1]` on the bound port, or a host named with repeatable `--allow-host`. This blocks DNS rebinding. `POST /api/*` requires the per-process `X-Lantern-Token` (compared with `hmac.compare_digest`, not logged) and, when `Origin` is sent, an `http` or `https` origin on that same allowlist. A missing `Origin` is accepted only with a valid token. On loopback, `GET` still has to pass the Host check and does not need the token, and the token is embedded in the page. Private-subnet limits are unchanged (RFC1918 only, at most 1024 addresses). `::1` is an IPv6 listener as well as an allowed Host. An absolute-form request line is rejected with 400. `--allow-host` rejects unspecified addresses (`0.0.0.0`, `::`), zone ids (`[fe80::1%eth0]`), wildcards, and CIDR.
- `--allow-lan` is the only way to bind a non-loopback address (`0.0.0.0`, a LAN IP, `::`). The Docker image command stays `--host 127.0.0.1`. Compose still uses host networking so a scan can see the host LAN, and it does not publish a port. The flag exits 2 before opening a socket unless there is one startup token of at least 128 bits. Precedence is `LANTERN_API_TOKEN_FILE`, then `LANTERN_API_TOKEN`, then `secrets.token_urlsafe` when stderr is an interactive terminal. That generated token is printed once on the terminal and is never written to the log, the database, or the image. When stderr is not a terminal, Lantern does not print a token and will not start without the file or the environment variable. The CLI passes that token into `make_server`, so the page token and the LAN token are the same value. In LAN mode every API route, including `GET` inventory and reports, requires `X-Lantern-Token`. The page does not contain it; the browser stores it in `sessionStorage` after you paste it once. The Host allowlist is only the explicit bind address and `--allow-host` values. `--host 0.0.0.0` or `::` also requires `--allow-host` with the address clients will send. A loud warning names the bind address and the allowlist. Anyone with the token has full control, and GET data is protected too.
- API handlers return a generic 500. Exception text is written only with `--debug`, and only to stderr. Each request socket times out after 10 seconds, concurrent connections are capped, and POST bodies stay capped at 64 KiB.
- The image runs as non-root uid/gid 10001 and owns `/data`. Compose drops all capabilities, sets a read-only root filesystem with a tmpfs on `/tmp` and the `/data` volume, and sets `no-new-privileges`. ICMP ping needs `CAP_NET_RAW` and a ping binary; neither is added. TCP connect scans and the host ARP cache need no extra capability. The offline Docker smoke job checks the process is not root, the listening socket is `127.0.0.1:8068`, a LAN bind without `--allow-lan` is refused, `--allow-lan` without a token is refused, and a start that mounts a token file does not log that token. Containers in that job use `--network none`.
- New database files, migration backups (`.vN.bak`), and the demo HTML report are created mode 0600. A directory Lantern creates for the database is mode 0700, including the `data/` directory the CLI opens for a new database. That holds under umask 022 and under a permissive umask. Lantern leaves a directory it did not create at the mode you set. If that directory is looser than 0700 (for example 0755), Lantern prints a warning on stderr and does not change it. If an existing database or backup is readable by the group or by other users, Lantern prints a warning on stderr and leaves the file unchanged. A database path that is a symlink is refused, including a dangling link. On Windows these Unix mode bits are not set or checked; the user profile ACL is what keeps the file private. For a bind-mounted Docker data directory, run `mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data` before `docker compose up`.
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
