# Lantern

Lantern is a local-first home network scanner. It finds the devices on your network, flags risky open ports in plain English, and shows what changed since the last scan.

It is defensive only. It scans your own private network, with your permission. It never guesses passwords, never sends exploits, and never phones home. All results stay in one local SQLite file.

Not affiliated with any other project named Lantern, including the Lantern VPN / censorship circumvention project. This Lantern only scans local networks.

## What it answers

1. What devices are on my network right now?
2. Which of them have risky ports open, in plain English?
3. What changed since the last scan? New device, missing device, new open port.

## Why not just Nmap or Fing?

Nmap is powerful and has no memory: no history, no diff, no plain English fix steps. Fing is closed and cloud tied. Lantern is the small middle: a fast connect scan, a saved history, a diff, and a report a non-security person can act on. The CLI is the product first, the dashboard is the view on top of it.

## Quick start

No third-party dependencies. Python 3.11 or newer.

From a clone of this repo:

```bash
# optional but recommended: install the package (includes the web UI assets)
python3 -m pip install -e .

python3 -m lantern demo
python3 -m lantern web
# open http://127.0.0.1:8068/
```

You can also run without installing: `python3 -m lantern …` from the repo root works the same way, because the `lantern` package lives next to the command.

The demo runs two fake scans, saves them, prints the diff (one new unknown device with Telnet open), and the dashboard shows the same result in a browser. No network is scanned in demo mode.

## Run and debug

| Goal | Command |
| --- | --- |
| Demo scan + diff (offline) | `python3 -m lantern demo` |
| Web dashboard | `python3 -m lantern web` then open http://127.0.0.1:8068/ |
| Dashboard with request logs | `python3 -m lantern web --debug` |
| Custom DB path | `python3 -m lantern web --db /tmp/lantern.db` |
| Custom bind/port | `python3 -m lantern web --host 127.0.0.1 --port 8068` |
| Extra dashboard Host | `python3 -m lantern web --allow-host dashboard.home` (repeat the flag for another host) |
| Real scan | `python3 -m lantern scan --subnet 192.168.1.0/24` |
| List named scopes | `python3 -m lantern scopes --config lantern.toml` |
| Scan one named scope | `python3 -m lantern scan --config lantern.toml --scope home` |
| Diff last two scans | `python3 -m lantern diff` |
| List saved scans | `python3 -m lantern history` |
| HTML/JSON report | `python3 -m lantern report --format html` (add `--scan-id N` for an older scan) |
| Tests | `python3 tests/run_tests.py` |

Every command accepts `--db PATH` and `--format`; see `python3 -m lantern <command> --help`. Errors go to stderr with exit code 2.

Default database file: `data/lantern.db` (created automatically; gitignored).

Opening a database applies any pending schema upgrade. Lantern only migrates forward, in one transaction. A file from a newer Lantern is refused so an older copy of the program cannot rewrite it. The first time a database from 0.3.0 is opened, Lantern copies it to the same path with `.v0.bak` added (for example `data/lantern.db.v0.bak`) and then stamps schema version 1. Scans, devices, and trusted devices stay in the file. Schema version 1 is that 0.3.0 layout plus the version table. The backup is still a local SQLite file; remove it yourself once you trust the upgraded one.

**Debug tips**

- Prefer demo mode while developing UI or storage: `python3 -m lantern demo` then `python3 -m lantern web --debug --db data/lantern.db`.
- `--debug` prints each HTTP request to stderr; leave it off for normal use.
- Break in the stdlib server with `python3 -m pdb -m lantern web --debug`, or attach your IDE debugger to `lantern.cli:main` / `lantern.webapp:serve`.
- API smoke check: `curl -s http://127.0.0.1:8068/api/status`. A POST also needs the per-process token from the page (it is not printed):

  ```bash
  token=$(curl -s http://127.0.0.1:8068/ | sed -n 's/.*name="lantern-token" content="\([^"]*\)".*/\1/p')
  curl -s -X POST http://127.0.0.1:8068/api/demo \
    -H 'Content-Type: application/json' \
    -H "X-Lantern-Token: $token" \
    -d '{}'
  ```
- If the dashboard 404s after `pip install`, the install is missing `lantern/web`. Reinstall from this repo (`pip install -e .`); package data is declared in `pyproject.toml`.
- Subnet auto-detect uses the machine's outbound private IPv4, then its hostname. A hostname lookup that takes more than half a second is skipped, so a slow DNS answer cannot stall the dashboard. If Lantern still cannot guess, pass `--subnet` (CLI) or fill the Subnet field in the UI.

## Scan your own network

```bash
python3 -m lantern scan --subnet 192.168.1.0/24
python3 -m lantern diff
python3 -m lantern history
python3 -m lantern report --format html > report.html
```

To keep a few networks on file, copy [`examples/lantern.toml`](examples/lantern.toml) to `lantern.toml` and edit the subnets to networks you are allowed to scan. Then:

```bash
python3 -m lantern scopes --config lantern.toml
python3 -m lantern scan --config lantern.toml --scope home
```

Each scope is one private subnet (`subnet`) plus an optional `description`. `lantern scopes` only prints the file. It does not scan and it does not create a database. If the file defines one scope, `--scope` may be omitted. If it defines several, `--scope` is required. `--subnet` on its own still works and does not read the file. Passing `--subnet` together with `--config` or `--scope` is an error. The dashboard does not read `lantern.toml`; its subnet field is unchanged.

A scan pings every address in the subnet (50 at a time), adds anything already in the OS neighbor (ARP) cache, then TCP-connects to the 25 risk ports on each live host, 8 hosts at a time. Expect roughly 10 to 30 seconds for a /24. Hosts that block ping and are not in the ARP cache are missed; run the scan twice if your router has just rebooted.

From the dashboard you can also run a real scan or a demo scan, see the diff banner, search and filter devices, label a device and mark it trusted or unknown, browse scan history, and open the HTML report. Trust is stored by MAC address in the same SQLite file, so a trusted label survives later scans.

Run scans from a machine on your home network. A scan from inside a normal Docker container only sees the container network.

## Safety rules, enforced in code

- Private RFC1918 subnets only. Public, loopback, and link-local addresses are refused.
- At most 1024 addresses per scan (a /22), normally a /24.
- A scope in `lantern.toml` uses those same checks. The file cannot raise the cap, allow a public, loopback, or link-local range, or set excludes, extra CIDRs, or a different port list. Those keys are rejected.
- No brute force, no exploits, no default password checks, ever. The only bytes Lantern sends after connecting are a single `HEAD / HTTP/1.0` to ports that usually speak HTTP.
- Stdlib only. No Nmap, no Scapy, no root needed.

Only scan networks you own or have explicit permission to scan. See [SECURITY.md](SECURITY.md).

## Threat model

Lantern is a local admin tool. The dashboard has no login. The checks below are there to stop another website in the same browser, not to keep out a person who can already open the page.

What it resists:

- Another site triggering a scan or reading the inventory (cross-site requests, and DNS rebinding where a public name starts pointing at `127.0.0.1`).
- A scan of a network that is not a small private range.

What it does not resist:

- Anyone who can open an allowed Host can read the page, and the page contains the API token. That person can call the API. `--allow-host` does not add a login, and binding to something other than loopback (`--host`) is still an explicit choice with the same warning as before.
- A person at the keyboard, or another local user who can read the SQLite file.

Every request, including `GET` and the index, must send a `Host` of `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`, or a host you named with `--allow-host`. Nothing else is accepted. A name you did not list is refused even when it resolves to loopback, which is the rebinding case. State-changing `POST /api/*` calls also require `X-Lantern-Token`. The process generates that token at startup with `secrets.token_urlsafe`, embeds it in the dashboard page, and compares it with `hmac.compare_digest`. It is not written to the log. If a `POST` includes an `Origin` header, that origin must be `http` or `https` and its host and port must be on the same allowlist. A `POST` with no `Origin` (curl, or another non-browser client) is accepted only when the token is valid.

Scanning is unchanged: private RFC1918 ranges only, at most 1024 addresses, no loopback or link-local targets. The Host allowlist does not widen that.

## Web dashboard

No pip install needed. The dashboard is stdlib only, plain HTML, CSS, and JavaScript, with a JSON API.

```bash
python3 -m lantern web
# open http://127.0.0.1:8068/
```

API. Every call is refused (403, body `{"error": "Forbidden."}`) unless `Host` is loopback on this port or a host passed with `--allow-host`.

| Route | Returns |
| --- | --- |
| `GET /api/status` | version, guessed subnet, scan count, latest scan id, `scan_running` |
| `GET /api/scans` | saved scans, newest first |
| `GET /api/scans/latest`, `GET /api/diff` | latest scan plus its diff against the scan before it |
| `GET /api/scans/{id}` | one scan plus its diff against the scan before it |
| `GET /api/report?format=json\|html&scan_id=N` | report for the latest scan, or scan `N` |
| `POST /api/scan` `{"subnet": "192.168.1.0/24"}` | runs a real scan (subnet optional, auto-detected); 409 while one is running |
| `POST /api/demo` `{}` | saves the two demo scans |
| `POST /api/trust` `{"mac": "...", "label": "...", "trusted": true}` | labels a device by MAC |

`GET` needs an allowed `Host` and does not need the token. `POST /api/*` also needs the header `X-Lantern-Token`. The dashboard reads that value from `<meta name="lantern-token">` in the page and sends it on every POST. A new token is generated each time the process starts. It is not printed and it is not written to the request log.

POST bodies must be JSON with `Content-Type: application/json` and under 64 KiB (415 or 413 otherwise). If a POST includes `Origin`, that origin's host and port must be on the same allowlist (`http` or `https` only). A POST with no `Origin` is accepted only when the token is valid. A bad Host, a missing or wrong token, or a disallowed Origin is a generic 403. Scan results include trusted labels and `trusted`/`known` flags per device.

`--allow-host` is repeatable. `python3 -m lantern web --allow-host dashboard.home` also accepts `Host: dashboard.home:<port>`. `python3 -m lantern web --allow-host dashboard.home:8443` accepts that exact host and port. Bracket an IPv6 address (`--allow-host '[2001:db8::5]'`). The default allowlist is only `127.0.0.1`, `localhost`, and `[::1]` on the bound port.

The dashboard binds to localhost by default and has no login, by design for local use. Keep it there, or behind Tailscale. Never expose it to the internet.

Docker, for a homelab host:

```bash
docker compose up -d
```

The compose file uses host networking, because a scan from inside a normal container only sees the container network. See `docker-compose.yml` for the warning. The Docker build has not been verified in every environment; please report issues.

## What it scans

25 ports, chosen for risk, not coverage: Telnet, FTP, SSH, SMB, RDP, VNC, databases, mail, web, plus homelab services (Jellyfin 8096, Plex 32400, Home Assistant 8123). Each open port maps to a severity, a plain English title, and a fix step in `lantern/ports.py`.

## Tests

```bash
python3 tests/run_tests.py
```

This discovers every `tests/test_*.py` (`unittest`): risk rules and safety guardrails, subnet and ARP parsing, TCP probes against a local listener, SQLite history and diff, the CLI, and the web API (routes, validation, request hygiene, Host allowlist, API token, static path safety) against temporary databases. It ends with a CLI demo smoke test in a fresh process. Nothing touches a real network. The web tests use a localhost listener and fake data only.

GitHub Actions runs that same suite on Linux, macOS, and Windows for Python 3.11, 3.12, and 3.13. A second job builds an sdist and a wheel, installs the wheel in a clean directory (so it is not importing the checkout), and runs `lantern demo`. The demo uses fake data; CI does not scan a network.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: keep it stdlib only, keep it defensive, keep the plain English fixes, and add a test for new behavior.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
