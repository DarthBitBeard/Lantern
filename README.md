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
| Custom bind/port | `python3 -m lantern web --host 127.0.0.1 --port 8068` (loopback only) |
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

On macOS and Linux, a new database file, that migration backup, and the HTML file from `lantern demo` are created mode `0600` (readable and writable only by your user). This holds under the usual umask `022` and under a permissive umask. If the directory for a new database does not exist yet, Lantern creates it mode `0700`. A directory that already exists stays at the mode you set. If a database or backup already on disk is readable by the group or by other users, Lantern prints a warning to stderr and leaves that file unchanged. A database path that is a symlink is refused.

On Windows, Lantern does not set or check these Unix permission bits. Who can read the file is the access control list on your user profile. Keep the database in your profile, not in a folder shared with other accounts.

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

Each scope is one private subnet (`subnet`) plus an optional `description`. A scope file larger than 64 KiB is refused before it is parsed. `lantern scopes` only prints the file. It does not scan and it does not create a database. If the file defines one scope, `--scope` may be omitted. If it defines several, `--scope` is required. `--subnet` on its own still works and does not read the file. Passing `--subnet` together with `--config` or `--scope` is an error. The dashboard does not read `lantern.toml`; its subnet field is unchanged.

A scan pings every address in the subnet (50 at a time), adds anything already in the OS neighbor (ARP) cache, then TCP-connects to the 25 risk ports on each live host, 8 hosts at a time. Expect roughly 10 to 30 seconds for a /24. Hosts that block ping and are not in the ARP cache are missed; run the scan twice if your router has just rebooted.

From the dashboard you can also run a real scan or a demo scan, see the diff banner, search and filter devices, label a device and mark it trusted or unknown, browse scan history, and open the HTML report. Trust is stored by MAC address in the same SQLite file, so a trusted label survives later scans.

Run scans from a machine on your home network. A scan from inside a normal Docker container only sees the container network.

## Safety rules, enforced in code

- Private RFC1918 subnets only. Public, loopback, and link-local addresses are refused.
- At most 1024 addresses per scan (a /22), normally a /24.
- A scope in `lantern.toml` uses those same checks. The file cannot raise the cap, allow a public, loopback, or link-local range, or set excludes, extra CIDRs, or a different port list. Those keys are rejected. A scope file larger than 64 KiB is refused.
- No brute force, no exploits, no default password checks, ever. The only bytes Lantern sends after connecting are a single `HEAD / HTTP/1.0` to ports that usually speak HTTP.
- Stdlib only. No Nmap, no Scapy, no root needed. The Docker image runs as uid 10001, not root.
- The database, its migration backup, and the demo HTML report are created private to your user. A database path that is a symlink is refused. Lantern leaves an existing directory at the mode you set, and warns on stderr if that directory is looser than 0700 (for example 0755). For the Docker bind mount of `./data`, run `mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data`.

Only scan networks you own or have explicit permission to scan. See [SECURITY.md](SECURITY.md).

## Threat model

Lantern is a local admin tool. The dashboard has no accounts. On loopback the checks stop another website in the same browser. A LAN bind is a separate, explicit choice and requires one startup token on every API call.

What it resists:

- Another site triggering a scan or reading the inventory (cross-site requests, and DNS rebinding where a public name starts pointing at `127.0.0.1`).
- A scan of a network that is not a small private range.
- A LAN client calling the API without the startup token. In that mode the page does not contain the token.

What it does not resist:

- On loopback, anyone who can open an allowed Host can read the page, and that page contains the token used for `POST`. That person can call the API. `--allow-host` does not add a login.
- On a LAN bind, anyone who has the startup token can read the inventory and start scans. Treat that token like a password. It is not an account system.
- A person at the keyboard, or another local user who can read the SQLite file.

Every request must send an allowed `Host`. On loopback that is `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`, plus any host you named with `--allow-host`. With `--allow-lan`, the allowlist is only the explicit bind address and the `--allow-host` values. `0.0.0.0` and `::` are not added, and a wildcard is not accepted. A name you did not list is refused even when it resolves to loopback.

Loopback `POST /api/*` requires `X-Lantern-Token`. The process generates that token at startup with `secrets.token_urlsafe` (256 bits), embeds it in the dashboard page, and compares it with `hmac.compare_digest`. It is not written to the log. `GET` on loopback needs the Host check and does not need the token. If a `POST` includes an `Origin` header, that origin must be `http` or `https` and its host and port must be on the same allowlist. A `POST` with no `Origin` is accepted only when the token is valid.

A LAN bind uses that same header for `POST` and for `GET` of inventory, status, and reports. The token is the one the CLI loaded or generated. It is not embedded in the page and it is not written to the log.

Scanning is unchanged: private RFC1918 ranges only, at most 1024 addresses, no loopback or link-local targets. The Host allowlist does not widen that.

## Web dashboard

No pip install needed. The dashboard is stdlib only, plain HTML, CSS, and JavaScript, with a JSON API.

```bash
python3 -m lantern web
# open http://127.0.0.1:8068/
```

API. Every call is refused (403, body `{"error": "Forbidden."}`) unless `Host` is on the allowlist. On loopback that is this port's loopback names, or a host passed with `--allow-host`. With `--allow-lan` it is only the bind address and `--allow-host`.

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

On loopback, `GET` needs an allowed `Host` and does not need the token. `POST /api/*` also needs the header `X-Lantern-Token`. The dashboard reads that value from `<meta name="lantern-token">` in the page and sends it on POST. A new token is generated each time the process starts. It is not printed and it is not written to the request log.

With `--allow-lan`, `GET /api/*` (inventory, status, and HTML or JSON reports) needs the same header as `POST`. The page does not contain the token. Paste it once into the dashboard; the browser keeps it in `sessionStorage` for that tab and sends it as `X-Lantern-Token`. Static files such as `app.js` stay available without the token. The comparison is `hmac.compare_digest`. A token that is presented and does not match waits a short fixed time. The token is not written to the log. `--debug` does not print a generated token; set the file or `LANTERN_API_TOKEN` instead.

POST bodies must be JSON with `Content-Type: application/json` and at most 64 KiB (415 or 413 otherwise). `Transfer-Encoding` is rejected with 400 and the connection is closed. Every POST closes the connection, so bytes after the body are not another request. If a POST includes `Origin`, that origin's host and port must be on the same allowlist (`http` or `https` only). A POST with no `Origin` is accepted only when the token is valid. A bad Host, a missing or wrong token, or a disallowed Origin is a generic 403. `OPTIONS`, `PUT`, `DELETE`, and `PATCH` are 405 after the Host check and, when LAN-bound, the token check. An unexpected server error is a generic 500; the exception text is logged only with `--debug`. Each connection has a 10 second idle timeout and a 10 second deadline for the request line and headers, so a slow drip cannot hold a slot. The process caps connections overall and per client address; a full cap is 503. A request target must be a path; an absolute URL in the request line is a 400. Scan results include trusted labels and `trusted`/`known` flags per device.

`--allow-host` is repeatable. `python3 -m lantern web --allow-host dashboard.home` also accepts `Host: dashboard.home:<port>`. `python3 -m lantern web --allow-host dashboard.home:8443` accepts that exact host and port. Bracket an IPv6 address (`--allow-host '[2001:db8::5]'`). `0.0.0.0`, `::`, a bare `0` or other all-digit name, a zone id such as `[fe80::1%eth0]`, a wildcard, and a CIDR are rejected. On loopback the default allowlist is only `127.0.0.1`, `localhost`, and `[::1]` on the bound port. `::1` is a real IPv6 loopback listener, not only an allowed Host value.

The dashboard binds to loopback by default (`127.0.0.1`). Any other address, including `0.0.0.0` and `::`, is refused unless you also pass `--allow-lan`. That flag still does not open the port by itself. It exits 2, before listening, unless it has a token of at least 128 bits (22 to 512 urlsafe characters). The token comes from `LANTERN_API_TOKEN_FILE`, then `LANTERN_API_TOKEN`, then `secrets.token_urlsafe` when stderr is an interactive terminal and `--debug` is not set. The generated token is printed once on that terminal and nowhere else. `--debug` does not print it. When stderr is not a terminal, which is how `docker logs` works, Lantern does not generate or print a token; set the file or the environment variable. The token is not written to the database or the request log. `--host 0.0.0.0` or `--host ::` also needs `--allow-host` set to the LAN address clients will send, because the unspecified address is not put on the allowlist. Prefer an SSH tunnel or Tailscale to `127.0.0.1`. Never expose port 8068 to the internet.

Docker, for a homelab host:

```bash
mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data
docker compose up -d
# on the host: http://127.0.0.1:8068/
```

The compose file uses host networking so a scan can see the host LAN (the ARP cache and neighbor hosts). The dashboard itself binds `127.0.0.1`. With host networking that is the host's loopback, not the LAN. Compose does not publish port 8068.

The container runs as uid 10001, not root. Compose drops every capability (`--cap-drop ALL`), makes the root filesystem read-only, mounts a tmpfs on `/tmp`, keeps the SQLite file on the `/data` volume, and sets `no-new-privileges`. ICMP ping needs `CAP_NET_RAW` and a ping binary. This image adds neither. TCP connect scans and the host ARP cache work with all capabilities dropped. A setuid or file-capability ping would not help: `no-new-privileges` ignores both. The comments in `Dockerfile` and `docker-compose.yml` record the same flags.

To opt in to a LAN bind, put the token in a regular file and point `LANTERN_API_TOKEN_FILE` at it (the compose file has a commented `secrets:` snippet). The file must not be a symlink or a FIFO, and it must be at most 4 KiB. On macOS and Linux it must be mode 0400 or 0600: any group or other bit, including a mode 0444 Docker secret, is refused. Compose bind-mounts the host file as-is and does not change its mode, so `chmod 400` and `chown` it to uid 10001 yourself. Lantern does not follow a symlink to a looser file. Override the command with `--host 0.0.0.0`, `--allow-lan`, and `--allow-host` set to the LAN address. Do not put the token in `docker-compose.yml`. The container has no terminal, so Lantern will not print a token into `docker logs`. Without the file or `LANTERN_API_TOKEN`, the command exits 2 and does not listen. Prefer Tailscale or an SSH tunnel instead.

CI (`.github/workflows/docker.yml`) builds the image and runs every container with `--network none` (loopback only). It checks the process is not root, the default command's listening socket is `127.0.0.1:8068`, a non-loopback bind without `--allow-lan` is refused, `--allow-lan` without a token is refused, and a start that uses a token file does not put that token in `docker logs`. It also runs `lantern --version`, an offline `lantern demo`, and a check that loopback and public subnets are refused. The job does not push, tag, or publish an image, and it does not scan a network. The demo uses the built-in fake devices.

## What it scans

25 ports, chosen for risk, not coverage: Telnet, FTP, SSH, SMB, RDP, VNC, databases, mail, web, plus homelab services (Jellyfin 8096, Plex 32400, Home Assistant 8123). Each open port maps to a severity, a plain English title, and a fix step in `lantern/ports.py`.

## Tests

```bash
python3 tests/run_tests.py
```

This discovers every `tests/test_*.py` (`unittest`): risk rules and safety guardrails, subnet and ARP parsing, TCP probes against a local listener, SQLite history and diff, database file permissions, scope files, the CLI, and the web API (routes, validation, request hygiene, Host allowlist, API token, static path safety) against temporary databases. It ends with a CLI demo smoke test in a fresh process. Nothing touches a real network. The web tests use a localhost listener and fake data only. On Windows the permission tests skip Unix mode bits.

GitHub Actions runs that same suite on Linux, macOS, and Windows for Python 3.11, 3.12, and 3.13. A second job builds an sdist and a wheel, installs the wheel in a clean directory (so it is not importing the checkout), and runs `lantern demo`. The demo uses fake data; CI does not scan a network.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: keep it stdlib only, keep it defensive, keep the plain English fixes, and add a test for new behavior.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
