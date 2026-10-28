<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/lantern_lockup_horizontal_dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo/lantern_lockup_horizontal_light.svg">
    <img alt="Lantern" src="assets/logo/lantern_lockup_horizontal_light.svg" width="450">
  </picture>
</p>

<p align="center">A local-first home network scanner.</p>

It finds the devices on your network, flags risky open ports in plain English, and shows what changed since the last scan.

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
# A terminal prints http://127.0.0.1:8068/#token=... once.
# Open that link. The token is valid until this process restarts.
# The fragment is not sent to the server.
# With no terminal, set LANTERN_API_TOKEN_FILE or the process exits 2.
```

You can also run without installing: `python3 -m lantern …` from the repo root works the same way, because the `lantern` package lives next to the command.

The demo runs two fake scans, saves them, prints the diff (one new unknown device with Telnet open), and the dashboard shows the same result in a browser. No network is scanned in demo mode.

## Run and debug

| Goal | Command |
| --- | --- |
| Demo scan + diff (offline) | `python3 -m lantern demo` |
| Web dashboard | `python3 -m lantern web`, then open the printed `http://127.0.0.1:8068/#token=...` link. With no terminal, set `LANTERN_API_TOKEN_FILE` or the process exits 2. |
| Dashboard with request logs | `python3 -m lantern web --debug` does not print a token. Set `LANTERN_API_TOKEN_FILE` first, or startup exits 2. With a terminal and no `--debug`, open the printed `#token=` link. |
| Custom DB path | `python3 -m lantern web --db /tmp/lantern.db` |
| Custom bind/port | `python3 -m lantern web --host 127.0.0.1 --port 8068` (loopback only) |
| Extra dashboard Host | `python3 -m lantern web --allow-host dashboard.home` (repeat the flag for another host) |
| Real scan | `python3 -m lantern scan --subnet 192.168.1.0/24` |
| List named scopes | `python3 -m lantern scopes --config lantern.toml` |
| Scan one named scope | `python3 -m lantern scan --config lantern.toml --scope home` |
| Scan several scopes | `python3 -m lantern scan --config lantern.toml --scope home --scope lab` |
| Scan every scope | `python3 -m lantern scan --config lantern.toml --all` |
| Diff last two scans | `python3 -m lantern diff` (add `--scope home` to stay inside one scope) |
| List saved scans | `python3 -m lantern history` (add `--scope home` to list one scope) |
| HTML/JSON report | `python3 -m lantern report --format html` (add `--scan-id N` or `--scope home`) |
| Tests | `python3 tests/run_tests.py` |

Every command accepts `--db PATH` and `--format`; see `python3 -m lantern <command> --help`. Errors go to stderr with exit code 2.

Default database file: `data/lantern.db` (created automatically; gitignored).

Opening a database applies any pending schema upgrade. Lantern only migrates forward, in one transaction. A file from a newer Lantern is refused so an older copy of the program cannot rewrite it. The first time a database from 0.3.0 is opened, Lantern copies it to the same path with `.v0.bak` added (for example `data/lantern.db.v0.bak`) and then upgrades it. Scans, devices, and trusted devices stay in the file. Schema version 1 is that 0.3.0 layout plus the version table. Schema version 2 adds `scope_name` on each scan. A database already at schema 1 is copied to `.v1.bak` and then gains that column; older rows keep a null scope name. The backup is still a local SQLite file; remove it yourself once you trust the upgraded one.

On macOS and Linux, a new database file, that migration backup, and the HTML file from `lantern demo` are created mode `0600` (readable and writable only by your user). This holds under the usual umask `022` and under a permissive umask. If the directory for a new database does not exist yet, Lantern creates it mode `0700`. A directory that already exists stays at the mode you set. If a database or backup already on disk is readable by the group or by other users, Lantern prints a warning to stderr and leaves that file unchanged. A database path that is a symlink is refused.

On Windows, Lantern does not set or check these Unix permission bits. Who can read the file is the access control list on your user profile. Keep the database in your profile, not in a folder shared with other accounts.

**Debug tips**

- Prefer demo mode while developing UI or storage: `python3 -m lantern demo` then `python3 -m lantern web --db data/lantern.db`. Open the printed `http://127.0.0.1:8068/#token=...` link. With no terminal, set `LANTERN_API_TOKEN_FILE` or the process exits 2.
- `--debug` prints each HTTP request to stderr; leave it off for normal use. `python3 -m lantern web --debug` does not print a generated token. Set `LANTERN_API_TOKEN_FILE` or startup exits 2.
- Break in the stdlib server with `python3 -m pdb -m lantern web --debug`, or attach your IDE debugger to `lantern.cli:main` / `lantern.webapp:serve`. `--debug` does not print a token, including under pdb, so set `LANTERN_API_TOKEN_FILE` or the process exits 2. Without `--debug`, open the printed `#token=` link. With no terminal, set that file.
- API smoke check: start `python3 -m lantern web` in a terminal and copy the token from the printed `http://127.0.0.1:8068/#token=...` link. The fragment is not sent by the browser, and the HTML page does not contain the token, so do not scrape it. `GET /api/status` without the header is 403. Send the token as `X-Lantern-Token`:

  ```bash
  # TOKEN is the value after #token= in the printed link.
  curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8068/api/status
  curl -s -H "X-Lantern-Token: $TOKEN" http://127.0.0.1:8068/api/status
  curl -s -X POST http://127.0.0.1:8068/api/demo \
    -H 'Content-Type: application/json' \
    -H "X-Lantern-Token: $TOKEN" \
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
python3 -m lantern scan --config lantern.toml --scope home --scope lab
python3 -m lantern scan --config lantern.toml --all
python3 -m lantern history --scope home
python3 -m lantern diff --scope home
python3 -m lantern report --scope home
```

Each scope is one private subnet (`subnet`) plus an optional `description`. A scope file larger than 64 KiB is refused before it is parsed. `lantern scopes` only prints the file. It does not scan and it does not create a database. If the file defines one scope, `--scope` may be omitted. Repeat `--scope` to scan a chosen list in the order given, or pass `--all` to scan every named scope in file order. Each stored scan is tagged with its scope name. `history`, `diff`, and `report` take `--scope` to stay inside that name. The comparison uses the spelling in the scope file, so `lab-2` matches a scope stored as `Lab-2`. If that name has been removed from the file, `history`, `diff`, and `report` match a unique spelling already stored on a scan. A name that is not a short token is rejected before case folding. A diff compares the latest two scans of that scope, not a scan from a different scope. One scope that fails during the scan does not drop the others; the summary lists which ran and which failed, and the command exits 1. A bad name or a public range is refused before any probe, and the command exits 2. One run scans at most 1024 unique addresses. Exactly 1024 is allowed and 1025 is refused before any probe. Repeated names, including names that differ only by case, are scanned once. Overlapping ranges count once. `lantern diff` and `lantern report` with no `--scope` compare a scan to the previous scan of that same scope. `--format html` with several scopes prints one HTML document. `--subnet` on its own still works and does not read the file. Passing `--subnet` together with `--config`, `--scope`, or `--all` is an error, and so is passing `--all` together with `--scope`. The dashboard does not read `lantern.toml`. When a saved scan has a scope name, the page shows that name escaped.

A scan pings every address in the subnet (50 at a time), adds anything already in the OS neighbor (ARP) cache, then TCP-connects to the 25 risk ports on each live host, 8 hosts at a time. Expect roughly 10 to 30 seconds for a /24. Hosts that block ping and are not in the ARP cache are missed; run the scan twice if your router has just rebooted.

From the dashboard you can also run a real scan or a demo scan, see the diff banner, search and filter devices, label a device and mark it trusted or unknown, browse scan history, and open the HTML report. Trust is stored by MAC address in the same SQLite file, so a trusted label survives later scans.

Run scans from a machine on your home network. A scan from inside a normal Docker container only sees the container network.

## Device inventory

Inventory fields stay with the device across scans. They are not a second copy of the trust label.

```bash
python3 -m lantern asset set aa:bb:cc:dd:ee:ff --owner Ada --location "Rack A" --tag web --criticality high --notes "Patched last week"
python3 -m lantern asset show aa:bb:cc:dd:ee:ff
python3 -m lantern asset list --tag web --criticality high
python3 -m lantern asset clear aa:bb:cc:dd:ee:ff --field notes
```

`set` only accepts a MAC or IPv4 address that already appears in a saved scan. A device with a MAC is stored by that MAC (lowercase, colon form), so a later scan with a new IP keeps the same record. A device with no MAC is stored by IP. Owner and location are at most 80 characters, notes at most 500. A blank or whitespace-only value is rejected; use `asset clear` to remove a field. Tags are at most 10 after duplicates are removed, each 1 to 32 characters from `a-z`, `0-9`, `.`, `_`, or `-` after ASCII lowercase only. A character that would change under case folding or NFKC normalization is rejected. Criticality is `low`, `medium`, `high`, or `critical`. Control, format, and separator characters are rejected, including bidirectional overrides, zero-width characters, and line separators. Lantern stores at most 10000 inventory records. Adding a new device past that limit is refused; updating a record that is already stored still works. `history`, `diff`, `report`, and `asset list --scope` can still match a scope name that has been removed from the config file when that name is stored on a scan. An exact stored spelling is used when more than one case variant is stored.

These fields appear in the CLI, in `report`, and in `diff`. The dashboard does not show them yet; that view arrives in M4. Owner, location, and notes are personal data. They are stored only in the local database, which is created mode 0600, they are not served by the dashboard or the API, and they are included in reports and diffs you may share. HTML output escapes them.

## Safety rules, enforced in code

- Private RFC1918 subnets only (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and the scope must sit fully inside one of them. Public addresses, loopback, link-local, `0.0.0.0/8`, `240.0.0.0/4`, `192.0.0.0/24`, the TEST-NET blocks, and `198.18.0.0/15` are refused.
- At most 1024 unique addresses in one run (a /22), normally a /24. Repeated scope names and overlapping ranges do not raise that total.
- A scope in `lantern.toml` uses those same checks. The file cannot raise the cap, allow a public, loopback, or link-local range, or set excludes, extra CIDRs, or a different port list. Those keys are rejected. A scope file larger than 64 KiB is refused. Several scopes in one run still share the 1024 unique-address cap.
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

- On loopback with `--no-strict-auth`, anyone who can open an allowed Host can read the page, and that page contains the token used for `POST`. That person can call the API. The default does not embed the token. `--allow-host` does not add a login.
- On a LAN bind, anyone who has the startup token can read the inventory and start scans. Treat that token like a password. It is not an account system.
- A person at the keyboard, or another local user who can read the SQLite file.

Every request must send an allowed `Host`. On loopback that is `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`, plus any host you named with `--allow-host`. With `--allow-lan`, the allowlist is only the explicit bind address and the `--allow-host` values. `0.0.0.0` and `::` are not added, and a wildcard is not accepted. A name you did not list is refused even when it resolves to loopback.

By default every `/api` route, including `GET`, requires `X-Lantern-Token`. The process generates that token at startup with `secrets.token_urlsafe` (256 bits), does not embed it in the page, and compares it with `hmac.compare_digest`. It is not written to the log. On a terminal it is printed once in the `#token=` link. `--no-strict-auth` embeds it on loopback and does not require it on `GET`. If a `POST` includes an `Origin` header, that origin must be `http` or `https` and its host and port must be on the same allowlist. A `POST` with no `Origin` is accepted only when the token is valid.

A LAN bind uses that same header for `POST` and for `GET` of inventory, status, and reports. The token is the one the CLI loaded or generated. It is not embedded in the page and it is not written to the log.

Scanning is unchanged: private RFC1918 ranges only, at most 1024 addresses, no loopback or link-local targets. The Host allowlist does not widen that.

## Web dashboard

No pip install needed. The dashboard is stdlib only, plain HTML, CSS, and JavaScript, with a JSON API.

```bash
python3 -m lantern web
# Open the printed http://127.0.0.1:8068/#token=... link.
# With no terminal, set LANTERN_API_TOKEN_FILE or the process exits 2.
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

On loopback, `GET` needs an allowed `Host`. By default it also needs `X-Lantern-Token`, and the page does not contain the token. `POST /api/*` needs that header too. A new token is generated each time the process starts. On a terminal it is printed once in the `#token=` link and is not written to the request log. `--no-strict-auth` embeds the token in the page and does not require it on `GET`. Any local user or process that can connect can then read the page, and therefore the token, and can read `GET /api/*` without it. With Docker host networking, that `127.0.0.1` is the host's loopback, so the same is true of every user on the Docker host when you opt out.

Strict auth is the default. It never puts the token in the page, and every `/api` route, including `GET`, requires `X-Lantern-Token` in both loopback and LAN mode. The comparison and the short delay on a presented mismatch are the same as the other modes. On an interactive terminal, a generated token is printed once as `http://127.0.0.1:PORT/#token=...`. Open that link in the browser. The token is valid until Lantern restarts. The `#token` fragment is not sent to the server. The page script stores it in `sessionStorage` only in this mode and in LAN mode, removes it from the address bar with `history.replaceState`, and sends it as `X-Lantern-Token`. A 403 clears that stored token and asks again, including after a restart leaves a stale value. Without a terminal, which is how `docker logs` works, Lantern does not generate or print a token. Prefer `LANTERN_API_TOKEN_FILE` over `LANTERN_API_TOKEN`: on Linux the process environment is `/proc/<pid>/environ` (mode 0400), so the same user and root can read an env token there, and child processes inherit it. A mode-0400 token file is not copied into that environment. `LANTERN_STRICT_AUTH` accepts `1`, `true`, `yes`, or `on` to enable, and `0`, `false`, `no`, or `off` to opt out (re-opens the local-user token gap). Any other non-empty value refuses to start; an empty value is treated as unset. `0` does not override `--strict-auth`. `--no-strict-auth` turns strict auth off even when `LANTERN_STRICT_AUTH` is `1`, `true`, `yes`, or `on`, and startup prints a warning that names that flag. `--debug` does not print a generated token either. There is no separate config file for this flag. The environment variable is the non-flag setting, the same way the token is configured.

With `--allow-lan`, `GET /api/*` (inventory, status, and HTML or JSON reports) needs the same header as `POST`. The page does not contain the token. Paste it once into the dashboard; the browser keeps it in `sessionStorage` for that tab and sends it as `X-Lantern-Token`. Static files such as `app.js` stay available without the token. The comparison is `hmac.compare_digest`. A token that is presented and does not match waits a short fixed time. The token is not written to the log. `--debug` does not print a generated token; set the file or `LANTERN_API_TOKEN` instead.

POST bodies must be JSON with `Content-Type: application/json` and at most 64 KiB (415 or 413 otherwise). `Transfer-Encoding`, including an empty header and chunked bodies, is rejected with 400 and the connection is closed. Every POST closes the connection. A GET or HEAD whose `Content-Length` is greater than 0 also closes the connection, so that unread body is not parsed as a second request. A `Content-Length` that is negative, not an integer, or repeated (`abc`, `-1`, `+2`, `1e3`, `5, 5`, or two headers) is 400 on every method, and the connection is closed. If a POST includes `Origin`, that origin's host and port must be on the same allowlist (`http` or `https` only). A POST with no `Origin` is accepted only when the token is valid. A bad Host, a missing or wrong token, or a disallowed Origin is a generic 403. `OPTIONS`, `PUT`, `DELETE`, and `PATCH` are 405 after the Host check and, when LAN-bound, the token check, and the response lists `Allow: GET, HEAD, POST`. An unexpected server error is a generic 500; the exception text is logged only with `--debug`. Each connection has a 10 second idle timeout and a 10 second deadline for reading the request line, the headers, and the body, so a slow drip cannot hold a slot. The response is sent in 16 KiB chunks. Each chunk waits up to 10 seconds for the client to take more data, and never longer than the time left on a 60 second overall deadline. A reader that keeps going can take longer than 10 seconds in total, up to 60 seconds. A reader that stalls is dropped when that wait runs out. The process handles at most 32 connections at once and at most 8 from one client address. `--allow-host` rejects loose IPv4 forms such as `0177.0.0.1`, `0x7f.1`, and `127.000.000.001`. A full cap is 503. A request target must be a path; an absolute URL in the request line is a 400. Scan results include trusted labels and `trusted`/`known` flags per device.

`--allow-host` is repeatable. `python3 -m lantern web --allow-host dashboard.home` also accepts `Host: dashboard.home:<port>`. `python3 -m lantern web --allow-host dashboard.home:8443` accepts that exact host and port. Bracket an IPv6 address (`--allow-host '[2001:db8::5]'`). `0.0.0.0`, `::`, a bare `0` or other all-digit name, shorthand and loose IPv4 such as `127.1`, `0x7f000001`, `0177.0.0.1`, `0x7f.1`, and `127.000.000.001` (the error says to use the full dotted form), a zone id such as `[fe80::1%eth0]`, a wildcard, and a CIDR are rejected. On loopback the default allowlist is only `127.0.0.1`, `localhost`, and `[::1]` on the bound port. `::1` is a real IPv6 loopback listener, not only an allowed Host value.

The dashboard binds to loopback by default (`127.0.0.1`). Any other address, including `0.0.0.0` and `::`, is refused unless you also pass `--allow-lan`. That flag still does not open the port by itself. It exits 2, before listening, unless it has a token of at least 128 bits (22 to 512 urlsafe characters). The token comes from `LANTERN_API_TOKEN_FILE`, then `LANTERN_API_TOKEN`, then `secrets.token_urlsafe` when stderr is an interactive terminal and `--debug` is not set. The generated token is printed once on that terminal and nowhere else. `--debug` does not print it. When stderr is not a terminal, which is how `docker logs` works, Lantern does not generate or print a token; set the file or the environment variable. The token is not written to the database or the request log. `--host 0.0.0.0` or `--host ::` also needs `--allow-host` set to the LAN address clients will send, because the unspecified address is not put on the allowlist. Prefer an SSH tunnel or Tailscale to `127.0.0.1`. Never expose port 8068 to the internet.

Docker, for a homelab host:

```bash
mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data
umask 077
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > lantern_token
chmod 400 lantern_token
sudo chown 10001:10001 lantern_token
```

Then uncomment the service `secrets:` list and the top-level `secrets:` block in `docker-compose.yml`, and set `LANTERN_API_TOKEN_FILE=/run/secrets/lantern_token` on the service. Do not write the token into the compose file. `docker compose up -d` then listens on the host at http://127.0.0.1:8068/. The page does not contain the token; use the value in `lantern_token`. Without that file the container exits 2. Docker has no terminal, so it will not print a token. Do not put the token in `LANTERN_API_TOKEN`: on Linux `/proc/<pid>/environ` is mode 0400, so the same user and root can read an env token there, and child processes inherit it. A mode-0400 token file is not copied into that environment. `LANTERN_STRICT_AUTH=0` opts out and re-opens the local-user token gap.

```yaml
environment:
  LANTERN_API_TOKEN_FILE: /run/secrets/lantern_token
```

The compose file uses host networking so a scan can see the host LAN (the ARP cache and neighbor hosts). The dashboard itself binds `127.0.0.1`. With host networking that is the host's loopback, not the LAN. Compose does not publish port 8068.

The container runs as uid 10001, not root. Compose drops every capability (`--cap-drop ALL`), makes the root filesystem read-only, mounts a tmpfs on `/tmp`, keeps the SQLite file on the `/data` volume, and sets `no-new-privileges`. ICMP ping needs `CAP_NET_RAW` and a ping binary. This image adds neither. TCP connect scans and the host ARP cache work with all capabilities dropped. A setuid or file-capability ping would not help: `no-new-privileges` ignores both. The comments in `Dockerfile` and `docker-compose.yml` record the same flags.

A token file is required by default (and for a LAN bind). Put the token in a regular file and point `LANTERN_API_TOKEN_FILE` at it (the compose file has a commented `secrets:` snippet). The file must not be a symlink or a FIFO, and it must be at most 4 KiB. On macOS and Linux it must be mode 0400 or 0600: any group or other bit is refused. That includes Docker Swarm secrets (mode 0444) and Kubernetes secrets (mode 0644 by default) until you set the file to 0400. Compose `secrets:` bind-mounts the host file as-is and does not change its mode; that path has not been run as a test. `chmod 400` and `chown` the file to uid 10001 yourself. Lantern does not follow a symlink to a looser file. Override the command with `--host 0.0.0.0`, `--allow-lan`, and `--allow-host` set to the LAN address. Do not put the token in `docker-compose.yml`. The container has no terminal, so Lantern will not print a token into `docker logs`. Without the file or `LANTERN_API_TOKEN`, the command exits 2 and does not listen. Prefer Tailscale or an SSH tunnel instead.

CI (`.github/workflows/docker.yml`) builds the image and runs every container with `--network none` (loopback only). It checks the process is not root, the default command without a token exits non-zero and does not listen, the same command with a mode-0400 token file listens on `127.0.0.1:8068`, `GET /api/*` is 403 without that token and 200 with it, and the token is not in the page or in `docker logs`, a non-loopback bind without `--allow-lan` is refused, and `--allow-lan` without a token is refused. It also runs `lantern --version`, an offline `lantern demo`, and a check that loopback and public subnets are refused. The job does not push, tag, or publish an image, and it does not scan a network. The demo uses the built-in fake devices.

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

## Logo

The mark at the top is original vector artwork for this project. The wordmark outlines are Manrope (Copyright 2019 The Manrope Project Authors, SIL Open Font License 1.1). The font file is not in this repo; the SVG glyphs are outlines. The OFL notice is [assets/logo/OFL-Manrope.txt](assets/logo/OFL-Manrope.txt). The artwork is included under this repository's MIT licence unless the maintainer states otherwise.

## License

MIT. See [LICENSE](LICENSE).
