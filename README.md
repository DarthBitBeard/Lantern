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
| Real scan | `python3 -m lantern scan --subnet 192.168.1.0/24` |
| Diff last two scans | `python3 -m lantern diff` |
| HTML/JSON report | `python3 -m lantern report --format html` |
| Tests | `python3 tests/run_tests.py` |

Default database file: `data/lantern.db` (created automatically; gitignored).

**Debug tips**

- Prefer demo mode while developing UI or storage: `python3 -m lantern demo` then `python3 -m lantern web --debug --db data/lantern.db`.
- `--debug` prints each HTTP request to stderr; leave it off for normal use.
- Break in the stdlib server with `python3 -m pdb -m lantern web --debug`, or attach your IDE debugger to `lantern.cli:main` / `lantern.webapp:serve`.
- API smoke check: `curl -s http://127.0.0.1:8068/api/status` and `curl -s -X POST http://127.0.0.1:8068/api/demo -H 'Content-Type: application/json' -d '{}'`.
- If the dashboard 404s after `pip install`, the install is missing `lantern/web`. Reinstall from this repo (`pip install -e .`); package data is declared in `pyproject.toml`.
- Subnet auto-detect uses the machine's outbound private IPv4. If it cannot guess, pass `--subnet` (CLI) or fill the Subnet field in the UI.

## Scan your own network

```bash
python3 -m lantern scan --subnet 192.168.1.0/24
python3 -m lantern diff
python3 -m lantern report --format html > report.html
```

From the dashboard you can also run a real scan or a demo scan, see the diff banner, search and filter devices, label a device and mark it trusted or unknown, browse scan history, and open the HTML report. Trust is stored by MAC address in the same SQLite file, so a trusted label survives later scans.

Run scans from a machine on your home network. A scan from inside a normal Docker container only sees the container network.

## Safety rules, enforced in code

- Private RFC1918 subnets only. Public IPs are refused.
- Nothing larger than a /16, normally a /24.
- No brute force, no exploits, no default password checks, ever.
- Stdlib only. No Nmap, no Scapy, no root needed.

Only scan networks you own or have explicit permission to scan. See [SECURITY.md](SECURITY.md).

## Web dashboard

No pip install needed. The dashboard is stdlib only, plain HTML, CSS, and JavaScript, with a JSON API.

```bash
python3 -m lantern web
# open http://127.0.0.1:8068/
```

API, same origin only: `GET /api/status`, `GET /api/scans`, `GET /api/scans/latest`, `GET /api/scans/{id}`, `GET /api/diff`, `GET /api/report?format=json|html`, `POST /api/scan`, `POST /api/demo`, `POST /api/trust`.

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

This runs the risk and safety tests and the web dashboard tests (index, status, demo, trust, public-scan refusal, report, history) against a temporary database.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: keep it stdlib only, keep it defensive, keep the plain English fixes, and add a test for new behavior.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
