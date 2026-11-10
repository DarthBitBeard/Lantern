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

### Windows installer

Download `lantern-<version>-windows-x64-setup.exe` from the [releases page](https://github.com/DarthBitBeard/Lantern/releases) and run it. It needs no Python and no admin rights. It installs for your user only into `%LOCALAPPDATA%\Programs\Lantern`, adds `lantern` to your PATH (a checkbox), and creates these Start Menu entries:

- **Lantern Dashboard** starts the dashboard and opens it in your browser. Closing its window stops Lantern.
- **Lantern Command Prompt** opens a prompt where `lantern scan`, `lantern history`, and the other commands work.

Both use the scan history in `%LOCALAPPDATA%\Lantern\lantern.db`. Uninstall from Settings > Apps. The uninstaller leaves that folder in place, so your history survives a reinstall; delete it yourself to remove it.

The installer and `lantern.exe` are not code-signed, so SmartScreen may warn "Windows protected your PC". Choose "More info", then "Run anyway", after checking the SHA-256 in the release notes. The build is `.github/workflows/windows-package.yml`, which installs, runs, and uninstalls the package on a clean runner.

### From source

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
python3 -m lantern web --open
# Same, and opens that link in your default browser (loopback only).
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
| Delete old scans | `python3 -m lantern prune --keep 30` shows what would go; add `--yes` to delete. `--older-than DAYS` works too, and `--vacuum` shrinks the file. The newest scan of each scope is always kept, and inventory and trust records are kept. |
| HTML/JSON report | `python3 -m lantern report --format html` (add `--scan-id N` or `--scope home`) |
| Export devices, findings, or history | `python3 -m lantern export --what devices --format csv --output report.csv` |
| Tests | `python3 tests/run_tests.py` |

Every command accepts `--db PATH` and `--format`; see `python3 -m lantern <command> --help`. Errors go to stderr with exit code 2.

Default database file: `data/lantern.db` (created automatically; gitignored).

The database is schema 6. Opening an older file upgrades it in place and writes `.vN.bak` first. Schema 5 stores the gateway and what a device announced. Schema 6 stores the switch map. Details are in [Database and migrations](docs/running.md#run-and-debug).

Lantern only scans private RFC1918 networks, at most 1024 addresses, and it does not guess passwords or send exploits. The full rules are in [Safety rules](docs/safety.md#safety-rules-enforced-in-code) and the [Threat model](docs/safety.md#threat-model).

## Troubleshooting

- **The dashboard exits 2 before it listens.** Strict auth is on, and there is no terminal to print a token. Set `LANTERN_API_TOKEN_FILE` to a regular file, mode 0400 or 0600, that contains one token. Docker has no terminal, so the same exit 2 means the token file or `LANTERN_API_TOKEN` is missing. Do not put the token in the image or in `docker-compose.yml`.
- **`Refusing to change it (schema …)`.** The database was written by a newer Lantern. This copy will not migrate it backwards. Upgrade Lantern, or restore the `.vN.bak` that the newer copy left beside the file.
- **`The saved scan could not be read.`** A stored scan row is not valid JSON, or the JSON has the wrong shape. The command exits 2. The dashboard returns HTTP 500 with that same line.
- **A subnet is refused.** Only networks fully inside `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16` are accepted, and a run is at most 1024 addresses. Public, loopback, and link-local ranges are refused.

## More detail

- [Run and debug](docs/running.md#run-and-debug)
- [Scan your own network](docs/scanning.md#scan-your-own-network)
- [Device inventory](docs/inventory.md#device-inventory)
- [Network map](docs/network-map.md#network-map) and [Switch map (managed switches)](docs/network-map.md#switch-map-managed-switches)
- [Export and `/api/v1`](docs/export.md#export-and-apiv1)
- [Safety rules, enforced in code](docs/safety.md#safety-rules-enforced-in-code)
- [Threat model](docs/safety.md#threat-model)
- [Web dashboard](docs/dashboard.md#web-dashboard)
- [What it scans](docs/ports.md#what-it-scans)
- [Limitations](docs/limitations.md#limitations)
- [Versioning and compatibility](docs/versioning.md#versioning-and-compatibility)

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

`lantern/data/oui.tsv.gz` is built from the IEEE Registration Authority public listing of MAC address assignments (MA-L, MA-M, MA-S), keeping only each prefix and organization name. IEEE does not assert copyright in that listing or restrict its distribution. `tools/update_oui.py` rebuilds it from IEEE directly, and a monthly workflow (`.github/workflows/oui-refresh.yml`) opens a pull request when it changes.
