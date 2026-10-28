# Contributing

Thanks for considering a contribution. Lantern is deliberately small, so please keep changes in that spirit.

## Ground rules

1. Defensive only. No brute force, no exploits, no password guessing, no scanning of public networks. If a feature needs to touch another machine, it must be a plain connect or read, with the user's explicit action.
2. Stdlib only. Do not add a third-party dependency without opening an issue first and making the case. The zero-install story is a feature.
3. Plain English. Every new finding needs a severity, a title a non-security person understands, and a fix step.
4. Local only. No cloud calls, no tracking, no accounts. Data stays in the local SQLite file unless the user exports a report.
5. No real network data in tests, examples, or screenshots. Use the demo network in `lantern/demo.py`, or clearly fake addresses and MACs.

## How to run it

```bash
python3 -m pip install -e .
python3 -m lantern demo
python3 -m lantern web --debug
# open http://127.0.0.1:8068/
```

See the README "Run and debug" section for DB path, ports, and debugger tips.

## Tests

```bash
python3 tests/run_tests.py
```

Tests use `unittest` and are discovered automatically from `tests/test_*.py`; you can also run one file directly, for example `python3 tests/test_web.py`. Add a test for new behavior, next to the module it covers: risk rules in `test_risks.py`, subnet and ARP handling in `test_discovery.py`, probes in `test_scanner.py`, storage and diff in `test_store.py`, commands in `test_cli.py`, scope files in `test_scopes.py`, dashboard API in `test_web.py`. Keep tests fast and offline: no real network scans in CI. Mock `ping_host`, `arp_table`, and `scan_host` where a test would otherwise touch the network.

CI (`.github/workflows/ci.yml`) runs the suite on Linux, macOS, and Windows for Python 3.11, 3.12, and 3.13, then builds a wheel and installs it on each of those operating systems for an offline demo smoke test. Use `python` in workflow steps so Windows runners, which do not provide `python3`, can run the same commands.

## Pull requests

- Keep the change focused. One feature or fix per pull request.
- Update the README and CHANGELOG.md when behavior or the API changes.
- Describe what you scanned (demo data, or your own network), and what the diff showed.
- The maintainer reviews every pull request. Please do not merge your own.

## Code style

Plain, readable Python. Short functions, explicit names, no clever tricks. Follow the existing file layout: discovery and scanning in their own modules, risk rules in `lantern/ports.py`, storage in `lantern/store.py`, the dashboard API in `lantern/webapp.py`, and the UI in `lantern/web/`.

A change to the SQLite tables is a new numbered function in the migration list in `lantern/store.py`. Do not edit a migration that has already shipped, and do not commit from inside a migration. Add a test that an older database file still loads, including one shaped like 0.3.0 (no `schema_version` table).
