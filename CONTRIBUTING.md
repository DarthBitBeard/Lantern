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
python3 -m lantern demo
python3 -m lantern web
# open http://127.0.0.1:8068/
```

## Tests

```bash
python3 tests/run_tests.py
```

Add a test for new behavior. Risk rules go in `tests/test_risks.py`, dashboard behavior in `tests/test_web.py`. Keep tests fast and offline: no real network scans in CI.

## Pull requests

- Keep the change focused. One feature or fix per pull request.
- Update the README and CHANGELOG.md when behavior or the API changes.
- Describe what you scanned (demo data, or your own network), and what the diff showed.
- The maintainer reviews every pull request. Please do not merge your own.

## Code style

Plain, readable Python. Short functions, explicit names, no clever tricks. Follow the existing file layout: discovery and scanning in their own modules, risk rules in `lantern/ports.py`, storage in `lantern/store.py`, the dashboard API in `lantern/webapp.py`, and the UI in `lantern/web/`.
