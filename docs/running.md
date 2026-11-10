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

Opening a database applies any pending schema upgrade. Lantern only migrates forward, in one transaction. A file from a newer Lantern is refused so an older copy of the program cannot rewrite it. The first time a database from 0.3.0 is opened, Lantern copies it to the same path with `.v0.bak` added (for example `data/lantern.db.v0.bak`) and then upgrades it. Scans, devices, and trusted devices stay in the file. Schema version 1 is that 0.3.0 layout plus the version table. Schema version 2 adds `scope_name` on each scan. Schema version 3 adds the inventory table. Schema version 4 adds an index on the device table and changes no rows. Schema version 5 adds the gateway address, gateway MAC, and this machine's address on each scan, and an `identity` column on each device. Schema version 6 adds `scans.topology`, the switch map as JSON. Each upgrade writes `.vN.bak` beside the database (N is the version it had before). A database already at schema 1 is copied to `.v1.bak` and then gains that column; older rows keep a null scope name. The backup is still a local SQLite file; remove it yourself once you trust the upgraded one.

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

