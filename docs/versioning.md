## Versioning and compatibility

From 1.0.0, Lantern follows semantic versioning for the things scripts and other tools rely on:

- **`/api/v1`**: routes, parameters, and JSON field names stay compatible for every 1.x release. New fields and routes may be added; nothing is renamed or removed. A breaking change would ship as `/api/v2` alongside v1, with `api_version` set to 2.
- **Command line**: command names, flags, exit codes (0 ok, 1 partial or not found, 2 refused or usage error), and `--format json` output stay compatible for 1.x. Plain-text output is for people and may change.
- **Export**: JSON and CSV column names stay compatible for 1.x.
- **Database**: a newer 1.x opens any older Lantern database and upgrades it in place after writing a `.vN.bak` copy beside it. Migrations only move forward, so an older Lantern refuses a database that a newer one has upgraded. Keep the backup if you may need to roll back.

The dashboard's own `/api/*` routes (without `v1`) serve the web page and may change in any release. Use `/api/v1` from scripts.

