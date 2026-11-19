## Device inventory

Inventory fields stay with the device across scans. They are not a second copy of the trust label.

```bash
python3 -m lantern asset set aa:bb:cc:dd:ee:ff --owner Ada --location "Rack A" --tag web --criticality high --notes "Patched last week"
python3 -m lantern asset show aa:bb:cc:dd:ee:ff
python3 -m lantern asset list --tag web --criticality high
python3 -m lantern asset clear aa:bb:cc:dd:ee:ff --field notes
```

`set` only accepts a MAC or IPv4 address that already appears in a saved scan. A device with a MAC is stored by that MAC (lowercase, colon form), so a later scan with a new IP keeps the same record. A device with no MAC is stored by IP. Owner and location are at most 80 characters, notes at most 500. A blank or whitespace-only value is rejected; use `asset clear` to remove a field. Tags are at most 10 after duplicates are removed, each 1 to 32 characters from `a-z`, `0-9`, `.`, `_`, or `-` after ASCII lowercase only. A character that would change under case folding or NFKC normalization is rejected. Criticality is `low`, `medium`, `high`, or `critical`. Control, format, and separator characters are rejected, including bidirectional overrides, zero-width characters, and line separators. Lantern stores at most 10000 inventory records. Adding a new device past that limit is refused; updating a record that is already stored still works. `asset list --scope` can still match a scope name that has been removed from the config file when one spelling is stored on a scan. An exact stored spelling is used when more than one case variant is stored. `history`, `diff`, and `report` instead keep the typed name when the file does not contain it or cannot be read.

You edit these fields with the `asset` commands. They show in the CLI, in `report`, in `diff`, and on the dashboard's device cards after the page has loaded a scan with the access token. The static HTML does not contain owner, location, tags, criticality, or notes; the cards fill them in from that response. There is no inventory editor in the dashboard. Owner, location, and notes are personal data. They are stored only in the local database, which is created mode 0600. `/api/v1/devices` and `/api/v1/diffs` return them to a caller with the token. `lantern export` and `/api/v1/export` leave owner, location, and notes out unless you ask. Reports and diffs you may share include them. HTML output escapes them.

