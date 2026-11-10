## Scan your own network

```bash
python3 -m lantern scan --subnet 192.168.1.0/24
python3 -m lantern diff
python3 -m lantern history
python3 -m lantern report --format html > report.html
```

To keep a few networks on file, copy [`examples/lantern.toml`](../examples/lantern.toml) to `lantern.toml` and edit the subnets to networks you are allowed to scan. Then:

```bash
python3 -m lantern scopes --config lantern.toml
python3 -m lantern scan --config lantern.toml --scope home
python3 -m lantern scan --config lantern.toml --scope home --scope lab
python3 -m lantern scan --config lantern.toml --all
python3 -m lantern history --scope home
python3 -m lantern diff --scope home
python3 -m lantern report --scope home
```

Each scope is one private subnet (`subnet`) plus an optional `description`. A scope file larger than 64 KiB is refused before it is parsed. `lantern scopes` only prints the file. It does not scan and it does not create a database. If the file defines one scope, `--scope` may be omitted. Repeat `--scope` to scan a chosen list in the order given, or pass `--all` to scan every named scope in file order. Each stored scan is tagged with its scope name. `history`, `diff`, and `report` take `--scope` to stay inside that name. The comparison uses the spelling in the scope file, so `lab-2` matches a scope stored as `Lab-2`. If that name is not in the file, or the file cannot be read, `history`, `diff`, and `report` use the typed name after the usual name check. Scans stored under that exact name are still listed. Those commands do not scan, so a broken `lantern.toml` does not block them. A name that is not a short token is rejected before case folding. A diff compares the latest two scans of that scope, not a scan from a different scope. One scope that fails during the scan does not drop the others; the summary lists which ran and which failed, and the command exits 1. A bad name or a public range is refused before any probe, and the command exits 2. One run scans at most 1024 unique addresses. Exactly 1024 is allowed and 1025 is refused before any probe. Repeated names, including names that differ only by case, are scanned once. Overlapping ranges count once. `lantern diff` and `lantern report` with no `--scope` compare a scan to the previous scan of that same scope. `--format html` with several scopes prints one HTML document. `--subnet` on its own still works and does not read the file. Passing `--subnet` together with `--config`, `--scope`, or `--all` is an error, and so is passing `--all` together with `--scope`. The dashboard does not read `lantern.toml`. When a saved scan has a scope name, the page shows that name escaped.

A scan pings every address in the subnet (50 at a time), adds anything already in the OS neighbor (ARP) cache, then tries a short TCP connect (ports 80, 443, 22, 445) on every address that did neither, so a host that blocks ping is still found and the Docker image, which has no `ping`, still discovers hosts. A refused connection counts as alive. It then TCP-connects to the risk ports on each live host, 8 hosts at a time. Expect roughly 15 to 40 seconds for a /24. A host that drops all of those ports and ignores ping is still missed. Without `--subnet`, the dashboard and `lantern scan` use the real prefix of the interface that reaches the network (a /23 is scanned whole), and fall back to the /24 around the address when the OS does not report one or the network is larger than 1024 addresses.

From the dashboard you can also run a real scan or a demo scan, see the diff banner, search and filter devices, label a device and mark it trusted or unknown, browse scan history, and open the HTML report. The Devices tab narrows the cards already on the page by tag and by criticality, together with the search box and the trust filter. Those controls do not start a scan and do not write anything. Search also matches owner, location, tags, notes, and criticality. There is still no inventory editor on the dashboard. Trust is stored by MAC address in the same SQLite file, so a trusted label survives later scans.

Run scans from a machine on your home network. A scan from inside a normal Docker container only sees the container network.

