## Safety rules, enforced in code

- Private RFC1918 subnets only (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and the scope must sit fully inside one of them. Public addresses, loopback, link-local, `0.0.0.0/8`, `240.0.0.0/4`, `192.0.0.0/24`, the TEST-NET blocks, and `198.18.0.0/15` are refused.
- At most 1024 unique addresses in one run (a /22), normally a /24. Repeated scope names and overlapping ranges do not raise that total.
- A scope in `lantern.toml` uses those same checks. The file cannot raise the cap, allow a public, loopback, or link-local range, or set excludes, extra CIDRs, or a different port list. Those keys are rejected. A scope file larger than 64 KiB is refused. Several scopes in one run still share the 1024 unique-address cap.
- No brute force, no exploits, no default password checks, ever. The only bytes Lantern sends after connecting to a scanned port are a single `HEAD / HTTP/1.0` to ports that usually speak HTTP.
- Switches are read only when you name them with `--switch`, using read-only SNMPv2c requests (no SetRequest exists in the code) to UDP port 161 of those private addresses. The community stays in memory and is never stored, printed, or logged.
- To name devices, each scan also sends one SSDP search (`239.255.255.250:1900`) and one mDNS query (`224.0.0.251:5353`) on the local link, with a multicast TTL of 1, and listens for 2.5 seconds. These are the same discovery messages phones and computers send all the time. When a device answers SSDP with a description URL, Lantern fetches that one XML file only from the device that answered, only over plain HTTP inside the scanned subnet, with a 2-second timeout and a 64 KiB cap, and refuses any document with a DTD. Replies from outside the subnet are ignored.
- Stdlib only. No Nmap, no Scapy, no root needed. The Docker image runs as uid 10001, not root.
- The database, its migration backup, and the demo HTML report are created private to your user. A database path that is a symlink is refused. Lantern leaves an existing directory at the mode you set, and warns on stderr if that directory is looser than 0700 (for example 0755). For the Docker bind mount of `./data`, run `mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data`.

Only scan networks you own or have explicit permission to scan. See [SECURITY.md](../SECURITY.md).

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

