# Security Policy

## Use Lantern only on networks you own

Lantern is a defensive scanner for your own home or small office network. Only scan a network you own, or one where you have explicit permission from the owner to scan it. Scanning someone else's network without permission may be unlawful and is out of scope for this project.

Lantern enforces part of this in code: it refuses public, loopback, and link-local addresses, and subnets larger than 1024 addresses (a /22). That is a guardrail, not a substitute for permission. A scope in `lantern.toml` is checked with the same function as `--subnet`, so the file cannot raise the cap or allow a public, loopback, or link-local range.

## Reporting a vulnerability in Lantern

If you find a security issue in Lantern itself, please report it privately so it can be fixed before public disclosure:

1. Open a GitHub issue titled "Security report" with no exploit details, and ask for a private contact, or
2. Email the maintainer through the address listed on their GitHub profile.

Please include the Lantern version, how you ran it, and what you observed, without including scan results from a real network, MAC addresses, or other private data.

## What Lantern will never do

- Guess passwords, try default credentials, or send login attempts.
- Send exploits, payloads, or vulnerability probes beyond a plain TCP connect and an optional banner read.
- Scan public IPs, phone home, or upload scan results anywhere.
- Store credentials. There are no accounts and no passwords in Lantern.

## Dashboard exposure

The web dashboard has no accounts. It binds to loopback (`127.0.0.1`) by default, including the Docker image command. `lantern web` refuses any other address unless you pass `--allow-lan`. That flag exits 2, before it listens, unless a startup token of at least 128 bits is available from `LANTERN_API_TOKEN_FILE`, then `LANTERN_API_TOKEN`, then an interactive terminal. A generated token is printed once on that terminal only. It is never written to the log, so `docker logs` is not a way to read it. In Docker, provide the file (mode 0400, uid 10001) or the environment variable. The same value is the only API token for that process. Reach the dashboard through localhost, or through a private VPN such as Tailscale. Never expose port 8068 to the internet or to an untrusted network.

The container runs as uid 10001, not root, and owns `/data`. Run it with all capabilities dropped, a read-only root filesystem, a tmpfs on `/tmp`, the `/data` volume, and `no-new-privileges`. `docker-compose.yml` sets those. Host networking is only so a scan can see the host LAN. ICMP ping would need `CAP_NET_RAW` and a ping binary; the image ships neither, and `no-new-privileges` would ignore a setuid ping. TCP connect scans do not need extra capabilities.

On loopback the dashboard answers a request only when the `Host` header is `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, or a host you added with `--allow-host`. That is what stops a public site from rebinding its name onto `127.0.0.1` and calling the API as if it were the dashboard. `::1` is served on IPv6. `POST /api/*` also requires the header `X-Lantern-Token`. Each process generates that token at startup, puts it in the HTML page, and compares it with `hmac.compare_digest`. The token is not written to the log. Anyone who can load the page from an allowed Host can read the token from it. It blocks other websites. It is not a password.

With `--allow-lan` the Host allowlist is only the explicit bind address and `--allow-host` values. Unspecified addresses (`0.0.0.0`, `::`), zone ids (`[fe80::1%eth0]`), wildcards, and CIDR notation are rejected, and they are not added automatically. Every API route, including `GET` of inventory and reports, requires `X-Lantern-Token`. The page does not contain the token. A client that forges `Host: 127.0.0.1` still needs the token, and that Host is refused unless you listed it. The browser asks for the token once and keeps it in `sessionStorage` for the tab.

If a POST includes an `Origin` header, that origin must be `http` or `https` and its host and port must be on the same allowlist. A POST with no `Origin` is accepted only when the token is valid, which is how curl and other non-browser clients call in. POST bodies must be JSON and at most 64 KiB. Request targets must be a path; an absolute-form request line is rejected. Unexpected errors return a generic 500 with no exception text. Each connection times out after about 10 seconds, and the number of concurrent connections is capped. HTML responses carry a strict Content Security Policy. These limits are not a login.

`--allow-host` does not make a non-loopback bind safe. `--host` other than loopback is an explicit choice with `--allow-lan` and the token, and the process still has no accounts. Scanning rules are separate and unchanged: private ranges only, at most 1024 addresses.

## Supported versions

Only the latest release on the default branch receives security fixes. Older snapshots are provided as-is for review.

## Local inventory files

Scan results stay in one SQLite file on the machine running Lantern. On macOS and Linux, Lantern creates that file, its migration backup, and the demo HTML report mode 0600, and creates a new data directory mode 0700. A directory that already exists keeps the mode you set. If that directory is looser than 0700, for example 0755, Lantern warns on stderr and does not change it. If an existing database or backup is readable by other local accounts, Lantern warns on stderr and leaves the file unchanged. A database path that is a symlink is refused. For the Docker bind mount of `./data`, run `mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data`.

On Windows, Lantern relies on the user profile ACL. Unix permission bits are not applied. Keep the database in your profile.
