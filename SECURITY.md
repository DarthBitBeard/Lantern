# Security Policy

## Reporting a vulnerability

Please report privately. Do not open a public issue, discussion, or pull request for a security problem.

GitHub Private Vulnerability Reporting is the only reporting channel. Use the "Report a vulnerability" button on the repository's Security tab.

Please include the Lantern version or commit, your OS and Python version, how you ran it (CLI, dashboard, Docker), the steps to reproduce, and the impact you see.
Do not include real network data. That means no real IPs, MAC addresses, hostnames, banners, scan databases, or screenshots of your inventory. Use `lantern demo` data or made-up values.

## What to expect

- Acknowledgement within 3 business days.
- Triage and a severity assessment within 7 days of the report.
- Fix target: 30 days for Critical and High, 90 days for Medium and Low. If a fix will take longer, we will tell you why and agree a new date with you.
- Coordinated disclosure: we publish a GitHub Security Advisory when the fixed release ships (with a CVE where appropriate), and we credit you unless you ask us not to.

## Safe harbor

We will not pursue or support legal action against good-faith research that:

- tests only on localhost, your own devices, or networks you own or are explicitly authorized to test;
- avoids privacy violations, data destruction, and service disruption;
- reports privately and gives us reasonable time to fix before disclosure.

This does not authorize testing against anyone else's network or devices.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.0 (the version in `pyproject.toml`) and `main` | Yes |
| 0.2.1, 0.2.0, 0.1.0, and older snapshots | No; please upgrade |

`main` has unreleased changes that are not a new version number. There is no 1.0 release.

## Scope

Lantern is a defensive tool. It finds hosts on one subnet you choose and checks a fixed list of common ports. It does not guess passwords, try credentials, or send exploits.

In scope: the `lantern` Python package (CLI, scanner, store, scopes), the web dashboard and its API, the Dockerfile and docker-compose.yml, and this repository's CI workflows.

Out of scope: vulnerabilities in the devices Lantern finds; issues that need an attacker who already controls your user account or machine; deployments that ignore the documented defaults (for example, exposing port 8068 to the internet); third-party services, forks, and repackaged builds; denial of service by flooding traffic.

## Security model

Checked against the code on `main` at `05791cefbb4e794bacf408b774ce258a316aaace`.

The dashboard has no user accounts. It does have one access token per process (`X-Lantern-Token`, compared with `hmac.compare_digest`). On loopback the process generates that token, embeds it in the page, and requires it on `POST /api/*` only. With `--allow-lan` the same token is required on every API route, including `GET` inventory and reports, and the page does not contain it. The browser keeps a pasted token in `sessionStorage` for that tab. A presented token that does not match waits 50 ms. The token is not written to the log or the database.

`--allow-lan` is the only way to bind an address other than loopback. The default bind is `127.0.0.1`. The flag exits 2 before it listens unless one token of at least 128 bits is available (22 to 512 urlsafe characters). Precedence is `LANTERN_API_TOKEN_FILE`, then `LANTERN_API_TOKEN`, then `secrets.token_urlsafe` when stderr is an interactive terminal and `--debug` is not set. A generated token is printed once on that terminal. `--debug` does not print one. When stderr is not a terminal, Lantern does not generate a token. The token file must be a regular file of at most 4 KiB, opened with `O_NOFOLLOW` and `O_NONBLOCK` where the platform has them. A symlink or a FIFO is refused. On macOS and Linux the mode must be 0400 or 0600. Mode 0444 is refused.

Every request needs an allowed `Host`. On loopback that is `127.0.0.1`, `localhost`, or `[::1]` on the bound port, plus any host named with `--allow-host`. With `--allow-lan` the allowlist is only the explicit bind address and the `--allow-host` values. `0.0.0.0` and `::` are not added. A `POST` that includes `Origin` must use `http` or `https`, and that origin's host and port must be on the same allowlist. A missing `Origin` is accepted only after the token matches. `--allow-host` rejects unspecified addresses, zone ids, wildcards, CIDR, all-digit names, and loose IPv4 forms such as `127.1`.

Reading one request (the request line, the headers, and the body) shares a 10 second deadline. The process serves at most 32 connections at once and at most 8 from one client address. A full cap is 503.

Scans go through `validate_subnet`, including every subnet in `lantern.toml`. IPv6 is refused. Loopback and link-local are refused. A network of more than 1024 addresses is refused. A host such as `192.168.1.5/24` is normalized to the network. There is no flag, config key, API field, or confirmation step that authorizes a range this check refuses. Extra keys in a scope file are rejected, and a scope file larger than 64 KiB is refused before it is parsed.

The check uses `IPv4Network.is_private`, which is wider than RFC1918. Comments in the code describe the limit as RFC1918. On Python 3.12.3 the function also accepts some special-use ranges that fit in 1024 addresses, including `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/24`, `0.1.2.0/24`, and `240.0.0.1/32`. It refuses public ranges such as `8.8.8.8/32`, `11.0.0.0/24`, and `100.64.1.0/24`. Those results were run against this function. They are not an authorization path.

Discovery does not phone home. The package has no telemetry, no update check, and no dependency that uploads results. A scan can ping hosts on the chosen subnet, read the local ARP cache, open a TCP connection to a fixed list of common ports, and read a short banner. On a few HTTP ports, if the service stays silent, it sends `HEAD / HTTP/1.0` and reads up to 256 bytes. Reverse DNS uses the system resolver (`socket.gethostbyaddr`), and guessing this machine's hostname can also ask the resolver. Guessing the local subnet connects a UDP socket to `8.8.8.8` and does not send a packet. Results stay in a local SQLite file.

On macOS and Linux, a new database, its migration backup, and the demo HTML report are created mode 0600. A directory Lantern creates is mode 0700. A directory or file Lantern did not create is left as it is; a mode looser than that gets a warning on stderr and is not changed. A database path that is a symlink is refused. On Windows those Unix mode bits are not set or checked.

The Docker image runs as uid/gid 10001. Its command binds `127.0.0.1`. It does not install ping. `docker-compose.yml` uses host networking, does not publish a port, sets `user: 10001:10001`, a read-only root filesystem, a tmpfs on `/tmp`, `cap_drop: ALL`, and `no-new-privileges`. This description is from those files. The image was not rebuilt for this policy text.

## Responsible use

Only scan networks you own or have explicit permission to scan. Scanning other people's networks may be illegal where you live. You are responsible for how you use Lantern.
