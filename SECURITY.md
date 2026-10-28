# Security Policy

## Reporting a vulnerability

Please report privately. Do not open a public issue, discussion, or pull request for a security problem.

GitHub Private Vulnerability Reporting is the only reporting channel: https://github.com/DarthBitBeard/Lantern/security/advisories/new (or the "Report a vulnerability" button on the Security tab).

Please include the Lantern version or commit, your OS and Python version, how you ran it (CLI, dashboard, Docker), the steps to reproduce, and the impact you see.
Do not include real network data. That means no real IPs, MAC addresses, hostnames, banners, scan databases, or screenshots of your inventory. Use `lantern demo` data or made-up values.

Please test only on localhost, or on networks you own or are authorized to test.

Reports are handled by the maintainer on a best-effort basis. There is no guaranteed response time or fix time. Fixes are announced with a GitHub Security Advisory when practical.

## Supported versions

Only `main` is supported. That branch is currently version 0.3.0 in `pyproject.toml`. There are no tagged releases yet. Security fixes go to `main`. Older versions are not maintained.

## Scope

Lantern is a defensive tool. It finds hosts on one subnet you choose and checks a fixed list of common ports. It does not guess passwords, try credentials, or send exploits.

In scope: the `lantern` Python package (CLI, scanner, store, scopes), the web dashboard and its API, the Dockerfile and docker-compose.yml, and this repository's CI workflows.

Out of scope: vulnerabilities in the devices Lantern finds; issues that need an attacker who already controls your user account or machine; deployments that ignore the documented defaults (for example, exposing port 8068 to the internet); third-party services, forks, and repackaged builds; denial of service by flooding traffic.

## Security model

The dashboard has no user accounts. It does have one access token per process (`X-Lantern-Token`, compared with `hmac.compare_digest`). On loopback the process generates that token, embeds it in the page, and requires it on `POST /api/*` only. `GET /api/*` on loopback does not require the token. With `--allow-lan` the same token is required on every API route, including `GET` inventory and reports, and the page does not contain it. The browser keeps a pasted token in `sessionStorage` for that tab. A presented token that does not match waits 50 ms. The token is not written to the log or the database.

`--allow-lan` is the only way to bind an address other than loopback. The default bind is `127.0.0.1`. The flag exits 2 before it listens unless one token of at least 128 bits is available (22 to 512 urlsafe characters). Precedence is `LANTERN_API_TOKEN_FILE`, then `LANTERN_API_TOKEN`, then `secrets.token_urlsafe` when stderr is an interactive terminal and `--debug` is not set. A generated token is printed once on that terminal. `--debug` does not print one. When stderr is not a terminal, Lantern does not generate a token. The token file must be a regular file of at most 4 KiB, opened with `O_NOFOLLOW` and `O_NONBLOCK` where the platform has them. A symlink or a FIFO is refused. On non-Windows systems the file must have no group or other permissions (0400 or 0600 recommended; 0500 and 0700 are also accepted). Mode 0444 is refused. Windows does not check the mode.

Every request needs an allowed `Host`. On loopback that is `127.0.0.1`, `localhost`, or `[::1]` on the bound port, plus any host named with `--allow-host`. With `--allow-lan` the allowlist is only the explicit bind address and the `--allow-host` values. `0.0.0.0` and `::` are not added. A `POST` that includes `Origin` must use `http` or `https`, and that origin's host and port must be on the same allowlist. A missing `Origin` is accepted only after the token matches. `--allow-host` rejects unspecified addresses, zone ids, wildcards, CIDR, all-digit names, and loose IPv4 forms such as `127.1`.

Reading one request (the request line, the headers, and the body) shares a 10 second deadline. A request body larger than 64 KiB is refused with 413. Responses are written in 16 KiB chunks. Each chunk waits at most 10 seconds, and never longer than the time left on a 60 second overall deadline. The process serves at most 32 connections at once and at most 8 from one client address. A full cap is 503. Those caps limit how many connections run at once. They do not stop a client from holding the slots it already has until a deadline.

Scans go through `validate_subnet`, including every subnet in `lantern.toml`. IPv6 is refused. Loopback and link-local are refused. A network of more than 1024 addresses is refused. A host such as `192.168.1.5/24` is normalized to the network. There is no flag, config key, API field, or confirmation step that authorizes a range this check refuses. Extra keys in a scope file are rejected, and a scope file larger than 64 KiB is refused before it is parsed.

The check uses Python's `ipaddress` `IPv4Network.is_private`, which is wider than RFC1918. Depending on the Python version, it also accepts some special-use ranges that fit in 1024 addresses, such as `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/24`, `0.0.0.0/32`, `240.0.0.0/24`, `192.0.0.0/29`, and the broadcast address `255.255.255.255/32`. `198.18.0.0/15`, `0.0.0.0/8`, and `240.0.0.0/4` are the blocks those examples sit in; each of those whole prefixes is larger than 1024 addresses and is refused. It refuses public addresses such as `8.8.8.8` and `11.0.0.0/24`, shared address space `100.64.0.0/10`, loopback, link-local, and multicast. This is a scope check, not an authorization.

Discovery does not phone home. The package has no telemetry, no update check, and no dependency that uploads results. A scan can ping hosts on the chosen subnet, read the local ARP cache, open a TCP connection to a fixed list of common ports, and read a short banner. On a few HTTP ports, if the service stays silent, it sends `HEAD / HTTP/1.0` and reads up to 256 bytes. Reverse DNS uses the system resolver (`socket.gethostbyaddr`). Those lookups go to the configured DNS server, which may be outside your network. Guessing this machine's hostname can also ask that resolver. Guessing the local subnet connects a UDP socket to `8.8.8.8` and does not send a packet. Results stay in a local SQLite file.

On non-Windows systems, a new database, its migration backup, and the demo HTML report are created mode 0600. A directory Lantern creates is mode 0700. A directory or file Lantern did not create is left as it is; a mode looser than that gets a warning on stderr and is not changed. A database path that is a symlink is refused. On Windows those Unix mode bits are not set or checked. Keep the database in your user profile.

The Docker image runs as uid/gid 10001. Its command binds `127.0.0.1`. The Dockerfile does not install ping. `docker-compose.yml` uses host networking, does not publish a port, sets `user: 10001:10001`, a read-only root filesystem, a tmpfs on `/tmp`, `cap_drop: ALL`, and `no-new-privileges`. With `docker-compose.yml`'s host networking, the container's `127.0.0.1` is the host's loopback, so every user and process on the Docker host can reach the dashboard. The server is `ThreadingHTTPServer`. It does not wrap the socket in TLS.

## Known limitations

The dashboard speaks plain HTTP. There is no TLS. With `--allow-lan`, the access token and the scan data cross the network in clear text. Do not use LAN mode on an untrusted or shared network. Prefer loopback plus an SSH tunnel or Tailscale to `127.0.0.1`, which is what `docker-compose.yml` already recommends. Do not expose port 8068 to the internet.

Loopback is the machine's loopback interface, not a per-user socket. Any local user or process that can open a TCP connection to `127.0.0.1` or `[::1]` on the bound port can reach the dashboard. With `docker-compose.yml`'s host networking, the container's `127.0.0.1` is the host's loopback, so the same applies to every user and process on the Docker host.

On loopback:

- `GET /` does not require the token. The HTML puts it in `<meta name="lantern-token">`, so any local client that can connect can read it.
- `GET /api/*` (inventory, status, and reports) does not require the token, so that client can read scan results.
- `POST /api/*` does require the token. That includes `POST /api/scan`, `POST /api/demo`, and `POST /api/trust`. The token is in the page, so the same local client can read it and then start a scan or change a trust label.
- `app.js` and the other static files do not contain the token.

That other user (other than root or an administrator) cannot read the SQLite database, its migration backup, or the demo HTML report when those files are mode 0600 and owned by the user running Lantern. A directory Lantern created is mode 0700, so that user cannot list it. They also cannot read a token file that has no group or other permission bits. Lantern does not put the token in the log or the database. On Windows, who can read those files is the user profile ACL.

With `--allow-lan`, `GET /` does not include the token, and every API route requires it. Another local user (other than root or an administrator) still cannot read a token file that has no group or other bits. They can call the API if they already have the token. On the network, that token and the data are clear text.

A scan sends real traffic. It pings every host address in the subnet. Hosts that answer, and hosts already in the local ARP cache, then get TCP connections, banner reads, and a reverse-DNS lookup. Network owners or intrusion-detection tools may notice it. Those lookups go to the configured DNS server, which may be outside your network.

The scope check can accept some non-RFC1918 special-use ranges. See the security model above. The 64 KiB body limit, the 10 second request deadline, and the 60 second response deadline still apply.

## Responsible use

Only scan networks you own or have explicit permission to scan. Scanning other people's networks may be illegal where you live. You are responsible for how you use Lantern.
