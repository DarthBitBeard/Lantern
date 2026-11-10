## Web dashboard

No pip install needed. The dashboard is stdlib only, plain HTML, CSS, and JavaScript, with a JSON API.

```bash
python3 -m lantern web
# Open the printed http://127.0.0.1:8068/#token=... link.
# With no terminal, set LANTERN_API_TOKEN_FILE or the process exits 2.
```

API. Every call is refused (403, body `{"error": "Forbidden."}`) unless `Host` is on the allowlist. On loopback that is this port's loopback names, or a host passed with `--allow-host`. With `--allow-lan` it is only the bind address and `--allow-host`.

| Route | Returns |
| --- | --- |
| `GET /api/status` | version, guessed subnet, scan count, latest scan id, `scan_running` |
| `GET /api/scans` | saved scans, newest first, with `total`. `?limit=` (default 200, at most 1000) and `?offset=` page through them |
| `GET /api/scans/latest`, `GET /api/diff` | latest scan plus its diff against the scan before it |
| `GET /api/scans/{id}` | one scan plus its diff against the scan before it |
| `GET /api/report?format=json\|html&scan_id=N` | report for the latest scan, or scan `N` |
| `POST /api/scan` `{"subnet": "192.168.1.0/24"}` | starts a real scan in the background (subnet optional, auto-detected) and returns 202 at once; 409 while one is running |
| `GET /api/scan` | the latest dashboard scan: `state` (`idle`, `running`, `done`, `error`), `subnet`, `scan_id` once done, and a fixed `error` message when it failed |
| `POST /api/demo` `{}` | saves the two demo scans |
| `POST /api/trust` `{"mac": "...", "label": "...", "trusted": true}` | labels a device by MAC |

On loopback, `GET` needs an allowed `Host`. By default it also needs `X-Lantern-Token`, and the page does not contain the token. `POST /api/*` needs that header too. A new token is generated each time the process starts. On a terminal it is printed once in the `#token=` link and is not written to the request log. `--no-strict-auth` embeds the token in the page and does not require it on `GET`. Any local user or process that can connect can then read the page, and therefore the token, and can read `GET /api/*` without it. With Docker host networking, that `127.0.0.1` is the host's loopback, so the same is true of every user on the Docker host when you opt out.

Strict auth is the default. It never puts the token in the page, and every `/api` route, including `GET`, requires `X-Lantern-Token` in both loopback and LAN mode. The comparison and the short delay on a presented mismatch are the same as the other modes. On an interactive terminal, a generated token is printed once as `http://127.0.0.1:PORT/#token=...`. Open that link in the browser. The token is valid until Lantern restarts. The `#token` fragment is not sent to the server. The page script stores it in `sessionStorage` only in this mode and in LAN mode, removes it from the address bar with `history.replaceState`, and sends it as `X-Lantern-Token`. A 403 clears that stored token and asks again, including after a restart leaves a stale value. Without a terminal, which is how `docker logs` works, Lantern does not generate or print a token. Prefer `LANTERN_API_TOKEN_FILE` over `LANTERN_API_TOKEN`: on Linux the process environment is `/proc/<pid>/environ` (mode 0400), so the same user and root can read an env token there, and child processes inherit it. A mode-0400 token file is not copied into that environment. `LANTERN_STRICT_AUTH` accepts `1`, `true`, `yes`, or `on` to enable, and `0`, `false`, `no`, or `off` to opt out (re-opens the local-user token gap). Any other non-empty value refuses to start; an empty value is treated as unset. `0` does not override `--strict-auth`. `--no-strict-auth` turns strict auth off even when `LANTERN_STRICT_AUTH` is `1`, `true`, `yes`, or `on`, and startup prints a warning that names that flag. `--debug` does not print a generated token either. There is no separate config file for this flag. The environment variable is the non-flag setting, the same way the token is configured.

With `--allow-lan`, `GET /api/*` (inventory, status, and HTML or JSON reports) needs the same header as `POST`. The page does not contain the token. Paste it once into the dashboard; the browser keeps it in `sessionStorage` for that tab and sends it as `X-Lantern-Token`. Static files such as `app.js` stay available without the token. The comparison is `hmac.compare_digest`. A token that is presented and does not match waits a short fixed time. The token is not written to the log. `--debug` does not print a generated token; set the file or `LANTERN_API_TOKEN` instead.

POST bodies must be JSON with `Content-Type: application/json` and at most 64 KiB (415 or 413 otherwise). `Transfer-Encoding`, including an empty header and chunked bodies, is rejected with 400 and the connection is closed. Every POST closes the connection. A GET or HEAD whose `Content-Length` is greater than 0 also closes the connection, so that unread body is not parsed as a second request. A `Content-Length` that is negative, not an integer, or repeated (`abc`, `-1`, `+2`, `1e3`, `5, 5`, or two headers) is 400 on every method, and the connection is closed. If a POST includes `Origin`, that origin's host and port must be on the same allowlist (`http` or `https` only). A POST with no `Origin` is accepted only when the token is valid. A bad Host, a missing or wrong token, or a disallowed Origin is a generic 403. `OPTIONS`, `PUT`, `DELETE`, and `PATCH` are 405 after the Host check and, when LAN-bound, the token check, and the response lists `Allow: GET, HEAD, POST`. An unexpected server error is a generic 500; the exception text is logged only with `--debug`. Each connection has a 10 second idle timeout and a 10 second deadline for reading the request line, the headers, and the body, so a slow drip cannot hold a slot. The response is sent in 16 KiB chunks. Each chunk waits up to 10 seconds for the client to take more data, and never longer than the time left on a 60 second overall deadline. A reader that keeps going can take longer than 10 seconds in total, up to 60 seconds. A reader that stalls is dropped when that wait runs out. The process handles at most 32 connections at once and at most 8 from one client address. `--allow-host` rejects loose IPv4 forms such as `0177.0.0.1`, `0x7f.1`, and `127.000.000.001`. A full cap is 503. A request target must be a path; an absolute URL in the request line is a 400. Scan results include trusted labels and `trusted`/`known` flags per device.

`--allow-host` is repeatable. `python3 -m lantern web --allow-host dashboard.home` also accepts `Host: dashboard.home:<port>`. `python3 -m lantern web --allow-host dashboard.home:8443` accepts that exact host and port. Bracket an IPv6 address (`--allow-host '[2001:db8::5]'`). `0.0.0.0`, `::`, a bare `0` or other all-digit name, shorthand and loose IPv4 such as `127.1`, `0x7f000001`, `0177.0.0.1`, `0x7f.1`, and `127.000.000.001` (the error says to use the full dotted form), a zone id such as `[fe80::1%eth0]`, a wildcard, and a CIDR are rejected. On loopback the default allowlist is only `127.0.0.1`, `localhost`, and `[::1]` on the bound port. `::1` is a real IPv6 loopback listener, not only an allowed Host value.

The dashboard binds to loopback by default (`127.0.0.1`). Any other address, including `0.0.0.0` and `::`, is refused unless you also pass `--allow-lan`. That flag still does not open the port by itself. It exits 2, before listening, unless it has a token of at least 128 bits (22 to 512 urlsafe characters). The token comes from `LANTERN_API_TOKEN_FILE`, then `LANTERN_API_TOKEN`, then `secrets.token_urlsafe` when stderr is an interactive terminal and `--debug` is not set. The generated token is printed once on that terminal and nowhere else. `--debug` does not print it. When stderr is not a terminal, which is how `docker logs` works, Lantern does not generate or print a token; set the file or the environment variable. The token is not written to the database or the request log. `--host 0.0.0.0` or `--host ::` also needs `--allow-host` set to the LAN address clients will send, because the unspecified address is not put on the allowlist. Prefer an SSH tunnel or Tailscale to `127.0.0.1`. Never expose port 8068 to the internet.

Docker, for a homelab host:

```bash
mkdir -p data && sudo chown 10001:10001 data && sudo chmod 700 data
umask 077
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > lantern_token
chmod 400 lantern_token
sudo chown 10001:10001 lantern_token
```

Then uncomment the service `secrets:` list and the top-level `secrets:` block in `docker-compose.yml`, and set `LANTERN_API_TOKEN_FILE=/run/secrets/lantern_token` on the service. Do not write the token into the compose file. `docker compose up -d` then listens on the host at http://127.0.0.1:8068/. The page does not contain the token; use the value in `lantern_token`. Without that file the container exits 2. Docker has no terminal, so it will not print a token. Do not put the token in `LANTERN_API_TOKEN`: on Linux `/proc/<pid>/environ` is mode 0400, so the same user and root can read an env token there, and child processes inherit it. A mode-0400 token file is not copied into that environment. `LANTERN_STRICT_AUTH=0` opts out and re-opens the local-user token gap.

```yaml
environment:
  LANTERN_API_TOKEN_FILE: /run/secrets/lantern_token
```

The compose file uses host networking so a scan can see the host LAN (the ARP cache and neighbor hosts). The dashboard itself binds `127.0.0.1`. With host networking that is the host's loopback, not the LAN. Compose does not publish port 8068.

The container runs as uid 10001, not root. Compose drops every capability (`--cap-drop ALL`), makes the root filesystem read-only, mounts a tmpfs on `/tmp`, keeps the SQLite file on the `/data` volume, and sets `no-new-privileges`. ICMP ping needs `CAP_NET_RAW` and a ping binary. This image adds neither. TCP connect scans and the host ARP cache work with all capabilities dropped. A setuid or file-capability ping would not help: `no-new-privileges` ignores both. The comments in `Dockerfile` and `docker-compose.yml` record the same flags.

A token file is required by default (and for a LAN bind). Put the token in a regular file and point `LANTERN_API_TOKEN_FILE` at it (the compose file has a commented `secrets:` snippet). The file must not be a symlink or a FIFO, and it must be at most 4 KiB. On macOS and Linux it must be mode 0400 or 0600: any group or other bit is refused. That includes Docker Swarm secrets (mode 0444) and Kubernetes secrets (mode 0644 by default) until you set the file to 0400. Compose `secrets:` bind-mounts the host file as-is and does not change its mode; that path has not been run as a test. `chmod 400` and `chown` the file to uid 10001 yourself. Lantern does not follow a symlink to a looser file. Override the command with `--host 0.0.0.0`, `--allow-lan`, and `--allow-host` set to the LAN address. Do not put the token in `docker-compose.yml`. The container has no terminal, so Lantern will not print a token into `docker logs`. Without the file or `LANTERN_API_TOKEN`, the command exits 2 and does not listen. Prefer Tailscale or an SSH tunnel instead.

CI (`.github/workflows/docker.yml`) builds the image and runs every container with `--network none` (loopback only). It checks the process is not root, the default command without a token exits non-zero and does not listen, the same command with a mode-0400 token file listens on `127.0.0.1:8068`, `GET /api/*` is 403 without that token and 200 with it, and the token is not in the page or in `docker logs`, a non-loopback bind without `--allow-lan` is refused, and `--allow-lan` without a token is refused. It also runs `lantern --version`, an offline `lantern demo`, and a check that loopback and public subnets are refused. The job does not push, tag, or publish an image, and it does not scan a network. The demo uses the built-in fake devices.

