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

The web dashboard has no login, by design for local use. Bind it to localhost (the default), or reach it only over a private VPN such as Tailscale. Never expose port 8068 to the internet or to an untrusted network.

The dashboard answers a request only when the `Host` header is `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, or a host you added with `--allow-host` (repeatable; nothing else is allowed by default). That is what stops a public site from rebinding its name onto `127.0.0.1` and calling the API as if it were the dashboard. `POST /api/*` also requires the header `X-Lantern-Token`. Each process generates that token at startup, puts it in the HTML page, and compares it in constant time. The token is not written to the log. Anyone who can load the page from an allowed Host can read the token from it. It blocks other websites. It is not a password.

If a POST includes an `Origin` header, that origin must be `http` or `https` and its host and port must be on the same allowlist. A POST with no `Origin` is accepted only when the token is valid, which is how curl and other non-browser clients call in. POST bodies must be JSON under 64 KiB. HTML responses carry a strict Content Security Policy. These limits are not a login.

`--allow-host` does not make a non-loopback bind safe. `--host` other than loopback is still an explicit choice, and the process still has no accounts. Scanning rules are separate and unchanged: private ranges only, at most 1024 addresses.

## Supported versions

Only the latest release on the default branch receives security fixes. Older snapshots are provided as-is for review.
