## Limitations

What this version does, and what it does not do.

- **Inventory is edited in the CLI and shown on the dashboard.** `lantern asset` writes owner, location, tags, criticality, and notes ([0.4.0](../CHANGELOG.md#040---2026-10-30)). The static page does not embed them. A caller with the access token receives them on the scan API, and the device cards render them ([0.5.0](../CHANGELOG.md#050---2026-11-02)). A device card on the dashboard can edit them too ([1.5.0](../CHANGELOG.md#150---2026-11-22)).
- **One token.** `GET /api/v1/status` reports `role` `admin`. There is no read-only token and no second role.
- **Plain HTTP.** The dashboard does not speak TLS. With `--allow-lan` the token and the scan data cross the network in clear text. See [SECURITY.md](../SECURITY.md#known-limitations).
- **SNMP was not checked on a real switch.** The switch map sends read-only SNMPv2c and was exercised against a simulated agent ([1.2.0](../CHANGELOG.md#120---2026-11-05)). SNMPv3 is not supported.
- **Windows binaries are not code-signed** ([1.1.0](../CHANGELOG.md#110---2026-11-05)). SmartScreen can warn. See [Windows installer](../README.md#windows-installer).
- **Not in this version:** showing banner fingerprints in reports, `/api/v1`, or exports (a scan stores them), a vulnerability database or matcher, and a watch mode or local alerts. A reverse-DNS hostname is stored only after control characters and bidi overrides are removed, and only up to 253 characters. A saved HTML report carries its own Content-Security-Policy (`default-src 'none'`). `frame-ancestors` is not honoured in that meta tag; the HTTP header on `/api/report?format=html` still sends it. Scans stay inside the RFC1918 ranges and the 1024-address cap in [Safety rules](safety.md#safety-rules-enforced-in-code).

